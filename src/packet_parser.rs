use std::net::Ipv4Addr;

use anyhow::{bail, Result};

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub const fn new() -> Self {
        Self {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Read a single byte and move the position one step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            bail!("End of buffer");
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            bail!("End of buffer");
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            bail!("End of buffer");
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    pub fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration. Will take something
    /// like [3]www[6]google[3]com[0] and append www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we might encounter jumps, we'll keep track of our position locally as opposed to
        // using the position within the struct. This allows us to move the shared position to a
        // point past our current qname, while keeping track of our progress on the current qname using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a dot at the beginning
        // of the domain name we'll leave it empty for now and set it to "." at the end of the first
        // iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone can craft a packet
            // with a cycle in the jump instructions. This guards against such packets.
            if jumps_performed > max_jumps {
                bail!("Limit of {max_jumps} jumps exceeded");
            }

            // At this point, we're always at the beginning of a label.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a jump to some other
            // offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current label.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by updating our local
                // position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0, so if the length is
                // zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them to the output
                // buffer.
                let str_buf = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buf).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl From<u8> for ResultCode {
    fn from(n: u8) -> Self {
        match n {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            _ => Self::NOERROR,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    pub id: u16, // 16b

    pub recursion_desired: bool,    // 1b
    pub truncated_message: bool,    // 1b
    pub authoritative_answer: bool, // 1b
    pub opcode: u8,                 // 4b
    pub response: bool,             // 1b

    pub rescode: ResultCode,       // 4b
    pub checking_disabled: bool,   // 1b
    pub authed_data: bool,         // 1b
    pub z: bool,                   // 1b
    pub recursion_available: bool, // 1b

    pub questions: u16,             // 16b
    pub answers: u16,               // 16b
    pub authoritative_entries: u16, // 16b
    pub resource_entries: u16,      // 16b
}

impl DnsHeader {
    pub const fn new() -> Self {
        Self {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & 1) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buf.read_u16()?;
        self.answers = buf.read_u16()?;
        self.authoritative_entries = buf.read_u16()?;
        self.resource_entries = buf.read_u16()?;

        // Return the constant header size
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl From<u16> for QueryType {
    fn from(n: u16) -> Self {
        match n {
            1 => Self::A,
            _ => Self::UNKNOWN(n),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(t: QueryType) -> Self {
        match t {
            QueryType::A => 1,
            QueryType::UNKNOWN(n) => n,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub const fn new(name: String, qtype: QueryType) -> Self {
        Self { name, qtype }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        buf.read_qname(&mut self.name)?;
        self.qtype = QueryType::from(buf.read_u16()?); // qtype
        let _ = buf.read_u16()?; // class

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
}

impl DnsRecord {
    pub fn read(buf: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();
        buf.read_qname(&mut domain)?;

        let qtype_num = buf.read_u16()?;
        let qtype = QueryType::from(qtype_num);
        let _ = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let data_len = buf.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buf.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );

                Ok(Self::A { domain, addr, ttl })
            }
            QueryType::UNKNOWN(_) => {
                buf.step(data_len as usize)?;

                Ok(Self::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub const fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buf: &mut BytePacketBuffer) -> Result<Self> {
        let mut res = Self::new();
        res.header.read(buf)?;

        for _ in 0..res.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buf)?;
            res.questions.push(question);
        }
        for _ in 0..res.header.answers {
            let rec = DnsRecord::read(buf)?;
            res.answers.push(rec);
        }
        for _ in 0..res.header.authoritative_entries {
            let rec = DnsRecord::read(buf)?;
            res.authorities.push(rec);
        }
        for _ in 0..res.header.resource_entries {
            let rec = DnsRecord::read(buf)?;
            res.resources.push(rec);
        }

        Ok(res)
    }
}
