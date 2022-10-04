use anyhow::{bail, Result};

use crate::packet_parser::{
    BytePacketBuffer, DnsHeader, DnsPacket, DnsQuestion, DnsRecord, QueryType,
};

impl BytePacketBuffer {
    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            bail!("End of buf");
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                bail!("Label exceeds 63 character limit");
            }

            self.write_u8(len as u8)?;
            for &b in label.as_bytes() {
                self.write_u8(b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}

impl DnsHeader {
    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<()> {
        buf.write_u16(self.id)?;

        buf.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buf.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buf.write_u16(self.questions)?;
        buf.write_u16(self.answers)?;
        buf.write_u16(self.authoritative_entries)?;
        buf.write_u16(self.resource_entries)?;

        Ok(())
    }
}

impl DnsQuestion {
    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<()> {
        buf.write_qname(&self.name)?;
        buf.write_u16(self.qtype.into())?;
        buf.write_u16(1)?;

        Ok(())
    }
}

impl DnsRecord {
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            Self::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            Self::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

impl DnsPacket {
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}
