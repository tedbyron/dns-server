#![warn(clippy::all, clippy::nursery, rust_2018_idioms)]

use std::fs::File;
use std::io::Read;

use anyhow::Result;

use dns_thingy::packet_parser::{BytePacketBuffer, DnsPacket};

fn main() -> Result<()> {
    let mut f = File::open("response_packet")?;
    let mut buf = BytePacketBuffer::new();
    let _ = f.read(&mut buf.buf)?;

    let packet = DnsPacket::from_buffer(&mut buf)?;
    println!("{packet:#?}");

    Ok(())
}
