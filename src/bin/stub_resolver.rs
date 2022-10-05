use std::net::UdpSocket;

use anyhow::Result;

use dns_thingy::packet_parser::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType};

fn main() -> Result<()> {
    let qname = "google.com";
    let qtype = QueryType::A;
    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 1234))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buf = BytePacketBuffer::new();
    packet.write(&mut req_buf)?;

    socket.send_to(&req_buf.buf[0..req_buf.pos], server)?;

    let mut res_buf = BytePacketBuffer::new();
    socket.recv_from(&mut res_buf.buf)?;

    let res_packet = DnsPacket::from_buffer(&mut res_buf)?;
    println!("{res_packet:#?}");

    Ok(())
}
