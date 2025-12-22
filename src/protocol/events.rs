use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug)]
pub enum Input {
    UdpPacket(Vec<u8>, SocketAddr),
    TunPacket(Vec<u8>),
    Tick(Instant),
}

#[derive(Debug, PartialEq)]
pub enum Output {
    SendUdp(Vec<u8>, SocketAddr),
    WriteTun(Vec<u8>),
    Log(String),
}
