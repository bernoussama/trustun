use std::net::SocketAddr;

#[derive(Debug)]
pub enum TunInput<'a> {
    Packet(&'a [u8]),
}

#[derive(Debug)]
pub enum TunOutput {
    Encrypted {
        data: Vec<u8>,
        target: SocketAddr,
    },
    Drop(String),
}

#[derive(Debug)]
pub enum UdpInput<'a> {
    Packet(&'a [u8], SocketAddr),
}

#[derive(Debug)]
pub enum UdpOutput {
    Decrypted(Vec<u8>),
    Drop(String),
}
