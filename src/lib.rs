use std::net::SocketAddr;

// modules
pub mod cli;
pub mod config;
pub mod crypto;
pub mod net;
pub mod protocol;
pub mod tasks;

// Constants
pub const MTU: usize = 1420;
pub const TUN_MTU: usize = 1280;
pub const CHANNEL_BUFFER_SIZE: usize = 2048; // Buffered channels

// types
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Peer {
    pub sock_addr: SocketAddr,
    pub pub_key: String,
}

// errors
#[derive(thiserror::Error, Debug)]
pub enum IpouError {
    #[error("An unknown error occurred: {0}")]
    Unknown(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parsing error: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    #[error("TUN device creation failed: {0}")]
    TunDevice(#[from] tun::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] protocol::errors::ProtocolError),
    #[error("Task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}

pub type Result<T> = std::result::Result<T, IpouError>;
