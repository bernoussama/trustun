use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Noise protocol error: {0}")]
    Snow(#[from] snow::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Packet too large")]
    PacketTooLarge,

    #[error("Unknown packet")]
    UnknownPacket,

    #[error("Invalid packet type")]
    InvalidPacketType,
}
