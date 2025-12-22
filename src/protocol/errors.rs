use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Noise protocol error: {0}")]
    Snow(#[from] snow::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Packet too large")]
    PacketTooLarge,
    #[error("Unknown packet")]
    UnknownPacket,
}
