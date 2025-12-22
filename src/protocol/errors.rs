use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("snow error: {0}")]
    Snow(#[from] snow::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("packet too large")]
    PacketTooLarge,
    #[error("unknown packet")]
    UnknownPacket,
}
