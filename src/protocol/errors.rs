#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("noise error: {0}")]
    Snow(#[from] snow::Error),
    #[error("serialization error")]
    Serialization,
    #[error("packet too large")]
    PacketTooLarge,
    #[error("unknown packet")]
    UnknownPacket,
    #[error("unknown peer")]
    UnknownPeer,
    #[error("replay rejected")]
    ReplayRejected,
    #[error("path unavailable")]
    PathUnavailable,
}
