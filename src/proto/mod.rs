use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{crypto::PublicKeyBytes, sans_io::SansIo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Packet {
    HandshakeInit {
        sender_pubkey: PublicKeyBytes,
        timestamp: u64,
    },
    HandshakeResponse {
        success: bool,
        message: String,
    },
    RequestPeer {
        target_pubkey: PublicKeyBytes,
    },
    PeerInfo {
        pubkey: PublicKeyBytes,
        endpoint: Option<SocketAddr>,
        last_seen: u64,
    },
    KeepAlive {
        timestamp: u64,
    },
    VpnData(Vec<u8>),
}
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {}

/// Wire format for Packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePacket {
    /// Quick discriminant
    pub packet_type: u8,
    /// encrypted Packet
    pub payload: Vec<u8>,
}

impl SansIo for WirePacket {
    type Error = WireError;

    fn consume(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        todo!()
    }

    fn take_output(&mut self) -> Vec<u8> {
        todo!()
    }
}
