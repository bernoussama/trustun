use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeInit {
    pub sender_index: u32,
    pub ephemeral: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeResp {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransportData {
    pub receiver_index: u32,
    pub counter: u64,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WirePacket {
    HandshakeInit(HandshakeInit),
    HandshakeResp(HandshakeResp),
    TransportData(TransportData),
}
