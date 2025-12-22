use serde::{Deserialize, Serialize};

use crate::protocol::errors::ProtocolError;

pub const TAG_HANDSHAKE_INIT: u8 = 1;
pub const TAG_HANDSHAKE_RESP: u8 = 2;
pub const TAG_TRANSPORT_DATA: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeInit {
    pub sender_index: u32,
    pub ephemeral: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeResp {
    pub sender_index: u32,
    pub ephemeral: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportData {
    pub receiver_index: u32,
    pub counter: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WirePacket {
    HandshakeInit(HandshakeInit),
    HandshakeResp(HandshakeResp),
    TransportData(TransportData),
}

impl WirePacket {
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::new();
        match self {
            WirePacket::HandshakeInit(init) => {
                buf.extend_from_slice(&init.sender_index.to_be_bytes());
                buf.push(TAG_HANDSHAKE_INIT);
                buf.extend_from_slice(&init.ephemeral);
                buf.extend_from_slice(&(init.payload.len() as u32).to_be_bytes());
                buf.extend_from_slice(&init.payload);
            }
            WirePacket::HandshakeResp(resp) => {
                buf.extend_from_slice(&resp.sender_index.to_be_bytes());
                buf.push(TAG_HANDSHAKE_RESP);
                buf.extend_from_slice(&resp.ephemeral);
                buf.extend_from_slice(&(resp.payload.len() as u32).to_be_bytes());
                buf.extend_from_slice(&resp.payload);
            }
            WirePacket::TransportData(data) => {
                buf.extend_from_slice(&data.receiver_index.to_be_bytes());
                buf.push(TAG_TRANSPORT_DATA);
                buf.extend_from_slice(&data.counter.to_be_bytes());
                buf.extend_from_slice(&(data.payload.len() as u32).to_be_bytes());
                buf.extend_from_slice(&data.payload);
            }
        }
        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 5 {
            return Err(ProtocolError::UnknownPacket);
        }
        let index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let tag = data[4];
        let mut offset = 5;

        match tag {
            TAG_HANDSHAKE_INIT => {
                if data.len() < offset + 32 + 4 {
                    return Err(ProtocolError::UnknownPacket);
                }
                let mut ephemeral = [0u8; 32];
                ephemeral.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                let len_bytes: [u8; 4] = data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ProtocolError::UnknownPacket)?;
                let payload_len = u32::from_be_bytes(len_bytes) as usize;
                offset += 4;
                let end = offset
                    .checked_add(payload_len)
                    .ok_or(ProtocolError::UnknownPacket)?;
                if data.len() < end {
                    return Err(ProtocolError::UnknownPacket);
                }
                let payload = data[offset..end].to_vec();
                Ok(WirePacket::HandshakeInit(HandshakeInit {
                    sender_index: index,
                    ephemeral,
                    payload,
                }))
            }
            TAG_HANDSHAKE_RESP => {
                if data.len() < offset + 32 + 4 {
                    return Err(ProtocolError::UnknownPacket);
                }
                let mut ephemeral = [0u8; 32];
                ephemeral.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                let len_bytes: [u8; 4] = data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ProtocolError::UnknownPacket)?;
                let payload_len = u32::from_be_bytes(len_bytes) as usize;
                offset += 4;
                let end = offset
                    .checked_add(payload_len)
                    .ok_or(ProtocolError::UnknownPacket)?;
                if data.len() < end {
                    return Err(ProtocolError::UnknownPacket);
                }
                let payload = data[offset..end].to_vec();
                Ok(WirePacket::HandshakeResp(HandshakeResp {
                    sender_index: index,
                    ephemeral,
                    payload,
                }))
            }
            TAG_TRANSPORT_DATA => {
                if data.len() < offset + 8 + 4 {
                    return Err(ProtocolError::UnknownPacket);
                }
                let counter_bytes: [u8; 8] = data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| ProtocolError::UnknownPacket)?;
                let counter = u64::from_be_bytes(counter_bytes);
                offset += 8;
                let len_bytes: [u8; 4] = data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ProtocolError::UnknownPacket)?;
                let payload_len = u32::from_be_bytes(len_bytes) as usize;
                offset += 4;
                let end = offset
                    .checked_add(payload_len)
                    .ok_or(ProtocolError::UnknownPacket)?;
                if data.len() < end {
                    return Err(ProtocolError::UnknownPacket);
                }
                let payload = data[offset..end].to_vec();
                Ok(WirePacket::TransportData(TransportData {
                    receiver_index: index,
                    counter,
                    payload,
                }))
            }
            _ => Err(ProtocolError::UnknownPacket),
        }
    }

    /// Serialize using serde/bincode for compatibility with tooling that expects
    /// a pure serde encoding without the manual header layout.
    pub fn serialize_bincode(&self) -> Result<Vec<u8>, ProtocolError> {
        bincode::serialize(self).map_err(ProtocolError::Serialization)
    }

    /// Deserialize a bincode-encoded packet. The primary wire format continues
    /// to use the manual header produced by `serialize`.
    pub fn deserialize_bincode(data: &[u8]) -> Result<Self, ProtocolError> {
        bincode::deserialize(data).map_err(ProtocolError::Serialization)
    }
}
