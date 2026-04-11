use super::errors::ProtocolError;

pub const MAX_PACKET_LEN: usize = 65_535;
const HEADER_LEN: usize = 19;

const HANDSHAKE_INIT_TAG: u8 = 1;
const HANDSHAKE_RESP_TAG: u8 = 2;
const TRANSPORT_DATA_TAG: u8 = 3;
const KEEPALIVE_TAG: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WirePacket {
    HandshakeInit {
        sender_index: u32,
        receiver_index: Option<u32>,
        noise_msg: Vec<u8>,
    },
    HandshakeResp {
        sender_index: u32,
        receiver_index: u32,
        noise_msg: Vec<u8>,
    },
    TransportData {
        receiver_index: u32,
        counter: u64,
        payload: Vec<u8>,
    },
    KeepAlive {
        receiver_index: u32,
        counter: u64,
    },
}

impl WirePacket {
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        let (tag, sender_index, receiver_index, counter, payload): (u8, u32, u32, u64, &[u8]) =
            match self {
                Self::HandshakeInit {
                    sender_index,
                    receiver_index,
                    noise_msg,
                } => (
                    HANDSHAKE_INIT_TAG,
                    *sender_index,
                    receiver_index.unwrap_or_default(),
                    0,
                    noise_msg.as_slice(),
                ),
                Self::HandshakeResp {
                    sender_index,
                    receiver_index,
                    noise_msg,
                } => (
                    HANDSHAKE_RESP_TAG,
                    *sender_index,
                    *receiver_index,
                    0,
                    noise_msg.as_slice(),
                ),
                Self::TransportData {
                    receiver_index,
                    counter,
                    payload,
                } => (
                    TRANSPORT_DATA_TAG,
                    0,
                    *receiver_index,
                    *counter,
                    payload.as_slice(),
                ),
                Self::KeepAlive {
                    receiver_index,
                    counter,
                } => (KEEPALIVE_TAG, 0u32, *receiver_index, *counter, &[][..]),
            };

        let payload_len =
            u16::try_from(payload.len()).map_err(|_| ProtocolError::PacketTooLarge)?;
        let total_len = HEADER_LEN + usize::from(payload_len);
        if total_len > MAX_PACKET_LEN {
            return Err(ProtocolError::PacketTooLarge);
        }

        let mut bytes = Vec::with_capacity(total_len);
        bytes.push(tag);
        bytes.extend_from_slice(&sender_index.to_be_bytes());
        bytes.extend_from_slice(&receiver_index.to_be_bytes());
        bytes.extend_from_slice(&counter.to_be_bytes());
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(payload);
        Ok(bytes)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtocolError::Serialization);
        }

        let tag = bytes[0];
        let sender_index = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
        let receiver_index = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
        let counter = u64::from_be_bytes(bytes[9..17].try_into().unwrap());
        let payload_len = u16::from_be_bytes(bytes[17..19].try_into().unwrap()) as usize;

        if HEADER_LEN + payload_len != bytes.len() {
            return Err(ProtocolError::Serialization);
        }

        let payload = bytes[HEADER_LEN..].to_vec();

        match tag {
            HANDSHAKE_INIT_TAG => Ok(Self::HandshakeInit {
                sender_index,
                receiver_index: (receiver_index != 0).then_some(receiver_index),
                noise_msg: payload,
            }),
            HANDSHAKE_RESP_TAG => Ok(Self::HandshakeResp {
                sender_index,
                receiver_index,
                noise_msg: payload,
            }),
            TRANSPORT_DATA_TAG => Ok(Self::TransportData {
                receiver_index,
                counter,
                payload,
            }),
            KEEPALIVE_TAG if payload.is_empty() => Ok(Self::KeepAlive {
                receiver_index,
                counter,
            }),
            KEEPALIVE_TAG => Err(ProtocolError::Serialization),
            _ => Err(ProtocolError::UnknownPacket),
        }
    }
}
