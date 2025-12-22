use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

#[derive(Debug, Clone, PartialEq)]
pub enum WirePacket {
    HandshakeInit {
        sender_index: u32,
        ephemeral: [u8; 32],
        payload: Vec<u8>,
    },
    HandshakeResp {
        sender_index: u32,
        ephemeral: [u8; 32],
        payload: Vec<u8>,
    },
    TransportData {
        receiver_index: u32,
        counter: u64,
        payload: Vec<u8>,
    },
}

impl WirePacket {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            WirePacket::HandshakeInit {
                sender_index,
                ephemeral,
                payload,
            } => {
                buf.push(1); // Type
                buf.write_u32::<BigEndian>(*sender_index).unwrap();
                buf.extend_from_slice(ephemeral);
                buf.extend_from_slice(payload);
            }
            WirePacket::HandshakeResp {
                sender_index,
                ephemeral,
                payload,
            } => {
                buf.push(2); // Type
                buf.write_u32::<BigEndian>(*sender_index).unwrap();
                buf.extend_from_slice(ephemeral);
                buf.extend_from_slice(payload);
            }
            WirePacket::TransportData {
                receiver_index,
                counter,
                payload,
            } => {
                buf.push(3); // Type
                buf.write_u32::<BigEndian>(*receiver_index).unwrap();
                buf.write_u64::<BigEndian>(*counter).unwrap();
                buf.extend_from_slice(payload);
            }
        }
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<WirePacket, &'static str> {
        if data.is_empty() {
            return Err("Empty packet");
        }
        let type_byte = data[0];
        let mut cursor = Cursor::new(&data[1..]);

        match type_byte {
            1 => {
                // HandshakeInit
                if data.len() < 1 + 4 + 32 {
                    return Err("Packet too short for HandshakeInit");
                }
                let sender_index = cursor.read_u32::<BigEndian>().map_err(|_| "Read error")?;
                let mut ephemeral = [0u8; 32];
                cursor
                    .read_exact(&mut ephemeral)
                    .map_err(|_| "Read error")?;

                let mut payload = Vec::new();
                cursor.read_to_end(&mut payload).map_err(|_| "Read error")?;

                Ok(WirePacket::HandshakeInit {
                    sender_index,
                    ephemeral,
                    payload,
                })
            }
            2 => {
                // HandshakeResp
                if data.len() < 1 + 4 + 32 {
                    return Err("Packet too short for HandshakeResp");
                }
                let sender_index = cursor.read_u32::<BigEndian>().map_err(|_| "Read error")?;
                let mut ephemeral = [0u8; 32];
                cursor
                    .read_exact(&mut ephemeral)
                    .map_err(|_| "Read error")?;

                let mut payload = Vec::new();
                cursor.read_to_end(&mut payload).map_err(|_| "Read error")?;

                Ok(WirePacket::HandshakeResp {
                    sender_index,
                    ephemeral,
                    payload,
                })
            }
            3 => {
                // TransportData
                if data.len() < 1 + 4 + 8 {
                    return Err("Packet too short for TransportData");
                }
                let receiver_index = cursor.read_u32::<BigEndian>().map_err(|_| "Read error")?;
                let counter = cursor.read_u64::<BigEndian>().map_err(|_| "Read error")?;

                let mut payload = Vec::new();
                cursor.read_to_end(&mut payload).map_err(|_| "Read error")?;

                Ok(WirePacket::TransportData {
                    receiver_index,
                    counter,
                    payload,
                })
            }
            _ => Err("Unknown packet type"),
        }
    }
}
