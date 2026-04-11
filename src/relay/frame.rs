#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayError {
    #[error("relay payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("unknown relay frame")]
    UnknownFrame,
    #[error("truncated relay frame")]
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    SendPacket {
        dst_pubkey: [u8; 32],
        packet: Vec<u8>,
    },
    RecvPacket {
        src_pubkey: [u8; 32],
        packet: Vec<u8>,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    PeerPresent {
        pubkey: [u8; 32],
    },
}

impl RelayFrame {
    pub fn serialize(&self) -> Result<Vec<u8>, RelayError> {
        let (frame_type, payload_len, write_payload): (u8, usize, Box<dyn FnOnce(&mut Vec<u8>)>) =
            match self {
                Self::SendPacket { dst_pubkey, packet } => {
                    let dst_pubkey = *dst_pubkey;
                    let packet = packet.clone();
                    (
                        1,
                        32 + packet.len(),
                        Box::new(move |bytes| {
                            bytes.extend_from_slice(&dst_pubkey);
                            bytes.extend_from_slice(&packet);
                        }),
                    )
                }
                Self::RecvPacket { src_pubkey, packet } => {
                    let src_pubkey = *src_pubkey;
                    let packet = packet.clone();
                    (
                        2,
                        32 + packet.len(),
                        Box::new(move |bytes| {
                            bytes.extend_from_slice(&src_pubkey);
                            bytes.extend_from_slice(&packet);
                        }),
                    )
                }
                Self::Ping { nonce } => {
                    let nonce = *nonce;
                    (
                        3,
                        8,
                        Box::new(move |bytes| bytes.extend_from_slice(&nonce.to_be_bytes())),
                    )
                }
                Self::Pong { nonce } => {
                    let nonce = *nonce;
                    (
                        4,
                        8,
                        Box::new(move |bytes| bytes.extend_from_slice(&nonce.to_be_bytes())),
                    )
                }
                Self::PeerPresent { pubkey } => {
                    let pubkey = *pubkey;
                    (
                        5,
                        32,
                        Box::new(move |bytes| bytes.extend_from_slice(&pubkey)),
                    )
                }
            };

        let payload_len_u32 =
            u32::try_from(payload_len).map_err(|_| RelayError::PayloadTooLarge(payload_len))?;
        let mut bytes = Vec::with_capacity(1 + 4 + payload_len);
        bytes.push(frame_type);
        bytes.extend_from_slice(&payload_len_u32.to_be_bytes());
        write_payload(&mut bytes);
        Ok(bytes)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, RelayError> {
        if bytes.len() < 5 {
            return Err(RelayError::Truncated);
        }

        let frame_type = bytes[0];
        let payload_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        if bytes.len() != 5 + payload_len {
            return Err(RelayError::Truncated);
        }

        let payload = &bytes[5..];
        match frame_type {
            1 => {
                if payload.len() < 32 {
                    return Err(RelayError::Truncated);
                }
                let mut dst_pubkey = [0u8; 32];
                dst_pubkey.copy_from_slice(&payload[..32]);
                Ok(Self::SendPacket {
                    dst_pubkey,
                    packet: payload[32..].to_vec(),
                })
            }
            2 => {
                if payload.len() < 32 {
                    return Err(RelayError::Truncated);
                }
                let mut src_pubkey = [0u8; 32];
                src_pubkey.copy_from_slice(&payload[..32]);
                Ok(Self::RecvPacket {
                    src_pubkey,
                    packet: payload[32..].to_vec(),
                })
            }
            3 | 4 => {
                if payload.len() != 8 {
                    return Err(RelayError::Truncated);
                }
                let nonce = u64::from_be_bytes(payload.try_into().unwrap());
                if frame_type == 3 {
                    Ok(Self::Ping { nonce })
                } else {
                    Ok(Self::Pong { nonce })
                }
            }
            5 => {
                if payload.len() != 32 {
                    return Err(RelayError::Truncated);
                }
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(payload);
                Ok(Self::PeerPresent { pubkey })
            }
            _ => Err(RelayError::UnknownFrame),
        }
    }
}
