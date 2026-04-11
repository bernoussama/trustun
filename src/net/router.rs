use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::config::Config;
use crate::control::coord::{CandidateRecord, CoordMessage};
use crate::protocol::{
    path_id_for_addr, Candidate, Input, Output, PathId, Peer, PeerConfig, PeerId, PeerRole,
    ProtocolError, RELAY_PATH_ID,
};
use crate::relay::RelayFrame;

#[derive(Debug, Clone)]
pub enum RuntimeAction {
    UdpSend { addr: SocketAddr, bytes: Vec<u8> },
    RelaySend { frame: Vec<u8> },
    TunSend(Vec<u8>),
    CoordSend(CoordMessage),
    Log(String),
}

#[derive(Debug)]
struct PeerEntry {
    remote_pubkey: [u8; 32],
    peer: Peer,
    direct_paths: HashMap<PathId, SocketAddr>,
    static_endpoint: SocketAddr,
}

#[derive(Debug)]
pub struct Router {
    local_pubkey: [u8; 32],
    peers: HashMap<PeerId, PeerEntry>,
    peer_by_tunnel_ip: HashMap<IpAddr, PeerId>,
    peer_by_pubkey: HashMap<[u8; 32], PeerId>,
    peer_by_endpoint: HashMap<SocketAddr, PeerId>,
    local_candidates: Vec<Candidate>,
}

impl Router {
    pub fn from_config(config: &Config) -> crate::Result<Self> {
        let local_pubkey = decode_key(&config.pubkey)?;
        let local_secret = decode_key(&config.secret)?;

        let mut peers = HashMap::new();
        let mut peer_by_tunnel_ip = HashMap::new();
        let mut peer_by_pubkey = HashMap::new();
        let mut peer_by_endpoint = HashMap::new();

        for (index, (tunnel_ip, peer_conf)) in config.peers.iter().enumerate() {
            let peer_id = (index as PeerId) + 1;
            let remote_pubkey = decode_key(&peer_conf.pub_key)?;
            let role = if local_pubkey < remote_pubkey {
                PeerRole::Initiator
            } else {
                PeerRole::Responder
            };
            let peer = Peer::new(PeerConfig {
                role,
                static_private: local_secret,
                remote_public: remote_pubkey,
                psk: None,
                mtu: config.mtu,
                home_relay_path: RELAY_PATH_ID,
            })?;

            let static_path = path_id_for_addr(peer_conf.sock_addr);
            let mut direct_paths = HashMap::new();
            direct_paths.insert(static_path, peer_conf.sock_addr);

            let entry = PeerEntry {
                remote_pubkey,
                peer,
                direct_paths,
                static_endpoint: peer_conf.sock_addr,
            };

            peers.insert(peer_id, entry);
            peer_by_tunnel_ip.insert(*tunnel_ip, peer_id);
            peer_by_pubkey.insert(remote_pubkey, peer_id);
            peer_by_endpoint.insert(peer_conf.sock_addr, peer_id);
        }

        Ok(Self {
            local_pubkey,
            peers,
            peer_by_tunnel_ip,
            peer_by_pubkey,
            peer_by_endpoint,
            local_candidates: Vec::new(),
        })
    }

    #[must_use]
    pub fn local_pubkey(&self) -> [u8; 32] {
        self.local_pubkey
    }

    pub fn set_local_candidates(&mut self, candidates: Vec<Candidate>) {
        self.local_candidates = candidates;
    }

    pub fn bootstrap(&mut self, now_ms: u64) -> Result<Vec<RuntimeAction>, ProtocolError> {
        let mut actions = Vec::new();
        let peer_ids: Vec<_> = self.peers.keys().copied().collect();
        for peer_id in peer_ids {
            let static_endpoint = self.peers.get(&peer_id).unwrap().static_endpoint;
            actions.extend(
                self.update_remote_candidates(peer_id, vec![Candidate::Lan(static_endpoint)])?,
            );
            let outputs = self
                .peers
                .get_mut(&peer_id)
                .unwrap()
                .peer
                .bootstrap(now_ms)?;
            actions.extend(self.translate_outputs(peer_id, outputs));
        }
        Ok(actions)
    }

    pub fn publish_local_candidates(&self) -> Vec<RuntimeAction> {
        self.peers
            .values()
            .map(|entry| {
                RuntimeAction::CoordSend(CoordMessage::PublishCandidates {
                    pubkey: base64::encode(self.local_pubkey),
                    peer_pubkey: base64::encode(entry.remote_pubkey),
                    candidates: self
                        .local_candidates
                        .iter()
                        .map(CandidateRecord::from)
                        .collect(),
                })
            })
            .collect()
    }

    pub fn handle_tun_packet(
        &mut self,
        packet: Vec<u8>,
    ) -> Result<Vec<RuntimeAction>, ProtocolError> {
        let Some(dst_ip) = extract_dst_ip(&packet) else {
            return Ok(Vec::new());
        };
        let Some(peer_id) = self.peer_by_tunnel_ip.get(&dst_ip).copied() else {
            return Ok(vec![RuntimeAction::Log(format!(
                "no peer for tunnel destination {dst_ip}"
            ))]);
        };

        let outputs = self
            .peers
            .get_mut(&peer_id)
            .unwrap()
            .peer
            .tick(Input::TunRx(packet))?;
        Ok(self.translate_outputs(peer_id, outputs))
    }

    pub fn handle_udp_datagram(
        &mut self,
        peer_addr: SocketAddr,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<Vec<RuntimeAction>, ProtocolError> {
        let Some(peer_id) = self.peer_by_endpoint.get(&peer_addr).copied() else {
            return Ok(vec![RuntimeAction::Log(format!(
                "ignoring datagram from unknown endpoint {peer_addr}"
            ))]);
        };

        let path = path_id_for_addr(peer_addr);
        let outputs = self
            .peers
            .get_mut(&peer_id)
            .unwrap()
            .peer
            .tick(Input::NetworkRx {
                path,
                bytes,
                now_ms,
            })?;

        self.peers
            .get_mut(&peer_id)
            .unwrap()
            .direct_paths
            .insert(path, peer_addr);
        self.peer_by_endpoint.insert(peer_addr, peer_id);

        Ok(self.translate_outputs(peer_id, outputs))
    }

    pub fn handle_relay_frame(
        &mut self,
        frame: RelayFrame,
        now_ms: u64,
    ) -> Result<Vec<RuntimeAction>, ProtocolError> {
        let RelayFrame::RecvPacket { src_pubkey, packet } = frame else {
            return Ok(Vec::new());
        };

        let Some(peer_id) = self.peer_by_pubkey.get(&src_pubkey).copied() else {
            return Ok(vec![RuntimeAction::Log(
                "ignoring relay packet for unknown peer".to_string(),
            )]);
        };

        let outputs = self
            .peers
            .get_mut(&peer_id)
            .unwrap()
            .peer
            .tick(Input::NetworkRx {
                path: RELAY_PATH_ID,
                bytes: packet,
                now_ms,
            })?;
        Ok(self.translate_outputs(peer_id, outputs))
    }

    pub fn handle_coord_message(
        &mut self,
        message: CoordMessage,
    ) -> Result<Vec<RuntimeAction>, ProtocolError> {
        let CoordMessage::PeerCandidates {
            peer_pubkey,
            candidates,
        } = message
        else {
            return Ok(Vec::new());
        };

        let remote_pubkey = decode_key(&peer_pubkey).map_err(|_| ProtocolError::UnknownPeer)?;
        let Some(peer_id) = self.peer_by_pubkey.get(&remote_pubkey).copied() else {
            return Err(ProtocolError::UnknownPeer);
        };

        let converted = candidates
            .into_iter()
            .filter_map(|candidate| Candidate::try_from(candidate).ok())
            .collect();
        self.update_remote_candidates(peer_id, converted)
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<RuntimeAction>, ProtocolError> {
        let mut actions = Vec::new();
        let peer_ids: Vec<_> = self.peers.keys().copied().collect();
        for peer_id in peer_ids {
            let outputs = self
                .peers
                .get_mut(&peer_id)
                .unwrap()
                .peer
                .tick(Input::Tick { now_ms })?;
            actions.extend(self.translate_outputs(peer_id, outputs));
        }
        Ok(actions)
    }

    fn update_remote_candidates(
        &mut self,
        peer_id: PeerId,
        candidates: Vec<Candidate>,
    ) -> Result<Vec<RuntimeAction>, ProtocolError> {
        let entry = self.peers.get_mut(&peer_id).unwrap();
        for candidate in &candidates {
            if let Some(addr) = candidate.socket_addr() {
                let path = path_id_for_addr(addr);
                entry.direct_paths.insert(path, addr);
                self.peer_by_endpoint.insert(addr, peer_id);
            }
        }

        let outputs = entry.peer.tick(Input::CandidatesUpdated {
            peer: peer_id,
            candidates,
        })?;
        Ok(self.translate_outputs(peer_id, outputs))
    }

    fn translate_outputs(&self, peer_id: PeerId, outputs: Vec<Output>) -> Vec<RuntimeAction> {
        let entry = self.peers.get(&peer_id).unwrap();
        outputs
            .into_iter()
            .flat_map(|output| match output {
                Output::NetworkTx { path, bytes } => entry
                    .direct_paths
                    .get(&path)
                    .copied()
                    .map(|addr| vec![RuntimeAction::UdpSend { addr, bytes }])
                    .unwrap_or_else(|| {
                        vec![RuntimeAction::Log(format!(
                            "missing endpoint for path {path}"
                        ))]
                    }),
                Output::RelayTx { frame, .. } => vec![RuntimeAction::RelaySend { frame }],
                Output::TunTx(packet) => vec![RuntimeAction::TunSend(packet)],
                Output::PublishLocalCandidates => self.publish_local_candidates(),
                Output::Log(message) => vec![RuntimeAction::Log(message)],
            })
            .collect()
    }
}

fn decode_key(value: &str) -> crate::Result<[u8; 32]> {
    let decoded = base64::decode(value)?;
    if decoded.len() != 32 {
        return Err(crate::IpouError::InvalidKeyLength(decoded.len()));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }

    Some(IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    )))
}
