use std::collections::VecDeque;

use snow::{HandshakeState, TransportState};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::events::{Input, Output, PathId};
use crate::relay::RelayFrame;

use super::errors::ProtocolError;
use super::path::{
    path_id_for_candidate, Candidate, PathManager, PathStatus, KEEPALIVE_INTERVAL_MS, RELAY_PATH_ID,
};
use super::wire::WirePacket;

const NOISE_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const NOISE_IK_PSK2: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const NOISE_TAG_LEN: usize = 16;
const WIRE_HEADER_LEN: usize = 19;
const PROTOCOL_OVERHEAD: usize = WIRE_HEADER_LEN + NOISE_TAG_LEN;
const MAX_REPLAY_ENTRIES: usize = 1024;
const HANDSHAKE_BUFFER_LEN: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub role: PeerRole,
    pub static_private: [u8; 32],
    pub remote_public: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub mtu: usize,
    pub home_relay_path: PathId,
}

#[derive(Debug)]
pub enum PeerState {
    Handshaking {
        noise: Option<HandshakeState>,
    },
    Established {
        transport: TransportState,
        replay: ReplayWindow,
    },
}

#[derive(Debug, Default)]
pub struct ReplayWindow {
    seen: VecDeque<u64>,
}

impl ReplayWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, counter: u64) -> Result<(), ProtocolError> {
        if self.seen.contains(&counter) {
            return Err(ProtocolError::ReplayRejected);
        }

        Ok(())
    }

    pub fn record(&mut self, counter: u64) {
        self.seen.push_back(counter);
        if self.seen.len() > MAX_REPLAY_ENTRIES {
            self.seen.pop_front();
        }
    }
}

#[derive(Debug)]
pub struct Peer {
    pub state: PeerState,
    pub path_manager: PathManager,
    pub config: PeerConfig,
    local_index: u32,
    remote_index: Option<u32>,
    published_candidates: bool,
    last_probe_counter: u64,
    cached_handshake_init: Option<Vec<u8>>,
}

impl Peer {
    pub fn new(config: PeerConfig) -> Result<Self, ProtocolError> {
        let noise = build_handshake_state(&config)?;
        let local_index = derive_local_index(config.static_private);
        let path_manager = PathManager::new(config.home_relay_path.max(RELAY_PATH_ID));

        Ok(Self {
            state: PeerState::Handshaking { noise: Some(noise) },
            path_manager,
            config,
            local_index,
            remote_index: None,
            published_candidates: false,
            last_probe_counter: 0,
            cached_handshake_init: None,
        })
    }

    pub fn bootstrap(&mut self, now_ms: u64) -> Result<Vec<Output>, ProtocolError> {
        let mut outputs = Vec::new();
        if !self.published_candidates {
            self.published_candidates = true;
            outputs.push(Output::PublishLocalCandidates);
        }

        if self.config.role != PeerRole::Initiator {
            return Ok(outputs);
        }

        let Some(noise) = self.handshake_mut() else {
            return Ok(outputs);
        };
        if !noise.is_my_turn() {
            return Ok(outputs);
        }

        let mut message = vec![0u8; HANDSHAKE_BUFFER_LEN];
        let len = noise.write_message(&[], &mut message)?;
        message.truncate(len);

        let packet = WirePacket::HandshakeInit {
            sender_index: self.local_index,
            receiver_index: self.remote_index,
            noise_msg: message,
        };
        self.cached_handshake_init = Some(packet.serialize()?);
        let active_path = self.path_manager.active_path();
        outputs.push(self.emit_packet(active_path, packet)?);
        self.path_manager.record_send(active_path, now_ms);
        self.promote_handshake_if_finished()?;
        Ok(outputs)
    }

    pub fn tick(&mut self, input: Input) -> Result<Vec<Output>, ProtocolError> {
        match input {
            Input::NetworkRx {
                path,
                bytes,
                now_ms,
            } => self.handle_network_rx(path, bytes, now_ms),
            Input::TunRx(packet) => self.handle_tun_rx(packet),
            Input::Tick { now_ms } => self.handle_tick(now_ms),
            Input::CandidatesUpdated { candidates, .. } => {
                self.handle_candidates_updated(candidates)
            }
        }
    }

    fn handle_tun_rx(&mut self, packet: Vec<u8>) -> Result<Vec<Output>, ProtocolError> {
        let PeerState::Established { transport, .. } = &mut self.state else {
            return Ok(Vec::new());
        };

        if packet.len() > self.config.mtu.saturating_sub(PROTOCOL_OVERHEAD) {
            return Err(ProtocolError::PacketTooLarge);
        }

        let receiver_index = self.remote_index.ok_or(ProtocolError::UnknownPeer)?;
        let counter = transport.sending_nonce();
        let mut ciphertext = vec![0u8; packet.len() + NOISE_TAG_LEN];
        let len = transport.write_message(&packet, &mut ciphertext)?;
        ciphertext.truncate(len);

        let active_path = self.path_manager.active_path();
        let output = self.emit_packet(
            active_path,
            WirePacket::TransportData {
                receiver_index,
                counter,
                payload: ciphertext,
            },
        )?;

        Ok(vec![output])
    }

    fn handle_network_rx(
        &mut self,
        path: PathId,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<Vec<Output>, ProtocolError> {
        match WirePacket::deserialize(&bytes)? {
            WirePacket::HandshakeInit {
                sender_index,
                receiver_index: _,
                noise_msg,
            } => self.handle_handshake_init(path, sender_index, noise_msg, now_ms),
            WirePacket::HandshakeResp {
                sender_index,
                receiver_index,
                noise_msg,
            } => self.handle_handshake_resp(path, sender_index, receiver_index, noise_msg, now_ms),
            WirePacket::TransportData {
                receiver_index,
                counter,
                payload,
            } => self.handle_transport_data(path, receiver_index, counter, payload, now_ms),
            WirePacket::KeepAlive {
                receiver_index,
                counter,
            } => self.handle_keepalive(path, receiver_index, counter, now_ms),
        }
    }

    fn handle_handshake_init(
        &mut self,
        path: PathId,
        sender_index: u32,
        noise_msg: Vec<u8>,
        now_ms: u64,
    ) -> Result<Vec<Output>, ProtocolError> {
        self.remote_index = Some(sender_index);
        let Some(noise) = self.handshake_mut() else {
            return Ok(Vec::new());
        };

        let mut payload = vec![0u8; HANDSHAKE_BUFFER_LEN];
        noise.read_message(&noise_msg, &mut payload)?;

        let mut outputs = Vec::new();
        if noise.is_my_turn() {
            let mut response = vec![0u8; HANDSHAKE_BUFFER_LEN];
            let len = noise.write_message(&[], &mut response)?;
            response.truncate(len);

            outputs.push(self.emit_packet(
                path,
                WirePacket::HandshakeResp {
                    sender_index: self.local_index,
                    receiver_index: sender_index,
                    noise_msg: response,
                },
            )?);
        }

        self.promote_handshake_if_finished()?;
        self.path_manager.record_authenticated_rx(path, now_ms);
        if path != self.path_manager.home_relay_path() {
            self.path_manager.switch_active_path(path);
        }
        Ok(outputs)
    }

    fn handle_handshake_resp(
        &mut self,
        path: PathId,
        sender_index: u32,
        receiver_index: u32,
        noise_msg: Vec<u8>,
        now_ms: u64,
    ) -> Result<Vec<Output>, ProtocolError> {
        if receiver_index != self.local_index {
            return Err(ProtocolError::UnknownPeer);
        }

        self.remote_index = Some(sender_index);
        let Some(noise) = self.handshake_mut() else {
            return Ok(Vec::new());
        };

        let mut payload = vec![0u8; HANDSHAKE_BUFFER_LEN];
        noise.read_message(&noise_msg, &mut payload)?;
        self.promote_handshake_if_finished()?;
        self.path_manager.record_authenticated_rx(path, now_ms);

        if path != self.path_manager.home_relay_path() {
            self.path_manager.switch_active_path(path);
        }
        Ok(Vec::new())
    }

    fn handle_transport_data(
        &mut self,
        path: PathId,
        receiver_index: u32,
        counter: u64,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<Vec<Output>, ProtocolError> {
        if receiver_index != self.local_index {
            return Err(ProtocolError::UnknownPeer);
        }

        let PeerState::Established { transport, replay } = &mut self.state else {
            return Err(ProtocolError::UnknownPacket);
        };

        replay.check(counter)?;
        transport.set_receiving_nonce(counter);
        let mut plaintext = vec![0u8; payload.len()];
        let len = transport.read_message(&payload, &mut plaintext)?;
        plaintext.truncate(len);
        replay.record(counter);
        self.path_manager.record_authenticated_rx(path, now_ms);

        if path != self.path_manager.home_relay_path() {
            self.path_manager.switch_active_path(path);
        }

        Ok(vec![Output::TunTx(plaintext)])
    }

    fn handle_keepalive(
        &mut self,
        path: PathId,
        receiver_index: u32,
        counter: u64,
        now_ms: u64,
    ) -> Result<Vec<Output>, ProtocolError> {
        if receiver_index != self.local_index {
            return Err(ProtocolError::UnknownPeer);
        }

        match &mut self.state {
            PeerState::Established { replay, .. } => {
                replay.check(counter)?;
                replay.record(counter);
            }
            PeerState::Handshaking { .. } => return Err(ProtocolError::UnknownPacket),
        }

        self.path_manager.record_authenticated_rx(path, now_ms);
        if path != self.path_manager.home_relay_path() {
            self.path_manager.switch_active_path(path);
        }
        Ok(Vec::new())
    }

    fn handle_candidates_updated(
        &mut self,
        candidates: Vec<Candidate>,
    ) -> Result<Vec<Output>, ProtocolError> {
        let mut outputs = Vec::new();

        for candidate in candidates {
            let Some(path) = path_id_for_candidate(&candidate) else {
                continue;
            };
            self.path_manager.add_candidate(&candidate);
            self.path_manager
                .mark_path_status(path, PathStatus::Probing);

            match &self.state {
                PeerState::Handshaking { .. } => {
                    if let Some(bytes) = &self.cached_handshake_init {
                        outputs.push(Output::NetworkTx {
                            path,
                            bytes: bytes.clone(),
                        });
                    }
                }
                PeerState::Established { .. } => outputs.push(self.emit_keepalive(path)?),
            }
        }

        Ok(outputs)
    }

    fn handle_tick(&mut self, now_ms: u64) -> Result<Vec<Output>, ProtocolError> {
        let mut outputs = Vec::new();
        if !self.published_candidates {
            self.published_candidates = true;
            outputs.push(Output::PublishLocalCandidates);
        }

        if self.path_manager.active_direct_path_timed_out(now_ms) {
            let active_path = self.path_manager.active_path();
            self.path_manager.fail_path(active_path);
            outputs.push(Output::Log(
                "direct path timed out; falling back to relay".to_string(),
            ));
        }

        if matches!(self.state, PeerState::Established { .. })
            && self.path_manager.active_path_idle_for(now_ms) >= KEEPALIVE_INTERVAL_MS
        {
            outputs.push(self.emit_keepalive(self.path_manager.active_path())?);
            self.path_manager
                .record_probe(self.path_manager.active_path(), now_ms);
        }

        if matches!(self.state, PeerState::Established { .. }) {
            for path in self.path_manager.direct_paths_needing_probe(now_ms) {
                outputs.push(self.emit_keepalive(path)?);
                self.path_manager.record_probe(path, now_ms);
            }
        }

        Ok(outputs)
    }

    fn emit_packet(&self, path: PathId, packet: WirePacket) -> Result<Output, ProtocolError> {
        let bytes = packet.serialize()?;
        if path == self.path_manager.home_relay_path() {
            let frame = RelayFrame::SendPacket {
                dst_pubkey: self.config.remote_public,
                packet: bytes,
            }
            .serialize()
            .map_err(|_| ProtocolError::Serialization)?;
            Ok(Output::RelayTx {
                relay_path: path,
                frame,
            })
        } else {
            Ok(Output::NetworkTx { path, bytes })
        }
    }

    fn emit_keepalive(&mut self, path: PathId) -> Result<Output, ProtocolError> {
        let receiver_index = self.remote_index.ok_or(ProtocolError::UnknownPeer)?;
        self.last_probe_counter = self.last_probe_counter.wrapping_add(1);
        self.emit_packet(
            path,
            WirePacket::KeepAlive {
                receiver_index,
                counter: self.last_probe_counter,
            },
        )
    }

    fn handshake_mut(&mut self) -> Option<&mut HandshakeState> {
        match &mut self.state {
            PeerState::Handshaking { noise } => noise.as_mut(),
            PeerState::Established { .. } => None,
        }
    }

    fn promote_handshake_if_finished(&mut self) -> Result<(), ProtocolError> {
        let finished = match &self.state {
            PeerState::Handshaking { noise } => noise
                .as_ref()
                .map(|noise| noise.is_handshake_finished())
                .unwrap_or(false),
            PeerState::Established { .. } => false,
        };

        if !finished {
            return Ok(());
        }

        let PeerState::Handshaking { noise } = &mut self.state else {
            return Ok(());
        };
        let handshake = noise.take().ok_or(ProtocolError::Serialization)?;
        let transport = handshake.into_transport_mode()?;
        self.state = PeerState::Established {
            transport,
            replay: ReplayWindow::new(),
        };
        Ok(())
    }
}

fn build_handshake_state(config: &PeerConfig) -> Result<HandshakeState, ProtocolError> {
    let pattern = if config.psk.is_some() {
        NOISE_IK_PSK2
    } else {
        NOISE_IK
    };

    let params = pattern.parse()?;
    let builder = snow::Builder::new(params)
        .local_private_key(&config.static_private)?
        .remote_public_key(&config.remote_public)?;

    let builder = if let Some(psk) = &config.psk {
        builder.psk(2, psk)?
    } else {
        builder
    };

    match config.role {
        PeerRole::Initiator => Ok(builder.build_initiator()?),
        PeerRole::Responder => Ok(builder.build_responder()?),
    }
}

fn derive_local_index(static_private: [u8; 32]) -> u32 {
    let public = PublicKey::from(&StaticSecret::from(static_private)).to_bytes();
    let index = u32::from_be_bytes(public[..4].try_into().unwrap());
    if index == 0 {
        1
    } else {
        index
    }
}
