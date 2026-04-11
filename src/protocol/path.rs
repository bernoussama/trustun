use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use super::events::PathId;

pub const KEEPALIVE_INTERVAL_MS: u64 = 15_000;
pub const PROBE_INTERVAL_MS: u64 = 5_000;
pub const DIRECT_PATH_TIMEOUT_MS: u64 = 30_000;
pub const RELAY_PATH_ID: PathId = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    Lan(SocketAddr),
    Reflexive(SocketAddr),
    Relay,
}

impl Candidate {
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Lan(addr) | Self::Reflexive(addr) => Some(*addr),
            Self::Relay => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    Unknown,
    Probing,
    Healthy,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathInfo {
    pub id: PathId,
    pub kind: PathKind,
    pub status: PathStatus,
    pub last_probe_ms: u64,
    pub last_send_ms: u64,
    pub last_recv_ms: u64,
}

#[derive(Debug, Clone)]
pub struct PathManager {
    home_relay_path: PathId,
    active_path: PathId,
    paths: HashMap<PathId, PathInfo>,
}

impl PathManager {
    #[must_use]
    pub fn new(home_relay_path: PathId) -> Self {
        let mut paths = HashMap::new();
        paths.insert(
            home_relay_path,
            PathInfo {
                id: home_relay_path,
                kind: PathKind::Relay,
                status: PathStatus::Healthy,
                last_probe_ms: 0,
                last_send_ms: 0,
                last_recv_ms: 0,
            },
        );

        Self {
            home_relay_path,
            active_path: home_relay_path,
            paths,
        }
    }

    #[must_use]
    pub fn home_relay_path(&self) -> PathId {
        self.home_relay_path
    }

    #[must_use]
    pub fn active_path(&self) -> PathId {
        self.active_path
    }

    #[must_use]
    pub fn active_kind(&self) -> PathKind {
        self.paths
            .get(&self.active_path)
            .map(|info| info.kind)
            .unwrap_or(PathKind::Relay)
    }

    pub fn add_candidate(&mut self, candidate: &Candidate) -> Option<PathId> {
        let path = path_id_for_candidate(candidate)?;
        self.paths.entry(path).or_insert(PathInfo {
            id: path,
            kind: PathKind::Direct,
            status: PathStatus::Unknown,
            last_probe_ms: 0,
            last_send_ms: 0,
            last_recv_ms: 0,
        });
        Some(path)
    }

    pub fn mark_path_status(&mut self, path: PathId, status: PathStatus) {
        if let Some(info) = self.paths.get_mut(&path) {
            info.status = status;
        }
    }

    pub fn switch_active_path(&mut self, path: PathId) {
        if self.paths.contains_key(&path) {
            self.active_path = path;
        }
    }

    pub fn record_send(&mut self, path: PathId, now_ms: u64) {
        if let Some(info) = self.paths.get_mut(&path) {
            info.last_send_ms = now_ms;
        }
    }

    pub fn record_probe(&mut self, path: PathId, now_ms: u64) {
        if let Some(info) = self.paths.get_mut(&path) {
            info.last_probe_ms = now_ms;
            info.last_send_ms = now_ms;
            if info.kind == PathKind::Direct && info.status != PathStatus::Healthy {
                info.status = PathStatus::Probing;
            }
        }
    }

    pub fn record_authenticated_rx(&mut self, path: PathId, now_ms: u64) {
        if let Some(info) = self.paths.get_mut(&path) {
            info.last_recv_ms = now_ms;
            info.status = PathStatus::Healthy;
        }
    }

    #[must_use]
    pub fn direct_paths_needing_probe(&self, now_ms: u64) -> Vec<PathId> {
        self.paths
            .values()
            .filter(|info| info.kind == PathKind::Direct)
            .filter(|info| now_ms.saturating_sub(info.last_probe_ms) >= PROBE_INTERVAL_MS)
            .map(|info| info.id)
            .collect()
    }

    #[must_use]
    pub fn active_path_idle_for(&self, now_ms: u64) -> u64 {
        self.paths
            .get(&self.active_path)
            .map(|info| now_ms.saturating_sub(info.last_send_ms.max(info.last_recv_ms)))
            .unwrap_or_default()
    }

    #[must_use]
    pub fn active_direct_path_timed_out(&self, now_ms: u64) -> bool {
        self.paths
            .get(&self.active_path)
            .filter(|info| info.kind == PathKind::Direct)
            .map(|info| now_ms.saturating_sub(info.last_recv_ms) >= DIRECT_PATH_TIMEOUT_MS)
            .unwrap_or(false)
    }

    pub fn fail_path(&mut self, path: PathId) {
        if let Some(info) = self.paths.get_mut(&path) {
            info.status = PathStatus::Failed;
            if self.active_path == path {
                self.active_path = self.home_relay_path;
            }
        }
    }
}

#[must_use]
pub fn path_id_for_candidate(candidate: &Candidate) -> Option<PathId> {
    candidate.socket_addr().map(path_id_for_addr)
}

#[must_use]
pub fn path_id_for_addr(addr: SocketAddr) -> PathId {
    match addr.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let mixed = u32::from_be_bytes(octets) ^ u32::from(addr.port());
            if mixed == 0 {
                2
            } else {
                mixed
            }
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            let mut mixed = u32::from(addr.port());
            for chunk in octets.chunks_exact(4) {
                mixed ^= u32::from_be_bytes(chunk.try_into().unwrap());
            }
            if mixed == 0 {
                2
            } else {
                mixed
            }
        }
    }
}
