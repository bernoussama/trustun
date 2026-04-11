use super::path::Candidate;

pub type PathId = u32;
pub type PeerId = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    NetworkRx {
        path: PathId,
        bytes: Vec<u8>,
        now_ms: u64,
    },
    TunRx(Vec<u8>),
    Tick {
        now_ms: u64,
    },
    CandidatesUpdated {
        peer: PeerId,
        candidates: Vec<Candidate>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    NetworkTx { path: PathId, bytes: Vec<u8> },
    RelayTx { relay_path: PathId, frame: Vec<u8> },
    TunTx(Vec<u8>),
    PublishLocalCandidates,
    Log(String),
}
