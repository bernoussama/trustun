use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use crate::protocol::peer::Peer;

#[derive(Default)]
pub struct Router {
    pub peers_by_ip: HashMap<u32, Arc<Mutex<Peer>>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            peers_by_ip: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, ip: Ipv4Addr, peer: Peer) -> Arc<Mutex<Peer>> {
        let key = u32::from(ip);
        let peer = Arc::new(Mutex::new(peer));
        self.peers_by_ip.insert(key, peer.clone());
        peer
    }

    pub fn lookup(&self, ip: u32) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_ip.get(&ip).cloned()
    }
}
