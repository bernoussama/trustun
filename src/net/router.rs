use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;
use crate::protocol::peer::Peer;

pub struct Router {
    peers_by_index: HashMap<u32, Arc<Mutex<Peer>>>,
    peers_by_ip: HashMap<u32, Arc<Mutex<Peer>>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            peers_by_index: HashMap::new(),
            peers_by_ip: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, local_index: u32, ip: Ipv4Addr, peer: Arc<Mutex<Peer>>) {
        self.peers_by_index.insert(local_index, peer.clone());
        self.peers_by_ip.insert(u32::from(ip), peer);
    }

    pub fn get_by_index(&self, index: u32) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_index.get(&index).cloned()
    }

    pub fn get_by_ip(&self, ip: Ipv4Addr) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_ip.get(&u32::from(ip)).cloned()
    }
}
