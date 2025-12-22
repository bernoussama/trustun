use crate::protocol::peer::Peer;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

pub struct Router {
    peers_by_ip: HashMap<Ipv4Addr, Arc<Mutex<Peer>>>,
    peers_by_index: HashMap<u32, Arc<Mutex<Peer>>>,
    peers_by_addr: HashMap<SocketAddr, Arc<Mutex<Peer>>>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            peers_by_ip: HashMap::new(),
            peers_by_index: HashMap::new(),
            peers_by_addr: HashMap::new(),
        }
    }

    pub fn add_peer(
        &mut self,
        ip: Ipv4Addr,
        index: u32,
        addr: Option<SocketAddr>,
        peer: Arc<Mutex<Peer>>,
    ) {
        self.peers_by_ip.insert(ip, peer.clone());
        self.peers_by_index.insert(index, peer.clone());
        if let Some(a) = addr {
            self.peers_by_addr.insert(a, peer);
        }
    }

    pub fn route_by_ip(&self, ip: &Ipv4Addr) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_ip.get(ip).cloned()
    }

    pub fn route_by_index(&self, index: u32) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_index.get(&index).cloned()
    }

    pub fn route_by_addr(&self, addr: &SocketAddr) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_addr.get(addr).cloned()
    }
}
