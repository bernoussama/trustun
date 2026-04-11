use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use chacha20poly1305::ChaCha20Poly1305;
use serde::{Deserialize, Serialize};

use crate::cli::Cli;
use crate::Peer;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(default)]
pub struct Config {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub secret: String,
    pub pubkey: String,
    pub mtu: usize,
    pub node_roles: Vec<String>,
    pub stun_servers: Vec<String>,
    pub coordination_url: String,
    pub relay_urls: Vec<String>,
    pub relay_listen_addr: Option<String>,
    pub coord_listen_addr: Option<String>,
    pub coord_auth_token: Option<String>,
    pub peers: HashMap<IpAddr, Peer>,
}

pub struct RuntimeConfig {
    pub shared_secrets: HashMap<IpAddr, [u8; 32]>,
    pub ciphers: HashMap<IpAddr, ChaCha20Poly1305>,
    pub ips: HashMap<SocketAddr, IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRoles {
    pub peer: bool,
    pub relay: bool,
    pub coord: bool,
}

impl NodeRoles {
    #[must_use]
    pub fn any(self) -> bool {
        self.peer || self.relay || self.coord
    }
}

impl Default for Config {
    fn default() -> Self {
        let (private_key, public_key) = crate::crypto::generate_keypair();

        Self {
            name: "utun0".to_string(),
            address: "10.0.0.1".to_string(),
            port: 1194,
            secret: base64::encode(private_key),
            pubkey: base64::encode(public_key),
            mtu: 1280,
            node_roles: vec!["peer".to_string()],
            stun_servers: vec!["stun.l.google.com:19302".to_string()],
            coordination_url: String::new(),
            relay_urls: Vec::new(),
            relay_listen_addr: None,
            coord_listen_addr: None,
            coord_auth_token: None,
            peers: HashMap::new(),
        }
    }
}

impl Config {
    #[must_use]
    pub fn merged_with_cli(&self, cli: &Cli) -> Self {
        let mut merged = self.clone();
        if let Some(name) = &cli.name {
            merged.name = name.clone();
        }
        if let Some(address) = &cli.address {
            merged.address = address.clone();
        }
        if let Some(port) = cli.port {
            merged.port = port;
        }
        if let Some(relay_listen) = &cli.relay_listen {
            merged.relay_listen_addr = Some(relay_listen.clone());
        }
        if let Some(coord_listen) = &cli.coord_listen {
            merged.coord_listen_addr = Some(coord_listen.clone());
        }
        if let Some(relay_url) = &cli.relay_url {
            merged.relay_urls = vec![relay_url.clone()];
        }
        if let Some(coord_url) = &cli.coord_url {
            merged.coordination_url = coord_url.clone();
        }
        merged
    }

    pub fn resolve_roles(&self, cli: &Cli) -> crate::Result<NodeRoles> {
        let cli_roles = NodeRoles {
            peer: cli.peer,
            relay: cli.relay,
            coord: cli.coord,
        };
        if cli_roles.any() {
            return Ok(cli_roles);
        }

        let mut roles = NodeRoles {
            peer: false,
            relay: false,
            coord: false,
        };
        for role in &self.node_roles {
            match role.as_str() {
                "peer" => roles.peer = true,
                "relay" => roles.relay = true,
                "coord" => roles.coord = true,
                other => {
                    return Err(crate::IpouError::Config(format!(
                        "unknown node role {other}"
                    )));
                }
            }
        }

        if roles.any() {
            Ok(roles)
        } else {
            Ok(NodeRoles {
                peer: true,
                relay: false,
                coord: false,
            })
        }
    }

    pub fn validate_runtime(&self, roles: NodeRoles) -> crate::Result<()> {
        if roles.relay && self.relay_listen_addr.is_none() {
            return Err(crate::IpouError::Config(
                "relay role requires relay_listen_addr or --relay-listen".to_string(),
            ));
        }
        if roles.coord && self.coord_listen_addr.is_none() {
            return Err(crate::IpouError::Config(
                "coord role requires coord_listen_addr or --coord-listen".to_string(),
            ));
        }
        if roles.peer {
            if self.coordination_url.is_empty() {
                return Err(crate::IpouError::Config(
                    "peer role requires coordination_url or --coord-url".to_string(),
                ));
            }
            if self.relay_urls.is_empty() {
                return Err(crate::IpouError::Config(
                    "peer role requires relay_urls or --relay-url".to_string(),
                ));
            }
            if self.peers.is_empty() {
                return Err(crate::IpouError::Config(
                    "peer role requires at least one entry in peers".to_string(),
                ));
            }
        }

        Ok(())
    }
}

pub fn load_config(config_path: &str) -> Config {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap(),
        Err(_) => {
            eprintln!("No config file found! using defaults.");
            let conf = Config::default();
            std::fs::write(config_path, serde_yaml::to_string(&conf).unwrap())
                .expect("Failed to write default config file");
            conf
        }
    }
}
