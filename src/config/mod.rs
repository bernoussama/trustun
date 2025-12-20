use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use chacha20poly1305::ChaCha20Poly1305;

use crate::Peer;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct Config {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub secret: String,
    pub pubkey: String,
    pub peers: HashMap<IpAddr, Peer>,
}

pub struct RuntimeConfig {
    pub shared_secrets: HashMap<IpAddr, [u8; 32]>,
    pub ciphers: HashMap<IpAddr, ChaCha20Poly1305>,
    pub ips: HashMap<SocketAddr, IpAddr>,
}

/// Load configuration from a YAML file or create and persist a default configuration when missing.
///
/// If a YAML file exists at `config_path` it is parsed into a `Config`. If the file is absent or unreadable,
/// a default `Config` is generated (including a newly created keypair), written to `config_path` as YAML,
/// and returned.
///
/// # Returns
///
/// `Config` loaded from the file or the generated default configuration written to `config_path`.
///
/// # Examples
///
/// ```
/// let cfg = load_config("/tmp/example_vpn_config.yml");
/// // On first run this will create the file and return the default config:
/// assert_eq!(cfg.name, "utun0");
/// ```
pub fn load_config(config_path: &str) -> Config {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap(),
        Err(_) => {
            eprintln!("No config file found! using defaults.");
            let (private_key, public_key) = crate::crypto::generate_keypair();

            let peers: HashMap<IpAddr, Peer> = HashMap::new();

            let conf = Config {
                name: "utun0".to_string(),
                address: "10.0.0.1".to_string(),
                secret: base64::encode(private_key),
                pubkey: base64::encode(public_key),
                port: 1194,
                peers,
            };
            std::fs::write(config_path, serde_yaml::to_string(&conf).unwrap())
                .expect("Failed to write default config file");
            conf
        }
    }
}