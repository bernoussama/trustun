use std::{
    collections::HashMap,
    net::IpAddr,
};

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

pub fn load_config(config_path: &str) -> Config {
    match std::fs::read_to_string(config_path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap(),
        Err(_) => {
            eprintln!("No config file found! using defaults.");

            let params: snow::params::NoiseParams =
                "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
            let builder = snow::Builder::new(params);
            let keypair = builder.generate_keypair().unwrap();

            let peers: HashMap<IpAddr, Peer> = HashMap::new();

            let conf = Config {
                name: "utun0".to_string(),
                address: "10.0.0.1".to_string(),
                secret: base64::encode(&keypair.private),
                pubkey: base64::encode(&keypair.public),
                port: 1194,
                peers,
            };
            std::fs::write(config_path, serde_yaml::to_string(&conf).unwrap())
                .expect("Failed to write default config file");
            conf
        }
    }
}
