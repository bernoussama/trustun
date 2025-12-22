use opentun::Result;
use opentun::protocol::peer::{Peer, PeerConfig};
use opentun::protocol::events::{Input, Output};
use opentun::net::router::Router;
use opentun::tasks::{udp, tun as tun_task};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use clap::Parser;
use std::net::{Ipv4Addr, IpAddr};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = opentun::cli::Cli::parse();
    match &cli.command {
        Some(opentun::cli::Commands::Genkey {}) => {
            let _ = opentun::cli::commands::handle_gen_key();
            return Ok(());
        },
        Some(opentun::cli::Commands::Pubkey {}) => {
            let _ = opentun::cli::commands::handle_pub_key();
            return Ok(());
        },
        None => {},
    }

    let config_path = "config.yaml";
    let conf = opentun::config::load_config(config_path);

    let mut static_private = [0u8; 32];
    base64::decode_config_slice(&conf.secret, base64::STANDARD, &mut static_private)?;

    let router = Arc::new(Mutex::new(Router::new()));
    let mut peers_to_start = Vec::new();

    for (ip, peer_conf) in &conf.peers {
        let mut remote_public = [0u8; 32];
        base64::decode_config_slice(&peer_conf.pub_key, base64::STANDARD, &mut remote_public)?;
        
        let p_config = PeerConfig {
             static_private,
             remote_public,
             psk: None,
             remote_endpoint: peer_conf.sock_addr,
             initiator: true,
        };
        
        let peer = Peer::new(p_config)?;
        let index = peer.local_index();
        let peer_arc = Arc::new(Mutex::new(peer));
        
        if let IpAddr::V4(ipv4) = *ip {
             router.lock().unwrap().add_peer(index, ipv4, peer_arc.clone());
             peers_to_start.push(peer_arc);
        } else {
             eprintln!("Skipping non-IPv4 peer: {}", ip);
        }
    }

    // Setup UDP
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", conf.port)).await?;
    let sock_arc = Arc::new(sock);
    println!("UDP socket bound to: {}", sock_arc.local_addr()?);

    // Setup TUN
    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&conf.name)
        .address(conf.address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(opentun::TUN_MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config)?;
    
    // Channels
    let (tun_tx, tun_rx) = mpsc::channel(opentun::CHANNEL_BUFFER_SIZE);

    // Start Handshakes
    for peer in peers_to_start {
        let mut p = peer.lock().unwrap();
        let outputs = p.tick(Input::Tick(std::time::Instant::now()))?;
        for output in outputs {
             match output {
                 Output::SendUdp(data, dst) => {
                     let _ = sock_arc.send_to(&data, dst).await;
                 }
                 _ => {}
             }
        }
    }

    // Spawn Tasks
    let udp_task = tokio::spawn(udp::run_udp(sock_arc.clone(), router.clone(), tun_tx));
    let tun_task = tokio::spawn(tun_task::run_tun(dev, router.clone(), sock_arc.clone(), tun_rx));

    let (udp_res, tun_res) = tokio::try_join!(udp_task, tun_task)?;
    udp_res?;
    tun_res?;

    Ok(())
}
