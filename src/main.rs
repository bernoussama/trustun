use clap::Parser;
use opentun::Result;
use opentun::TunMessage;
use opentun::net::router::Router;
use opentun::protocol::events::Output;
use opentun::protocol::peer::{Peer, PeerConfig};
use opentun::tasks;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = opentun::cli::Cli::parse();

    if let Some(cmd) = &cli.command {
        match cmd {
            opentun::cli::Commands::Genkey {} => opentun::cli::commands::handle_gen_key()?,
            opentun::cli::Commands::Pubkey {} => opentun::cli::commands::handle_pub_key()?,
        }
        return Ok(());
    }

    let config_path = "config.yaml";
    let conf = opentun::config::load_config(config_path);

    let router = Arc::new(Mutex::new(Router::new()));

    let mut local_private = [0u8; 32];
    base64::decode_config_slice(&conf.secret, base64::STANDARD, &mut local_private).unwrap();

    let mut peer_idx_counter = 1000;
    let mut initial_packets = Vec::new();

    for (ip_addr, peer_conf) in &conf.peers {
        let ip = match ip_addr {
            std::net::IpAddr::V4(v4) => *v4,
            _ => continue,
        };

        let mut remote_public = [0u8; 32];
        base64::decode_config_slice(&peer_conf.pub_key, base64::STANDARD, &mut remote_public)
            .unwrap();

        let index = peer_idx_counter;
        peer_idx_counter += 1;

        let p_config = PeerConfig {
            static_private: local_private,
            remote_public,
            psk: None,
            index,
            initiator: true,
            endpoint: Some(peer_conf.sock_addr),
        };

        match Peer::new(p_config) {
            Ok((peer, outputs)) => {
                for out in outputs {
                    if let Output::SendUdp(data, addr) = out {
                        initial_packets.push((data, addr));
                    }
                }

                let peer_arc = Arc::new(Mutex::new(peer));
                router
                    .lock()
                    .unwrap()
                    .add_peer(ip, index, Some(peer_conf.sock_addr), peer_arc);
            }
            Err(e) => eprintln!("Failed to create peer for {}: {}", ip, e),
        }
    }

    let mut tun_config = tun::Configuration::default();
    tun_config
        .tun_name(&conf.name)
        .address(conf.address.parse::<Ipv4Addr>().unwrap())
        .netmask((255, 255, 255, 0))
        .mtu(opentun::MTU as u16)
        .up();

    let dev = tun::create_as_async(&tun_config).expect("Failed to create TUN device");
    let dev_arc = Arc::new(dev);

    let sock = UdpSocket::bind(format!("0.0.0.0:{}", conf.port))
        .await
        .expect("Failed to bind UDP socket");
    let sock_arc = Arc::new(sock);

    println!("UDP socket bound to: {}", sock_arc.local_addr().unwrap());

    let (tun_tx, tun_rx) = mpsc::channel::<TunMessage>(opentun::CHANNEL_BUFFER_SIZE);

    for (data, addr) in initial_packets {
        if let Err(e) = sock_arc.send_to(&data, addr).await {
            eprintln!("Failed to send handshake init to {}: {}", addr, e);
        }
    }

    let udp_task = tokio::spawn(tasks::udp::run(sock_arc.clone(), router.clone(), tun_tx));

    let tun_task = tokio::spawn(tasks::tun::run(
        dev_arc.clone(),
        router.clone(),
        sock_arc.clone(),
        tun_rx,
    ));

    let _ = tokio::join!(udp_task, tun_task);

    Ok(())
}
