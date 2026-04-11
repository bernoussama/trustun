pub mod coord;
pub mod relay;
pub mod timer;
pub mod tun;
pub mod udp;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use ::tun::{Configuration, create_as_async};

use crate::config::Config;
use crate::net::router::{Router, RuntimeAction};

#[derive(Clone)]
pub struct Dispatcher {
    udp_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    tun_tx: mpsc::UnboundedSender<Vec<u8>>,
    relay_tx: mpsc::UnboundedSender<Vec<u8>>,
    coord_tx: mpsc::UnboundedSender<crate::control::coord::CoordMessage>,
}

impl Dispatcher {
    #[must_use]
    pub fn new(
        udp_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
        tun_tx: mpsc::UnboundedSender<Vec<u8>>,
        relay_tx: mpsc::UnboundedSender<Vec<u8>>,
        coord_tx: mpsc::UnboundedSender<crate::control::coord::CoordMessage>,
    ) -> Self {
        Self {
            udp_tx,
            tun_tx,
            relay_tx,
            coord_tx,
        }
    }

    pub fn dispatch(&self, actions: Vec<RuntimeAction>) -> crate::Result<()> {
        for action in actions {
            match action {
                RuntimeAction::UdpSend { addr, bytes } => {
                    self.udp_tx
                        .send((bytes, addr))
                        .map_err(|_| crate::IpouError::ChannelClosed("udp writer"))?;
                }
                RuntimeAction::RelaySend { frame } => {
                    self.relay_tx
                        .send(frame)
                        .map_err(|_| crate::IpouError::ChannelClosed("relay writer"))?;
                }
                RuntimeAction::TunSend(packet) => {
                    self.tun_tx
                        .send(packet)
                        .map_err(|_| crate::IpouError::ChannelClosed("tun writer"))?;
                }
                RuntimeAction::CoordSend(message) => {
                    self.coord_tx
                        .send(message)
                        .map_err(|_| crate::IpouError::ChannelClosed("coord writer"))?;
                }
                RuntimeAction::Log(message) => {
                    eprintln!("{message}");
                }
            }
        }

        Ok(())
    }
}

pub async fn run_peer(config: Arc<Config>) -> crate::Result<()> {
    use tokio::net::UdpSocket;

    let mut tun_config = Configuration::default();
    tun_config
        .tun_name(&config.name)
        .address(config.address.parse::<std::net::Ipv4Addr>()?)
        .netmask((255, 255, 255, 0))
        .mtu(config.mtu as u16)
        .up();

    let dev = Arc::new(create_as_async(&tun_config)?);
    let socket = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", config.port)).await?);

    let mut router = Router::from_config(&config)?;
    let local_candidates = crate::control::stun::discover_candidates(&socket, &config.stun_servers).await;
    router.set_local_candidates(local_candidates);
    let router = Arc::new(Mutex::new(router));

    let (udp_write_tx, udp_write_rx) = mpsc::unbounded_channel();
    let (tun_write_tx, tun_write_rx) = mpsc::unbounded_channel();
    let (relay_write_tx, relay_write_rx) = mpsc::unbounded_channel();
    let (coord_write_tx, coord_write_rx) = mpsc::unbounded_channel();
    let dispatcher = Dispatcher::new(udp_write_tx, tun_write_tx, relay_write_tx, coord_write_tx);

    let bootstrap_actions = {
        let mut router = router.lock().await;
        router.bootstrap(crate::tasks::timer::now_ms())?
    };
    dispatcher.dispatch(bootstrap_actions)?;

    let tun_reader = tokio::spawn(tun::run_reader(
        Arc::clone(&dev),
        Arc::clone(&router),
        dispatcher.clone(),
    ));
    let tun_writer = tokio::spawn(tun::run_writer(Arc::clone(&dev), tun_write_rx));
    let udp_reader = tokio::spawn(udp::run_reader(
        Arc::clone(&socket),
        Arc::clone(&router),
        dispatcher.clone(),
    ));
    let udp_writer = tokio::spawn(udp::run_writer(Arc::clone(&socket), udp_write_rx));
    let relay_client = tokio::spawn(relay::run_client(
        config.relay_urls[0].clone(),
        router.lock().await.local_pubkey(),
        relay_write_rx,
        Arc::clone(&router),
        dispatcher.clone(),
    ));
    let coord_client = tokio::spawn(coord::run_client(
        config.coordination_url.clone(),
        router.lock().await.local_pubkey(),
        config.coord_auth_token.clone(),
        coord_write_rx,
        Arc::clone(&router),
        dispatcher.clone(),
    ));
    let timer = tokio::spawn(timer::run(Arc::clone(&router), dispatcher.clone()));

    let (a, b, c, d, e, f, g) = tokio::try_join!(
        tun_reader,
        tun_writer,
        udp_reader,
        udp_writer,
        relay_client,
        coord_client,
        timer,
    )?;
    a?;
    b?;
    c?;
    d?;
    e?;
    f?;
    g?;

    Ok(())
}

pub async fn run_relay_server(listen_addr: &str) -> crate::Result<()> {
    relay::run_server(listen_addr).await
}

pub async fn run_coord_server(listen_addr: &str, auth_token: Option<String>) -> crate::Result<()> {
    crate::control::coord::run_coord_server(listen_addr, auth_token).await
}
