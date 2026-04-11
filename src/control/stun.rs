use std::collections::HashSet;
use std::net::SocketAddr;

use tokio::net::{UdpSocket, lookup_host};

use crate::protocol::Candidate;

pub async fn discover_candidates(socket: &UdpSocket, stun_servers: &[String]) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    if let Ok(local_addr) = socket.local_addr() {
        if !local_addr.ip().is_unspecified() && seen.insert(local_addr) {
            candidates.push(Candidate::Lan(local_addr));
        }
    }

    for server in stun_servers {
        let Ok(stun_server) = resolve_socket_addr(server).await else {
            continue;
        };

        let client = stunclient::StunClient::new(stun_server);
        if let Ok(addr) = client.query_external_address_async(socket).await {
            if seen.insert(addr) {
                candidates.push(Candidate::Reflexive(addr));
            }
        }
    }

    candidates.push(Candidate::Relay);
    candidates
}

async fn resolve_socket_addr(value: &str) -> crate::Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut addrs = lookup_host(value).await?;
    addrs
        .next()
        .ok_or_else(|| crate::IpouError::Config(format!("unable to resolve STUN server {value}")))
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    use super::*;

    #[tokio::test]
    async fn discover_candidates_does_not_publish_unspecified_bind_addr() {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        let candidates = discover_candidates(&socket, &[]).await;

        assert_eq!(candidates, vec![Candidate::Relay]);
    }
}
