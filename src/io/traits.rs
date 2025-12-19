//! I/O abstraction layer for sans-IO architecture
//!
//! This module defines traits that abstract network operations without
//! coupling to specific I/O implementations. The traits allow protocol
//! logic to remain independent of networking details.

use crate::protocol::EncryptedPacket;
use crate::{DecryptedPacket, Result};
use std::net::SocketAddr;

/// Abstraction for TUN device operations
#[async_trait::async_trait]
pub trait TunDevice: Send + Sync {
    /// Read a packet from the TUN device
    async fn read(&self, buf: &mut [u8]) -> Result<usize>;

    /// Write a packet to the TUN device
    async fn write(&self, buf: &[u8]) -> Result<usize>;
}

/// Abstraction for UDP socket operations  
#[async_trait::async_trait]
pub trait UdpSocket: Send + Sync {
    /// Receive a UDP packet from the socket
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Send a UDP packet to the specified address
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;
}

/// Buffer pool for efficient memory management
pub trait BufferPool: Send + Sync {
    /// Acquire a buffer for writing
    fn acquire_write_buffer(&self, size: usize) -> Vec<u8>;

    /// Acquire a buffer for reading
    fn acquire_read_buffer(&self, size: usize) -> Vec<u8>;

    /// Return a buffer to the pool after use
    fn release_buffer(&self, buf: Vec<u8>);
}

/// Event handler trait for protocol events
pub trait ProtocolEventHandler: Send + Sync {
    /// Handle a successfully processed decrypted packet
    fn on_decrypted_packet(&self, packet: DecryptedPacket);

    /// Handle a protocol error
    fn on_protocol_error(&self, error: &str);

    /// Handle successful packet transmission
    fn on_packet_sent(&self, destination: SocketAddr, bytes_sent: usize);
}

/// Coordinator for managing async operations between protocol and I/O layers
pub trait AsyncCoordinator: Send + Sync {
    /// Send a decrypted packet to be written to TUN device
    async fn send_to_tun(&self, packet: DecryptedPacket) -> Result<()>;

    /// Send an encrypted packet to be sent over UDP
    async fn send_to_udp(&self, packet: EncryptedPacket) -> Result<()>;

    /// Check if coordinator is still running
    fn is_running(&self) -> bool;

    /// Gracefully shutdown the coordinator
    async fn shutdown(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock TUN device for testing
    #[async_trait::async_trait]
    pub struct MockTunDevice {
        read_queue: Arc<Mutex<Vec<Vec<u8>>>>,
        write_log: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockTunDevice {
        pub fn new() -> Self {
            Self {
                read_queue: Arc::new(Mutex::new(Vec::new())),
                write_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn queue_packet(&self, packet: Vec<u8>) {
            self.read_queue.lock().unwrap().push(packet);
        }

        pub fn get_written_packets(&self) -> Vec<Vec<u8>> {
            self.write_log.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl TunDevice for MockTunDevice {
        async fn read(&self, buf: &mut [u8]) -> Result<usize> {
            let mut queue = self.read_queue.lock().unwrap();
            if let Some(packet) = queue.pop() {
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            } else {
                Ok(0) // No data available
            }
        }

        async fn write(&self, buf: &[u8]) -> Result<usize> {
            self.write_log.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
    }
}

// Note: Arc wrapper impls would need proper async trait handling
// For now, we'll skip these as they're causing compilation issues
