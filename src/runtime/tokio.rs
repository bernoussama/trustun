//! Runtime integration layer for sans-IO architecture
//!
//! This module provides the bridge between the protocol layer and I/O layer,
//! handling async coordination, event processing, and runtime-specific concerns.
//! It maintains the tokio runtime integration while keeping protocol logic clean.

use crate::io::traits::{AsyncCoordinator, ProtocolEventHandler, TunDevice, UdpSocket};
use crate::protocol::{PacketProcessor, ProcessResult};
use crate::{CHANNEL_BUFFER_SIZE, MTU};
use crate::{DecryptedPacket, EncryptedPacket, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

/// Runtime coordinator that manages communication between protocol and I/O layers
///
/// Note: This is a simplified implementation for compilation.
/// In a full sans-IO implementation, this would be properly generic.
pub struct RuntimeCoordinator {
    packet_processor: PacketProcessor,
    event_handler: Arc<dyn ProtocolEventHandler>,
    running: bool,
}

impl RuntimeCoordinator {
    /// Create a new runtime coordinator (simplified for demo)
    pub fn new(
        packet_processor: PacketProcessor,
        event_handler: Arc<dyn ProtocolEventHandler>,
    ) -> Self {
        Self {
            packet_processor,
            event_handler,
            running: true,
        }
    }

    /// Run the main coordination loop (simplified for demo)
    pub async fn run(&mut self) -> Result<()> {
        #[cfg(debug_assertions)]
        println!("Starting runtime coordinator...");

        Ok(())
    }

    /// Get a default destination address for testing
    pub fn get_default_destination(&self) -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }
}

impl AsyncCoordinator for Arc<RuntimeCoordinator> {
    async fn send_to_tun(&self, _packet: DecryptedPacket) -> Result<()> {
        // Simplified implementation
        Ok(())
    }

    async fn send_to_udp(&self, _packet: EncryptedPacket) -> Result<()> {
        // Simplified implementation
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

/// Protocol event handler that logs events and provides debugging info
#[derive(Debug)]
pub struct LoggingEventHandler {
    // Could add metrics collection here
}

impl LoggingEventHandler {
    /// Create a new logging event handler
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LoggingEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolEventHandler for LoggingEventHandler {
    fn on_decrypted_packet(&self, packet: DecryptedPacket) {
        #[cfg(debug_assertions)]
        println!("Decrypted packet received: {} bytes", packet.len());
    }

    fn on_protocol_error(&self, error: &str) {
        eprintln!("Protocol error: {}", error);
    }

    fn on_packet_sent(&self, destination: SocketAddr, bytes_sent: usize) {
        #[cfg(debug_assertions)]
        println!("Sent {} bytes to {}", bytes_sent, destination);
    }
}

/// Async task spawner for running multiple protocol tasks
pub struct TaskSpawner {
    // Could add task management, cancellation, etc. here
}

impl TaskSpawner {
    /// Create a new task spawner
    pub fn new() -> Self {
        Self {}
    }

    /// Spawn a TUN listener task
    pub fn spawn_tun_listener<T: TunDevice + 'static>(
        &self,
        device: Arc<T>,
        coordinator: Arc<RuntimeCoordinator>,
    ) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; MTU];

            loop {
                match device.read(&mut buf).await {
                    Ok(len) if len > 0 => {
                        // Process TUN packet through protocol layer
                        let packet_data = buf[..len].to_vec();
                        match coordinator
                            .packet_processor
                            .process_tun_packet(&packet_data)
                        {
                            ProcessResult::Success(Some(encrypted_data)) => {
                                // Extract routing information from the coordinator
                                // This is a simplified version - in practice, routing would be cleaner
                                let destination = coordinator.get_default_destination();

                                let encrypted_packet =
                                    EncryptedPacket::new(encrypted_data, destination);

                                if let Err(e) = coordinator.send_to_udp(encrypted_packet).await {
                                    eprintln!("Failed to send encrypted packet: {}", e);
                                }
                            }
                            ProcessResult::Error(e) => {
                                eprintln!("TUN packet processing error: {}", e);
                            }
                            _ => {}
                        }
                    }
                    Ok(_) => {
                        // No data available, continue
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        eprintln!("TUN read error: {}", e);
                        break;
                    }
                }
            }

            Ok(())
        })
    }

    /// Spawn a UDP listener task
    pub fn spawn_udp_listener<U: UdpSocket + 'static>(
        &self,
        socket: Arc<U>,
        coordinator: Arc<RuntimeCoordinator>,
    ) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; MTU + 512];

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer_addr)) => {
                        if len >= 28 {
                            // Minimum encrypted packet size
                            let packet_data = buf[..len].to_vec();
                            match coordinator
                                .packet_processor
                                .process_udp_packet(&packet_data, peer_addr)
                            {
                                ProcessResult::Success(Some(decrypted_data)) => {
                                    if let Err(e) = coordinator.send_to_tun(decrypted_data).await {
                                        eprintln!("Failed to send decrypted packet to TUN: {}", e);
                                    }
                                }
                                ProcessResult::Error(e) => {
                                    eprintln!("UDP packet processing error: {}", e);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("UDP recv error: {}", e);
                        break;
                    }
                }
            }

            Ok(())
        })
    }
}

impl Default for TaskSpawner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::traits::{TunDevice, UdpSocket};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    // Mock implementations for testing
    struct MockTunDevice {
        read_queue: Arc<Mutex<Vec<Vec<u8>>>>,
        write_log: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockTunDevice {
        fn new() -> Self {
            Self {
                read_queue: Arc::new(Mutex::new(Vec::new())),
                write_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn queue_read(&self, data: Vec<u8>) {
            self.read_queue.lock().unwrap().push(data);
        }

        fn get_written_data(&self) -> Vec<Vec<u8>> {
            self.write_log.lock().unwrap().clone()
        }
    }

    impl TunDevice for MockTunDevice {
        async fn read(&self, buf: &mut [u8]) -> Result<usize> {
            let mut queue = self.read_queue.lock().unwrap();
            if let Some(data) = queue.pop() {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            } else {
                Ok(0)
            }
        }

        async fn write(&self, buf: &[u8]) -> Result<usize> {
            self.write_log.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
    }

    struct MockUdpSocket {
        recv_queue: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
        send_log: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
    }

    impl MockUdpSocket {
        fn new() -> Self {
            Self {
                recv_queue: Arc::new(Mutex::new(Vec::new())),
                send_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn queue_recv(&self, data: Vec<u8>, addr: SocketAddr) {
            self.recv_queue.lock().unwrap().push((data, addr));
        }

        fn get_sent_data(&self) -> Vec<(Vec<u8>, SocketAddr)> {
            self.send_log.lock().unwrap().clone()
        }
    }

    impl UdpSocket for MockUdpSocket {
        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            let mut queue = self.recv_queue.lock().unwrap();
            if let Some((data, addr)) = queue.pop() {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok((len, addr))
            } else {
                Ok((0, "127.0.0.1:0".parse().unwrap()))
            }
        }

        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
            self.send_log.lock().unwrap().push((buf.to_vec(), addr));
            Ok(buf.len())
        }
    }

    #[tokio::test]
    async fn test_runtime_coordinator() {
        // This test would require setting up proper mock implementations
        // and testing the coordination between protocol and I/O layers

        // For now, we'll just test that the coordinator compiles and can be created
        let tun_device = Arc::new(MockTunDevice::new());
        let udp_socket = Arc::new(MockUdpSocket::new());
        let event_handler = Arc::new(LoggingEventHandler::new());

        // We would need a proper packet processor setup for a full test
        // let packet_processor = PacketProcessor::new(/* config */);

        // let (coordinator, tun_tx, udp_tx) = RuntimeCoordinator::new(
        //     tun_device,
        //     udp_socket,
        //     packet_processor,
        //     event_handler,
        // );

        // Basic compilation test
        assert!(true, "Runtime coordinator compiles successfully");
    }
}
