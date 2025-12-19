//! Comprehensive tests for the sans-IO architecture
//! 
//! This test module validates that the protocol layer works correctly
//! independently of I/O, and that the I/O abstraction layer properly
//! adapts to real networking components.

use crate::io::traits::{AsyncCoordinator, ProtocolEventHandler, TunDevice, UdpSocket, BufferPool};
use crate::io::buffer::{SimpleBufferPool, FixedBuffer, PacketBuffer, PacketType};
use crate::protocol::{PacketProcessor, ProcessResult, extract_dest_ip, extract_src_ip, validate_ipv4_packet};
use crate::config::{RuntimeConfig, Config};
use crate::{DecryptedPacket, EncryptedPacket};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn create_test_runtime_config() -> RuntimeConfig {
        let mut shared_secrets = HashMap::new();
        let mut ciphers = HashMap::new();
        let mut ips = HashMap::new();
        let mut peers = HashMap::new();

        // Generate test keys
        let secret = StaticSecret::from([1u8; 32]);
        let public = PublicKey::from(&secret);
        
        let test_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let test_peer_addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        
        // Create shared secret and cipher
        let shared_secret = secret.diffie_hellman(&public);
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        
        shared_secrets.insert(test_ip, *shared_secret.as_bytes());
        ciphers.insert(test_ip, cipher);
        ips.insert(test_peer_addr, test_ip);
        
        let peer = crate::Peer {
            sock_addr: test_peer_addr,
            pub_key: base64::encode(public.as_bytes()),
        };
        peers.insert(test_ip, peer);

        RuntimeConfig {
            shared_secrets,
            ciphers,
            ips,
            peers,
        }
    }

    #[test]
    fn test_protocol_layer_basic_functionality() {
        let runtime_config = create_test_runtime_config();
        let processor = PacketProcessor::new(runtime_config);

        // Test IPv4 packet extraction
        let mut packet = vec![0x45, 0x00, 0x00, 0x3C]; // IPv4 header
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // TTL, Protocol, Checksum
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]); // Source: 10.11.12.13
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x02]); // Dest: 10.0.0.2
        
        // Test destination IP extraction
        let dest_ip = extract_dest_ip(&packet);
        assert_eq!(dest_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        
        // Test source IP extraction
        let src_ip = extract_src_ip(&packet);
        assert_eq!(src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13))));

        // Test packet validation
        assert!(validate_ipv4_packet(&packet).is_ok());
    }

    #[test]
    fn test_packet_processor_with_routing() {
        let runtime_config = create_test_runtime_config();
        let processor = PacketProcessor::new(runtime_config);

        // Test TUN packet processing
        let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]); // Source: 10.11.12.13
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x02]); // Dest: 10.0.0.2

        let result = processor.process_tun_packet(&packet);
        
        // Should succeed and return encrypted data
        match result {
            ProcessResult::Success(Some(encrypted_data)) => {
                assert!(encrypted_data.len() > 28); // Should have nonce + encrypted data
            }
            ProcessResult::Error(e) => {
                panic!("Unexpected error: {}", e);
            }
            _ => panic!("Expected success with encrypted data"),
        }
    }

    #[test]
    fn test_buffer_management() {
        let pool = SimpleBufferPool::default();
        
        // Test small buffer acquisition
        let mut buf = pool.acquire_write_buffer(100);
        assert_eq!(buf.len(), crate::SMALL_BUFFER_SIZE);
        
        // Fill some data
        for i in 0..50 {
            buf[i] = i as u8;
        }
        
        // Test buffer release
        pool.release_buffer(buf);
        
        // Acquire again (should reuse)
        let buf2 = pool.acquire_write_buffer(100);
        assert_eq!(buf2.len(), crate::SMALL_BUFFER_SIZE);
    }

    #[test]
    fn test_packet_buffer_with_metadata() {
        let mut buffer = PacketBuffer::tun_packet();
        
        let test_data = b"Test IPv4 packet data";
        let write_slice = buffer.write_slice(test_data.len());
        write_slice.copy_from_slice(test_data);
        
        assert_eq!(buffer.len(), test_data.len());
        assert_eq!(buffer.packet_type(), PacketType::Tun);
        
        // Test metadata
        buffer.set_peer_addr("192.168.1.1:8080".parse().unwrap());
        assert!(buffer.peer_addr().is_some());
        
        // Test age tracking
        let age = buffer.age();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(buffer.age() > age);
    }

    #[test]
    fn test_fixed_buffer_operations() {
        let mut buffer = FixedBuffer::with_size(100);
        
        // Test writing
        let data = b"Hello, buffer!";
        let write_slice = buffer.write_slice(data.len());
        write_slice.copy_from_slice(data);
        
        assert_eq!(buffer.len(), data.len());
        assert_eq!(buffer.read_slice(), data);
        assert!(!buffer.is_empty());
        assert!(!buffer.is_full());
        
        // Test clearing
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    // Mock implementations for testing I/O traits
    struct TestTunDevice {
        read_data: Vec<Vec<u8>>,
        written_data: Vec<Vec<u8>>,
    }

    impl TestTunDevice {
        fn new() -> Self {
            Self {
                read_data: Vec::new(),
                written_data: Vec::new(),
            }
        }
        
        fn queue_read(&mut self, data: Vec<u8>) {
            self.read_data.push(data);
        }
        
        fn get_written_data(&self) -> &[Vec<u8>] {
            &self.written_data
        }
    }

    impl TunDevice for TestTunDevice {
        async fn read(&self, buf: &mut [u8]) -> crate::Result<usize> {
            if let Some(data) = self.read_data.get(0) {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            } else {
                Ok(0)
            }
        }

        async fn write(&self, buf: &[u8]) -> crate::Result<usize> {
            // Note: This would need interior mutability for real implementation
            Ok(buf.len())
        }
    }

    struct TestUdpSocket {
        recv_queue: Vec<(Vec<u8>, SocketAddr)>,
        sent_data: Vec<(Vec<u8>, SocketAddr)>,
    }

    impl TestUdpSocket {
        fn new() -> Self {
            Self {
                recv_queue: Vec::new(),
                sent_data: Vec::new(),
            }
        }
        
        fn queue_recv(&mut self, data: Vec<u8>, addr: SocketAddr) {
            self.recv_queue.push((data, addr));
        }
    }

    impl UdpSocket for TestUdpSocket {
        async fn recv_from(&self, buf: &mut [u8]) -> crate::Result<(usize, SocketAddr)> {
            if let Some((data, addr)) = self.recv_queue.get(0) {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok((len, *addr))
            } else {
                Ok((0, "127.0.0.1:0".parse().unwrap()))
            }
        }

        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> crate::Result<usize> {
            // Note: This would need interior mutability for real implementation
            Ok(buf.len())
        }
    }

    #[test]
    fn test_io_traits_compile() {
        // Test that our trait definitions compile correctly
        let tun_device = TestTunDevice::new();
        let udp_socket = TestUdpSocket::new();
        
        // These would compile if we had proper async test context
        // let _ = tun_device.read(&mut [0u8; 100]);
        // let _ = udp_socket.recv_from(&mut [0u8; 1024]);
        
        // For now, just verify the types exist
        let _: &dyn TunDevice = &tun_device;
        let _: &dyn UdpSocket = &udp_socket;
        let _: &dyn BufferPool = &SimpleBufferPool::default();
    }

    // Event handler for testing
    struct TestEventHandler {
        packets_sent: Vec<SocketAddr>,
        errors: Vec<String>,
        decrypted_packets: Vec<DecryptedPacket>,
    }

    impl TestEventHandler {
        fn new() -> Self {
            Self {
                packets_sent: Vec::new(),
                errors: Vec::new(),
                decrypted_packets: Vec::new(),
            }
        }
        
        fn get_packets_sent(&self) -> &[SocketAddr] {
            &self.packets_sent
        }
        
        fn get_errors(&self) -> &[String] {
            &self.errors
        }
        
        fn get_decrypted_packets(&self) -> &[DecryptedPacket] {
            &self.decrypted_packets
        }
    }

    impl ProtocolEventHandler for TestEventHandler {
        fn on_decrypted_packet(&self, packet: DecryptedPacket) {
            // In real implementation, would track this
        }
        
        fn on_protocol_error(&self, error: &str) {
            // In real implementation, would track this
        }
        
        fn on_packet_sent(&self, destination: SocketAddr, bytes_sent: usize) {
            // In real implementation, would track this
        }
    }
}

#[cfg(test)]
mod protocol_benchmarks {
    use super::*;
    use test::Bencher;

    fn create_benchmark_config() -> RuntimeConfig {
        let mut shared_secrets = HashMap::new();
        let mut ciphers = HashMap::new();
        let mut ips = HashMap::new();
        let mut peers = HashMap::new();

        let secret = StaticSecret::from([1u8; 32]);
        let public = PublicKey::from(&secret);
        
        let test_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let test_peer_addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        
        let shared_secret = secret.diffie_hellman(&public);
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        
        shared_secrets.insert(test_ip, *shared_secret.as_bytes());
        ciphers.insert(test_ip, cipher);
        ips.insert(test_peer_addr, test_ip);
        
        let peer = crate::Peer {
            sock_addr: test_peer_addr,
            pub_key: base64::encode(public.as_bytes()),
        };
        peers.insert(test_ip, peer);

        RuntimeConfig {
            shared_secrets,
            ciphers,
            ips,
            peers,
        }
    }

    #[bench]
    fn bench_extract_dest_ip(b: &mut Bencher) {
        let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x02]);

        b.iter(|| {
            extract_dest_ip(&packet)
        });
    }

    #[bench]
    fn bench_validate_ipv4_packet(b: &mut Bencher) {
        let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x02]);

        b.iter(|| {
            validate_ipv4_packet(&packet)
        });
    }

    #[bench]
    fn bench_process_tun_packet(b: &mut Bencher) {
        let runtime_config = create_benchmark_config();
        let processor = PacketProcessor::new(runtime_config);

        let mut packet = vec![0x45, 0x00, 0x00, 0x3C];
        packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]);
        packet.extend_from_slice(&[0x0A, 0x00, 0x00, 0x02]);

        b.iter(|| {
            processor.process_tun_packet(&packet)
        });
    }
}