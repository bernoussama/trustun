//! Buffer management for sans-IO architecture
//!
//! This module provides efficient buffer management utilities for packet processing.
//! It includes buffer pools, fixed-size buffers, and utilities for managing
//! packet buffers throughout the processing pipeline.

use crate::io::traits::BufferPool;
use crate::{ENCRYPTION_OVERHEAD, MTU, Result};
use std::sync::Mutex;

/// Pre-allocated buffer sizes
pub const SMALL_BUFFER_SIZE: usize = MTU; // 1420 bytes
pub const LARGE_BUFFER_SIZE: usize = MTU + 512; // 1932 bytes
pub const MAX_PACKET_SIZE: usize = MTU + ENCRYPTION_OVERHEAD; // 1448 bytes

/// Fixed-size buffer for packet processing
#[derive(Debug)]
pub struct FixedBuffer {
    data: Vec<u8>,
    size: usize,
    used: usize,
}

impl FixedBuffer {
    /// Create a new fixed-size buffer
    pub fn with_size(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
            size,
            used: 0,
        }
    }

    /// Get a mutable slice for writing
    pub fn write_slice(&mut self, len: usize) -> &mut [u8] {
        let write_len = len.min(self.size - self.used);
        &mut self.data[self.used..self.used + write_len]
    }

    /// Get a read-only slice of the used data
    pub fn read_slice(&self) -> &[u8] {
        &self.data[..self.used]
    }

    /// Get a mutable slice for reading
    pub fn read_slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.used]
    }

    /// Get the number of bytes currently used
    pub fn len(&self) -> usize {
        self.used
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.used >= self.size
    }

    /// Reset the buffer to empty state
    pub fn clear(&mut self) {
        self.used = 0;
    }

    /// Reserve space in the buffer
    pub fn reserve(&mut self, additional: usize) -> Result<()> {
        let new_used = self.used + additional;
        if new_used > self.size {
            return Err(crate::IpouError::Unknown(format!(
                "Buffer overflow: {} + {} > {}",
                self.used, additional, self.size
            )));
        }
        Ok(())
    }
}

/// Packet buffer with metadata
#[derive(Debug)]
pub struct PacketBuffer {
    buffer: FixedBuffer,
    packet_type: PacketType,
    peer_addr: Option<std::net::SocketAddr>,
    timestamp: std::time::Instant,
}

impl PacketBuffer {
    /// Create a new packet buffer
    pub fn new(size: usize, packet_type: PacketType) -> Self {
        Self {
            buffer: FixedBuffer::with_size(size),
            packet_type,
            peer_addr: None,
            timestamp: std::time::Instant::now(),
        }
    }

    /// Create a small buffer for TUN packets
    pub fn tun_packet() -> Self {
        Self::new(SMALL_BUFFER_SIZE, PacketType::Tun)
    }

    /// Create a large buffer for UDP packets
    pub fn udp_packet() -> Self {
        Self::new(LARGE_BUFFER_SIZE, PacketType::Udp)
    }

    /// Create a buffer for encrypted packets
    pub fn encrypted_packet() -> Self {
        Self::new(MAX_PACKET_SIZE, PacketType::Encrypted)
    }

    /// Set the peer address for this packet
    pub fn set_peer_addr(&mut self, addr: std::net::SocketAddr) {
        self.peer_addr = Some(addr);
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr
    }

    /// Get the packet type
    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }

    /// Get the age of this packet
    pub fn age(&self) -> std::time::Duration {
        self.timestamp.elapsed()
    }
}

impl std::ops::Deref for PacketBuffer {
    type Target = FixedBuffer;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl std::ops::DerefMut for PacketBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

/// Types of packets handled by the buffer system
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Tun,       // Raw IPv4 packets from TUN device
    Udp,       // UDP packets received from network
    Encrypted, // Encrypted packets ready for transmission
}

/// Simple buffer pool implementation
#[derive(Debug)]
pub struct SimpleBufferPool {
    small_buffers: Mutex<Vec<FixedBuffer>>,
    large_buffers: Mutex<Vec<FixedBuffer>>,
    max_small: usize,
    max_large: usize,
}

impl SimpleBufferPool {
    /// Create a new buffer pool with specified limits
    pub fn new(max_small: usize, max_large: usize) -> Self {
        Self {
            small_buffers: Mutex::new(Vec::new()),
            large_buffers: Mutex::new(Vec::new()),
            max_small,
            max_large,
        }
    }

    /// Create a default buffer pool
    pub fn default() -> Self {
        Self::new(100, 50) // 100 small, 50 large buffers
    }

    /// Acquire a small buffer (TUN packet size)
    fn acquire_small(&self) -> FixedBuffer {
        let mut pool = self.small_buffers.lock().unwrap();
        if let Some(buffer) = pool.pop() {
            buffer
        } else {
            FixedBuffer::with_size(SMALL_BUFFER_SIZE)
        }
    }

    /// Acquire a large buffer (UDP packet size)
    fn acquire_large(&self) -> FixedBuffer {
        let mut pool = self.large_buffers.lock().unwrap();
        if let Some(buffer) = pool.pop() {
            buffer
        } else {
            FixedBuffer::with_size(LARGE_BUFFER_SIZE)
        }
    }

    /// Return a buffer to the pool
    fn release_buffer(&self, buffer: FixedBuffer) {
        if buffer.size == SMALL_BUFFER_SIZE {
            let mut pool = self.small_buffers.lock().unwrap();
            if pool.len() < self.max_small {
                pool.push(buffer);
            }
        } else if buffer.size == LARGE_BUFFER_SIZE {
            let mut pool = self.large_buffers.lock().unwrap();
            if pool.len() < self.max_large {
                pool.push(buffer);
            }
        }
        // Buffers of other sizes are simply dropped
    }
}

impl BufferPool for SimpleBufferPool {
    fn acquire_write_buffer(&self, size: usize) -> Vec<u8> {
        if size <= SMALL_BUFFER_SIZE {
            let buffer = self.acquire_small();
            vec![0u8; buffer.size] // Return a zeroed buffer
        } else if size <= LARGE_BUFFER_SIZE {
            let buffer = self.acquire_large();
            vec![0u8; buffer.size]
        } else {
            vec![0u8; size]
        }
    }

    fn acquire_read_buffer(&self, size: usize) -> Vec<u8> {
        self.acquire_write_buffer(size)
    }

    fn release_buffer(&self, buf: Vec<u8>) {
        if buf.len() == SMALL_BUFFER_SIZE {
            let buffer = FixedBuffer::with_size(SMALL_BUFFER_SIZE);
            self.release_buffer(buffer);
        } else if buf.len() == LARGE_BUFFER_SIZE {
            let buffer = FixedBuffer::with_size(LARGE_BUFFER_SIZE);
            self.release_buffer(buffer);
        }
        // Other sizes are not pooled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_buffer() {
        let mut buffer = FixedBuffer::with_size(100);

        // Test writing
        let data = b"Hello, world!";
        let write_slice = buffer.write_slice(data.len());
        write_slice.copy_from_slice(data);

        assert_eq!(buffer.len(), data.len());
        assert_eq!(buffer.read_slice(), data);

        // Test clearing
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_packet_buffer() {
        let mut buffer = PacketBuffer::tun_packet();

        let data = b"Test packet";
        let write_slice = buffer.write_slice(data.len());
        write_slice.copy_from_slice(data);

        assert_eq!(buffer.len(), data.len());
        assert_eq!(buffer.packet_type(), PacketType::Tun);
        assert!(buffer.peer_addr().is_none());

        buffer.set_peer_addr("127.0.0.1:8080".parse().unwrap());
        assert!(buffer.peer_addr().is_some());
    }

    #[test]
    fn test_buffer_pool() {
        let pool = SimpleBufferPool::default();

        // Acquire some buffers
        let buf1 = pool.acquire_write_buffer(SMALL_BUFFER_SIZE);
        let buf2 = pool.acquire_write_buffer(LARGE_BUFFER_SIZE);

        assert_eq!(buf1.len(), SMALL_BUFFER_SIZE);
        assert_eq!(buf2.len(), LARGE_BUFFER_SIZE);

        // Release them
        pool.release_buffer(buf1);
        pool.release_buffer(buf2);

        // Acquire again (should reuse)
        let buf3 = pool.acquire_write_buffer(SMALL_BUFFER_SIZE);
        let buf4 = pool.acquire_write_buffer(LARGE_BUFFER_SIZE);

        assert_eq!(buf3.len(), SMALL_BUFFER_SIZE);
        assert_eq!(buf4.len(), LARGE_BUFFER_SIZE);
    }
}
