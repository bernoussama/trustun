//! I/O abstraction layer module
//!
//! This module provides the I/O abstraction layer for the sans-IO architecture,
//! including trait definitions, concrete implementations, and buffer management.

pub mod adapters;
pub mod buffer;
pub mod traits;

pub use adapters::{TunAdapter, UdpAdapter};
pub use buffer::{FixedBuffer, PacketBuffer, PacketType, SimpleBufferPool};
pub use traits::{AsyncCoordinator, BufferPool, ProtocolEventHandler, TunDevice, UdpSocket};
