//! Runtime integration layer module
//!
//! This module provides the runtime integration layer that bridges the protocol
//! layer with I/O operations and async runtime coordination.

pub mod tokio;

pub use tokio::{LoggingEventHandler, RuntimeCoordinator, TaskSpawner};
