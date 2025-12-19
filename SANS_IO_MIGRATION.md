# Sans-IO Migration Plan

## Current Architecture Analysis

The current codebase exhibits tight coupling between I/O operations and business logic:

- **Direct I/O coupling**: `main.rs` directly manages TUN devices and UDP sockets
- **Async runtime dependency**: All networking code written against tokio-specific APIs
- **Mixed concerns**: Protocol handling, encryption, and network operations intertwined in same functions

## Target Sans-IO Architecture

### Core Principles
1. **Protocol Logic Separation**: Pure Rust functions working with in-memory buffers
2. **I/O Abstraction**: Traits defining network operations without concrete implementations
3. **Runtime Independence**: Protocol logic independent of async runtime choice
4. **Testability**: Protocol handlers can be unit tested without network I/O

## Migration Phases

### Phase 1: Extract Protocol Logic (Core Sans-IO Layer)

#### New Structure:
```
src/
├── protocol/          # Pure protocol logic
│   ├── mod.rs        # Core protocol definitions
│   ├── packet.rs     # Packet parsing/validation
│   └── crypto.rs     # Encryption/decryption logic
├── io/               # I/O abstraction layer
│   ├── traits.rs     # Network operation traits
│   ├── adapters.rs   # I/O trait implementations
│   └── buffer.rs     # Buffer management
└── runtime/          # Async runtime integration
    ├── tokio.rs      # Tokio-specific implementations
    └── async_trait.rs # Async trait definitions
```

### Phase 2: Protocol Layer

#### Core Components:
1. **PacketProcessor**: Stateless protocol handlers
2. **KeyManager**: Centralized key and cipher management  
3. **Routing**: Peer lookup and packet routing logic

### Phase 3: I/O Abstraction

#### Traits:
```rust
// Core I/O traits
trait TunDevice: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> Result<usize>;
    async fn write(&self, buf: &[u8]) -> Result<usize>;
}

trait UdpSocket: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;
}
```

### Phase 4: Runtime Integration

#### Async Adapters:
- Bridge protocol handlers with concrete I/O implementations
- Manage channel coordination between protocol and I/O layers
- Handle error propagation and graceful shutdown

## Implementation Strategy

### Step 1: Extract Pure Protocol Logic
- Move encryption/decryption to `protocol::crypto`
- Extract packet parsing to `protocol::packet`
- Create routing logic in `protocol::routing`

### Step 2: Define I/O Traits
- Create `io::traits` module with network operation traits
- Define buffer management interfaces
- Abstract away concrete TUN/UDP implementations

### Step 3: Refactor I/O Layer  
- Implement trait adapters for existing TUN/UDP code
- Create buffer pool for efficient memory management
- Add error handling and logging abstractions

### Step 4: Runtime Integration
- Create tokio-specific runtime adapters
- Refactor main.rs to use new architecture
- Update spawning and coordination logic

### Step 5: Testing Infrastructure
- Add unit tests for protocol logic
- Create mock I/O implementations for testing
- Add integration tests with simulated network

## Benefits of Migration

1. **Testability**: Protocol logic can be unit tested without network I/O
2. **Flexibility**: Different I/O backends (UDP, TCP, QUIC) can be swapped
3. **Maintainability**: Clear separation of concerns reduces complexity
4. **Reusability**: Protocol logic can be reused in different contexts
5. **Performance**: Buffer management can be optimized independently

## Backward Compatibility

The migration will maintain the same external API while refactoring internal implementation:
- Same CLI interface
- Same configuration format  
- Same runtime behavior
- Minimal disruption to existing users

## Risk Mitigation

1. **Incremental Migration**: Phase-by-phase refactoring minimizes risk
2. **Testing Coverage**: Comprehensive tests for each phase
3. **Performance Monitoring**: Ensure no performance regression
4. **Feature Flags**: Allow gradual rollout of new architecture

## Next Steps

1. Implement Phase 1: Protocol layer extraction
2. Create unit tests for protocol logic
3. Define I/O traits and start trait-based refactoring
4. Add runtime integration layer
5. Finalize migration with updated main.rs