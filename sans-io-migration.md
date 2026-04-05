# **MASTER PLAN: Project "Silent Noise" (v2.0)**

### **The Strategy: "Inside-Out" Rewrite**
We are building a **Sans-IO Protocol Core** in isolation (pure Rust, no `tokio`, no `std::net`, no OS calls), verifying it with unit tests, and *then* building the async shell around it. This ensures the crypto and state logic are deterministic and fuzzable.

---

## **PHASE 1: The Protocol Definition (Sans-IO)**
**Goal:** Define packets, errors, and state machines without touching a socket.

### **Plan 1.1: Protocol Scaffolding**
*Context: Define the data structures. No logic yet.*

1.  **Action:** Create `src/protocol/wire.rs`.
    *   Implement `WirePacket` enum.
    *   **Struct:** `HandshakeInit { sender_index: u32, ephemeral: [u8; 32], payload: Vec<u8> }`
    *   **Struct:** `HandshakeResp { sender_index: u32, ephemeral: [u8; 32], payload: Vec<u8> }`
    *   **Struct:** `TransportData { receiver_index: u32, counter: u64, payload: Vec<u8> }`
    *   **Req:** Use `bincode` or manual parsing. Must implement `serialize` -> `Vec<u8>` and `deserialize` -> `Result<Self>`.

2.  **Action:** Create `src/protocol/errors.rs`.
    *   Define `pub enum ProtocolError`:
        *   `Snow(snow::Error)`
        *   `Serialization(bincode::Error)`
        *   `InvalidNonce`
        *   `PacketTooLarge`
        *   `UnknownPacket`

3.  **Action:** Create `src/protocol/events.rs`.
    *   **Enum `Input`:** `UdpPacket(Vec<u8>, SocketAddr)`, `TunPacket(Vec<u8>)`, `Tick(Instant)`.
    *   **Enum `Output`:** `SendUdp(Vec<u8>, SocketAddr)`, `WriteTun(Vec<u8>)`, `Log(String)`.

### **Plan 1.2: The Peer Skeleton**
*Context: The empty state machine.*

1.  **Action:** Create `src/protocol/peer.rs`.
    *   **Struct:** `Peer` holding `state: PeerState`.
    *   **Enum `PeerState`:** `Handshaking`, `Established`.
    *   **Signature:** `pub fn tick(&mut self, input: Input) -> Result<Vec<Output>, ProtocolError>`.
2.  **Test:** Write a unit test that feeds a dummy `Input::TunPacket` and asserts the function returns `Ok`.

---

## **PHASE 2: The Noise Crypto Layer**
**Goal:** Integrate `snow` (Noise Protocol Framework) into the state machine.

### **Plan 2.1: Dependencies & Configuration**
*Context: Setup keys and libraries.*

1.  **Action:** Add `snow = "0.9.6"` and `base64` to `Cargo.toml`.
2.  **Action:** Update `Peer` struct in `src/protocol/peer.rs`.
    *   Create `pub struct PeerConfig { pub static_private: [u8; 32], pub remote_public: [u8; 32], pub psk: Option<[u8; 32]> }`.
    *   Update `Peer::new(config: PeerConfig)` to initialize the `PeerState`.

### **Plan 2.2: Handshake Logic**
*Context: Establish the session.*

1.  **Action:** Implement `Handshaking` state logic.
    *   **Fields:** Add `noise: snow::HandshakeState` to `PeerState::Handshaking`.
    *   **Transition (Init):** On creation, call `noise.write_message()` to generate Handshake Packet 1. Return `Output::SendUdp`.
    *   **Transition (Recv):** On `Input::UdpPacket` (Type: Handshake), call `noise.read_message()`.
    *   **Completion:** If handshake finishes, split transport state (Tx/Rx), transition `PeerState` to `Established`.

### **Plan 2.3: Transport Logic & MTU Safety**
*Context: Encrypt/Decrypt data packets.*

1.  **Action:** Implement `Established` state logic.
    *   **Fields:** Add `tx: TransportState, rx: TransportState` to `PeerState::Established`.
2.  **Action:** Handle `Input::TunPacket` (Encrypt).
    *   **Check:** `if packet.len() > (1500 - OVERHEAD) { return Err(ProtocolError::PacketTooLarge); }`
    *   **Logic:** Use `tx.write_message()`. Explicitly grab the `nonce` and write it into the `TransportData` header.
3.  **Action:** Handle `Input::UdpPacket` (Decrypt).
    *   **Logic:** Parse header for `counter`. Call `rx.set_receiving_nonce(counter)`. Call `rx.read_message()`.
    *   **Result:** Return `Output::WriteTun`.

---

## **PHASE 3: The Async Shell (Tokio)**
**Goal:** Wire the pure state machine to the OS. This is the **only** place `async/.await` is allowed.

### **Plan 3.1: The Synchronous Router**
*Context: Shared state management.*

1.  **Action:** Create `src/net/router.rs`.
    *   **Struct:** `Router`.
    *   **Storage:** `peers_by_ip: HashMap<u32, Arc<std::sync::Mutex<Peer>>>` (Note: `std::sync`, not `tokio`).
    *   **Routing Logic:** Basic IPv4 `/32` lookup. If IP matches, return the locked Peer.

### **Plan 3.2: The UDP Reactor**
*Context: The network driver.*

1.  **Action:** Rewrite `src/tasks/udp.rs`.
    *   **Buffer:** Allocate a single `[u8; 65535]` buffer outside the loop (reuse it).
    *   **Loop:** `socket.recv_from`.
    *   **Process:**
        1. Parse first 4 bytes for `ReceiverIndex`.
        2. Lookup `Peer` in Router.
        3. `let outputs = peer.lock().unwrap().tick(Input::UdpPacket(...))?`.
        4. Execute outputs: `SendUdp` -> `socket.send_to`. `WriteTun` -> Send to TUN channel.

### **Plan 3.3: The TUN Reactor**
*Context: The OS interface.*

1.  **Action:** Rewrite `src/tasks/tun.rs`.
    *   **Config:** hardcode TUN Interface MTU to **1280** (Safe V1 default).
    *   **Loop:** `tun.read`.
    *   **Process:**
        1. Parse IP Header for `DstIP`.
        2. Lookup `Peer` in Router.
        3. `peer.lock().unwrap().tick(Input::TunPacket(...))`.
        4. Execute outputs (mostly `SendUdp`).

---

## **PHASE 4: Cleanup & Hardening**
**Goal:** Production readiness.

1.  **Action:** **Replay Protection.** Implement a sliding window bitmap (e.g., `[u64; 2]`) in `Peer` to reject duplicate nonces.
2.  **Action:** **Timers.** Update `tick()` to handle `Input::Tick`. Trigger Keepalives every 15s if idle.
3.  **Action:** **Roaming.** In `peer.rs`, update the "Current Endpoint" `SocketAddr` whenever an authenticated packet arrives from a *new* address.
4.  **Action:** **Integration Test.** Spin up two instances locally on different ports and verify `ping`.
