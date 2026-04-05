# **MASTER PLAN: Project "Silent Noise" (v3.0)**

### **The Strategy: "Inside-Out" Rewrite + Relay-First Upgrade**
We will build a **Sans-IO protocol core** first (pure Rust, no `tokio`, no `std::net`, no OS calls), then attach async drivers.

This plan adds a **path layer** inspired by Tailscale:
- Start traffic on relay immediately (zero wait).
- Probe direct paths in parallel.
- Switch to the best direct path when validated.
- Keep probing in background and fall back to relay if needed.

### **ASCII Diagrams: Protocol Data Flow**

#### **1) Runtime component flow (outbound + inbound)**

```text
Outbound (host -> peer)

  [TUN device]
       |
       v
  +------------------+        Input::TunRx(packet)        +---------------------+
  | TUN reactor      | ----------------------------------> | protocol::Peer core |
  | tasks/tun.rs     |                                     | tick()              |
  +------------------+                                     +---------------------+
                                                               |            |
                                 Output::NetworkTx(path, pkt)  |            | Output::RelayTx(path, frame)
                                                               v            v
                                                     +----------------+  +------------------+
                                                     | UDP reactor    |  | Relay reactor    |
                                                     | tasks/udp.rs   |  | tasks/relay.rs   |
                                                     +----------------+  +------------------+
                                                             |                    |
                                                             v                    v
                                                       [Direct UDP]         [WebSocket relay]


Inbound (peer -> host)

 [Direct UDP] or [WebSocket relay]
              |
              v
  +------------------+        Input::NetworkRx(path, bytes, now_ms)  +---------------------+
  | UDP/Relay reactor| ----------------------------------------------> | protocol::Peer core |
  +------------------+                                                 | tick()              |
                                                                       +---------------------+
                                                                                 |
                                                                                 | Output::TunTx(packet)
                                                                                 v
                                                                            +------------+
                                                                            | TUN reactor |
                                                                            +------------+
                                                                                 |
                                                                                 v
                                                                            [TUN device]
```

#### **2) Packet layering and encapsulation**

```text
Direct path (UDP)

  Inner packet from TUN (IPv4/IPv6 payload)
      -> Noise transport encrypt (snow::TransportState)
      -> WirePacket::TransportData {
             receiver_index,
             counter,
             payload: noise_ciphertext
         }
      -> UDP datagram


Relay path (WebSocket over HTTPS/443)

  Same WirePacket bytes as direct path
      -> RelayFrame::SendPacket {
             dst_pubkey,
             packet: wire_packet_bytes
         }
      -> [1 byte frame_type][4 byte length][payload]
      -> WebSocket message

  Relay server forwards by dst_pubkey only.
  Relay never decrypts Noise payload.
```

#### **3) Session bootstrap: relay-first, then direct upgrade**

```text
Peer A                         Coordination         STUN            Relay           Peer B
  |                                 |                |                |               |
  |--- discover reflexive addr ---->| (local call)   |<-- query ----->|               |
  |<-- local candidate set ---------|                |                |               |
  |--- publish candidates --------->|                |                |               |
  |<-- peer candidates -------------|                |                |               |
  |                                                                      connect WS    |
  |---------------------------------------------------- WebSocket connect -----------> |
  |<--------------------------------------------------- WebSocket connect ------------ |
  |--- Send HandshakeInit via relay frame ----------------------------->|--- fwd ----->|
  |<-- HandshakeResp via relay frame <----------------------------------|<-- fwd ------|
  |--- encrypted data via relay --------------------------------------->|--- fwd ----->|
  |
  |--- parallel direct probes (LAN + reflexive candidates) --------------------------->|
  |<-- first authenticated direct response ---------------------------------------------|
  |--- switch active path relay -> direct (silent) ------------------------------------>|
  |
  |--- background probes continue; if direct fails, fallback to relay ----------------->|
```

#### **4) Path manager state transitions**

```text
                   +------------------+
                   | RelayOnly        |
                   | active=relay     |
                   +------------------+
                            |
                            | candidates available + start probes
                            v
                   +------------------+
                   | Probing          |
                   | relay still used |
                   +------------------+
                      |           |
        best direct ok|           | probe timeout/failure
                      v           |
             +------------------+ |
             | DirectPreferred  | |
             | active=direct    | |
             +------------------+ |
                      |           |
         direct unhealthy         |
                      v           |
                   +------------------+
                   | RelayOnly        |
                   +------------------+

  Tick events keep probing in all steady states.
```

#### **5) Inbound packet handling inside `Peer::tick`**

```text
Input::NetworkRx(path, bytes, now_ms)
              |
              v
     deserialize WirePacket
              |
     +--------+----------------------------+
     |                                     |
     v                                     v
HandshakeInit/Resp                   TransportData/KeepAlive
     |                                     |
  noise.read/write                         parse counter
  maybe transition to Established           replay check
                                            set_receiving_nonce(counter)
                                            noise.read_message
                                            |
                                            v
                                       Output::TunTx
```

---

## **PHASE 1: Protocol Contracts (Sans-IO)**
**Goal:** Define deterministic packet formats, events, errors, and state boundaries.

### **Plan 1.1: Wire Formats**
*Context: Define all data structures and codecs before behavior.*

1. **Action:** Create `src/protocol/wire.rs`.
   - Implement `WirePacket` with explicit type tags and manual parsing.
   - Use a **shared outer header** so routing is unambiguous for all packet types.
   - Define:
     - `HandshakeInit { sender_index: u32, receiver_index: Option<u32>, noise_msg: Vec<u8> }`
     - `HandshakeResp { sender_index: u32, receiver_index: u32, noise_msg: Vec<u8> }`
     - `TransportData { receiver_index: u32, counter: u64, payload: Vec<u8> }`
     - `KeepAlive { receiver_index: u32, counter: u64 }`
   - `serialize(&self) -> Vec<u8>` and `deserialize(bytes: &[u8]) -> Result<Self>`.
   - Add size guards for max packet length.

2. **Action:** Create `src/relay/frame.rs`.
   - Define relay frame format:
     - `[1 byte frame_type][4 byte be_length][payload]`
   - Frame types:
     - `SendPacket { dst_pubkey: [u8; 32], packet: Vec<u8> }`
     - `RecvPacket { src_pubkey: [u8; 32], packet: Vec<u8> }`
     - `Ping { nonce: u64 }`
     - `Pong { nonce: u64 }`
     - `PeerPresent { pubkey: [u8; 32] }`

3. **Action:** Create `src/protocol/errors.rs`.
   - Define `ProtocolError`:
     - `Snow(snow::Error)`
     - `Serialization`
     - `PacketTooLarge`
     - `UnknownPacket`
     - `UnknownPeer`
     - `ReplayRejected`
     - `PathUnavailable`

### **Plan 1.2: Core Events (Strict Sans-IO)**
*Context: Core must not know sockets or OS time types.*

1. **Action:** Create `src/protocol/events.rs`.
   - `type PathId = u32`.
   - `type PeerId = u32`.
   - `Input`:
     - `NetworkRx { path: PathId, bytes: Vec<u8>, now_ms: u64 }`
     - `TunRx(Vec<u8>)`
     - `Tick { now_ms: u64 }`
     - `CandidatesUpdated { peer: PeerId, candidates: Vec<Candidate> }`
   - `Output`:
     - `NetworkTx { path: PathId, bytes: Vec<u8> }`
     - `RelayTx { relay_path: PathId, frame: Vec<u8> }`
     - `TunTx(Vec<u8>)`
     - `PublishLocalCandidates`
     - `Log(String)`

2. **Action:** Create `src/protocol/path.rs`.
   - Define candidate and path metadata:
     - `Candidate::Lan`, `Candidate::Reflexive`, `Candidate::Relay`
     - `PathKind::Direct`, `PathKind::Relay`
     - `PathStatus::Unknown`, `Probing`, `Healthy`, `Failed`

### **Plan 1.3: Peer Skeleton**
*Context: State machine shape only, no crypto yet.*

1. **Action:** Create `src/protocol/peer.rs`.
   - `Peer { state: PeerState, path_manager: PathManager, ... }`
   - `PeerState`:
     - `Handshaking`
     - `Established`
   - Signature:
     - `pub fn tick(&mut self, input: Input) -> Result<Vec<Output>, ProtocolError>`

2. **Tests:** Add unit tests for:
   - Wire packet round-trip encoding/decoding.
   - Relay frame round-trip encoding/decoding.
   - `tick(TunRx(...))` in `Handshaking` does not panic.

---

## **PHASE 2: Noise Data Plane**
**Goal:** Integrate `snow` into peer state machine correctly.

### **Plan 2.1: Dependencies and Peer Config**
*Context: Build robust crypto state ownership.*

1. **Action:** Add dependencies:
   - `snow = "0.10"`
   - `base64`

2. **Action:** Define config in `src/protocol/peer.rs`:
   - `PeerRole::{Initiator, Responder}`
   - `PeerConfig {`
     - `role: PeerRole,`
     - `static_private: [u8; 32],`
     - `remote_public: [u8; 32],`
     - `psk: Option<[u8; 32]>,`
     - `mtu: usize,`
     - `home_relay_path: PathId,`
     - `}`

### **Plan 2.2: Handshake State**
*Context: Deterministic handshake with clear kickoff behavior.*

1. **Action:** Implement `PeerState::Handshaking { noise: snow::HandshakeState }`.
2. **Action:** Add startup method:
   - `pub fn bootstrap(&mut self, now_ms: u64) -> Result<Vec<Output>, ProtocolError>`
   - Initiator writes handshake message and emits `NetworkTx` on active path (relay first).
3. **Action:** On `NetworkRx` handshake packets:
   - Parse packet kind and call `noise.read_message()`.
   - If it is our turn, call `noise.write_message()` and emit response.
4. **Completion:** On finish, call `into_transport_mode()` and transition to:
   - `PeerState::Established { transport: snow::TransportState, replay: ReplayWindow }`

### **Plan 2.3: Transport + Replay + MTU Safety**
*Context: Encrypt/decrypt with explicit nonce and replay checks.*

1. **Action:** Outbound (`TunRx` in `Established`):
   - Check `packet.len() <= (config.mtu - PROTOCOL_OVERHEAD)`.
   - Read `counter = transport.sending_nonce()` before encryption.
   - `transport.write_message()` then emit `TransportData { receiver_index, counter, payload }`.

2. **Action:** Inbound (`NetworkRx` transport packet):
   - Parse `counter`.
   - Check replay window first.
   - Set receive nonce to `counter`, then `transport.read_message()`.
   - On success: mark replay window and emit `TunTx`.

3. **Tests:** Add peer unit tests for:
   - Handshake completion (initiator/responder).
   - Transport encrypt/decrypt roundtrip.
   - Replay rejection for duplicate counter.
   - Oversized TUN packet rejection.

---

## **PHASE 3: Traversal and Relay Control Plane**
**Goal:** Add magicsock-like path management while keeping payload encryption end-to-end.

### **Plan 3.1: Candidate Discovery and Coordination**
*Context: Learn and exchange reachable addresses.*

1. **Action:** Add control-plane modules:
   - `src/control/stun.rs` (query STUN servers, collect reflexive candidates)
   - `src/control/coord.rs` (publish local candidates, receive remote candidates)

2. **Action:** Candidate sets include:
   - Local/LAN addresses
   - STUN reflexive address
   - Assigned home relay path

3. **Action:** Feed candidate updates into peer core using `Input::CandidatesUpdated`.

### **Plan 3.2: Relay-First Path Behavior**
*Context: Zero-delay startup with direct upgrade.*

1. **Action:** On session start:
   - Set active path to home relay immediately.
   - Send handshake and data on relay with no waiting.

2. **Action:** In parallel, probe all direct candidates.
   - LAN candidates first, then reflexive pairs.
   - Record RTT and success rate per path.

3. **Action:** Switch policy:
   - If a direct path is authenticated and faster than relay, switch silently.
   - If direct becomes unhealthy, fall back to relay immediately.

4. **Action:** Background re-probing:
   - Keep probing every N seconds even when a direct path is active.
   - Allow seamless upgrades/downgrades after network changes.

### **Plan 3.3: Relay Protocol Integration**
*Context: Relay server forwards encrypted packets only.*

1. **Action:** Build relay client transport over WebSocket/HTTPS 443.
2. **Action:** Use relay frames from `src/relay/frame.rs`.
3. **Action:** Relay server behavior remains minimal:
   - Route by destination public key.
   - Never decrypt or inspect inner Noise/Wire payload.

### **Plan 3.4: Node Roles via Flags (Peer/Relay/Coord)**
*Context: Single binary can run one or more roles.*

1. **Action:** Add runtime role flags:
   - `--peer` (default)
   - `--relay`
   - `--coord`
   - Allow combinations (example: `--relay --coord`).

2. **Action:** Startup behavior by selected roles:
   - `peer`: run TUN + UDP + relay client + coordination client.
   - `relay`: run relay websocket listener and packet forwarder.
   - `coord`: run candidate publish/subscribe service.
   - `relay + coord`: run both services in one process.

3. **Action:** Safety and deployment rules:
   - Relay/coord roles require explicit bind addresses and auth config.
   - If server roles are enabled without required config, fail fast at startup.
   - Keep relay and coordination protocol-independent of inner payload crypto.

4. **Action:** Recommended deployment:
   - Dev/small deployments: combined `relay + coord` is supported.
   - Production: allow split services for scaling and fault isolation.

#### **CLI usage examples (roles)**

```text
# Peer mode (default data-plane node)
opentun --peer

# Relay-only node
opentun --relay --relay-listen 0.0.0.0:443

# Coordination-only node
opentun --coord --coord-listen 0.0.0.0:8443

# Combined relay + coordination node
opentun --relay --coord --relay-listen 0.0.0.0:443 --coord-listen 0.0.0.0:8443

# Peer pinned to specific services
opentun --peer --coord-url https://coord.example.com --relay-url wss://relay.example.com/ws
```

```text
Validation rules:
- If --relay is set, --relay-listen must be provided.
- If --coord is set, --coord-listen must be provided.
- If --peer is set, coordination and relay endpoints must be configured.
- Unknown role combinations fail fast.
```

---

## **PHASE 4: Async Shell (Tokio Drivers)**
**Goal:** Connect Sans-IO core to UDP, TUN, relay socket, and coordination channels.

### **Plan 4.1: Router and Runtime State**
*Context: Keep shell responsibilities outside the core.*

1. **Action:** Create `src/net/router.rs`.
   - `Router` stores peers by tunnel destination and by protocol index.
   - Routing for handshake packets that may not have `receiver_index` yet uses endpoint or key mapping.

### **Plan 4.2: UDP Reactor**
*Context: Direct path network driver.*

1. **Action:** Rewrite `src/tasks/udp.rs`.
   - Reuse one `[u8; 65535]` buffer in the loop.
   - Convert incoming datagrams to `Input::NetworkRx { path, bytes, now_ms }`.
   - Execute outputs:
     - `NetworkTx` -> UDP send on selected path.
     - `TunTx` -> TUN channel.
     - `RelayTx` -> relay channel.

### **Plan 4.3: TUN Reactor**
*Context: Data plane ingress from OS.*

1. **Action:** Rewrite `src/tasks/tun.rs`.
   - TUN MTU comes from config, default `1280`.
   - Parse destination IP, resolve peer, call `tick(TunRx(...))`.
   - Execute resulting `NetworkTx`/`RelayTx`.

### **Plan 4.4: Relay and Coordination Reactors**
*Context: Control and fallback paths.*

1. **Action:** Add `src/tasks/relay.rs` for websocket relay read/write loop.
2. **Action:** Add `src/tasks/coord.rs` for candidate publish/subscribe.
3. **Action:** Add `src/tasks/timer.rs` to inject `Tick { now_ms }` events.

---

## **PHASE 5: Hardening and Validation**
**Goal:** Production safety and migration confidence.

1. **Action:** Keepalive and liveness.
   - Trigger keepalive every 15s if idle.
   - Track path health and failover counters.

2. **Action:** Roaming.
   - On authenticated packet from a new direct endpoint, update peer endpoint mapping.

3. **Action:** Configuration migration.
   - Extend config with:
     - `node_roles: Vec<String>` (`peer`, `relay`, `coord`)
     - `stun_servers: Vec<String>`
     - `coordination_url: String`
     - `relay_urls: Vec<String>`
     - `relay_listen_addr: Option<String>`
     - `coord_listen_addr: Option<String>`
     - `coord_auth_token: Option<String>`
   - Keep backward compatibility with existing peer entries.

4. **Action:** Test matrix.
   - Unit: codec, replay window, path score logic.
   - Integration: two peers direct path on LAN.
   - Integration: relay-only path when direct fails.
   - Integration: relay-first then silent switch to direct.
   - Integration: runtime fallback to relay after direct failure.

5. **Exit criteria:**
   - First encrypted packet is delivered via relay without waiting for punch.
   - Direct upgrade happens automatically when available.
   - No payload decryption capability exists at relay.
   - Existing `ping` scenario passes under both direct and relay paths.
