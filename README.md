# opentun

Relay-first IP tunnel with a sans-IO Noise protocol core, direct UDP upgrade, and local relay/coordination services.

## Overview

`opentun` now uses a split architecture:

- A pure protocol core in `src/protocol/` handles Noise handshakes, encrypted transport, replay protection, keepalives, and path state.
- Async Tokio tasks handle TUN, UDP, relay websocket traffic, coordination websocket traffic, and timer ticks.
- Traffic starts on relay immediately, direct paths are probed in parallel, and the active path switches after authenticated direct traffic is observed.

## Features

- Sans-IO Noise IK transport core with replay protection
- Relay-first startup with direct UDP probing and fallback
- Local websocket relay server role
- Local websocket coordination server role
- STUN-based reflexive candidate discovery
- Role-based runtime: `peer`, `relay`, `coord`, or combined server roles
- YAML config with backwards-compatible defaults for legacy peer configs

## Build

```bash
cargo build
```

## Key Utilities

```bash
cargo run -- genkey
cargo run -- pubkey
```

## Runtime Model

### Peer

Runs the TUN device, UDP socket, relay client, and coordination client.

```bash
sudo cargo run -- --peer --coord-url ws://127.0.0.1:8443 --relay-url ws://127.0.0.1:9443
```

### Relay Server

Runs the local websocket relay that forwards encrypted packets by peer public key.

```bash
cargo run -- --relay --relay-listen 127.0.0.1:9443
```

### Coordination Server

Runs the local websocket coordination service used to publish and receive path candidates.

```bash
cargo run -- --coord --coord-listen 127.0.0.1:8443
```

### Combined Relay + Coord

```bash
cargo run -- --relay --coord --relay-listen 127.0.0.1:9443 --coord-listen 127.0.0.1:8443
```

## Config

Default config shape:

```yaml
name: utun0
address: 10.0.0.1
port: 1194
mtu: 1280
secret: <base64-private-key>
pubkey: <base64-public-key>
node_roles:
  - peer
stun_servers:
  - stun.l.google.com:19302
coordination_url: ws://127.0.0.1:8443
relay_urls:
  - ws://127.0.0.1:9443
relay_listen_addr: null
coord_listen_addr: null
coord_auth_token: null
peers:
  10.0.0.2:
    sock_addr: 192.168.1.20:1194
    pub_key: <peer-base64-public-key>
```

Notes:

- `node_roles` controls the default process mode when CLI role flags are omitted.
- `coordination_url` and `relay_urls` are required for `peer` mode.
- `relay_listen_addr` is required for `relay` mode.
- `coord_listen_addr` is required for `coord` mode.

## Example Deployment

### Server node

```yaml
node_roles:
  - relay
  - coord
relay_listen_addr: 0.0.0.0:9443
coord_listen_addr: 0.0.0.0:8443
coord_auth_token: change-me
```

### Peer node

```yaml
node_roles:
  - peer
coordination_url: ws://server.example.com:8443
relay_urls:
  - ws://server.example.com:9443
stun_servers:
  - stun.l.google.com:19302
```

## Testing

```bash
cargo test
cargo check
```

Privileged Linux VPN smoke test:

```bash
scripts/e2e-vpn.sh
```

The script creates two network namespaces, starts local relay and coordination services,
runs two peers with temporary configs, and verifies `10.88.0.1 <-> 10.88.0.2`
with `ping` over TUN. It defaults to relay-mode end-to-end traffic. To test the
direct UDP upgrade path as well, run:

```bash
OPENTUN_E2E_DIRECT=1 scripts/e2e-vpn.sh
```

Current automated coverage includes:

- wire packet and relay frame roundtrips
- Noise handshake and encrypted transport behavior
- replay rejection and MTU checks
- direct-path probing and fallback logic
- local relay server end-to-end forwarding
- local coordination server end-to-end candidate forwarding

## Current Scope

Implemented:

- relay-first bootstrap
- direct-path probing from published candidates
- keepalive-driven re-probing
- fallback to relay when direct path times out
- local relay and coordination services for development and small deployments

Still minimal:

- path scoring is first-authenticated-direct, not RTT-ranked best-path selection
- integration coverage exercises relay and coordination services directly, not a full privileged TUN-to-TUN system test

## License

MIT
