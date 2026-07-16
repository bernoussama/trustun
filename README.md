# opentun - IP over UDP VPN

A secure, high-performance user-space IP-over-UDP tunnel implementation written in Rust using async I/O and modern cryptography.

## Overview

**opentun** creates a TUN interface that tunnels IP packets over UDP with ChaCha20-Poly1305 encryption. It enables secure communication between peers across networks using Curve25519 key exchange and YAML-based configuration.

## Features

- ✅ **IP-over-UDP tunneling** - Encapsulate IP packets in UDP for transport
- ✅ **Async I/O** - Built with Tokio for high performance
- ✅ **ChaCha20-Poly1305 encryption** - Modern authenticated encryption
- ✅ **Curve25519 key exchange** - Elliptic curve Diffie-Hellman key agreement
- ✅ **YAML configuration** - Persistent peer and key management
- ✅ **Key generation tools** - Built-in cryptographic key utilities
- ✅ **IPv4 support** - Full IPv4 packet routing
- ⏳ **Planned**: IPv6 support, rate limiting, improved error handling

## Quick Start

### Prerequisites

- Rust 1.70+
- Linux/macOS (requires TUN interface support)
- Root privileges (for TUN interface creation)

### Installation

```bash
git clone https://github.com/yourusername/opentun
cd opentun
cargo build --release
```

### Key Generation

Generate cryptographic keys for secure communication:

```bash
# Generate a private key
./target/release/opentun genkey

# Generate public key from private key
./target/release/opentun pubkey
```

### Configuration

Create a `config.yaml` file or let opentun generate a default one:

```yaml
name: "utun0"
address: "10.0.0.1"
port: 1194
secret: "base64-encoded-private-key"
pubkey: "base64-encoded-public-key"
peers:
  10.0.0.2:
    sock_addr: "192.168.1.100:1194"
    pub_key: "peer-base64-public-key"
```

### Basic Usage

```bash
# Run with configuration file (recommended)
sudo ./target/release/opentun

# CLI arguments (legacy support)
sudo ./target/release/opentun [NAME] [ADDRESS] [PORT]
```

### Using the Helper Script

```bash
# Build and run with proper capabilities
chmod +x run.sh
./run.sh
```

## Command Line Options

```
Usage: opentun [OPTIONS] [NAME] [ADDRESS] [PORT]

Arguments:
  [NAME]     TUN interface name (default: from config)
  [ADDRESS]  Local IP address (default: from config) 
  [PORT]     UDP port to bind (default: from config)

Commands:
  genkey     Generate a new private key
  pubkey     Generate public key from private key

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## How It Works

1. **TUN Interface**: Creates a virtual network interface that captures IP packets
2. **Encryption**: Each packet is encrypted with ChaCha20-Poly1305 using shared secrets
3. **Key Exchange**: Curve25519 Diffie-Hellman establishes shared secrets between peers
4. **UDP Transport**: Encrypted packets are transmitted over UDP with random nonces
5. **Configuration**: Peers are defined in YAML with their public keys and addresses

```
┌─────────────┐    Encrypted UDP    ┌─────────────┐
│   Client A  │◄─────────────────►│   Client B  │
│             │  ChaCha20-Poly1305  │             │
│ TUN: tun0   │   + Curve25519      │ TUN: tun0   │
│ IP: 10.0.0.1│                     │ IP: 10.0.0.2│
└─────────────┘                     └─────────────┘
```

## Packet Flow Diagram

```
Peer A (10.0.0.1)                                    Peer B (10.0.0.2)
┌─────────────────┐                                   ┌─────────────────┐
│  Application    │                                   │  Application    │
└─────────┬───────┘                                   └─────────┬───────┘
          │ IP packet (10.0.0.1 → 10.0.0.2)                     │
          ▼                                                     ▼
┌─────────────────┐                                   ┌─────────────────┐
│   TUN Device    │                                   │   TUN Device    │
│    (utun0)      │                                   │    (utun0)      │
└─────────┬───────┘                                   └─────────┬───────┘
          │                                                     ▲
          │ 1. Read IP packet                                   │ 6. Write decrypted
          ▼                                                     │    IP packet
┌─────────────────┐                                   ┌─────────────────┐
│ opentun Process │                                   │ opentun Process │
│                 │                                   │                 │
│ ┌─────────────┐ │                                   │ ┌─────────────┐ │
│ │ Extract     │ │                                   │ │ Decrypt     │ │
│ │ dst IP      │ │                                   │ │ with shared │ │
│ └─────────────┘ │                                   │ │ secret      │ │
│ ┌─────────────┐ │                                   │ └─────────────┘ │
│ │ Lookup peer │ │                                   │ ┌─────────────┐ │
│ │ config      │ │                                   │ │ Verify      │ │
│ └─────────────┘ │                                   │ │ nonce +     │ │
│ ┌─────────────┐ │                                   │ │ auth tag    │ │
│ │ Generate    │ │                                   │ └─────────────┘ │
│ │ random      │ │                                   │                 │
│ │ nonce       │ │                                   │                 │
│ └─────────────┘ │                                   │                 │
│ ┌─────────────┐ │                                   │                 │
│ │ Encrypt     │ │                                   │                 │
│ │ with shared │ │                                   │                 │
│ │ secret      │ │                                   │                 │
│ └─────────────┘ │                                   │                 │
└─────────┬───────┘                                   └─────────┬───────┘
          │                                                     ▲
          │ 2. Send encrypted                                   │ 5. Receive encrypted
          │    packet over UDP                                  │    packet from UDP
          ▼                                                     │
┌─────────────────┐                                   ┌─────────────────┐
│   UDP Socket    │                                   │   UDP Socket    │
│ (port 1194)     │                                   │ (port 1194)     │
└─────────┬───────┘                                   └─────────┬───────┘
          │                                                     ▲
          │ 3. Network transmission                             │
          │    [nonce(12) + encrypted_data + auth_tag(16)]      │
          └─────────────────────────────────────────────────────┘
                           4. Internet/LAN

Legend:
- Shared Secret = ECDH(local_private_key, peer_public_key)
- Encryption = ChaCha20-Poly1305(shared_secret, nonce, ip_packet)
- Packet Format = nonce || encrypted_data_with_auth_tag
```

## Configuration Examples

### Two-Node Setup

**Node A:**

1. Generate keys:

```bash
# Generate private key
PRIVATE_A=$(./target/release/opentun genkey)
# Generate public key  
PUBLIC_A=$(echo "$PRIVATE_A" | ./target/release/opentun pubkey)
```

2. Create config.yaml:

```yaml
name: "utun0"
address: "10.0.0.1"
port: 1194
secret: "$PRIVATE_A"
pubkey: "$PUBLIC_A" 
peers:
  10.0.0.2:
    sock_addr: "192.168.1.100:1194"
    pub_key: "$PUBLIC_B"  # Get from Node B
```

3. Run:

```bash
sudo ./target/release/opentun
```

**Node B:**

1. Generate keys and create similar config with reversed IPs
2. Exchange public keys securely with Node A
3. Run the tunnel

### Network Configuration

After starting opentun, configure routing:

```bash
# Add route for the tunnel network
sudo ip route add 10.0.0.0/24 dev utun0

# Bring interface up (if needed)
sudo ip link set up dev utun0
```

## Architecture

- **Async Design**: Uses `tokio::select!` for concurrent TUN/UDP handling
- **Encryption**: ChaCha20-Poly1305 authenticated encryption with random nonces
- **Key Exchange**: Curve25519 elliptic curve Diffie-Hellman key agreement
- **Configuration**: YAML-based peer management with persistent keys
- **Zero-Copy**: Efficient packet forwarding with minimal allocations
- **Error Resilience**: Continues operation despite individual packet errors

## Development Status

This project is experimental and in development.

### Current Limitations

- IPv4 only  
- Static peer configuration (no dynamic discovery)
- No structured logging
- No rate limiting or DoS protection
- Basic error recovery

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security Notice

✅ **This software uses ChaCha20-Poly1305 encryption with Curve25519 key exchange for secure communication.** While cryptographically secure, ensure proper key management.
⚠️ **This software is an experiment and not meant to be used in production**.
