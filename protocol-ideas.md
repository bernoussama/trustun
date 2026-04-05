i want to add another layer over the data layer similar to tailscale for nat traversal the logic im thinking of is:

1. Queries STUN servers → learns public IP:port (reflexive address)
2. Reports candidates to coordination server
3. Receives peer's candidates from coordination server  
4. Probes all candidate pairs simultaneously:
   - Peer's local IPs (same LAN?)
   - Peer's STUN-reflexive address (hole punch)
   - DERP-like relay (always works, used as fallback)
5. Picks the fastest working path
6. Continuously re-probes in background (path can change)

always sends via DERP first while probing — so there's zero connection delay. If a direct path is found, it silently switches over.


How DERP relay works:

```
```
Peer A (CGNAT)                DERP Server              Peer B (strict NAT)
     │                             │                         │
     │── WebSocket (HTTPS/443) ───→│←── WebSocket ───────────│
     │                             │                         │
     │── WireGuard pkt (encrypted)→│── forward to B ────────→│
     │←─────────────────────────────── WireGuard pkt ────────│
     │                             │                         │
     │    [magicsock probing in background...]                 │
     │                             │                         │
     │←────────── direct UDP (if hole punch succeeds) ───────│
     │    [DERP traffic stops, direct path takes over]         │
```
```


DERP frame format is minimal:

```
```
[1 byte frame type][4 byte length][payload]

Frame types:
- SendPacket  → relay this to peer X
- RecvPacket  → here's a packet from peer X
- Ping/Pong   → keepalive + latency measurement
- PeerPresent → peer X is connected to this DERP node
```
```

The DERP server just reads the destination public key from the frame header and forwards the encrypted blob. It never touches the WireGuard payload.
4. Path Selection and Upgrade
This is one of the most elegant parts. Tailscale uses a always-relay-then-upgrade strategy:
t=0ms   → Start sending via DERP immediately (no latency waiting for hole punch)
t=0ms   → magicsock starts sending UDP probes to all candidates in parallel
t=~500ms → If a direct UDP path responds → switch to direct silently
t=ongoing → Keep re-checking in background (network changes, roaming, etc.)
The peer on the other end doesn't notice the switch — WireGuard sessions are stateless enough that changing the underlying transport path is seamless.

## What to steal for trustun
From WireGuard: the roaming idea — when you receive a valid authenticated packet, update the peer's endpoint. Simple and effective.
From Tailscale/DERP:

Always relay first, upgrade to direct — don't make users wait for hole punch negotiation before traffic flows
WebSocket/443 for relay — gets through corporate firewalls that block raw UDP
Continuous background re-probing — paths change (mobile networks, roaming), keep checking
Home relay assignment — assign each peer a relay server by latency, not randomly
