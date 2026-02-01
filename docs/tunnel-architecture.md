# Tunnel Architecture

This document describes the architecture of the Omerta Mesh Tunnel system — a session-based communication layer built on top of the Omerta Mesh network.

## Layer Overview

```
Application
    │  send(data) / receiveHandler(data)
    ▼
TunnelSession          – per-(machineId, channel) session with batching
    │
TunnelManager          – session pool, handshake protocol, health monitoring
    │
ChannelProvider        – abstract channel-based messaging interface
    │
MeshNode               – routing, encryption, multi-endpoint, relay
    │
UDP / Network
```

## Session Lifecycle

### Keys and States

Each session is identified by a `TunnelSessionKey(remoteMachineId, channel)`. Sessions progress through states:

```
connecting → active → degraded → disconnected
                  │                    ▲
                  └────────────────────┘  (close or failure)
```

- **connecting**: Handshake in progress.
- **active**: Fully established, data can flow.
- **degraded**: Health monitor detected missed probes but hasn't declared failure. Sends still allowed.
- **disconnected**: Closed normally.
- **failed(reason)**: Error occurred.

### Handshake Protocol

Sessions are established over the `tunnel-handshake` channel using JSON-encoded messages:

1. **Initiator** sends `{type: "request", channel: "data", sessionId: "a1b2c3d4"}`.
2. **Responder** calls its `inboundSessionHandler` factory. If it returns a receive callback, accept; otherwise reject.
3. **Responder** sends `{type: "ack", channel: "data", sessionId: "a1b2c3d4"}` (or `"reject"`).
4. Both sides create a `TunnelSession` and mark it active.

Close uses `{type: "close", channel, sessionId}`. The sessionId prevents stale close messages from killing a newer session on the same key.

### Pre-Session Buffering

Data that arrives on a wire channel before the handshake completes is buffered (up to 32 packets per key, 5s TTL) and flushed to the session once it's created.

## Health Monitoring

### Design

Health is tracked **per-machine**, not per-session. Multiple sessions to the same machine share one `TunnelHealthMonitor` actor. Both sides independently run monitors and send probes — there is no echo/response protocol.

Liveness is determined by whether *any* packet (probes, application data, etc.) has been received from the remote machine since the last check.

### Algorithm

```
graceRemaining ← graceIntervals     // skip early failure counting
consecutiveFailures ← 0
probeInterval ← minProbeInterval
degradedFired ← false

loop:
    packetTimeBefore ← lastPacketTime
    send probe to remote
    sleep(probeInterval)

    if pendingRecovery:
        pendingRecovery ← false
        if degradedFired:
            degradedFired ← false
            call onRecovered

    if graceRemaining > 0:
        graceRemaining -= 1
        continue

    if lastPacketTime > packetTimeBefore:
        // Packet received — remote is alive
        consecutiveFailures ← 0
        probeInterval ← min(probeInterval * 2, maxProbeInterval)
        continue

    // No packet received — failure
    consecutiveFailures += 1

    if consecutiveFailures == degradedThreshold and not degradedFired:
        degradedFired ← true
        call onDegraded          // sessions marked degraded, sends still work

    if consecutiveFailures >= failureThreshold:
        call onFailure           // sessions closed, monitor stops
        break
```

### Packet Received (any source)

When any packet arrives from a machine (data dispatch, health probe, etc.):

```
wasDegraded ← consecutiveFailures >= degradedThreshold
lastPacketTime ← now
probeInterval ← minProbeInterval
consecutiveFailures ← 0
if wasDegraded:
    pendingRecovery ← true       // onRecovered fires next loop iteration
```

### Thresholds

| Parameter | Default | Effect |
|-----------|---------|--------|
| `healthProbeMinInterval` | 500ms | Initial probe frequency |
| `healthProbeMaxInterval` | 15s | Maximum backoff interval |
| `healthDegradedThreshold` | 3 | Consecutive misses before degraded |
| `healthFailureThreshold` | 6 | Consecutive misses before hard failure |
| `healthGraceIntervals` | 3 | Initial intervals where failures aren't counted |

### Any-Packet Liveness

Data packets dispatched to sessions also count as liveness. `dispatchToSession` calls `notifyPacketReceived(from: machineId)` before delivering to the session, so a machine that's actively sending data will never be declared unhealthy even if dedicated health probes are lost.

### Endpoint Change Detection

`EndpointChangeDetector` monitors OS-level network changes:
- **macOS/iOS**: NWPathMonitor for interface status changes.
- **Linux**: Polls `getifaddrs()` every 2 seconds for IP address changes.

When a change is detected, all health monitors get their failure counters reset (`reprobeAllMachines`), forcing a fresh liveness check on the new network path.

## Batching

### Two Levels

Batching operates at two layers:

1. **TunnelSession batching** — `send()` buffers packets; `flush()` packs and sends. Auto-flush fires after `maxFlushDelay` (default 1ms). Hard limit: UDP datagram size (~65KB).

2. **ChannelProvider (mesh-level) batching** — `sendOnChannelBuffered()` accumulates at the mesh layer with its own `BatchConfig`. `flushChannel()` sends.

Both layers use the same `BatchConfig` struct:

```swift
struct BatchConfig {
    var maxFlushDelay: Duration    // default: 1ms
    var maxBufferSize: Int         // default: 0 (no byte limit, only datagram limit)
}
```

### Wire Format

```
Single packet:  [0x01][payload bytes...]
Batch:          [0x02][reserved:1B][count:2B BE]
                  [len₁:2B BE][data₁][pad?]
                  [len₂:2B BE][data₂][pad?]
                  ...
```

Each packet is padded to 2-byte alignment (at most 1 byte). Unpacking returns the original payloads.

### Probe Stats

Health probes carry per-channel receive statistics so each side knows its delivered throughput as reported by the remote:

```
Probe payload:  [channelCount:1B]
  per channel:  [nameLen:1B][name bytes][bytesPerSec:8B LE][packetsPerSec:8B LE]
```

Round-robin selects up to 10 channels per probe to bound payload size.

## Multi-Endpoint and Relay Support

### Endpoint Management

`PeerEndpointManager` tracks endpoints per `(peerId, machineId)` pair, persisted to `~/.omerta/mesh/networks/{networkId}/peer_endpoints.json`.

- Endpoints are ordered by recency (front = best).
- On successful communication, the used endpoint is promoted to front.
- `EndpointUtils.preferredEndpoint()` prefers IPv6 over IPv4.

### Auto-Routing

`MeshNode.sendWithAutoRouting` tries delivery strategies in order:

1. **IPv6 direct** — if peer has an IPv6 endpoint (no NAT issues).
2. **Direct** — if peer's NAT type is known to be directly reachable.
3. **Relay via best relay** — if relay paths are available.
4. **Relay via any connected relay** — fallback.
5. **Direct anyway** — last resort.

### Relay Protocol

Relay sessions use these message types on the `mesh-relay` channel:

- `relayRequest(targetPeerId, sessionId)` → request relay
- `relayAccept(sessionId)` / `relayDeny(sessionId, reason)`
- `relayData(sessionId, data)` → payload forwarding
- `relayEnd(sessionId)` → teardown
- `relayForward(targetPeerId, payload)` → simple store-and-forward

`RelayManager` maintains a pool of relay connections (default 3-5) with periodic health checks.

## Wire Encryption (Binary Envelope V3)

All mesh traffic uses a three-section encrypted envelope:

```
[3B magic "OMR"][1B version=0x03]
[12B nonce][16B routing_tag][44B encrypted routing header]
[16B auth_tag][128B encrypted auth header]
[4B payload_length][chunked encrypted payload...]
```

- **Routing header**: Encrypted with network key. Contains channel hash, source/destination, and message metadata. Readable by any network member for forwarding.
- **Auth header**: Encrypted with peer session key. Contains sender identity and signature.
- **Payload**: Chunked in 512-byte blocks, each with its own Poly1305 tag, enabling parallel decryption.

Nonces use domain separation (XOR with 0x00 for routing, 0x01 for auth, 0x02+ for payload chunks).
