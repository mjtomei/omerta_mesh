# OmertaMesh Migration Guide

This document describes the migration from the legacy API to the new channel-based utility services.

## Table of Contents

1. [Overview](#overview)
2. [Code Being Removed](#code-being-removed)
3. [Code Replacement Map](#code-replacement-map)
4. [Infrastructure Migration](#infrastructure-migration)
5. [Test Strategy](#test-strategy)
6. [Implementation Phases](#implementation-phases)

---

## Overview

The utility services introduce a **channel-based architecture** that **replaces** the legacy API. This is not an additive change - the utilities supersede existing capabilities.

### Key Changes

| Legacy | Replacement | Notes |
|--------|-------------|-------|
| `MeshNetwork.ping()` | `mesh.ping(peer:)` with lightweight option | Core infrastructure, not utility |
| `MeshNetwork.statistics()` | `HealthClient` | Utility for local AND remote queries |
| `MeshNetwork.knownPeers()` | `DirectoryService` (core) | Core infrastructure - used by send internally |
| `MeshNetwork.send()` | `sendOnChannel()` with default channel | Channel ID 0 reserved for default |
| `MeshNetwork.setMessageHandler()` | `onChannel()` | Remove completely |
| `MeshMessage` enum (ping/pong/relay/etc) | Channel-based messages | Convert infrastructure to channels |

### Architecture Principle

| Layer | Purpose | Implementation |
|-------|---------|----------------|
| **Transport** | UDP sockets, encryption, routing | Low-level, not channel-based |
| **Infrastructure** | Keepalive, gossip, relay, hole punch | Channel-based (new) |
| **Utilities** | Echo, Health, Directory, NetworkInfo, Message | Channel-based |

### Network Isolation

Multiple networks can run simultaneously on the same machine, each as a separate `omertad` process. Isolation is enforced at multiple levels:

| Layer | Isolation Mechanism |
|-------|---------------------|
| **Process** | Separate `omertad` process per network |
| **Socket** | `/tmp/omertad-{networkId}.sock` per network |
| **Persistence** | `~/.omerta/mesh/networks/{networkId}/` per network |
| **Wire format** | Unencrypted network hash + authenticated encryption |

**Network ID derivation:**

The network ID used for sockets, storage, and wire format is derived from the encryption key:

```swift
// MeshConfig.swift:16-19
public var networkId: String {
    let hash = SHA256.hash(data: encryptionKey)
    return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
}
```

This produces a 16-character hex string (e.g., `"a1b2c3d4e5f67890"`).

---

### Wire Format v2 (NEW)

The current wire format encrypts everything, requiring full decryption before any filtering. The new format enables fast packet rejection and efficient header processing.

**Current format (v1) - inefficient:**
```
[12 bytes: nonce][encrypted JSON envelope][16 bytes: Poly1305 tag]
```
- Every packet requires full ChaCha20-Poly1305 decryption
- No way to reject wrong-network packets without crypto operation
- No way to read routing info without decrypting payload

**New format (v2) - layered encryption:**

```
UNENCRYPTED PREFIX (5 bytes) - instant garbage filtering:
┌─────────────────────────────────────────────────────────────┐
│ Offset │ Size │ Field         │ Purpose                     │
├────────┼──────┼───────────────┼─────────────────────────────┤
│ 0      │ 4    │ magic "OMRT"  │ Reject non-Omerta packets   │
│ 4      │ 1    │ version (0x02)│ Reject incompatible versions│
└─────────────────────────────────────────────────────────────┘

HEADER SECTION (ChaCha20 encrypted, authenticated):
┌─────────────────────────────────────────────────────────────┐
│ Offset │ Size │ Field         │ Purpose                     │
├────────┼──────┼───────────────┼─────────────────────────────┤
│ 5      │ 12   │ nonce         │ Unique per message          │
│ 17     │ 8    │ header_tag    │ Truncated Poly1305 for hdr  │
│ 25     │ 2    │ header_length │ Length of encrypted header  │
│ 27     │ N    │ header_data   │ Encrypted routing fields    │
└─────────────────────────────────────────────────────────────┘

Header fields (after decryption):
  - network_hash (8 bytes) - verified after decrypt, reject if mismatch
  - fromPeerId (length-prefixed)
  - toPeerId (length-prefixed, optional)
  - channel (length-prefixed)
  - hopCount (1 byte)
  - timestamp (8 bytes)
  - messageId (length-prefixed)

PAYLOAD SECTION (ChaCha20-Poly1305 encrypted):
┌─────────────────────────────────────────────────────────────┐
│ Offset │ Size │ Field         │ Purpose                     │
├────────┼──────┼───────────────┼─────────────────────────────┤
│ 27+N   │ 4    │ payload_length│ Length of encrypted payload │
│ 31+N   │ M    │ payload_data  │ Encrypted message content   │
│ 31+N+M │ 16   │ payload_tag   │ Full Poly1305 for payload   │
└─────────────────────────────────────────────────────────────┘
```

**Privacy benefit:** Network membership is not visible to observers. Packets cannot be correlated by network ID.

**Processing flow:**

```swift
func processPacket(_ data: Data) async {
    // 1. Check magic (4-byte compare) - O(1)
    guard data.prefix(4) == "OMRT".data(using: .utf8) else {
        return  // Not an Omerta packet
    }

    // 2. Check version (1-byte compare) - O(1)
    guard data[4] == 0x02 else {
        return  // Incompatible version
    }

    // 3. Extract header nonce, derive body nonce
    let headerNonce = Array(data[5..<17])  // 12 bytes at offset 5
    var bodyNonce = headerNonce
    bodyNonce[11] ^= 0x01  // Derive body nonce

    // 4. Verify header tag, decrypt header - O(header_size)
    guard let header = try? decryptAndVerifyHeader(data, nonce: headerNonce) else {
        return  // Invalid/tampered header (or wrong network)
    }

    // 5. Verify network hash (inside encrypted header)
    guard header.networkHash == self.networkHash else {
        return  // Wrong network (authenticated rejection)
    }

    // 6. Make routing decision based on header
    if header.toPeerId != nil && header.toPeerId != self.peerId {
        // Forward to another peer (don't decrypt payload)
        await forward(data, to: header.toPeerId)
        return
    }

    // 7. Decrypt payload only when needed - O(payload_size)
    guard let payload = try? decryptPayload(data, nonce: bodyNonce) else {
        return  // Invalid payload
    }

    // 8. Process message
    await handleMessage(header: header, payload: payload)
}
```

**Overhead comparison:**

| Component | v1 | v2 | Delta |
|-----------|----|----|-------|
| Magic | - | 4 bytes | +4 |
| Version | - | 1 byte | +1 |
| Nonce | 12 bytes | 12 bytes | 0 |
| Header tag | - | 8 bytes | +8 |
| Header length | - | 2 bytes | +2 |
| Network hash (in header) | - | 8 bytes | +8 |
| Payload length | - | 4 bytes | +4 |
| Payload tag | 16 bytes | 16 bytes | 0 |
| **Total fixed** | **28 bytes** | **47 bytes** | **+19 bytes** |

**Benefits:**

| Scenario | v1 Cost | v2 Cost |
|----------|---------|---------|
| Random UDP garbage | Full decrypt | 5-byte compare |
| Wrong network packet | Full decrypt | Header decrypt (~100 bytes) |
| Relay forwarding | Full decrypt + re-encrypt | Header decrypt only |
| Normal message | Full decrypt | Header + payload decrypt |

**Security properties:**

- **Network privacy**: Network hash is encrypted - observers cannot correlate packets by network
- **Network isolation**: Wrong network = header tag verification fails (authenticated rejection)
- **Header authentication**: 8-byte truncated Poly1305 (64-bit security)
- **Payload authentication**: Full 16-byte Poly1305 (128-bit security)
- **No frequency analysis**: ChaCha20 keystream is pseudorandom per (key, nonce)
- **Nonce uniqueness**: Random 96-bit nonce per message
- **Independent keystreams**: Header and payload use different keys AND different nonces (defense in depth)

**Nonce derivation:**

Header and body use independent keystreams via two mechanisms (defense in depth):

1. **Different keys** - Header key derived via HKDF, payload uses network key directly
2. **Different nonces** - Body nonce derived from header nonce

Either mechanism alone ensures independent keystreams; together they provide defense in depth.

```swift
// Only header_nonce is transmitted
let headerNonce: [UInt8] = ... // 12 random bytes

// Body nonce derived deterministically (XOR last byte with 0x01)
var bodyNonce = headerNonce
bodyNonce[11] ^= 0x01  // Last byte XOR'd

// Header: ChaCha20(headerKey, headerNonce)
// Body: ChaCha20-Poly1305(payloadKey, bodyNonce)
```

This means:
- Only one nonce transmitted (12 bytes, not 24)
- Header uses `headerNonce` with `headerKey`
- Body uses `bodyNonce` (derived) with `payloadKey`
- Two independent safeguards against keystream reuse

**Key derivation:**

```swift
// Derive header key from network key (different key for header vs payload)
let headerKey = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: networkKey,
    info: "omerta-header-v2".data(using: .utf8)!,
    outputByteCount: 32
)

// Payload uses network key directly (with derived nonce)
let payloadKey = networkKey
```

**Migration:**

- Old JSON envelope format is removed entirely
- All packets use new binary format with "OMRT" magic
- Network upgrade requires all nodes to update together
- No backward compatibility with v1 format

---

## Existing Code Reference

This section documents existing functionality that will be converted or exposed.

### Existing Endpoint Discovery (FreshnessManager)

**Location:** `Sources/OmertaMesh/Freshness/`

The endpoint discovery system already exists and works well:

| File | Purpose |
|------|---------|
| `FreshnessManager.swift` | Coordinates freshness queries, handles responses |
| `FreshnessQuery.swift:96-169` | `whoHasRecent` query workflow with rate limiting |
| `RecentContactTracker.swift` | Tracks last contact time per peer |
| `PathFailureReporter.swift` | Broadcasts `pathFailed` messages |

**Current MeshMessage protocol:**
```swift
case whoHasRecent(peerId: PeerId, maxAgeSeconds: Int)      // "Who has recent contact with X?"
case iHaveRecent(peerId: PeerId, lastSeenSecondsAgo: Int, reachability: ReachabilityPath)  // Response
case pathFailed(peerId: PeerId, path: ReachabilityPath, failedAt: Date)  // Broadcast failures
```

**Migration:** Convert to `mesh-dir-*` channels, expose via `mesh.queryPeers()` / `mesh.lookupPeer()`.

### Existing Statistics/Health

**Location:** `Sources/OmertaMesh/Public/MeshNetwork.swift:543-558`

```swift
public struct MeshStatistics {
    public let peerCount: Int
    public let connectionCount: Int
    public let directConnectionCount: Int
    public let relayCount: Int
    public let natType: NATType
    public let publicEndpoint: String?
    public let uptime: TimeInterval
}

public func statistics() async -> MeshStatistics
```

**Also:** `ConnectionKeepalive.swift:203-216` has per-machine health tracking (missed pings, healthy counts).

**Migration:** Keep local statistics, add `HealthClient` for remote queries via `health-*` channels.

### Existing Ping Implementation

**Location:** `Sources/OmertaMesh/MeshNode.swift:1497-1592`

Full ping implementation already exists:
- `sendPingWithDetails()` - Returns `PingResult` with RTT, gossip peers, NAT observations
- Exchanges peer lists (gossip)
- Updates endpoint manager with learned peers
- Records freshness contact
- Logs latency metrics

**Migration:** Add `lightweight: true` parameter for minimal payload on spotty connections.

### Existing Topology Tracking

**Location:** Multiple files

| File | Data |
|------|------|
| `PeerEndpointManager.swift` | Multi-endpoint tracking per (peerId, machineId) |
| `MeshNetwork.swift:442-459` | `knownPeers()`, `knownPeersWithInfo()` |
| `MeshNetwork.swift:462-467` | `connectedRelays()` |
| `Discovery/Gossip.swift` | Peer announcement gossip protocol |

**Migration:** Add `NetworkInfoClient` for querying remote peer's topology view.

### Existing Logging Infrastructure

**Location:** `Sources/OmertaMesh/Logging/`

| File | Lines | Purpose |
|------|-------|---------|
| `MeshEventLogger.swift` | 762 | JSON Lines event logging to disk |
| `MeshEventTypes.swift` | 118 | Event type enums (DiscoveryMethod, ConnectionEventType, etc.) |

**MeshEventLogger records:**
- `peer_discovery` - How peers are discovered
- `connections` - Connection lifecycle events
- `latency_stats` - Aggregated latency metrics (mean, p50, p95, p99)
- `nat_events` - NAT type and endpoint changes
- `hole_punch` - Hole punch attempts/results
- `relay` - Relay connection events
- `messages` - Message send/receive with size
- `errors` - Component-specific errors
- `hourly_stats` - Aggregate statistics

**Migration:** Keep as-is. Components call logger directly. No channel conversion needed.

### Existing Event Publisher

**Location:** `Sources/OmertaMesh/Public/MeshEvent.swift` (362 lines)

```swift
public enum MeshEvent {
    case started, stopped
    case natDetected, natTypeChanged
    case peerDiscovered, peerConnected, peerDisconnected, peerUnreachable
    case relayConnected, relayDisconnected
    case holePunchStarted, holePunchSucceeded, holePunchFailed
    case messageReceived, messageSendFailed
    case directConnectionEstablished, directConnectionLost
    case error, warning
    // ... 30+ cases
}

public actor MeshEventPublisher {
    func subscribe() -> MeshEventStream
    func publish(_ event: MeshEvent)
}
```

**Migration:** Keep as-is. This is the public event API - applications subscribe to events.

### Existing Persistence Stores

**Location:** `Sources/OmertaMesh/`

| File | Lines | Purpose | Storage Path |
|------|-------|---------|--------------|
| `Identity/IdentityStore.swift` | 123 | Per-network keypair management | `~/.omerta/mesh/identities.json` |
| `Network/NetworkStore.swift` | 225 | Network membership tracking | `~/.omerta/mesh/networks.json` |
| `Discovery/PeerStore.swift` | 385 | Peer announcements + reliability | `~/.omerta/mesh/networks/{id}/peers.json` |
| `PeerEndpointManager.swift` | 413 | Endpoint prioritization | `~/.omerta/mesh/networks/{id}/peer_endpoints.json` |

**Migration:** Keep as-is. These are internal persistence layers, not protocol.

### Existing Connection Keepalive

**Location:** `Sources/OmertaMesh/Connection/ConnectionKeepalive.swift` (454 lines)

Maintains NAT mappings via periodic pings:
- Tracks machines (peerId + machineId), not just peers
- Weighted sampling for large peer counts
- Configurable missed ping threshold (default: 3)
- Budget-based to avoid overwhelming network

```swift
public struct Config {
    var interval: TimeInterval = 15        // Ping interval
    var missedThreshold: Int = 3           // Failures before marking unhealthy
    var responseTimeout: TimeInterval = 5  // Ping timeout
    var maxMachinesPerCycle: Int = 30      // Budget per cycle
}
```

**Migration:** Keep as-is. Internal infrastructure that uses ping protocol.

### Existing Retry Utilities

**Location:** `Sources/OmertaMesh/Utilities/Retry.swift` (170 lines)

```swift
public struct RetryConfig {
    var maxAttempts: Int = 3
    var initialDelay: TimeInterval = 0.1
    var maxDelay: TimeInterval = 5.0
    var backoffMultiplier: Double = 2.0
    var jitter: Bool = true  // ±25% randomization

    static let network: RetryConfig    // 3 attempts, 0.5s-10s
    static let quick: RetryConfig      // 2 attempts, 0.1s-1s
    static let persistent: RetryConfig // 5 attempts, 1s-30s
}

func withRetry<T>(config:operation:shouldRetry:action:) throws -> T
```

**Migration:** Keep as-is. Utility used by network operations.

### What's Truly New

| Component | Status |
|-----------|--------|
| Message persistence | **NEW** - No existing code |
| Delivery receipts | **NEW** - No existing code |
| Remote health queries | **NEW** - Only local `statistics()` exists |
| Remote topology queries | **NEW** - Only local tracking exists |
| Lightweight ping | **NEW** - Add parameter to existing ping |
| Network key negotiation | **NEW** - Secure private network creation |

### Network Key Negotiation Utility (NEW)

**Purpose:** Allow two peers on an existing network to securely create a new private network.

**Use cases:**
- Create a private network between two parties
- Upgrade from a shared network to an exclusive one
- Establish a secure communication channel that persists across sessions

**Channels:**
- Request: `cloister-negotiate`
- Response: `cloister-response-{peerId}`

**Protocol (X25519 key agreement):**

```
┌─────────────┐                           ┌─────────────┐
│   Peer A    │                           │   Peer B    │
└──────┬──────┘                           └──────┬──────┘
       │                                         │
       │  1. Generate X25519 keypair             │
       │     (ephemeral, just for this exchange) │
       │                                         │
       │  2. CloisterRequest                   │
       │     - requestId                         │
       │     - networkName                       │
       │     - ephemeralPublicKey (A)            │
       │     - [optional] invitees list          │
       │─────────────────────────────────────────>
       │                                         │
       │                    3. Generate X25519 keypair
       │                       (ephemeral)
       │                                         │
       │                    4. Compute shared secret:
       │                       secret = X25519(privB, pubA)
       │                       cloister = HKDF(secret, "omerta-network-key")
       │                                         │
       │              5. CloisterResponse      │
       │                 - requestId             │
       │                 - ephemeralPublicKey (B)│
       │                 - encryptedConfirmation │
       │<─────────────────────────────────────────
       │                                         │
       │  6. Compute shared secret:              │
       │     secret = X25519(privA, pubB)        │
       │     cloister = HKDF(secret, ...)      │
       │                                         │
       │  7. Verify confirmation                 │
       │                                         │
       │  8. Both peers now have same cloister │
       │     Both join the new network locally   │
       └─────────────────────────────────────────┘
```

**Message types:**

```swift
public struct CloisterRequest: Codable, Sendable {
    public let requestId: UUID
    public let networkName: String
    public let ephemeralPublicKey: Data     // X25519 public key (32 bytes)
    public let proposedBootstraps: [String] // Optional initial bootstrap peers
}

public struct CloisterResponse: Codable, Sendable {
    public let requestId: UUID
    public let accepted: Bool
    public let ephemeralPublicKey: Data?    // X25519 public key (32 bytes), nil if rejected
    public let encryptedConfirmation: Data? // Proves B derived the same key
    public let rejectReason: String?
}

public struct CloisterResult {
    public let cloister: Cloister       // Ready to use
    public let networkId: String            // Derived from key
    public let sharedWith: PeerId           // The peer we negotiated with
}
```

**Client API:**

```swift
public actor CloisterClient {
    /// Negotiate a new network key with a peer
    /// Returns the new Cloister that both peers now share
    public func negotiate(
        with peer: PeerId,
        networkName: String,
        timeout: TimeInterval = 30
    ) async throws -> CloisterResult

    /// Handle incoming negotiation requests
    public func onNegotiationRequest(
        handler: @escaping (PeerId, CloisterRequest) async -> Bool
    ) async
}

// Usage
let client = try await utilities.cloisterClient()

// Initiator
let result = try await client.negotiate(with: peerB, networkName: "private-channel")
try await networkStore.addNetwork(result.cloister)
// Now can start omertad for the new network

// Responder (auto-accept example)
await client.onNegotiationRequest { from, request in
    print("Peer \(from) wants to create network '\(request.networkName)'")
    return true  // Accept
}
```

**Security properties:**
- **Forward secrecy**: Ephemeral X25519 keys are discarded after derivation
- **Mutual authentication**: Both peers are already authenticated on the parent network
- **Confirmation**: Encrypted confirmation proves both derived the same key
- **No key transmission**: The network key is never sent over the wire

---

### Secure Network Invite Sharing (Extension)

The same X25519 key exchange can be used to **share an existing network's invite** securely:

**Use cases:**
- Invite a peer to a network you're already part of
- Share network credentials without exposing them to observers
- Securely transfer invite links over untrusted networks

**Protocol:**

```
┌─────────────┐                           ┌─────────────┐
│   Peer A    │                           │   Peer B    │
│ (has invite)│                           │(wants invite)│
└──────┬──────┘                           └──────┬──────┘
       │                                         │
       │  1. X25519 key exchange (same as above) │
       │     Derive shared secret                │
       │                                         │
       │  2. NetworkInviteShare                  │
       │     - requestId                         │
       │     - encryptedInvite (ChaCha20-Poly1305)
       │     - networkNameHint (optional)        │
       │─────────────────────────────────────────>
       │                                         │
       │                    3. Decrypt invite with shared secret
       │                       Verify integrity (Poly1305)
       │                       Join the network
       │                                         │
       │              4. NetworkInviteAck        │
       │                 - success               │
       │                 - joined networkId      │
       │<─────────────────────────────────────────
       └─────────────────────────────────────────┘
```

**Message types:**

```swift
public struct NetworkInviteShare: Codable, Sendable {
    public let requestId: UUID
    public let ephemeralPublicKey: Data       // X25519 public key (32 bytes)
    public let encryptedInvite: Data          // ChaCha20-Poly1305 encrypted Cloister JSON
    public let networkNameHint: String?       // Optional unencrypted hint
}

public struct NetworkInviteAck: Codable, Sendable {
    public let requestId: UUID
    public let ephemeralPublicKey: Data       // For key derivation
    public let accepted: Bool
    public let joinedNetworkId: String?       // If accepted
    public let rejectReason: String?          // If rejected
}
```

**Client API:**

```swift
public actor CloisterClient {
    // ... existing negotiate() method ...

    /// Share an existing network invite with a peer
    /// The invite is encrypted with a derived shared secret
    public func shareInvite(
        _ cloister: Cloister,
        with peer: PeerId,
        timeout: TimeInterval = 30
    ) async throws -> NetworkInviteResult

    /// Derive a shared secret with a peer (for custom use)
    /// Returns 32-byte shared secret via X25519 + HKDF
    public func deriveSharedSecret(
        with peer: PeerId,
        context: String,           // HKDF info string for domain separation
        timeout: TimeInterval = 30
    ) async throws -> Data

    /// Handle incoming invite shares
    public func onInviteShare(
        handler: @escaping (PeerId, String?) async -> Bool  // (from, networkNameHint) -> accept?
    ) async
}

// Usage - sharing an invite
let client = try await utilities.cloisterClient()
let existingNetwork = try await networkStore.network(id: "abc123")!

let result = try await client.shareInvite(existingNetwork.key, with: peerB)
print("Peer joined: \(result.accepted)")

// Usage - receiving an invite
await client.onInviteShare { from, nameHint in
    print("Peer \(from) wants to share network '\(nameHint ?? "unknown")'")
    return true  // Accept and auto-join
}

// Usage - derive shared secret for custom purposes
let secret = try await client.deriveSharedSecret(
    with: peerB,
    context: "my-app-encryption-v1"
)
// Use secret for application-specific encryption
```

**Channels:**
- Share: `cloister-share`
- Ack: `cloister-share-ack-{peerId}`
- Secret derivation: `cloister-derive`
- Secret response: `cloister-derive-response-{peerId}`

**CLI integration:**

```bash
# Create new private network with peer
omerta network negotiate <peerId> --name "private-net"

# Share existing network with peer
omerta network share <networkId> --with <peerId>

# Accept incoming shares (interactive or auto-accept)
omerta network share --listen
omerta network share --auto-accept

# Derive shared secret (outputs hex, for scripting)
omerta network derive-secret <peerId> --context "my-app"
```

**Security notes:**
- Invite is encrypted end-to-end; observers see only ciphertext
- Forward secrecy: ephemeral keys prevent later compromise
- Integrity: Poly1305 tag detects tampering
- The shared secret derivation uses HKDF with context for domain separation

---

## Code Being Removed

### Public API Methods to Delete

| Method | Location | Replacement |
|--------|----------|-------------|
| `setMessageHandler()` | MeshNetwork.swift:340-365 | `onChannel()` handlers |
| `send(_ data:to:)` | MeshNetwork.swift:312-324 | `sendOnChannel()` with default channel |

**Note:** `statistics()`, `knownPeers()`, `knownPeersWithInfo()`, and `ping()` are **kept** but enhanced.

### Binaries to Delete

| Binary | Location | Reason |
|--------|----------|--------|
| `omerta-mesh` | Sources/OmertaMeshCLI/ | Redundant - merge into `omertad`/`omerta` pattern |

**Architecture consolidation:**

The correct pattern is:
- **`omertad`** - Daemon that runs the mesh network (always running)
- **`omerta`** - CLI that interacts with daemon via IPC (control socket)

`omerta-mesh` (393 lines) is a standalone mesh node that bypasses this pattern. Its functionality should be available through the standard `omertad` + `omerta` IPC pattern instead.

**Functionality to migrate from `omerta-mesh` to `omerta` CLI:**

| `omerta-mesh` Feature | `omerta` Command |
|-----------------------|------------------|
| `--bootstrap` | `omerta network join` / daemon config |
| `--relay` | `omerta daemon start --relay` |
| `--target` + test messages | `omerta mesh send <peer> <message>` |
| Event display | `omerta mesh events` / `omerta mesh status --watch` |
| Test mode | `omerta mesh test <peer>` |
| Statistics display | `omerta mesh status` |

**IPC messages to add to control socket:**

```swift
// New control messages for mesh operations
enum ControlMessage {
    // Existing...

    // Mesh operations (migrate from omerta-mesh)
    case meshStatus                              // Get mesh statistics
    case meshPeers                               // List known peers
    case meshPing(peerId: PeerId, lightweight: Bool)  // Ping a peer
    case meshSend(peerId: PeerId, data: Data)   // Send message
    case meshConnect(peerId: PeerId)            // Connect to peer
    case meshEvents(subscribe: Bool)            // Subscribe to events
    case meshTest(peerId: PeerId)               // Run connectivity test
}
```

**Files to delete after migration:**
- `Sources/OmertaMeshCLI/main.swift` (393 lines)
- Remove `OmertaMeshCLI` target from `Package.swift`

### MeshMessage Cases to Convert

The `MeshMessage` enum infrastructure messages will be converted to channel-based protocols:

| Message Type | New Channel | Existing Code |
|--------------|-------------|---------------|
| `ping` / `pong` | `mesh-ping` / `mesh-pong-{peerId}` | MeshNode.swift:1497-1592 |
| `whoHasRecent` / `iHaveRecent` | `mesh-dir-*` | FreshnessManager.swift |
| `pathFailed` | **REMOVE** | FreshnessManager.swift - security risk, see below |
| `relayRequest` / `relayResponse` | `mesh-relay-*` | RelayConnection.swift |

### pathFailed Broadcast Removal

The `pathFailed` broadcast message is being **removed** rather than converted to channels. Broadcasting path failures to the network has several security issues:

1. **Information leakage** - Reveals your failed connection attempts to all peers
2. **Attack vector** - Malicious peers can broadcast fake failures to isolate nodes or disrupt routing
3. **Privacy** - Exposes network topology information (who you're trying to reach)
4. **Spam potential** - Can flood the network with failure messages

**Alternative approach:** Keep path failure tracking **local only**. Each node tracks its own failed paths for routing decisions, but doesn't broadcast them. If a node can't reach a peer directly, it will naturally fall back to relay/hole-punch without needing network-wide failure information.
| `relayForward` / `relayForwardResult` | `mesh-relay-data` | RelayConnection.swift |
| `holePunchRequest` / `holePunchResponse` | `mesh-holepunch-*` | HolePunchManager.swift |
| `announce` / `peerInfo` | `mesh-gossip` | Gossip.swift |

**Note**: The `data` and `channelData` cases remain - they ARE the channel transport.

### Reserved Channel IDs

Channels are identified by name (string) but internally mapped to numeric IDs for efficiency:

| Channel ID | Name | Purpose |
|------------|------|---------|
| 0 | `""` (empty) | Default channel for backward compatibility |
| 1 | `mesh-gossip` | Peer discovery and gossip |
| 2-99 | `mesh-*` | Reserved for infrastructure (ping, relay, hole punch) |
| 100+ | User-defined | Application channels |

```swift
// Default channel (ID 0) for convenience
public func send(_ data: Data, to peerId: PeerId) async throws {
    try await sendOnChannel(data, to: peerId, channel: "")  // Uses channel ID 0
}

// Gossip channel (ID 1)
try await mesh.onChannel("mesh-gossip") { from, data in
    // Peer discovery messages
}
```

### Send Error Handling and Endpoint Discovery

When `sendOnChannel()` cannot reach a peer, it tries **aggressively** to find a working route:

1. **Try known endpoints** - IPv6 first, then IPv4
2. **Ask peers for endpoint** - Query connected peers "do you know how to reach X?" (directory lookup)
3. **Try discovered endpoints** - Any new endpoints learned from peers
4. **Hole punch** - If peer is behind NAT, coordinate hole punch
5. **Relay fallback** - Route through a relay peer as last resort

Only after all strategies fail does it throw `MeshError.peerUnreachable(peerId:)`.

```swift
do {
    try await mesh.sendOnChannel(data, to: peerId, channel: "my-channel")
} catch MeshError.peerUnreachable(let id) {
    // All strategies exhausted - peer truly unreachable
    print("Cannot reach \(id)")
}
```

### Directory Lookup is Core Infrastructure

The directory lookup ("ask peers for endpoints") is **core infrastructure**, not a utility. It's built into the send path because:

- **Send needs it** - To find endpoints for unknown/stale peers
- **Automatic** - Applications don't need to manually look up endpoints
- **Protocol level** - Uses `mesh-dir-query` channel internally

```swift
// This "just works" even if we don't know the peer's endpoint
try await mesh.sendOnChannel(data, to: unknownPeerId, channel: "my-channel")
// Internally: asks connected peers, learns endpoint, sends
```

### Relay and Hole Punch: Separate Services

Relay and hole punch remain **separate services** (not built into base send):

- **RelayHandler** - Listens on `mesh-relay-*` channels, forwards data between peers
- **HolePunchHandler** - Listens on `mesh-holepunch` channel, coordinates NAT traversal

This separation is intentional:
- **IPv6 migration friendly** - When IPv6 is ubiquitous, relay/hole punch can be disabled
- **Testable** - Each component can be tested independently
- **Optional** - Nodes can choose not to relay or coordinate hole punches

---

## Code Replacement Map

### Files Requiring Changes

#### 1. MeshProviderDaemon.swift

| Line | Current | Replacement |
|------|---------|-------------|
| 702 | `await mesh.statistics()` | `await healthClient.check(peer: .local)` |
| 733 | `await mesh.knownPeers()` | `await directoryClient.localPeers()` |
| 752 | `await mesh.ping(peerId, ...)` | `await pingClient.ping(peer: peerId, ...)` |

```swift
// BEFORE
public func getStatus() async -> MeshDaemonStatus {
    let stats = await mesh.statistics()
    // ...
}

// AFTER
public func getStatus() async -> MeshDaemonStatus {
    let health = await healthClient.check(peer: .local)
    // ...
}
```

#### 2. OmertaMeshCLI/main.swift

| Line | Current | Replacement |
|------|---------|-------------|
| 194 | `await mesh.setMessageHandler { ... }` | `try await mesh.onChannel("") { ... }` |
| 269 | `await mesh.knownPeers()` | `await directoryClient.localPeers()` |
| 296 | `try await mesh.send(data, to: peerId)` | `try await mesh.sendOnChannel(data, to: peerId, channel: "")` |
| 316 | `await mesh.statistics()` | `await healthClient.check(peer: .local)` |

#### 3. OmertaDaemon.swift

| Line | Current | Replacement |
|------|---------|-------------|
| 640-642 | `.ping` control message handling | Use `PingClient` |

#### 4. MeshNode.swift (Internal)

All internal `MeshMessage.ping()` construction and handling will be converted to use `PingHandler` channels.

#### 5. HolePunchCoordinator.swift / HolePunchManager.swift

| Current | Replacement |
|---------|-------------|
| `services.send(message, to: peerId, strategy: .auto)` | Channel-based hole punch messages |

#### 6. RelayConnection.swift / RelaySelector.swift

| Current | Replacement |
|---------|-------------|
| `node.send(.relayEnd(...), to: endpoint)` | Channel-based relay messages |
| `node.send(.relayData(...), to: endpoint)` | Channel-based relay messages |

#### 7. Gossip.swift / Bootstrap.swift

| Current | Replacement |
|---------|-------------|
| `node.send(.announce(...), to: endpoint)` | Channel-based gossip messages |
| `MeshMessage.ping(...)` construction | `PingClient` utility |

---

## Infrastructure Migration

### Ping/Pong to PingClient

**Before (MeshMessage-based):**
```swift
// MeshNode.swift
let ping = MeshMessage.ping(recentPeers: sentPeers, myNATType: myNATType)
try await socket.send(encryptedEnvelope(ping), to: endpoint)

// Handler
case .ping(let recentPeers, let theirNATType, let requestFullList):
    // Process ping, send pong
```

**After (Channel-based):**
```swift
// PingClient
public struct PingRequest: Codable, Sendable {
    public let id: UUID
    public let recentPeers: [GossipPeerInfo]
    public let myNATType: NATType
    public let requestFullList: Bool
    public let sentAt: Date
}

public struct PingResponse: Codable, Sendable {
    public let id: UUID
    public let recentPeers: [GossipPeerInfo]
    public let myNATType: NATType
    public let yourEndpoint: String
    public let receivedAt: Date
}

// Usage
let pingClient = try await utilities.pingClient()
let result = try await pingClient.ping(peer: targetPeerId, requestFullList: true)
print("RTT: \(result.rtt)ms, Learned \(result.newPeers.count) new peers")
```

### Relay to RelayHandler

**Before:**
```swift
node.send(.relayRequest(targetPeerId: target, sessionId: id), to: relay)
node.send(.relayForward(originalFrom: from, sessionId: id, originalPayload: data), to: target)
```

**After:**
```swift
// Uses mesh-relay-request channel
let relay = try await utilities.relayClient()
try await relay.requestSession(to: targetPeerId, via: relayPeerId)
try await relay.forward(data, to: targetPeerId, sessionId: sessionId)
```

### Hole Punch to HolePunchHandler

**Before:**
```swift
services.send(.holePunchRequest(targetPeerId: target, requesterEndpoint: ep), to: coordinator)
```

**After:**
```swift
// Uses mesh-holepunch channel
let holePunch = try await utilities.holePunchClient()
try await holePunch.coordinate(to: targetPeerId, via: coordinatorPeerId)
```

---

## Test Strategy

### Tests to Update

Tests that use `MeshMessage.ping()` or other legacy message types need updating:

| Test File | Changes Needed |
|-----------|----------------|
| `Phase0Tests.swift` | Replace `.ping()` with `PingClient` |
| `Phase1Tests.swift` | Replace `.ping()` with `PingClient` |
| `GossipEfficiencyTests.swift` | Update to channel-based gossip |
| `MultiEndpointTests.swift` | Replace `.ping()` with `PingClient` |
| `BinaryEnvelopeTests.swift` | Test channel-based envelopes |
| `MessageStructureTests.swift` | Update message format tests |
| `NATAwareRoutingTests.swift` | Replace `.ping()` with `PingClient` |
| `RelayForwardingTests.swift` | Use channel-based relay |
| `ObservedEndpointTests.swift` | Update ping format tests |
| `FirstHandTrackingTests.swift` | Update gossip format tests |

### New Tests to Add

| Test File | Coverage |
|-----------|----------|
| `EchoTests.swift` | Echo request/response, timeout handling |
| `HealthTests.swift` | Local AND remote health checks |
| `PingTests.swift` | Ping utility with gossip, NAT detection |
| `DirectoryTests.swift` | Local and remote peer lookup |
| `NetworkInfoTests.swift` | Topology query, neighbor info |
| `MessageTests.swift` | Send/receive, receipts, persistence |
| `RelayChannelTests.swift` | Channel-based relay |
| `HolePunchChannelTests.swift` | Channel-based hole punch |

### Mock Channel Provider

```swift
actor MockChannelProvider: ChannelProvider {
    var peerId: PeerId = "mock-peer-id"
    var handlers: [String: (PeerId, Data) async -> Void] = [:]
    var sentMessages: [(to: PeerId, channel: String, data: Data)] = []

    func onChannel(_ channel: String, handler: @escaping @Sendable (PeerId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        sentMessages.append((to: peerId, channel: channel, data: data))
    }

    func simulateIncoming(from: PeerId, channel: String, data: Data) async {
        if let handler = handlers[channel] {
            await handler(from, data)
        }
    }
}
```

---

## Implementation Phases

### Phase 1: Core Infrastructure + Utilities

**Core Infrastructure (enhance existing code):**

| Component | Existing Code | Changes Needed |
|-----------|---------------|----------------|
| `DirectoryService` | FreshnessManager.swift, FreshnessQuery.swift | Convert `whoHasRecent`/`iHaveRecent` to `mesh-dir-*` channels |
| `PingService` | MeshNode.swift:1497-1592 | Add `lightweight: true` parameter |
| `send()` routing | MeshNode.swift:1928-1969 (`sendWithAutoRouting`) | Already tries IPv6 → direct → relay |

**Application Utilities (new remote query capability):**

| Utility | Existing Code | New Capability |
|---------|---------------|----------------|
| `HealthClient/Handler` | MeshNetwork.swift:543-558 (`statistics()`) | Add remote queries via `health-*` channels |
| `NetworkInfoClient/Handler` | PeerEndpointManager, Gossip.swift (internal) | Expose + add remote queries via `netinfo-*` channels |
| `MessageClient/Handler` | None | **Fully new** - persistence, receipts, inbox |
| `CloisterClient/Handler` | None | **Fully new** - X25519 key negotiation for private networks |

**PingService modes:**

| Mode | Use Case | Existing? |
|------|----------|-----------|
| `ping(peer:)` | Normal ping - full gossip exchange, NAT info, peer discovery | YES (MeshNode.swift:1508-1592) |
| `ping(peer:, lightweight: true)` | Spotty connection - minimal payload, just connectivity + RTT | NEW |

```swift
// Normal ping - EXISTING, exchanges peer info, detects NAT
let result = try await mesh.ping(peer: targetPeerId)
print("RTT: \(result.rtt)ms, learned \(result.newPeers.count) peers")

// Lightweight ping - NEW, for spotty connections
let result = try await mesh.ping(peer: targetPeerId, lightweight: true)
print("RTT: \(result.rtt)ms")  // No gossip overhead
```

**DirectoryService (convert existing FreshnessManager):**

```swift
// EXISTING - FreshnessQuery.swift already does this internally:
// - Broadcasts whoHasRecent to connected peers
// - Waits for iHaveRecent responses
// - Picks freshest response
// - Rate-limits queries (30s per peer)

// NEW - Expose as public API + convert to channels:
let peers = await mesh.knownPeers()           // EXISTING
let peersWithInfo = await mesh.knownPeersWithInfo()  // EXISTING
let remotePeers = try await mesh.queryPeers(from: bootstrapPeer)  // NEW public API
```

### Phase 2: Infrastructure Migration

Convert internal infrastructure to channel-based:
1. Convert `MeshMessage.ping/pong` to `PingHandler` channels
2. Convert relay messages to `RelayHandler` channels
3. Convert hole punch messages to `HolePunchHandler` channels
4. Convert gossip messages to `GossipHandler` channels

### Phase 3: Cleanup

1. Remove `MeshMessage` enum cases (keep only `channelData`)
2. Remove deprecated public methods
3. Update all tests
4. Update documentation

---

## Functionality Gaps

### Addressed by This Migration

| Gap | Solution | Existing Code? |
|-----|----------|----------------|
| Remote health monitoring | `HealthClient.check(peer: remotePeerId)` | NEW |
| Local health | `statistics()` (keep) or `HealthClient.check(peer: .local)` | EXISTS |
| Lightweight ping for spotty connections | `mesh.ping(peer:, lightweight: true)` | ADD PARAM |
| Send can't find endpoint | FreshnessManager already does this | EXISTS (expose better) |
| Local peer lookup | `mesh.knownPeers()` / `mesh.knownPeersWithInfo()` | EXISTS |
| Remote peer lookup | `mesh.queryPeers(from: remotePeer)` | EXPOSE (FreshnessQuery does it internally) |
| Message persistence | `MessageClient` with local storage | NEW |
| Delivery receipts | `MessageClient` with receipts | NEW |
| Private network creation | `CloisterClient` with X25519 key exchange | NEW |

### Future Work

| Feature | Description | Priority |
|---------|-------------|----------|
| Streaming | Large data transfer over channels | Medium |
| Channel encryption | Per-channel encryption keys | Low |
| Message compression | Compress large payloads | Low |
| Rate limiting | Per-channel message rate limits | Low |

**Removed from scope** (can be built as separate apps):
- ~~Broadcast channels~~ - Doesn't fit distributed architecture
- ~~Presence system~~ - Doesn't fit distributed architecture
- ~~Channel groups~~ - Low priority

---

## Summary

| Action | What | Existing Code | Work Needed |
|--------|------|---------------|-------------|
| **DELETE** | `setMessageHandler()` | MeshNetwork.swift:340-365 | Remove |
| **DELETE** | `send(_ data:to:)` | MeshNetwork.swift:312-324 | Remove (use `sendOnChannel`) |
| **CONVERT** | `MeshMessage.ping/pong` | MeshNode.swift:1497-1592 | Convert to `mesh-ping` channel |
| **CONVERT** | `MeshMessage.whoHasRecent/iHaveRecent` | FreshnessManager.swift | Convert to `mesh-dir-*` channels |
| **REMOVE** | `MeshMessage.pathFailed` | FreshnessManager.swift | Security risk - see below |
| **CONVERT** | `MeshMessage.relay*` | RelayConnection.swift | Convert to `mesh-relay-*` channels |
| **CONVERT** | `MeshMessage.holePunch*` | HolePunchManager.swift | Convert to `mesh-holepunch-*` channels |
| **CONVERT** | `MeshMessage.announce` | Gossip.swift | Convert to `mesh-gossip` channel |
| **ENHANCE** | `ping()` | MeshNode.swift:1508-1592 | Add `lightweight: true` parameter |
| **KEEP** | `statistics()` | MeshNetwork.swift:543-558 | Keep for local, add HealthClient for remote |
| **KEEP** | `knownPeers()` / `knownPeersWithInfo()` | MeshNetwork.swift:442-459 | Keep, add `queryPeers(from:)` |
| **ADD** | `HealthClient/Handler` | None (only local stats) | New remote query capability |
| **ADD** | `NetworkInfoClient/Handler` | Internal tracking only | Expose + remote queries |
| **ADD** | `MessageClient/Handler` | None | **Fully new** - persistence, receipts |
| **ADD** | `CloisterClient/Handler` | None | **Fully new** - X25519 key negotiation |

**Summary by effort:**
- **No changes (keep as-is):** Logging (MeshEventLogger, MeshEventPublisher), Persistence (IdentityStore, NetworkStore, PeerStore, PeerEndpointManager), Retry utilities, ConnectionKeepalive
- **Small changes:** Add lightweight ping parameter, expose `queryPeers()` API
- **Medium changes:** Convert MeshMessage cases to channel-based, add Health/NetworkInfo remote queries
- **Large changes:** MessageClient with persistence, CloisterClient with X25519 negotiation (truly new functionality)

**Component inventory:**

| Component | Lines | Migration Action |
|-----------|-------|------------------|
| MeshEventLogger | 762 | KEEP - logging infrastructure |
| MeshEventPublisher | 362 | KEEP - public event API |
| IdentityStore | 123 | KEEP - identity persistence |
| NetworkStore | 225 | KEEP - network membership |
| PeerStore | 385 | KEEP - peer persistence |
| PeerEndpointManager | 413 | KEEP - endpoint tracking |
| ConnectionKeepalive | 454 | KEEP - NAT keepalive |
| Retry | 170 | KEEP - backoff utility |
| FreshnessManager | 325 | CONVERT - to channels |
| Gossip | 272 | CONVERT - to channels |
| HolePunchManager | 489 | CONVERT - to channels |
| RelayManager | 373 | CONVERT - to channels |
| MeshNode | ~2000 | CONVERT - message handling |

**Core vs Utility:**
- **Core** = Built into MeshNetwork, used by send internally (Ping, Directory)
- **Utility** = Separate client/handler for remote queries (Health, NetworkInfo, Message)
