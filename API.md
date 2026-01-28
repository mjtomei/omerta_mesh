# OmertaMesh API Documentation

OmertaMesh is a peer-to-peer mesh networking library that handles NAT traversal, peer discovery, and encrypted communication. This document covers the public API for building applications on top of the mesh network.

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Getting Started](#getting-started)
3. [ChannelProvider Protocol](#channelprovider-protocol)
4. [Building Channel-Based Services](#building-channel-based-services)
5. [Utility Services](#utility-services)
6. [Best Practices](#best-practices)
7. [Error Handling](#error-handling)
8. [Examples](#examples)
9. [Tunnel Sessions (OmertaTunnel)](#tunnel-sessions-omertatunnel)

---

## Core Concepts

### PeerId and Identity

Every node in the mesh network has a cryptographic identity consisting of an Ed25519 keypair. The **PeerId** is derived from the public key and uniquely identifies a peer.

```swift
// Generate a new identity
let identity = IdentityKeypair()

// Get the peer ID (base64-encoded public key hash)
let peerId = identity.peerId  // e.g., "abc123def456..."

// Identities are persistent - save the keypair for reconnection
```

### Channels and Messaging

Channels are named message streams that allow multiple services to share the same mesh connection. Each channel is a string identifier (max 64 characters, alphanumeric plus `-` and `_`).

```swift
// Send data on a specific channel
try await mesh.sendOnChannel(data, to: peerId, channel: "my-channel")

// Register a handler for incoming messages on a channel
try await mesh.onChannel("my-channel") { fromPeerId, data in
    // Handle incoming message
}
```

**Channel naming convention:**
- Request channels: `service-request` (e.g., `echo-request`)
- Response channels: `service-response-{peerId}` (e.g., `echo-response-abc123...`)

This pattern prevents crosstalk when multiple peers make requests simultaneously.

**Reserved channel IDs:**

| Channel ID | Name | Purpose |
|------------|------|---------|
| 0 | `""` (empty) | Default channel for backward compatibility |
| 1 | `mesh-gossip` | Peer discovery and gossip |
| 2-99 | `mesh-*` | Reserved for infrastructure (ping, relay, hole punch) |
| 100+ | User-defined | Application channels |

**Sending tries hard to find endpoints:**

When you call `sendOnChannel()`, it automatically:
1. Tries known endpoints (IPv6 first, then IPv4)
2. Asks connected peers for the target's endpoint (directory lookup)
3. Tries any newly discovered endpoints
4. Coordinates hole punch if needed
5. Falls back to relay as last resort

```swift
// This "just works" even if we don't know the peer's endpoint
try await mesh.sendOnChannel(data, to: unknownPeerId, channel: "my-channel")
// Internally: asks peers, learns endpoint, sends

// Only throws if ALL strategies fail
do {
    try await mesh.sendOnChannel(data, to: peerId, channel: "my-channel")
} catch MeshError.peerUnreachable(let id) {
    // Truly unreachable after trying everything
}
```

### NAT Traversal (Automatic)

OmertaMesh automatically handles NAT traversal using multiple strategies:
1. **IPv6 direct** - If both peers have IPv6, use direct connection
2. **Hole punching** - Coordinate UDP hole punches through a relay
3. **Relay fallback** - Route through a relay peer when direct connection fails

Applications don't need to handle NAT traversal - it happens transparently.

### Network Encryption

All messages are encrypted with a shared network key (symmetric encryption) and signed with the sender's identity (asymmetric signing). This provides:
- **Confidentiality** - Only network members can read messages
- **Authenticity** - Messages are verified to come from the claimed sender
- **Integrity** - Messages cannot be modified in transit

---

## Getting Started

### Creating a Mesh Network

```swift
import OmertaMesh

// Create configuration with encryption key
let config = MeshConfig(
    encryptionKey: cloister,         // 32-byte symmetric key
    port: 0,                           // 0 = auto-assign port
    bootstrapPeers: [                  // Peers to connect to initially
        "peer1Id@192.168.1.10:8080",
        "peer2Id@192.168.1.11:8080"
    ]
)

// Create and start the mesh
let mesh = MeshNetwork(config: config)
try await mesh.start()

// Get our peer ID
let myPeerId = await mesh.peerId

// Create utilities for common operations
let utilities = MeshUtilities(provider: mesh)

// Stop when done
await mesh.stop()
```

### Joining a Network via Invite Link

```swift
// Join using an invite link
let network = try await mesh.joinNetwork(
    inviteLink: "omerta://join/...",
    name: "My Network"
)

// Or create a new network
let cloister = try await mesh.createNetwork(
    name: "My New Network",
    bootstrapEndpoint: "my.server.com:8080"
)

// Share the invite link
let inviteLink = cloister.encode()  // "omerta://join/..."
```

---

## ChannelProvider Protocol

The `ChannelProvider` protocol is the standardized interface for channel-based messaging. Both `MeshNetwork` and wrapper types conform to this protocol.

```swift
public protocol ChannelProvider: ChannelSender {
    /// The peer ID of this node
    var peerId: PeerId { get async }

    /// Register a handler for messages on a specific channel
    func onChannel(
        _ channel: String,
        handler: @escaping @Sendable (PeerId, Data) async -> Void
    ) async throws

    /// Unregister a handler for a channel
    func offChannel(_ channel: String) async
}

public protocol ChannelSender: Sendable {
    /// Send data to a peer on a specific channel
    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws
}
```

### When to Use ChannelProvider

| Use Case | Type | Reason |
|----------|------|--------|
| Building utility services | `ChannelProvider` | Decoupled from specific implementation |
| Application code | `MeshNetwork` via utilities | Use utility clients for common operations |
| Testing | `MockChannelProvider` | Easy to mock for unit tests |

---

## Building Channel-Based Services

This section shows how to build services using the channel API. This is the recommended pattern for application-level services.

### Request/Response Pattern

The standard pattern uses:
1. A **static request channel** that all peers listen on
2. A **personalized response channel** per requester to prevent crosstalk

```swift
public enum MyServiceChannels {
    public static let request = "myservice-request"

    public static func response(for peerId: PeerId) -> String {
        "myservice-response-\(peerId)"
    }
}
```

### Client Pattern

Clients send requests and await responses. Key elements:
- Track pending requests with `CheckedContinuation`
- Use UUID to correlate requests with responses
- Implement timeout handling

```swift
public actor MyServiceClient {
    private let channelProvider: any ChannelProvider
    private let myPeerId: PeerId
    private var pending: [UUID: CheckedContinuation<MyResponse, Error>] = [:]

    public init(channelProvider: any ChannelProvider) async throws {
        self.channelProvider = channelProvider
        self.myPeerId = await channelProvider.peerId

        // Register response handler
        try await channelProvider.onChannel(
            MyServiceChannels.response(for: myPeerId)
        ) { [weak self] from, data in
            await self?.handleResponse(from: from, data: data)
        }
    }

    public func request(_ payload: Data, to peer: PeerId, timeout: TimeInterval = 10) async throws -> MyResponse {
        let requestId = UUID()
        let request = MyRequest(id: requestId, payload: payload)
        let requestData = try JSONEncoder().encode(request)

        return try await withCheckedThrowingContinuation { continuation in
            // Store continuation for response
            self.pending[requestId] = continuation

            // Set timeout
            Task {
                try? await Task.sleep(for: .seconds(timeout))
                if let cont = self.pending.removeValue(forKey: requestId) {
                    cont.resume(throwing: UtilityError.timeout)
                }
            }

            // Send request
            Task {
                do {
                    try await self.channelProvider.sendOnChannel(
                        requestData,
                        to: peer,
                        channel: MyServiceChannels.request
                    )
                } catch {
                    if let cont = self.pending.removeValue(forKey: requestId) {
                        cont.resume(throwing: error)
                    }
                }
            }
        }
    }

    private func handleResponse(from: PeerId, data: Data) async {
        guard let response = try? JSONDecoder().decode(MyResponse.self, from: data) else {
            return
        }
        if let continuation = pending.removeValue(forKey: response.id) {
            continuation.resume(returning: response)
        }
    }
}
```

### Handler Pattern

Handlers receive requests and send responses. Key elements:
- Listen on the static request channel
- Send responses to the requester's personalized response channel
- Validate the request before processing

```swift
public actor MyServiceHandler {
    private let channelProvider: any ChannelProvider
    private var isRunning = false

    public init(channelProvider: any ChannelProvider) {
        self.channelProvider = channelProvider
    }

    public func start() async throws {
        guard !isRunning else { return }
        try await channelProvider.onChannel(MyServiceChannels.request) { [weak self] from, data in
            await self?.handleRequest(from: from, data: data)
        }
        isRunning = true
    }

    public func stop() async {
        guard isRunning else { return }
        await channelProvider.offChannel(MyServiceChannels.request)
        isRunning = false
    }

    private func handleRequest(from: PeerId, data: Data) async {
        guard let request = try? JSONDecoder().decode(MyRequest.self, from: data) else {
            return
        }

        // Process request
        let response = MyResponse(
            id: request.id,
            result: processRequest(request)
        )

        // Send response on requester's response channel
        guard let responseData = try? JSONEncoder().encode(response) else { return }
        try? await channelProvider.sendOnChannel(
            responseData,
            to: from,
            channel: MyServiceChannels.response(for: from)
        )
    }
}
```

---

## Utility Services

OmertaMesh provides built-in services split between **core infrastructure** (built into MeshNetwork) and **application utilities** (separate clients).

### Core Infrastructure (on MeshNetwork)

These are built into MeshNetwork because other core functionality depends on them:

| Method | Purpose |
|--------|---------|
| `ping(peer:)` | Full ping with gossip, NAT detection, peer discovery |
| `ping(peer:, lightweight: true)` | Minimal ping for spotty connections - just RTT |
| `knownPeers()` | Local peer cache |
| `knownPeersWithInfo()` | Local peers with endpoints, NAT type |
| `queryPeers(from:)` | Query remote peer's directory |

### Application Utilities

**Choosing the right utility:**

| Use Case | Solution | Why |
|----------|----------|-----|
| "Is peer X alive?" | `mesh.ping(peer:, lightweight: true)` | Minimal overhead, core infrastructure |
| "Latency + learn about network?" | `mesh.ping(peer:)` | Full gossip exchange, NAT info |
| "What's peer X's status and metrics?" | **HealthClient** | Detailed health info, monitoring |
| "What does peer X see?" | **NetworkInfoClient** | Topology from peer's perspective |
| "Send a message to peer X" | **MessageClient** | Text messaging with receipts |
| "Create private network with peer X" | **CloisterClient**.negotiate() | X25519 key negotiation |
| "Invite peer X to existing network" | **CloisterClient**.shareInvite() | Encrypted invite transfer |
| "Derive shared secret with peer X" | **CloisterClient**.deriveSharedSecret() | For app-specific encryption |

### 1. Ping (Core Infrastructure)

Ping is built into MeshNetwork with two modes:

```swift
// Full ping - exchanges peer info, detects NAT, discovers peers
let result = try await mesh.ping(peer: targetPeerId)
print("RTT: \(result.rtt)ms")
print("Their NAT type: \(result.theirNATType)")
print("My observed endpoint: \(result.myObservedEndpoint)")
print("Learned \(result.newPeers.count) new peers")

// Lightweight ping - for spotty connections, minimal payload
let result = try await mesh.ping(peer: targetPeerId, lightweight: true)
print("RTT: \(result.rtt)ms")  // No gossip overhead

// Unlimited pings (for diagnostics)
for await result in mesh.pingStream(peer: targetPeerId, count: .unlimited) {
    print("RTT: \(result.rtt)ms")
}
```

**Channels:**
- Request: `mesh-ping`
- Response: `mesh-pong-{peerId}`

### 2. Directory (Core Infrastructure)

Directory lookup is built into MeshNetwork and used internally by send:

```swift
// Local peer cache
let peers = await mesh.knownPeers()
let peersWithInfo = await mesh.knownPeersWithInfo()

for peer in peersWithInfo {
    print("\(peer.peerId): \(peer.endpoints.joined(separator: ", "))")
    print("  NAT: \(peer.natType), Last seen: \(peer.lastSeen)")
}

// Query remote peer's directory
let remotePeers = try await mesh.queryPeers(from: bootstrapPeer)
for peer in remotePeers {
    print("\(peer.peerId): \(peer.natType)")
}

// Lookup specific peer from remote
let peerInfo = try await mesh.lookupPeer(targetId, from: knownPeer)
```

**Channels:**
- Request: `mesh-dir-query`
- Response: `mesh-dir-response-{peerId}`

### 4. Health Check Utility

Query health status and metrics - works for **local** AND **remote** peers.

```swift
let health = try await utilities.healthClient()

// Query LOCAL health (replaces statistics())
let localHealth = try await health.check(peer: .local)
print("Local status: \(localHealth.status)")
print("Local uptime: \(localHealth.uptime) seconds")

// Query REMOTE peer health
let remoteHealth = try await health.check(peer: .remote(targetPeerId))
print("Remote status: \(remoteHealth.status)")
print("Remote peer count: \(remoteHealth.peerCount)")
print("Remote NAT type: \(remoteHealth.natType)")

// With optional metrics
let detailed = try await health.check(peer: .remote(targetPeerId), includeMetrics: true)
if let metrics = detailed.metrics {
    print("Messages sent: \(metrics.messagesSent)")
    print("Avg latency: \(metrics.avgLatencyMs ?? 0)ms")
}
```

**Channels:**
- Request: `health-request`
- Response: `health-response-{peerId}`

### 5. Network Info Utility

Query a peer's view of the network topology.

```swift
let netinfo = try await utilities.networkInfoClient()
let info = try await netinfo.query(peer: targetPeerId, includeNeighbors: true)

print("Peer \(info.peerId) sees:")
print("  Known peers: \(info.knownPeers)")
print("  Direct connections: \(info.directConnections)")
print("  Relay connections: \(info.relayConnections)")

if let neighbors = info.neighbors {
    print("  Neighbors:")
    for neighbor in neighbors {
        print("    \(neighbor.peerId): \(neighbor.connectionType)")
    }
}
```

**Channels:**
- Request: `netinfo-query`
- Response: `netinfo-response-{peerId}`

### 6. Message Utility

Simple peer-to-peer messaging with **persistence** for offline delivery.

```swift
// Send a message
let messages = try await utilities.messageClient()
try await messages.send("Hello!", to: targetPeerId)

// Send with delivery receipt
let receipt = try await messages.send("Important message", to: targetPeerId, requestReceipt: true)
print("Delivered at: \(receipt.receivedAt)")

// Receive messages
let inbox = try await utilities.messageHandler { message in
    print("From \(message.from): \(message.text)")

    // Optionally reply
    try await messages.send("Got it!", to: message.from, replyTo: message.id)
}

// Check for persisted messages (offline delivery)
let pending = try await messages.pendingMessages()
for msg in pending {
    print("Queued message to \(msg.to): \(msg.text)")
}
```

**Features:**
- Text messages with timestamps
- Optional delivery receipts
- Reply threading via `replyTo`
- Message persistence for offline delivery

**Channels:**
- Inbox: `msg-inbox-{peerId}` (each peer listens on their own inbox)
- Receipts: `msg-receipt-{peerId}` (optional delivery acknowledgment)

### 7. Network Key Negotiation

Securely create a new private network with another peer using X25519 key exchange.

```swift
let cloister = try await utilities.cloisterClient()

// Initiate negotiation with a peer
let result = try await cloister.negotiate(
    with: trustedPeerId,
    networkName: "private-channel"
)

// Result contains the new network key
print("Created network: \(result.networkId)")
print("Shared with: \(result.sharedWith)")

// Save the new network
try await networkStore.addNetwork(result.cloister)

// Can now start a daemon for the new private network
// omertad start --network <result.networkId>
```

**Handling incoming requests:**

```swift
// Manual approval
await cloister.onNegotiationRequest { from, request in
    print("Peer \(from) wants to create '\(request.networkName)'")

    // Show UI, ask user, etc.
    let approved = await askUserForApproval(from: from, name: request.networkName)
    return approved
}

// Auto-accept from trusted peers
let trustedPeers: Set<PeerId> = [...]
await cloister.onNegotiationRequest { from, request in
    return trustedPeers.contains(from)
}
```

**Sharing existing network invites:**

```swift
// Share an existing network's invite securely
let existingNetwork = try await networkStore.network(id: "abc123")!
let result = try await cloister.shareInvite(existingNetwork.key, with: trustedPeerId)

if result.accepted {
    print("Peer joined network \(result.joinedNetworkId!)")
}

// Handle incoming invite shares
await cloister.onInviteShare { from, networkNameHint in
    print("Peer \(from) wants to share '\(networkNameHint ?? "a network")'")
    return true  // Accept and auto-join
}
```

**Derive shared secret for custom use:**

```swift
// Derive a 32-byte shared secret with a peer
// Useful for application-specific encryption
let secret = try await cloister.deriveSharedSecret(
    with: peerB,
    context: "my-app-encryption-v1"  // Domain separation
)

// Use for your own encryption needs
let encrypted = try MyApp.encrypt(data, key: secret)
```

**Security properties:**
- Forward secrecy: ephemeral X25519 keys discarded after use
- Mutual authentication: both peers already authenticated on parent network
- Key never transmitted: derived independently via Diffie-Hellman
- Invite encryption: shared invites are ChaCha20-Poly1305 encrypted
- Domain separation: HKDF context string prevents cross-protocol attacks

**Channels:**
- Negotiate: `cloister-negotiate` / `cloister-response-{peerId}`
- Share invite: `cloister-share` / `cloister-share-ack-{peerId}`
- Derive secret: `cloister-derive` / `cloister-derive-response-{peerId}`

### MeshUtilities Convenience Wrapper

The `MeshUtilities` class provides convenient access to application utilities:

```swift
let utilities = MeshUtilities(provider: mesh)

// Start all utility handlers (makes this node respond to utility requests)
try await utilities.startAllHandlers()

// Or start individual handlers
try await utilities.startHealthHandler()
try await utilities.startNetworkInfoHandler()
try await utilities.startMessageHandler()
try await utilities.startCloisterHandler()

// Get utility clients
let health = try await utilities.healthClient()
let netinfo = try await utilities.networkInfoClient()
let messages = try await utilities.messageClient()
let cloister = try await utilities.cloisterClient()

// Stop all handlers
await utilities.stopAllHandlers()
```

**Note:** Ping and Directory are core infrastructure on `MeshNetwork`, not utilities:
```swift
// These are on mesh directly, not utilities
let result = try await mesh.ping(peer: targetPeerId)
let peers = await mesh.knownPeers()
let remotePeers = try await mesh.queryPeers(from: bootstrapPeer)
```

---

## Best Practices

### Channel Naming Conventions

| Pattern | Example | Use Case |
|---------|---------|----------|
| `service-request` | `echo-request` | Static request channel |
| `service-response-{peerId}` | `echo-response-abc123` | Personalized response channel |
| `mesh-*` | `mesh-ping` | Reserved for infrastructure |
| `{namespace}-{channel}` | `myapp-data` | Application-namespaced channels |

**Rules:**
- Max 64 characters
- Alphanumeric plus `-` and `_` only
- No spaces, dots, slashes, or special characters
- Empty string is reserved for default channel
- `mesh-*` prefix is reserved for infrastructure

### Message Versioning

Include version info for backwards compatibility:

```swift
public struct MyRequest: Codable, Sendable {
    public static let version = 1

    public let version: Int
    public let id: UUID
    public let payload: Data

    public init(id: UUID = UUID(), payload: Data) {
        self.version = Self.version
        self.id = id
        self.payload = payload
    }
}
```

### Timeout Handling

Always implement timeouts for requests:

```swift
public func request(timeout: TimeInterval = 10) async throws -> Response {
    return try await withCheckedThrowingContinuation { continuation in
        pending[requestId] = continuation

        Task {
            try? await Task.sleep(for: .seconds(timeout))
            if let cont = self.pending.removeValue(forKey: requestId) {
                cont.resume(throwing: UtilityError.timeout)
            }
        }

        // Send request...
    }
}
```

### Graceful Degradation

Handle unavailable services gracefully:

```swift
do {
    let health = try await healthClient.check(peer: .remote(targetPeerId), timeout: 5)
    updateDashboard(health)
} catch UtilityError.timeout {
    // Peer might be offline or not running health handler
    markPeerUnresponsive(targetPeerId)
} catch {
    log.warning("Health check failed: \(error)")
}
```

### Resource Cleanup

Always clean up channel handlers:

```swift
public actor MyClient {
    private let channelProvider: any ChannelProvider
    private let responseChannel: String

    public init(channelProvider: any ChannelProvider) async throws {
        self.channelProvider = channelProvider
        let peerId = await channelProvider.peerId
        self.responseChannel = MyChannels.response(for: peerId)
        try await channelProvider.onChannel(responseChannel) { ... }
    }

    public func close() async {
        await channelProvider.offChannel(responseChannel)
    }
}
```

---

## Error Handling

### Send Operations

All `send` operations now properly propagate errors. Operations that were previously fire-and-forget now explicitly handle errors:

```swift
// Sending throws on failure
do {
    try await mesh.send(message, to: endpoint)
} catch let error as UDPSocketError {
    // Network-level failure
    switch error {
    case .sendFailed(let destination, let byteCount, let underlying):
        print("Failed to send \(byteCount) bytes to \(destination): \(underlying)")
        // underlying contains the system error (e.g., "host unreachable")
    case .notRunning:
        print("Socket not running")
    default:
        print("Send error: \(error)")
    }
}

// For fire-and-forget scenarios, use try? explicitly
try? await mesh.send(response, to: endpoint)  // Errors logged but ignored
```

### UDPSocketError

Low-level socket errors with full context:

```swift
public enum UDPSocketError: Error {
    case alreadyRunning
    case notRunning
    case invalidEndpoint(String)
    case sendFailed(destination: String, byteCount: Int, underlying: Error)
    case addressMismatch(String)
}
```

The `sendFailed` case includes:
- `destination`: The target address that failed
- `byteCount`: Number of bytes attempted to send
- `underlying`: The system-level error (e.g., EHOSTUNREACH, ENETUNREACH)

### MeshError

Core mesh errors for network operations:

```swift
public enum MeshError: Error {
    case peerNotFound(peerId: PeerId)
    case connectionFailed(peerId: PeerId, reason: String)
    case timeout(operation: String)
    case peerUnreachable(peerId: PeerId)
    case notStarted
    case alreadyStarted
    case noRelaysAvailable
    case sendFailed(reason: String)
    case invalidMessage(reason: String)
}
```

### UtilityError

Errors specific to utility services:

```swift
public enum UtilityError: Error {
    case timeout
    case invalidResponse
    case serviceUnavailable
    case notStarted
    case alreadyStarted
    case persistenceFailed(reason: String)
}
```

### Error Recovery

```swift
func requestWithRetry<T>(
    maxAttempts: Int = 3,
    operation: () async throws -> T
) async throws -> T {
    var lastError: Error?

    for attempt in 1...maxAttempts {
        do {
            return try await operation()
        } catch let error as MeshError where error.shouldRetry {
            lastError = error
            let delay = Double(1 << (attempt - 1))
            try? await Task.sleep(for: .seconds(delay))
        } catch {
            throw error
        }
    }

    throw lastError!
}
```

---

## Examples

### Health Monitoring Dashboard

```swift
func updateDashboard() async {
    let health = try await utilities.healthClient()

    // Local node health
    let localHealth = try await health.check(peer: .local)
    dashboard.updateLocal(
        status: localHealth.status,
        uptime: localHealth.uptime,
        peerCount: localHealth.peerCount
    )

    // Remote peer health
    for peerId in monitoredPeers {
        do {
            let status = try await health.check(peer: .remote(peerId), timeout: 5)
            dashboard.updatePeer(peerId, status: status.status, uptime: status.uptime)
        } catch {
            dashboard.markUnreachable(peerId)
        }
    }
}
```

### Peer Discovery

```swift
// Get local known peers (core infrastructure)
let localPeers = await mesh.knownPeersWithInfo()

print("Known peers:")
for peer in localPeers {
    print("  \(peer.peerId): \(peer.natType)")
}

// Query bootstrap peer for more
let remotePeers = try await mesh.queryPeers(from: bootstrapPeer)
print("\nPeers from bootstrap:")
for peer in remotePeers {
    print("  \(peer.peerId): \(peer.endpoints.joined(separator: ", "))")
}
```

### Building a Chat Application

```swift
actor ChatApp {
    private let messages: MessageClient
    private var onMessage: ((PeerMessage) -> Void)?

    init(utilities: MeshUtilities) async throws {
        self.messages = try await utilities.messageClient()

        // Start message handler
        try await utilities.messageHandler { [weak self] message in
            self?.onMessage?(message)
        }
    }

    func setMessageHandler(_ handler: @escaping (PeerMessage) -> Void) {
        self.onMessage = handler
    }

    func send(_ text: String, to peer: PeerId) async throws {
        try await messages.send(text, to: peer)
    }

    func reply(_ text: String, to message: PeerMessage) async throws {
        try await messages.send(text, to: message.from, replyTo: message.id)
    }

    func pendingMessages() async throws -> [PeerMessage] {
        try await messages.pendingMessages()
    }
}
```

---

## API Reference Summary

### MeshNetwork

| Method | Description |
|--------|-------------|
| `start()` | Start the mesh network |
| `stop()` | Stop the mesh network |
| `onChannel(_:handler:)` | Register channel handler |
| `offChannel(_:)` | Unregister channel handler |
| `sendOnChannel(_:to:channel:)` | Send data on a channel (tries hard to find endpoint) |
| `connect(to:)` | Connect to a peer |
| `ping(peer:)` | Full ping with gossip |
| `ping(peer:, lightweight: true)` | Lightweight ping for spotty connections |
| `knownPeers()` | Get local peer cache |
| `knownPeersWithInfo()` | Get local peers with full info |
| `queryPeers(from:)` | Query remote peer's directory |
| `lookupPeer(_:from:)` | Look up specific peer from remote |

### ChannelProvider

| Method | Description |
|--------|-------------|
| `peerId` | This node's peer ID |
| `onChannel(_:handler:)` | Register channel handler |
| `offChannel(_:)` | Unregister channel handler |
| `sendOnChannel(_:to:channel:)` | Send data on a channel |

### MeshUtilities

| Method | Description |
|--------|-------------|
| `startAllHandlers()` | Start all utility handlers |
| `stopAllHandlers()` | Stop all utility handlers |
| `healthClient()` | Get Health client (local + remote) |
| `networkInfoClient()` | Get NetworkInfo client |
| `messageClient()` | Get Message client (with persistence) |

### TunnelManager (OmertaTunnel)

| Method | Description |
|--------|-------------|
| `start()` | Start the tunnel manager |
| `stop()` | Stop and close all sessions |
| `getSession(for:channel:)` | Get or create a session (handles connection automatically) |
| `getExistingSession(for:channel:)` | Get session without creating |
| `closeSession(for:channel:)` | Close a specific session |
| `activeSessions()` | List all active sessions |
| `setSessionEstablishedHandler(_:)` | Handler for incoming sessions |

Endpoint management (hole-punch, relay, reconnection) is internal. For fine-grained control, use `MeshNetwork` directly.

### TunnelSession (OmertaTunnel)

| Property/Method | Description |
|-----------------|-------------|
| `remoteMachineId` | The remote machine ID |
| `channel` | The channel name |
| `state` | Current session state |
| `stats` | Connection statistics |
| `send(_:)` | Send data to remote |
| `onReceive(_:)` | Set receive callback |
| `close()` | Close the session |

---

## Tunnel Sessions (OmertaTunnel)

For latency-sensitive applications like SSH or real-time communication, OmertaTunnel provides **proactively-managed connections** on top of the base mesh.

### Reactive vs Proactive Connection Management

The base `MeshNetwork` already handles hole-punching, relay fallback, and reconnection — but it does so **reactively**, only refreshing connections when traffic flows. This is efficient for background operations, but connections may go stale between uses, causing latency spikes when traffic resumes.

`TunnelManager` adds **proactive** connection management:

| Aspect | MeshNetwork (Reactive) | TunnelManager (Proactive) |
|--------|------------------------|---------------------------|
| Connection refresh | When traffic flows | Continuous, even when idle |
| Problem detection | When a send fails | Before sends fail (health probes) |
| Reconnection | After failure | Preemptive, before timeout |
| Latency visibility | Per-message | Continuous RTT tracking |
| Best for | Background/bulk traffic | User-facing, latency-sensitive |

The underlying mechanisms (hole-punch, relay, encryption) are identical. The difference is **timing**: TunnelManager doesn't wait for traffic to discover a problem.

### Basic Usage

```swift
import OmertaTunnel

// Create tunnel manager on top of mesh
let tunnelManager = TunnelManager(provider: mesh)
try await tunnelManager.start()

// Get or create a session to a remote machine
// This triggers endpoint negotiation if no connection exists
let session = try await tunnelManager.getSession(
    for: remoteMachineId,
    channel: "ssh"  // Logical channel name
)

// Send data
try await session.send(packetData)

// Receive data (callback-based)
session.onReceive { data in
    // Handle incoming packet
}

// Check session state
print("State: \(await session.state)")
print("Latency: \(await session.stats.latencyMs ?? 0)ms")

// Close when done
await tunnelManager.closeSession(for: remoteMachineId, channel: "ssh")
await tunnelManager.stop()
```

### Session Addressing

Sessions are identified by `(MachineId, channel)`:

- **MachineId**: The remote machine (a peer may have multiple machines)
- **channel**: A logical name for the session purpose (e.g., "ssh", "packets", "control")

Multiple sessions to the same machine on different channels are supported. All sessions to the same machine share a single actively-managed endpoint.

```swift
// Multiple channels to the same machine
let sshSession = try await tunnelManager.getSession(for: machineId, channel: "ssh")
let fileSession = try await tunnelManager.getSession(for: machineId, channel: "files")

// Both share the same underlying endpoint (one set of health probes)
```

### TunnelSession API

```swift
public actor TunnelSession {
    /// Session identifier
    public let key: TunnelSessionKey  // (remoteMachineId, channel)
    public var remoteMachineId: MachineId { key.remoteMachineId }
    public var channel: String { key.channel }

    /// Current state
    public var state: TunnelState { get }

    /// Connection statistics
    public var stats: Stats { get }

    public struct Stats {
        public var packetsSent: UInt64
        public var packetsReceived: UInt64
        public var bytesSent: UInt64
        public var bytesReceived: UInt64
        public var lastActivity: Date
    }

    /// Send data to the remote machine
    func send(_ data: Data) async throws

    /// Set handler for incoming data
    func onReceive(_ handler: @escaping (Data) async -> Void)

    /// Close the session
    func close() async
}

public enum TunnelState: Sendable, Equatable {
    case connecting
    case active
    case disconnected
    case failed(String)
}
```

### TunnelManager API

```swift
public actor TunnelManager {
    init(provider: any ChannelProvider, config: TunnelManagerConfig = .default)

    func start() async throws
    func stop() async

    /// Get or create a session. Connection is established automatically.
    func getSession(for machineId: MachineId, channel: String = "default") async throws -> TunnelSession

    /// Get existing session without creating
    func getExistingSession(for machineId: MachineId, channel: String = "default") -> TunnelSession?

    /// Close a session
    func closeSession(for machineId: MachineId, channel: String = "default") async

    /// All active sessions
    func activeSessions() -> [TunnelSession]

    /// Handler for incoming sessions
    func setSessionEstablishedHandler(_ handler: @escaping (TunnelSession) async -> Void)
}
```

Endpoint management (hole-punch, relay fallback, health probes, reconnection) is handled internally. TunnelManager proactively maintains connections so they're ready when you need them. For fine-grained endpoint control, use `MeshNetwork` directly.

### Configuration

```swift
public struct TunnelManagerConfig: Sendable {
    public var idleTimeout: TimeInterval = 300  // Close idle sessions after 5 min
    public var maxSessionsPerMachine: Int = 10
    public var maxTotalSessions: Int = 1000

    // Proactive health monitoring
    public var probeIntervalMs: Int = 5000      // Probe every 5 seconds
    public var probeTimeoutMs: Int = 2000       // Probe timeout
    public var relayFallbackThreshold: Int = 3  // Switch to relay after 3 failed probes
}

let config = TunnelManagerConfig()
config.probeIntervalMs = 1000  // More aggressive for SSH
let tunnelManager = TunnelManager(provider: mesh, config: config)
```

### When to Use Tunnels vs Raw Mesh

| Use Case | Recommendation |
|----------|----------------|
| SSH, interactive shell | TunnelSession |
| Real-time collaboration | TunnelSession |
| Video/audio streaming | TunnelSession |
| File sync (background) | Raw mesh (`sendOnChannel`) |
| Gossip/discovery | Raw mesh |
| Infrequent notifications | Raw mesh |

Rule of thumb: if the user is waiting for a response, use TunnelSession.

---

## See Also

- [MIGRATION.md](MIGRATION.md) - Migration guide from legacy API
- [MeshError.swift](MeshError.swift) - Error type definitions
- [ChannelProvider.swift](ChannelProvider.swift) - Protocol definitions
- [VIRTUAL_NETWORK_REWORK.md](plans/VIRTUAL_NETWORK_REWORK.md) - Virtual network architecture
- [INGRESS_NAT_TRAVERSAL.md](plans/INGRESS_NAT_TRAVERSAL.md) - VM networking architecture
