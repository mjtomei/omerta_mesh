# VM Networking via Ephemeral Mesh Networks

## Overview

This document describes the implementation of VM-to-consumer networking using
ephemeral mesh networks for each VM, with the consumer forwarding traffic to
their local network.

**Problem**: Both providers and consumers are typically home users behind NAT.
The VM needs to send traffic through the consumer's network, but neither side
has a public IP.

**Solution**:
- Create an ephemeral mesh network for each VM
- Use the mesh's existing NAT traversal (hole punch → relay fallback)
- Consumer receives traffic from VM and forwards to local network
- No WireGuard — the mesh provides encryption, authentication, and NAT traversal

**Key Design Principles**:
1. **One network per VM** — isolation, clean teardown, simple lifecycle
2. **Both sides monitor** — consumer and provider independently track connection health
3. **Consumer forwards traffic** — VM traffic exits through consumer's network
4. **Transport-agnostic** — tunnel layer doesn't care what's inside the packets
5. **Extensible gossip** — OmertaMesh provides generic gossip; utilities register their own channel types
6. **Usage-based priority** — nodes prioritize gossip they use, forward everything else best-effort

---

## Summary

### Key Design: User-Mode Networking with Netstack

The VM's traffic is captured by the provider, tunneled through the mesh, and
processed by gVisor's netstack on the consumer side.

**This is the same architecture used by:**
- Tailscale (userspace networking, exit nodes)
- wireguard-go (processing decrypted tunnel packets)

### Traffic Flow Summary

```
VM App
   │ (normal socket call)
   ▼
VM eth0 (veth in namespace)
   │ (raw IP packet)
   ▼
Provider: VMPacketCapture (captures packet)
   │
   ▼
Provider: TunnelSession.injectPacket()
   │ (OmertaTunnel handles encryption/routing)
   ▼
Ephemeral Mesh Network (encrypted, UDP-based)
   │ (OmertaTunnel handles decryption)
   ▼
Consumer: TunnelSession (traffic exit point)
   │ (internal: netstack in OmertaTunnel)
   ▼
Netstack (gVisor) — inside OmertaTunnel
   │ (TCP/UDP/ICMP processing)
   ▼
Real socket connection
   │
   ▼
Consumer's Local Network → Internet
```

**Key:** Consumer and provider only interact with `TunnelSession`. Netstack is
internal to OmertaTunnel — consumers of the utility don't import or configure it.

### Protocol Support

| Protocol               | Handled by                        | Root? |
|------------------------|-----------------------------------|-------|
| TCP                    | Netstack + real socket forwarding | No    |
| UDP                    | Netstack + real socket forwarding | No    |
| ICMP                   | Netstack                          | No    |
| All other IP protocols | Netstack                          | No    |

**All IP protocols supported** — netstack processes at the IP layer, not just
TCP/UDP.

### Strict Isolation Guarantees

Isolation is provided by the platform, not firewall rules (stays in userspace):

**macOS (Virtualization.framework):**
- `VZFileHandleNetworkDeviceAttachment` — VM's only network is the file handle
- No bridge to host network exists
- VM literally cannot reach anything except through our VMPacketCapture

**Linux (network namespaces):**
- VM is in isolated namespace, cannot see host interfaces
- Only interface is veth with route to 10.200.x.1 (our bridge)
- No route to provider's LAN or internet exists in the namespace
- Packets have nowhere to go except through VMPacketCapture

### Advantages

1. **No root on consumer** — netstack runs entirely in userspace
2. **Fully transparent to VM** — VM needs no special configuration
3. **Complete isolation** — network namespace provides strong separation
4. **No special entitlements** — no Apple bridged networking entitlement needed
5. **All IP protocols** — netstack handles everything, not just TCP/UDP
6. **Battle-tested** — same stack used by Tailscale and WireGuard
7. **No WireGuard dependency** — mesh handles encryption/auth

### Extensible Gossip with Usage-Based Priority

**Architecture Choice:** Functionality-specific features (like relay availability for VM
networking) are NOT built into core OmertaMesh. Instead:

1. **Extensible gossip via registration** — OmertaMesh provides generic gossip
   infrastructure, but does NOT know about relay-specific (or other utility-specific)
   message types:
   - Utilities register their gossip channel types through an API
   - OmertaMesh handles propagation without understanding the payload
   - Nodes only process channels they've registered handlers for

2. **Usage-based gossip priority** — Nodes prioritize gossip for channels they
   actively use, but still forward other gossip with spare bandwidth:
   - Registered channels: high priority, always propagate
   - Unregistered channels: best-effort, forwarded when bandwidth allows
   - Popular gossip spreads fast (many nodes prioritize it)
   - Niche gossip still propagates, just slower
   - No configuration needed — natural flow based on actual usage

3. **Single network, multiple channels** — No need for separate networks per function:
   - All gossip flows through the same mesh network
   - Channel registration determines what each node processes
   - Simpler topology, no bridging complexity
   - Nodes are good citizens — they help propagate all gossip, prioritizing their own

4. **OmertaTunnel owns relay logic** — Relay discovery, capacity tracking, and
   coordination live in OmertaTunnel (or higher layers), not OmertaMesh. The mesh
   just provides:
   - A registration API for custom gossip channels
   - Priority-based propagation
   - Generic peer metadata storage

This keeps OmertaMesh focused on core networking (encryption, routing, NAT traversal)
while gossip naturally flows based on what nodes actually use.

### Build Notes

The OmertaTunnel utility includes a Go component (netstack) compiled as a C archive:

```bash
# Build Go netstack as C archive
cd Sources/OmertaTunnel/Netstack
go build -buildmode=c-archive -o libnetstack.a ./...

# Swift links against libnetstack.a via module map
```

This adds a Go toolchain dependency for building OmertaTunnel, but the
resulting binary is self-contained. Consumers of the tunnel utility don't need
to know about netstack — they just use the TunnelSession API.

---

## Implementation Phases

This section breaks down the implementation into discrete phases. Each phase
includes files to create/modify, API changes, tests, and manual verification.

### Phase 1: Netstack Integration and Validation

**Goal:** Download netstack, integrate with build system, verify basic packet
processing works as expected. Netstack lives in OmertaTunnel so the tunnel
utility can provide both peer-to-peer connections AND internet traffic routing.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaTunnel/Netstack/go.mod` | Go module definition |
| `Sources/OmertaTunnel/Netstack/tunnel_netstack.go` | Core netstack wrapper |
| `Sources/OmertaTunnel/Netstack/link_endpoint.go` | Custom link endpoint |
| `Sources/OmertaTunnel/Netstack/exports.go` | C-exported functions |
| `Sources/OmertaTunnel/Netstack/Makefile` | Build as C archive |
| `Sources/CNetstack/module.modulemap` | Swift module map |
| `Sources/OmertaTunnel/Netstack/netstack_test.go` | Go unit tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Package.swift` | Add CNetstack system library, linker flags for OmertaTunnel |

#### API Changes

None — this phase is internal to OmertaTunnel.

#### Unit Tests

| Test | Description |
|------|-------------|
| `TestNetstackInit` | Verify netstack initializes without error |
| `TestTCPHandshake` | Inject SYN, verify SYN-ACK generated |
| `TestTCPDataTransfer` | Inject data packets, verify forwarding |
| `TestUDPForward` | Inject UDP packet, verify real socket created |
| `TestICMPEcho` | Inject ICMP request, verify reply |
| `TestDNSQuery` | Inject DNS query, verify resolution |
| `TestInvalidPacket` | Inject malformed packet, verify no crash |
| `BenchmarkThroughput` | Measure packets/sec baseline |

#### Manual Testing

```bash
# Build netstack
cd Sources/OmertaTunnel/Netstack
go mod tidy
go test -v ./...   # Includes end-to-end UDP and TCP tests
make               # produces libnetstack.a
make install       # copies to Sources/CNetstack/

# Verify Swift can link and run tests
swift build --target OmertaTunnel
swift test --filter OmertaTunnelTests
```

The Go tests include:
- `TestEndToEndUDP`: Injects UDP packet, verifies echo response through netstack
- `TestEndToEndTCP`: Full TCP handshake + HTTP request/response through netstack

---

### Phase 2: Tunnel Utility and Cloister Integration

**Goal:** Create a new Tunnel utility that wraps the existing Cloister
functionality for ephemeral network creation and sharing. Tunnels are generic
persistent sessions — not VM-specific. Consumer and provider consume this
utility — they never call Cloister APIs directly.

**Architecture:**

The tunnel utility is **Cloister-agnostic**. It operates on any mesh network
(ChannelProvider) and assumes a simple two-peer topology. Cloister negotiation
happens at the Provider/Consumer layer, not in OmertaTunnel.

```
┌─────────────────────────────────────────────────────────────┐
│  Consumer / Provider                                        │
│  - Uses CloisterClient to negotiate ephemeral network       │
│  - Creates MeshNetwork with derived network key             │
│  - Passes MeshNetwork to OmertaTunnel                       │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  OmertaTunnel (UTILITY)                             │    │
│  │  - TunnelManager: session lifecycle                 │    │
│  │  - TunnelSession: peer messaging + traffic routing  │    │
│  │  - Operates on ChannelProvider (mesh-agnostic)      │    │
│  │  - Assumes two endpoints (+ optional relay)         │    │
│  └──────────────────────┬──────────────────────────────┘    │
│                         │ uses                              │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  OmertaMesh (EXISTING)                              │    │
│  │  - ChannelProvider: onChannel, sendOnChannel        │    │
│  │  - MeshNetwork: implements ChannelProvider          │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Key design decision:** OmertaTunnel doesn't know about Cloister. The fact that
the underlying network was created via Cloister key exchange is incidental.
This keeps the tunnel utility simple and reusable.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaTunnel/TunnelManager.swift` | High-level tunnel API |
| `Sources/OmertaTunnel/TunnelSession.swift` | Per-tunnel state container |
| `Sources/OmertaTunnel/TunnelConfig.swift` | Tunnel configuration |
| `Tests/OmertaTunnelTests/TunnelManagerTests.swift` | Unit tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Package.swift` | Add OmertaTunnel target, depends on OmertaMesh |
| `Sources/OmertaConsumer/MeshConsumerClient.swift` | Use TunnelManager |
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Use TunnelManager |

#### API Changes

```swift
// OmertaTunnel public API
//
// OmertaTunnel provides TWO capabilities:
// 1. Peer-to-peer messaging over any mesh network
// 2. Internet traffic routing via netstack (traffic exits through one peer)
//
// The utility is Cloister-agnostic and netstack-agnostic from the caller's
// perspective. It just takes a ChannelProvider and manages a session.

public actor TunnelManager {
    /// Initialize with any ChannelProvider (e.g., MeshNetwork)
    init(provider: any ChannelProvider)

    /// Start the manager (registers handshake channel)
    func start() async throws

    /// Stop the manager
    func stop() async

    /// Create a session with a remote peer
    func createSession(with peer: PeerId) async throws -> TunnelSession

    /// Get the current session (only one at a time in simple model)
    func currentSession() -> TunnelSession?

    /// Close the current session
    func closeSession() async

    /// Set handler for incoming session requests
    func setSessionRequestHandler(_ handler: @escaping (PeerId) async -> Bool)

    /// Set handler called when session is established
    func setSessionEstablishedHandler(_ handler: @escaping (TunnelSession) async -> Void)
}

public actor TunnelSession {
    /// The remote peer we're connected to
    let remotePeer: PeerId

    /// Current state
    var state: TunnelState { get }

    /// Current role in traffic routing
    var role: TunnelRole { get }

    // --- Peer-to-peer messaging ---
    /// Send data to the remote peer
    func send(_ data: Data) async throws

    /// Stream of incoming messages from the remote peer
    func receive() -> AsyncStream<Data>

    // --- Internet traffic routing (netstack-backed) ---
    /// Enable traffic routing through this session
    /// - Parameter asExit: If true, this peer is the exit (runs netstack).
    ///   If false, this peer forwards traffic to remote for exit.
    func enableTrafficRouting(asExit: Bool) async throws

    /// Inject a raw IP packet for routing
    func injectPacket(_ packet: Data) async throws

    /// Stream of return packets (responses from internet)
    var returnPackets: AsyncStream<Data> { get }

    /// Disable traffic routing
    func disableTrafficRouting() async

    // --- Lifecycle ---
    func leave() async
}

// Session states
public enum TunnelState: Sendable, Equatable {
    case connecting
    case active
    case disconnected
    case failed(String)
}

// Traffic routing roles
public enum TunnelRole: Sendable, Equatable {
    case peer           // Just messaging, no traffic routing
    case trafficSource  // Forwards traffic to remote peer for exit
    case trafficExit    // Receives traffic and exits via netstack
}

// INTERNAL: Traffic routing uses netstack (Go, compiled as C archive)
// Consumers of the utility don't need to know about netstack
```

**Usage pattern (Provider/Consumer layer):**
```swift
// 1. Use Cloister to negotiate ephemeral network (at Provider/Consumer layer)
let cloister = CloisterClient(provider: mainMesh)
let result = try await cloister.negotiate(with: consumerPeerId, networkName: "vm-\(vmId)")

// 2. Create MeshNetwork with derived key
let ephemeralConfig = MeshConfig(encryptionKey: result.networkKey)
let ephemeralMesh = MeshNetwork(identity: identity, config: ephemeralConfig)
try await ephemeralMesh.start()

// 3. Use TunnelManager on that network
let tunnel = TunnelManager(provider: ephemeralMesh)
try await tunnel.start()
let session = try await tunnel.createSession(with: consumerPeerId)

// 4. Enable traffic routing
try await session.enableTrafficRouting(asExit: false)  // Provider forwards to consumer

// 5. Inject VM packets
try await session.injectPacket(vmPacket)
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testManagerInitialization` | Create manager, verify no session initially |
| `testManagerStartStop` | Start/stop manager, verify channel registration |
| `testCreateSession` | Create session, verify handshake sent |
| `testSendMessage` | Send data, verify delivered to remote peer |
| `testLeaveSession` | Leave session, verify cleanup |
| `testSessionActivation` | Activate session, verify channels registered |
| `testSendRequiresActiveState` | Send without activation fails |
| `testTrafficRoutingNotEnabledByDefault` | Inject packet fails without enabling |
| `testEnableTrafficRoutingAsSource` | Enable as source, verify can inject |
| `testCloseSession` | Close session, verify handshake sent |

#### Manual Testing

Since OmertaTunnel is Cloister-agnostic, manual testing requires setting up
the full stack (Cloister negotiation + ephemeral network). This is best done
via the Provider/Consumer integration.

**Option 1: Unit test verification**
```bash
# Run the tunnel utility tests
swift test --filter OmertaTunnelTests

# Expected output:
# NetstackBridgeTests: 7 passed
# TunnelConfigTests: 3 passed
# TunnelManagerTests: 5 passed
# TunnelSessionTests: 7 passed
```

**Option 2: Integration test with netstack**
```bash
# Run Go netstack tests (requires Go)
cd Sources/OmertaTunnel/Netstack
go test -v

# Expected: TestEndToEndUDP and TestEndToEndTCP pass
```

**Option 3: Full stack test (Phase 4)**
Full manual testing of the tunnel utility happens as part of VM integration
testing in Phase 4, where Provider and Consumer use the complete stack.

---

### Phase 3: Tunnel Traffic Routing Integration

**Goal:** Connect TunnelSession's traffic routing to netstack. The tunnel utility
now handles all traffic routing internally — consumers just use the TunnelSession
API (`injectPacket`, `returnPackets`). Test with dummy data to verify real
internet connections work.

**Status:** ✅ Implemented in Phase 1-2. Traffic routing is integrated directly
into TunnelSession via NetstackBridge.

#### Files Created (in Phase 1-2)

| File | Description |
|------|-------------|
| `Sources/OmertaTunnel/NetstackBridge.swift` | Swift/Go bridge for netstack |
| `Sources/OmertaTunnel/TunnelSession.swift` | Traffic routing via channels |
| `Tests/OmertaTunnelTests/NetstackBridgeTests.swift` | Integration tests |

#### Implementation Notes

Traffic routing is built into TunnelSession:
- `enableTrafficRouting(asExit: true)` — Creates NetstackBridge, processes packets
- `enableTrafficRouting(asExit: false)` — Forwards packets to remote peer
- `injectPacket(_:)` — Sends packet via appropriate channel
- `returnPackets` — Stream of responses

The implementation uses three channels:
- `tunnel-traffic` — Forward packets (source → exit)
- `tunnel-return` — Return packets (exit → source)
- `tunnel-data` — General messaging

```swift
// PUBLIC API (from TunnelSession):
// - enableTrafficRouting(asExit:)  // true=exit point, false=source
// - injectPacket(_:)               // Sends packet
// - returnPackets                  // Receives responses
// - disableTrafficRouting()        // Tears down routing

// Consumer/Provider code ONLY uses TunnelSession public API.
// NetstackBridge is internal to TunnelSession.
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testEnableTrafficRoutingAsSource` | Enable as source, verify can inject |
| `testTrafficRoutingNotEnabledByDefault` | Inject without enable fails |
| `testNetstackInit` | Create netstack, verify initialization |
| `testNetstackStartStop` | Start/stop lifecycle |
| `testReturnCallback` | Verify callback receives packets |
| `TestEndToEndUDP` (Go) | Full UDP echo through netstack |
| `TestEndToEndTCP` (Go) | Full TCP/HTTP through netstack |

#### Manual Testing

Traffic routing is tested via the Go netstack tests:

```bash
# Run end-to-end netstack tests
cd Sources/OmertaTunnel/Netstack
go test -v -run TestEndToEnd

# Expected output:
# === RUN   TestEndToEndUDP
# --- PASS: TestEndToEndUDP
# === RUN   TestEndToEndTCP
# --- PASS: TestEndToEndTCP
```

Full stack testing happens in Phase 4 with VM integration.

---

### Phase 4: VM Integration

**Goal:** Connect VM network interface to TunnelSession. Provider captures VM
packets and uses TunnelSession.injectPacket(). Consumer receives via netstack
(handled by OmertaTunnel internally). Test full flow with internet-connected VM.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaProvider/VMPacketCapture.swift` | Captures packets from VM |
| `Sources/OmertaProvider/VMNetworkNamespace.swift` | Linux namespace setup |
| `Sources/OmertaProvider/VMNetworkFileHandle.swift` | macOS file handle setup |
| `Tests/OmertaProviderTests/VMPacketCaptureTests.swift` | Integration tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Create tunnel, wire up packet capture |
| `Sources/OmertaVM/VMManager.swift` | Configure VM for packet capture |

#### API Changes

```swift
// VMPacketCapture: captures VM traffic and sends via TunnelSession
public actor VMPacketCapture {
    init(vmId: UUID, packetSource: PacketSource, tunnelSession: TunnelSession)
    func start() async throws
    func stop() async
}

// PacketSource protocol (abstracts Linux namespaces vs macOS file handles)
public protocol PacketSource: Sendable {
    var inbound: AsyncStream<Data> { get }
    func write(_ packet: Data) async throws
}

// Usage in provider:
// 1. Use Cloister to negotiate ephemeral network with consumer
// 2. Create MeshNetwork with derived key, start it
// 3. Create TunnelManager on that network
// 4. Create session: let session = try await tunnel.createSession(with: consumerPeerId)
// 5. Enable traffic routing: try await session.enableTrafficRouting(asExit: false)
// 6. Create VMPacketCapture with session
// 7. VMPacketCapture calls session.injectPacket() for outbound
// 8. VMPacketCapture reads session.returnPackets for inbound
//
// On consumer side:
// 1. Accept Cloister negotiation
// 2. Create MeshNetwork with derived key
// 3. Create TunnelManager, accept session
// 4. Enable as exit: try await session.enableTrafficRouting(asExit: true)
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testCaptureVMPacket` | VM sends packet, verify capture |
| `testInjectToVM` | Inject packet, verify VM receives |
| `testDHCPResponse` | VM requests DHCP, verify response |
| `testARPResponse` | VM sends ARP, verify response |
| `testMTUHandling` | Large packet, verify fragmentation |
| `testBridgeCleanup` | Stop bridge, verify resources freed |

#### Manual Testing

```bash
# Terminal 1: Start consumer (will be traffic exit point)
omertad start --port 18002

# Terminal 2: Start provider
omertad start --port 18003 --bootstrap localhost:18002

# Request VM from provider (creates tunnel automatically)
# Provider creates tunnel with consumer, enables traffic routing
omerta vm request --provider <provider-peer-id> --consumer <consumer-peer-id>
# Output: VM started, tunnel: <tunnel-id>, exit: <consumer-peer-id>

# In VM console:
ping 1.1.1.1
# Should succeed - packets flow:
#   VM -> VMPacketCapture -> TunnelSession.injectPacket()
#   -> mesh -> consumer's TunnelSession.returnPackets -> netstack
#   -> internet -> netstack -> TunnelSession -> mesh -> VM

curl https://example.com
# Should return HTML

dig google.com
# Should resolve

# Verify no traffic on provider's network
# Terminal 2 (provider):
tcpdump -i eth0 host 1.1.1.1
# Should show NO packets (all go through mesh to consumer)

# Terminal 1 (consumer):
tcpdump -i eth0 host 1.1.1.1
# Should show packets (consumer is the exit point)
```

---

### Phase 5: Relay Discovery and Gossip Integration

**Goal:** Track and propagate which peers are willing to act as relays. Use
the same gossip mechanism as endpoint announcements. Request relay nodes to
join ephemeral networks.

**Key Design:**
- **Extensible gossip** — OmertaMesh provides generic gossip infrastructure;
  relay-specific messages are registered by OmertaTunnel, not hardcoded
- **Usage-based priority** — Nodes prioritize gossip for channels they use,
  but still forward all other gossip with spare bandwidth
- **Single network** — No separate networks for different functions; all gossip
  flows through the same mesh with channel-based filtering
- **Relay capacity is PER-MACHINE (per peer ID), not per-endpoint**
  - A machine may advertise multiple endpoints (IPv4, IPv6, etc.)
  - But relay capacity is a single value for the whole machine
  - Stored locally in `~/.omerta/mesh/relay-config.json` (machine-level file)

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaTunnel/RelayCoordinator.swift` | Relay selection/request |
| `Sources/OmertaMesh/Gossip/GossipRouter.swift` | Channel registration + priority routing |
| `Sources/OmertaMesh/Gossip/PeerMetadataStore.swift` | Generic key-value metadata per peer |
| `Tests/OmertaTunnelTests/RelayCoordinatorTests.swift` | Relay tests |
| `Tests/OmertaMeshTests/GossipRouterTests.swift` | Gossip routing tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaMesh/Discovery/PeerStore.swift` | Add generic metadata storage hooks |
| `Sources/OmertaMesh/MeshNode.swift` | Integrate GossipRouter |
| `Sources/OmertaMesh/Public/MeshNetwork.swift` | Expose gossip registration API |
| `Sources/OmertaMesh/Public/MeshConfig.swift` | Add GossipConfig (budget, recency half-life) |

#### API Changes

```swift
// === OmertaMesh: Generic Gossip Infrastructure ===
// OmertaMesh does NOT know about relay-specific types. It provides:
// 1. A registration API for custom gossip channels
// 2. Usage-based priority routing
// 3. Generic peer metadata storage

/// Gossip entry - opaque to OmertaMesh except for channel ID
public struct GossipEntry: Codable, Sendable {
    let channelId: String
    let peerId: PeerId
    let payload: Data
    let timestamp: Date
}

/// Gossip router - handles registration and priority-based propagation
public actor GossipRouter {
    /// Channels this node has registered handlers for (high priority)
    private var activeChannels: Set<String>

    /// Register a handler for a channel - marks it as active (high priority)
    func register<T: Codable>(
        channel: String,
        handler: @escaping (PeerId, T) async -> Void
    )

    /// Publish data on a channel
    func publish<T: Codable>(channel: String, data: T) async throws

    /// Stream of updates for a channel (must be registered)
    func updates<T: Codable>(channel: String) -> AsyncStream<(PeerId, T)>

    /// Prioritize gossip for propagation:
    /// - Active channels: always propagate
    /// - Other channels: propagate with spare bandwidth
    func prioritize(_ entries: [GossipEntry], bandwidth: Int) -> [GossipEntry]
}

/// Generic per-peer metadata storage - utilities store their data here
public actor PeerMetadataStore {
    /// Store metadata for a peer (key-value, any Codable)
    func set<T: Codable>(_ key: String, value: T, for peer: PeerId) async

    /// Retrieve metadata for a peer
    func get<T: Codable>(_ key: String, for peer: PeerId) async -> T?

    /// Get all peers with a given metadata key
    func peers<T: Codable>(with key: String) async -> [(PeerId, T)]

    /// Stream metadata updates for a key across all peers
    func updates<T: Codable>(for key: String) -> AsyncStream<(PeerId, T)>
}

// === OmertaTunnel: Relay-Specific Types ===
// These are defined in OmertaTunnel, NOT OmertaMesh

/// Relay announcement - published via GossipRouter
public struct RelayAnnouncement: Codable, Sendable {
    static let channelId = "relay"

    let peerId: PeerId
    let capacity: Int           // 0 = not a relay, >0 = available slots
    let currentLoad: Int        // How many sessions currently relaying
    let timestamp: Date
}

/// Local per-machine state for relay willingness (stored on disk)
public struct RelayConfig: Codable {
    var enabled: Bool = false
    var maxCapacity: Int = 10       // Total slots this machine offers
    var currentLoad: Int = 0        // Slots currently in use
    // Stored at: ~/.omerta/mesh/relay-config.json (machine-level, not per-network)
}

/// Relay coordinator (in OmertaTunnel, uses gossiped data)
public actor RelayCoordinator {
    init(gossipRouter: GossipRouter, metadataStore: PeerMetadataStore)

    func start() async  // Registers "relay" channel with router
    func stop() async

    func availableRelays() async -> [PeerId]
    func requestRelay(for session: TunnelSession) async throws -> PeerId
    func releaseRelay(_ relayPeerId: PeerId, for session: TunnelSession) async
}
```

**Usage Pattern:**
```swift
// In OmertaTunnel initialization:
let router = meshNetwork.gossipRouter
let metadataStore = meshNetwork.peerMetadataStore

let relayCoordinator = RelayCoordinator(
    gossipRouter: router,
    metadataStore: metadataStore
)
await relayCoordinator.start()  // Registers "relay" channel

// This node now:
// 1. Receives relay announcements (registered handler processes them)
// 2. Prioritizes relay gossip when propagating to peers
// 3. Still forwards other gossip types with spare bandwidth
```

**Gossip Priority Example:**
```
Node A (uses relay)          Node B (uses relay + vm-status)    Node C (uses nothing extra)
───────────────────          ───────────────────────────────    ────────────────────────────
Receives gossip:             Receives gossip:                   Receives gossip:
 - relay: process + high pri  - relay: process + high pri        - relay: forward, low pri
 - vm-status: forward, low    - vm-status: process + high pri    - vm-status: forward, low
 - other: forward, low        - other: forward, low              - other: forward, low

All gossip flows everywhere, but nodes prioritize what they use.
Popular channels spread faster because more nodes prioritize them.
```

**Gossip Prioritization Algorithm:**

Gossip bandwidth is controlled by a configurable bytes/second budget. Prioritization
uses both recency and activity weighting:

```swift
// Config
public struct GossipConfig {
    var budgetBytesPerSecond: Int = 10_000  // 10 KB/s default
    var recencyHalfLifeSeconds: Double = 60  // Weight halves every 60s
}

// Channel activity tracking
struct ChannelActivity {
    var lastPublishTime: Date?      // When we last published on this channel
    var lastReceiveTime: Date?      // When we last processed a message
    var publishCount: Int = 0       // Total publishes by this node
    var receiveCount: Int = 0       // Total messages processed
}

// Priority calculation
func priority(for entry: GossipEntry, activity: ChannelActivity?) -> Double {
    // Base priority: is this an active channel?
    let isActive = activity != nil
    var score: Double = isActive ? 1000.0 : 1.0

    // Factor 1: Recency of gossip entry (newer = higher priority)
    let entryAgeSeconds = Date().timeIntervalSince(entry.timestamp)
    let entryRecency = pow(0.5, entryAgeSeconds / config.recencyHalfLifeSeconds)
    score *= entryRecency

    // Factor 2: Recency of channel activity (recently used channels = higher)
    if let activity = activity {
        let lastActivity = max(
            activity.lastPublishTime ?? .distantPast,
            activity.lastReceiveTime ?? .distantPast
        )
        let activityAgeSeconds = Date().timeIntervalSince(lastActivity)
        let activityRecency = pow(0.5, activityAgeSeconds / config.recencyHalfLifeSeconds)
        score *= (1.0 + activityRecency)  // Boost, not multiply to zero
    }

    // Factor 3: Activity level (more active on channel = higher priority)
    if let activity = activity {
        let activityLevel = Double(activity.publishCount + activity.receiveCount)
        score *= (1.0 + log1p(activityLevel) * 0.1)  // Gentle boost
    }

    return score
}

// Gossip round: select entries within budget
func selectForGossip(_ entries: [GossipEntry]) -> [GossipEntry] {
    let scored = entries.map { ($0, priority(for: $0, activity: channelActivity[$0.channelId])) }
    let sorted = scored.sorted { $0.1 > $1.1 }

    var selected: [GossipEntry] = []
    var bytesUsed = 0
    let budget = config.budgetBytesPerSecond  // Per round, assuming 1s rounds

    for (entry, _) in sorted {
        let entrySize = entry.payload.count + 50  // Payload + overhead estimate
        if bytesUsed + entrySize <= budget {
            selected.append(entry)
            bytesUsed += entrySize
        }
    }

    return selected
}
```

**Priority Factors Summary:**

| Factor | Effect | Rationale |
|--------|--------|-----------|
| Active channel | 1000× boost | Prioritize what we use |
| Entry age | Exponential decay | Fresh gossip is more valuable |
| Channel activity recency | 1-2× boost | Recently used channels matter more |
| Channel activity level | ~1.3× boost at 10 msgs | Reward sustained participation |

**Storage Locations:**
- **RelayConfig** (machine-level): `~/.omerta/mesh/relay-config.json`
  - Single file per machine
  - Controls whether this machine acts as a relay
- **RelayAnnouncement** (gossiped): Published via GossipRouter on "relay" channel
  - Stored in PeerMetadataStore under "relay" key for quick lookups

#### Unit Tests

| Test | Description |
|------|-------------|
| `testGossipChannelRegistration` | Register channel, verify handler called on receive |
| `testGossipPriorityActiveChannels` | Active channels prioritized over inactive |
| `testGossipBestEffortForwarding` | Unregistered channels still forwarded with spare bandwidth |
| `testPeerMetadataStorage` | Store/retrieve metadata for peers |
| `testRelayAnnouncementGossiped` | Relay announces capacity, peers receive it |
| `testRelayCapacityUpdates` | Capacity changes, gossip propagates update |
| `testAvailableRelays` | Query available relays, correct list returned |
| `testRequestRelay` | Request relay, verify accepted |
| `testRelayAtCapacity` | Request when full, verify fallback |

#### Manual Testing

```bash
# Terminal 1: Start bootstrap/relay node
omertad start --port 18001 --relay-capacity 10

# Verify relay capacity is gossiped
omerta mesh peers --show-metadata
# Output:
#   <bootstrap-id>: endpoint=..., relay_capacity=10

# Terminal 2: Start provider
omertad start --port 18002 --bootstrap localhost:18001

# Verify provider sees relay availability
omerta mesh relays
# Output: Available relays: <bootstrap-id> (10 slots)

# The relay is used at the mesh network level when establishing
# the ephemeral network connection (not at the tunnel session level).
# If direct connection fails, the mesh falls back to relay automatically.

# Verify relay load updated when connection uses relay
omerta mesh peers --show-metadata
# Output:
#   <bootstrap-id>: endpoint=..., relay_capacity=10, current_load=1
```

---

### Phase 6: Complete Network Isolation

**Goal:** Ensure absolutely no internet traffic goes through the provider host,
including DNS. All traffic must flow through the mesh to the consumer.

**Note:** Isolation is built into the network namespace/file handle setup from
Phase 4. This phase validates that isolation through tests. No separate
verification code is needed — the tests themselves serve as verification.

**DNS Handling:** We defer DNS interception until tests reveal whether it's
needed. The VM's DNS should be configured to use the mesh gateway (10.200.X.1).
If tests show DNS leaking to the host, we'll add interception code.

#### Files to Create

| File | Description |
|------|-------------|
| `Tests/OmertaProviderTests/IsolationTests.swift` | Isolation validation tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaVM/VMManager.swift` | Ensure DNS points to mesh gateway |

#### API Changes

None — isolation is inherent in the architecture, validated by tests.

#### Unit Tests

| Test | Description |
|------|-------------|
| `testVMCannotReachHost` | VM pings host IP, verify failure |
| `testVMCannotReachLAN` | VM pings LAN IPs, verify failure |
| `testVMCannotReachInternetDirect` | Block mesh, VM has no connectivity |
| `testDNSGoesToMeshGateway` | Check VM resolv.conf points to 10.200.X.1 |
| `testNoHostDNSLeak` | tcpdump on host, verify no DNS traffic |
| `testAllTrafficViaMesh` | Monitor host, verify no non-mesh traffic |

#### Manual Testing

```bash
# Start provider and VM as in Phase 4
omertad start --port 18002
omerta vm create --name isolated-vm --image ubuntu-22.04 --remote-bridge
omerta vm start isolated-vm

# On provider host, monitor all traffic
sudo tcpdump -i any -n 'not port 18002'
# Should show NO traffic from VM

# In VM:
# Try to reach host
ping 192.168.1.1  # Provider's LAN IP
# Should fail: Network unreachable

# Try to reach LAN
ping 192.168.1.100  # Another LAN device
# Should fail: Network unreachable

# Verify DNS configuration
cat /etc/resolv.conf
# Should show: 10.200.X.1 (mesh gateway, not host DNS)

# Test DNS works through mesh
dig google.com
# Should work (via mesh to consumer)

# Disconnect consumer, retry
dig google.com
# Should fail: no connectivity (proves DNS goes through mesh)
```

---

### Phase 7: Endpoint Change Detection and Keepalive

**Goal:** Detect when consumer or provider endpoints change. Implement RTT-based
keepalive. Connection heals automatically when endpoints change.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaMesh/Tunnel/TunnelHealthMonitor.swift` | Health monitoring |
| `Sources/OmertaMesh/Tunnel/EndpointChangeDetector.swift` | OS event monitoring |
| `Tests/OmertaMeshTests/TunnelHealthTests.swift` | Health tests |
| `Tests/OmertaMeshTests/EndpointChangeTests.swift` | Change detection tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaTunnel/TunnelManager.swift` | Integrate health monitor |
| `Sources/OmertaMesh/Public/MeshConfig.swift` | Add keepalive intervals |
| `Sources/OmertaMesh/Types/MeshMessage.swift` | Add TunnelEndpointUpdate |

#### API Changes

```swift
// Health monitor
public actor TunnelHealthMonitor {
    var currentProbeIntervalMs: Int { get }
    func onPacketReceived()
    func startMonitoring(tunnel: ManagedTunnel) async
}

// Endpoint change detector
public actor EndpointChangeDetector {
    func startMonitoring() async
    var endpointChanges: AsyncStream<EndpointChange> { get }
}

public struct EndpointChange: Sendable {
    let oldEndpoint: Endpoint?
    let newEndpoint: Endpoint
    let reason: ChangeReason  // networkSwitch, ipChange, interfaceDown
}

// New message
case tunnelEndpointUpdate(tunnelId: UUID, newEndpoint: Endpoint, reason: String)
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testKeepaliveProbe` | No traffic, verify probe sent |
| `testKeepaliveBackoff` | Idle connection, verify interval grows |
| `testKeepaliveReset` | Traffic received, verify interval resets |
| `testEndpointChangeDetected` | Simulate IP change, verify detection |
| `testRenegotiationOnChange` | Endpoint changes, verify renegotiation |
| `testConnectionHeals` | Change endpoint, verify traffic resumes |
| `testBothSidesMonitor` | Either side detects, both recover |

#### Manual Testing

```bash
# Start full setup (provider + VM + consumer)
# Establish working connection, verify traffic flows

# Test 1: Consumer network change
# On consumer machine:
# Disconnect WiFi, connect to different network
# Watch logs for: "Endpoint changed, renegotiating..."
# Verify VM traffic resumes within 5 seconds

# Test 2: Provider network change
# On provider machine:
# Change IP address
sudo ip addr del 192.168.1.X/24 dev eth0
sudo ip addr add 192.168.1.Y/24 dev eth0
# Watch logs for renegotiation
# Verify VM traffic resumes

# Test 3: Keepalive under load
# In VM, start continuous ping
ping -i 0.1 1.1.1.1
# Verify no keepalive probes (traffic counts as keepalive)
# Stop ping, wait 30 seconds
# Verify keepalive probes start, interval increases

# Test 4: RTT measurement
omerta vm-network stats <network-id>
# Output: RTT avg: 5ms, p99: 12ms, probe interval: 2000ms
```

---

### Phase 8: Failure Backoff and User Messaging

**Goal:** Implement backoff for failed reconnection attempts. Provide clear user
messages about connection state without spamming.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaMesh/Tunnel/ReconnectionManager.swift` | Backoff logic |
| `Sources/OmertaMesh/Tunnel/ConnectionStateReporter.swift` | User messaging |
| `Tests/OmertaMeshTests/ReconnectionTests.swift` | Backoff tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaMesh/Tunnel/TunnelHealthMonitor.swift` | Integrate backoff |
| `Sources/OmertaMesh/Types/MeshNodeServices.swift` | Add state delegate |
| `Sources/OmertaConsumer/MeshConsumerClient.swift` | Display state changes |
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Display state changes |

#### API Changes

```swift
// Connection state (from earlier)
public enum TunnelConnectionState: Sendable {
    case connected
    case reconnecting(attempt: Int, nextRetryMs: Int)
    case degraded(reason: String)
}

// Delegate for state changes
public protocol TunnelConnectionDelegate: AnyObject, Sendable {
    func connectionStateDidChange(
        tunnelId: UUID,
        state: TunnelConnectionState
    ) async
}

// Reconnection manager
public actor ReconnectionManager {
    var currentBackoffMs: Int { get }
    func recordFailure() -> Int  // Returns next retry delay
    func recordSuccess()         // Resets backoff
}
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testBackoffIncreases` | Each failure doubles delay |
| `testBackoffCaps` | Verify max backoff (60s) |
| `testBackoffResets` | Success resets to minimum |
| `testStateTransitions` | connected → reconnecting → connected |
| `testNoMessageSpam` | 10 failures, verify ≤3 user messages |
| `testDegradedState` | High latency, verify degraded reported |

#### Manual Testing

```bash
# Start full setup with VM

# Test 1: Simulate consumer disconnect
# Kill consumer process
# Watch provider logs:
#   "Connection lost, reconnecting (attempt 1, retry in 500ms)"
#   "Reconnecting (attempt 2, retry in 1000ms)"
#   "Reconnecting (attempt 3, retry in 2000ms)"
# Messages should NOT repeat every 100ms

# Restart consumer
# Watch logs: "Connection restored"

# Test 2: Sustained outage
# Keep consumer offline for 2 minutes
# Verify backoff reaches 60s max
# Verify user sees at most ~5 messages total

# Test 3: Degraded state
# Add latency: tc qdisc add dev eth0 root netem delay 500ms
# Verify: "Connection degraded: high latency (>200ms)"
# Remove latency
# Verify: "Connection restored"
```

---

### Phase 9: Consumer Port Forwarding

**Goal:** Allow port forwarding on consumer side so external traffic (SSH, web)
can reach the VM.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaConsumer/PortForwarder.swift` | Port forwarding logic |
| `Sources/OmertaConsumer/Netstack/port_forward.go` | Go-side forwarding |
| `Tests/OmertaConsumerTests/PortForwardTests.swift` | Port forward tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaConsumer/MeshConsumerClient.swift` | Add port forward API |
| `Sources/OmertaConsumer/Netstack/exports.go` | Export port forward funcs |
| `Sources/CNetstack/module.modulemap` | Add new exports |

#### API Changes

```swift
// Port forwarding API
public actor PortForwarder {
    func addForward(
        externalPort: UInt16,
        vmPort: UInt16,
        protocol: IPProtocol  // .tcp or .udp
    ) async throws -> PortForwardHandle

    func removeForward(_ handle: PortForwardHandle) async
    func listForwards() -> [PortForward]
}

public struct PortForward: Sendable {
    let externalPort: UInt16
    let vmPort: UInt16
    let proto: IPProtocol
    let bytesForwarded: UInt64
}
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testTCPForward` | Forward port 2222→22, verify SSH works |
| `testUDPForward` | Forward UDP port, verify traffic flows |
| `testMultipleForwards` | Add 5 forwards, all work |
| `testRemoveForward` | Remove forward, port closes |
| `testPortConflict` | Forward same port twice, verify error |
| `testForwardPersistence` | Restart consumer, forwards restored |

#### Manual Testing

```bash
# Start full setup with VM running SSH server

# Add port forward
omerta port-forward add 2222:22 --vm test-vm
# Output: Forwarding localhost:2222 → VM:22

# Test SSH access
ssh -p 2222 user@localhost
# Should connect to VM

# Add web server forward
omerta port-forward add 8080:80 --vm test-vm
curl http://localhost:8080
# Should return VM's web page

# List forwards
omerta port-forward list
# Output:
#   2222 → 22/tcp (VM: test-vm) - 15.2 KB transferred
#   8080 → 80/tcp (VM: test-vm) - 1.1 MB transferred

# Remove forward
omerta port-forward remove 2222
ssh -p 2222 user@localhost
# Should fail: Connection refused
```

---

### Phase 10: Peer Expiry and Rejoin

**Goal:** Implement backoff and dropoff for peers that stop responding.
Support successful rejoin after being dropped from peer lists.

**Note:** This code belongs in core **OmertaMesh**, not the OmertaTunnel utility.
Peer expiry is fundamental mesh behavior that applies to all mesh usage, not
just tunnels.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaMesh/Peers/PeerExpiryManager.swift` | Expiry tracking |
| `Tests/OmertaMeshTests/PeerExpiryTests.swift` | Expiry tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaMesh/MeshNode.swift` | Integrate expiry manager |
| `Sources/OmertaMesh/Discovery/PeerStore.swift` | Add stale/expired states |
| `Sources/OmertaMesh/Public/MeshConfig.swift` | Add expiry thresholds |

#### API Changes

```swift
// Peer state (in OmertaMesh, not OmertaTunnel)
public enum PeerState: Sendable {
    case active              // Responding normally
    case stale(missedPings: Int)  // Not responding, still tracked
    case expired             // Removed from peer list
}

// Expiry manager (in OmertaMesh)
public actor PeerExpiryManager {
    func recordPing(peerId: PeerId, success: Bool)
    func peerState(_ peerId: PeerId) -> PeerState
    var expiredPeers: AsyncStream<PeerId> { get }
}

// Config additions
public struct MeshConfig {
    var staleThresholdMissedPings: Int = 3
    var expiryThresholdMissedPings: Int = 8
    var rejoinGracePeriodSeconds: Int = 300
}
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testPeerBecomesStale` | 3 missed pings → stale |
| `testPeerExpires` | 8 missed pings → expired |
| `testStaleRecovery` | Stale peer responds, becomes active |
| `testExpiredPeerDropped` | Expired peer removed from list |
| `testRejoinAfterExpiry` | Expired peer rejoins, accepted |
| `testGossipReducedForStale` | Stale peers not actively gossiped |
| `testMultiplePeersExpire` | 5 peers go offline, all expire correctly |

#### Manual Testing

```bash
# Start 3-node network
# Terminal 1: Bootstrap
omertad start --port 18001

# Terminal 2: Node A
omertad start --port 18002 --bootstrap localhost:18001

# Terminal 3: Node B
omertad start --port 18003 --bootstrap localhost:18001

# Verify all see each other
omerta mesh peers
# Output: 3 peers (bootstrap, A, B)

# Kill Node B (Ctrl+C in Terminal 3)
# Wait 30 seconds, check Node A
omerta mesh peers --show-state
# Output:
#   bootstrap: active (last seen: 1s ago)
#   B: stale (missed pings: 4)

# Wait another 30 seconds
omerta mesh peers --show-state
# Output:
#   bootstrap: active
#   (B no longer listed - expired)

# Restart Node B
omertad start --port 18003 --bootstrap localhost:18001

# Check Node A
omerta mesh peers
# Output: 3 peers (bootstrap, A, B) - B rejoined

# Verify ephemeral network handles expiry
omerta vm-network create --vm-id test
# Join from all nodes
# Kill consumer
# Verify provider sees: "Consumer expired from network"
# Restart consumer, rejoin
# Verify: "Consumer rejoined network"
```

---

### Phase 11: WireGuard and Legacy VPN Cleanup

**Goal:** Remove all WireGuard-related code and unnecessary VPN infrastructure.
The mesh with netstack replaces WireGuard for VM networking.

#### Files to Delete

| File | Reason |
|------|--------|
| `Sources/OmertaVPN/LinuxWireGuardManager.swift` | WireGuard no longer used |
| `Sources/OmertaVPN/LinuxWireGuardNetlink.swift` | WireGuard no longer used |
| `Sources/OmertaVPN/LinuxNetlink.swift` | WireGuard no longer used |
| `Sources/OmertaVPN/MacOSWireGuard.swift` | WireGuard no longer used |
| `Sources/OmertaVPN/MacOSRouting.swift` | WireGuard routing no longer used |
| `Sources/OmertaVPN/MacOSUtun.swift` | WireGuard utun no longer used |
| `Sources/OmertaVPN/MacOSPacketFilter.swift` | WireGuard filtering no longer used |
| `Sources/OmertaVPN/VPNManager.swift` | Replaced by TunnelManager |
| `Sources/OmertaVPN/VPNTunnelService.swift` | Replaced by mesh tunnels |
| `Sources/OmertaVPN/EphemeralVPN.swift` | Replaced by OmertaTunnel |
| `Sources/OmertaVPN/NetworkExtensionVPN.swift` | Not needed with netstack |
| `Sources/OmertaVPN/VPNProvider.swift` | Replaced by TunnelManager |
| `Sources/OmertaVPN/EthernetFrame.swift` | Packet handling moved to netstack |
| `Sources/OmertaVPN/IPv4Packet.swift` | Packet handling moved to netstack |
| `Sources/OmertaVPN/EndpointAllowlist.swift` | No longer needed |
| `Sources/OmertaVPN/FramePacketBridge.swift` | Replaced by netstack bridge |
| `Sources/OmertaVPN/FilteredNAT.swift` | Replaced by netstack |
| `Sources/OmertaVPN/FilteringStrategy.swift` | Replaced by netstack |
| `Sources/OmertaVPN/VMNetworkManager.swift` | Replaced by VMPacketCapture |
| `Sources/OmertaVPN/UDPForwarder.swift` | Replaced by netstack |
| `Sources/OmertaProvider/ProviderVPNManager.swift` | Replaced by TunnelManager |
| `Sources/OmertaProvider/VPNHealthMonitor.swift` | Replaced by TunnelHealthMonitor |
| `Sources/OmertaVPNExtension/` (entire directory) | Network extension not needed |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaDaemon/OmertaDaemon.swift` | Remove WireGuard references |
| `Sources/OmertaCLI/main.swift` | Remove VPN commands, add tunnel commands |
| `Sources/OmertaConsumer/MeshConsumerClient.swift` | Remove WireGuard setup |
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Remove VPN manager |
| `Sources/OmertaVM/VMManager.swift` | Remove WireGuard config |
| `Sources/OmertaVM/CloudInitGenerator.swift` | Remove WireGuard setup |
| `Sources/OmertaCore/Domain/Resource.swift` | Remove VPN resource types |
| `Sources/OmertaCore/System/DependencyChecker.swift` | Remove wg-quick check |
| `Package.swift` | Remove OmertaVPN, OmertaVPNExtension targets |

#### Tests to Delete

| Test File | Reason |
|-----------|--------|
| `Tests/OmertaVPNTests/` (entire directory) | All VPN tests replaced by tunnel/netstack tests |

Specifically, the following test files will be deleted:
- `VPNManagerTests.swift` - VPN removed
- `NativeWireGuardTests.swift` - WireGuard removed
- `EphemeralVPNTests.swift` - Replaced by tunnel tests
- `CrossPlatformTests.swift` - VPN removed
- `EndpointAllowlistTests.swift` - No longer needed
- `EthernetFrameTests.swift` - Packet handling moved to netstack
- `FilteredNATTests.swift` - Replaced by netstack
- `FilteringStrategyTests.swift` - Replaced by netstack
- `FramePacketBridgeTests.swift` - Replaced by netstack bridge
- `IPv4PacketTests.swift` - Packet handling moved to netstack
- `PacketFilterTests.swift` - WireGuard filtering removed
- `UDPForwarderTests.swift` - Replaced by netstack
- `VMNetworkManagerTests.swift` - Replaced by VMPacketCapture tests

Also delete:
| `Tests/OmertaProviderTests/VPNHealthMonitorTests.swift` | Replaced by TunnelHealthMonitor tests |

#### Tests to Modify

| Test File | Changes |
|-----------|---------|
| `Tests/OmertaMeshTests/Phase7Tests.swift` | Remove WireGuard references |
| `Tests/OmertaConsumerTests/ConsumerEventLoggerTests.swift` | Update events |
| `Tests/OmertaProviderTests/ProviderEventLoggerTests.swift` | Update events |
| `Tests/OmertaVMTests/QEMUNetworkTests.swift` | Use mesh instead of WG |
| `Tests/OmertaVMTests/CloudInitTests.swift` | Remove WireGuard config |
| `Tests/OmertaVMTests/StandaloneVMTests.swift` | Use mesh tunnels |

#### API Changes

```swift
// Remove these types entirely:
// - VPNManager
// - VPNTunnelService
// - EphemeralVPN
// - ProviderVPNManager
// - VPNHealthMonitor

// These are replaced by (from earlier phases):
// - TunnelManager (OmertaTunnel)
// - TunnelSession (OmertaTunnel)
// - TunnelHealthMonitor (OmertaMesh)
// - ConsumerNetstackBridge (OmertaConsumer)
// - VMPacketCapture (OmertaMesh)
```

#### Sudo/Root Check Removals

The netstack approach runs entirely in userspace — no root required on consumer.
Remove all sudo-related code that was needed for WireGuard.

| File | Line | Code to Remove |
|------|------|----------------|
| `Sources/OmertaCore/System/ProcessRunner.swift` | 16 | `isRoot` property and `getuid() == 0` check |
| `Sources/OmertaCLI/main.swift` | 3344 | `getuid() == 0` check and sudo hints |
| `Sources/OmertaVPN/EphemeralVPN.swift` | 764 | `getuid() != 0` root requirement check |
| `Sources/OmertaDaemon/OmertaDaemon.swift` | - | "run with sudo" messages |
| `Sources/OmertaCore/System/DependencyChecker.swift` | 63-95 | `wireguard` and `wireguardQuick` dependencies |

**Note:** Keep SUDO_USER handling in home directory resolution (OmertaConfig,
stores) — this is still useful when the daemon runs as root but stores config
in user's home.

#### Cleanup Checklist

- [ ] Remove all `import WireGuard` statements
- [ ] Remove all `wg-quick` process spawning
- [ ] Remove WireGuard key generation code
- [ ] Remove WireGuard config file generation
- [ ] Remove Network Extension entitlements (if no longer needed)
- [ ] Update documentation to remove WireGuard references
- [ ] Remove `wireguard-go` submodule if present
- [ ] Update CI/CD to not build WireGuard dependencies
- [ ] Remove `ProcessRunner.isRoot` and sudo prepending logic
- [ ] Remove `checkSudoAccess()` from CLI
- [ ] Remove "requires sudo" error messages
- [ ] Remove "run with sudo" instructions from help text

#### Manual Testing

```bash
# Verify WireGuard completely removed
grep -r "wireguard\|WireGuard\|wg-quick" Sources/
# Should return NO matches (except documentation)

# Verify sudo checks removed
grep -r "isRoot\|checkSudoAccess\|requires sudo\|run.*sudo" Sources/
# Should return NO matches (except SUDO_USER home dir handling)

# Verify build succeeds without WireGuard
swift build

# Verify tests pass
swift test

# Verify VM networking works with mesh (not WireGuard)
omerta vm create --name test --image ubuntu-22.04
omerta vm start test
# In VM: curl https://example.com should work via mesh

# Verify no WireGuard processes
ps aux | grep wireguard
# Should show NO wireguard processes
```

---

## Part 1: Architecture

### 1.1 Ephemeral Network Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────┐
│ VM PROVISIONING                                                         │
│                                                                         │
│ 1. Consumer requests VM from provider                                   │
│ 2. Provider creates ephemeral mesh network (unique network ID)          │
│ 3. Provider joins network, starts VM with mesh agent                    │
│ 4. Consumer joins network                                               │
│ 5. Endpoint negotiation happens (direct → hole punch → relay)           │
│ 6. Tunnel established, VM can send traffic                              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ VM TERMINATION                                                          │
│                                                                         │
│ 1. VM shuts down                                                        │
│ 2. Provider stops responding to pings for this network                  │
│ 3. Consumer stops responding to pings for this network                  │
│ 4. After backoff period, peers drop each other from peer lists          │
│ 5. Network "ceases to exist" when no peers track it                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.4 Peer Expiry (No Explicit Leave)

Peers are removed from the network via backoff, not explicit "leave" operations:

```
Peer stops responding
        │
        ▼
After 3 missed pings → marked "stale"
        │
        ▼
Stale peers have reduced TTL in gossip (not propagated as actively)
        │
        ▼
After 5 more missed pings → removed from local peer list
        │
        ▼
Network "gone" when all peers have dropped each other
```

This respects user choice to disconnect without requiring coordination.

### 1.2 Network Topology

```
┌──────────────┐                              ┌──────────────┐
│     VM       │                              │   Consumer   │
│              │                              │              │
│  Mesh Agent  │◄────── Ephemeral Network ───►│  Mesh Node   │
│              │         (encrypted)          │      │       │
└──────────────┘                              │      ▼       │
       │                                      │  Forwarder   │
       │ runs on                              │      │       │
       ▼                                      │      ▼       │
┌──────────────┐                              │ Local Network│
│   Provider   │                              └──────────────┘
│  Mesh Node   │
└──────────────┘
```

### 1.3 Traffic Flow

**VM → Internet (outbound):**
```
VM App → Mesh Agent → [ephemeral network] → Consumer → Local Network → Internet
```

**Internet → VM (inbound/response):**
```
Internet → Consumer → [ephemeral network] → Mesh Agent → VM App
```

---

## Part 2: API Design

### 2.1 Core Types

**`Endpoint`** struct - Basic endpoint value type (shared across codebase):
```swift
public struct Endpoint: Codable, Sendable, Equatable, CustomStringConvertible {
    public let hostPort: String

    public var description: String { hostPort }
    public var host: String { /* parse */ }
    public var port: UInt16 { /* parse */ }
    public var isIPv6: Bool { /* check brackets */ }

    public init?(_ string: String) { /* validate */ }
}
```

**`TunnelEndpoint`** struct - Result of endpoint negotiation:
```swift
public struct TunnelEndpoint: Codable, Sendable, Equatable {
    public let endpoint: Endpoint
    public let tunnelId: UUID
    public let isRelayed: Bool
    public let relayPeerId: PeerId?  // Set if isRelayed == true
    public let ttlSeconds: Int
    public let negotiatedAt: Date

    public var isExpired: Bool { ... }
}
```

### 2.2 Delegate Protocol

The tunnel never "fails" — it keeps reconnecting until the user explicitly disconnects.

```swift
/// Connection state for user awareness
public enum TunnelConnectionState: Sendable {
    case connected           // Direct or relayed, traffic flowing
    case reconnecting        // Lost connection, attempting recovery
    case degraded(reason: String)  // Connected but with issues (high latency, packet loss)
}

public protocol TunnelEndpointDelegate: AnyObject, Sendable {
    /// Connection state changed — for user awareness
    func tunnelConnectionStateDidChange(
        tunnelId: UUID,
        state: TunnelConnectionState
    ) async

    /// Our endpoint changed after re-negotiation
    func tunnelEndpointDidChange(
        tunnelId: UUID,
        oldEndpoint: TunnelEndpoint,
        newEndpoint: TunnelEndpoint
    ) async

    /// Peer notified us their endpoint changed
    func tunnelPeerEndpointDidChange(
        tunnelId: UUID,
        newPeerEndpoint: Endpoint
    ) async

    /// Switched to/from relayed mode
    func tunnelRelayStatusDidChange(
        tunnelId: UUID,
        isRelayed: Bool,
        relayPeerId: PeerId?
    ) async
}
```

**Never give up:** The tunnel keeps trying indefinitely with exponential backoff:
1. Try direct connection
2. Try hole punch
3. Fall back to relay
4. If relay fails, try different relay
5. Repeat with backoff until user disconnects

### 2.3 TunnelManager Public API

```swift
public actor TunnelManager {

    // MARK: - Endpoint Negotiation

    func negotiateEndpoint(
        localPort: UInt16,
        remotePeer: PeerId,
        timeout: Duration = .seconds(30)
    ) async throws -> TunnelEndpoint

    func releaseEndpoint(_ tunnelId: UUID) async

    // MARK: - Subscriptions

    func subscribe(tunnelId: UUID, delegate: TunnelEndpointDelegate) -> UUID
    func cancelSubscription(_ subscriptionId: UUID)

    // MARK: - Relayed Mode

    func startRelayedMode(
        tunnelId: UUID,
        remotePeer: PeerId,
        localPort: UInt16
    ) async throws -> UInt16

    func stopRelayedMode(tunnelId: UUID) async
}
```

### 2.4 Tunnel API (OmertaTunnel)

```swift
/// High-level tunnel management (uses Cloister internally)
public actor TunnelManager {
    init(meshNode: MeshNode)

    /// Create a new tunnel by negotiating with a peer
    func createTunnel(
        with peer: PeerId,
        metadata: [String: String] = [:]
    ) async throws -> TunnelSession

    /// Share an existing tunnel with a peer
    func shareTunnel(_ session: TunnelSession, with peer: PeerId) async throws

    /// Accept an incoming tunnel invitation
    func acceptTunnel(_ tunnelId: TunnelId) async throws -> TunnelSession

    /// Active tunnel sessions
    func activeTunnels() -> [TunnelSession]
}

public actor TunnelSession {
    let tunnelId: TunnelId
    let networkKey: Data
    let metadata: [String: String]
    var peers: [PeerId] { get }

    func send(_ data: Data, to peer: PeerId) async throws
    func leave() async
}
```

---

## Part 3: User-Mode Networking

The provider captures all VM traffic and forwards it through the mesh. The
consumer processes packets with netstack and makes real connections to
destinations.

### 3.1 Provider Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PROVIDER HOST                                 │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ VM Network Namespace (vm-{id})                                    │  │
│  │                                                                   │  │
│  │  ┌─────────┐                                                      │  │
│  │  │   VM    │  sees: eth0 with 10.200.{id}.2/24                    │  │
│  │  │         │  gateway: 10.200.{id}.1                              │  │
│  │  │         │  DNS: 10.200.{id}.1 (forwarded to consumer)          │  │
│  │  └────┬────┘                                                      │  │
│  │       │ veth-vm-{id}                                              │  │
│  └───────┼───────────────────────────────────────────────────────────┘  │
│          │                                                              │
│          │ veth pair                                                    │
│          │                                                              │
│  ┌───────┴───────────────────────────────────────────────────────────┐  │
│  │  veth-host-{id} (10.200.{id}.1/24)                                │  │
│  │       │                                                           │  │
│  │       ▼                                                           │  │
│  │  ┌───────────────────┐                                            │  │
│  │  │ Remote Bridge     │ ─────► Mesh ─────► Consumer                │  │
│  │  │ (packet capture + │                                            │  │
│  │  │  tunnel to mesh)  │                                            │  │
│  │  └───────────────────┘                                            │  │
│  │                                                                   │  │
│  │  Firewall: DROP all non-mesh traffic from 10.200.0.0/16           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

**VM sees normal networking:**
- IP address: 10.200.{id}.2
- Gateway: 10.200.{id}.1 (provider's veth endpoint)
- DNS: 10.200.{id}.1 (intercepted and forwarded to consumer)
- Apps work normally — no proxy configuration needed

### 3.2 Provider-Side Setup

**Linux (network namespace + veth):**

```bash
# Create isolated namespace for VM
ip netns add vm-${VM_ID}

# Create veth pair (virtual ethernet cable)
ip link add veth-vm-${VM_ID} type veth peer name veth-host-${VM_ID}

# Move one end into VM namespace
ip link set veth-vm-${VM_ID} netns vm-${VM_ID}

# Configure VM side
ip netns exec vm-${VM_ID} ip addr add 10.200.${VM_NUM}.2/24 dev veth-vm-${VM_ID}
ip netns exec vm-${VM_ID} ip link set veth-vm-${VM_ID} up
ip netns exec vm-${VM_ID} ip link set lo up
ip netns exec vm-${VM_ID} ip route add default via 10.200.${VM_NUM}.1

# Configure host side
ip addr add 10.200.${VM_NUM}.1/24 dev veth-host-${VM_ID}
ip link set veth-host-${VM_ID} up

# Isolation is inherent: VM namespace has no routes to host LAN or internet
# VMPacketCapture captures packets on veth-host in userspace
```

**macOS (Virtualization.framework):**

```swift
// VM's network is entirely provided by file handles we control
let (vmRead, hostWrite) = Pipe().fileHandles
let (hostRead, vmWrite) = Pipe().fileHandles

let networkAttachment = VZFileHandleNetworkDeviceAttachment(
    fileHandleForReading: vmRead,
    fileHandleForWriting: vmWrite
)

// VMPacketCapture reads from hostRead, writes to hostWrite
// VM has no other network path — isolation is inherent
```

### 3.3 Packet Flow

**Outbound (VM → Internet):**

```
1. VM sends packet to 8.8.8.8:443
   src: 10.200.1.2:54321, dst: 8.8.8.8:443

2. Kernel routes to gateway (10.200.1.1)

3. Provider's VMPacketCapture captures packet on veth-host

4. VMPacketCapture encrypts and sends via mesh:
   ForwardPacket { vmId, packet: [IP header + payload] }

5. Consumer receives and decrypts ForwardPacket

6. Consumer feeds packet to netstack

7. Netstack processes TCP/UDP, opens real connection to 8.8.8.8:443

8. Traffic flows to internet from consumer's network
```

**Inbound (Internet → VM):**

```
1. Response arrives at consumer's real socket

2. Netstack generates response packet for VM

3. Consumer encrypts and sends via mesh:
   ReturnPacket { vmId, packet }

4. Provider decrypts, injects into veth-host

5. Packet arrives at VM's eth0
```

### 3.4 Edge Cases

**1. DHCP**
- *Problem*: VM might try to DHCP for IP address
- *Solution*: Provider's bridge responds to DHCP requests with static IP

```swift
// Provider intercepts DHCP on veth, responds with:
// - IP: 10.200.{id}.2
// - Gateway: 10.200.{id}.1
// - DNS: 10.200.{id}.1
```

**2. DNS Resolution**
- *Problem*: VM sends DNS to its configured resolver (10.200.{id}.1)
- *Solution*: Provider intercepts DNS queries, forwards to consumer

```swift
// On provider, intercept UDP port 53
if packet.destPort == 53 {
    // Forward via mesh to consumer, consumer resolves, returns answer
}
```

**3. ARP**
- *Problem*: VM ARPs for gateway MAC
- *Solution*: Host responds to ARP for 10.200.{id}.1 (automatic with veth setup)

**4. MTU**
- *Problem*: Mesh has overhead, effective MTU is smaller
- *Solution*: Set VM's interface MTU lower, or use TCP MSS clamping

```bash
ip netns exec vm-${VM_ID} ip link set veth-vm-${VM_ID} mtu 1400
```

**5. Connection Tracking**
- *Problem*: Consumer needs to track connections
- *Solution*: Netstack handles connection state automatically

**6. Consumer Offline**
- *Problem*: What happens if consumer disconnects?
- *Solution*: VM traffic fails (connection refused/timeout) — expected behavior

### 3.5 Strict Isolation Guarantees

> **Existing code:** See `VMManager.swift` for Linux/macOS VM isolation
> setup and `VMNetworkManager.swift` for macOS VZFileHandleNetworkDeviceAttachment
> handling. The new VMPacketCapture builds on this existing isolation infrastructure.

The VM CANNOT:
- Access provider's host network (isolated namespace)
- Access provider's LAN (firewall blocks forwarding)
- Access internet directly (no route except through veth)
- Communicate with other VMs (each has own namespace + IP range)

The VM CAN ONLY:
- Send packets to its gateway (10.200.{id}.1)
- Receive packets from its gateway
- All traffic goes through VMPacketCapture → Mesh → Consumer

---

## Part 3b: Packet Forwarding with gVisor Netstack

### 3b.1 Why Netstack?

Instead of manually parsing packets and managing TCP state, we use **gVisor's
netstack** — the same userspace TCP/IP stack used by:

> **Note:** Netstack handles TCP/IP processing in userspace. It does NOT handle
> UPnP or NAT-PMP port forwarding — those would be separate features if needed
> for inbound connections to the consumer.
- **Tailscale** — for userspace networking mode and exit nodes
- **wireguard-go** — for processing decrypted tunnel packets
- **gVisor** — for container sandboxing

Netstack handles:
- TCP state machine (SYN, ACK, FIN, retransmission, congestion control)
- UDP datagram handling
- ICMP
- Checksums, reassembly, etc.

We just feed it packets and respond to connection events.

### 3b.2 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CONSUMER                                      │
│                                                                         │
│   Mesh receives ForwardPacket                                           │
│         │                                                               │
│         ▼                                                               │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │  Netstack (gVisor)                                              │   │
│   │                                                                 │   │
│   │  InjectInbound(packet) ──► TCP/UDP processing ──► Connection    │   │
│   │                                                    events       │   │
│   │                                                       │         │   │
│   │  OutboundPackets() ◄─────────────────────────────────-┘         │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│         │                              │                                │
│         ▼                              ▼                                │
│   Response packets              Real connections                        │
│   (back to VM)                  (to internet)                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3b.3 Message Types

```swift
/// IP packet from VM to forward through consumer
public struct ForwardPacket: Codable, Sendable {
    public let vmId: UUID
    public let packet: Data  // Raw IP packet (IPv4 or IPv6)
}

/// IP packet returning to VM
public struct ReturnPacket: Codable, Sendable {
    public let vmId: UUID
    public let packet: Data
}
```

### 3b.4 Provider's Remote Bridge

Provider captures ALL packets from VM — doesn't filter or interpret them.

> **ACK mechanism:** The mesh layer handles retry and duplicate packet detection.
> However, the bridge needs its own ACK mechanism for flow control — to avoid
> overwhelming the consumer or filling memory with queued packets. This is
> similar to libslirp's `notify` callback for backpressure.

```swift
public actor VMPacketCapture {
    let vmId: UUID
    let packetSource: PacketSource  // veth on Linux, file handle on macOS
    let meshNetwork: MeshNetwork
    let consumerPeerId: PeerId

    /// Capture all packets from VM and forward to consumer
    func start() async throws {
        for await packet in packetSource.inbound {
            let forward = ForwardPacket(vmId: vmId, packet: packet)
            try? await meshNetwork.send(forward, to: consumerPeerId)
        }
    }

    /// Receive packets from consumer, inject to VM
    func handleReturnPacket(_ ret: ReturnPacket) async {
        try? await packetSource.write(ret.packet)
    }
}
```

### 3b.5 Consumer's Netstack Integration (Go)

The consumer's packet handler is written in Go to use netstack directly.

```go
// consumer_netstack.go

package consumer

import (
    "gvisor.dev/gvisor/pkg/tcpip"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
    "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
    "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
    "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
    "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
    "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

type ConsumerNetstack struct {
    stack       *stack.Stack
    linkEP      *channelEndpoint  // Custom endpoint for mesh packets
    sendToMesh  func(vmId string, packet []byte)
}

// Initialize netstack
func NewConsumerNetstack(sendToMesh func(string, []byte)) *ConsumerNetstack {
    s := stack.New(stack.Options{
        NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
        TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
    })

    linkEP := newChannelEndpoint()
    s.CreateNIC(1, linkEP)

    // Set up TCP/UDP forwarding
    tcpForwarder := tcp.NewForwarder(s, 0, 65535, handleTCPConnection)
    s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

    udpForwarder := udp.NewForwarder(s, handleUDPPacket)
    s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

    return &ConsumerNetstack{stack: s, linkEP: linkEP, sendToMesh: sendToMesh}
}

// Inject packet from VM (received via mesh)
func (c *ConsumerNetstack) InjectPacket(vmId string, packet []byte) {
    pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
        Payload: buffer.MakeWithData(packet),
    })
    c.linkEP.InjectInbound(ipv4.ProtocolNumber, pkb)
}

// Handle outbound packets (responses to VM)
func (c *ConsumerNetstack) StartOutboundLoop(vmId string) {
    for {
        pkb := c.linkEP.ReadContext(context.Background())
        packet := pkb.ToView().AsSlice()
        c.sendToMesh(vmId, packet)
    }
}

// TCP connection handler - opens real connection to destination
func handleTCPConnection(r *tcp.ForwarderRequest) {
    id := r.ID()

    // Open real TCP connection to destination
    conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", id.RemoteAddress, id.RemotePort))
    if err != nil {
        r.Complete(true)  // Send RST
        return
    }

    // Create endpoint for netstack side
    var wq waiter.Queue
    ep, tcpErr := r.CreateEndpoint(&wq)
    if tcpErr != nil {
        conn.Close()
        return
    }

    // Bidirectional relay
    go relay(ep, conn)
}

// UDP packet handler
func handleUDPPacket(r *udp.ForwarderRequest) {
    // Similar pattern: receive from netstack, send via real socket
}
```

### 3b.6 Go/Swift Integration

The Go netstack component is compiled as a C archive and linked with Swift.

**Build process:**

```bash
# Build Go code as C archive
cd Sources/OmertaConsumer/Netstack
go build -buildmode=c-archive -o libnetstack.a ./...

# This produces:
# - libnetstack.a (static library)
# - libnetstack.h (C header)
```

**Swift integration via module map:**

```swift
// Package.swift
targets: [
    .systemLibrary(
        name: "CNetstack",
        path: "Sources/CNetstack",
        pkgConfig: nil,
        providers: []
    ),
    .target(
        name: "OmertaConsumer",
        dependencies: ["CNetstack", "OmertaMesh"],
        linkerSettings: [
            .linkedLibrary("netstack"),
            .unsafeFlags(["-LSources/OmertaConsumer/Netstack"])
        ]
    )
]
```

**C header (exported from Go):**

```c
// libnetstack.h (generated by Go)

typedef struct {
    void* handle;
} NetstackHandle;

// Initialize netstack with callback for sending packets to mesh
NetstackHandle* netstack_init(void (*send_callback)(const char* vmId, const uint8_t* packet, size_t len));

// Inject packet from VM
void netstack_inject(NetstackHandle* h, const char* vmId, const uint8_t* packet, size_t len);

// Shutdown
void netstack_shutdown(NetstackHandle* h);
```

**Swift wrapper:**

```swift
import CNetstack

public actor ConsumerNetstackBridge {
    private var handle: OpaquePointer?
    private let meshNetwork: MeshNetwork

    public init(meshNetwork: MeshNetwork) {
        self.meshNetwork = meshNetwork

        // Initialize Go netstack with callback
        handle = netstack_init { vmId, packet, len in
            // Called from Go when netstack has a packet to send to VM
            let data = Data(bytes: packet!, count: Int(len))
            let vmIdStr = String(cString: vmId!)
            Task {
                await self.sendToMesh(vmId: vmIdStr, packet: data)
            }
        }
    }

    /// Handle packet from VM (received via mesh)
    public func handleForwardPacket(_ fwd: ForwardPacket) {
        fwd.packet.withUnsafeBytes { ptr in
            netstack_inject(handle, fwd.vmId.uuidString, ptr.baseAddress, fwd.packet.count)
        }
    }

    private func sendToMesh(vmId: String, packet: Data) async {
        let ret = ReturnPacket(vmId: UUID(uuidString: vmId)!, packet: packet)
        try? await meshNetwork.send(ret, to: providerPeerId)
    }
}
```

### 3b.7 Protocol Support

| Protocol        | Supported | How                                   |
|-----------------|-----------|---------------------------------------|
| TCP             | ✓         | Netstack TCP + real socket forwarding |
| UDP             | ✓         | Netstack UDP + real socket forwarding |
| ICMP            | ✓         | Netstack ICMP                         |
| GRE, SCTP, etc. | ✓         | Netstack handles at IP level          |

**All IP protocols are supported** because netstack processes at the IP layer.
No root required.

### 3b.8 Why This Approach?

| Aspect             | Custom packet handling | Netstack                   |
|--------------------|------------------------|----------------------------|
| TCP state machine  | Must implement         | Provided                   |
| Packet parsing     | Must implement         | Provided                   |
| Retransmission     | Must implement         | Provided                   |
| Congestion control | Must implement         | Provided                   |
| Proven in prod     | No                     | Yes (Tailscale, WireGuard) |
| Protocol coverage  | TCP/UDP/ICMP only      | All IP protocols           |

**Trade-off:** Go dependency for the consumer. But the complexity savings are
significant — we get a battle-tested TCP/IP stack instead of writing our own.

### 3b.9 Performance Considerations

**Throughput:**
- Tailscale reports netstack handles their traffic well
- gVisor benchmarks: ~17 Gbps download, ~8 Gbps upload

**MTU:**
- Set VM's interface MTU to 1400 to account for mesh overhead
- Or use TCP MSS clamping

**Latency:**
- Userspace processing adds ~1-2ms per hop
- Total: ~3-5ms added latency (VM → Provider → Mesh → Consumer → Internet)

---

## Part 4: Endpoint Negotiation and Migration

### 4.1 Failure Detection

Tunnel endpoint failure is detected through two mechanisms:

| Method                          | Latency     | When It Triggers             |
|---------------------------------|-------------|------------------------------|
| OS network change events        | ~0ms        | Local IP/interface changes   |
| Traffic-triggered probe timeout | 500ms + RTT | No incoming packet for 500ms |

**1. OS Network Change Events**

```swift
// Darwin/iOS
let monitor = NWPathMonitor()
monitor.pathUpdateHandler = { path in
    if path.status != .satisfied || addressChanged(path) {
        triggerRenegotiation(reason: .networkChange)
    }
}

// Linux: Monitor netlink socket for RTM_NEWADDR/RTM_DELADDR
```

**2. Traffic-Triggered Probing with Backoff**

```swift
actor TunnelHealthMonitor {
    var lastPacketTime: ContinuousClock.Instant = .now
    var currentProbeInterval: Duration = .milliseconds(500)

    let minProbeInterval: Duration = .milliseconds(500)
    let maxProbeInterval: Duration = .seconds(15)

    func onPacketReceived() {
        lastPacketTime = .now
        currentProbeInterval = minProbeInterval  // Reset backoff
    }

    func startMonitoring(tunnel: ManagedTunnel) {
        Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: currentProbeInterval)

                if (ContinuousClock.now - lastPacketTime) >= currentProbeInterval {
                    do {
                        try await sendProbe(tunnel)
                        // Probe succeeded, backoff
                        currentProbeInterval = min(currentProbeInterval * 2, maxProbeInterval)
                    } catch {
                        triggerRenegotiation(tunnel, reason: .probeTimeout)
                        return
                    }
                }
            }
        }
    }
}
```

### 4.2 Migration Flow

> **Implementation note:** Re-negotiation reuses the exact same code path as
> initial negotiation. There is no separate "migration" logic — just call
> `negotiateEndpoint()` again. This simplifies testing and ensures consistent
> behavior.

When either side's endpoint stops working:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. DETECTION (either side can detect)                                   │
│                                                                         │
│    Provider detects:                    Consumer detects:               │
│    - OS network change event            - Traffic stops from VM         │
│    - Traffic stops from consumer        - Probe timeout                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. RE-NEGOTIATION                                                       │
│    Detecting side runs tunnel negotiation:                              │
│    - Try direct (same LAN / public IP check)                            │
│    - Try hole punch                                                     │
│    - Fall back to relay                                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. NOTIFY PEER                                                          │
│    Send TunnelEndpointUpdate via mesh relay:                            │
│    - tunnelId                                                           │
│    - newEndpoint                                                        │
│    - reason ("migration", "failover")                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. PEER ATTEMPTS CONNECTION                                             │
│    Peer tries to connect to new endpoint.                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
┌───────────────────────────────┐   ┌───────────────────────────────────┐
│ 5a. CONNECTION SUCCEEDS       │   │ 5b. CONNECTION FAILS              │
│                               │   │                                   │
│ Traffic resumes normally.     │   │ Must relay all traffic through    │
│                               │   │ bootstrap node.                   │
└───────────────────────────────┘   └───────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 6. RESUME FORWARDING                                                    │
│    Active connections continue — they're just mesh messages.            │
│    No connection re-establishment needed at the application layer.      │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Dual-Side Monitoring

Both consumer and provider monitor the tunnel independently:

| Who detects | Action                                                   |
|-------------|----------------------------------------------------------|
| Provider    | Re-negotiate endpoint, send `TunnelEndpointUpdate` to consumer |
| Consumer    | Re-negotiate endpoint, send `TunnelEndpointUpdate` to provider |

Both run `TunnelHealthMonitor`. Either can initiate recovery.

---

## Part 5: Configuration

### 5.1 MeshConfig Additions

```swift
// MARK: - Relay Configuration (for bootstrap/public nodes)
public var canRelayTunnel: Bool = false
public var tunnelPortRange: ClosedRange<UInt16> = 54000...54999
public var maxTunnels: Int = 50
public var tunnelIdleTimeout: TimeInterval = 300

// MARK: - Health Monitoring
public var tunnelMinProbeIntervalMs: Int = 500
public var tunnelMaxProbeIntervalMs: Int = 15_000
public var tunnelProbeTimeoutMultiplier: Double = 5.0

// MARK: - Traffic Forwarding
public var maxConnectionsPerVM: Int = 100
public var forwardConnectTimeout: TimeInterval = 30
public var forwardIdleTimeout: TimeInterval = 300
```

---

## Part 6: Files to Create

### OmertaTunnel (New Package)

OmertaTunnel provides both peer-to-peer tunnels AND internet traffic routing.
Consumers of the utility don't need to know about netstack internals.

| File                                        | Lines | Description                        |
|---------------------------------------------|-------|------------------------------------|
| `Sources/OmertaTunnel/TunnelManager.swift`  | ~300  | High-level tunnel API (uses Cloister) |
| `Sources/OmertaTunnel/TunnelSession.swift`  | ~200  | Per-tunnel state, messaging, and traffic routing |
| `Sources/OmertaTunnel/TunnelConfig.swift`   | ~50   | Tunnel configuration               |
| `Sources/OmertaTunnel/RelayCoordinator.swift` | ~200 | Relay selection for tunnels        |
| `Sources/OmertaTunnel/TrafficRouter.swift`  | ~200  | Internal traffic routing coordinator |
| `Sources/OmertaTunnel/NetstackBridge.swift` | ~150  | Swift wrapper for Go netstack      |
| `Sources/OmertaTunnel/TrafficMessages.swift`| ~50   | Internal ForwardPacket/ReturnPacket |

### OmertaTunnel Go Files (Netstack)

*All paths relative to `Sources/OmertaTunnel/Netstack/`*

| File                  | Lines | Description                          |
|-----------------------|-------|--------------------------------------|
| `tunnel_netstack.go`  | ~300  | Netstack integration, TCP/UDP fwd    |
| `link_endpoint.go`    | ~100  | Custom endpoint for mesh injection   |
| `tcp_forwarder.go`    | ~150  | TCP connection forwarding            |
| `udp_forwarder.go`    | ~100  | UDP forwarding to real sockets       |
| `exports.go`          | ~80   | C-exported functions for Swift       |

### OmertaMesh Additions

| File                                        | Lines | Description                        |
|---------------------------------------------|-------|------------------------------------|
| `Tunnel/TunnelHealthMonitor.swift`          | ~150  | Traffic-triggered probing          |
| `Peers/PeerExpiryManager.swift`             | ~100  | Peer stale/expiry tracking         |
| `Gossip/GossipDataProvider.swift`           | ~80   | Unified gossip interface           |

*Paths relative to `Sources/OmertaMesh/`*

### OmertaProvider Additions

| File                                        | Lines | Description                        |
|---------------------------------------------|-------|------------------------------------|
| `OmertaProvider/VMPacketCapture.swift`      | ~150  | Captures VM packets, uses TunnelSession |
| `OmertaProvider/VMNetworkNamespace.swift`   | ~150  | Linux: network namespace setup     |
| `OmertaProvider/VMNetworkFileHandle.swift`  | ~100  | macOS: VZFileHandle integration    |

*Paths relative to `Sources/`*

### Build Integration

| File                                  | Description                              |
|---------------------------------------|------------------------------------------|
| `Sources/CNetstack/module.modulemap`  | Module map for Swift to import C headers |
| `Sources/OmertaTunnel/Netstack/Makefile` | Build Go code as C archive            |
| `Package.swift`                       | Add CNetstack system library + linker    |

## Part 7: Files to Modify

| File                                      | Changes                              |
|-------------------------------------------|--------------------------------------|
| `OmertaMesh/Types/MeshMessage.swift`      | Add relay capacity to PeerAnnouncement |
| `OmertaMesh/Types/MeshNodeServices.swift` | Add tunnel delegate protocols        |
| `OmertaMesh/Public/MeshConfig.swift`      | Add tunnel and relay configuration   |
| `OmertaMesh/MeshNode.swift`               | Integrate GossipDataProvider         |
| `OmertaMesh/Relay/RelayManager.swift`     | Add relay selection for tunnels      |
| `OmertaMesh/Discovery/PeerStore.swift`    | Persists PeerAnnouncement (includes machine-level relay capacity) |
| `OmertaConsumer/MeshConsumerClient.swift` | Use TunnelManager (netstack handled internally by OmertaTunnel) |
| `OmertaProvider/MeshProviderDaemon.swift` | Use TunnelManager, VMPacketCapture   |
| `Package.swift`                           | Add OmertaTunnel target with CNetstack dependency |

*All paths relative to `Sources/`*

---

## Part 8: Testing Strategy

Testing is split into three phases, each validating a layer of the stack before
adding the next. This isolates failures and makes debugging easier.

### 8.1 Phase 1: Netstack Standalone

**Goal:** Verify netstack correctly processes packets and makes real connections.

**Setup:**
```
┌─────────────────────────────────────────────────────────────┐
│  Test harness (no mesh, no VM)                              │
│                                                             │
│  [Raw IP packets] ──► Netstack ──► [Real sockets]           │
│                           │                                 │
│                           ▼                                 │
│                      Internet                               │
└─────────────────────────────────────────────────────────────┘
```

**Tests:**

| Test              | Description                      | Success Criteria              |
|-------------------|----------------------------------|-------------------------------|
| TCP connect       | Inject SYN for 1.1.1.1:80        | TCP opens, HTTP response      |
| TCP data transfer | Inject HTTP GET packets          | Correct seq/ack in response   |
| UDP echo          | Inject UDP to echo server        | Response packet generated     |
| DNS resolution    | Inject DNS query packet          | Response with resolved IP     |
| ICMP ping         | Inject ICMP echo request         | Echo reply generated          |
| Connection track  | 100 concurrent TCP connections   | All tracked, no leaks         |
| Invalid packets   | Inject malformed packets         | Graceful handling, no crash   |
| Throughput        | Inject at max rate               | Measure pps, bytes/sec        |

**Test harness (Go):**

```go
func TestNetstackTCPConnect(t *testing.T) {
    ns := NewConsumerNetstack(func(vmId string, packet []byte) {
        // Capture response packets
        responses <- packet
    })

    // Craft a TCP SYN packet to 1.1.1.1:80
    syn := craftTCPPacket(
        src: "10.200.1.2:54321",
        dst: "1.1.1.1:80",
        flags: SYN,
    )

    ns.InjectPacket("test-vm", syn)

    // Should receive SYN-ACK response
    select {
    case resp := <-responses:
        assertTCPFlags(t, resp, SYN|ACK)
    case <-time.After(5 * time.Second):
        t.Fatal("timeout waiting for SYN-ACK")
    }
}
```

**Performance baseline:**

```go
func BenchmarkNetstackThroughput(b *testing.B) {
    ns := NewConsumerNetstack(discardCallback)

    // Pre-establish TCP connection
    establishTCPConnection(ns, "10.200.1.2:54321", "10.0.0.1:9999")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        // Inject 1KB data packet
        ns.InjectPacket("test-vm", dataPacket)
    }
    // Report: packets/sec, MB/sec
}
```

### 8.2 Phase 2: Netstack + Mesh Forwarding (No VM)

**Goal:** Verify packets flow correctly through the mesh tunnel without a real VM.

**Setup:**
```
┌──────────────────────┐              ┌──────────────────────┐
│  Simulated Provider  │              │      Consumer        │
│                      │              │                      │
│  [Packet generator]  │◄── Mesh ────►│  Netstack            │
│         │            │  encrypted   │      │               │
│         ▼            │              │      ▼               │
│  ForwardPacket ──────┼──────────────┼──► InjectPacket      │
│                      │              │      │               │
│  ◄── ReturnPacket ◄──┼──────────────┼──── Response         │
└──────────────────────┘              └──────────────────────┘
```

**Tests:**

| Test | Description | Success Criteria |
|------|-------------|------------------|
| Round-trip latency | Send packet, measure time to response | Baseline latency established |
| Mesh encryption | Capture wire traffic | All packets encrypted, no plaintext |
| Packet ordering | Send 1000 numbered packets | All arrive in order |
| Packet loss recovery | Drop 10% of mesh packets | All application data delivered |
| Relay fallback | Block direct path | Traffic flows via relay |
| Reconnection | Kill mesh connection mid-transfer | Transfer resumes after reconnect |
| Throughput over mesh | Sustained transfer | Measure MB/sec through tunnel |
| Multiple streams | 10 concurrent TCP connections | All complete successfully |

**Test harness (Swift + Go):**

```swift
// Provider side: packet generator
actor PacketGenerator {
    let meshNetwork: MeshNetwork
    let consumerPeerId: PeerId

    func sendTCPStream(packetCount: Int) async throws -> Duration {
        let start = ContinuousClock.now

        for i in 0..<packetCount {
            let packet = craftDataPacket(seq: i, size: 1400)
            let fwd = ForwardPacket(vmId: testVMId, packet: packet)
            try await meshNetwork.send(fwd, to: consumerPeerId)
        }

        // Wait for all ACKs
        try await waitForACKs(count: packetCount)

        return ContinuousClock.now - start
    }
}
```

```swift
func testMeshForwardingThroughput() async throws {
    // Start consumer with netstack
    let consumer = try await startConsumerNode()

    // Start provider packet generator
    let provider = try await startProviderNode()
    try await provider.joinNetwork(consumer.networkId)

    // Measure throughput
    let duration = try await provider.sendTCPStream(packetCount: 10_000)
    let throughput = (10_000 * 1400) / duration.seconds

    print("Throughput: \(throughput / 1_000_000) MB/s")
}
```

**Latency test:**

```swift
func testRoundTripLatency() async throws {
    var latencies: [Duration] = []

    for _ in 0..<100 {
        let start = ContinuousClock.now

        // Send ICMP echo request
        let ping = craftICMPEchoRequest(id: 1, seq: 1)
        try await provider.sendPacket(ping)

        // Wait for echo reply
        let reply = try await provider.waitForICMPReply(timeout: .seconds(5))

        latencies.append(ContinuousClock.now - start)
    }

    let avg = latencies.reduce(.zero, +) / latencies.count
    let p99 = latencies.sorted()[98]

    print("Latency avg: \(avg.milliseconds)ms, p99: \(p99.milliseconds)ms")
}
```

### 8.3 Phase 3: Full Integration (VM End-to-End)

**Goal:** Verify complete flow from VM application to internet and back.

**Setup:**
```
┌─────────────────────┐            ┌─────────────────────┐
│      Provider       │            │      Consumer       │
│                     │            │                     │
│  ┌───────────────┐  │            │                     │
│  │      VM       │  │            │                     │
│  │  curl, ping   │  │◄── Mesh ──►│  Netstack           │
│  │  iperf, etc.  │  │            │      │              │
│  └───────────────┘  │            │      ▼              │
│         │           │            │  Real connections   │
│    VMPacketCapture     │            │      │              │
│                     │            │      ▼              │
│                     │            │  Internet           │
└─────────────────────┘            └─────────────────────┘
```

**Tests:**

| Test | Description | Success Criteria |
|------|-------------|------------------|
| HTTP GET | `curl https://example.com` from VM | 200 OK, page content correct |
| DNS resolution | `dig google.com` from VM | Resolves to valid IP |
| ICMP ping | `ping 1.1.1.1` from VM | Replies received |
| Large download | `curl -O` 100MB file | File intact, checksum matches |
| Upload | `curl -T` 10MB file to httpbin | Upload completes |
| SSH | SSH from VM to external server | Interactive session works |
| iperf3 | Run iperf3 client in VM | Measure actual throughput |
| Long-running | 1-hour continuous transfer | No memory leaks, stable throughput |
| Consumer reconnect | Restart consumer mid-transfer | VM connections recover |
| Provider network change | Change provider's IP | Tunnel re-establishes |

**VM test script:**

```bash
#!/bin/bash
# run-vm-tests.sh - Execute inside VM

set -e

echo "=== DNS Resolution ==="
dig +short google.com || exit 1

echo "=== ICMP Ping ==="
ping -c 5 1.1.1.1 || exit 1

echo "=== HTTP GET ==="
curl -s -o /dev/null -w "%{http_code}" https://example.com | grep 200 || exit 1

echo "=== HTTPS with TLS ==="
curl -s https://api.github.com/zen || exit 1

echo "=== Large Download ==="
curl -s -o /tmp/testfile http://speedtest.tele2.net/10MB.zip
md5sum /tmp/testfile

echo "=== Upload ==="
dd if=/dev/urandom of=/tmp/upload bs=1M count=5
curl -s -X POST -d @/tmp/upload https://httpbin.org/post | jq .data

echo "=== All tests passed ==="
```

**Automated integration test (Swift):**

```swift
func testFullVMIntegration() async throws {
    // 1. Start consumer node
    let consumer = try await ConsumerNode.start()

    // 2. Start provider and create VM
    let provider = try await ProviderNode.start()
    let vm = try await provider.createVM(
        image: "ubuntu-22.04",
        consumerPeerId: consumer.peerId
    )

    // 3. Wait for VM to boot and network to be ready
    try await vm.waitForBoot(timeout: .seconds(60))
    try await vm.waitForNetwork(timeout: .seconds(30))

    // 4. Run test suite inside VM
    let result = try await vm.exec("/root/run-vm-tests.sh")
    XCTAssertEqual(result.exitCode, 0, "VM tests failed: \(result.stderr)")

    // 5. Measure throughput with iperf3
    // Start iperf3 server on consumer's network
    let iperf = try await consumer.startIperfServer()

    let throughput = try await vm.exec(
        "iperf3 -c \(iperf.address) -t 10 -J"
    )
    let json = try JSONDecoder().decode(IperfResult.self, from: throughput.stdout)
    print("VM throughput: \(json.bitsPerSecond / 1_000_000) Mbps")

    // 6. Cleanup
    try await vm.shutdown()
    try await provider.stop()
    try await consumer.stop()
}
```

### 8.4 Performance Benchmarks

**Metrics to track:**

| Metric | Phase 1 | Phase 2 | Phase 3 | Notes |
|--------|---------|---------|---------|-------|
| Packets/sec | Netstack only | + mesh overhead | + VM overhead | Higher is better |
| Throughput (MB/s) | Baseline | Expected ~30% drop | Expected ~50% drop | Track regression |
| Latency (ms) | <1ms | +2-5ms mesh | +1-2ms VM | p50/p99 |
| Memory (MB) | Baseline | + mesh buffers | + VM overhead | Watch for leaks |
| CPU (%) | Baseline | + encryption | + packet copy | Per-core |

**Benchmark harness:**

```swift
struct BenchmarkResult: Codable {
    let phase: String
    let metric: String
    let value: Double
    let unit: String
    let timestamp: Date
}

actor BenchmarkRunner {
    var results: [BenchmarkResult] = []

    func runAllBenchmarks() async throws {
        // Phase 1
        results.append(try await benchmarkNetstackThroughput())
        results.append(try await benchmarkNetstackLatency())
        results.append(try await benchmarkNetstackConnections())

        // Phase 2
        results.append(try await benchmarkMeshThroughput())
        results.append(try await benchmarkMeshLatency())
        results.append(try await benchmarkMeshReconnection())

        // Phase 3
        results.append(try await benchmarkVMThroughput())
        results.append(try await benchmarkVMLatency())
        results.append(try await benchmarkVMLongRunning())

        // Save results
        try saveResults(to: "benchmark-\(Date()).json")
    }
}
```

### 8.5 Failure Injection Tests

| Failure | How to inject | Expected behavior |
|---------|---------------|-------------------|
| Consumer crash | `kill -9` consumer process | Provider buffers, VM sees timeout |
| Provider crash | `kill -9` provider process | Consumer cleans up connections |
| Network partition | `iptables -A INPUT -j DROP` | Reconnect via relay |
| High latency | `tc qdisc add netem delay 500ms` | Throughput degrades gracefully |
| Packet loss | `tc qdisc add netem loss 10%` | TCP retransmits, completes |
| Consumer OOM | Limit memory, flood connections | Graceful degradation, no crash |

---

## 9. Experimental Findings: T-Mobile NAT Behavior (January 2026)

### 9.1 Test Environment

- **Local machine**: T-Mobile Home Internet (CGNAT)
- **Mac**: T-Mobile Phone Hotspot
- **Bootstrap**: AWS (non-T-Mobile IP)

### 9.2 IPv6 Privacy Extensions Issue

On macOS with IPv6 privacy extensions enabled, the system maintains multiple IPv6 addresses:
- **Secured address**: Stable address used for incoming connections
- **Temporary address**: Rotating address used by default for outbound connections
- **CLAT46 address**: For NAT64 translation

**Problem discovered**: When binding to `::` (any address), macOS uses the temporary address for outbound packets, but we advertise the secured address to peers. This causes source address mismatch.

**Fix implemented**: Detect the local IPv6 address via `getBestLocalIPv6Address()` and bind the UDP socket to that specific address instead of `::`.

### 9.3 T-Mobile Peer-to-Peer Blocking

T-Mobile appears to block direct peer-to-peer IPv6 communication between their consumer devices:

| Source | Destination | Result |
|--------|-------------|--------|
| Local (T-Mobile Home) | Mac (T-Mobile Hotspot) | BLOCKED initially |
| Mac (T-Mobile Hotspot) | Local (T-Mobile Home) | BLOCKED initially |
| Bootstrap (AWS) | Mac (T-Mobile Hotspot) | SUCCESS |
| Mac | Bootstrap | SUCCESS |
| Local | Bootstrap | SUCCESS |

### 9.4 Firewall/NAT Pinhole Behavior

The T-Mobile NAT/firewall has specific behaviors:

1. **Endpoint-dependent NAT on Local**: Local's NAT only accepts packets from IPs it has directly sent to. Sending to Bootstrap does NOT open the pinhole for Mac.

2. **Firewall on Mac**: Mac requires outbound traffic to open the firewall for that specific peer. Unlike local, Mac accepts traffic from non-T-Mobile IPs (AWS) without prior outbound.

3. **Communication pattern that works**:
   ```
   1. Mac sends packet to Bootstrap (opens Mac's firewall to internet)
   2. Local sends packet to Mac (Mac receives it)
   3. Mac can now respond to Local
   4. Bidirectional communication established
   ```

4. **Communication pattern that fails**:
   ```
   1. Mac sends to Bootstrap
   2. Mac tries to send to Local
   → Local's endpoint-dependent NAT rejects (never sent to Mac)
   ```

### 9.5 Working Relay Strategy

For T-Mobile peer-to-peer:
1. **Both peers must send outbound first** before receiving
2. **Hole punching via relay**: Relay coordinates timing so both peers send packets to each other simultaneously
3. **Relay fallback**: If hole punching fails, relay traffic through AWS bootstrap

### 9.6 Key Takeaways

1. **Bind to specific IPv6 address** on macOS to ensure source address matches advertised address
2. **T-Mobile blocks peer-to-peer** between their consumer devices but allows internet traffic
3. **Endpoint-dependent NAT** requires precise hole punching coordination
4. **Relay infrastructure** is essential for T-Mobile-to-T-Mobile connectivity

