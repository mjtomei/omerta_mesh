# Virtual Network Architecture Rework

## Overview

Redesign the mesh network to support a true virtual LAN where:
1. VMs run omertad and are first-class mesh participants
2. Machines have LAN addresses (10.x.x.x) mapped to their machine IDs
3. Consumer acts as internet gateway
4. Tunnel sessions are created on-demand based on LAN address routing
5. **Dual interface modes:** Both userspace (netstack) and kernel (TUN) from the start

## Interface Modes

The system supports two interface modes, enabling different use cases:

### Kernel Mode (TUN Interface) - Requires Root
```
┌───────────────────────────────────────┐
│  omerta0 interface (10.0.x.x)         │
│  ├── Real OS interface                │
│  ├── Standard socket APIs work        │
│  ├── sshd, nginx, etc bind normally   │
│  └── ifconfig/ip addr visible         │
└───────────────────────────────────────┘
           │
           ▼
┌───────────────────────────────────────┐
│  omertad (TUN packet handler)         │
│  └── Routes packets through mesh      │
└───────────────────────────────────────┘
```

**Use cases:**
- **VMs:** sshd binds to `omerta0`, standard SSH works without modification
- **Consumer VPN mode:** Real interface, use standard `ssh 10.0.x.x`
- **Host machines:** Join network directly, fully accessible to mesh peers

### Userspace Mode (Netstack) - No Root Required
```
┌───────────────────────────────────────┐
│  Application (OmertaSSH, etc)         │
│  └── Uses netstack dial APIs          │
└───────────────────────────────────────┘
           │
           ▼
┌───────────────────────────────────────┐
│  NetstackBridge (gVisor TCP/IP)       │
│  └── Routes packets through mesh      │
└───────────────────────────────────────┘
```

**Use cases:**
- **Consumer without root:** Use OmertaSSH client to reach VMs
- **Fallback:** When TUN unavailable (no permissions, platform limits)
- **Testing:** Simpler setup for development

### Build Configuration

- **App Store build** (`OMERTA_APPSTORE_BUILD`): Userspace only
- **Direct build** (Linux/macOS): Both modes available, TUN requires root

---

## Implementation Phases

### Phase 1: TunnelSession Rework

**Goal:** Simplify TunnelSession to be a bidirectional packet channel identified by (remoteMachineId, channel). Remove all routing/netstack code.

#### Architecture Context

**Current state:** TunnelSession already uses `MachineId` for addressing (not `PeerId`). The mesh's `ChannelProvider` has been updated:
- `onChannel` handler receives `MachineId` (the sender's machine)
- `sendOnChannel(_:toMachine:channel:)` sends to a specific machine
- `sendOnChannel(_:to peerId:channel:)` broadcasts to all machines of a peer

**Current problem:** TunnelSession still contains netstack, traffic routing, and role-based logic. This mixes concerns - session management vs network routing. It also uses AsyncStream for receive instead of the callback pattern used by ChannelProvider.

**New design:** TunnelSession is just a reliable bidirectional pipe between two machines on a specific channel. It follows the same send/receive callback pattern as the mesh. Sessions are keyed by (remoteMachineId, channel) to allow multiple logical channels per machine pair.

```
┌───────────────────────────────────────────────────────────────────┐
│  TunnelSession                                                    │
│  ├── remoteMachineId: MachineId  (which machine)                  │
│  ├── channel: String             (logical channel name)           │
│  ├── send(Data) async throws                                      │
│  └── onReceive(handler: (Data) async -> Void)                     │
└───────────────────────────────────────────────────────────────────┘

Session Key: (remoteMachineId, channel)
```

#### Module: OmertaTunnel

**Files to modify:**
- `Sources/OmertaTunnel/TunnelSession.swift`
- `Sources/OmertaTunnel/TunnelState.swift`
- `Sources/OmertaTunnel/TunnelError.swift`

#### Changes

1. Add `channel` property (session key component along with machineId)
2. Use callback-based receive (like ChannelProvider's `onChannel`) instead of AsyncStream
3. Make sessions bidirectional (remove directional roles)
4. Add session statistics tracking

**Code to REMOVE from TunnelSession:**
- `netstackBridge` property
- `enableTrafficRouting(asExit:)` method
- `enableDialSupport()` method
- `trafficChannel`, `returnChannel` handling
- `TunnelRole` enum usage
- `setTrafficForwardCallback()` method
- `messageStream`, `messageContinuation` (AsyncStream-based receive)
- `returnPacketStream`, `returnPacketContinuation`

#### API

```swift
/// Uniquely identifies a tunnel session
public struct TunnelSessionKey: Hashable, Sendable {
    public let remoteMachineId: MachineId
    public let channel: String

    public init(remoteMachineId: MachineId, channel: String) {
        self.remoteMachineId = remoteMachineId
        self.channel = channel
    }
}

public actor TunnelSession {
    public let key: TunnelSessionKey
    public private(set) var state: TunnelState = .connecting

    // Convenience accessors
    public var remoteMachineId: MachineId { key.remoteMachineId }
    public var channel: String { key.channel }

    private let provider: any ChannelProvider
    private var receiveHandler: ((Data) async -> Void)?

    // Wire channel name for mesh transport
    private var wireChannel: String {
        "tunnel:\(channel)"
    }

    // Statistics
    public struct Stats {
        public var packetsSent: UInt64 = 0
        public var packetsReceived: UInt64 = 0
        public var bytesSent: UInt64 = 0
        public var bytesReceived: UInt64 = 0
        public var lastActivity: Date = Date()
    }
    public private(set) var stats = Stats()

    public init(
        remoteMachineId: MachineId,
        channel: String,
        provider: any ChannelProvider
    ) {
        self.key = TunnelSessionKey(
            remoteMachineId: remoteMachineId,
            channel: channel
        )
        self.provider = provider
    }

    /// Set handler for incoming packets (like ChannelProvider.onChannel)
    public func onReceive(_ handler: @escaping (Data) async -> Void) {
        self.receiveHandler = handler
    }

    /// Send a packet to the remote machine
    public func send(_ data: Data) async throws {
        guard state == .active else { throw TunnelError.notConnected }
        try await provider.sendOnChannel(data, toMachine: remoteMachineId, channel: wireChannel)
        stats.packetsSent += 1
        stats.bytesSent += UInt64(data.count)
        stats.lastActivity = Date()
    }

    /// Activate the session (called after handshake)
    public func activate() async {
        state = .active
        // Register handler on the mesh channel
        try? await provider.onChannel(wireChannel) { [weak self] senderMachine, data in
            guard let self = self else { return }
            await self.handleIncoming(from: senderMachine, data: data)
        }
    }

    /// Close the session
    public func close() async {
        state = .disconnected
        await provider.offChannel(wireChannel)
        receiveHandler = nil
    }

    private func handleIncoming(from senderMachine: MachineId, data: Data) async {
        // Verify sender matches expected machine
        guard senderMachine == remoteMachineId else { return }

        stats.packetsReceived += 1
        stats.bytesReceived += UInt64(data.count)
        stats.lastActivity = Date()

        await receiveHandler?(data)
    }
}
```

#### Unit Tests

```swift
// TunnelSessionTests.swift
func testSessionKey() async throws {
    let session = TunnelSession(
        remoteMachineId: "machine456",
        channel: "packets",
        provider: mockProvider
    )
    XCTAssertEqual(session.remoteMachineId, "machine456")
    XCTAssertEqual(session.channel, "packets")
    XCTAssertEqual(session.state, .connecting)

    // Key should be (machineId, channel)
    XCTAssertEqual(session.key, TunnelSessionKey(remoteMachineId: "machine456", channel: "packets"))
}

func testReceiveCallback() async throws {
    let session = try await createActiveSession(remoteMachineId: "machine1")
    var receivedData: Data?

    await session.onReceive { data in
        receivedData = data
    }

    // Simulate incoming packet from the expected machine
    await session.handleIncoming(from: "machine1", data: Data("hello".utf8))

    XCTAssertEqual(receivedData, Data("hello".utf8))
}

func testSessionStatistics() async throws {
    let session = try await createActiveSession()
    try await session.send(Data(repeating: 0x42, count: 100))

    let stats = await session.stats
    XCTAssertEqual(stats.packetsSent, 1)
    XCTAssertEqual(stats.bytesSent, 100)
}

func testSendWhileDisconnectedThrows() async throws {
    let session = TunnelSession(
        remoteMachineId: "machine",
        channel: "packets",
        provider: mockProvider
    )
    do {
        try await session.send(Data("test".utf8))
        XCTFail("Should have thrown")
    } catch TunnelError.notConnected {
        // Expected
    }
}

func testIgnoresWrongSender() async throws {
    let session = try await createActiveSession(remoteMachineId: "expected-machine")
    var receivedData: Data?

    await session.onReceive { data in
        receivedData = data
    }

    // Packet from wrong machine should be ignored
    await session.handleIncoming(from: "wrong-machine", data: Data("hello".utf8))

    XCTAssertNil(receivedData)
}
```

#### Integration Tests

```swift
// TunnelSessionIntegrationTests.swift
func testSessionOverMockMesh() async throws {
    let node1 = MockMeshNode(machineId: "machine1")
    let node2 = MockMeshNode(machineId: "machine2")
    node1.connectTo(node2)

    let session1 = TunnelSession(
        remoteMachineId: "machine2",
        channel: "packets",
        provider: node1
    )

    let session2 = TunnelSession(
        remoteMachineId: "machine1",
        channel: "packets",
        provider: node2
    )

    var received2: Data?
    await session2.onReceive { data in
        received2 = data
    }

    await session1.activate()
    await session2.activate()

    try await session1.send(Data("ping".utf8))
    try await Task.sleep(for: .milliseconds(50))

    XCTAssertEqual(received2, Data("ping".utf8))
}

func testMultipleChannelsSameMachine() async throws {
    let node1 = MockMeshNode(machineId: "machine1")
    let node2 = MockMeshNode(machineId: "machine2")
    node1.connectTo(node2)

    // Two sessions to same machine, different channels
    let controlSession = TunnelSession(
        remoteMachineId: "machine2",
        channel: "control",
        provider: node1
    )

    let dataSession = TunnelSession(
        remoteMachineId: "machine2",
        channel: "data",
        provider: node1
    )

    await controlSession.activate()
    await dataSession.activate()

    // Both sessions are independent
    XCTAssertNotEqual(controlSession.key, dataSession.key)
}
```

#### Manual Tests

```bash
# Run tunnel tests
cd ~/omerta
swift test --filter TunnelSessionTests

# Verify no regressions
swift test
```

**Deliverable:** TunnelSession is a simple bidirectional packet pipe identified by (machineId, channel) using callback-based receive.

---

### Phase 2: TunnelManager Session Pool

**Goal:** Rework TunnelManager to maintain a pool of sessions keyed by (machineId, channel), with active endpoint management for connection reliability.

#### Architecture Context

**Current state:** TunnelManager already uses `MachineId` throughout (not `PeerId`). It uses `sendOnChannel(_:toMachine:channel:)` for targeted sends. However, it only supports one session at a time.

**New:** TunnelManager maintains multiple sessions keyed by TunnelSessionKey. Sessions are created on-demand when packets need to be sent. Multiple channels to the same machine are supported.

**Connection management:** The base MeshNetwork already provides hole-punching, relay fallback, and reconnection — but it does so *reactively*, only refreshing connections when they're actually used. This is efficient for background traffic but means connections may go stale between uses, causing latency spikes when traffic resumes.

TunnelManager adds *proactive* connection management for latency-sensitive applications (SSH, real-time communication):
- **Active health monitoring** — Periodic probes even when idle, so connection problems are detected immediately
- **Preemptive reconnection** — Re-establishes connections before they're needed, not when a send fails
- **Latency tracking** — Continuous RTT measurement for connection quality visibility
- **Faster failover** — Switches to relay sooner when direct path degrades

The underlying mechanisms (hole-punch, relay, etc.) are the same as MeshNetwork. The difference is timing: TunnelManager doesn't wait for traffic to discover a problem.

This responsibility is per-machine, not per-session. Multiple sessions to the same machine share a single actively-managed endpoint.

```
┌───────────────────────────────────────────────────────────────────┐
│  TunnelManager                                                    │
│  ├── sessions: [TunnelSessionKey: TunnelSession]                  │
│  │   └── Keyed by (machineId, channel)                            │
│  ├── (internal) endpoints, health monitors                        │
│  │   └── Proactive connection management (probes even when idle)  │
│  ├── getSession(machineId:channel:)                               │
│  ├── closeSession(key:)                                           │
│  └── onSessionEstablished(handler:)                               │
└───────────────────────────────────────────────────────────────────┘

Public:   (machineId, channel) → TunnelSession
Internal: machineId → endpoint state, health probes
```

#### Module: OmertaTunnel

**Files to modify:**
- `Sources/OmertaTunnel/TunnelManager.swift`

**Files to create:**
- `Sources/OmertaTunnel/TunnelManagerConfig.swift`

#### API

```swift
public actor TunnelManager {
    private var sessions: [TunnelSessionKey: TunnelSession] = [:]
    private var endpoints: [MachineId: TunnelEndpoint] = [:]  // Per-machine connection state
    private let provider: any ChannelProvider
    private let config: TunnelManagerConfig
    private var healthMonitors: [MachineId: Task<Void, Never>] = [:]

    /// Callback when a new session is established (incoming or outgoing)
    private var sessionEstablishedHandler: ((TunnelSession) async -> Void)?

    public init(provider: any ChannelProvider, config: TunnelManagerConfig = .default) {
        self.provider = provider
        self.config = config
    }

    /// Get or create a session to a specific machine on a specific channel.
    /// If no endpoint exists for this machine, triggers endpoint negotiation
    /// (hole-punch, relay fallback) before returning the session.
    public func getSession(
        machineId: MachineId,
        channel: String
    ) async throws -> TunnelSession {
        let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)

        if let existing = sessions[key] {
            return existing
        }

        // Ensure we have a managed endpoint to this machine
        if endpoints[machineId] == nil {
            try await negotiateEndpoint(for: machineId)
        }

        let session = TunnelSession(
            remoteMachineId: machineId,
            channel: channel,
            provider: provider
        )
        await session.activate()
        sessions[key] = session

        await sessionEstablishedHandler?(session)
        return session
    }

    /// Internal: negotiate endpoint (hole-punch, relay fallback)
    private func negotiateEndpoint(for machineId: MachineId) async throws {
        endpoints[machineId] = TunnelEndpoint(
            machineId: machineId,
            connectionType: .connecting,
            latencyMs: nil,
            lastProbeTime: nil
        )

        // 1. Attempt UDP hole-punch via mesh signaling
        // 2. If fails after timeout, request relay from RelayCoordinator
        // 3. Update endpoint with result
        // 4. Start health monitor for this machine

        // (Implementation details in TunnelEndpointNegotiator)
    }

    /// Get existing session by key (does not create)
    public func getExistingSession(key: TunnelSessionKey) -> TunnelSession? {
        sessions[key]
    }

    /// Close a specific session
    public func closeSession(key: TunnelSessionKey) async {
        if let session = sessions.removeValue(forKey: key) {
            await session.close()
        }
    }

    /// Close all sessions to a machine (all channels)
    public func closeAllSessions(to machineId: MachineId) async {
        let keysToRemove = sessions.keys.filter { $0.remoteMachineId == machineId }
        for key in keysToRemove {
            if let session = sessions.removeValue(forKey: key) {
                await session.close()
            }
        }
    }

    /// Number of active sessions
    public var sessionCount: Int { sessions.count }

    /// All active session keys
    public var activeSessionKeys: [TunnelSessionKey] { Array(sessions.keys) }

    /// Set handler for new sessions (like onChannel pattern)
    public func onSessionEstablished(_ handler: @escaping (TunnelSession) async -> Void) {
        sessionEstablishedHandler = handler
    }

    /// Start accepting incoming sessions
    public func start() async {
        // Register handler for incoming session requests
        try? await provider.onChannel("tunnel-handshake") { [weak self] senderMachine, data in
            await self?.handleIncomingHandshake(from: senderMachine, data: data)
        }
    }

    /// Stop and close all sessions
    public func stop() async {
        for session in sessions.values {
            await session.close()
        }
        sessions.removeAll()
        await provider.offChannel("tunnel-handshake")
    }
}

public struct TunnelManagerConfig: Sendable {
    public var idleTimeout: TimeInterval = 300  // 5 minutes
    public var maxSessionsPerMachine: Int = 10
    public var maxTotalSessions: Int = 1000

    // Proactive health monitoring — the key difference from base MeshNetwork.
    // These probes run even when no traffic is flowing, so connection
    // problems are detected before they impact user-facing latency.
    public var probeIntervalMs: Int = 5000      // How often to probe idle connections
    public var probeTimeoutMs: Int = 2000       // When to consider a probe failed
    public var relayFallbackThreshold: Int = 3  // Failed probes before switching to relay

    public static let `default` = TunnelManagerConfig()
}

// MARK: - Endpoint Management (Internal)
//
// TunnelManager actively manages the connection to each remote machine.
// Multiple sessions to the same machine share a single managed endpoint.
// This is all internal — users who need fine-grained endpoint control
// should use the MeshNetwork API directly.
//
// Internal state:
// - endpoints: [MachineId: EndpointState]
// - healthMonitors: [MachineId: Task] — continuous probes
//
// Internal behavior:
// - getSession() triggers endpoint negotiation if needed
// - Health probes run continuously, even when idle
// - Auto-failover to relay after probeFailureThreshold failures
// - Auto-reconnect on network changes
```

#### Unit Tests

```swift
// TunnelManagerTests.swift
func testGetOrCreateSession() async throws {
    let manager = TunnelManager(provider: mockProvider)
    await manager.start()

    // First call creates session
    let session1 = try await manager.getSession(
        machineId: "machine1",
        channel: "packets"
    )
    XCTAssertEqual(await manager.sessionCount, 1)

    // Second call with same key returns same session
    let session2 = try await manager.getSession(
        machineId: "machine1",
        channel: "packets"
    )
    XCTAssertTrue(session1 === session2)
    XCTAssertEqual(await manager.sessionCount, 1)
}

func testDifferentChannelsDifferentSessions() async throws {
    let manager = TunnelManager(provider: mockProvider)
    await manager.start()

    let controlSession = try await manager.getSession(
        machineId: "machine1",
        channel: "control"
    )

    let dataSession = try await manager.getSession(
        machineId: "machine1",
        channel: "data"
    )

    // Different channels = different sessions
    XCTAssertFalse(controlSession === dataSession)
    XCTAssertEqual(await manager.sessionCount, 2)
}

func testCloseAllSessionsToMachine() async throws {
    let manager = TunnelManager(provider: mockProvider)
    await manager.start()

    // Create multiple sessions to same machine
    _ = try await manager.getSession(machineId: "m1", channel: "control")
    _ = try await manager.getSession(machineId: "m1", channel: "data")
    _ = try await manager.getSession(machineId: "m2", channel: "packets")
    XCTAssertEqual(await manager.sessionCount, 3)

    // Close all sessions to m1
    await manager.closeAllSessions(to: "m1")
    XCTAssertEqual(await manager.sessionCount, 1)
}

func testSessionEstablishedCallback() async throws {
    let manager = TunnelManager(provider: mockProvider)
    var callbackSession: TunnelSession?

    await manager.onSessionEstablished { session in
        callbackSession = session
    }
    await manager.start()

    _ = try await manager.getSession(
        machineId: "machine1",
        channel: "packets"
    )

    XCTAssertNotNil(callbackSession)
    XCTAssertEqual(callbackSession?.remoteMachineId, "machine1")
    XCTAssertEqual(callbackSession?.channel, "packets")
}
```

#### Integration Tests

```swift
// TunnelManagerIntegrationTests.swift
func testTwoManagersCommunicate() async throws {
    let node1 = MockMeshNode(machineId: "m1")
    let node2 = MockMeshNode(machineId: "m2")
    node1.connectTo(node2)

    let manager1 = TunnelManager(provider: node1)
    let manager2 = TunnelManager(provider: node2)

    await manager1.start()
    await manager2.start()

    // Setup receive handler on manager2
    var received: Data?
    await manager2.onSessionEstablished { session in
        await session.onReceive { data in
            received = data
        }
    }

    // Manager1 creates session to m2
    let session = try await manager1.getSession(
        machineId: "m2",
        channel: "packets"
    )

    try await session.send(Data("hello".utf8))
    try await Task.sleep(for: .milliseconds(100))

    XCTAssertEqual(received, Data("hello".utf8))
}
```

#### Manual Tests

```bash
swift test --filter TunnelManagerTests
swift test --filter TunnelIntegration
```

**Deliverable:** TunnelManager maintains session pool keyed by (machineId, channel), creates sessions on demand.

---

### Phase 3: VirtualNetwork Routing

**Goal:** Create VirtualNetwork for IP-to-machineId mapping and routing decisions.

#### Architecture Context

This is where we start building the network layer. VirtualNetwork knows about IP addresses and decides where packets should go.

```
┌──────────────────────────────────────────────────────────────────┐
│  VirtualNetwork                                                  │
│  ├── addressMap: [IP: MachineId]      (who has which IP)         │
│  ├── localIP: String                  (our IP)                   │
│  ├── gatewayMachineId: MachineId?     (internet exit)            │
│  └── route(destinationIP) -> RouteDecision                       │
└──────────────────────────────────────────────────────────────────┘

RouteDecision:
  .local           → packet is for us
  .peer(MachineId) → send via tunnel to this machine
  .gateway         → send to gateway for internet
  .drop(reason)    → discard packet
```

#### Module: OmertaNetwork (NEW)

**Files to create:**
- `Sources/OmertaNetwork/VirtualNetwork.swift`
- `Sources/OmertaNetwork/VirtualNetworkConfig.swift`
- `Sources/OmertaNetwork/RouteDecision.swift`

**Files to modify:**
- `Package.swift` - Add OmertaNetwork module
- `Sources/OmertaMesh/GossipProtocol.swift` - Add address mapping gossip

#### API

```swift
public enum RouteDecision: Equatable, Sendable {
    case local
    case peer(MachineId)
    case gateway
    case drop(String)
}

public struct VirtualNetworkConfig: Sendable {
    public var subnet: String = "10.0.0.0"
    public var netmask: String = "255.255.0.0"
    public var gatewayIP: String = "10.0.0.1"

    public static let `default` = VirtualNetworkConfig()
}

public actor VirtualNetwork {
    private let localMachineId: MachineId
    private let config: VirtualNetworkConfig

    private var localIP: String?
    private var addressMap: [String: MachineId] = [:]  // IP -> MachineId
    private var reverseMap: [MachineId: String] = [:]  // MachineId -> IP
    private var gatewayMachineId: MachineId?

    public init(localMachineId: MachineId, config: VirtualNetworkConfig = .default) {
        self.localMachineId = localMachineId
        self.config = config
    }

    /// Set our local IP address
    public func setLocalAddress(_ ip: String) {
        localIP = ip
        addressMap[ip] = localMachineId
        reverseMap[localMachineId] = ip
    }

    /// Register another machine's address (from DHCP or gossip)
    public func registerAddress(ip: String, machineId: MachineId) {
        addressMap[ip] = machineId
        reverseMap[machineId] = ip
    }

    /// Set the gateway machine
    public func setGateway(machineId: MachineId, ip: String) {
        gatewayMachineId = machineId
        registerAddress(ip: ip, machineId: machineId)
    }

    /// Determine where to route a packet
    public func route(destinationIP: String) -> RouteDecision {
        // Is it for us?
        if destinationIP == localIP {
            return .local
        }

        // Do we know this IP?
        if let machineId = addressMap[destinationIP] {
            return .peer(machineId)
        }

        // Is it in our subnet but unknown?
        if isInSubnet(destinationIP) {
            return .drop("Unknown address in subnet: \(destinationIP)")
        }

        // External IP - route to gateway if we have one
        if let _ = gatewayMachineId {
            return .gateway
        }

        return .drop("No route to \(destinationIP) (no gateway)")
    }

    /// Lookup machine by IP
    public func lookupMachine(ip: String) -> MachineId? {
        addressMap[ip]
    }

    /// Lookup IP by machine
    public func lookupIP(machineId: MachineId) -> String? {
        reverseMap[machineId]
    }

    private func isInSubnet(_ ip: String) -> Bool {
        // Check if IP is in 10.0.0.0/16
        ip.hasPrefix("10.0.")
    }
}
```

#### Unit Tests

```swift
// VirtualNetworkTests.swift
func testRouteToLocalAddress() async throws {
    let vnet = VirtualNetwork(localMachineId: "local-m")
    await vnet.setLocalAddress("10.0.0.5")

    let decision = await vnet.route(destinationIP: "10.0.0.5")
    XCTAssertEqual(decision, .local)
}

func testRouteToPeer() async throws {
    let vnet = VirtualNetwork(localMachineId: "local-m")
    await vnet.setLocalAddress("10.0.0.5")
    await vnet.registerAddress(ip: "10.0.0.10", machineId: "peer-m")

    let decision = await vnet.route(destinationIP: "10.0.0.10")
    XCTAssertEqual(decision, .peer("peer-m"))
}

func testRouteToGateway() async throws {
    let vnet = VirtualNetwork(localMachineId: "local-m")
    await vnet.setLocalAddress("10.0.0.5")
    await vnet.setGateway(machineId: "gateway-m", ip: "10.0.0.1")

    // External IP should route to gateway
    let decision = await vnet.route(destinationIP: "8.8.8.8")
    XCTAssertEqual(decision, .gateway)
}

func testRouteUnknownInSubnet() async throws {
    let vnet = VirtualNetwork(localMachineId: "local-m")
    await vnet.setLocalAddress("10.0.0.5")

    // Unknown IP in mesh range, no gateway
    let decision = await vnet.route(destinationIP: "10.0.0.99")
    if case .drop(let reason) = decision {
        XCTAssertTrue(reason.contains("Unknown"))
    } else {
        XCTFail("Expected .drop")
    }
}

func testAddressLookup() async throws {
    let vnet = VirtualNetwork(localMachineId: "local-m")
    await vnet.registerAddress(ip: "10.0.0.50", machineId: "m50")

    XCTAssertEqual(await vnet.lookupMachine(ip: "10.0.0.50"), "m50")
    XCTAssertEqual(await vnet.lookupIP(machineId: "m50"), "10.0.0.50")
}
```

#### Integration Tests

```swift
// VirtualNetworkIntegrationTests.swift
func testAddressPropagationViaGossip() async throws {
    let node1 = MockMeshNode(machineId: "m1")
    let node2 = MockMeshNode(machineId: "m2")
    node1.connectTo(node2)

    let vnet1 = VirtualNetwork(localMachineId: "m1")
    let vnet2 = VirtualNetwork(localMachineId: "m2")

    // Setup gossip handler for vnet1
    node1.onGossip { msg in
        if case .addressMapping(let machineId, let ip) = msg {
            await vnet1.registerAddress(ip: ip, machineId: machineId)
        }
    }

    // vnet2 announces its address
    await vnet2.setLocalAddress("10.0.0.100")
    await node2.gossip(.addressMapping(machineId: "m2", ip: "10.0.0.100"))

    // Wait for propagation
    try await Task.sleep(for: .milliseconds(100))

    // vnet1 should now know about m2
    let decision = await vnet1.route(destinationIP: "10.0.0.100")
    XCTAssertEqual(decision, .peer("m2"))
}
```

#### Manual Tests

```bash
swift test --filter VirtualNetworkTests
```

**Deliverable:** VirtualNetwork handles routing decisions and address mapping.

---

### Phase 4: DHCP Service & Client

**Goal:** Implement DHCP over mesh channel for address allocation.

#### Architecture Context

DHCP runs over a mesh channel (not IP packets) to solve the chicken-and-egg problem: you need an IP to send IP packets, but you need to request an IP first.

```
┌─────────────────┐                      ┌─────────────────┐
│  DHCPClient     │ ──"dhcp" channel───→ │  DHCPService    │
│  (peer)         │                      │  (gateway)      │
│                 │ ←───DHCPResponse───  │                 │
└─────────────────┘                      └─────────────────┘
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/DHCPService.swift`
- `Sources/OmertaNetwork/DHCPClient.swift`
- `Sources/OmertaNetwork/DHCPMessages.swift`

#### API

```swift
// DHCPMessages.swift
public struct DHCPRequest: Codable, Sendable {
    public let machineId: MachineId
    public let requestedIP: String?  // Optional preferred IP
    public let hostname: String?
}

public struct DHCPResponse: Codable, Sendable {
    public let machineId: MachineId
    public let assignedIP: String
    public let netmask: String
    public let gateway: String
    public let leaseSeconds: UInt32
}

public struct DHCPRelease: Codable, Sendable {
    public let machineId: MachineId
    public let ip: String
}

// DHCPService.swift (runs on gateway)
public actor DHCPService {
    private var leases: [MachineId: Lease] = [:]
    private var ipPool: Set<String>  // Available IPs
    private let config: DHCPConfig

    public struct Lease {
        let ip: String
        let machineId: MachineId
        let expiresAt: Date
        let hostname: String?
    }

    public init(config: DHCPConfig = .default) {
        self.config = config
        // Initialize pool: 10.0.0.100 - 10.0.255.254
        ipPool = Set((100...65534).map { "10.0.\($0 / 256).\($0 % 256)" })
    }

    public func handleRequest(_ request: DHCPRequest) async -> DHCPResponse {
        // Check for existing lease
        if let existing = leases[request.machineId], !existing.isExpired {
            return DHCPResponse(
                machineId: request.machineId,
                assignedIP: existing.ip,
                netmask: "255.255.0.0",
                gateway: "10.0.0.1",
                leaseSeconds: config.leaseTime
            )
        }

        // Try requested IP if available
        let ip: String
        if let requested = request.requestedIP, ipPool.contains(requested) {
            ip = requested
        } else {
            ip = ipPool.removeFirst()
        }

        ipPool.remove(ip)
        leases[request.machineId] = Lease(
            ip: ip,
            machineId: request.machineId,
            expiresAt: Date().addingTimeInterval(Double(config.leaseTime)),
            hostname: request.hostname
        )

        return DHCPResponse(
            machineId: request.machineId,
            assignedIP: ip,
            netmask: "255.255.0.0",
            gateway: "10.0.0.1",
            leaseSeconds: config.leaseTime
        )
    }

    public func handleRelease(_ release: DHCPRelease) async {
        if let lease = leases.removeValue(forKey: release.machineId) {
            ipPool.insert(lease.ip)
        }
    }
}

// DHCPClient.swift (runs on peers)
public actor DHCPClient {
    private let meshNode: any ChannelProvider
    private let machineId: MachineId
    private var gatewayPeerId: PeerId?
    private var currentLease: DHCPResponse?

    public func obtainAddress() async throws -> DHCPResponse {
        guard let gateway = gatewayPeerId else {
            throw DHCPError.noGateway
        }

        let request = DHCPRequest(machineId: machineId, requestedIP: nil, hostname: nil)
        let data = try JSONEncoder().encode(request)

        let responseData = try await meshNode.requestOnChannel(data, to: gateway, channel: "dhcp")
        let response = try JSONDecoder().decode(DHCPResponse.self, from: responseData)

        currentLease = response
        return response
    }
}
```

#### Unit Tests

```swift
// DHCPServiceTests.swift
func testAllocateFirstAddress() async throws {
    let dhcp = DHCPService()

    let request = DHCPRequest(machineId: "m1", requestedIP: nil, hostname: nil)
    let response = await dhcp.handleRequest(request)

    XCTAssertEqual(response.assignedIP, "10.0.0.100")
    XCTAssertEqual(response.gateway, "10.0.0.1")
}

func testSameMachineGetsSameIP() async throws {
    let dhcp = DHCPService()

    let r1 = await dhcp.handleRequest(DHCPRequest(machineId: "m1", requestedIP: nil, hostname: nil))
    let r2 = await dhcp.handleRequest(DHCPRequest(machineId: "m1", requestedIP: nil, hostname: nil))

    XCTAssertEqual(r1.assignedIP, r2.assignedIP)
}

func testSequentialAllocation() async throws {
    let dhcp = DHCPService()

    let r1 = await dhcp.handleRequest(DHCPRequest(machineId: "m1", requestedIP: nil, hostname: nil))
    let r2 = await dhcp.handleRequest(DHCPRequest(machineId: "m2", requestedIP: nil, hostname: nil))
    let r3 = await dhcp.handleRequest(DHCPRequest(machineId: "m3", requestedIP: nil, hostname: nil))

    XCTAssertEqual(r1.assignedIP, "10.0.0.100")
    XCTAssertEqual(r2.assignedIP, "10.0.0.101")
    XCTAssertEqual(r3.assignedIP, "10.0.0.102")
}

func testReleaseAndReallocate() async throws {
    let dhcp = DHCPService()

    let r1 = await dhcp.handleRequest(DHCPRequest(machineId: "m1", requestedIP: nil, hostname: nil))
    await dhcp.handleRelease(DHCPRelease(machineId: "m1", ip: r1.assignedIP))

    // New machine gets the released IP
    let r2 = await dhcp.handleRequest(DHCPRequest(machineId: "m2", requestedIP: nil, hostname: nil))
    XCTAssertEqual(r2.assignedIP, "10.0.0.100")
}
```

#### Integration Tests

```swift
// DHCPIntegrationTests.swift
func testDHCPOverMockMesh() async throws {
    let gatewayNode = MockMeshNode(peerId: "gateway-peer", machineId: "gateway")
    let clientNode = MockMeshNode(peerId: "client-peer", machineId: "client")
    gatewayNode.connectTo(clientNode)

    let dhcpService = DHCPService()

    // Register DHCP handler on gateway
    await gatewayNode.registerRequestHandler(channel: "dhcp") { data in
        let request = try! JSONDecoder().decode(DHCPRequest.self, from: data)
        let response = await dhcpService.handleRequest(request)
        return try! JSONEncoder().encode(response)
    }

    let client = DHCPClient(meshNode: clientNode, machineId: "client")
    await client.setGatewayPeerId("gateway-peer")

    let response = try await client.obtainAddress()
    XCTAssertEqual(response.assignedIP, "10.0.0.100")
}
```

#### Manual Tests

```bash
swift test --filter DHCPTests
```

**Deliverable:** DHCP allocates addresses via mesh channel.

---

### Phase 5: NetworkInterface Abstraction

**Goal:** Create NetworkInterface protocol and implementations for packet I/O.

#### Architecture Context

NetworkInterface abstracts the difference between TUN (kernel) and Netstack (userspace). The rest of the system doesn't need to know which mode we're in.

```
┌──────────────────────────────────────────────────────────────────┐
│  NetworkInterface (protocol)                                     │
│  ├── readPacket() -> Data      (packets from apps/kernel)        │
│  ├── writePacket(Data)         (packets to apps/kernel)          │
│  └── dialTCP() -> TCPConnection?  (userspace only)               │
└──────────────────────────────────────────────────────────────────┘
            │                                │
            ▼                                ▼
┌───────────────────────┐      ┌───────────────────────┐
│  TUNInterface         │      │  NetstackInterface    │
│  (kernel mode)        │      │  (userspace mode)     │
│  /dev/net/tun         │      │  gVisor netstack      │
└───────────────────────┘      └───────────────────────┘
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/NetworkInterface.swift`
- `Sources/OmertaNetwork/MockNetworkInterface.swift`
- `Sources/OmertaNetwork/NetstackInterface.swift`

#### API

```swift
// NetworkInterface.swift
public protocol NetworkInterface: Sendable {
    var localIP: String { get }

    /// Read a packet from the interface (outbound from apps)
    func readPacket() async throws -> Data

    /// Write a packet to the interface (inbound to apps)
    func writePacket(_ packet: Data) async throws

    /// Dial a TCP connection (userspace mode only, returns nil for TUN)
    func dialTCP(host: String, port: UInt16) async throws -> TCPConnection?

    /// Start the interface
    func start() async throws

    /// Stop the interface
    func stop() async
}

// MockNetworkInterface.swift (for testing)
public actor MockNetworkInterface: NetworkInterface {
    public let localIP: String

    private var outboundQueue: [Data] = []
    private var inboundQueue: [Data] = []
    private var outboundContinuation: AsyncStream<Data>.Continuation?

    public init(localIP: String) {
        self.localIP = localIP
    }

    public func readPacket() async throws -> Data {
        // Return next packet from outbound queue (simulates app sending)
        while outboundQueue.isEmpty {
            try await Task.sleep(for: .milliseconds(10))
        }
        return outboundQueue.removeFirst()
    }

    public func writePacket(_ packet: Data) async throws {
        // Deliver to inbound queue (simulates app receiving)
        inboundQueue.append(packet)
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        // Mock implementation
        return MockTCPConnection(host: host, port: port)
    }

    // Test helpers
    public func simulateAppSend(_ packet: Data) {
        outboundQueue.append(packet)
    }

    public func getAppReceived() -> Data? {
        inboundQueue.isEmpty ? nil : inboundQueue.removeFirst()
    }
}

// NetstackInterface.swift
public actor NetstackInterface: NetworkInterface {
    public let localIP: String
    private let netstack: NetstackBridge
    private var outboundStream: AsyncStream<Data>!
    private var outboundContinuation: AsyncStream<Data>.Continuation!

    public init(localIP: String) throws {
        self.localIP = localIP
        let config = NetstackBridge.Config(gatewayIP: localIP, mtu: 1400)
        self.netstack = try NetstackBridge(config: config)

        let (stream, continuation) = AsyncStream<Data>.makeStream()
        self.outboundStream = stream
        self.outboundContinuation = continuation

        // Wire netstack outbound packets to our stream
        netstack.setReturnCallback { [weak self] packet in
            self?.outboundContinuation.yield(packet)
        }
    }

    public func start() async throws {
        try netstack.start()
    }

    public func stop() async {
        netstack.stop()
        outboundContinuation.finish()
    }

    public func readPacket() async throws -> Data {
        for await packet in outboundStream {
            return packet
        }
        throw InterfaceError.closed
    }

    public func writePacket(_ packet: Data) async throws {
        try netstack.injectPacket(packet)
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        try netstack.dialTCP(host: host, port: port)
    }
}
```

#### Unit Tests

```swift
// NetworkInterfaceTests.swift
func testMockInterfaceRoundtrip() async throws {
    let interface = MockNetworkInterface(localIP: "10.0.0.5")

    // Simulate app sending
    let packet = Data("test packet".utf8)
    await interface.simulateAppSend(packet)

    // Should be readable
    let read = try await interface.readPacket()
    XCTAssertEqual(read, packet)
}

func testMockInterfaceReceive() async throws {
    let interface = MockNetworkInterface(localIP: "10.0.0.5")

    // Write packet (as if from network)
    let packet = Data("incoming".utf8)
    try await interface.writePacket(packet)

    // App should receive it
    let received = await interface.getAppReceived()
    XCTAssertEqual(received, packet)
}
```

#### Integration Tests

```swift
// NetworkInterfaceIntegrationTests.swift
func testTwoMockInterfacesConnected() async throws {
    let if1 = MockNetworkInterface(localIP: "10.0.0.1")
    let if2 = MockNetworkInterface(localIP: "10.0.0.2")

    // Wire them together
    Task {
        while true {
            let packet = try await if1.readPacket()
            try await if2.writePacket(packet)
        }
    }

    // if1 sends, if2 receives
    await if1.simulateAppSend(Data("hello".utf8))
    try await Task.sleep(for: .milliseconds(50))

    let received = await if2.getAppReceived()
    XCTAssertEqual(received, Data("hello".utf8))
}
```

#### Manual Tests

```bash
swift test --filter NetworkInterfaceTests
```

**Deliverable:** NetworkInterface abstraction with mock for testing.

---

### Phase 6: PacketRouter

**Goal:** Create PacketRouter to wire NetworkInterface → VirtualNetwork → TunnelManager.

#### Architecture Context

PacketRouter is the glue that connects everything. It reads packets from the local interface, uses VirtualNetwork to decide where they go, and sends them through TunnelManager.

```
┌──────────────────────────────────────────────────────────────────┐
│                         PacketRouter                             │
│                                                                  │
│  ┌─────────────┐    ┌────────────────┐    ┌────────────────┐    │
│  │ Network     │───→│ VirtualNetwork │───→│ TunnelManager  │    │
│  │ Interface   │    │ (routing)      │    │ (sessions)     │    │
│  │ (packets)   │←───│                │←───│                │    │
│  └─────────────┘    └────────────────┘    └────────────────┘    │
│                                                                  │
│  Outbound: interface.read() → route() → session.send()          │
│  Inbound:  session.receive() → interface.write()                │
└──────────────────────────────────────────────────────────────────┘
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/PacketRouter.swift`

#### API

```swift
public actor PacketRouter {
    private let localInterface: any NetworkInterface
    private let virtualNetwork: VirtualNetwork
    private let tunnelManager: TunnelManager
    private var gatewayService: GatewayService?

    private var outboundTask: Task<Void, Never>?
    private var inboundTasks: [MachineId: Task<Void, Never>] = [:]

    public init(
        localInterface: any NetworkInterface,
        virtualNetwork: VirtualNetwork,
        tunnelManager: TunnelManager,
        gatewayService: GatewayService? = nil
    ) {
        self.localInterface = localInterface
        self.virtualNetwork = virtualNetwork
        self.tunnelManager = tunnelManager
        self.gatewayService = gatewayService
    }

    public func start() async throws {
        try await localInterface.start()

        // Start outbound routing loop
        outboundTask = Task {
            await routeOutboundLoop()
        }

        // Register for incoming tunnel sessions
        await tunnelManager.setSessionEstablishedHandler { [weak self] session in
            await self?.handleNewSession(session)
        }
    }

    public func stop() async {
        outboundTask?.cancel()
        for task in inboundTasks.values {
            task.cancel()
        }
        await localInterface.stop()
    }

    private func routeOutboundLoop() async {
        while !Task.isCancelled {
            do {
                let packet = try await localInterface.readPacket()
                await routeOutbound(packet)
            } catch {
                if !Task.isCancelled {
                    // Log error, continue
                }
            }
        }
    }

    private func routeOutbound(_ packet: Data) async {
        guard let destIP = extractDestinationIP(packet) else { return }

        let decision = await virtualNetwork.route(destinationIP: destIP)

        switch decision {
        case .local:
            // Deliver locally
            try? await localInterface.writePacket(packet)

        case .peer(let machineId):
            // Send via tunnel
            if let session = await tunnelManager.getExistingSession(for: machineId) {
                try? await session.send(packet)
            }

        case .gateway:
            // Forward to gateway service (we are a peer) or internet (we are gateway)
            if let gateway = gatewayService {
                await gateway.forwardToInternet(packet, from: await virtualNetwork.localMachineId)
            } else if let gatewayMachineId = await virtualNetwork.gatewayMachineId,
                      let session = await tunnelManager.getExistingSession(for: gatewayMachineId) {
                try? await session.send(packet)
            }

        case .drop(let reason):
            // Log and discard
            break
        }
    }

    private func handleNewSession(_ session: TunnelSession) async {
        let machineId = session.remoteMachineId

        // Start inbound routing for this session
        inboundTasks[machineId] = Task {
            for await packet in session.receive() {
                try? await localInterface.writePacket(packet)
            }
        }
    }
}
```

#### Unit Tests

```swift
// PacketRouterTests.swift
func testRouteToLocal() async throws {
    let interface = MockNetworkInterface(localIP: "10.0.0.5")
    let vnet = VirtualNetwork(localMachineId: "m1")
    await vnet.setLocalAddress("10.0.0.5")
    let tunnelManager = TunnelManager(provider: mockProvider)

    let router = PacketRouter(
        localInterface: interface,
        virtualNetwork: vnet,
        tunnelManager: tunnelManager
    )
    try await router.start()

    // Packet to self
    let packet = createIPPacket(src: "10.0.0.10", dst: "10.0.0.5")
    await interface.simulateAppSend(packet)

    try await Task.sleep(for: .milliseconds(50))

    // Should be delivered back to interface
    let received = await interface.getAppReceived()
    XCTAssertEqual(received, packet)
}

func testRouteToPeer() async throws {
    let interface = MockNetworkInterface(localIP: "10.0.0.5")
    let vnet = VirtualNetwork(localMachineId: "m1")
    await vnet.setLocalAddress("10.0.0.5")
    await vnet.registerAddress(ip: "10.0.0.10", machineId: "m2")

    let mockProvider = MockChannelProvider()
    let tunnelManager = TunnelManager(provider: mockProvider)
    await tunnelManager.start()

    // Pre-create session
    _ = try await tunnelManager.getSession(forPeerId: "peer2", machineId: "m2")

    let router = PacketRouter(
        localInterface: interface,
        virtualNetwork: vnet,
        tunnelManager: tunnelManager
    )
    try await router.start()

    // Send packet to peer
    let packet = createIPPacket(src: "10.0.0.5", dst: "10.0.0.10")
    await interface.simulateAppSend(packet)

    try await Task.sleep(for: .milliseconds(50))

    // Verify sent through tunnel
    let sent = await mockProvider.lastSentData(channel: "tunnel-packet")
    XCTAssertEqual(sent, packet)
}
```

#### Integration Tests: Multi-Node Single Machine

```swift
// PacketRouterMultiNodeTests.swift
func testThreeNodeNetwork() async throws {
    // Create 3 mock mesh nodes
    let node1 = MockMeshNode(peerId: "p1", machineId: "m1")
    let node2 = MockMeshNode(peerId: "p2", machineId: "m2")
    let node3 = MockMeshNode(peerId: "p3", machineId: "m3")

    // Connect all nodes
    node1.connectTo(node2)
    node1.connectTo(node3)
    node2.connectTo(node3)

    // Setup interfaces and routers
    let if1 = MockNetworkInterface(localIP: "10.0.0.100")
    let if2 = MockNetworkInterface(localIP: "10.0.0.101")
    let if3 = MockNetworkInterface(localIP: "10.0.0.102")

    let vnet1 = VirtualNetwork(localMachineId: "m1")
    await vnet1.setLocalAddress("10.0.0.100")
    await vnet1.registerAddress(ip: "10.0.0.101", machineId: "m2")
    await vnet1.registerAddress(ip: "10.0.0.102", machineId: "m3")

    let vnet2 = VirtualNetwork(localMachineId: "m2")
    await vnet2.setLocalAddress("10.0.0.101")
    await vnet2.registerAddress(ip: "10.0.0.100", machineId: "m1")
    await vnet2.registerAddress(ip: "10.0.0.102", machineId: "m3")

    let vnet3 = VirtualNetwork(localMachineId: "m3")
    await vnet3.setLocalAddress("10.0.0.102")
    await vnet3.registerAddress(ip: "10.0.0.100", machineId: "m1")
    await vnet3.registerAddress(ip: "10.0.0.101", machineId: "m2")

    let tm1 = TunnelManager(provider: node1)
    let tm2 = TunnelManager(provider: node2)
    let tm3 = TunnelManager(provider: node3)

    await tm1.start()
    await tm2.start()
    await tm3.start()

    let router1 = PacketRouter(localInterface: if1, virtualNetwork: vnet1, tunnelManager: tm1)
    let router2 = PacketRouter(localInterface: if2, virtualNetwork: vnet2, tunnelManager: tm2)
    let router3 = PacketRouter(localInterface: if3, virtualNetwork: vnet3, tunnelManager: tm3)

    try await router1.start()
    try await router2.start()
    try await router3.start()

    // Node 1 sends to Node 3
    let packet = createIPPacket(src: "10.0.0.100", dst: "10.0.0.102", payload: "hello")
    await if1.simulateAppSend(packet)

    try await Task.sleep(for: .milliseconds(100))

    // Node 3 should receive
    let received = await if3.getAppReceived()
    XCTAssertNotNil(received)
}
```

#### Manual Tests

```bash
swift test --filter PacketRouterTests
swift test --filter PacketRouterMultiNodeTests
```

**Deliverable:** Full packet routing working with multiple mock nodes on single machine.

---

### Phase 7: GatewayService

**Goal:** Create GatewayService with its own NetstackBridge for internet forwarding.

#### Architecture Context

GatewayService runs on the gateway machine (consumer). It receives packets from peers that are destined for the internet, injects them into its own netstack for real TCP/UDP handling, and routes responses back.

```
┌──────────────────────────────────────────────────────────────────┐
│  GatewayService (on gateway machine)                             │
│                                                                  │
│  ┌─────────────┐    ┌────────────────┐    ┌────────────────┐    │
│  │ Peer packet │───→│ NAT Table      │───→│ NetstackBridge │    │
│  │ (10.0.x→ext)│    │ (track origin) │    │ (real TCP/UDP) │    │
│  └─────────────┘    └────────────────┘    └───────┬────────┘    │
│                                                   │              │
│                                                   ▼              │
│                                              [Internet]          │
│                                                   │              │
│  ┌─────────────┐    ┌────────────────┐           │              │
│  │ Peer        │←───│ NAT lookup     │←──────────┘              │
│  │ (response)  │    │ (find origin)  │                          │
│  └─────────────┘    └────────────────┘                          │
└──────────────────────────────────────────────────────────────────┘
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/GatewayService.swift`

#### API

```swift
public actor GatewayService {
    private let internetNetstack: NetstackBridge
    private var natTable: [NATKey: MachineId] = [:]
    private var returnHandler: ((Data, MachineId) async -> Void)?

    public struct NATKey: Hashable {
        let srcIP: String
        let srcPort: UInt16
        let dstIP: String
        let dstPort: UInt16
        let proto: IPProtocol
    }

    public init() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1", mtu: 1500)
        self.internetNetstack = try NetstackBridge(config: config)

        internetNetstack.setReturnCallback { [weak self] packet in
            Task { await self?.handleInternetResponse(packet) }
        }
    }

    public func start() async throws {
        try internetNetstack.start()
    }

    public func setReturnHandler(_ handler: @escaping (Data, MachineId) async -> Void) {
        returnHandler = handler
    }

    /// Forward packet from peer to internet
    public func forwardToInternet(_ packet: Data, from sourceMachineId: MachineId) async {
        guard let natKey = extractNATKey(packet) else { return }

        // Record NAT mapping
        natTable[natKey] = sourceMachineId

        // Inject into netstack for real TCP/UDP handling
        try? internetNetstack.injectPacket(packet)
    }

    /// Handle response from internet
    private func handleInternetResponse(_ packet: Data) async {
        guard let returnKey = extractReturnNATKey(packet),
              let destMachineId = natTable[returnKey] else {
            return  // Unknown return, drop
        }

        await returnHandler?(packet, destMachineId)
    }
}
```

#### Unit Tests

```swift
// GatewayServiceTests.swift
func testNATTableTracking() async throws {
    let gateway = try GatewayService()

    let packet = createTCPPacket(
        src: "10.0.0.100", srcPort: 12345,
        dst: "8.8.8.8", dstPort: 443
    )
    await gateway.forwardToInternet(packet, from: "m1")

    // NAT table should have entry
    let natKey = GatewayService.NATKey(
        srcIP: "10.0.0.100", srcPort: 12345,
        dstIP: "8.8.8.8", dstPort: 443,
        proto: .tcp
    )
    // (Would need internal access or test helper to verify)
}

func testReturnPacketRouting() async throws {
    let gateway = try GatewayService()
    var routedPacket: (Data, MachineId)?

    await gateway.setReturnHandler { packet, machineId in
        routedPacket = (packet, machineId)
    }

    // Setup NAT entry by forwarding outbound
    let outbound = createTCPPacket(
        src: "10.0.0.100", srcPort: 12345,
        dst: "8.8.8.8", dstPort: 443
    )
    await gateway.forwardToInternet(outbound, from: "m1")

    // Simulate internet response (would come from netstack callback)
    // ... test internal method or use mock netstack
}
```

#### Manual Tests

```bash
swift test --filter GatewayServiceTests
```

**Deliverable:** GatewayService forwards internet traffic and tracks NAT for returns.

---

### Phase 8: Proxy & Port Forwarding

**Goal:** Implement SOCKS proxy and port forwarding for userspace mode.

#### Architecture Context

In userspace mode (no TUN), apps can't use standard sockets to reach mesh IPs. We provide:
- **SOCKS5 proxy:** Apps that support SOCKS can connect through it
- **Port forwarding:** Map local ports to mesh destinations

```
┌──────────────────────────────────────────────────────────────────┐
│  SOCKS5 Proxy (localhost:1080)                                   │
│                                                                  │
│  curl --socks5 localhost:1080 http://10.0.0.100/                 │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────┐    ┌─────────────────┐    ┌────────────────┐   │
│  │ SOCKS5      │───→│ NetworkInterface │───→│ Mesh routing   │   │
│  │ handshake   │    │ .dialTCP()       │    │                │   │
│  └─────────────┘    └─────────────────┘    └────────────────┘   │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  Port Forward (localhost:2222 → 10.0.0.100:22)                   │
│                                                                  │
│  ssh -p 2222 localhost                                           │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────┐    ┌─────────────────┐    ┌────────────────┐   │
│  │ Local TCP   │───→│ NetworkInterface │───→│ 10.0.0.100:22  │   │
│  │ listener    │    │ .dialTCP()       │    │                │   │
│  └─────────────┘    └─────────────────┘    └────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/SOCKSProxy.swift`
- `Sources/OmertaNetwork/PortForwarder.swift`

**Files to modify:**
- `Sources/OmertaCLI/main.swift` - Add proxy/forward commands
- `Sources/OmertaDaemon/OmertaDaemon.swift` - Add `--socks-proxy` flag

#### API

```swift
// SOCKSProxy.swift
public actor SOCKSProxy {
    private let port: UInt16
    private let networkInterface: any NetworkInterface
    private var listener: TCPListener?

    public private(set) var actualPort: UInt16 = 0

    public init(port: UInt16, interface: any NetworkInterface) {
        self.port = port
        self.networkInterface = interface
    }

    public func start() async throws {
        listener = try await TCPListener(port: port)
        actualPort = listener!.port

        Task {
            for try await client in listener!.connections {
                Task { await handleClient(client) }
            }
        }
    }

    private func handleClient(_ client: TCPConnection) async {
        // SOCKS5 handshake
        // 1. Greeting (version, auth methods)
        // 2. Auth (we support no-auth)
        // 3. Connect request (dest host:port)
        // 4. Dial via networkInterface
        // 5. Relay data bidirectionally
    }
}

// PortForwarder.swift
public actor PortForwarder {
    private let localPort: UInt16
    private let remoteHost: String
    private let remotePort: UInt16
    private let networkInterface: any NetworkInterface

    public func start() async throws {
        let listener = try await TCPListener(port: localPort)

        Task {
            for try await client in listener.connections {
                Task {
                    guard let remote = try await networkInterface.dialTCP(
                        host: remoteHost,
                        port: remotePort
                    ) else { return }

                    await relay(client, remote)
                }
            }
        }
    }
}
```

#### Unit Tests

```swift
// SOCKSProxyTests.swift
func testSOCKS5Handshake() async throws {
    let interface = MockNetworkInterface(localIP: "10.0.0.1")
    let proxy = SOCKSProxy(port: 0, interface: interface)
    try await proxy.start()

    let client = try await TCPConnection.connect(
        host: "127.0.0.1",
        port: await proxy.actualPort
    )

    // Send SOCKS5 greeting (no auth)
    try await client.write(Data([0x05, 0x01, 0x00]))

    // Should get response
    let response = try await client.read(2)
    XCTAssertEqual(response, Data([0x05, 0x00]))
}

// PortForwarderTests.swift
func testPortForward() async throws {
    let interface = MockNetworkInterface(localIP: "10.0.0.1")
    interface.mockDialTCP = { host, port in
        MockTCPConnection(responseData: Data("SSH-2.0-OpenSSH".utf8))
    }

    let forwarder = PortForwarder(
        localPort: 0,
        remoteHost: "10.0.0.100",
        remotePort: 22,
        interface: interface
    )
    try await forwarder.start()

    let client = try await TCPConnection.connect(
        host: "127.0.0.1",
        port: forwarder.actualPort
    )

    let data = try await client.read(15)
    XCTAssertEqual(String(data: data, encoding: .utf8), "SSH-2.0-OpenSSH")
}
```

#### Manual Tests

```bash
# Unit tests
swift test --filter SOCKSProxyTests
swift test --filter PortForwarderTests

# Manual: Start daemon with SOCKS proxy
./build/debug/omertad start --gateway --socks-proxy 1080 &

# Test with curl
curl --socks5 localhost:1080 http://10.0.0.100/

# Test port forward
./build/debug/omerta forward 2222:10.0.0.100:22 &
ssh -p 2222 localhost
```

**Deliverable:** SOCKS proxy and port forwarding work in userspace mode.

---

### Phase 9: TUN Interface (Linux)

**Goal:** Implement real TUN interface for Linux.

#### Architecture Context

TUN creates a real network interface in the kernel. Apps use standard sockets, kernel routes packets to/from the TUN device, omertad reads/writes packets.

```
┌──────────────────────────────────────────────────────────────────┐
│  Linux Kernel                                                    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  omerta0 interface (10.0.0.x/16)                         │   │
│  │  - Created via /dev/net/tun                              │   │
│  │  - Configured with ip addr, ip link                      │   │
│  └────────────────────────┬─────────────────────────────────┘   │
│                           │ read/write                           │
│  ┌────────────────────────▼─────────────────────────────────┐   │
│  │  TUNInterface (userspace)                                │   │
│  │  - Opens /dev/net/tun with IFF_TUN | IFF_NO_PI           │   │
│  │  - Reads outbound packets (apps → mesh)                  │   │
│  │  - Writes inbound packets (mesh → apps)                  │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/TUNInterface.swift`
- `Sources/OmertaNetwork/BuildCapabilities.swift`

#### API

```swift
// TUNInterface.swift
#if os(Linux)
public actor TUNInterface: NetworkInterface {
    public let localIP: String
    private let name: String
    private var fd: Int32 = -1

    public init(name: String, ip: String) throws {
        self.name = name
        self.localIP = ip
    }

    public func start() async throws {
        // Open /dev/net/tun
        fd = open("/dev/net/tun", O_RDWR)
        guard fd >= 0 else {
            throw TUNError.openFailed(errno)
        }

        // Configure interface
        var ifr = ifreq()
        withUnsafeMutableBytes(of: &ifr.ifr_name) { ptr in
            _ = name.utf8CString.withUnsafeBufferPointer { src in
                memcpy(ptr.baseAddress!, src.baseAddress!, min(ptr.count, src.count))
            }
        }
        ifr.ifr_flags = Int16(IFF_TUN | IFF_NO_PI)

        guard ioctl(fd, TUNSETIFF, &ifr) >= 0 else {
            close(fd)
            throw TUNError.ioctlFailed(errno)
        }

        // Configure IP
        try configureIP()
    }

    public func stop() async {
        if fd >= 0 {
            close(fd)
            fd = -1
        }
        // Remove interface
        _ = try? Process.run("/sbin/ip", arguments: ["link", "delete", name])
    }

    public func readPacket() async throws -> Data {
        var buffer = [UInt8](repeating: 0, count: 1500)
        let n = read(fd, &buffer, buffer.count)
        guard n > 0 else {
            throw TUNError.readFailed(errno)
        }
        return Data(buffer[..<n])
    }

    public func writePacket(_ packet: Data) async throws {
        try packet.withUnsafeBytes { ptr in
            let n = write(fd, ptr.baseAddress!, packet.count)
            guard n == packet.count else {
                throw TUNError.writeFailed(errno)
            }
        }
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        nil  // TUN mode uses kernel TCP
    }

    private func configureIP() throws {
        // ip addr add 10.0.0.x/16 dev omerta0
        _ = try Process.run("/sbin/ip", arguments: [
            "addr", "add", "\(localIP)/16", "dev", name
        ])
        // ip link set omerta0 up
        _ = try Process.run("/sbin/ip", arguments: [
            "link", "set", name, "up"
        ])
    }
}
#endif

// BuildCapabilities.swift
public enum BuildCapabilities {
    #if OMERTA_APPSTORE_BUILD
    public static let tunSupported = false
    #elseif os(Linux)
    public static let tunSupported = true
    #elseif os(macOS)
    public static let tunSupported = true  // via utun
    #else
    public static let tunSupported = false
    #endif
}
```

#### Unit Tests (Requires Root)

```swift
// TUNInterfaceTests.swift
#if os(Linux)
func testTUNCreation() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    let tun = try TUNInterface(name: "omerta-test0", ip: "10.99.0.1")
    try await tun.start()
    defer { Task { await tun.stop() } }

    // Verify interface exists
    let result = try Process.run("/sbin/ip", arguments: ["addr", "show", "omerta-test0"])
    XCTAssertTrue(result.output.contains("10.99.0.1"))
}
#endif
```

#### Manual Tests

```bash
# On Linux, as root
sudo swift test --filter TUNInterfaceTests

# Verify interface creation
sudo swift run omertad start --vpn --test-mode &
ip addr show omerta0
ping -c 1 10.0.0.1  # Should respond
```

**Deliverable:** TUN interface works on Linux with root.

---

### Phase 10: Two-Machine Test (Userspace)

**Goal:** Test packet routing between two physical machines using userspace networking.

**No new code** - integration testing of existing components.

#### Manual Tests

**Setup:**
```bash
# On local (192.168.1.10)
cd ~/omerta
swift build

# On arch-home (192.168.1.20)
ssh arch-home
cd ~/omerta-native
git pull origin master
source ~/.local/share/swiftly/env.sh
swift build
```

**Test 1: Two nodes, userspace, mesh connection**
```bash
# Terminal 1 - Local as gateway
./build/debug/omertad start --port 18002 --gateway

# Note the peer ID from output, e.g., "abc123..."

# Terminal 2 - arch-home as peer
ssh arch-home
./.build/debug/omertad start --port 18002 --bootstrap "abc123...@192.168.1.10:18002"

# Verify mesh connection
# On local:
./build/debug/omerta mesh status
# Should show arch-home as peer

# On arch-home:
./.build/debug/omerta mesh status
# Should show local as peer
```

**Test 2: DHCP address allocation**
```bash
# With both nodes from Test 1 running

# Verify IP assignment
# On arch-home:
./.build/debug/omerta network address
# Should show 10.0.0.100

# On local:
./build/debug/omerta dhcp leases
# Should show arch-home's machine ID with 10.0.0.100
```

**Test 3: Packet routing (userspace ping)**
```bash
# On local (10.0.0.1 gateway):
./build/debug/omerta ping 10.0.0.100
# Should show responses from arch-home

# On arch-home (10.0.0.100):
./.build/debug/omerta ping 10.0.0.1
# Should show responses from local
```

**Deliverable:** Two physical machines communicate via virtual network in userspace.

---

### Phase 11: Three-Machine Test

**Goal:** Test with all three available machines (local, arch-home, Mac).

#### Manual Tests

**Test 1: Three-node mesh**
```bash
# Terminal 1 - Local as gateway
./build/debug/omertad start --port 18002 --gateway

# Terminal 2 - arch-home
ssh arch-home
./.build/debug/omertad start --port 18002 --bootstrap "<local>@192.168.1.10:18002"

# Terminal 3 - Mac
ssh mac
cd ~/omerta
./build/debug/omertad start --port 18002 --bootstrap "<local>@192.168.1.10:18002"

# Verify all three connected
./build/debug/omerta mesh status
# Should show 3 peers

./build/debug/omerta network peers
# Should show:
# 10.0.0.1 = local (gateway)
# 10.0.0.100 = arch-home
# 10.0.0.101 = mac
```

**Test 2: Cross-machine ping**
```bash
# From arch-home, ping mac
./.build/debug/omerta ping 10.0.0.101

# From mac, ping arch-home
./build/debug/omerta ping 10.0.0.100
```

**Test 3: Direct peer-to-peer routing**
```bash
# Verify packets go direct, not through gateway
# On arch-home:
./.build/debug/omerta tunnel sessions
# Should show direct session to mac
```

**Deliverable:** Three machines form mesh, packets route directly between peers.

---

### Phase 12: TUN Mode Test (Linux)

**Goal:** Test with real TUN interfaces on Linux machines.

#### Manual Tests

**Test 1: Local with TUN**
```bash
# On local (as root)
sudo ./build/debug/omertad start --port 18002 --gateway --vpn

# Verify interface
ip addr show omerta0
# → inet 10.0.0.1/16
```

**Test 2: Two Linux machines with TUN**
```bash
# Terminal 1 - Local as gateway with TUN
sudo ./build/debug/omertad start --port 18002 --gateway --vpn

# Terminal 2 - arch-home with TUN
ssh arch-home
sudo ./.build/debug/omertad start --port 18002 --vpn --bootstrap "<local>@192.168.1.10:18002"

# Standard ping should work
# On arch-home:
ping 10.0.0.1

# On local:
ping 10.0.0.100
```

**Test 3: Standard SSH over TUN**
```bash
# From local (with TUN):
ssh user@10.0.0.100
# Should connect to arch-home via mesh!
```

**Deliverable:** Standard network tools (ping, ssh) work over TUN interface.

---

### Phase 13: Gateway Internet Access

**Goal:** Test internet access through gateway's netstack.

#### Manual Tests

**Test 1: Internet via gateway**
```bash
# Terminal 1 - Local as gateway
./build/debug/omertad start --port 18002 --gateway

# Terminal 2 - arch-home with TUN
ssh arch-home
sudo ./.build/debug/omertad start --port 18002 --vpn --bootstrap "<local>@192.168.1.10:18002"

# Set default route through mesh
sudo ip route add default via 10.0.0.1 dev omerta0

# Test internet access
curl -I https://google.com
# Should work! Traffic: arch-home → omerta0 → mesh → gateway → netstack → internet
```

**Deliverable:** Peers can reach internet through gateway.

---

### Phase 14: Mac Userspace + OmertaSSH

**Goal:** Test Mac in userspace mode with OmertaSSH client.

#### Manual Tests

**Test 1: Mac userspace connects to Linux TUN**
```bash
# Terminal 1 - arch-home with TUN (sshd running)
ssh arch-home
sudo ./.build/debug/omertad start --port 18002 --vpn --bootstrap "<local>@192.168.1.10:18002"

# Terminal 2 - Local as gateway
./build/debug/omertad start --port 18002 --gateway

# Terminal 3 - Mac userspace
ssh mac
./build/debug/omertad start --port 18002 --bootstrap "<local>@192.168.1.10:18002"

# Mac gets IP via DHCP
./build/debug/omerta network address
# → 10.0.0.101

# OmertaSSH from Mac to arch-home
./build/debug/omerta ssh user@10.0.0.100
# Should connect!
```

**Test 2: Standard ssh vs OmertaSSH**
```bash
# Standard ssh won't work (no TUN interface)
ssh user@10.0.0.100
# → No route to host

# OmertaSSH works (uses netstack dial)
./build/debug/omerta ssh user@10.0.0.100
# → Connected
```

**Deliverable:** Mac userspace connects via OmertaSSH to Linux TUN peers.

---

### Phase 15: VM Network Integration

**Goal:** Test VMs joining the virtual network as first-class peers.

#### Integration Tests

```swift
// VMNetworkIntegrationTests.swift
func testVMJoinsNetwork() async throws {
    guard VMManager.isAvailable else {
        throw XCTSkip("VM support not available")
    }

    let gateway = try await startGateway()
    defer { await gateway.stop() }

    let vm = try await VMManager.create(config: .meshEnabled(bootstrap: gateway))
    defer { await vm.destroy() }

    try await vm.waitForMeshJoin(timeout: 60)

    let vmIP = try await vm.getMeshIP()
    XCTAssertTrue(vmIP.hasPrefix("10.0.0."))
}

func testSSHToVMOverMesh() async throws {
    guard VMManager.isAvailable else {
        throw XCTSkip("VM support not available")
    }

    let gateway = try await startGateway()
    let vm = try await VMManager.create(config: .meshEnabled(bootstrap: gateway))
    defer { await gateway.stop(); await vm.destroy() }

    try await vm.waitForMeshJoin(timeout: 60)
    let vmIP = try await vm.getMeshIP()

    let ssh = try await OmertaSSH.connect(
        host: vmIP, port: 22, user: "omerta",
        networkInterface: gateway.networkInterface
    )

    let result = try await ssh.execute("whoami")
    XCTAssertEqual(result.trimmed, "omerta")
}
```

#### Manual Tests

**Test 1: VM joins network**
```bash
# Terminal 1 - Mac as provider with gateway
ssh mac
./build/debug/omertad start --port 18002 --gateway --provider

# Terminal 2 - Request VM
./build/debug/omerta vm request --wait
# VM boots and joins mesh

# Verify VM joined
./build/debug/omerta network peers
# Should show VM with 10.0.0.100
```

**Test 2: SSH to VM from consumer**
```bash
# Terminal 1 - Mac provider/gateway (running)

# Terminal 2 - Local as consumer
./build/debug/omertad start --port 18002 --bootstrap "<mac>@..."

# OmertaSSH to VM
./build/debug/omerta ssh omerta@10.0.0.100
# Should connect!

whoami
# → omerta
```

**Test 3: Consumer with TUN SSH to VM**
```bash
# Terminal 2 - Local with TUN
sudo ./build/debug/omertad start --port 18002 --vpn --bootstrap "<mac>@..."

# Standard SSH works
ssh omerta@10.0.0.100
# → Connected (via kernel TCP over TUN)
```

**Test 4: VM-to-VM communication**
```bash
# Request second VM
./build/debug/omerta vm request --wait

# From VM 1:
ping 10.0.0.102
ssh omerta@10.0.0.102
```

**Deliverable:** VMs join mesh as first-class peers, SSH works from any mesh node.

---

### Phase 16: Full Integration & Cleanup

**Goal:** Final integration, cleanup legacy code, comprehensive testing.

#### Changes

1. Remove legacy `TunnelRole` code from TunnelSession
2. Remove legacy provider-proxy code paths
3. Add CLI commands: `network join`, `network peers`, `dhcp leases`, `tunnel sessions`
4. Documentation updates

#### Integration Tests

```swift
// FullIntegrationTests.swift
func testCompleteNetworkLifecycle() async throws {
    // 1. Start gateway
    let gateway = try await startGateway()

    // 2. Start 3 peers (mock)
    let peers = try await (1...3).asyncMap { _ in
        try await startPeer(bootstrap: gateway)
    }

    // 3. All obtain IPs via DHCP
    for peer in peers {
        let ip = await peer.virtualNetwork.localIP
        XCTAssertNotNil(ip)
    }

    // 4. All can ping each other
    // 5. One peer accesses internet via gateway
    // 6. One peer leaves
    // 7. New peer joins, gets released IP
    // 8. Gateway restarts, leases persist
}
```

#### Manual Tests - Full Scenario

```bash
# Complete test scenario

# 1. Local as gateway (TUN)
sudo ./build/debug/omertad start --port 18002 --gateway --vpn

# 2. arch-home joins (TUN)
ssh arch-home
sudo ./.build/debug/omertad start --port 18002 --vpn --bootstrap "<local>@..."

# 3. Mac as provider (userspace)
ssh mac
./build/debug/omertad start --port 18002 --provider --bootstrap "<local>@..."

# 4. Request VM
./build/debug/omerta vm request --wait

# 5. Verify network
./build/debug/omerta network peers
# 10.0.0.1 = Local (gateway)
# 10.0.0.100 = arch-home
# 10.0.0.101 = Mac
# 10.0.0.102 = VM

# 6. Cross-machine tests
# arch-home: ssh omerta@10.0.0.102 (VM)
# mac: omerta ssh omerta@10.0.0.102 (VM via userspace)
# VM: ping 10.0.0.100 (arch-home)
# arch-home: curl https://google.com (internet via gateway)

# 7. Gateway restart
# Ctrl+C, restart gateway
sudo ./build/debug/omertad start --port 18002 --gateway --vpn

# 8. Verify reconnection
./build/debug/omerta dhcp leases
# IPs preserved
```

**Deliverable:** Complete virtual network system working across all machines, VMs, and modes.

---

## Test Summary Matrix

| Phase                | Unit Tests | Integration Tests | Manual Tests              |
|----------------------|------------|-------------------|---------------------------|
| 1. TunnelSession     | ✓          | ✓ (mock)          | swift test                |
| 2. TunnelManager     | ✓          | ✓ (mock)          | swift test                |
| 3. VirtualNetwork    | ✓          | ✓ (mock)          | swift test                |
| 4. DHCP              | ✓          | ✓ (mock)          | swift test                |
| 5. NetworkInterface  | ✓          | ✓ (mock)          | swift test                |
| 6. PacketRouter      | ✓          | ✓ (multi-node)    | swift test                |
| 7. GatewayService    | ✓          | ✓ (mock)          | swift test                |
| 8. Proxy & Port Fwd  | ✓          | ✓ (mock)          | swift test                |
| 9. TUN Interface     | ✓ (root)   | ✓ (root)          | sudo swift test           |
| 10. Two-Machine      | -          | -                 | local + arch-home         |
| 11. Three-Machine    | -          | -                 | local + arch-home + mac   |
| 12. TUN Mode         | -          | -                 | Linux with TUN            |
| 13. Gateway Internet | -          | -                 | Internet via gateway      |
| 14. Mac Userspace    | -          | -                 | OmertaSSH from Mac        |
| 15. VM Integration   | -          | ✓ (VM)            | VM + SSH tests            |
| 16. Full Integration | ✓          | ✓                 | All machines, VMs         |

---

## Quick Reference: Test Commands

```bash
# Phase 1-9: Unit tests
swift test --filter TunnelSessionTests
swift test --filter TunnelManagerTests
swift test --filter VirtualNetworkTests
swift test --filter DHCPTests
swift test --filter NetworkInterfaceTests
swift test --filter PacketRouterTests
swift test --filter GatewayServiceTests
swift test --filter SOCKSProxyTests
sudo swift test --filter TUNInterfaceTests

# All unit tests
swift test

# Multi-machine setup
# Local:
./build/debug/omertad start --port 18002 --gateway

# arch-home:
./.build/debug/omertad start --port 18002 --bootstrap "<local>@192.168.1.10:18002"

# Mac:
./build/debug/omertad start --port 18002 --bootstrap "<local>@192.168.1.10:18002"

# Status commands
./build/debug/omerta mesh status
./build/debug/omerta network peers
./build/debug/omerta network address
./build/debug/omerta dhcp leases
./build/debug/omerta tunnel sessions
```
