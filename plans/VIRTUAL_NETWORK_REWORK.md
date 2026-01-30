# Virtual Network Architecture Rework

## Overview

Redesign the mesh network to support a true virtual LAN where:
1. VMs run omertad and are first-class mesh participants
2. Machines have LAN addresses (10.x.x.x) mapped to their machine IDs
3. Consumer acts as internet gateway
4. Tunnel sessions are created on-demand based on LAN address routing
5. **Dual interface modes:** Both userspace (netstack) and kernel (TUN) from the start

## Architecture

Each machine runs the same stack. The NetworkInterface (netstack or TUN) is the
local packet I/O layer — it produces and consumes raw IP packets. PacketRouter
reads those packets, uses VirtualNetwork to decide which peer machine they
should go to, and sends them through TunnelManager over the mesh. On the
receiving end, the peer's PacketRouter writes the packet into that machine's
NetworkInterface.

```
Per-Machine Stack:

  App (standard sockets / netstack dial API)
       │
       ▼
  ┌─────────────────────────────────────────┐
  │  NetworkInterface                       │
  │  (NetstackBridge or TUN — swappable)    │
  │  ├── readPacket()   (outbound from app) │
  │  └── writePacket()  (inbound to app)    │
  └──────────────┬──────────────────────────┘
                 │ raw IP packets
                 ▼
  ┌─────────────────────────────────────────┐
  │  PacketRouter                           │
  │  ├── Reads packets from interface       │
  │  ├── Routes via VirtualNetwork          │
  │  │   .local → deliver back to interface │
  │  │   .peer  → send via TunnelSession    │
  │  │   .gateway → send to gateway machine │
  │  └── Writes inbound packets to iface    │
  └──────────────┬──────────────────────────┘
                 │
                 ▼
  ┌─────────────────────────────────────────┐
  │  TunnelManager → TunnelSessions         │
  │  └── Mesh channel transport             │
  └─────────────────────────────────────────┘
```

Two machines communicating:
```
Machine A                                    Machine B
┌────────────────┐                          ┌────────────────┐
│ App            │                          │ App            │
│   ↕            │                          │   ↕            │
│ NetworkIface   │                          │ NetworkIface   │
│ (netstack/TUN) │                          │ (netstack/TUN) │
│   ↕            │                          │   ↕            │
│ PacketRouter   │                          │ PacketRouter   │
│   ↕            │                          │   ↕            │
│ TunnelSession ═══════ mesh channel ═══════│ TunnelSession  │
└────────────────┘                          └────────────────┘
```

## Interface Modes

The NetworkInterface is swappable. The rest of the stack (PacketRouter,
VirtualNetwork, TunnelManager) is identical regardless of which mode is used.

### Kernel Mode (TUN Interface) - Requires Root
```
┌───────────────────────────────────────┐
│  omerta0 interface (10.0.x.x)         │
│  ├── Real OS interface                │
│  ├── Standard socket APIs work        │
│  ├── sshd, nginx, etc bind normally   │
│  └── ifconfig/ip addr visible         │
└───────────────┬───────────────────────┘
                │ raw IP packets
                ▼
         PacketRouter → mesh
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
└───────────────┬───────────────────────┘
                │ raw IP packets
                ▼
┌───────────────────────────────────────┐
│  NetstackBridge (gVisor TCP/IP)       │
│  └── Userspace TCP/IP stack           │
└───────────────┬───────────────────────┘
                │ raw IP packets
                ▼
         PacketRouter → mesh
```

**Use cases:**
- **Consumer without root:** Use OmertaSSH client to reach VMs
- **Fallback:** When TUN unavailable (no permissions, platform limits)
- **Testing:** Simpler setup for development

### Build Configuration

- **App Store build** (`OMERTA_APPSTORE_BUILD`): Userspace only
- **Direct build** (Linux): Both modes available, TUN requires root
- **Direct build** (macOS): Userspace only — kernel networking (TUN/utun) not yet implemented

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

**Goal:** Rework TunnelManager to maintain a pool of sessions keyed by (machineId, channel), with health monitoring for connection reliability.

#### Architecture Context

**Current state:** TunnelManager already uses `MachineId` throughout (not `PeerId`). It uses `sendOnChannel(_:toMachine:channel:)` for targeted sends. However, it only supports one session at a time.

**New:** TunnelManager maintains multiple sessions keyed by TunnelSessionKey. Sessions are created on-demand when packets need to be sent. Multiple channels to the same machine are supported.

**Separation of concerns:**
- **MeshNetwork** handles the mechanics: hole-punching, relay coordination, endpoint discovery
- **TunnelManager** triggers and monitors connections: sends probes to force establishment, tracks health

The tunnel layer is agnostic to how connections are established (cloister, manual key, etc.) — it triggers establishment by sending packets, then monitors health.

**Reactive vs Proactive:** The base MeshNetwork establishes connections *reactively* when user traffic flows. TunnelManager is *proactive*:
- **Eager establishment** — Sends probe packets immediately to force hole-punch/relay, not waiting for user data
- **Health probing** — Continuous probes even when idle, detecting problems before they impact traffic
- **Latency tracking** — Continuous RTT measurement for connection quality visibility
- **Endpoint switching** — Can request the mesh to try alternative endpoints when health degrades

This is per-machine, not per-session. Multiple sessions to the same machine share connection state.

```
┌───────────────────────────────────────────────────────────────────┐
│  TunnelManager                                                    │
│  ├── sessions: [TunnelSessionKey: TunnelSession]                  │
│  │   └── Keyed by (machineId, channel)                            │
│  ├── (internal) healthState: [MachineId: EndpointHealth]          │
│  │   └── Probes, latency, failure count (monitoring only)         │
│  ├── getSession(machineId:channel:)                               │
│  ├── closeSession(key:)                                           │
│  └── onSessionEstablished(handler:)                               │
└───────────────────────────────────────────────────────────────────┘

Public:   (machineId, channel) → TunnelSession
Internal: machineId → health monitoring state
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
    private var healthState: [MachineId: EndpointHealth] = [:]  // Per-machine health tracking
    private var healthMonitors: [MachineId: Task<Void, Never>] = [:]
    private let provider: any ChannelProvider
    private let config: TunnelManagerConfig

    /// Callback when a new session is established (incoming or outgoing)
    private var sessionEstablishedHandler: ((TunnelSession) async -> Void)?

    public init(provider: any ChannelProvider, config: TunnelManagerConfig = .default) {
        self.provider = provider
        self.config = config
    }

    /// Get or create a session to a specific machine on a specific channel.
    /// Proactively establishes connection by sending probes (doesn't wait for user traffic).
    public func getSession(
        machineId: MachineId,
        channel: String
    ) async throws -> TunnelSession {
        let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)

        if let existing = sessions[key] {
            return existing
        }

        // Proactively establish connection if this is first session to this machine
        if healthState[machineId] == nil {
            try await establishConnection(to: machineId)
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

    /// Internal: proactively establish connection by sending probes
    /// This triggers the mesh's hole-punch/relay mechanisms immediately,
    /// rather than waiting for user traffic.
    private func establishConnection(to machineId: MachineId) async throws {
        healthState[machineId] = EndpointHealth(state: .connecting)

        // Send initial probes to force connection establishment
        // The mesh will do hole-punch/relay as needed
        for attempt in 1...config.initialProbeAttempts {
            do {
                let start = ContinuousClock.now
                try await sendProbe(to: machineId)
                let latency = ContinuousClock.now - start
                healthState[machineId]?.recordSuccess(latencyMs: Int(latency.components.milliseconds))

                // Connection established, start ongoing monitoring
                startHealthMonitor(for: machineId)
                return
            } catch {
                if attempt == config.initialProbeAttempts {
                    healthState[machineId] = nil
                    throw TunnelError.connectionFailed("Failed to establish connection after \(attempt) attempts")
                }
                try? await Task.sleep(for: .milliseconds(config.initialProbeRetryMs))
            }
        }
    }

    /// Internal: start ongoing health monitoring for a machine
    private func startHealthMonitor(for machineId: MachineId) {
        healthMonitors[machineId] = Task {
            await runHealthProbes(for: machineId)
        }
    }

    /// Internal: run periodic health probes
    private func runHealthProbes(for machineId: MachineId) async {
        while !Task.isCancelled {
            try? await Task.sleep(for: .milliseconds(config.probeIntervalMs))
            let start = ContinuousClock.now
            do {
                try await sendProbe(to: machineId)
                let latency = ContinuousClock.now - start
                healthState[machineId]?.recordSuccess(latencyMs: Int(latency.components.milliseconds))
            } catch {
                healthState[machineId]?.recordFailure()
                // If too many failures, could request endpoint change from mesh
            }
        }
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

    // Proactive connection establishment — triggers hole-punch/relay immediately
    public var initialProbeAttempts: Int = 5    // Attempts to establish connection
    public var initialProbeRetryMs: Int = 500   // Delay between initial attempts

    // Ongoing health monitoring — detects problems before they impact traffic
    public var probeIntervalMs: Int = 5000      // How often to probe established connections
    public var probeTimeoutMs: Int = 2000       // When to consider a probe failed
    public var failureThreshold: Int = 3        // Failures before requesting endpoint change

    public static let `default` = TunnelManagerConfig()
}

// MARK: - Health Monitoring (Internal)
//
// TunnelManager monitors connection health for each remote machine.
// Multiple sessions to the same machine share health state.
// Connection establishment (hole-punch, relay) is handled by MeshNetwork.
//
// Internal state:
// - healthState: [MachineId: EndpointHealth] — latency, failure count
// - healthMonitors: [MachineId: Task] — continuous probe tasks
//
// Internal behavior:
// - getSession() starts health monitoring if not already running
// - Health probes run continuously via ping/pong messages
// - Tracks latency and consecutive failures
// - Can request mesh to try alternative endpoints on degradation

/// Health tracking for a machine's connection
struct EndpointHealth {
    var latencyMs: Int?
    var consecutiveFailures: Int = 0
    var lastProbeTime: Date?

    mutating func recordSuccess(latencyMs: Int) {
        self.latencyMs = latencyMs
        self.consecutiveFailures = 0
        self.lastProbeTime = Date()
    }

    mutating func recordFailure() {
        self.consecutiveFailures += 1
        self.lastProbeTime = Date()
    }
}
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
    private let bridge: any NetstackBridgeProtocol
    private var outboundStream: AsyncStream<Data>!
    private var outboundContinuation: AsyncStream<Data>.Continuation!
    private var isRunning = false

    /// Initialize with a netstack bridge (dependency injection for testability)
    public init(localIP: String, bridge: any NetstackBridgeProtocol) {
        self.localIP = localIP
        self.bridge = bridge

        let (stream, continuation) = AsyncStream<Data>.makeStream()
        self.outboundStream = stream
        self.outboundContinuation = continuation
    }

    public func start() async throws {
        guard !isRunning else { throw InterfaceError.alreadyStarted }
        let continuation = self.outboundContinuation!
        await bridge.setReturnCallback { packet in
            continuation.yield(packet)
        }
        try await bridge.start()
        isRunning = true
    }

    public func stop() async {
        guard isRunning else { return }
        isRunning = false
        await bridge.stop()
        outboundContinuation.finish()
    }

    public func readPacket() async throws -> Data {
        guard isRunning else { throw InterfaceError.notStarted }
        for await packet in outboundStream {
            return packet
        }
        throw InterfaceError.closed
    }

    public func writePacket(_ packet: Data) async throws {
        guard isRunning else { throw InterfaceError.notStarted }
        try await bridge.injectPacket(packet)
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        guard isRunning else { throw InterfaceError.notStarted }
        return try await bridge.dialTCP(host: host, port: port)
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
        guard let destIP = extractDestinationIP(from: packet) else { return }

        let decision = await virtualNetwork.route(destinationIP: destIP)

        switch decision {
        case .local:
            try? await localInterface.writePacket(packet)

        case .peer(let machineId):
            // Send via tunnel — get or create session on "packet" channel
            let key = TunnelSessionKey(remoteMachineId: machineId, channel: "packet")
            if let session = await tunnelManager.getExistingSession(key: key) {
                try? await session.send(packet)
            } else {
                let session = try? await tunnelManager.getSession(machineId: machineId, channel: "packet")
                if let session {
                    await setupInboundRouting(for: session)
                    try? await session.send(packet)
                }
            }

        case .gateway:
            // If we ARE the gateway, forward locally
            if let gatewayService {
                guard let sourceIP = extractSourceIP(from: packet),
                      let machineId = await virtualNetwork.lookupMachine(ip: sourceIP) else { return }
                await gatewayService.forwardToInternet(packet, from: machineId)
            } else if let gatewayMachineId = await virtualNetwork.getGatewayMachineId() {
                // Send to gateway via tunnel
                let key = TunnelSessionKey(remoteMachineId: gatewayMachineId, channel: "packet")
                if let session = await tunnelManager.getExistingSession(key: key) {
                    try? await session.send(packet)
                } else {
                    let session = try? await tunnelManager.getSession(machineId: gatewayMachineId, channel: "packet")
                    if let session {
                        await setupInboundRouting(for: session)
                        try? await session.send(packet)
                    }
                }
            }

        case .drop:
            break
        }
    }

    /// Set up inbound routing using callback pattern (not AsyncSequence)
    private func setupInboundRouting(for session: TunnelSession) async {
        await session.onReceive { [weak self] packet in
            guard let self else { return }
            await self.handleInboundPacket(packet, from: await session.remoteMachineId)
        }
    }

    private func handleInboundPacket(_ packet: Data, from machineId: MachineId) async {
        // If we are the gateway and this is internet-bound, forward it
        if let gatewayService {
            if let destIP = extractDestinationIP(from: packet) {
                let decision = await virtualNetwork.route(destinationIP: destIP)
                if case .gateway = decision {
                    await gatewayService.forwardToInternet(packet, from: machineId)
                    return
                }
            }
        }
        try? await localInterface.writePacket(packet)
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

**Goal:** Create GatewayService for internet forwarding, supporting both netstack and TUN bridge modes.

#### Architecture Context

GatewayService runs on the gateway machine (consumer). It receives packets from peers that are destined for the internet and forwards them out to the real network. Two modes are supported:

**Mode 1: Netstack (userspace)** — GatewayService injects packets into its own NetstackBridge, which makes real TCP/UDP connections and returns responses. Requires NAT tracking to route responses back to the originating peer.

```
┌──────────────────────────────────────────────────────────────────┐
│  GatewayService — Netstack Mode                                  │
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

**Mode 2: TUN bridge (kernel)** — The gateway has a TUN interface (`omerta0`) and bridges it to a real NIC (e.g., `eth0`) using standard Linux IP forwarding and iptables NAT. No userspace netstack needed on the gateway side — the kernel handles TCP/IP and NAT natively. Packets from peers arrive via tunnel, get written to `omerta0`, and the kernel forwards them out `eth0`.

```
┌──────────────────────────────────────────────────────────────────┐
│  GatewayService — TUN Bridge Mode                                │
│                                                                  │
│  Peer packet ───→ omerta0 (TUN) ───→ kernel IP forwarding       │
│                                          │                       │
│                                          ▼                       │
│                                     iptables MASQUERADE          │
│                                          │                       │
│                                          ▼                       │
│                                     eth0 → [Internet]            │
│                                          │                       │
│  Peer ←─── omerta0 ←─── kernel ←────────┘                       │
└──────────────────────────────────────────────────────────────────┘

Setup: sysctl net.ipv4.ip_forward=1
       iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -o eth0 -j MASQUERADE
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/GatewayService.swift`

#### API

```swift
public enum IPProtocol: Equatable, Hashable, Sendable {
    case tcp, udp, other(UInt8)
}

/// NAT key using UInt32 IPs for efficient packet parsing
public struct NATKey: Hashable, Sendable {
    public let srcIP: UInt32
    public let srcPort: UInt16
    public let dstIP: UInt32
    public let dstPort: UInt16
    public let proto: IPProtocol

    public func reversed() -> NATKey {
        NATKey(srcIP: dstIP, srcPort: dstPort, dstIP: srcIP, dstPort: srcPort, proto: proto)
    }
}

public struct NATEntry: Sendable {
    public let machineId: MachineId
    public let createdAt: Date
}

/// Forwards internet-bound packets from peers via a NetstackBridge.
/// Takes the bridge via init for testability (can use stub or real netstack).
public actor GatewayService {
    private let bridge: any NetstackBridgeProtocol
    private let natTimeout: TimeInterval
    private var natTable: [NATKey: NATEntry] = [:]
    private var returnHandler: (@Sendable (Data, MachineId) async -> Void)?
    private var running = false

    public init(bridge: any NetstackBridgeProtocol, natTimeout: TimeInterval = 120) {
        self.bridge = bridge
        self.natTimeout = natTimeout
    }

    public func start() async throws {
        running = true
        await bridge.setReturnCallback { [weak self] packet in
            guard let self else { return }
            Task { await self.handleReturnPacket(packet) }
        }
        try await bridge.start()
    }

    public func stop() async {
        running = false
        await bridge.stop()
    }

    public func setReturnHandler(_ handler: @escaping @Sendable (Data, MachineId) async -> Void) {
        self.returnHandler = handler
    }

    /// Forward packet from peer to internet
    public func forwardToInternet(_ packet: Data, from machineId: MachineId) async {
        guard running else { return }
        guard let key = Self.extractNATKey(from: packet) else { return }

        natTable[key] = NATEntry(machineId: machineId, createdAt: Date())
        try? await bridge.injectPacket(packet)
    }

    /// Handle response from internet — reverse NAT lookup to find originating peer
    private func handleReturnPacket(_ packet: Data) async {
        guard let key = Self.extractNATKey(from: packet) else { return }
        let reverseKey = key.reversed()
        guard let entry = natTable[reverseKey] else { return }
        await returnHandler?(packet, entry.machineId)
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

### Phase 9: TUN Interface (Linux Only)

**Goal:** Implement real TUN interface for Linux, usable both as a mesh node's
local interface and as a gateway's internet bridge.

> **Platform note:** This phase is Linux-only. macOS uses a different kernel
> interface (`utun` via `NetworkExtension.framework`) which is not yet
> implemented. On macOS, use the userspace netstack mode (DemoSOCKSGateway).

#### Architecture Context

TUN creates a real network interface in the kernel. Apps use standard sockets,
kernel routes packets to/from the TUN device, omertad reads/writes packets.

A single `TUNInterface` implementation serves **two roles**:

1. **Node mode** — local interface for mesh apps (replaces NetstackInterface).
   PacketRouter reads outbound packets from TUN, routes them through the mesh,
   and writes inbound packets back to TUN for delivery to apps.

2. **Bridge mode** — internet exit for the gateway (replaces NetstackBridge).
   GatewayService writes internet-bound packets into TUN, the kernel routes
   them to the real internet via normal routing + NAT, and responses come back
   through TUN to GatewayService.

This is possible because `NetworkInterface` and `NetstackBridgeProtocol` do the
same thing with different API shapes:

| NetworkInterface          | NetstackBridgeProtocol   | TUN fd operation |
|---------------------------|--------------------------|------------------|
| `readPacket()`            | `setReturnCallback()`    | `read(fd)`       |
| `writePacket(packet)`     | `injectPacket(packet)`   | `write(fd)`      |
| `dialTCP()` → nil         | `dialTCP()` → nil        | kernel handles   |

To bridge this, a `TUNBridgeAdapter` wraps a `TUNInterface` and conforms to
`NetstackBridgeProtocol` by mapping `injectPacket` → `writePacket` and forwarding
packets from the `DispatchSource` read callback to the return callback.

#### Event-Driven I/O

Rather than blocking `read()` calls or polling read loops, `TUNInterface` uses
`DispatchSource.makeReadSource(fileDescriptor:)` to get notified when the fd is
readable. This avoids tying up Swift cooperative thread pool threads.

Internally, `TUNInterface` is callback-driven:

```
TUN fd → DispatchSource fires → read() → onPacket callback
```

Both API shapes are thin wrappers over this single event source:

- **`readPacket()` (pull, for NetworkInterface):** The `DispatchSource` callback
  yields packets into an `AsyncStream`. `readPacket()` awaits the next element.
  No threads blocked — `AsyncStream.Continuation.yield` is non-blocking.

- **`setReturnCallback()` (push, for TUNBridgeAdapter):** The `DispatchSource`
  callback invokes the return callback directly. No adapter read loop needed.

```swift
// Internal to TUNInterface:
private var onPacket: ((Data) -> Void)?          // set by bridge adapter
private var streamContinuation: AsyncStream<Data>.Continuation?  // for readPacket

private func setupDispatchSource() {
    // Set fd non-blocking
    fcntl(fd, F_SETFL, O_NONBLOCK)

    let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: readQueue)
    source.setEventHandler { [weak self] in
        guard let self else { return }
        var buf = [UInt8](repeating: 0, count: 1500)
        let n = read(self.fd, &buf, buf.count)
        guard n > 0 else { return }
        let packet = Data(buf[..<n])

        if let onPacket = self.onPacket {
            onPacket(packet)           // push path (bridge mode)
        } else {
            self.streamContinuation?.yield(packet)  // pull path (node mode)
        }
    }
    source.resume()
    self.readSource = source
}
```

This means `TUNBridgeAdapter` doesn't need its own read loop — it just sets the
`onPacket` callback on the underlying `TUNInterface`, and packets flow directly
from the `DispatchSource` to `GatewayService` with zero intermediate buffering.

```
Node mode (local-facing):                  Bridge mode (internet-facing):

 ┌─────────────────────────┐                ┌─────────────────────────┐
 │  Apps (sockets)          │                │  Peer packets from mesh  │
 └───────────┬──────────────┘                └───────────┬──────────────┘
             │                                           │
 ┌───────────▼──────────────┐                ┌───────────▼──────────────┐
 │  omerta0 TUN device       │                │  GatewayService          │
 │  10.0.0.x/16             │                │  (NAT tracking)          │
 └───────────┬──────────────┘                └───────────┬──────────────┘
             │ read/write                                │ injectPacket/callback
 ┌───────────▼──────────────┐                ┌───────────▼──────────────┐
 │  TUNInterface             │                │  TUNBridgeAdapter        │
 │  (NetworkInterface)       │                │  (NetstackBridgeProtocol)│
 └───────────┬──────────────┘                └───────────┬──────────────┘
             │                                           │ writePacket/readPacket
 ┌───────────▼──────────────┐                ┌───────────▼──────────────┐
 │  PacketRouter             │                │  omerta-gw0 TUN device   │
 │  → mesh tunnel            │                │  + kernel ip_forward     │
 └──────────────────────────┘                │  + iptables MASQUERADE   │
                                             └──────────────────────────┘
                                                         │
                                              ┌──────────▼──────────────┐
                                              │  Real internet           │
                                              └─────────────────────────┘
```

#### Module: OmertaNetwork

**Files to create:**
- `Sources/OmertaNetwork/TUNInterface.swift`
- `Sources/OmertaNetwork/TUNBridgeAdapter.swift`
- `Sources/OmertaNetwork/KernelNetworking.swift`
- `Sources/OmertaNetwork/BuildCapabilities.swift`

#### API

```swift
// TUNInterface.swift
#if os(Linux)
import Glibc

public actor TUNInterface: NetworkInterface {
    public let localIP: String
    private let name: String
    private var fd: Int32 = -1

    // Event-driven read via DispatchSource
    private var readSource: DispatchSourceRead?
    private let readQueue = DispatchQueue(label: "omerta.tun.read")

    // Push path: direct callback for bridge mode
    private var onPacket: (@Sendable (Data) -> Void)?

    // Pull path: AsyncStream for readPacket() in node mode
    private var packetStream: AsyncStream<Data>?
    private var streamContinuation: AsyncStream<Data>.Continuation?

    public init(name: String, ip: String) {
        self.name = name
        self.localIP = ip
    }

    public func start() async throws {
        fd = open("/dev/net/tun", O_RDWR)
        guard fd >= 0 else { throw TUNError.openFailed(errno) }

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

        try configureIP()

        // Set non-blocking and start DispatchSource
        fcntl(fd, F_SETFL, O_NONBLOCK)

        // Set up the AsyncStream for pull-based readPacket()
        let (stream, continuation) = AsyncStream<Data>.makeStream()
        self.packetStream = stream
        self.streamContinuation = continuation

        let tunFd = fd
        let onPkt = onPacket
        let cont = continuation

        let source = DispatchSource.makeReadSource(fileDescriptor: tunFd, queue: readQueue)
        source.setEventHandler {
            var buf = [UInt8](repeating: 0, count: 1500)
            while true {
                let n = read(tunFd, &buf, buf.count)
                guard n > 0 else { break }
                let packet = Data(buf[..<n])
                if let onPkt {
                    onPkt(packet)         // push path (bridge mode)
                } else {
                    cont.yield(packet)    // pull path (node mode)
                }
            }
        }
        source.resume()
        self.readSource = source
    }

    public func stop() async {
        readSource?.cancel()
        readSource = nil
        streamContinuation?.finish()
        streamContinuation = nil
        if fd >= 0 {
            close(fd)
            fd = -1
        }
        _ = try? Process.run("/sbin/ip", arguments: ["link", "delete", name])
    }

    public func readPacket() async throws -> Data {
        guard let stream = packetStream else { throw InterfaceError.notStarted }
        for await packet in stream {
            return packet
        }
        throw InterfaceError.closed
    }

    public func writePacket(_ packet: Data) async throws {
        guard fd >= 0 else { throw InterfaceError.notStarted }
        try packet.withUnsafeBytes { ptr in
            let n = write(fd, ptr.baseAddress!, packet.count)
            guard n == packet.count else { throw TUNError.writeFailed(errno) }
        }
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        nil  // TUN mode uses kernel TCP — apps dial directly via sockets
    }

    /// Set a direct packet callback for bridge mode. When set, packets go to
    /// this callback instead of the AsyncStream. Must be called before start().
    public func setPacketCallback(_ callback: @escaping @Sendable (Data) -> Void) {
        onPacket = callback
    }

    private func configureIP() throws {
        _ = try Process.run("/sbin/ip", arguments: [
            "addr", "add", "\(localIP)/16", "dev", name
        ])
        _ = try Process.run("/sbin/ip", arguments: [
            "link", "set", name, "up"
        ])
    }
}
#endif
```

```swift
// TUNBridgeAdapter.swift
// Wraps a TUNInterface to conform to NetstackBridgeProtocol so GatewayService
// can use a TUN device as its internet exit instead of a gVisor netstack.
// No read loop needed — packets flow directly from the TUNInterface's
// DispatchSource to GatewayService via the onPacket callback.
#if os(Linux)
public actor TUNBridgeAdapter: NetstackBridgeProtocol {
    private let tun: TUNInterface

    public init(tun: TUNInterface) {
        self.tun = tun
    }

    public func start() async throws {
        try await tun.start()
    }

    public func stop() async {
        await tun.stop()
    }

    public func injectPacket(_ packet: Data) async throws {
        try await tun.writePacket(packet)
    }

    public func setReturnCallback(_ callback: @escaping @Sendable (Data) -> Void) async {
        // Wire the TUNInterface's DispatchSource directly to the callback.
        // Packets arriving on the TUN fd fire the DispatchSource, which
        // invokes this callback with zero intermediate buffering.
        await tun.setPacketCallback(callback)
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection {
        throw InterfaceError.notSupported  // kernel handles TCP
    }
}
#endif
```

```swift
// KernelNetworking.swift
// Configures kernel IP forwarding and NAT masquerade for gateway bridge mode.
#if os(Linux)
public enum KernelNetworking {
    /// Enable kernel IP forwarding
    public static func enableForwarding() throws {
        try "1".write(toFile: "/proc/sys/net/ipv4/ip_forward",
                       atomically: true, encoding: .utf8)
    }

    /// Set up iptables MASQUERADE for a TUN interface so packets exiting
    /// through the kernel get source-NATted to the host's real IP.
    /// - Parameters:
    ///   - tunName: The TUN device name (e.g. "omerta-gw0")
    ///   - outInterface: The internet-facing interface (e.g. "eth0")
    public static func enableMasquerade(tunName: String, outInterface: String) throws {
        _ = try Process.run("/sbin/iptables", arguments: [
            "-t", "nat", "-A", "POSTROUTING",
            "-s", "10.0.0.0/16", "-o", outInterface,
            "-j", "MASQUERADE"
        ])
        _ = try Process.run("/sbin/iptables", arguments: [
            "-A", "FORWARD", "-i", tunName, "-o", outInterface,
            "-j", "ACCEPT"
        ])
        _ = try Process.run("/sbin/iptables", arguments: [
            "-A", "FORWARD", "-i", outInterface, "-o", tunName,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
    }

    /// Clean up iptables rules
    public static func disableMasquerade(tunName: String, outInterface: String) throws {
        _ = try? Process.run("/sbin/iptables", arguments: [
            "-t", "nat", "-D", "POSTROUTING",
            "-s", "10.0.0.0/16", "-o", outInterface,
            "-j", "MASQUERADE"
        ])
        _ = try? Process.run("/sbin/iptables", arguments: [
            "-D", "FORWARD", "-i", tunName, "-o", outInterface,
            "-j", "ACCEPT"
        ])
        _ = try? Process.run("/sbin/iptables", arguments: [
            "-D", "FORWARD", "-i", outInterface, "-o", tunName,
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
    }
}
#endif
```

```swift
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

#### Gateway Setup Example (Bridge Mode)

```swift
// Gateway node using TUN for internet access:
let meshTun = TUNInterface(name: "omerta0", ip: "10.0.0.1")
let bridgeTun = TUNInterface(name: "omerta-gw0", ip: "10.200.0.1")
let bridgeAdapter = TUNBridgeAdapter(tun: bridgeTun)

try KernelNetworking.enableForwarding()
try KernelNetworking.enableMasquerade(tunName: "omerta-gw0", outInterface: "eth0")

let gatewayService = GatewayService(bridge: bridgeAdapter)
let router = PacketRouter(
    localInterface: meshTun,
    virtualNetwork: vnet,
    tunnelManager: tunnelManager,
    gatewayService: gatewayService
)
```

#### Unit Tests (Requires Root)

```swift
// TUNInterfaceTests.swift
#if os(Linux)

// --- Basic lifecycle ---

func testTUNCreation() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    let tun = TUNInterface(name: "omerta-test0", ip: "10.99.0.1")
    try await tun.start()
    defer { Task { await tun.stop() } }

    // Verify interface exists and has correct IP
    let result = try Process.run("/sbin/ip", arguments: ["addr", "show", "omerta-test0"])
    XCTAssertTrue(result.output.contains("10.99.0.1"))
    XCTAssertTrue(result.output.contains("UP"))
}

func testTUNStartStop() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    let tun = TUNInterface(name: "omerta-lifecycle0", ip: "10.99.2.1")
    try await tun.start()
    await tun.stop()

    // Interface should be gone
    let result = try Process.run("/sbin/ip", arguments: ["link", "show", "omerta-lifecycle0"])
    XCTAssertFalse(result.exitCode == 0)
}

func testTUNDoubleStartThrows() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    let tun = TUNInterface(name: "omerta-dbl0", ip: "10.99.3.1")
    try await tun.start()
    defer { Task { await tun.stop() } }

    do {
        try await tun.start()
        XCTFail("Second start should throw")
    } catch {
        // expected
    }
}

// --- Packet I/O ---

func testTUNWriteAndReadLoopback() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    // Create two TUN interfaces in the same subnet and send a packet between them.
    // This verifies writePacket and readPacket (via DispatchSource) both work.
    let tun1 = TUNInterface(name: "omerta-io1", ip: "10.99.10.1")
    let tun2 = TUNInterface(name: "omerta-io2", ip: "10.99.10.2")
    try await tun1.start()
    try await tun2.start()
    defer {
        Task { await tun1.stop(); await tun2.stop() }
    }

    // Add route so tun1 knows to send to tun2
    _ = try Process.run("/sbin/ip", arguments: [
        "route", "add", "10.99.10.2/32", "dev", "omerta-io1"
    ])

    // Send a UDP packet from tun1 → 10.99.10.2
    // Use ping from shell to generate traffic
    let pingTask = Task {
        _ = try? Process.run("/bin/ping", arguments: [
            "-c", "1", "-W", "2", "-I", "omerta-io1", "10.99.10.2"
        ])
    }

    // tun2 should receive the ICMP packet via DispatchSource → readPacket
    let packet = try await withTimeout(seconds: 3) {
        try await tun2.readPacket()
    }
    XCTAssertGreaterThan(packet.count, 20)  // at least an IP header

    pingTask.cancel()
}

// --- DispatchSource (event-driven) ---

func testTUNDispatchSourceNotBlocking() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    // Verify that readPacket doesn't block the actor when no data available.
    // Start TUN, schedule a read, verify the actor is still responsive.
    let tun = TUNInterface(name: "omerta-nb0", ip: "10.99.4.1")
    try await tun.start()
    defer { Task { await tun.stop() } }

    // This should not block — the DispatchSource only fires when data arrives
    let readTask = Task {
        try await tun.readPacket()
    }

    // The actor should still respond while readTask is waiting
    let ip = await tun.localIP
    XCTAssertEqual(ip, "10.99.4.1")

    readTask.cancel()
}

func testTUNCallbackMode() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    // Verify the push-path (onPacket callback) works
    let tun = TUNInterface(name: "omerta-cb0", ip: "10.99.5.1")

    let expectation = XCTestExpectation(description: "packet received via callback")
    var callbackPacket: Data?
    await tun.setPacketCallback { packet in
        callbackPacket = packet
        expectation.fulfill()
    }

    try await tun.start()
    defer { Task { await tun.stop() } }

    // Generate traffic to the interface (ping ourselves)
    _ = try? Process.run("/bin/ping", arguments: ["-c", "1", "-W", "1", "10.99.5.1"])

    await fulfillment(of: [expectation], timeout: 3)
    XCTAssertNotNil(callbackPacket)
}

// --- TUNBridgeAdapter ---

func testTUNBridgeAdapterConforms() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    let tun = TUNInterface(name: "omerta-bridge0", ip: "10.99.6.1")
    let bridge = TUNBridgeAdapter(tun: tun)
    try await bridge.start()
    defer { Task { await bridge.stop() } }

    // Verify return callback is wired through
    let expectation = XCTestExpectation(description: "return callback fired")
    await bridge.setReturnCallback { packet in
        expectation.fulfill()
    }

    // Generate traffic to the TUN (ping ourselves)
    _ = try? Process.run("/bin/ping", arguments: ["-c", "1", "-W", "1", "10.99.6.1"])

    await fulfillment(of: [expectation], timeout: 3)
}

func testTUNBridgeInjectPacket() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    let tun = TUNInterface(name: "omerta-binj0", ip: "10.99.7.1")
    let bridge = TUNBridgeAdapter(tun: tun)
    try await bridge.start()
    defer { Task { await bridge.stop() } }

    // Build a minimal ICMP echo to ourselves — the kernel should process it
    // and send a reply back through the TUN
    let icmpPacket = buildICMPEchoPacket(src: "10.99.7.2", dst: "10.99.7.1")

    let expectation = XCTestExpectation(description: "ICMP reply via callback")
    await bridge.setReturnCallback { packet in
        // Should receive an ICMP echo reply
        if packet.count >= 20 && packet[9] == 1 { // ICMP protocol
            expectation.fulfill()
        }
    }

    try await bridge.injectPacket(icmpPacket)
    await fulfillment(of: [expectation], timeout: 3)
}

func testTUNBridgeDialTCPThrows() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    let tun = TUNInterface(name: "omerta-bdial0", ip: "10.99.8.1")
    let bridge = TUNBridgeAdapter(tun: tun)
    try await bridge.start()
    defer { Task { await bridge.stop() } }

    do {
        _ = try await bridge.dialTCP(host: "1.2.3.4", port: 80)
        XCTFail("dialTCP should throw notSupported")
    } catch InterfaceError.notSupported {
        // expected
    }
}

// --- KernelNetworking ---

func testKernelForwardingToggle() async throws {
    guard ProcessInfo.processInfo.effectiveUserID == 0 else {
        throw XCTSkip("Requires root")
    }

    // Save original value
    let original = try String(contentsOfFile: "/proc/sys/net/ipv4/ip_forward").trimmingCharacters(in: .whitespacesAndNewlines)
    defer {
        try? original.write(toFile: "/proc/sys/net/ipv4/ip_forward",
                            atomically: true, encoding: .utf8)
    }

    try KernelNetworking.enableForwarding()
    let value = try String(contentsOfFile: "/proc/sys/net/ipv4/ip_forward").trimmingCharacters(in: .whitespacesAndNewlines)
    XCTAssertEqual(value, "1")
}

#endif
```

#### Demo: TUN-Based SOCKS5 Gateway

A variant of `DemoSOCKSGateway` that uses real TUN interfaces instead of the
in-process gVisor netstack. Requires Linux and root.

**File:** `Sources/DemoTUNGateway/main.swift`
**Script:** `demo-tun-gateway.sh`

```
Traffic flow with TUN:

  curl -x socks5h://127.0.0.1:1080 http://example.com
    │
    ▼
  SOCKSProxy (port 1080)
    │  dialTCP → nil (TUN mode doesn't support dialTCP)
    │  ... wait, SOCKS needs dialTCP for netstack mode.
    │
    │  In TUN mode, SOCKS isn't needed! Apps use standard sockets
    │  and the kernel routes through the TUN device. So the TUN demo
    │  uses a different entry point:
    │
    ▼
  Standard curl/ping/ssh (any app)
    │
    ▼
  Kernel routes via omerta0 (10.0.0.100/16)
    │  read() from TUN fd
    ▼
  TUNInterface (peer, node mode)
    │  DispatchSource fires → readPacket()
    ▼
  PacketRouter
    │  VirtualNetwork.route("93.184.216.34") → .gateway
    ▼
  TunnelManager → mock relay → gateway TunnelManager
    │
    ▼
  PacketRouter (gateway)
    │  gatewayService.forwardToInternet()
    ▼
  GatewayService
    │  NAT tracking, injectPacket()
    ▼
  TUNBridgeAdapter → TUNInterface (gateway, bridge mode)
    │  writePacket() → write to TUN fd
    ▼
  Kernel (ip_forward + MASQUERADE)
    │  routes to real internet
    ▼
  Real internet → response back through full chain
```

```swift
// Sources/DemoTUNGateway/main.swift (sketch)
// Requires: Linux, root, two TUN devices

// 1. Peer node — TUN as local interface
let peerTun = TUNInterface(name: "omerta0", ip: "10.0.0.100")

// 2. Gateway node — TUN as internet bridge
let gwTun = TUNInterface(name: "omerta-gw0", ip: "10.200.0.1")
let gwBridge = TUNBridgeAdapter(tun: gwTun)
let gatewayService = GatewayService(bridge: gwBridge)

// 3. Kernel networking for gateway bridge
try KernelNetworking.enableForwarding()
try KernelNetworking.enableMasquerade(tunName: "omerta-gw0", outInterface: "eth0")

// 4. Virtual networks (same as netstack demo)
let peerVNet = VirtualNetwork(localMachineId: "peer")
await peerVNet.setLocalAddress("10.0.0.100")
await peerVNet.setGateway(machineId: "gw", ip: "10.0.0.1")

let gwVNet = VirtualNetwork(localMachineId: "gw")
await gwVNet.setLocalAddress("10.0.0.1")
await gwVNet.setGateway(machineId: "gw", ip: "10.0.0.1")
await gwVNet.registerAddress(ip: "10.0.0.100", machineId: "peer")

// 5. Mock channel providers + relay (same as netstack demo)
let peerProvider = E2EChannelProvider(machineId: "peer")
let gwProvider = E2EChannelProvider(machineId: "gw")
let relay = E2ERelay()
await relay.register(machineId: "peer", provider: peerProvider)
await relay.register(machineId: "gw", provider: gwProvider)

// 6. Tunnel managers + packet routers
let peerTunnelManager = TunnelManager(provider: peerProvider)
let gwTunnelManager = TunnelManager(provider: gwProvider)

let peerRouter = PacketRouter(
    localInterface: peerTun,
    virtualNetwork: peerVNet,
    tunnelManager: peerTunnelManager
)

let gwRouter = PacketRouter(
    localInterface: TUNInterface(name: "omerta-gw-mesh0", ip: "10.0.0.1"),
    virtualNetwork: gwVNet,
    tunnelManager: gwTunnelManager,
    gatewayService: gatewayService
)

// 7. Start everything, add routes
// ...

// 8. Add route so the host sends internet traffic through omerta0
// sudo ip route add default via 10.0.0.1 dev omerta0 metric 100

// Now standard tools work:
//   ping 8.8.8.8         → through mesh → gateway → internet
//   curl http://example.com  → through mesh → gateway → internet
//   ssh user@10.0.0.1    → through mesh → gateway node
```

```bash
#!/usr/bin/env bash
# demo-tun-gateway.sh
#
# Demo: TUN-based SOCKS5 Gateway
#
# Unlike the netstack demo (demo-socks-gateway.sh) which uses a SOCKS proxy
# and userspace gVisor stacks, this demo uses real Linux TUN interfaces.
# Standard networking tools (curl, ping, ssh) work without any proxy config
# because the kernel routes traffic through the TUN device.
#
# Requires: Linux, root privileges
#
# What it creates:
#   omerta0      — peer TUN device (10.0.0.100/16), local app traffic
#   omerta-gw0   — gateway TUN device (10.200.0.1), internet bridge
#   iptables     — MASQUERADE rule for gateway internet access
#   ip_forward   — enabled for kernel packet forwarding
#
# Traffic flow:
#   any app → kernel → omerta0 → PacketRouter → mesh relay →
#   gateway PacketRouter → GatewayService → omerta-gw0 → kernel →
#   real internet → response back through full chain
#
# Test with (in another terminal):
#   ping 8.8.8.8
#   curl http://example.com
#   # These use standard sockets — no SOCKS proxy needed!
#
# Press Ctrl+C to stop. Cleanup removes TUN devices and iptables rules.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (need TUN device access)"
    echo "Usage: sudo ./demo-tun-gateway.sh"
    exit 1
fi

echo "Building DemoTUNGateway..."
swift build --target DemoTUNGateway

echo ""
echo "Starting TUN gateway demo (requires root)..."
swift run DemoTUNGateway
```

#### Comparison: Netstack Demo vs TUN Demo

| Aspect             | DemoSOCKSGateway (netstack)     | DemoTUNGateway (TUN)            |
|--------------------|----------------------------------|---------------------------------|
| Platform           | Any (Linux, macOS)              | Linux only                      |
| Root required      | No                              | Yes                             |
| App entry point    | SOCKS5 proxy (port 1080)        | Standard sockets (any app)      |
| TCP/IP stack       | gVisor userspace (peer+gateway) | Kernel (peer), kernel (gateway) |
| DNS resolution     | Through gVisor UDP → gateway    | Through kernel → TUN → gateway  |
| Internet bridge    | NetstackBridge (gVisor)         | TUNBridgeAdapter (kernel+NAT)   |
| `curl` usage       | `curl -x socks5h://...`        | `curl` (no proxy needed)        |
| `ping` works       | No (SOCKS is TCP only)          | Yes                             |
| `ssh` works        | No (need OmertaSSH)            | Yes (standard ssh)              |

#### Manual Tests

```bash
# On Linux, as root
sudo swift test --filter TUNInterfaceTests

# Verify interface creation
sudo swift run DemoTUNGateway &
ip addr show omerta0
ip addr show omerta-gw0
ping -c 1 10.0.0.1  # Should respond

# Verify bridge mode (gateway)
cat /proc/sys/net/ipv4/ip_forward  # Should be 1
sudo iptables -t nat -L  # Should show MASQUERADE rule

# Test internet access through TUN
curl http://example.com
ping -c 3 8.8.8.8
```

**Deliverable:** TUN interface works on Linux with root, both as a mesh node
local interface and as a gateway internet bridge via TUNBridgeAdapter. Two demo
binaries demonstrate both modes: netstack (cross-platform including macOS, SOCKS
proxy) and TUN (Linux-only, standard sockets). macOS kernel networking (utun)
is deferred to a future phase.

---

### Phase 10: Two-Machine Test (Userspace)

**Goal:** Build the `omertad` daemon binary that wires the real `MeshNetwork` (ChannelProvider) to the virtual network stack, then test between two physical machines.

#### New Code

**`Sources/omertad/main.swift`** — The real daemon entry point (~200 lines)

Wires together all components built in Phases 1–9:

```swift
// Pseudocode structure:
@main struct OmertaDaemon {
    static func main() async throws {
        let args = parseArgs()  // --port, --gateway, --bootstrap, --interface tun|userspace

        // 1. Identity
        let identity = try loadOrCreateIdentity()

        // 2. Real mesh network (the ChannelProvider)
        let mesh = MeshNetwork(identity: identity, config: .init(listenPort: args.port))
        if let bootstrap = args.bootstrap {
            try await mesh.bootstrap(to: bootstrap)
        }

        // 3. Virtual network (address allocation)
        let virtualNetwork = VirtualNetwork()

        // 4. DHCP
        if args.gateway {
            let dhcpServer = DHCPServer(virtualNetwork: virtualNetwork)
            // register on virtual network
        } else {
            let dhcpClient = DHCPClient(virtualNetwork: virtualNetwork)
        }

        // 5. Tunnel manager (wraps MeshNetwork as ChannelProvider)
        let tunnelManager = TunnelManager(channelProvider: mesh)

        // 6. Local interface (TUN or userspace netstack)
        let localInterface: NetworkInterface
        if args.interface == .tun {
            localInterface = try TUNInterface(name: "omerta0")
        } else {
            let bridge = try NetstackBridge(config: .init(gatewayIP: myIP))
            localInterface = NetstackInterface(bridge: bridge)
        }

        // 7. Gateway service (only on gateway node)
        let gatewayService: GatewayService? = args.gateway
            ? GatewayService(bridge: try NetstackBridge(config: .init(gatewayIP: "10.200.0.1")))
            : nil

        // 8. Packet router (ties it all together)
        let router = PacketRouter(
            localInterface: localInterface,
            virtualNetwork: virtualNetwork,
            tunnelManager: tunnelManager,
            gatewayService: gatewayService
        )

        try await router.start()
        // await shutdown signal
    }
}
```

**Key design decisions:**
- Single binary, flag-driven mode (`--gateway` vs peer)
- `--interface tun|userspace` selects TUNInterface or NetstackInterface
- Identity persisted to `~/.omerta/identity.json`
- `--bootstrap peerID@host:port` for initial mesh join

**Dependencies:** `OmertaNetwork`, `OmertaTunnel`, `OmertaMesh`, `ArgumentParser`

**Package.swift addition:**
```swift
.executableTarget(
    name: "omertad",
    dependencies: [
        "OmertaNetwork", "OmertaTunnel", "OmertaMesh",
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
        .product(name: "Logging", package: "swift-log"),
    ]
),
```

#### Manual Tests

**Setup:**
```bash
# On local (192.0.2.10)
cd ~/omerta
swift build

# On arch-home (192.0.2.20)
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
./.build/debug/omertad start --port 18002 --bootstrap "abc123...@192.0.2.10:18002"

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
./.build/debug/omertad start --port 18002 --bootstrap "<local>@192.0.2.10:18002"

# Terminal 3 - Mac
ssh mac
cd ~/omerta
./build/debug/omertad start --port 18002 --bootstrap "<local>@192.0.2.10:18002"

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
sudo ./.build/debug/omertad start --port 18002 --vpn --bootstrap "<local>@192.0.2.10:18002"

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
sudo ./.build/debug/omertad start --port 18002 --vpn --bootstrap "<local>@192.0.2.10:18002"

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
sudo ./.build/debug/omertad start --port 18002 --vpn --bootstrap "<local>@192.0.2.10:18002"

# Terminal 2 - Local as gateway
./build/debug/omertad start --port 18002 --gateway

# Terminal 3 - Mac userspace
ssh mac
./build/debug/omertad start --port 18002 --bootstrap "<local>@192.0.2.10:18002"

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
| 9. TUN Interface     | ✓ (root)   | ✓ (root+demo)     | sudo swift test + demo    |
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
# Phase 1-8: Unit tests (no root)
swift test

# Phase 9: TUN tests (root required)
sudo swift test --filter TUNInterfaceTests

# Phase 9: Demos
swift run DemoSOCKSGateway                    # netstack demo (any platform)
sudo swift run DemoTUNGateway                 # TUN demo (Linux, root)

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
./.build/debug/omertad start --port 18002 --bootstrap "<local>@192.0.2.10:18002"

# Mac:
./build/debug/omertad start --port 18002 --bootstrap "<local>@192.0.2.10:18002"

# Status commands
./build/debug/omerta mesh status
./build/debug/omerta network peers
./build/debug/omerta network address
./build/debug/omerta dhcp leases
./build/debug/omerta tunnel sessions
```
