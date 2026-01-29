# Tunnel Infrastructure

> **Architecture Alignment Note:** This plan supplements VIRTUAL_NETWORK_REWORK.md.
> It covers functionality NOT in that plan:
> - VM packet capture and network isolation
> - Relay discovery and gossip infrastructure
> - Tunnel health monitoring and endpoint change detection
> - Failure backoff and user messaging
> - Peer expiry and rejoin
> - WireGuard legacy cleanup
>
> **Source of truth for tunnel APIs:** VIRTUAL_NETWORK_REWORK.md
> - TunnelSession: thin bidirectional pipe (MachineId, channel, send, onReceive)
> - TunnelManager: session pool + proactive health monitoring
> - PacketRouter: routes packets between NetworkInterface and TunnelSessions
> - GatewayService: internet exit via netstack (in OmertaNetwork, not OmertaTunnel)

## Overview

This document covers tunnel infrastructure beyond the core virtual network
architecture. It focuses on VM integration, relay coordination, health
monitoring, failure handling, and legacy cleanup.

**Key Design Principles**:
1. **Both sides monitor** — consumer and provider independently track connection health
2. **Transport-agnostic** — tunnel layer doesn't care what's inside the packets
3. **Extensible gossip** — OmertaMesh provides generic gossip; utilities register their own channel types
4. **Usage-based priority** — nodes prioritize gossip they use, forward everything else best-effort
5. **Tunnel is agnostic** — no awareness of cloister or how networks are established

---

## Traffic Flow Summary

```
VM App
   │ (normal socket call)
   ▼
VM eth0 (veth in namespace)
   │ (raw IP packet)
   ▼
Provider: VMPacketCapture (implements NetworkInterface)
   │
   ▼
Provider: PacketRouter (routes via VirtualNetwork)
   │
   ▼
Provider: TunnelSession.send() — thin bidirectional pipe
   │ (OmertaMesh handles encryption/routing)
   ▼
Mesh Network (encrypted, UDP-based)
   │ (OmertaMesh handles decryption)
   ▼
Consumer: TunnelSession.onReceive() callback
   │
   ▼
Consumer: PacketRouter (receives packet, routes to GatewayService)
   │
   ▼
Consumer: GatewayService (internet exit via netstack)
   │ (netstack is in OmertaNetwork, not OmertaTunnel)
   ▼
Netstack (gVisor) — inside GatewayService
   │ (TCP/UDP/ICMP processing)
   ▼
Real socket connection
   │
   ▼
Consumer's Local Network → Internet
```

**Key:** TunnelSession is a thin bidirectional pipe — it just sends/receives Data.
Netstack lives in GatewayService (OmertaNetwork module), not in OmertaTunnel.

---

## Implementation Phases

### Phase 1: VM Integration

**Goal:** Connect VM network interface to PacketRouter via NetworkInterface.
Provider captures VM packets, PacketRouter routes them through TunnelSessions
to the consumer's GatewayService.

#### Architecture

VMPacketCapture implements the NetworkInterface protocol (defined in
VIRTUAL_NETWORK_REWORK Phase 5), abstracting Linux namespaces vs macOS
file handles.

```
┌───────────────────────────────────────────────────────────────────┐
│  VMPacketCapture: NetworkInterface                                 │
│  ├── readPacket() → Data       (packet from VM)                   │
│  ├── writePacket(Data)         (packet to VM)                     │
│  ├── Platform-specific:                                           │
│  │   ├── Linux: veth in network namespace                         │
│  │   └── macOS: VZFileHandleNetworkDeviceAttachment               │
│  └── Plugs into PacketRouter                                      │
└───────────────────────────────────────────────────────────────────┘
```

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaProvider/VMPacketCapture.swift` | Implements NetworkInterface for VM traffic |
| `Sources/OmertaProvider/VMNetworkNamespace.swift` | Linux namespace setup |
| `Sources/OmertaProvider/VMNetworkFileHandle.swift` | macOS file handle setup |
| `Tests/OmertaProviderTests/VMPacketCaptureTests.swift` | Integration tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Wire up VMPacketCapture → PacketRouter |
| `Sources/OmertaVM/VMManager.swift` | Configure VM for packet capture |

#### API

```swift
/// VMPacketCapture implements NetworkInterface (from OmertaNetwork).
/// Abstracts platform-specific VM packet capture.
public actor VMPacketCapture: NetworkInterface {
    public let localIP: String

    /// Platform-specific packet source
    private let packetSource: any PacketSource

    public init(vmId: UUID, localIP: String, packetSource: any PacketSource) {
        self.localIP = localIP
        self.packetSource = packetSource
    }

    public func readPacket() async throws -> Data {
        try await packetSource.read()
    }

    public func writePacket(_ packet: Data) async throws {
        try await packetSource.write(packet)
    }

    public func start() async throws {
        try await packetSource.start()
    }

    public func stop() async {
        await packetSource.stop()
    }
}

/// Platform-specific packet source
public protocol PacketSource: Sendable {
    func read() async throws -> Data
    func write(_ packet: Data) async throws
    func start() async throws
    func stop() async
}
```

**Usage (provider side):**
```swift
// 1. Create VM with network namespace/file handle
let packetSource = try await VMNetworkNamespace.create(vmId: vmId)

// 2. Create VMPacketCapture as NetworkInterface
let vmCapture = VMPacketCapture(
    vmId: vmId,
    localIP: "10.0.0.2",
    packetSource: packetSource
)

// 3. Wire into PacketRouter (from VIRTUAL_NETWORK_REWORK Phase 6)
let router = PacketRouter(
    networkInterface: vmCapture,
    virtualNetwork: vnet,
    tunnelManager: tunnelManager
)
try await router.start()

// PacketRouter handles:
// - Reading packets from VMPacketCapture
// - Looking up destination via VirtualNetwork
// - Sending via TunnelSession to the right machine
// - Writing return packets back to VMPacketCapture
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testCaptureVMPacket` | VM sends packet, verify capture via readPacket() |
| `testInjectToVM` | writePacket(), verify VM receives |
| `testDHCPResponse` | VM requests DHCP, verify response via gateway |
| `testARPResponse` | VM sends ARP, verify response |
| `testMTUHandling` | Large packet, verify fragmentation |
| `testStartStop` | Start/stop lifecycle, verify cleanup |

#### Manual Testing

```bash
# Terminal 1: Start consumer (will be traffic exit point)
omertad start --port 18002

# Terminal 2: Start provider
omertad start --port 18003 --bootstrap localhost:18002

# Request VM from provider
omerta vm request --provider <provider-machine-id> --consumer <consumer-machine-id>

# In VM console:
ping 1.1.1.1
# Packets flow: VM → VMPacketCapture → PacketRouter → TunnelSession
#   → mesh → consumer PacketRouter → GatewayService → internet

curl https://example.com
# Should return HTML

# Verify isolation: no traffic on provider's network
tcpdump -i eth0 host 1.1.1.1
# Should show NO packets (all go through mesh to consumer)
```

---

### Phase 2: Relay Discovery and Gossip Integration

**Goal:** Track and propagate which peers are willing to act as relays. Use
extensible gossip infrastructure. Request relay nodes to join ephemeral networks.

**Key Design:**
- **Extensible gossip** — OmertaMesh provides generic gossip infrastructure;
  relay-specific messages are registered by OmertaTunnel, not hardcoded
- **Usage-based priority** — Nodes prioritize gossip for channels they use,
  but still forward all other gossip with spare bandwidth
- **Relay capacity is per-machine**, not per-endpoint

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

#### API

```swift
// === OmertaMesh: Generic Gossip Infrastructure ===

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

    /// Prioritize gossip for propagation
    func prioritize(_ entries: [GossipEntry], bandwidth: Int) -> [GossipEntry]
}

/// Generic per-peer metadata storage
public actor PeerMetadataStore {
    func set<T: Codable>(_ key: String, value: T, for peer: PeerId) async
    func get<T: Codable>(_ key: String, for peer: PeerId) async -> T?
    func peers<T: Codable>(with key: String) async -> [(PeerId, T)]
    func updates<T: Codable>(for key: String) -> AsyncStream<(PeerId, T)>
}

// === OmertaTunnel: Relay-Specific Types ===

/// Relay announcement - published via GossipRouter
public struct RelayAnnouncement: Codable, Sendable {
    static let channelId = "relay"

    let peerId: PeerId
    let capacity: Int           // 0 = not a relay, >0 = available slots
    let currentLoad: Int
    let timestamp: Date
}

/// Per-machine relay config (stored on disk)
public struct RelayConfig: Codable {
    var enabled: Bool = false
    var maxCapacity: Int = 10
    var currentLoad: Int = 0
    // Stored at: ~/.omerta/mesh/relay-config.json
}

/// Relay coordinator (in OmertaTunnel)
public actor RelayCoordinator {
    init(gossipRouter: GossipRouter, metadataStore: PeerMetadataStore)

    func start() async
    func stop() async

    func availableRelays() async -> [PeerId]
    func requestRelay(for machineId: MachineId) async throws -> PeerId
    func releaseRelay(_ relayPeerId: PeerId, for machineId: MachineId) async
}
```

**Gossip Priority:**
```
Node A (uses relay)          Node B (uses relay + vm-status)    Node C (uses nothing extra)
───────────────────          ───────────────────────────────    ────────────────────────────
 - relay: process + high pri  - relay: process + high pri        - relay: forward, low pri
 - vm-status: forward, low    - vm-status: process + high pri    - vm-status: forward, low

All gossip flows everywhere, but nodes prioritize what they use.
```

**Gossip Config:**
```swift
public struct GossipConfig {
    var budgetBytesPerSecond: Int = 10_000  // 10 KB/s default
    var recencyHalfLifeSeconds: Double = 60
}
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testGossipChannelRegistration` | Register channel, verify handler called |
| `testGossipPriorityActiveChannels` | Active channels prioritized over inactive |
| `testGossipBestEffortForwarding` | Unregistered channels still forwarded |
| `testPeerMetadataStorage` | Store/retrieve metadata for peers |
| `testRelayAnnouncementGossiped` | Relay announces capacity, peers receive it |
| `testAvailableRelays` | Query available relays, correct list returned |
| `testRequestRelay` | Request relay, verify accepted |
| `testRelayAtCapacity` | Request when full, verify fallback |

---

### Phase 3: Network Isolation

**Goal:** Ensure absolutely no internet traffic goes through the provider host,
including DNS. All traffic must flow through the mesh to the consumer.

**Note:** Isolation is built into the network namespace/file handle setup from
Phase 1. This phase validates that isolation through tests.

#### Files to Create

| File | Description |
|------|-------------|
| `Tests/OmertaProviderTests/IsolationTests.swift` | Isolation validation tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaVM/VMManager.swift` | Ensure DNS points to mesh gateway |

#### Unit Tests

| Test | Description |
|------|-------------|
| `testVMCannotReachHost` | VM pings host IP, verify failure |
| `testVMCannotReachLAN` | VM pings LAN IPs, verify failure |
| `testVMCannotReachInternetDirect` | Block mesh, VM has no connectivity |
| `testDNSGoesToMeshGateway` | Check VM resolv.conf points to gateway |
| `testNoHostDNSLeak` | tcpdump on host, verify no DNS traffic |
| `testAllTrafficViaMesh` | Monitor host, verify no non-mesh traffic |

#### Manual Testing

```bash
# Start provider and VM
omertad start --port 18002
omerta vm create --name isolated-vm --image ubuntu-22.04
omerta vm start isolated-vm

# On provider host, monitor all traffic
sudo tcpdump -i any -n 'not port 18002'
# Should show NO traffic from VM

# In VM:
ping 192.0.2.1          # Provider's LAN IP — should fail
cat /etc/resolv.conf       # Should show mesh gateway IP
dig google.com             # Should work (via mesh to consumer)

# Disconnect consumer, retry
dig google.com             # Should fail (proves DNS goes through mesh)
```

---

### Phase 4: Health Monitoring and Endpoint Change Detection

**Goal:** Implement tunnel health monitoring with proactive probing and
OS-level endpoint change detection. This extends the health monitoring
described in VIRTUAL_NETWORK_REWORK Phase 2 with detailed implementation.

> **Note:** VIRTUAL_NETWORK_REWORK Phase 2 defines the health monitoring
> interface within TunnelManager (EndpointHealth, establishConnection,
> runHealthProbes). This phase covers the implementation details and adds
> OS-level network change detection.

#### Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│  TunnelManager (from VIRTUAL_NETWORK_REWORK)                      │
│  ├── healthState: [MachineId: EndpointHealth]                     │
│  ├── healthMonitors: [MachineId: Task]                            │
│  │                                                                │
│  │  Uses:                                                         │
│  │  ├── TunnelHealthMonitor — probe logic, adaptive intervals     │
│  │  └── EndpointChangeDetector — OS network change events         │
│  │                                                                │
│  │  On failure:                                                   │
│  │  └── Requests mesh to try alternative endpoints                │
└───────────────────────────────────────────────────────────────────┘
```

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaTunnel/TunnelHealthMonitor.swift` | Probe logic with adaptive intervals |
| `Sources/OmertaTunnel/EndpointChangeDetector.swift` | OS network change events |
| `Tests/OmertaTunnelTests/TunnelHealthTests.swift` | Health monitoring tests |
| `Tests/OmertaTunnelTests/EndpointChangeTests.swift` | Change detection tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaTunnel/TunnelManager.swift` | Integrate health monitor and change detector |

#### API

```swift
/// Probe logic with adaptive intervals.
/// Used internally by TunnelManager's health monitoring.
public actor TunnelHealthMonitor {
    var lastPacketTime: ContinuousClock.Instant = .now
    var currentProbeInterval: Duration = .milliseconds(500)

    let minProbeInterval: Duration = .milliseconds(500)
    let maxProbeInterval: Duration = .seconds(15)

    /// Reset interval when traffic is received
    func onPacketReceived() {
        lastPacketTime = .now
        currentProbeInterval = minProbeInterval
    }

    /// Run probe loop for a machine
    func startMonitoring(
        machineId: MachineId,
        sendProbe: @escaping (MachineId) async throws -> Void,
        onFailure: @escaping (MachineId) async -> Void
    ) async {
        while !Task.isCancelled {
            try? await Task.sleep(for: currentProbeInterval)

            if (ContinuousClock.now - lastPacketTime) >= currentProbeInterval {
                do {
                    try await sendProbe(machineId)
                    // Probe succeeded, back off interval
                    currentProbeInterval = min(
                        currentProbeInterval * 2,
                        maxProbeInterval
                    )
                } catch {
                    await onFailure(machineId)
                    return
                }
            }
        }
    }
}

/// OS-level network change detection
public actor EndpointChangeDetector {
    func startMonitoring() async
    var endpointChanges: AsyncStream<EndpointChange> { get }
}

public struct EndpointChange: Sendable {
    let oldEndpoint: Endpoint?
    let newEndpoint: Endpoint
    let reason: ChangeReason  // networkSwitch, ipChange, interfaceDown
}
```

**Detection mechanisms:**

| Method | Latency | When It Triggers |
|--------|---------|------------------|
| OS network change events | ~0ms | Local IP/interface changes |
| Traffic-triggered probe timeout | 500ms + RTT | No incoming packet for 500ms |

```swift
// Darwin/iOS
let monitor = NWPathMonitor()
monitor.pathUpdateHandler = { path in
    if path.status != .satisfied || addressChanged(path) {
        // Notify TunnelManager to re-probe
    }
}

// Linux: Monitor netlink socket for RTM_NEWADDR/RTM_DELADDR
```

#### Unit Tests

| Test | Description |
|------|-------------|
| `testKeepaliveProbe` | No traffic, verify probe sent |
| `testKeepaliveBackoff` | Idle connection, verify interval grows |
| `testKeepaliveReset` | Traffic received, verify interval resets |
| `testEndpointChangeDetected` | Simulate IP change, verify detection |
| `testConnectionHeals` | Change endpoint, verify traffic resumes |
| `testBothSidesMonitor` | Either side detects, both recover |

---

### Phase 5: Failure Backoff and User Messaging

**Goal:** Implement backoff for failed reconnection attempts. Provide clear user
messages about connection state without spamming.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaTunnel/ReconnectionManager.swift` | Backoff logic |
| `Sources/OmertaTunnel/ConnectionStateReporter.swift` | User messaging |
| `Tests/OmertaTunnelTests/ReconnectionTests.swift` | Backoff tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaTunnel/TunnelManager.swift` | Integrate backoff and state reporting |

#### API

```swift
/// Connection state for user awareness
public enum TunnelConnectionState: Sendable {
    case connected
    case reconnecting(attempt: Int, nextRetryMs: Int)
    case degraded(reason: String)
}

/// Reconnection manager with exponential backoff
public actor ReconnectionManager {
    var currentBackoffMs: Int { get }
    func recordFailure() -> Int  // Returns next retry delay
    func recordSuccess()         // Resets backoff
}

/// Handler for state changes
public typealias ConnectionStateHandler = (MachineId, TunnelConnectionState) async -> Void
```

**Behavior:**
- Never give up — keep retrying with exponential backoff
- Max backoff: 60 seconds
- Success resets backoff to minimum
- User sees at most ~5 messages during sustained outage

#### Unit Tests

| Test | Description |
|------|-------------|
| `testBackoffIncreases` | Each failure doubles delay |
| `testBackoffCaps` | Verify max backoff (60s) |
| `testBackoffResets` | Success resets to minimum |
| `testStateTransitions` | connected → reconnecting → connected |
| `testNoMessageSpam` | 10 failures, verify ≤3 user messages |
| `testDegradedState` | High latency, verify degraded reported |

---

### Phase 6: Peer Expiry and Rejoin

**Goal:** Implement backoff and dropoff for peers that stop responding.
Support successful rejoin after being dropped from peer lists.

**Note:** This code belongs in core **OmertaMesh**, not OmertaTunnel.
Peer expiry is fundamental mesh behavior.

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

#### API

```swift
/// Peer state (in OmertaMesh)
public enum PeerState: Sendable {
    case active
    case stale(missedPings: Int)
    case expired
}

/// Expiry manager
public actor PeerExpiryManager {
    func recordPing(peerId: PeerId, success: Bool)
    func peerState(_ peerId: PeerId) -> PeerState
    var expiredPeers: AsyncStream<PeerId> { get }
}

/// Config additions
extension MeshConfig {
    var staleThresholdMissedPings: Int  // default: 3
    var expiryThresholdMissedPings: Int // default: 8
    var rejoinGracePeriodSeconds: Int   // default: 300
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

---

### Phase 7: WireGuard and Legacy VPN Cleanup

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
| `Sources/OmertaVPN/EthernetFrame.swift` | Packet handling in netstack |
| `Sources/OmertaVPN/IPv4Packet.swift` | Packet handling in netstack |
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
| `Tests/OmertaVPNTests/` (entire directory) | All VPN tests replaced |
| `Tests/OmertaProviderTests/VPNHealthMonitorTests.swift` | Replaced |

#### Sudo/Root Check Removals

The netstack approach runs entirely in userspace — no root required on consumer.

| File | Code to Remove |
|------|----------------|
| `Sources/OmertaCore/System/ProcessRunner.swift` | `isRoot` property and `getuid() == 0` check |
| `Sources/OmertaCLI/main.swift` | `getuid() == 0` check and sudo hints |
| `Sources/OmertaVPN/EphemeralVPN.swift` | `getuid() != 0` root requirement check |
| `Sources/OmertaDaemon/OmertaDaemon.swift` | "run with sudo" messages |
| `Sources/OmertaCore/System/DependencyChecker.swift` | `wireguard` dependencies |

**Note:** Keep SUDO_USER handling in home directory resolution — still useful
when daemon runs as root.

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

---

## Reference: VM Networking Architecture

### Strict Isolation Guarantees

Isolation is provided by the platform, not firewall rules:

**macOS (Virtualization.framework):**
- `VZFileHandleNetworkDeviceAttachment` — VM's only network is the file handle
- No bridge to host network exists
- VM literally cannot reach anything except through VMPacketCapture

**Linux (network namespaces):**
- VM is in isolated namespace, cannot see host interfaces
- Only interface is veth with route to gateway (our bridge)
- Packets have nowhere to go except through VMPacketCapture

### Provider-Side Setup

**Linux (network namespace + veth):**

```bash
# Create isolated namespace for VM
ip netns add vm-${VM_ID}

# Create veth pair
ip link add veth-vm-${VM_ID} type veth peer name veth-host-${VM_ID}

# Move one end into VM namespace
ip link set veth-vm-${VM_ID} netns vm-${VM_ID}

# Configure VM side
ip netns exec vm-${VM_ID} ip addr add 10.0.${VM_NUM}.2/24 dev veth-vm-${VM_ID}
ip netns exec vm-${VM_ID} ip link set veth-vm-${VM_ID} up
ip netns exec vm-${VM_ID} ip link set lo up
ip netns exec vm-${VM_ID} ip route add default via 10.0.${VM_NUM}.1

# Configure host side
ip addr add 10.0.${VM_NUM}.1/24 dev veth-host-${VM_ID}
ip link set veth-host-${VM_ID} up
```

**macOS (Virtualization.framework):**

```swift
let (vmRead, hostWrite) = Pipe().fileHandles
let (hostRead, vmWrite) = Pipe().fileHandles

let networkAttachment = VZFileHandleNetworkDeviceAttachment(
    fileHandleForReading: vmRead,
    fileHandleForWriting: vmWrite
)

// VMPacketCapture reads from hostRead, writes to hostWrite
```

### Edge Cases

**DHCP:** Gateway responds via unicast DHCP (see VIRTUAL_NETWORK_REWORK Phase 4)

**DNS:** VM's DNS points to mesh gateway IP, forwarded through mesh to consumer

**ARP:** Host responds to ARP for gateway (automatic with veth setup)

**MTU:** Set VM's interface MTU to 1400 to account for mesh overhead

**Consumer Offline:** VM traffic fails (connection refused/timeout) — expected

### Endpoint Negotiation and Migration

When either side's endpoint stops working:

1. **Detection** — OS network change event or probe timeout
2. **Re-probe** — TunnelManager sends probes to trigger mesh reconnection
3. **Notify peer** — Mesh handles endpoint update propagation
4. **Resume** — Active connections continue (just mesh messages, no app-layer reconnect)

Both consumer and provider run health monitoring. Either can initiate recovery.

---

## Reference: Experimental Findings

### T-Mobile NAT Behavior (January 2026)

**Test Environment:**
- Local machine: T-Mobile Home Internet (CGNAT)
- Mac: T-Mobile Phone Hotspot
- Bootstrap: AWS (non-T-Mobile IP)

**Key Findings:**

1. **Bind to specific IPv6 address** on macOS — privacy extensions cause
   source address mismatch when binding to `::`

2. **T-Mobile blocks peer-to-peer** between their consumer devices but allows
   internet traffic

3. **Endpoint-dependent NAT** requires precise hole punching coordination —
   sending to Bootstrap does NOT open the pinhole for Mac

4. **Working relay strategy:** Both peers must send outbound first. Relay
   coordinates timing for simultaneous sends. Fallback to relay if hole
   punching fails.
