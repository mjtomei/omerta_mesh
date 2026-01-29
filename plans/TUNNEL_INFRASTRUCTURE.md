# Tunnel Infrastructure

> **Architecture Alignment Note:** This plan covers tunnel infrastructure
> that supplements VIRTUAL_NETWORK_REWORK.md and GOSSIP_RELAY_PLAN.md.
>
> **Scope:**
> - Health monitoring and endpoint change detection (implemented)
> - Failure backoff and user messaging (planned)
> - Peer expiry and rejoin (planned)
> - WireGuard legacy cleanup (planned)
>
> **Out of scope (covered elsewhere):**
> - TunnelSession/TunnelManager core APIs → VIRTUAL_NETWORK_REWORK.md
> - Gossip infrastructure and relay discovery → GOSSIP_RELAY_PLAN.md
> - VM integration → VMs join the mesh VPN directly as first-class peers

## Overview

This document covers tunnel resilience infrastructure: detecting failures,
recovering from them, communicating state to users, managing peer lifecycles,
and cleaning up legacy code.

**Key Design Principles**:
1. **Both sides monitor** — each end independently tracks connection health
2. **Adaptive probing** — probe frequency adjusts based on traffic patterns
3. **Graceful degradation** — transient failures tolerated, sustained failures trigger recovery
4. **Clear user feedback** — connection state changes reported without spam
5. **Tunnel is agnostic** — no awareness of cloister, VMs, or how networks are established

---

## Current Architecture

```
TunnelManager
├── sessions: [TunnelSessionKey: TunnelSession]
│   └── Keyed by (machineId, channel)
├── healthMonitors: [MachineId: TunnelHealthMonitor]
│   └── Per-machine, shared across all sessions to same machine
├── endpointChangeDetector: EndpointChangeDetector
│   └── OS-level network change events
├── getSession(machineId:channel:) → TunnelSession
├── closeSession(key:)
├── closeAllSessions(to:)
├── notifyPacketReceived(from:)
└── getHealthMonitor(for:) → TunnelHealthMonitor?

Wire Channels:
  "tunnel-handshake"     — session setup/teardown (request, ack, reject, close)
  "tunnel-health-probe"  — health probes (0x01 request, 0x02 response)
  "tunnel-{channel}"     — session data transport

Handshake Protocol:
  SessionHandshake { type, machineId, channel, sessionId }
  Types: request → ack/reject, close (with sessionId to prevent stale closes)

Health Monitoring Flow:
  1. New session → create/reuse TunnelHealthMonitor for machine
  2. Probes sent every 500ms–15s depending on traffic
  3. Application data → onPacketReceived() → reset interval to min
  4. Probe responses → onProbeResponseReceived() → update liveness (no interval reset)
  5. 3 consecutive failures → close all sessions to machine, remove monitor
```

---

## Implementation Phases

### Phase 4: Health Monitoring and Endpoint Change Detection ✅ COMPLETE

**Status:** Fully implemented and validated with 11-phase cross-machine test suite.

#### What Was Built

**TunnelHealthMonitor** (`Sources/OmertaTunnel/TunnelHealthMonitor.swift`):
```swift
public actor TunnelHealthMonitor {
    public init(
        minProbeInterval: Duration = .milliseconds(500),
        maxProbeInterval: Duration = .seconds(15),
        failureThreshold: Int = 3,
        graceIntervals: Int = 0
    )

    public func onPacketReceived()
    public func onProbeResponseReceived()

    public func startMonitoring(
        machineId: MachineId,
        sendProbe: @escaping (MachineId) async throws -> Void,
        onFailure: @escaping (MachineId) async -> Void
    )

    public func stopMonitoring()

    // Test accessors
    public var _consecutiveFailures: Int
    public var _currentProbeInterval: Duration
}
```

**EndpointChangeDetector** (`Sources/OmertaTunnel/EndpointChangeDetector.swift`):
```swift
public actor EndpointChangeDetector {
    public init()

    public var changes: AsyncStream<EndpointChange> { get }

    public func start() async
    public func stop() async
}

public struct EndpointChange: Sendable {
    public let oldEndpoint: String?
    public let newEndpoint: String?
    public let reason: ChangeReason
    public let timestamp: ContinuousClock.Instant
}

public enum ChangeReason: Sendable {
    case networkSwitch
    case ipChange
    case interfaceDown
    case interfaceUp
}
```

**Platform-specific detection:**
- **Darwin/macOS:** `NWPathMonitor` with dispatch queue
- **Linux:** Polls primary IPv4 address via `getifaddrs()` every 2 seconds

**TunnelManager integration:**
- Per-machine `TunnelHealthMonitor` instances, shared across all sessions to same machine
- Subscribes to `EndpointChangeDetector` and re-probes all machines on network changes
- Health probes on separate channel (`tunnel-health-probe`) to avoid creating sessions
- Grace period for remote startup (configurable intervals before failure counting)

#### Validated By

Cross-machine test suite (`Sources/HealthTestRunner/main.swift`) — 11 phases, all passing:

| Phase | What It Tests |
|-------|---------------|
| 1. Baseline Traffic | Bidirectional messaging over real mesh |
| 2. Idle Probe Backoff | Probe interval doubles during idle (500ms → 8s) |
| 3. Traffic Resets Probes | Application data resets interval to minimum |
| 4. Failure Detection | Firewall block → 3 failures → sessions closed |
| 5. Recovery After Block | New session after network restored |
| 6. Bidirectional Block | Both sides independently detect failure |
| 7. Transient Failure | Block < threshold → sessions survive |
| 8. Rapid Flapping | Block/unblock every 2s for 20s |
| 9. Endpoint Change | IP add/del detected, mesh still functional |
| 10. Latency & Jitter | 6 traffic shaping profiles (50ms–500ms latency, 1%–10% loss) |
| 11. Network State Cleanup | No test-specific artifacts remain |

Run with: `./demo-health-test.sh <ssh-host> <remote-path>`

---

### Phase 5: Failure Backoff and User Messaging

**Goal:** When health monitoring detects a failure and closes sessions,
automatically attempt reconnection with exponential backoff. Report
connection state changes to the application layer without spamming.

Currently, health failure closes all sessions to a machine and removes
the monitor. There is no automatic reconnection — the next `getSession()`
call starts fresh. This phase adds persistent reconnection attempts and
user-facing state reporting.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaTunnel/ReconnectionManager.swift` | Exponential backoff logic per machine |
| `Sources/OmertaTunnel/ConnectionStateReporter.swift` | Throttled user-facing state updates |
| `Tests/OmertaTunnelTests/ReconnectionManagerTests.swift` | Backoff behavior tests |
| `Tests/OmertaTunnelTests/ConnectionStateReporterTests.swift` | State reporting tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaTunnel/TunnelManager.swift` | Integrate ReconnectionManager into health failure handler; add ConnectionStateReporter |
| `Sources/OmertaTunnel/TunnelConfig.swift` | Add reconnection and state reporting config to `TunnelManagerConfig` |

#### API

```swift
/// Exponential backoff for reconnection attempts per machine.
///
/// Used by TunnelManager when health monitoring detects failure.
/// After closing sessions, TunnelManager hands off to ReconnectionManager
/// which retries with increasing delays.
public actor ReconnectionManager {
    public struct Config: Sendable {
        public var initialBackoff: Duration = .seconds(1)
        public var maxBackoff: Duration = .seconds(60)
        public var backoffMultiplier: Double = 2.0

        public static let `default` = Config()
    }

    public init(config: Config = .default)

    /// Record a failure for a machine. Returns the delay before next retry.
    public func recordFailure(for machineId: MachineId) -> Duration

    /// Record a successful reconnection. Resets backoff to initial.
    public func recordSuccess(for machineId: MachineId)

    /// Current backoff delay for a machine (nil if no active backoff).
    public func currentBackoff(for machineId: MachineId) -> Duration?

    /// Number of consecutive failures for a machine.
    public func failureCount(for machineId: MachineId) -> Int

    /// Clear state for a machine (e.g., when manually disconnecting).
    public func clear(machineId: MachineId)
}
```

```swift
/// Connection state visible to the application layer.
public enum TunnelConnectionState: Sendable, Equatable {
    case connected
    case reconnecting(attempt: Int, nextRetry: Duration)
    case failed(reason: String)
    case degraded(reason: String)
}

/// Reports connection state changes with throttling to avoid spam.
///
/// At most one state change per machine per `minInterval` (default 5s).
/// Identical consecutive states are suppressed.
public actor ConnectionStateReporter {
    public struct Config: Sendable {
        public var minInterval: Duration = .seconds(5)
        public var maxReconnectingMessages: Int = 5

        public static let `default` = Config()
    }

    public init(config: Config = .default)

    /// Set handler for state changes.
    public func onStateChange(
        _ handler: @escaping (MachineId, TunnelConnectionState) async -> Void
    )

    /// Report a state change (throttled internally).
    public func report(machineId: MachineId, state: TunnelConnectionState) async

    /// Stream of state changes for a specific machine.
    public func stateChanges(for machineId: MachineId) -> AsyncStream<TunnelConnectionState>
}
```

#### TunnelManager Integration

```swift
// Current handleHealthFailure (TunnelManager.swift:325):
//   1. Logs warning
//   2. Calls closeAllSessions(to:) — which closes sessions, sends close handshakes,
//      stops health monitor, and removes it from healthMonitors dict
//   3. Removes monitor from healthMonitors (redundant — closeAllSessions already does this)
//
// New handleHealthFailure with reconnection:
private func handleHealthFailure(machineId: MachineId) async {
    logger.warning("Health check FAILED for machine — closing all sessions",
                   metadata: ["machine": "\(machineId)"])
    await closeAllSessions(to: machineId)
    // Note: closeAllSessions() already stops and removes the health monitor

    // Report state change
    let delay = await reconnectionManager.recordFailure(for: machineId)
    let attempt = await reconnectionManager.failureCount(for: machineId)
    await stateReporter.report(
        machineId: machineId,
        state: .reconnecting(attempt: attempt, nextRetry: delay)
    )

    // Cancel any existing reconnection task for this machine
    reconnectionTasks[machineId]?.cancel()

    // Schedule reconnection attempt
    reconnectionTasks[machineId] = Task { [weak self] in
        try? await Task.sleep(for: delay)
        guard !Task.isCancelled, let self else { return }
        await self.attemptReconnection(to: machineId)
    }
}

private func attemptReconnection(to machineId: MachineId) async {
    do {
        // createSession → getSession → creates new session + new health monitor
        let session = try await createSession(withMachine: machineId)
        await reconnectionManager.recordSuccess(for: machineId)
        await stateReporter.report(machineId: machineId, state: .connected)
        reconnectionTasks.removeValue(forKey: machineId)
    } catch {
        // Failed again — handleHealthFailure will schedule next retry with increased backoff
        await handleHealthFailure(machineId: machineId)
    }
}
```

**New properties to add to TunnelManager:**
```swift
private let reconnectionManager: ReconnectionManager
private let stateReporter: ConnectionStateReporter
private var reconnectionTasks: [MachineId: Task<Void, Never>] = [:]
```

These should be initialized in `TunnelManager.init()` using config values from
`TunnelManagerConfig`.

#### Behavior

- Never gives up — keeps retrying with exponential backoff
- Backoff: 1s → 2s → 4s → 8s → 16s → 32s → 60s (capped)
- Success resets backoff to 1s
- User sees at most 5 "reconnecting" messages during sustained outage
- Identical consecutive states suppressed
- Manual `closeAllSessions()` clears reconnection state (no auto-retry)

#### Unit Tests

| Test | Description |
|------|-------------|
| `testBackoffDoubles` | Each failure doubles delay: 1s, 2s, 4s, 8s |
| `testBackoffCapsAt60s` | Delay never exceeds 60s |
| `testSuccessResetsBackoff` | Success after failures resets to 1s |
| `testClearStopsReconnection` | Manual clear stops retry loop |
| `testStateReporterThrottles` | Rapid state changes throttled to minInterval |
| `testIdenticalStatesSuppressed` | Same state twice → only one report |
| `testMaxReconnectingMessages` | At most 5 "reconnecting" messages during outage |
| `testStateTransitions` | connected → reconnecting → connected |
| `testDegradedOnHighLatency` | High probe latency → degraded state |
| `testFailedAfterMaxAttempts` | Optional: report .failed after N attempts (configurable, default: never) |

#### Cross-Machine Validation

Add to HealthTestRunner after Phase 5 is implemented:

| Phase | What It Tests |
|-------|---------------|
| New: Auto-Recovery | Block network, verify reconnection after unblock |
| New: Backoff Timing | Block network, verify retry delays increase |
| New: State Reporting | Verify state callback fires during block/unblock cycle |

---

### Phase 6: Peer Expiry and Rejoin

**Goal:** Implement peer lifecycle management in core OmertaMesh. Peers that
stop responding transition through stale → expired states. Expired peers are
dropped from peer lists. Peers can rejoin after being dropped.

**Note:** This code belongs in **OmertaMesh**, not OmertaTunnel. Peer expiry
is fundamental mesh behavior. TunnelManager's health monitoring detects
tunnel-level failures; PeerExpiryManager detects mesh-level peer dropout.

#### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaMesh/Discovery/PeerExpiryManager.swift` | Peer state tracking and expiry |
| `Tests/OmertaMeshTests/PeerExpiryManagerTests.swift` | Expiry behavior tests |

#### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaMesh/Public/MeshNetwork.swift` | Integrate PeerExpiryManager into mesh lifecycle |
| `Sources/OmertaMesh/Discovery/PeerStore.swift` | Add stale/expired states to stored peer records (currently persistence-only) |
| `Sources/OmertaMesh/Public/MeshConfig.swift` | Add `PeerExpiryConfig` to mesh configuration |

#### API

```swift
/// Peer lifecycle state.
public enum PeerState: Sendable, Equatable {
    case active
    case stale(missedPings: Int)
    case expired
}

/// Configuration for peer expiry.
public struct PeerExpiryConfig: Sendable {
    /// Missed pings before marking as stale (default: 3)
    public var staleThreshold: Int = 3

    /// Missed pings before marking as expired (default: 8)
    public var expiryThreshold: Int = 8

    /// Grace period for rejoining after expiry (default: 300s)
    public var rejoinGracePeriod: Duration = .seconds(300)

    /// Interval between peer liveness checks (default: 10s)
    public var checkInterval: Duration = .seconds(10)

    public static let `default` = PeerExpiryConfig()
}

/// Tracks peer liveness and manages stale/expired transitions.
///
/// Runs in OmertaMesh, not OmertaTunnel. Integrated with the mesh
/// node's ping/pong cycle.
public actor PeerExpiryManager {
    public init(config: PeerExpiryConfig = .default)

    /// Record a ping result for a peer.
    public func recordPing(peerId: PeerId, success: Bool)

    /// Current state of a peer.
    public func peerState(_ peerId: PeerId) -> PeerState

    /// Stream of peers that have expired (should be removed from peer lists).
    public var expiredPeers: AsyncStream<PeerId> { get }

    /// Stream of peers that have become stale (reduce gossip priority).
    public var stalePeers: AsyncStream<PeerId> { get }

    /// Handle a peer rejoining after expiry.
    /// Accepts if within grace period, rejects otherwise.
    public func handleRejoin(peerId: PeerId) -> Bool

    /// Start periodic liveness checks.
    public func start() async

    /// Stop checks and clear state.
    public func stop() async
}
```

#### MeshNode Integration

```swift
// In MeshNetwork, during periodic ping cycle:
for peer in peerStore.allPeers() {
    let success = await ping(peer)
    await expiryManager.recordPing(peerId: peer.id, success: success)
}

// Listen for expiry events:
for await expiredPeerId in expiryManager.expiredPeers {
    await peerStore.removePeer(expiredPeerId)
    // Notify TunnelManager to clean up sessions
    await tunnelManager?.closeAllSessions(to: expiredPeerId.machineId)
}

// Listen for stale events:
for await stalePeerId in expiryManager.stalePeers {
    await gossipRouter?.deprioritize(peerId: stalePeerId)
}
```

#### State Transitions

```
active ──(3 missed pings)──→ stale ──(8 missed pings)──→ expired
  ↑                            │                            │
  └──(any successful ping)─────┘                            │
  ↑                                                         │
  └──(rejoin within grace period)───────────────────────────┘
```

#### Interaction with Tunnel Health Monitoring

These are complementary systems at different layers:

| Concern | TunnelHealthMonitor | PeerExpiryManager |
|---------|--------------------|--------------------|
| Layer | OmertaTunnel | OmertaMesh |
| Monitors | Individual tunnel connections | Peer presence in mesh |
| Probe type | Health probe on tunnel channel | Mesh-level ping/pong |
| Failure action | Close sessions, trigger reconnection | Remove from peer list |
| Timescale | 500ms–15s probe intervals | 10s check intervals |
| Recovery | ReconnectionManager retries | Rejoin via discovery |

A peer can have healthy tunnel connections but be marked stale at the mesh level
(e.g., if mesh pings are lost but tunnel probes succeed on an existing session).
Conversely, a tunnel can fail while the peer remains active in the mesh.

#### Unit Tests

| Test | Description |
|------|-------------|
| `testPeerBecomesStale` | 3 missed pings → `.stale(missedPings: 3)` |
| `testPeerExpires` | 8 missed pings → `.expired` |
| `testStaleRecovery` | Stale peer responds → back to `.active` |
| `testExpiredPeerEmitted` | Expired peer appears in `expiredPeers` stream |
| `testStalePeerEmitted` | Stale peer appears in `stalePeers` stream |
| `testRejoinWithinGrace` | Expired peer rejoins within 300s → accepted |
| `testRejoinAfterGrace` | Expired peer rejoins after 300s → rejected |
| `testSuccessResetsState` | Any successful ping from stale → active |
| `testMultiplePeersIndependent` | Peer A stale doesn't affect peer B |
| `testStopClearsState` | Stop clears all tracking |

---

### Phase 7: WireGuard and Legacy VPN Cleanup

**Goal:** Remove all WireGuard-related code and unnecessary VPN infrastructure.
The mesh with netstack replaces WireGuard for networking.

**Status:** The omerta_mesh_tunnel repo has no OmertaVPN module — all tunnel
infrastructure uses the netstack-based architecture. The remaining WireGuard
references in this repo are minimal. The parent omerta repo and other
submodules (omerta_node, omerta_provider) may have more extensive legacy code.

#### This Repo (omerta_mesh_tunnel)

**Files to modify:**

| File | Changes |
|------|---------|
| `Sources/OmertaMesh/Public/DirectConnection.swift` | Remove WireGuard config generation methods and comments. The `DirectConnection` struct itself may still be useful for representing direct connections, but the WireGuard-specific parts should go. |
| `Sources/OmertaMesh/Public/nat-traversal-review.rtf` | Delete or archive — contains outdated WireGuard cleanup notes |

**Cleanup checklist for this repo:**

- [ ] Remove WireGuard config generation from `DirectConnection.swift`
- [ ] Remove or archive `nat-traversal-review.rtf`
- [ ] Grep for any remaining `WireGuard` / `wireguard` / `wg-quick` references
- [ ] Verify `swift build` and `swift test` pass after cleanup

#### Parent Repo and Other Submodules

The parent omerta repo and submodules (omerta_node, omerta_provider) likely
contain the bulk of legacy VPN code (OmertaVPN module, VPNManager,
EphemeralVPN, WireGuard managers, etc.). That cleanup should be tracked
separately in those repos. Key modules to remove:

- `OmertaVPN` — entire module (WireGuard managers, VPN tunnel service, packet filters)
- `OmertaVPNExtension` — network extension (replaced by netstack)
- VPN-related CLI commands and daemon startup code
- Root/sudo requirement checks (netstack runs in userspace)

**Note:** Keep SUDO_USER handling in home directory resolution — still useful
when daemon runs as root for TUN mode.

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
