# WireGuard Roaming Design for OmertaMesh

> **Note (January 2026)**: References to STUN-based NAT detection in this document have been superseded.
> NAT type is now detected via peer-based observation (peers report endpoints in pong messages).
> See `mesh-relay-network.md` for details.

## Overview

This document describes how OmertaMesh handles device roaming transparently while using WireGuard as the underlying transport. The goal is to maintain active connections when devices:

- Change networks (WiFi to cellular, home to office)
- Change IP addresses (DHCP renewal, NAT rebinding)
- Transition between direct and relay-mediated connections
- Have multiple active interfaces with different priorities

## WireGuard's Native Roaming Behavior

WireGuard has built-in roaming support with specific characteristics:

### How WireGuard Roaming Works

1. **Peer Identification**: Peers are identified by their public key, not by IP address
2. **Endpoint Update on Receive**: When a valid encrypted packet arrives from a new source IP:port, WireGuard automatically updates the peer's endpoint
3. **Stateless Design**: No explicit "connection" state - just cryptographic sessions
4. **Keepalive Mechanism**: `PersistentKeepalive` sends packets every N seconds to maintain NAT mappings

### WireGuard Roaming Limitations

1. **Passive Discovery**: WireGuard only updates endpoints when it *receives* a packet from the new address. The roaming peer must initiate.
2. **Single Endpoint**: Each peer can only have one active endpoint at a time
3. **No Multi-path**: Cannot use multiple interfaces simultaneously for the same peer
4. **No Path Quality Awareness**: Doesn't consider latency, packet loss, or metered status
5. **No Relay Awareness**: Doesn't know about relay-mediated paths

## OmertaMesh Roaming Architecture

### Layer Separation

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│            (send/receive encrypted messages)                 │
├─────────────────────────────────────────────────────────────┤
│                    Mesh Routing Layer                        │
│  - Peer discovery and announcement                          │
│  - Path selection (direct vs relay)                         │
│  - Roaming detection and recovery                           │
│  - Interface prioritization                                  │
├─────────────────────────────────────────────────────────────┤
│                   Connection Manager                         │
│  - WireGuard tunnel management                              │
│  - Endpoint updates                                         │
│  - Keepalive coordination                                   │
├─────────────────────────────────────────────────────────────┤
│                    WireGuard Layer                           │
│  - Cryptographic transport                                  │
│  - Native roaming (endpoint update on receive)              │
└─────────────────────────────────────────────────────────────┘
```

### Roaming Detection

The mesh layer must detect network changes through multiple mechanisms:

```swift
class NetworkMonitor {
    // 1. Interface state monitoring
    func monitorInterfaceChanges() {
        // Detect: interface up/down, IP address changes
        // Platform-specific: netlink (Linux), SCNetworkReachability (macOS/iOS)
    }

    // 2. Connectivity probing
    func probeConnectivity() {
        // Periodic probes to relay/bootstrap nodes
        // Detect: NAT rebinding, path failures
    }

    // 3. WireGuard handshake monitoring
    func monitorHandshakes() {
        // Track last handshake time per peer
        // Detect: stale connections needing refresh
    }
}
```

### Roaming Recovery Process

When a network change is detected:

```
1. DETECT CHANGE
   └── Interface event OR probe failure OR handshake timeout

2. RE-EVALUATE NETWORK
   ├── Perform NAT type detection (STUN)
   ├── Check available interfaces
   └── Determine best path for each peer

3. UPDATE PATHS
   ├── If direct still possible: Update WireGuard endpoint
   ├── If relay needed: Establish relay session
   └── If upgrading from relay: Attempt direct, keep relay as backup

4. NOTIFY PEERS
   ├── Send announcement with new endpoint(s)
   └── Trigger keepalive to update remote endpoint

5. VERIFY CONNECTIVITY
   ├── Send probe packets
   └── Confirm bidirectional communication
```

## Interface Prioritization

### Priority Model

```swift
struct NetworkInterface: Comparable {
    let name: String           // "en0", "wlan0", "pdp_ip0"
    let type: InterfaceType    // .wifi, .ethernet, .cellular, .vpn
    let isMetered: Bool        // Cellular usually metered
    let priority: Int          // Lower = preferred (0 = highest)
    let ipv4Address: String?
    let ipv6Address: String?

    // Default priorities (configurable)
    static let defaultPriorities: [InterfaceType: Int] = [
        .ethernet: 0,      // Wired = most preferred
        .wifi: 10,         // WiFi = second choice
        .vpn: 20,          // VPN = third (may add latency)
        .cellular: 100,    // Cellular = last resort (metered)
    ]
}
```

### Interface Selection Algorithm

```swift
func selectBestInterface(for peer: PeerID) -> NetworkInterface? {
    let availableInterfaces = getActiveInterfaces()
        .filter { $0.hasConnectivity }
        .sorted { $0.priority < $1.priority }

    for interface in availableInterfaces {
        // Check if this interface can reach the peer
        if canReachPeer(peer, via: interface) {
            // Check NAT compatibility
            let natType = detectNATType(on: interface)
            let peerNatType = getPeerNATType(peer)

            if canConnectDirect(natType, peerNatType) {
                return interface
            }
        }
    }

    // Fall back to relay-capable interface
    return availableInterfaces.first { canReachRelay(via: $0) }
}
```

### Metered Connection Policy

```swift
enum MeteredPolicy {
    case allowAlways           // Use cellular freely
    case allowForKeepalive     // Only keepalive on cellular
    case allowWhenNoAlternative // Only if WiFi unavailable
    case neverAllow            // Block cellular entirely
}

func shouldUseInterface(_ iface: NetworkInterface, for traffic: TrafficType) -> Bool {
    guard iface.isMetered else { return true }

    switch (meteredPolicy, traffic) {
    case (.allowAlways, _):
        return true
    case (.allowForKeepalive, .keepalive):
        return true
    case (.allowWhenNoAlternative, _):
        return !hasUnmeteredAlternative()
    case (.neverAllow, _):
        return false
    default:
        return false
    }
}
```

## Direct-to-Relay Transitions

### Scenario: Direct → Relay

When moving from a direct-capable network to one requiring relay:

```
BEFORE (Full-cone NAT - direct works):
┌─────────┐                      ┌─────────┐
│ Peer A  │◄────── direct ──────►│ Peer B  │
└─────────┘                      └─────────┘

AFTER (Symmetric NAT - relay required):
┌─────────┐      ┌─────────┐      ┌─────────┐
│ Peer A  │◄────►│  Relay  │◄────►│ Peer B  │
└─────────┘      └─────────┘      └─────────┘
```

**Recovery Steps:**

1. Detect NAT type change (STUN returns different mapping)
2. Direct connection starts failing (handshake timeouts)
3. Request relay allocation from selected relay node
4. Establish WireGuard tunnel to relay
5. Relay forwards encapsulated traffic to Peer B
6. Send path update announcement to Peer B
7. Traffic flows via relay with minimal interruption

### Scenario: Relay → Direct

When moving from relay-required to direct-capable network:

```swift
func attemptDirectUpgrade(peer: PeerID, currentPath: RelayPath) async {
    // 1. Detect improved NAT type
    let newNatType = await detectNATType()
    guard newNatType.canHolePunch(with: peer.natType) else { return }

    // 2. Keep relay path active during upgrade attempt
    let upgradeTimeout: Duration = .seconds(30)

    // 3. Attempt hole punch
    if let directEndpoint = await attemptHolePunch(with: peer, timeout: upgradeTimeout) {
        // 4. Verify direct path works
        if await verifyPath(directEndpoint, peer: peer) {
            // 5. Switch to direct
            updateWireGuardEndpoint(peer: peer, endpoint: directEndpoint)

            // 6. Gradually phase out relay
            await Task.sleep(for: .seconds(5))
            releaseRelayPath(currentPath)
        }
    }
    // If upgrade fails, continue using relay (no action needed)
}
```

## Warm Relay Strategy

### The Symmetric NAT + Roaming Peer Problem

Consider this edge case:
- **Peer A**: Stationary, behind symmetric NAT
- **Peer B**: Roaming, currently connected via hole-punched direct connection

```
CURRENT STATE (direct connection established via hole punch):
┌─────────────┐                           ┌─────────────┐
│   Peer A    │◄──────── direct ─────────►│   Peer B    │
│ (symmetric) │                           │  (roaming)  │
└─────────────┘                           └─────────────┘
       │                                         │
       │  NAT mapping: allows traffic from       │
       │  B's current IP:port only               │
       └─────────────────────────────────────────┘
```

**When Peer B roams and gets a new IP address:**

1. Peer B's new IP is different from what Peer A's NAT expects
2. Peer A's symmetric NAT drops packets from B's new IP (not from expected source)
3. Peer B cannot reach Peer A directly
4. The direct connection is broken
5. **Problem**: How does Peer B notify Peer A to switch to relay?

```
AFTER ROAM (connection broken):
┌─────────────┐          ✗               ┌─────────────┐
│   Peer A    │◄──────── blocked ────────│   Peer B    │
│ (symmetric) │                          │ (new IP)    │
└─────────────┘                          └─────────────┘
       │
       │  NAT drops packets from B's new IP
       │  because it's not the expected source
       └──────────────────────────────────
```

### Solution: Always-On Warm Relay Connections

Both peers maintain persistent "warm" connections to relay nodes, even when using direct paths:

```
NORMAL OPERATION (direct + warm relay):
┌─────────────┐                           ┌─────────────┐
│   Peer A    │◄──────── direct ─────────►│   Peer B    │
│ (symmetric) │                           │  (mobile)   │
└──────┬──────┘                           └──────┬──────┘
       │                                         │
       │  keepalive (every 30s)                  │  keepalive (every 30s)
       ▼                                         ▼
┌─────────────────────────────────────────────────────────┐
│                         Relay                            │
│  (maintains session state for both peers)               │
└─────────────────────────────────────────────────────────┘
```

**When Peer B roams:**

```
AFTER ROAM (instant relay failover):
┌─────────────┐                           ┌─────────────┐
│   Peer A    │         ✗ blocked         │   Peer B    │
│ (symmetric) │                           │ (new IP)    │
└──────┬──────┘                           └──────┬──────┘
       │                                         │
       │  existing session                       │  new session from new IP
       ▼                                         ▼
┌─────────────────────────────────────────────────────────┐
│                         Relay                            │
│  "I know both peers - forward B's traffic to A"         │
└─────────────────────────────────────────────────────────┘
```

1. Peer B detects network change
2. Peer B immediately sends traffic via its warm relay connection
3. Relay already knows Peer A (from keepalives) and forwards traffic
4. Peer A receives traffic from Relay (which its NAT allows)
5. Connection continues with minimal interruption

### Implementation

```swift
class WarmRelayManager {
    // Minimum number of warm relay connections to maintain
    let minWarmRelays: Int = 2

    // Keepalive interval for warm connections (less frequent than active)
    let warmKeepaliveInterval: Duration = .seconds(30)

    // Active relay sessions (currently forwarding traffic)
    var activeRelays: [RelaySession] = []

    // Warm relay sessions (ready for instant failover)
    var warmRelays: [RelaySession] = []

    // Establish warm connections on startup
    func initializeWarmRelays() async {
        let relays = await selectBestRelays(count: minWarmRelays)

        for relay in relays {
            let session = await establishRelaySession(relay)
            warmRelays.append(session)

            // Start keepalive task
            Task {
                await maintainWarmSession(session)
            }
        }
    }

    // Maintain a warm session with periodic keepalives
    func maintainWarmSession(_ session: RelaySession) async {
        while session.isActive {
            // Send lightweight keepalive
            await session.sendKeepalive()

            // Update relay with our current endpoint info
            await session.updateEndpointInfo(
                currentIP: getExternalIP(),
                natType: currentNATType,
                interfaces: getActiveInterfaces()
            )

            try? await Task.sleep(for: warmKeepaliveInterval)
        }
    }

    // Instant failover when roaming detected
    func handleRoaming(newInterface: NetworkInterface) async {
        // 1. Immediately switch to relay for all peer connections
        for peer in connectedPeers {
            if let warmRelay = findBestWarmRelay(for: peer) {
                // Promote warm relay to active
                await activateRelayPath(warmRelay, for: peer)

                // Notify peer (via relay) that we've roamed
                await sendRoamingNotification(to: peer, via: warmRelay)
            }
        }

        // 2. Update warm relays with new endpoint info
        for relay in warmRelays {
            await relay.updateEndpointInfo(
                currentIP: newInterface.externalIP,
                natType: detectNATType(on: newInterface),
                interfaces: [newInterface]
            )
        }

        // 3. Attempt to re-establish direct connections in background
        Task {
            await attemptDirectReconnection()
        }
    }
}
```

### Relay Session State

The relay maintains state for warm connections:

```swift
struct RelayPeerState {
    let peerID: PeerID
    let publicKey: WireGuardPublicKey

    // Last known endpoint (may be outdated if peer roamed)
    var lastKnownEndpoint: Endpoint

    // Warm session info
    var isWarm: Bool                    // Keepalives being received
    var lastKeepalive: Date
    var natType: NATType
    var prefersDirect: Bool             // Peer prefers direct when possible

    // For instant failover
    var canReceiveViaRelay: Bool {
        // Peer has sent keepalive recently enough
        return Date().timeIntervalSince(lastKeepalive) < 60
    }
}

class RelayNode {
    var peerStates: [PeerID: RelayPeerState] = [:]

    // Handle incoming traffic for a peer
    func forwardToPeer(_ data: Data, destination: PeerID) async throws {
        guard let state = peerStates[destination] else {
            throw RelayError.unknownPeer
        }

        guard state.canReceiveViaRelay else {
            throw RelayError.peerNotReachable
        }

        // Forward to peer's last known endpoint
        // (or via their warm connection if they're also connected to us)
        await send(data, to: state.lastKnownEndpoint)
    }

    // Handle keepalive from a peer
    func handleKeepalive(from peer: PeerID, endpoint: Endpoint, info: EndpointInfo) {
        peerStates[peer] = RelayPeerState(
            peerID: peer,
            publicKey: info.publicKey,
            lastKnownEndpoint: endpoint,
            isWarm: true,
            lastKeepalive: Date(),
            natType: info.natType,
            prefersDirect: info.prefersDirect
        )
    }
}
```

### Roaming Notification Protocol

When a peer roams, it notifies other peers via the relay:

```swift
struct RoamingNotification: Codable {
    let fromPeer: PeerID
    let newEndpoint: Endpoint?          // nil if behind symmetric NAT
    let newNATType: NATType
    let preferredPath: PathPreference   // .direct, .relay, .any
    let timestamp: Date

    enum PathPreference {
        case direct     // Try to establish direct connection
        case relay      // Stay on relay (e.g., metered network)
        case any        // No preference, choose best
    }
}

// Receiving peer handles the notification
func handleRoamingNotification(_ notification: RoamingNotification) async {
    let peer = notification.fromPeer

    // Update peer's known state
    updatePeerState(peer,
        natType: notification.newNATType,
        endpoint: notification.newEndpoint
    )

    // Decide on path strategy
    switch (myNATType, notification.newNATType, notification.preferredPath) {
    case (_, _, .relay):
        // Peer prefers relay, use it
        await switchToRelayPath(peer)

    case (.symmetric, .symmetric, _):
        // Both symmetric - must use relay
        await switchToRelayPath(peer)

    case (_, _, .direct) where canHolePunch(with: notification.newNATType):
        // Try direct, keep relay as backup
        await attemptDirectWithRelayBackup(peer, notification.newEndpoint)

    default:
        // Use relay, attempt direct upgrade in background
        await switchToRelayPath(peer)
        Task { await attemptDirectUpgrade(peer) }
    }
}
```

### Benefits of Warm Relay Strategy

1. **Instant Failover**: No delay establishing relay connection during roaming
2. **Symmetric NAT Compatibility**: Works even when stationary peer can't accept new connections
3. **Make-Before-Break**: New path ready before old path fails
4. **Bidirectional Notification**: Both peers learn about roaming via relay
5. **Graceful Degradation**: If direct fails, relay is already working

### Keepalive Traffic Analysis

Warm relay connections add minimal overhead:

| Traffic Type | Frequency | Size | Monthly Data |
|--------------|-----------|------|--------------|
| Warm keepalive | Every 30s | ~100 bytes | ~8.6 MB |
| Endpoint update | Every 30s | ~200 bytes | ~17.3 MB |
| **Total per relay** | | | **~26 MB** |

With 2 warm relays: ~52 MB/month - acceptable even on metered connections.

### Configuration

```yaml
warm_relay:
  # Number of warm relay connections to maintain
  min_warm_relays: 2
  max_warm_relays: 3

  # Keepalive interval (seconds)
  keepalive_interval: 30

  # How long before a warm session is considered stale
  stale_threshold: 60

  # Whether to maintain warm relays on metered connections
  allow_on_metered: true

  # Relay selection criteria
  selection:
    prefer_low_latency: true
    prefer_geographic_diversity: true
    max_latency_ms: 100
```

## WireGuard Integration Details

### Endpoint Update Strategy

```swift
class WireGuardManager {
    // Update peer endpoint when roaming detected
    func updatePeerEndpoint(peer: PeerID, newEndpoint: Endpoint) {
        // 1. Update WireGuard configuration
        wgSetPeerEndpoint(peer.publicKey, newEndpoint)

        // 2. Trigger immediate handshake
        sendKeepalive(to: peer)

        // 3. Monitor for handshake completion
        awaitHandshake(peer, timeout: .seconds(10))
    }

    // Handle endpoint for relay-mediated connections
    func configureRelayEndpoint(peer: PeerID, relay: RelayNode) {
        // WireGuard endpoint points to relay
        // Relay handles forwarding to actual peer
        let relayEndpoint = Endpoint(
            host: relay.publicIP,
            port: relay.wgPort
        )
        wgSetPeerEndpoint(peer.publicKey, relayEndpoint)

        // Configure relay session
        relay.registerSession(
            localPeer: self.identity,
            remotePeer: peer,
            wgPublicKey: peer.publicKey
        )
    }
}
```

### Keepalive Coordination

```swift
struct KeepaliveConfig {
    // Base keepalive interval (WireGuard PersistentKeepalive)
    let wgKeepalive: Duration = .seconds(25)

    // Mesh-layer keepalive (more frequent during roaming)
    var meshKeepalive: Duration = .seconds(60)

    // Aggressive keepalive after network change
    let roamingKeepalive: Duration = .seconds(5)
    let roamingDuration: Duration = .seconds(30)
}

func handleNetworkChange() {
    // Temporarily increase keepalive frequency
    keepaliveConfig.meshKeepalive = keepaliveConfig.roamingKeepalive

    // Send immediate keepalive to all connected peers
    for peer in connectedPeers {
        sendKeepalive(to: peer)
    }

    // Return to normal after roaming stabilizes
    Task {
        await Task.sleep(for: keepaliveConfig.roamingDuration)
        keepaliveConfig.meshKeepalive = .seconds(60)
    }
}
```

### Multi-path Considerations

While WireGuard only supports one endpoint per peer, the mesh can manage multiple paths:

```swift
class PathManager {
    // Track multiple possible paths per peer
    struct PeerPaths {
        var activePath: Path           // Currently used by WireGuard
        var backupPaths: [Path]        // Ready to switch to
        var directPath: Path?          // Direct if available
        var relayPaths: [Path]         // Via different relays
    }

    // Proactive path maintenance
    func maintainBackupPaths(for peer: PeerID) {
        // Keep relay session warm even when using direct
        if let directPath = paths[peer]?.directPath, directPath.isActive {
            // Periodic relay keepalive (infrequent)
            for relayPath in paths[peer]?.relayPaths ?? [] {
                sendRelayKeepalive(relayPath, interval: .seconds(300))
            }
        }
    }

    // Fast failover
    func handlePathFailure(peer: PeerID, failedPath: Path) {
        guard let backup = paths[peer]?.backupPaths.first else {
            // No backup - attempt recovery
            attemptPathRecovery(peer)
            return
        }

        // Switch to backup immediately
        switchToPath(peer, path: backup)
    }
}
```

## Testing Roaming Scenarios

### Test Matrix

| Scenario | Initial State | Action | Expected Behavior |
|----------|--------------|--------|-------------------|
| WiFi→Cellular | Direct via WiFi | WiFi disabled | Failover to cellular, maintain connection |
| Cellular→WiFi | Relay via cellular | WiFi available | Upgrade to direct via WiFi |
| NAT Change | Direct (full-cone) | Move to symmetric NAT | Fallback to relay |
| IP Change | Connected | DHCP renewal (new IP) | Re-establish with same peer |
| Dual-stack | IPv4 direct | IPv6 becomes available | Consider IPv6 if lower latency |
| Multi-relay | Using relay A | Relay A fails | Failover to relay B |

### Verification Points

For each roaming test, verify:

1. **Connection Continuity**: No connection reset at application layer
2. **Message Delivery**: No lost messages during transition
3. **Latency Impact**: Measure latency before/during/after roam
4. **Path Optimality**: Correct path selected (direct when possible)
5. **Resource Cleanup**: Old paths/sessions released properly

## Implementation Phases

### Phase 1: Basic Roaming
- Network interface monitoring
- Simple endpoint updates
- Manual relay fallback

### Phase 2: Intelligent Path Selection
- NAT type awareness
- Automatic direct↔relay transitions
- Interface prioritization

### Phase 3: Seamless Handoff
- Zero-downtime transitions
- Proactive path maintenance
- Message queuing during transition

### Phase 4: Advanced Features
- Multi-path aggregation (bond multiple interfaces)
- Predictive roaming (pre-establish paths)
- Quality-based path selection (latency, jitter, loss)

## Configuration Options

```yaml
roaming:
  # Interface priority (lower = preferred)
  interface_priorities:
    ethernet: 0
    wifi: 10
    cellular: 100

  # Metered connection policy
  metered_policy: allow_when_no_alternative

  # Keepalive settings
  keepalive:
    normal: 60s
    roaming: 5s
    roaming_duration: 30s

  # Path maintenance
  paths:
    maintain_backup_relay: true
    direct_upgrade_timeout: 30s
    probe_interval: 30s

  # Detection thresholds
  detection:
    handshake_timeout: 10s
    probe_failure_threshold: 3
    path_switch_hysteresis: 5s
```

## Security Considerations

1. **Endpoint Spoofing**: WireGuard's cryptographic verification prevents endpoint spoofing
2. **Relay Trust**: Relay cannot decrypt traffic (end-to-end encryption via WireGuard)
3. **Path Manipulation**: Mesh announcements should be authenticated
4. **DoS via Roaming**: Rate-limit path change announcements
