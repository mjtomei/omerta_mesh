# Extensible Gossip and Relay Discovery

> **Context:** OmertaMesh provides generic gossip infrastructure. VM management
> utilities (OmertaProvider) use it to announce relay willingness for cloister
> networks. OmertaMesh has no awareness of VMs, cloisters, or relay semantics —
> it only provides the propagation mechanism.
>
> **Related plans:**
> - TUNNEL_INFRASTRUCTURE.md — tunnel health, VM packet capture, cleanup
> - VIRTUAL_NETWORK_REWORK.md — source of truth for tunnel/network APIs

## Overview

The existing `Gossip` actor (`Sources/OmertaMesh/Discovery/Gossip.swift`) only
handles `PeerAnnouncement` propagation. The existing `ChannelProvider` protocol
supports arbitrary channel-based point-to-point messaging. Neither provides
broadcast propagation of application-specific metadata across the mesh.

This plan adds:
1. **Extensible gossip** in OmertaMesh — any module can register typed gossip
   channels that propagate network-wide
2. **Relay announcement** in OmertaProvider — VM utilities gossip their
   willingness to relay cloister traffic, using the extensible gossip API

**Key Design Principles:**
- OmertaMesh owns propagation mechanics, not payload semantics
- Consumers register channels and receive typed `AsyncStream`s
- Usage-based priority — nodes prioritize channels they subscribe to
- All gossip propagates everywhere; priority only affects ordering under bandwidth pressure

---

## Phase 1: Extensible Gossip Infrastructure (OmertaMesh)

**Goal:** Add a generic gossip channel system alongside the existing
`PeerAnnouncement` gossip. Modules register channels, publish typed data,
and receive updates via `AsyncStream`.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Existing Gossip actor                                  │
│  └── PeerAnnouncement broadcast (unchanged)             │
│                                                         │
│  New: GossipChannel system                              │
│  ├── GossipChannelRouter — registration + propagation   │
│  ├── GossipEntry — opaque envelope (channelId + Data)   │
│  └── Plugs into existing gossip round in Gossip actor   │
└─────────────────────────────────────────────────────────┘
```

The `GossipChannelRouter` piggybacks on the existing `Gossip` actor's
periodic rounds. Each round, in addition to broadcasting `PeerAnnouncement`s,
the node also broadcasts recent `GossipEntry` items to the same fanout targets.

### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaMesh/Discovery/GossipChannelRouter.swift` | Channel registration, publish, subscribe, priority |
| `Sources/OmertaMesh/Discovery/GossipEntry.swift` | Envelope type for channel gossip |
| `Tests/OmertaMeshTests/GossipChannelRouterTests.swift` | Unit tests |

### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaMesh/Discovery/Gossip.swift` | Call into GossipChannelRouter during gossip rounds; handle incoming GossipEntry messages |
| `Sources/OmertaMesh/Types/MeshMessage.swift` | Add `.gossipEntries([GossipEntry])` case |
| `Sources/OmertaMesh/Public/MeshNetwork.swift` | Expose `gossipRouter: GossipChannelRouter` property |
| `Sources/OmertaMesh/MeshNode.swift` | Create and wire GossipChannelRouter |

### API

```swift
// === GossipEntry — opaque envelope ===

/// A single gossip entry. OmertaMesh treats payload as opaque bytes.
/// Only channelId is inspected for routing/priority.
public struct GossipEntry: Codable, Sendable, Identifiable {
    public let id: String                // dedup key: "\(channelId):\(machineId):\(sequence)"
    public let channelId: String
    public let machineId: MachineId      // originator
    public let payload: Data             // opaque to OmertaMesh
    public let timestamp: Date
    public let sequence: UInt64          // monotonic per (channelId, machineId)
}

// === GossipChannelRouter ===

/// Manages extensible gossip channels.
///
/// Consumers subscribe to channels and receive updates as AsyncStream.
/// Publishing sends to local subscribers immediately and queues for
/// next gossip round.
public actor GossipChannelRouter {
    /// Subscribe to a channel. Marks the channel as active (high priority).
    /// Only the latest entry per (channelId, machineId) is retained.
    ///
    /// Returns a stream of (machineId, decodedPayload) updates.
    public func subscribe<T: Codable & Sendable>(
        channel: String,
        as type: T.Type
    ) -> AsyncStream<(MachineId, T)>

    /// Unsubscribe from a channel. If no subscribers remain, channel
    /// becomes low priority (still forwarded, not processed).
    public func unsubscribe(channel: String)

    /// Publish an entry on a channel. Delivered to local subscribers
    /// immediately and queued for the next gossip round.
    public func publish<T: Codable & Sendable>(
        channel: String,
        data: T
    ) async throws

    /// Called by Gossip actor during each round. Returns entries to
    /// include in the next broadcast, ordered by priority.
    ///
    /// - Parameter budget: max bytes to include
    /// - Returns: entries to broadcast, highest priority first
    func entriesForBroadcast(budget: Int) -> [GossipEntry]

    /// Called by Gossip actor when entries arrive from a peer.
    func handleIncoming(_ entries: [GossipEntry]) async

    /// Channels this node is subscribed to (used for priority).
    var activeChannels: Set<String> { get }
}
```

### Priority Behavior

```
Subscribed channels:   entries broadcast every round, processed locally
Unsubscribed channels: entries forwarded with remaining budget, not processed

Budget allocation per round:
  1. All entries from subscribed channels (up to 70% of budget)
  2. Most recent entries from unsubscribed channels (remaining 30%)
```

### Retention

Each `(channelId, machineId)` pair retains only the latest entry (by sequence
number). Entries older than `entryTTLSeconds` (default: 300) are pruned.

### Configuration

```swift
/// Added to existing GossipConfig
extension GossipConfig {
    /// Max bytes of channel gossip entries per round (default: 4096)
    public var channelBudgetBytes: Int

    /// TTL for channel entries before pruning (default: 300s)
    public var channelEntryTTLSeconds: TimeInterval
}
```

### Unit Tests

| Test | Description |
|------|-------------|
| `testSubscribeReceivesPublished` | Subscribe to channel, publish, verify stream yields value |
| `testPublishEncodesDecodes` | Publish typed data, verify subscriber receives correct type |
| `testLatestEntryWins` | Publish twice from same machine, verify only latest retained |
| `testUnsubscribedChannelForwarded` | Unsubscribed channel entries included in broadcast |
| `testSubscribedChannelPrioritized` | Under budget pressure, subscribed entries sent first |
| `testEntryTTLPruning` | Old entries pruned after TTL |
| `testMultipleSubscribers` | Two subscribers on same channel both receive updates |
| `testEntriesForBroadcast` | Verify budget respected and priority ordering |

---

## Phase 2: Relay Announcement (OmertaProvider)

**Goal:** VM management utilities announce relay willingness via the gossip
channel system. Other nodes discover available relays by subscribing to the
relay channel. OmertaMesh knows nothing about what "relay" means — it just
propagates the gossip entries.

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│  OmertaProvider                                          │
│  ├── RelayAnnouncer — publishes relay status via gossip  │
│  └── RelayDiscovery — subscribes to relay channel,       │
│                       maintains list of available relays  │
│                                                          │
│  Uses: GossipChannelRouter (from OmertaMesh)             │
│  Channel: "relay-availability"                           │
└──────────────────────────────────────────────────────────┘
```

### Files to Create

| File | Description |
|------|-------------|
| `Sources/OmertaProvider/Relay/RelayAnnouncer.swift` | Publishes relay availability |
| `Sources/OmertaProvider/Relay/RelayDiscovery.swift` | Discovers available relays |
| `Sources/OmertaProvider/Relay/RelayStatus.swift` | Shared types for relay gossip |
| `Tests/OmertaProviderTests/RelayAnnouncerTests.swift` | Announcement tests |
| `Tests/OmertaProviderTests/RelayDiscoveryTests.swift` | Discovery tests |

### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Wire up RelayAnnouncer and RelayDiscovery |

### API

```swift
// === Relay gossip types (in OmertaProvider, NOT OmertaMesh) ===

/// What gets gossiped on the "relay-availability" channel.
/// OmertaMesh sees this as opaque Data.
public struct RelayStatus: Codable, Sendable {
    /// Available capacity (0 = not accepting relays)
    public let availableSlots: Int

    /// Current number of active relay sessions
    public let activeSessionCount: Int

    /// Supported cloister protocol versions
    public let supportedVersions: [Int]
}

/// Per-machine relay config (stored on disk at ~/.omerta/provider/relay.json)
public struct RelayConfig: Codable, Sendable {
    public var enabled: Bool = false
    public var maxSlots: Int = 10
}

// === RelayAnnouncer ===

/// Periodically publishes this node's relay availability via gossip.
/// Only publishes when relay is enabled in config.
public actor RelayAnnouncer {
    public static let channel = "relay-availability"

    public init(
        gossipRouter: GossipChannelRouter,
        config: RelayConfig,
        announceInterval: Duration = .seconds(60)
    )

    /// Start periodic announcements. No-op if relay not enabled.
    public func start() async

    /// Stop announcements. Publishes a final status with 0 slots.
    public func stop() async

    /// Update the current session count (called when sessions change).
    public func updateActiveSessionCount(_ count: Int) async
}

// === RelayDiscovery ===

/// Subscribes to relay gossip and maintains a list of available relays.
public actor RelayDiscovery {
    public init(gossipRouter: GossipChannelRouter)

    /// Start listening for relay announcements.
    public func start() async

    /// Stop listening.
    public func stop() async

    /// Available relays sorted by available capacity (descending).
    public func availableRelays() async -> [(machineId: MachineId, status: RelayStatus)]

    /// Request a specific relay. Returns true if the relay accepts.
    /// This uses point-to-point channel messaging (ChannelProvider),
    /// not gossip — gossip is only for discovery.
    public func requestRelay(
        machineId: MachineId,
        via channelProvider: any ChannelProvider
    ) async throws -> Bool
}
```

### Relay Request Flow

Discovery uses gossip. Relay requests use point-to-point channels:

```
1. RelayDiscovery subscribes to "relay-availability" gossip channel
2. RelayAnnouncer publishes RelayStatus periodically
3. Consumer calls availableRelays() to find candidates
4. Consumer sends relay request via ChannelProvider ("relay-request" channel)
5. Provider's handler accepts/rejects, responds via "relay-response" channel
6. Provider decrements available slots, publishes updated RelayStatus
```

### Unit Tests

| Test | Description |
|------|-------------|
| `testAnnouncerPublishesWhenEnabled` | Enabled config → status published on channel |
| `testAnnouncerSilentWhenDisabled` | Disabled config → nothing published |
| `testAnnouncerStopPublishesZero` | Stop → final status with 0 slots |
| `testDiscoveryReceivesAnnouncements` | Published status appears in availableRelays() |
| `testDiscoverySortsByCapacity` | Multiple relays sorted by available slots |
| `testDiscoveryRemovesExpired` | Relay that stops announcing is removed after TTL |
| `testRequestRelayAccepted` | Request to relay with capacity → accepted |
| `testRequestRelayFull` | Request to relay at capacity → rejected |
| `testSessionCountUpdatesAnnouncement` | Active session change triggers updated announcement |

### Manual Testing

```bash
# Terminal 1: Start node A (relay enabled)
omertad start --port 18001 --relay-enabled --relay-slots 5

# Terminal 2: Start node B (relay enabled)
omertad start --port 18002 --bootstrap localhost:18001 --relay-enabled --relay-slots 3

# Terminal 3: Start node C (consumer, no relay)
omertad start --port 18003 --bootstrap localhost:18001

# On node C, discover relays:
omerta relay list
# Should show:
#   Machine A: 5 slots available
#   Machine B: 3 slots available

# Request relay from A:
omerta relay request --machine <A-machine-id>
# Should succeed

# Check updated availability:
omerta relay list
#   Machine A: 4 slots available
#   Machine B: 3 slots available
```

---

## Phase 3: Integration with VM Lifecycle

**Goal:** Wire relay announcements into VM session lifecycle so slot counts
stay accurate as VMs are provisioned and released.

### Files to Modify

| File | Changes |
|------|---------|
| `Sources/OmertaProvider/MeshProviderDaemon.swift` | Update RelayAnnouncer when VM sessions start/stop |
| `Sources/OmertaVM/VMManager.swift` | Notify provider daemon on VM lifecycle events |

### Behavior

```
VM provisioned for relay:
  1. VMManager creates VM
  2. MeshProviderDaemon increments active session count
  3. RelayAnnouncer publishes updated status (slots - 1)

VM released:
  1. VMManager tears down VM
  2. MeshProviderDaemon decrements active session count
  3. RelayAnnouncer publishes updated status (slots + 1)

Provider shutdown:
  1. RelayAnnouncer.stop() publishes 0-slot status
  2. Peers see updated gossip, remove from relay list
  3. TTL expiry handles the case where shutdown status doesn't propagate
```

### Unit Tests

| Test | Description |
|------|-------------|
| `testVMProvisionDecrementsSlots` | Provision VM → announcement shows fewer slots |
| `testVMReleaseIncrementsSlots` | Release VM → announcement shows more slots |
| `testShutdownPublishesZero` | Provider shutdown → 0-slot announcement |
| `testSlotCountNeverNegative` | Over-provision attempt → rejected at capacity |
