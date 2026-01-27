# OmertaMesh Post-Migration File Structure

This document describes the file structure after the channel-based migration is complete, and summarizes changes to each file.

## Legend

| Symbol | Meaning |
|--------|---------|
| `[NEW]` | New file being added |
| `[MOD]` | Existing file being modified |
| `[MOVE]` | File moving to different directory |
| `[DEL]` | File being deleted |
| `[KEEP]` | No changes |

---

## Sources/OmertaMesh/

### Directory Summaries

| Directory | Purpose |
|-----------|---------|
| **Connection/** | Manages peer connection lifecycle and keepalive. Tracks connection state and sends periodic pings to maintain NAT mappings. |
| **Crypto/** | Encryption and decryption primitives. ChaCha20-Poly1305 implementation and key derivation. |
| **Envelope/** | Message envelope framing. Binary envelope structure with layered encryption. |
| **Discovery/** | Peer discovery via gossip protocol and bootstrap nodes. Handles initial network join and ongoing peer exchange. |
| **Freshness/** | Tracks how recently peers were contacted. Used for routing decisions and endpoint discovery queries. |
| **HolePunch/** | NAT traversal via UDP hole punching. Coordinates simultaneous connection attempts between peers behind NAT. Includes NAT behavior prediction. |
| **Identity/** | Ed25519 keypair management for peer identity. Handles key generation, storage, and signing. |
| **Logging/** | Structured event logging to JSON Lines files. Records mesh events for debugging and analysis. |
| **Network/** | Network membership and key management. Stores network credentials and tracks joined networks. |
| **Public/** | Public API surface and documentation. Contains `MeshNetwork`, `ChannelProvider`, configuration, and errors. |
| **Relay/** | Message relaying through intermediate peers. Used when direct connection and hole punching fail. |
| **Transport/** | Low-level UDP socket operations. Handles packet send/receive and socket lifecycle. |
| **Types/** | Shared type definitions. Message enums, envelope formats, endpoint utilities, and NAT types. |
| **Utilities/** | Internal helper code. Retry logic, JSON coding helpers. |
| **Services/** | Channel-based example applications. Health monitoring, latency probes, directory lookup, messaging, key negotiation. |
| **Validation/** | Input validation helpers. Endpoint format validation and sanitization. |

### File Tree

```
Sources/OmertaMesh/
├── OmertaMesh.swift                          [KEEP]    Module exports
├── MachineId.swift                           [KEEP]    Machine identifier
├── MeshNode.swift                            [MOD]     Convert message handling to channels
├── PeerEndpointManager.swift                 [KEEP]    Endpoint prioritization
│
│   # Connection/ - Peer connection lifecycle and NAT keepalive
├── Connection/
│   ├── ConnectionKeepalive.swift             [MOD]     Use channel-based ping internally
│   └── PeerConnection.swift                  [KEEP]    Connection state
│
│   # Crypto/ - Encryption primitives (ChaCha20-Poly1305, key derivation)
├── Crypto/
│   └── MessageEncryption.swift               [KEEP]    ChaCha20-Poly1305 encrypt/decrypt
│
│   # Envelope/ - Message framing and wire format encoding
├── Envelope/
│   ├── BinaryEnvelope.swift                  [MOVE]    From Types/, rewritten for v2
│   └── EnvelopeHeader.swift                  [NEW]     Header structure and encoding
│
│   # Discovery/ - Gossip protocol and bootstrap for peer discovery
├── Discovery/
│   ├── Bootstrap.swift                       [MOD]     Use channel-based gossip
│   ├── Gossip.swift                          [MOD]     Convert to mesh-gossip channel
│   ├── PeerCache.swift                       [KEEP]    In-memory peer cache
│   └── PeerStore.swift                       [KEEP]    Peer persistence
│
│   # Freshness/ - Contact recency tracking for routing decisions
├── Freshness/
│   ├── FreshnessManager.swift                [MOD]     Convert to mesh-dir-* channels, remove pathFailed
│   ├── FreshnessQuery.swift                  [MOD]     Use channel-based queries
│   ├── PathFailureReporter.swift             [MOD]     Remove broadcast, keep local tracking only
│   └── RecentContactTracker.swift            [KEEP]    Contact time tracking
│
│   # HolePunch/ - NAT traversal via coordinated UDP hole punching
├── HolePunch/
│   ├── HolePunchCoordinator.swift            [MOD]     Convert to mesh-holepunch channel
│   ├── HolePuncher.swift                     [KEEP]    Low-level punch implementation
│   ├── HolePunchManager.swift                [MOD]     Convert to mesh-holepunch channel
│   ├── HolePunchStrategySelector.swift       [KEEP]    Strategy selection
│   ├── NATPredictor.swift                    [MOVE]    From NAT/, predicts hole punch success
│   └── ProbePacket.swift                     [KEEP]    Probe packet format
│
│   # Identity/ - Ed25519 keypair generation and storage
├── Identity/
│   ├── IdentityKeypair.swift                 [KEEP]    Ed25519 keypair
│   └── IdentityStore.swift                   [KEEP]    Identity persistence
│
│   # Logging/ - JSON Lines event logging for debugging
├── Logging/
│   ├── MeshEventLogger.swift                 [KEEP]    JSON Lines logging
│   └── MeshEventTypes.swift                  [KEEP]    Event type enums
│
│   # Network/ - Network membership, keys, and persistence
├── Network/
│   ├── Network.swift                         [KEEP]    Network model
│   ├── NetworkKey.swift                      [KEEP]    Network key type
│   └── NetworkStore.swift                    [KEEP]    Network persistence
│
│   # Public/ - Public API: MeshNetwork, ChannelProvider, config, errors, docs
├── Public/
│   ├── API.md                                [KEEP]    API documentation
│   ├── ChannelProvider.swift                 [KEEP]    Channel protocol
│   ├── DirectConnection.swift                [KEEP]    Connection result type
│   ├── MANUAL_TESTING.md                     [KEEP]    Manual test plan
│   ├── MeshConfig.swift                      [KEEP]    Configuration
│   ├── MeshError.swift                       [KEEP]    Error types
│   ├── MeshEvent.swift                       [KEEP]    Event publisher
│   ├── MeshNetwork.swift                     [MOD]     Remove deprecated methods, add lightweight ping
│   ├── MIGRATION.md                          [KEEP]    Migration guide
│   └── STRUCTURE.md                          [NEW]     This file
│
│   # Relay/ - Message forwarding through intermediate peers
├── Relay/
│   ├── RelayConnection.swift                 [MOD]     Convert to mesh-relay-* channels
│   ├── RelayManager.swift                    [MOD]     Convert to mesh-relay-* channels
│   ├── RelaySelector.swift                   [KEEP]    Relay selection logic
│   └── RelaySession.swift                    [KEEP]    Session state
│
│   # Transport/ - Low-level UDP socket operations
├── Transport/
│   └── UDPSocket.swift                       [KEEP]    UDP socket wrapper
│
│   # Types/ - Message enums, endpoint utils, NAT types
├── Types/
│   ├── BinaryEnvelope.swift                  [MOVE]    Moved to Envelope/
│   ├── EndpointUtils.swift                   [KEEP]    Endpoint parsing
│   ├── MeshMessage.swift                     [MOD]     Remove pathFailed, deprecate converted cases
│   ├── MeshNodeServices.swift                [KEEP]    Internal services protocol
│   └── NATType.swift                         [KEEP]    NAT type enum
│
│   # Utilities/ - Internal helper code
├── Utilities/
│   ├── JSONCoding.swift                      [KEEP]    JSON helpers
│   └── Retry.swift                           [KEEP]    Retry with backoff
│
│   # Services/ - Channel-based example applications demonstrating mesh usage
├── Services/
│   ├── ServiceChannels.swift                 [NEW]     Channel name constants for all services
│   ├── ServiceMessages.swift                 [NEW]     Codable message types for all services
│   ├── ServiceError.swift                    [NEW]     Shared error types
│   └── MeshServices.swift                    [NEW]     Convenience wrapper for all services
│
│   # Services/Health/ - Health and metrics queries (local and remote)
├── Services/Health/
│   ├── HealthClient.swift                    [NEW]     Health query client
│   └── HealthHandler.swift                   [NEW]     Health query handler
│
│   # Services/Message/ - P2P messaging with delivery receipts
├── Services/Message/
│   ├── MessageClient.swift                   [NEW]     P2P messaging client
│   └── MessageHandler.swift                  [NEW]     P2P messaging handler
│
│   # Services/Cloister/ - X25519 key exchange for private networks
├── Services/Cloister/
│   ├── CloisterClient.swift                  [NEW]     X25519 key negotiation client
│   └── CloisterHandler.swift                 [NEW]     Key negotiation handler
│
│   # Validation/ - Input validation and sanitization
└── Validation/
    └── EndpointValidator.swift               [KEEP]    Endpoint validation
```

---

## Tests/OmertaMeshTests/

### Test Directory Summaries

| Directory | Purpose |
|-----------|---------|
| **Benchmarks/** | Performance benchmarks for latency, throughput, and scalability measurements. |
| **Demos/** | Interactive demos showing network topology scenarios. Not automated tests. |
| **Infrastructure/** | Test utilities: mocks, simulators, virtual networks, and test node builders. |
| **ServiceTests/** | Tests for channel-based services (health, messaging, cloister) and message serialization. |
| **EnvelopeTests/** | Tests for binary envelope encoding/decoding, crypto (key/nonce derivation), and security (attack vectors). |

### Test File Tree

```
Tests/OmertaMeshTests/
│   # Benchmarks/ - Performance measurement (not CI tests)
├── Benchmarks/
│   └── PerformanceBenchmarks.swift           [KEEP]    Performance tests
│
│   # Demos/ - Interactive topology demos
├── Demos/
│   └── NetworkTopologyDemos.swift            [KEEP]    Topology demos
│
│   # Infrastructure/ - Test utilities, mocks, and simulators
├── Infrastructure/
│   ├── ChaosScenarios.swift                  [KEEP]    Chaos testing
│   ├── FaultInjector.swift                   [KEEP]    Fault injection
│   ├── MockMeshNodeServices.swift            [MOD]     Add channel mocking
│   ├── MockChannelProvider.swift             [NEW]     Channel provider mock
│   ├── SimulatedNAT.swift                    [KEEP]    NAT simulation
│   ├── TestNetworkBuilder.swift              [KEEP]    Network builder
│   ├── TestNode.swift                        [MOD]     Support channel-based testing
│   └── VirtualNetwork.swift                  [KEEP]    Virtual network
│
│   # Phase tests - Progressive feature tests (Phase 0 = basic, Phase 8 = advanced)
├── Phase0Tests.swift                         [MOD]     Update ping to channel-based
├── Phase1Tests.swift                         [MOD]     Update ping to channel-based
├── Phase2Tests.swift                         [KEEP]    Multi-peer discovery
├── Phase3Tests.swift                         [KEEP]    NAT detection
├── Phase4Tests.swift                         [KEEP]    Hole punching
├── Phase5Tests.swift                         [KEEP]    Relay fallback
├── Phase6Tests.swift                         [KEEP]    Multi-hop relay
├── Phase7Tests.swift                         [KEEP]    Network partition recovery
├── Phase8Tests.swift                         [KEEP]    Stress and chaos
│
│   # Feature tests - Specific component tests
├── BidirectionalHolePunchTests.swift         [MOD]     Update to channel-based
├── BinaryEnvelopeTests.swift                 [MOD]     Add v2 envelope tests
├── ChannelTests.swift                        [KEEP]    Channel hashing and collision
├── ConnectionKeepaliveTests.swift            [KEEP]    Keepalive timing
├── EndpointValidatorTests.swift              [KEEP]    Endpoint parsing
├── FirstHandTrackingTests.swift              [MOD]     Update gossip format
├── GossipEfficiencyTests.swift               [MOD]     Update to channel-based
├── GossipTests.swift                         [MOD]     Update to channel-based
├── KnownContactsTests.swift                  [KEEP]    Contact tracking
├── MeshEventLoggerTests.swift                [KEEP]    Logging format
├── MessageStructureTests.swift               [MOD]     Update message format
├── MultiEndpointTests.swift                  [MOD]     Update ping format
├── NATAwareRoutingTests.swift                [MOD]     Update ping format
├── NATPredictorTests.swift                   [KEEP]    NAT prediction
├── NetworkManagementTests.swift              [KEEP]    Network CRUD
├── NetworkTests.swift                        [KEEP]    Network model
├── ObservedEndpointTests.swift               [MOD]     Update ping format
├── RelayDiscoveryTests.swift                 [KEEP]    Relay finding
├── RelayForwardingTests.swift                [MOD]     Update to channel-based
├── RetryTests.swift                          [KEEP]    Backoff logic
│
│   # ServiceTests/ - Tests for channel-based example services
├── ServiceTests/
│   ├── HealthTests.swift                     [NEW]     Health service tests
│   ├── MessageTests.swift                    [NEW]     Message service tests
│   ├── CloisterTests.swift                   [NEW]     Cloister service tests
│   ├── MeshServicesTests.swift               [NEW]     Integration tests
│   └── ServiceMessagesTests.swift            [NEW]     Message serialization round-trips
│
│   # EnvelopeTests/ - Binary envelope encoding/decoding and security tests
└── EnvelopeTests/
    ├── BinaryEnvelopeTests.swift             [NEW]     Envelope encoding/decoding
    ├── EnvelopeHeaderTests.swift             [NEW]     Header field encoding
    ├── EnvelopeCryptoTests.swift             [NEW]     Key/nonce derivation, tag verification
    └── EnvelopeSecurityTests.swift           [NEW]     Attack vector rejection tests
```

---

## File Change Details

### MeshNode.swift

**Current:** Handles `MeshMessage` enum directly in message processing loop.

**Changes:**
- Convert ping/pong handling to use `mesh-ping` / `mesh-pong-{peerId}` channels
- Convert gossip handling to use `mesh-gossip` channel
- Route infrastructure messages through channel handlers
- Keep low-level UDP send/receive

**Lines affected:** ~1500-2000 (message handling section)

---

### Envelope/ (New Directory)

**Purpose:** Consolidate all message framing and wire format code.

**Files:**

| File | Purpose |
|------|---------|
| `BinaryEnvelope.swift` | Moved from Types/. Rewritten for binary format with layered encryption. |
| `EnvelopeHeader.swift` | Header structure, encoding, and field definitions. |

**BinaryEnvelope.swift structure:**
```swift
public struct BinaryEnvelope {
    /// Encode header and payload with layered encryption
    public static func encode(
        header: EnvelopeHeader,
        payload: Data,
        networkKey: NetworkKey
    ) throws -> Data

    /// Decode and verify header only (for routing decisions)
    public static func decodeHeader(
        _ data: Data,
        networkKey: NetworkKey
    ) throws -> EnvelopeHeader

    /// Decode full payload (after header verification)
    public static func decodePayload(
        _ data: Data,
        networkKey: NetworkKey
    ) throws -> Data
}
```

**EnvelopeHeader.swift structure:**
```swift
public struct EnvelopeHeader: Sendable {
    public let networkHash: Data      // 8 bytes
    public let fromPeerId: PeerId
    public let toPeerId: PeerId?
    public let channel: UInt16
    public let hopCount: UInt8
    public let timestamp: Date
    public let messageId: UUID

    /// Binary encode header fields
    public func encode() -> Data

    /// Decode from binary
    public static func decode(_ data: Data) throws -> EnvelopeHeader
}
```

**No v1 compatibility:** The old JSON envelope format is removed entirely. All nodes must upgrade together.

---

### MeshMessage.swift

**Current:** Enum with all message types including infrastructure.

**Changes:**
- Remove `pathFailed` case entirely
- Deprecate `ping`, `pong`, `announce`, `peerInfo` (still functional, marked deprecated)
- Deprecate `whoHasRecent`, `iHaveRecent`
- Deprecate `relayRequest`, `relayResponse`, `relayForward`, `relayForwardResult`
- Deprecate `holePunchRequest`, `holePunchResponse`
- Keep `data` and `channelData` (these ARE the transport)

**After migration (future cleanup):**
```swift
public enum MeshMessage: Codable, Sendable {
    case channelData(channel: UInt16, payload: Data)
    // All others removed
}
```

---

### FreshnessManager.swift

**Current:** Uses MeshMessage for `whoHasRecent`, `iHaveRecent`, `pathFailed`.

**Changes:**
- Convert to `mesh-dir-query` / `mesh-dir-response-{peerId}` channels
- Remove `pathFailed` broadcast entirely
- Keep `PathFailureReporter` for local tracking only

---

### PathFailureReporter.swift

**Current:** Creates `MeshMessage.pathFailed` for broadcast.

**Changes:**
- Remove `reportFailure()` return of MeshMessage
- Keep local failure tracking (`isPathFailed`, `failures(for:)`)
- Remove broadcast-related code

---

### Gossip.swift

**Current:** Uses `MeshMessage.announce` and `MeshMessage.peerInfo`.

**Changes:**
- Convert to `mesh-gossip` channel
- Same semantics, different transport

---

### HolePunchCoordinator.swift / HolePunchManager.swift

**Current:** Uses `MeshMessage.holePunchRequest/Response`.

**Changes:**
- Convert to `mesh-holepunch` / `mesh-holepunch-{peerId}` channels
- Same protocol, different transport

---

### RelayConnection.swift / RelayManager.swift

**Current:** Uses `MeshMessage.relayRequest/Response/Forward/ForwardResult`.

**Changes:**
- Convert to `mesh-relay-*` channels
- Same relay protocol, different transport

---

### MeshNetwork.swift

**Current:** Public API with `setMessageHandler()`, `send()`, `ping()`, etc.

**Changes:**
- Remove `setMessageHandler()` (use `onChannel()` instead)
- Remove `send(_ data:to:)` (use `sendOnChannel()` with default channel)
- Add `ping(peer:lightweight:)` parameter for minimal payload option
- Keep `statistics()`, `knownPeers()`, `knownPeersWithInfo()`

---

### ConnectionKeepalive.swift

**Current:** Uses internal ping for keepalive.

**Changes:**
- Use channel-based ping internally
- No public API changes

---

### BinaryEnvelope.swift

**Current:** JSON envelope structure in Types/.

**Changes:**
- Move to new Envelope/ directory
- Rewrite for binary format with layered encryption
- Remove JSON encoding entirely
- Add header-only decoding for routing decisions

---

## New Utility Files

### Services/ServiceChannels.swift

```swift
public enum HealthChannels {
    public static let request = "health-request"
    public static func response(for peerId: PeerId) -> String { "health-response-\(peerId)" }
}

public enum MessageChannels {
    public static func inbox(for peerId: PeerId) -> String { "msg-inbox-\(peerId)" }
    public static func receipt(for peerId: PeerId) -> String { "msg-receipt-\(peerId)" }
}

public enum CloisterChannels {
    public static let negotiate = "cloister-negotiate"
    public static func response(for peerId: PeerId) -> String { "cloister-response-\(peerId)" }
    public static let share = "cloister-share"
    public static func shareAck(for peerId: PeerId) -> String { "cloister-share-ack-\(peerId)" }
}
```

---

### Services/ServiceMessages.swift

All Codable message types for services:
- `HealthRequest`, `HealthResponse`, `HealthMetrics`, `HealthStatus`
- `PeerMessage`, `MessageReceipt`, `MessageStatus`
- `CloisterRequest`, `CloisterResponse`, `CloisterInviteShare`, `CloisterInviteAck`

---

### Services/ServiceError.swift

```swift
public enum ServiceError: Error, Sendable {
    case timeout
    case peerUnreachable(PeerId)
    case invalidResponse
    case rejected(reason: String)
    case alreadyRegistered(channel: String)
}
```

---

### Services/MeshServices.swift

```swift
public actor MeshServices {
    private let provider: any ChannelProvider

    public init(provider: any ChannelProvider)

    // Start all handlers (makes this node respond to service requests)
    public func startAllHandlers() async throws
    public func stopAllHandlers() async

    // Create clients for querying other peers
    public func healthClient() async throws -> HealthClient
    public func messageClient() async throws -> MessageClient
    public func cloisterClient() async throws -> CloisterClient
}
```

---

## New Test Files

### Infrastructure/MockChannelProvider.swift

```swift
public actor MockChannelProvider: ChannelProvider {
    public var peerId: PeerId
    public var handlers: [String: (PeerId, Data) async -> Void] = [:]
    public var sentMessages: [(to: PeerId, channel: String, data: Data)] = []

    public func onChannel(_ channel: String, handler: ...) async throws
    public func offChannel(_ channel: String) async
    public func sendOnChannel(_ data: Data, to: PeerId, channel: String) async throws

    // Test helpers
    public func simulateIncoming(from: PeerId, channel: String, data: Data) async
    public func clearSentMessages()
    public func messagesTo(_ peerId: PeerId) -> [(channel: String, data: Data)]
}
```

---

### ServiceTests/HealthTests.swift

```swift
final class HealthTests: XCTestCase {
    func testHealthCheckLocal() async throws
    func testHealthCheckRemote() async throws
    func testHealthWithMetrics() async throws
    func testHealthTimeout() async throws
}
```

---

### ServiceTests/MessageTests.swift

```swift
final class MessageTests: XCTestCase {
    func testSendReceive() async throws
    func testDeliveryReceipt() async throws
    func testReadReceipt() async throws
    func testMessageToOfflinePeer() async throws
    func testReplyThread() async throws
}
```

---

### ServiceTests/CloisterTests.swift

```swift
final class CloisterTests: XCTestCase {
    func testKeyNegotiation() async throws
    func testNegotiationRejected() async throws
    func testShareInvite() async throws
    func testDeriveSharedSecret() async throws
    func testForwardSecrecy() async throws
    func testNegotiationTimeout() async throws
}
```

---

### EnvelopeTests/BinaryEnvelopeTests.swift

```swift
final class BinaryEnvelopeTests: XCTestCase {
    func testMagicNumber() async throws
    func testVersionByte() async throws
    func testHeaderEncryption() async throws
    func testPayloadEncryption() async throws
    func testNonceDerivation() async throws
    func testHeaderTagVerification() async throws
    func testNetworkHashInHeader() async throws
    func testRoundTrip() async throws
    func testHeaderOnlyDecode() async throws
    func testWrongNetworkRejection() async throws
}
```

---

### EnvelopeTests/EnvelopeHeaderTests.swift

```swift
final class EnvelopeHeaderTests: XCTestCase {
    func testHeaderEncode() async throws
    func testHeaderDecode() async throws
    func testOptionalToPeerId() async throws
    func testChannelField() async throws
    func testHopCount() async throws
    func testTimestamp() async throws
}
```

---

### EnvelopeTests/EnvelopeCryptoTests.swift

```swift
final class EnvelopeCryptoTests: XCTestCase {
    func testHeaderKeyDerivation() async throws        // HKDF from network key
    func testNonceXorDerivation() async throws         // headerNonce XOR 0x01 = bodyNonce
    func testIndependentKeystreams() async throws      // Header/body use different keystreams
    func testTruncatedHeaderTag() async throws         // 8-byte Poly1305 verification
    func testFullPayloadTag() async throws             // 16-byte Poly1305 verification
    func testDifferentKeysAndNonces() async throws     // Defense in depth verification
    func testNonceUniqueness() async throws            // Random 96-bit nonces don't collide
}
```

---

### EnvelopeTests/EnvelopeSecurityTests.swift

```swift
final class EnvelopeSecurityTests: XCTestCase {
    func testInvalidMagicRejection() async throws      // Wrong magic bytes rejected fast
    func testInvalidVersionRejection() async throws    // Wrong version rejected fast
    func testWrongNetworkRejection() async throws      // Wrong network hash rejected after header decrypt
    func testTamperedHeaderDetection() async throws    // Modified header fails tag verification
    func testTamperedPayloadDetection() async throws   // Modified payload fails tag verification
    func testTruncatedPacketHandling() async throws    // Partial packets handled gracefully
    func testOversizedPacketHandling() async throws    // Giant packets rejected
    func testHeaderTagBitflip() async throws           // Single bit flip in tag fails verification
    func testPayloadTagBitflip() async throws          // Single bit flip in tag fails verification
    func testNonceReuse() async throws                 // Same nonce with same key is detectable
}
```

---

### ServiceTests/ServiceMessagesTests.swift

```swift
final class ServiceMessagesTests: XCTestCase {
    // Health messages
    func testHealthRequestRoundTrip() async throws
    func testHealthResponseRoundTrip() async throws
    func testHealthMetricsEncoding() async throws

    // Message messages
    func testPeerMessageRoundTrip() async throws
    func testMessageReceiptRoundTrip() async throws
    func testMessageStatusEnum() async throws

    // Cloister messages
    func testCloisterRequestRoundTrip() async throws
    func testCloisterResponseRoundTrip() async throws
    func testNetworkInviteShareRoundTrip() async throws
    func testNetworkInviteAckRoundTrip() async throws

    // Edge cases
    func testEmptyPayloadHandling() async throws
    func testMaxSizePayload() async throws
    func testUnicodeInMessages() async throws
}
```

---

## Summary Statistics

| Category | Count |
|----------|-------|
| New source files | 12 |
| Modified files | 21 |
| Moved files | 2 |
| Deleted directories | 1 |
| Unchanged files | 36 |
| New test files | 9 |
| Modified test files | 13 |

**New source files:** 12
- 4 service infrastructure (`ServiceChannels`, `ServiceMessages`, `ServiceError`, `MeshServices`)
- 6 service client/handler pairs (3 services × 2: Health, Message, Cloister)
- 1 envelope header (`EnvelopeHeader`)
- 1 mock (`MockChannelProvider`)

**New test files:** 9
- 5 service tests (Health, Message, Cloister, MeshServices, ServiceMessages)
- 4 envelope tests (BinaryEnvelope, EnvelopeHeader, EnvelopeCrypto, EnvelopeSecurity)

**New documentation:** 1
- `STRUCTURE.md`

**Moved files:** 2
- `BinaryEnvelope.swift` from Types/ to Envelope/ (rewritten)
- `NATPredictor.swift` from NAT/ to HolePunch/

**Deleted directories:** 1
- `NAT/` (empty after moving NATPredictor.swift)

**Lines of code estimate:**
- Service infrastructure: ~200 lines
- Each service (client + handler): ~200-400 lines
- Envelope: ~400 lines
- Tests: ~1200 lines (9 new test files)
- **Total new code: ~2400-2900 lines**
