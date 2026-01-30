# Plan: Batched Send API for Channels and Tunnels

## Problem

Each `TunnelSession.send()` traverses 4-5 actor hops + per-packet crypto. At ~1ms/packet overhead, throughput caps at ~10 Mbps. Same issue affects raw `sendOnChannel`.

## Design Overview

Add `send()`/`flush()`/`sendAndFlush()` at **two levels**:
1. **Channel level** — `ChannelSender` protocol gets buffered send + flush
2. **Tunnel level** — `TunnelSession` gets buffered send + flush (tunnels always use `sendAndFlush` on their channel since they batch first)

Batch config is a simple struct with two parameters (buffer size + flush timer delay), resolved with priority: **hardcoded defaults → process-level config → per-channel overrides → per-tunnel overrides → dynamic monitors**.

Dynamic monitors can adjust parameters at runtime based on endpoint characteristics and traffic patterns.

## BatchConfig

```swift
/// Configuration for send batching
public struct BatchConfig: Sendable {
    /// Maximum time to hold buffered data before auto-flushing
    public var maxFlushDelay: Duration  // default: 1ms

    /// Maximum buffer size in bytes before auto-flushing (0 = no limit)
    public var maxBufferSize: Int       // default: 0 (no limit)

    public static let `default` = BatchConfig(maxFlushDelay: .milliseconds(1), maxBufferSize: 0)
}
```

**File:** `Sources/OmertaMesh/Public/BatchConfig.swift` (new)

## Config Priority Chain

```
hardcoded default → MeshConfig (process) → per-channel → per-tunnel → dynamic monitors
```

Each level can override the previous. `nil` means "inherit from parent."

### Process level — MeshConfig

```swift
// In MeshConfig.Builder:
public func defaultBatchConfig(_ config: BatchConfig) -> Builder
```

**File:** `Sources/OmertaMesh/Public/MeshConfig.swift`

### Per-channel overrides

When registering a channel handler via `onChannel`, optionally pass a `BatchConfig`:

```swift
// ChannelProvider protocol addition:
func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: ...) async throws
```

Or set after registration. The batch config is stored per-channel in MeshNode.

**File:** `Sources/OmertaMesh/Public/ChannelProvider.swift`
**File:** `Sources/OmertaMesh/MeshNode.swift`

### Per-tunnel overrides — TunnelManagerConfig

```swift
// In TunnelManagerConfig:
public var batchConfig: BatchConfig?  // overrides channel-level for tunnel traffic
```

**File:** `Sources/OmertaTunnel/TunnelConfig.swift`

### Dynamic monitors

Register monitor callbacks that can adjust batch parameters at runtime:

```swift
/// Protocol for dynamic batch parameter adjustment
public protocol BatchMonitor: Sendable {
    /// Called periodically or on endpoint changes. Returns updated config, or nil to keep current.
    func recommendedConfig(for endpoint: String, currentTraffic: TrafficStats) -> BatchConfig?
}

/// Traffic statistics provided to monitors
public struct TrafficStats: Sendable {
    public var bytesPerSecond: UInt64
    public var packetsPerSecond: UInt64
    public var activeEndpoints: Int
    public var averageLatencyMicroseconds: Double
}
```

Monitors are registered on MeshNetwork/MeshNode:

```swift
// MeshNetwork:
public func registerBatchMonitor(_ monitor: BatchMonitor) async
public func unregisterBatchMonitor(_ monitor: BatchMonitor) async
```

When the monitor returns a non-nil config, it overrides the static config chain for that endpoint. This allows adapting to:
- Endpoint performance characteristics (latency, bandwidth)
- Network conditions (congestion, packet loss)
- Traffic patterns (bulk transfer vs interactive)

**File:** `Sources/OmertaMesh/Public/BatchConfig.swift` (BatchMonitor protocol, TrafficStats)
**File:** `Sources/OmertaMesh/Public/MeshNetwork.swift` (registration)
**File:** `Sources/OmertaMesh/MeshNode.swift` (query monitors on flush decisions)

## Channel-Level Batching (ChannelSender)

### ChannelSender protocol additions

```swift
public protocol ChannelSender: Sendable {
    // Existing
    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws
    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws

    // New — buffered
    func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws
    func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws
    func flushChannel(_ channel: String) async throws

    // Convenience — existing methods become sendAndFlush semantics (no change needed, they already are)
}
```

**Implementation in MeshNode:**
- Per-channel send buffer: `[String: Data]` keyed by channel name + destination
- `sendOnChannelBuffered` appends length-prefixed data to buffer, starts auto-flush timer if needed
- `flushChannel` packs buffer into batch format, calls existing `sendOnChannel` once
- Auto-flush timer fires based on resolved `BatchConfig` for that channel
- Monitors are consulted for the destination endpoint to get dynamic overrides

**File:** `Sources/OmertaMesh/Public/ChannelProvider.swift`
**File:** `Sources/OmertaMesh/MeshNode.swift`
**File:** `Sources/OmertaMesh/Public/MeshNetwork.swift` (passthrough)

## Tunnel-Level Batching (TunnelSession)

### TunnelSession API

```swift
public actor TunnelSession {
    // Existing renamed
    public func sendAndFlush(_ data: Data) async throws  // old send(), immediate

    // New
    public func send(_ data: Data) async throws          // buffers, starts auto-flush
    public func flush() async throws                     // packs → single sendAndFlush on channel
}
```

- `send()` appends to internal buffer with length prefix
- `flush()` takes buffer, wraps in batch wire format, calls `provider.sendOnChannel()` once (not buffered — tunnel already batched)
- `sendAndFlush()` wraps single packet in wire format, sends immediately
- Auto-flush timer based on resolved `BatchConfig` (tunnel override → channel → process → default → monitor override)

**File:** `Sources/OmertaTunnel/TunnelSession.swift`

## Envelope Format — Compact Header with Layered Decryption

### Header field compaction

Shrink header fields to minimum collision-safe sizes:
- **fromPeerId**: 44 bytes (Base64 string) → 16 bytes (truncated raw key)
- **toPeerId**: 44 bytes (optional) → 16 bytes (always present; all-zeros = broadcast)
- **machineId**: 36 bytes (UUID string) → 16 bytes (raw UUID)
- **channelString**: 64 bytes → removed (use UInt16 channel hash only)
- **publicKey**, **signature**, **timestamp**, **messageId**: unchanged

### Split into routing header + auth header

Two separately encrypted header sections, plus encrypted payload. All three use the same base nonce with XOR differentiation (0x00, 0x01, 0x02). Relay nodes decrypt only the routing header.

**Routing header** (encrypted with header key derived via HKDF from network key):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | networkHash |
| 8 | 16 | fromPeerId (truncated) |
| 24 | 16 | toPeerId (always present; all-zeros = broadcast) |
| 40 | 1 | flags |
| 41 | 1 | hopCount |
| 42 | 2 | channel (UInt16) |

**Total: 44 bytes** (fixed). All multi-byte fields 8-byte aligned; flags/hopCount/channel at the end. Broadcast uses all-zero toPeerId.

**Auth header** (encrypted with payload key, nonce XOR 0x01):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | timestamp (UInt64 ms) |
| 8 | 16 | messageId (UUID) |
| 16 | 16 | machineId (raw UUID) |
| 32 | 32 | publicKey (Ed25519) |
| 64 | 64 | signature (Ed25519) |

**Total: 136 bytes** (8+16+16+32+64=136). All fields 8-byte aligned. Recipients decrypt this before the payload to verify signature without decrypting potentially large payloads.

**Payload** (encrypted with payload key, nonce XOR 0x02):

Arbitrary application data (MeshMessage JSON, batched tunnel data, etc.)

### Wire layout

```
UNENCRYPTED PREFIX (4 bytes):
  [3 bytes] magic "OMR"
  [1 byte]  version

ROUTING HEADER SECTION:
  [12 bytes] nonce (base nonce, shared by all sections)
  [16 bytes] routing_tag (Poly1305)
  [44 bytes] encrypted routing header (fixed size)

AUTH HEADER SECTION:
  [16 bytes] auth_tag (Poly1305)
  [136 bytes] encrypted auth header (fixed size)

PAYLOAD SECTION (chunked encryption for parallel decryption):
  [4 bytes]  total_payload_length (plaintext size)
  For each chunk (count = ceil(total_payload_length / 512), chunk size 512):
    [N bytes]  encrypted chunk data (512 bytes for all but last)
    [16 bytes] chunk_tag (Poly1305)
```

**Chunked payload encryption:** The payload is split into 512-byte chunks, each encrypted independently with ChaCha20-Poly1305. Each chunk uses a unique nonce derived from the base nonce: `base_nonce XOR (0x02 | (chunk_index << 8))` — the low byte provides domain separation from routing/auth, and the chunk index in higher bytes differentiates chunks. This enables parallel decryption on the receiver side for lower latency on large payloads.

The last chunk may be smaller than 512 bytes. For payloads ≤ 512 bytes, there is exactly one chunk. The chunk count and sizes are derived from `total_payload_length` and the fixed chunk size of 512 bytes. Overhead per chunk is 16 bytes (tag only). For a 10 KB payload this is ~3.1% bandwidth overhead.

Extra cost of split auth section: 16 bytes (auth tag). No extra nonce or length field.

Total envelope overhead: 4 + 12 + 16 + 44 + 16 + 136 + 4 + (16 per chunk) bytes. For a single-chunk payload: **248 bytes**.

### Files

- `Sources/OmertaMesh/Envelope/BinaryEnvelope.swift` — rewrite: split headers, compact fields, layered decryption
- `Sources/OmertaMesh/Envelope/EnvelopeHeader.swift` — split into `RoutingHeader` + `AuthHeader`, compact field sizes
- `Sources/OmertaMesh/MachineId.swift` — add raw UUID conversion helpers
- `Sources/OmertaMesh/Types/MeshMessage.swift` — update PeerId handling for truncated keys
- `CRYPTOGRAPHY.md` — update to document new wire format, split header sections, and alignment rationale

### Tests

**Existing test files to rewrite** (all tests change due to new header structure, compact fields, split routing/auth):
- `Tests/OmertaMeshTests/EnvelopeTests/EnvelopeHeaderTests.swift` — rewrite for RoutingHeader + AuthHeader split, compact field sizes (16-byte peerId, raw UUID machineId, no channelString), new field ordering
- `Tests/OmertaMeshTests/EnvelopeTests/BinaryEnvelopeTests.swift` — rewrite (rename to `BinaryEnvelopeTests.swift`): update all encode/decode tests for split routing/auth headers, layered decryption, new wire layout
- `Tests/OmertaMeshTests/BinaryEnvelopeTests.swift` — rewrite: update unified encode/decode, format detection, error cases for new format

**New tests to add** (in the rewritten files above or a new file):
  - `testRoutingOnlyDecrypt` — decrypt routing header without decrypting auth or payload
  - `testAuthDecryptRejectsBadSignature` — bad signature detected without payload decryption
  - `testFieldAlignment` — verify all multi-byte fields land on correct alignment boundaries
  - `testTruncatedPeerIdCollisionResistance` — 16-byte truncation preserves uniqueness for realistic peer counts
  - `testCompactMachineId` — raw UUID round-trips correctly vs string UUID
  - `testNonceDerivedCorrectly` — routing/auth/payload nonces differ by XOR
  - `testVersionByte` — correct version in prefix
  - `testRoutingHeaderFixedSize` — always 44 bytes
  - `testBroadcastUsesZeroPeerId` — all-zero toPeerId for broadcast messages
  - `testAuthHeaderFixedSize` — always 136 bytes
  - `testChunkedPayloadRoundTrip` — payload split into 512-byte chunks encrypts/decrypts correctly
  - `testChunkedPayloadSingleChunk` — payload ≤ 512 bytes produces exactly one chunk
  - `testChunkedPayloadMultipleChunks` — payload > 512 bytes produces correct chunk count
  - `testChunkedPayloadEmptyPayload` — empty payload produces one zero-length chunk
  - `testChunkNoncesUnique` — each chunk gets a distinct derived nonce

## Batch Wire Format

First byte tag distinguishes packet types:

| Tag | Meaning | Format |
|-----|---------|--------|
| `0x01` | Single packet | `[0x01][data...]` |
| `0x02` | Batch | `[0x02][1B reserved][2B count][2B len₁][data₁ padded to even][2B len₂][data₂ padded to even]...` |

All length and count fields are `UInt16` (big-endian). Max 65535 packets per batch, max 65535 bytes per individual packet. Per-packet overhead is just 2 bytes. Each packet is padded to 2-byte alignment (at most 1 byte of padding) so all length fields and packet starts land on even offsets.

Pack/unpack utility functions:

```swift
enum BatchWireFormat {
    static func packSingle(_ data: Data) -> Data
    static func packBatch(_ packets: [Data]) -> Data  // precondition: each packet.count <= UInt16.max
    static func unpack(_ data: Data) -> [Data]  // returns 1+ packets
}
```

**File:** `Sources/OmertaTunnel/BatchWireFormat.swift` (new, small utility)

## Receiver Side

In `TunnelSession.deliverIncoming` (or `TunnelManager.dispatchToSession`):

```swift
let packets = BatchWireFormat.unpack(data)
for packet in packets {
    await receiveHandler?(packet)
}
```

**File:** `Sources/OmertaTunnel/TunnelSession.swift` or `TunnelManager.swift`

## Daemon Config

Add batch config to daemon config file format:

```swift
// In DaemonConfig or equivalent:
struct BatchSettings: Codable {
    var maxFlushDelayMs: Int?
    var maxBufferSize: Int?
}
```

Loaded in `DaemonMain.swift`, applied to `MeshConfig.Builder`.

**File:** `Sources/OmertaMeshDaemon/DaemonMain.swift`

## HealthTestRunner — Bandwidth Sweep

Update mesh bandwidth test to use `send()` + `flush()` and sweep different `BatchConfig` values:

- Sweep `maxFlushDelay`: [0ms (immediate), 1ms, 5ms, 10ms, 50ms]
- For each, measure bandwidth and latency
- Report table: delay vs throughput vs added latency

**File:** `Sources/HealthTestRunner/main.swift`

## Files to Modify

1. `Sources/OmertaMesh/Envelope/BinaryEnvelope.swift` — rewrite: split headers, compact fields, layered decryption
2. `Sources/OmertaMesh/Envelope/EnvelopeHeader.swift` — split into RoutingHeader + AuthHeader, compact fields
4. `Sources/OmertaMesh/MachineId.swift` — raw UUID conversion helpers
5. `Sources/OmertaMesh/Types/MeshMessage.swift` — update PeerId handling
6. `CRYPTOGRAPHY.md` — document new format, split headers, alignment
7. `Sources/OmertaMesh/Public/BatchConfig.swift` — **new**: BatchConfig struct, BatchMonitor protocol, TrafficStats
8. `Sources/OmertaMesh/Public/MeshConfig.swift` — add `defaultBatchConfig`
9. `Sources/OmertaMesh/Public/ChannelProvider.swift` — add buffered send/flush to ChannelSender
10. `Sources/OmertaMesh/Public/MeshNetwork.swift` — passthrough + monitor registration
11. `Sources/OmertaMesh/MeshNode.swift` — per-channel buffers, auto-flush timer, monitor queries, new envelope
12. `Sources/OmertaTunnel/BatchWireFormat.swift` — **new**: pack/unpack utilities
13. `Sources/OmertaTunnel/TunnelSession.swift` — send/flush/sendAndFlush, auto-flush timer, unpack on receive
14. `Sources/OmertaTunnel/TunnelConfig.swift` — add `batchConfig` to TunnelManagerConfig
15. `Sources/OmertaTunnel/TunnelManager.swift` — unpack batches in dispatch (if not in TunnelSession)
16. `Sources/OmertaMeshDaemon/DaemonMain.swift` — daemon config for batch settings
17. `Sources/OmertaMesh/Monitors/AdaptiveBatchMonitor.swift` — **new**: hill-climbing adaptive monitor
18. `Sources/HealthTestRunner/main.swift` — use batching, sweep configs, test adaptive monitor
19. `Tests/OmertaMeshTests/EnvelopeTests/EnvelopeHeaderTests.swift` — rewrite for split routing/auth headers
20. `Tests/OmertaMeshTests/EnvelopeTests/BinaryEnvelopeTests.swift` — rewrite + rename to `BinaryEnvelopeTests.swift`
21. `Tests/OmertaMeshTests/BinaryEnvelopeTests.swift` — rewrite for new format
22. `Tests/OmertaTunnelTests/BatchWireFormatTests.swift` — **new**: wire format unit tests
23. `Tests/OmertaMeshTests/BatchConfigTests.swift` — **new**: config resolution tests
24. `Tests/OmertaMeshTests/ChannelBatchingTests.swift` — **new**: channel-level batching tests
25. `Tests/OmertaTunnelTests/TunnelSessionBatchingTests.swift` — **new**: tunnel batching tests
26. `Tests/OmertaMeshTests/AdaptiveBatchMonitorTests.swift` — **new**: adaptive monitor tests (17 tests)

## Adaptive Demo Monitor

Include a built-in `AdaptiveBatchMonitor` that optimizes for minimum latency while preserving bandwidth:

**Algorithm:**
1. Start with small batch size and short flush delay (low latency)
2. Periodically sample current throughput (bytes/sec) and latency
3. When utilized bandwidth is **low/decreasing**: reduce `maxFlushDelay` and `maxBufferSize` toward minimums — latency improves with minimal bandwidth cost since there isn't much data flowing anyway
4. When utilized bandwidth is **high/increasing**: increase `maxFlushDelay` and `maxBufferSize` — amortize per-packet overhead to sustain throughput
5. If a change causes bandwidth to drop noticeably, back off to the previous values

This is a hill-climbing approach: probe in the direction that favors latency, back off when bandwidth suffers.

```swift
public actor AdaptiveBatchMonitor: BatchMonitor {
    /// Tuning parameters
    private let sampleInterval: Duration         // how often to re-evaluate (e.g. 1s)
    private let bandwidthDropThreshold: Double    // e.g. 0.05 = 5% drop triggers backoff
    private let delaySteps: [Duration]            // ordered list of flush delays to try
    private let bufferSteps: [Int]                // ordered list of buffer sizes to try

    /// State per endpoint
    private var endpointState: [String: EndpointState]

    struct EndpointState {
        var currentDelayIndex: Int
        var currentBufferIndex: Int
        var lastBandwidth: Double
        var lastLatency: Double
        var direction: Direction  // .decreasing (favor latency) or .increasing (favor throughput)
    }

    public func recommendedConfig(for endpoint: String, currentTraffic: TrafficStats) -> BatchConfig? {
        // Hill-climbing logic here
    }
}
```

**File:** `Sources/OmertaMesh/Monitors/AdaptiveBatchMonitor.swift` (new)

The HealthTestRunner bandwidth sweep will test both with and without the adaptive monitor to show its effect.

## Verification

1. `swift build` — all products compile
2. `swift test` — existing tests pass
3. `./demo-health-test.sh <ssh-host> <remote-path>` — all phases pass, bandwidth sweep shows improvement
4. `sendAndFlush` works identically to old `send`

## Unit Tests

### BatchWireFormat tests (`Tests/OmertaTunnelTests/BatchWireFormatTests.swift` — new)

- `testPackSingle` — pack single packet, verify tag + data
- `testPackBatch` — pack multiple packets, verify tag + count + length-prefixed data
- `testUnpackSingle` — unpack single-tagged data returns 1 packet
- `testUnpackBatch` — unpack batch-tagged data returns correct packets
- `testRoundTripSingle` — pack then unpack single, data matches
- `testRoundTripBatch` — pack then unpack batch, all packets match
- `testUnpackEmptyBatch` — batch with count=0 returns empty array
- `testUnpackLargePayloads` — batch with multi-MB packets round-trips correctly
- `testUnpackManyPackets` — batch with 1000+ small packets round-trips

### BatchConfig tests (`Tests/OmertaMeshTests/BatchConfigTests.swift` — new)

- `testDefaultValues` — verify default maxFlushDelay and maxBufferSize
- `testConfigOverride` — per-channel overrides process-level
- `testTunnelOverridesChannel` — tunnel config takes priority over channel
- `testNilInheritsParent` — nil at a level means inherit from parent
- `testResolveChain` — full chain: default → process → channel → tunnel, verify final values

### Channel-level batching tests (`Tests/OmertaMeshTests/ChannelBatchingTests.swift` — new)

- `testSendOnChannelBufferedAccumulates` — multiple buffered sends don't trigger actual send
- `testFlushChannelSendsAll` — flush sends accumulated data as one batch
- `testAutoFlushTimerFires` — after maxFlushDelay, buffer is auto-flushed
- `testAutoFlushTimerResetsOnFlush` — manual flush cancels pending auto-flush
- `testEmptyFlushIsNoop` — flushing empty buffer does nothing
- `testSendAndFlushBypassesBuffer` — sendOnChannel (unbuffered) sends immediately
- `testBufferSizeTrigger` — when maxBufferSize > 0, buffer auto-flushes at threshold
- `testConcurrentBufferedSends` — multiple concurrent send() calls don't corrupt buffer

### TunnelSession batching tests (`Tests/OmertaTunnelTests/TunnelSessionBatchingTests.swift` — new)

- `testSendBuffers` — send() accumulates, doesn't call provider
- `testFlushSendsToProvider` — flush() calls sendOnChannel once with batch payload
- `testSendAndFlushImmediate` — sendAndFlush() calls provider immediately
- `testAutoFlushTimer` — buffered data auto-flushes after delay
- `testDeliverIncomingUnpacksBatch` — deliverIncoming with batch tag delivers each packet separately
- `testDeliverIncomingSinglePacket` — deliverIncoming with single tag delivers one packet
- `testFlushWhileNotActive` — flush on non-active session throws

### AdaptiveBatchMonitor tests (`Tests/OmertaMeshTests/AdaptiveBatchMonitorTests.swift` — new)

- `testInitialConfigIsLowLatency` — starts with smallest delay/buffer values
- `testLowBandwidthReducesDelay` — when traffic is low, recommends shorter flush delay
- `testHighBandwidthIncreasesDelay` — when traffic is high, recommends longer flush delay
- `testBandwidthDropTriggersBackoff` — if bandwidth drops after increasing delay, reverts to previous
- `testBackoffThreshold` — bandwidth drop below threshold triggers backoff, above threshold does not
- `testStabilizesAtOptimal` — after several iterations, config stabilizes (stops oscillating)
- `testMultipleEndpointsIndependent` — different endpoints get independent configs
- `testNewEndpointStartsFresh` — unseen endpoint gets initial low-latency config
- `testNoRecommendationWhenStable` — returns nil when no change needed (avoids unnecessary updates)
- `testDelayStepsMonotonicity` — larger delay always produces same or higher throughput ceiling
- `testBufferStepsMonotonicity` — larger buffer always produces same or higher throughput ceiling
- `testRapidTrafficChangeResponds` — sudden traffic spike quickly adjusts config upward
- `testTrafficDropResponds` — sudden traffic decrease quickly adjusts config downward
- `testMinimumLatencyFloor` — never recommends delay below configured minimum
- `testMaximumDelayCapFloor` — never recommends delay above configured maximum
- `testZeroTraffic` — no traffic → recommends minimum latency config
- `testBurstySendsConverge` — alternating high/low traffic converges to reasonable middle ground
