// EnvelopeHeaderTests.swift - Tests for split RoutingHeader + AuthHeader format

import XCTest
@testable import OmertaMesh

final class EnvelopeHeaderTests: XCTestCase {

    // MARK: - Helpers

    private func makeNetworkHash() -> Data {
        Data(repeating: 0x12, count: 8)
    }

    private func makeSignature() -> Data {
        Data(repeating: 0xAB, count: 64)
    }

    // MARK: - 1. RoutingHeader Encode/Decode Round Trip

    func testRoutingHeaderRoundTrip() throws {
        let networkHash = makeNetworkHash()
        let fromPeerId = Data(repeating: 0x01, count: 16)
        let toPeerId = Data(repeating: 0x02, count: 16)

        let header = RoutingHeader(
            networkHash: networkHash,
            fromPeerId: fromPeerId,
            toPeerId: toPeerId,
            flags: 0,
            hopCount: 5,
            channel: 0x1234
        )

        let encoded = try header.encode()
        XCTAssertEqual(encoded.count, 44)

        let decoded = try RoutingHeader.decode(from: encoded)
        XCTAssertEqual(decoded.networkHash, networkHash)
        XCTAssertEqual(decoded.fromPeerId, fromPeerId)
        XCTAssertEqual(decoded.toPeerId, toPeerId)
        XCTAssertEqual(decoded.flags, 0)
        XCTAssertEqual(decoded.hopCount, 5)
        XCTAssertEqual(decoded.channel, 0x1234)
    }

    // MARK: - 2. AuthHeader Encode/Decode Round Trip

    func testAuthHeaderRoundTrip() throws {
        let keypair = IdentityKeypair()
        let messageId = UUID()
        let machineId = UUID()
        let timestamp = Date()
        let signature = makeSignature()

        let header = AuthHeader(
            timestamp: timestamp,
            messageId: messageId,
            machineId: machineId,
            publicKey: keypair.publicKeyData,
            signature: signature
        )

        let encoded = try header.encode()
        XCTAssertEqual(encoded.count, 136)

        let decoded = try AuthHeader.decode(from: encoded)
        XCTAssertEqual(decoded.messageId, messageId)
        XCTAssertEqual(decoded.machineId, machineId)
        XCTAssertEqual(decoded.publicKey, keypair.publicKeyData)
        XCTAssertEqual(decoded.signature, signature)
        XCTAssertEqual(decoded.timestamp.timeIntervalSince1970,
                       timestamp.timeIntervalSince1970,
                       accuracy: 0.001)
    }

    // MARK: - 3. Broadcast Uses All-Zero toPeerId

    func testBroadcastUsesAllZeroToPeerId() throws {
        let header = RoutingHeader(
            networkHash: makeNetworkHash(),
            fromPeerId: Data(repeating: 0x01, count: 16),
            toPeerId: RoutingHeader.broadcastPeerId,
            hopCount: 0,
            channel: 100
        )

        XCTAssertTrue(header.isBroadcast)
        XCTAssertEqual(header.toPeerId, Data(repeating: 0, count: 16))

        let encoded = try header.encode()
        let decoded = try RoutingHeader.decode(from: encoded)
        XCTAssertTrue(decoded.isBroadcast)
    }

    func testNonBroadcastIsNotBroadcast() {
        let header = RoutingHeader(
            networkHash: makeNetworkHash(),
            fromPeerId: Data(repeating: 0x01, count: 16),
            toPeerId: Data(repeating: 0x02, count: 16),
            hopCount: 0,
            channel: 100
        )

        XCTAssertFalse(header.isBroadcast)
    }

    // MARK: - 4. RoutingHeader Fixed Size Validation

    func testRoutingHeaderFixedSize() throws {
        // Different field values should always produce exactly 44 bytes
        let headers = [
            RoutingHeader(networkHash: Data(repeating: 0x00, count: 8),
                          fromPeerId: Data(repeating: 0x00, count: 16),
                          toPeerId: Data(repeating: 0x00, count: 16),
                          hopCount: 0, channel: 0),
            RoutingHeader(networkHash: Data(repeating: 0xFF, count: 8),
                          fromPeerId: Data(repeating: 0xFF, count: 16),
                          toPeerId: Data(repeating: 0xFF, count: 16),
                          flags: 0xFF, hopCount: 255, channel: UInt16.max),
        ]

        for header in headers {
            let encoded = try header.encode()
            XCTAssertEqual(encoded.count, RoutingHeader.encodedSize,
                           "RoutingHeader must always be exactly \(RoutingHeader.encodedSize) bytes")
        }
    }

    // MARK: - 5. AuthHeader Fixed Size Validation

    func testAuthHeaderFixedSize() throws {
        let headers = [
            AuthHeader(timestamp: Date(timeIntervalSince1970: 0),
                       messageId: UUID(),
                       machineId: UUID(),
                       publicKey: Data(repeating: 0x00, count: 32),
                       signature: Data(repeating: 0x00, count: 64)),
            AuthHeader(timestamp: Date(timeIntervalSince1970: Double(UInt32.max)),
                       messageId: UUID(),
                       machineId: UUID(),
                       publicKey: Data(repeating: 0xFF, count: 32),
                       signature: Data(repeating: 0xFF, count: 64)),
        ]

        for header in headers {
            let encoded = try header.encode()
            XCTAssertEqual(encoded.count, AuthHeader.encodedSize,
                           "AuthHeader must always be exactly \(AuthHeader.encodedSize) bytes")
        }
    }

    // MARK: - 6. HopCount Range

    func testHopCountRange() throws {
        for hopCount: UInt8 in [0, 1, 127, 255] {
            let header = RoutingHeader(
                networkHash: makeNetworkHash(),
                fromPeerId: Data(repeating: 0x01, count: 16),
                toPeerId: Data(repeating: 0x02, count: 16),
                hopCount: hopCount,
                channel: 100
            )

            let encoded = try header.encode()
            let decoded = try RoutingHeader.decode(from: encoded)
            XCTAssertEqual(decoded.hopCount, hopCount, "Hop count \(hopCount) should round-trip")
        }
    }

    // MARK: - 7. Channel Hash Consistency

    func testChannelHashConsistency() {
        let channel = "health-request"
        let hash1 = ChannelHash.hash(channel)
        let hash2 = ChannelHash.hash(channel)
        XCTAssertEqual(hash1, hash2, "Same channel should produce same hash")
    }

    // MARK: - 8. Different Channels Produce Different Hashes

    func testChannelHashDifferentChannels() {
        let hash1 = ChannelHash.hash("health-request")
        let hash2 = ChannelHash.hash("health-response")
        XCTAssertNotEqual(hash1, hash2, "Different channels should produce different hashes")
    }

    // MARK: - 9. Empty Channel Hashes to 0

    func testChannelHashEmptyChannel() {
        let hash = ChannelHash.hash("")
        XCTAssertEqual(hash, 0, "Empty channel should hash to 0")
    }

    func testChannelHashNonZeroForNonEmpty() {
        let hash = ChannelHash.hash("test")
        XCTAssertNotEqual(hash, 0, "Non-empty channel should not hash to 0")
    }

    // MARK: - 10. PeerIdCompact Truncation and Matching

    func testPeerIdCompactTruncation() {
        let keypair = IdentityKeypair()
        let truncated = PeerIdCompact.truncate(keypair.peerId)
        XCTAssertEqual(truncated.count, 16, "Truncated peer ID must be 16 bytes")
    }

    func testPeerIdCompactMatching() {
        let keypair = IdentityKeypair()
        let truncated = PeerIdCompact.truncate(keypair.peerId)
        XCTAssertTrue(PeerIdCompact.matches(truncated: truncated, full: keypair.peerId),
                      "Truncated peer ID should match its source")
    }

    func testPeerIdCompactDifferentKeysDoNotMatch() {
        let keypair1 = IdentityKeypair()
        let keypair2 = IdentityKeypair()
        let truncated1 = PeerIdCompact.truncate(keypair1.peerId)
        XCTAssertFalse(PeerIdCompact.matches(truncated: truncated1, full: keypair2.peerId),
                       "Truncated peer ID should not match a different peer")
    }

    func testPeerIdCompactConsistency() {
        let keypair = IdentityKeypair()
        let t1 = PeerIdCompact.truncate(keypair.peerId)
        let t2 = PeerIdCompact.truncate(keypair.peerId)
        XCTAssertEqual(t1, t2, "Same peer ID should always truncate the same way")
    }

    // MARK: - 11. MachineIdCompact Round Trip

    func testMachineIdCompactRoundTrip() {
        let originalId = UUID()
        let machineIdString = originalId.uuidString

        let uuid = MachineIdCompact.toUUID(machineIdString)
        XCTAssertNotNil(uuid)

        let restored = MachineIdCompact.toString(uuid!)
        // UUID strings are uppercased
        XCTAssertEqual(restored.lowercased(), machineIdString.lowercased(),
                       "MachineId should round-trip through UUID conversion")
    }

    func testMachineIdCompactInvalidString() {
        let result = MachineIdCompact.toUUID("not-a-uuid")
        XCTAssertNil(result, "Invalid UUID string should return nil")
    }

    // MARK: - 12. Error: Invalid Network Hash Size

    func testInvalidNetworkHashSize() {
        let header = RoutingHeader(
            networkHash: Data(repeating: 0x12, count: 4), // Wrong size
            fromPeerId: Data(repeating: 0x01, count: 16),
            toPeerId: Data(repeating: 0x02, count: 16),
            hopCount: 0,
            channel: 0
        )

        XCTAssertThrowsError(try header.encode()) { error in
            guard case EnvelopeError.invalidNetworkHash = error else {
                XCTFail("Expected invalidNetworkHash error, got \(error)")
                return
            }
        }
    }

    // MARK: - 13. Error: Invalid Public Key Size

    func testInvalidPublicKeySize() {
        let header = AuthHeader(
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID(),
            publicKey: Data(repeating: 0x42, count: 16), // Wrong size
            signature: Data(repeating: 0xAB, count: 64)
        )

        XCTAssertThrowsError(try header.encode()) { error in
            guard case EnvelopeError.invalidPublicKeySize = error else {
                XCTFail("Expected invalidPublicKeySize error, got \(error)")
                return
            }
        }
    }

    // MARK: - 14. Error: Invalid Signature Size

    func testInvalidSignatureSize() {
        let header = AuthHeader(
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID(),
            publicKey: Data(repeating: 0x42, count: 32),
            signature: Data(repeating: 0xAB, count: 32) // Wrong size
        )

        XCTAssertThrowsError(try header.encode()) { error in
            guard case EnvelopeError.invalidSignatureSize = error else {
                XCTFail("Expected invalidSignatureSize error, got \(error)")
                return
            }
        }
    }

    // MARK: - 15. Error: Truncated Routing Header Data

    func testTruncatedRoutingHeaderData() {
        let truncatedData = Data(repeating: 0x00, count: 10) // Less than 44 bytes

        XCTAssertThrowsError(try RoutingHeader.decode(from: truncatedData)) { error in
            guard case BinaryEnvelopeError.truncatedData = error else {
                XCTFail("Expected truncatedData error, got \(error)")
                return
            }
        }
    }

    // MARK: - 16. Error: Truncated Auth Header Data

    func testTruncatedAuthHeaderData() {
        let truncatedData = Data(repeating: 0x00, count: 64) // Less than 128 bytes

        XCTAssertThrowsError(try AuthHeader.decode(from: truncatedData)) { error in
            guard case BinaryEnvelopeError.truncatedData = error else {
                XCTFail("Expected truncatedData error, got \(error)")
                return
            }
        }
    }

    // MARK: - 17. UUID Round Trip in Auth Header

    func testUUIDRoundTripInAuthHeader() throws {
        let messageId = UUID()
        let machineId = UUID()

        let header = AuthHeader(
            timestamp: Date(),
            messageId: messageId,
            machineId: machineId,
            publicKey: Data(repeating: 0x42, count: 32),
            signature: Data(repeating: 0xAB, count: 64)
        )

        let encoded = try header.encode()
        let decoded = try AuthHeader.decode(from: encoded)

        XCTAssertEqual(decoded.messageId, messageId, "messageId UUID should round-trip exactly")
        XCTAssertEqual(decoded.machineId, machineId, "machineId UUID should round-trip exactly")
    }

    // MARK: - 18. Timestamp Millisecond Precision Preserved

    func testTimestampMillisecondPrecision() throws {
        // Use a timestamp with specific millisecond value
        let timestampMs: UInt64 = 1_700_000_000_123 // 123 ms component
        let timestamp = Date(timeIntervalSince1970: Double(timestampMs) / 1000.0)

        let header = AuthHeader(
            timestamp: timestamp,
            messageId: UUID(),
            machineId: UUID(),
            publicKey: Data(repeating: 0x42, count: 32),
            signature: Data(repeating: 0xAB, count: 64)
        )

        let encoded = try header.encode()
        let decoded = try AuthHeader.decode(from: encoded)

        // Convert both back to milliseconds and compare exactly
        let originalMs = UInt64(timestamp.timeIntervalSince1970 * 1000)
        let decodedMs = UInt64(decoded.timestamp.timeIntervalSince1970 * 1000)
        XCTAssertEqual(decodedMs, originalMs,
                       "Timestamp millisecond precision must be preserved")
    }

    // MARK: - EnvelopeHeader Convenience Wrapper

    func testEnvelopeHeaderConvenienceInit() throws {
        let keypair = IdentityKeypair()
        let messageId = UUID()
        let machineId = UUID()
        let channelHash = ChannelHash.hash("test-channel")

        let header = EnvelopeHeader(
            networkHash: makeNetworkHash(),
            fromPeerId: keypair.peerId,
            toPeerId: nil, // broadcast
            channel: channelHash,
            channelString: "test-channel",
            hopCount: 3,
            timestamp: Date(),
            messageId: messageId,
            machineId: machineId.uuidString,
            publicKey: keypair.publicKeyData,
            signature: makeSignature()
        )

        XCTAssertEqual(header.channelString, "test-channel")
        XCTAssertEqual(header.fromPeerIdFull, keypair.peerId)
        XCTAssertNil(header.toPeerIdFull)
        XCTAssertEqual(header.machineIdString, machineId.uuidString)
        XCTAssertEqual(header.channel, channelHash)
        XCTAssertEqual(header.hopCount, 3)
        XCTAssertTrue(header.routing.isBroadcast)

        // Routing and auth should encode independently
        let routingData = try header.encodeRouting()
        XCTAssertEqual(routingData.count, RoutingHeader.encodedSize)

        let authData = try header.encodeAuth()
        XCTAssertEqual(authData.count, AuthHeader.encodedSize)
    }

    func testEnvelopeHeaderWithRecipient() throws {
        let keypair = IdentityKeypair()
        let recipientKeypair = IdentityKeypair()

        let header = EnvelopeHeader(
            networkHash: makeNetworkHash(),
            fromPeerId: keypair.peerId,
            toPeerId: recipientKeypair.peerId,
            channel: ChannelHash.hash("direct"),
            hopCount: 1,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: makeSignature()
        )

        XCTAssertFalse(header.routing.isBroadcast)
        XCTAssertEqual(header.toPeerIdFull, recipientKeypair.peerId)

        // The truncated toPeerId in routing should match the recipient
        XCTAssertTrue(PeerIdCompact.matches(truncated: header.routing.toPeerId,
                                            full: recipientKeypair.peerId))
    }

    // MARK: - 19. Field Alignment in Routing Header

    func testFieldAlignment() throws {
        let networkHash = makeNetworkHash()
        let fromPeerId = Data(repeating: 0xAA, count: 16)
        let toPeerId = Data(repeating: 0xBB, count: 16)
        let flags: UInt8 = 0x07
        let hopCount: UInt8 = 42
        let channel: UInt16 = 0xCAFE

        let header = RoutingHeader(
            networkHash: networkHash,
            fromPeerId: fromPeerId,
            toPeerId: toPeerId,
            flags: flags,
            hopCount: hopCount,
            channel: channel
        )

        let encoded = try header.encode()

        // networkHash at offset 0, length 8
        XCTAssertEqual(Data(encoded[0..<8]), networkHash)
        // fromPeerId at offset 8, length 16
        XCTAssertEqual(Data(encoded[8..<24]), fromPeerId)
        // toPeerId at offset 24, length 16
        XCTAssertEqual(Data(encoded[24..<40]), toPeerId)
        // flags at offset 40, length 1
        XCTAssertEqual(encoded[40], flags)
        // hopCount at offset 41, length 1
        XCTAssertEqual(encoded[41], hopCount)
        // channel at offset 42, length 2 (big-endian)
        let channelBytes = Data(encoded[42..<44])
        let decodedChannel = UInt16(channelBytes[channelBytes.startIndex]) << 8 |
                             UInt16(channelBytes[channelBytes.startIndex + 1])
        XCTAssertEqual(decodedChannel, channel)
    }

    // MARK: - 20. Truncated PeerId Collision Resistance

    func testTruncatedPeerIdCollisionResistance() {
        // Generate 1000 unique peer IDs and verify no collisions after truncation
        var truncatedSet: Set<Data> = []
        let peerCount = 1000

        for _ in 0..<peerCount {
            let keypair = IdentityKeypair()
            let truncated = PeerIdCompact.truncate(keypair.peerId)
            truncatedSet.insert(truncated)
        }

        XCTAssertEqual(truncatedSet.count, peerCount,
                       "No collisions expected among \(peerCount) truncated peer IDs (16 bytes = 128 bits)")
    }

    // MARK: - 21. Compact MachineId Round Trip via Raw UUID

    func testCompactMachineId() {
        let originalUUID = UUID()

        // Convert UUID -> string -> UUID -> string and verify round-trip
        let asString = MachineIdCompact.toString(originalUUID)
        let backToUUID = MachineIdCompact.toUUID(asString)
        XCTAssertNotNil(backToUUID)
        XCTAssertEqual(backToUUID, originalUUID,
                       "Raw UUID should round-trip through MachineIdCompact.toString -> toUUID")

        // Also verify the reverse direction: string -> UUID -> string
        let originalString = originalUUID.uuidString
        let uuid = MachineIdCompact.toUUID(originalString)
        XCTAssertNotNil(uuid)
        let restored = MachineIdCompact.toString(uuid!)
        XCTAssertEqual(restored.uppercased(), originalString.uppercased(),
                       "String UUID should round-trip through MachineIdCompact.toUUID -> toString")
    }
}
