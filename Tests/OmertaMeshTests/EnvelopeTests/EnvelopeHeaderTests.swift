// EnvelopeHeaderTests.swift - Tests for EnvelopeHeader binary encoding

import XCTest
@testable import OmertaMesh

final class EnvelopeHeaderTests: XCTestCase {

    // MARK: - Basic Encode/Decode

    func testEncodeDecodeRoundTrip() throws {
        let networkHash = Data(repeating: 0x12, count: 8)
        let keypair = IdentityKeypair()
        let messageId = UUID()
        let channelHash = ChannelHash.hash("test-channel")
        let signature = Data(repeating: 0xAB, count: 64)

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: "recipient-peer-id-12345",
            channel: channelHash,
            hopCount: 5,
            timestamp: Date(),
            messageId: messageId,
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: signature
        )

        let encoded = try header.encode()
        let decoded = try EnvelopeHeader.decode(from: encoded)

        XCTAssertEqual(decoded.networkHash, header.networkHash)
        XCTAssertEqual(decoded.fromPeerId, header.fromPeerId)
        XCTAssertEqual(decoded.toPeerId, header.toPeerId)
        XCTAssertEqual(decoded.channel, header.channel)
        XCTAssertEqual(decoded.hopCount, header.hopCount)
        XCTAssertEqual(decoded.messageId, header.messageId)
        XCTAssertEqual(decoded.machineId, header.machineId)
        XCTAssertEqual(decoded.publicKey, header.publicKey)
        XCTAssertEqual(decoded.signature, header.signature)

        // Timestamp should be very close (within millisecond precision)
        XCTAssertEqual(decoded.timestamp.timeIntervalSinceReferenceDate,
                       header.timestamp.timeIntervalSinceReferenceDate,
                       accuracy: 0.001)
    }

    func testEncodeDecodeWithoutRecipient() throws {
        let networkHash = Data(repeating: 0x34, count: 8)
        let keypair = IdentityKeypair()
        let channelHash = ChannelHash.hash("broadcast-channel")

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,  // Broadcast
            channel: channelHash,
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0xCD, count: 64)
        )

        let encoded = try header.encode()
        let decoded = try EnvelopeHeader.decode(from: encoded)

        XCTAssertNil(decoded.toPeerId)
        XCTAssertEqual(decoded.fromPeerId, header.fromPeerId)
        XCTAssertEqual(decoded.channel, channelHash)
    }

    // MARK: - Edge Cases

    func testZeroChannelHash() throws {
        let networkHash = Data(repeating: 0x56, count: 8)
        let keypair = IdentityKeypair()

        // Channel hash 0 is used for default mesh protocol messages
        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: 0,  // Zero channel for mesh protocol
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0xEF, count: 64)
        )

        let encoded = try header.encode()
        let decoded = try EnvelopeHeader.decode(from: encoded)

        XCTAssertEqual(decoded.channel, 0)
    }

    func testMaxChannelHash() throws {
        let networkHash = Data(repeating: 0x78, count: 8)
        let keypair = IdentityKeypair()

        // Test with maximum UInt16 value
        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: UInt16.max,
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0x12, count: 64)
        )

        let encoded = try header.encode()
        let decoded = try EnvelopeHeader.decode(from: encoded)

        XCTAssertEqual(decoded.channel, UInt16.max)
    }

    func testHopCountRange() throws {
        let networkHash = Data(repeating: 0x9A, count: 8)
        let keypair = IdentityKeypair()

        for hopCount in [0, 1, 127, 128, 254, 255] as [UInt8] {
            let header = EnvelopeHeader(
                networkHash: networkHash,
                fromPeerId: keypair.peerId,
                toPeerId: nil,
                channel: 0x1234,
                hopCount: hopCount,
                timestamp: Date(),
                messageId: UUID(),
                machineId: UUID().uuidString,
                publicKey: keypair.publicKeyData,
                signature: Data(repeating: 0x34, count: 64)
            )

            let encoded = try header.encode()
            let decoded = try EnvelopeHeader.decode(from: encoded)

            XCTAssertEqual(decoded.hopCount, hopCount, "Hop count \(hopCount) should round-trip")
        }
    }

    // MARK: - Error Cases

    func testInvalidNetworkHash() throws {
        let keypair = IdentityKeypair()

        // Network hash must be exactly 8 bytes
        let invalidHash = Data(repeating: 0x12, count: 4)  // Only 4 bytes

        let header = EnvelopeHeader(
            networkHash: invalidHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: 0,
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0x56, count: 64)
        )

        XCTAssertThrowsError(try header.encode()) { error in
            guard case EnvelopeError.invalidNetworkHash = error else {
                XCTFail("Expected invalidNetworkHash error, got \(error)")
                return
            }
        }
    }

    func testInvalidPublicKeySize() throws {
        let networkHash = Data(repeating: 0x12, count: 8)
        let keypair = IdentityKeypair()

        // Public key must be exactly 32 bytes
        let invalidPublicKey = Data(repeating: 0x42, count: 16)  // Only 16 bytes

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: 0,
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: invalidPublicKey,
            signature: Data(repeating: 0x78, count: 64)
        )

        XCTAssertThrowsError(try header.encode()) { error in
            guard case EnvelopeError.invalidPublicKeySize = error else {
                XCTFail("Expected invalidPublicKeySize error, got \(error)")
                return
            }
        }
    }

    func testInvalidSignatureSize() throws {
        let networkHash = Data(repeating: 0x12, count: 8)
        let keypair = IdentityKeypair()

        // Signature must be exactly 64 bytes
        let invalidSignature = Data(repeating: 0x9A, count: 32)  // Only 32 bytes

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: 0,
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: invalidSignature
        )

        XCTAssertThrowsError(try header.encode()) { error in
            guard case EnvelopeError.invalidSignatureSize = error else {
                XCTFail("Expected invalidSignatureSize error, got \(error)")
                return
            }
        }
    }

    func testTruncatedData() throws {
        let networkHash = Data(repeating: 0xBC, count: 8)
        let keypair = IdentityKeypair()

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: 0,
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0xDE, count: 64)
        )

        let encoded = try header.encode()

        // Try decoding truncated data
        let truncated = encoded.prefix(10)

        XCTAssertThrowsError(try EnvelopeHeader.decode(from: Data(truncated))) { error in
            guard case BinaryEnvelopeError.truncatedData = error else {
                XCTFail("Expected truncatedData error, got \(error)")
                return
            }
        }
    }

    // MARK: - Equatable

    func testHeaderEquality() {
        let networkHash = Data(repeating: 0xDE, count: 8)
        let keypair = IdentityKeypair()
        let timestamp = Date()
        let messageId = UUID()
        let machineId = UUID().uuidString
        let channelHash: UInt16 = 0x5678
        let signature = Data(repeating: 0xF0, count: 64)

        let header1 = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: "peer-123",
            channel: channelHash,
            hopCount: 5,
            timestamp: timestamp,
            messageId: messageId,
            machineId: machineId,
            publicKey: keypair.publicKeyData,
            signature: signature
        )

        let header2 = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: "peer-123",
            channel: channelHash,
            hopCount: 5,
            timestamp: timestamp,
            messageId: messageId,
            machineId: machineId,
            publicKey: keypair.publicKeyData,
            signature: signature
        )

        XCTAssertEqual(header1, header2)
    }

    func testHeaderInequalityDifferentChannel() {
        let networkHash = Data(repeating: 0xEF, count: 8)
        let keypair = IdentityKeypair()
        let timestamp = Date()
        let messageId = UUID()
        let signature = Data(repeating: 0x11, count: 64)

        let header1 = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: ChannelHash.hash("channel-a"),
            hopCount: 0,
            timestamp: timestamp,
            messageId: messageId,
            machineId: "machine-1",
            publicKey: keypair.publicKeyData,
            signature: signature
        )

        let header2 = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: ChannelHash.hash("channel-b"),  // Different channel
            hopCount: 0,
            timestamp: timestamp,
            messageId: messageId,
            machineId: "machine-1",
            publicKey: keypair.publicKeyData,
            signature: signature
        )

        XCTAssertNotEqual(header1, header2)
    }

    // MARK: - Size Efficiency

    func testEncodedSize() throws {
        let networkHash = Data(repeating: 0x11, count: 8)
        let keypair = IdentityKeypair()

        // Minimal header (short strings, no recipient)
        let minimalHeader = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: "peer",
            toPeerId: nil,
            channel: 0,
            hopCount: 0,
            timestamp: Date(),
            messageId: UUID(),
            machineId: "m",
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0x22, count: 64)
        )

        let minimalEncoded = try minimalHeader.encode()

        // Header should be reasonably compact
        // Fixed fields: 8 (network hash) + 1 (flags) + 44 (fromPeerId) + 2 (channel) + 64 (channelString) +
        // 1 (hop) + 8 (timestamp) + 16 (messageId) + 36 (machineId) + 32 (pubkey) + 64 (sig) = 276 bytes (without toPeerId)
        XCTAssertLessThan(minimalEncoded.count, 280, "Minimal header should be compact")

        // Larger header
        let largerHeader = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: "recipient-" + String(repeating: "x", count: 40),
            channel: 0xFFFF,
            hopCount: 255,
            timestamp: Date(),
            messageId: UUID(),
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0x33, count: 64)
        )

        let largerEncoded = try largerHeader.encode()

        // Should still be reasonable size (fixed fields + variable strings)
        XCTAssertLessThan(largerEncoded.count, 400, "Larger header should fit in reasonable size")
    }

    // MARK: - Channel Hash Tests

    func testChannelHashConsistency() {
        let channel = "health-request"
        let hash1 = ChannelHash.hash(channel)
        let hash2 = ChannelHash.hash(channel)

        XCTAssertEqual(hash1, hash2, "Same channel should produce same hash")
    }

    func testChannelHashDifferentChannels() {
        let hash1 = ChannelHash.hash("health-request")
        let hash2 = ChannelHash.hash("health-response")

        XCTAssertNotEqual(hash1, hash2, "Different channels should produce different hashes")
    }

    func testChannelHashEmptyChannel() {
        let hash = ChannelHash.hash("")
        XCTAssertEqual(hash, 0, "Empty channel should hash to 0")
    }

    func testChannelHashNonZeroForNonEmpty() {
        // The hash function ensures non-empty channels don't hash to 0
        let hash = ChannelHash.hash("test")
        XCTAssertNotEqual(hash, 0, "Non-empty channel should not hash to 0")
    }

    // MARK: - UUID Round Trip

    func testUUIDRoundTrip() throws {
        let networkHash = Data(repeating: 0x44, count: 8)
        let keypair = IdentityKeypair()
        let originalUUID = UUID()

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: keypair.peerId,
            toPeerId: nil,
            channel: 0x1234,
            hopCount: 0,
            timestamp: Date(),
            messageId: originalUUID,
            machineId: UUID().uuidString,
            publicKey: keypair.publicKeyData,
            signature: Data(repeating: 0x55, count: 64)
        )

        let encoded = try header.encode()
        let decoded = try EnvelopeHeader.decode(from: encoded)

        XCTAssertEqual(decoded.messageId, originalUUID, "UUID should round-trip exactly")
    }
}
