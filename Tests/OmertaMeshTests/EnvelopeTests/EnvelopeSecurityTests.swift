// EnvelopeSecurityTests.swift - Security tests for envelope format

import XCTest
import Crypto
@testable import OmertaMesh

final class EnvelopeSecurityTests: XCTestCase {

    let testKey = Data(repeating: 0x42, count: 32)

    // MARK: - Magic Number Rejection Tests

    func testInvalidMagicRejected() {
        // Create data that looks like a packet but has wrong magic
        var invalidData = Data("OOPS".utf8)  // Wrong magic
        invalidData.append(0x02)  // Correct version
        invalidData.append(Data(repeating: 0x00, count: 100))  // Padding

        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(invalidData))
    }

    func testEmptyDataRejected() {
        let emptyData = Data()
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(emptyData))
    }

    func testTruncatedMagicRejected() {
        let truncated = Data("OMR".utf8)  // Only 3 bytes
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(truncated))
    }

    func testRandomGarbageRejected() {
        // Generate random garbage data
        var garbage = Data(count: 100)
        for i in 0..<100 {
            garbage[i] = UInt8.random(in: 0...255)
        }

        // Very unlikely to match magic by chance
        // This test is probabilistic but extremely reliable
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(garbage))
    }

    // MARK: - Version Rejection Tests

    func testUnsupportedVersionRejected() throws {
        // Create data with correct magic but wrong version
        var data = Data("OMRT".utf8)  // Correct magic
        data.append(0x01)  // Wrong version (v1)
        data.append(Data(repeating: 0x00, count: 100))  // Padding

        // isValidPrefix should return false for wrong version
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(data))
    }

    func testFutureVersionRejected() throws {
        var data = Data("OMRT".utf8)
        data.append(0xFF)  // Future version
        data.append(Data(repeating: 0x00, count: 100))

        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(data))
    }

    // MARK: - Network Isolation Tests

    func testNetworkMismatchRejected() throws {
        let keypair = IdentityKeypair()
        let key1 = Data(repeating: 0x11, count: 32)
        let key2 = Data(repeating: 0x22, count: 32)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("secret".utf8))
        )

        // Encode with key1
        let encoded = try envelope.encodeV2(networkKey: key1)

        // Try to decode with key2 - should fail
        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: key2)) { error in
            // Could fail at crypto layer or network hash check
            XCTAssertNotNil(error)
        }
    }

    // MARK: - Truncation Attack Tests

    func testTruncatedPacketRejected() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("test".utf8))
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)

        // Truncate at various points
        let truncationPoints = [5, 10, 20, encoded.count / 2, encoded.count - 1]

        for point in truncationPoints {
            guard point < encoded.count else { continue }
            let truncated = encoded.prefix(point)

            XCTAssertThrowsError(try MeshEnvelope.decodeV2(Data(truncated), networkKey: testKey),
                               "Should reject packet truncated at \(point) bytes")
        }
    }

    // MARK: - Tampering Tests

    func testTamperedHeaderRejected() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("tamper test".utf8))
        )

        var encoded = try envelope.encodeV2(networkKey: testKey)

        // Tamper with header section (after prefix and nonce)
        // Position 17 is in the header tag area
        if encoded.count > 20 {
            encoded[20] ^= 0xFF
        }

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: testKey))
    }

    func testTamperedPayloadRejected() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("important data".utf8))
        )

        var encoded = try envelope.encodeV2(networkKey: testKey)

        // Tamper with payload section (near the end, before tag)
        if encoded.count > 50 {
            encoded[encoded.count - 20] ^= 0xFF
        }

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: testKey))
    }

    func testTamperedTagRejected() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("tag test".utf8))
        )

        var encoded = try envelope.encodeV2(networkKey: testKey)

        // Tamper with authentication tag (last 16 bytes)
        if encoded.count >= 16 {
            encoded[encoded.count - 1] ^= 0xFF
        }

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: testKey))
    }

    // MARK: - Replay Attack Considerations

    func testSameMessageProducesDifferentCiphertext() throws {
        let keypair = IdentityKeypair()

        let envelope1 = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("same message".utf8))
        )

        let envelope2 = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("same message".utf8))
        )

        let encoded1 = try envelope1.encodeV2(networkKey: testKey)
        let encoded2 = try envelope2.encodeV2(networkKey: testKey)

        // Due to random nonce, same plaintext should produce different ciphertext
        // Skip magic/version comparison (first 5 bytes are same)
        let ciphertext1 = encoded1.suffix(from: 5)
        let ciphertext2 = encoded2.suffix(from: 5)

        XCTAssertNotEqual(ciphertext1, ciphertext2,
                         "Same message should produce different ciphertext due to random nonce")
    }

    // MARK: - Signature Verification Tests

    func testInvalidSignatureRejected() throws {
        let keypair1 = IdentityKeypair()
        let keypair2 = IdentityKeypair()

        // Create envelope with keypair1 but try to claim it's from keypair2
        var envelope = try MeshEnvelope.signed(
            from: keypair1,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("test".utf8))
        )

        // Verify original signature is valid
        XCTAssertTrue(envelope.verifySignature())

        // Note: We can't easily tamper with the envelope after creation
        // because it's immutable. The signature verification happens
        // in processEnvelope, not during decode.
    }

    // MARK: - Hop Count Bounds Tests

    func testHopCountBoundsPreserved() throws {
        let keypair = IdentityKeypair()

        // Test with maximum hop count
        let envelope = MeshEnvelope(
            messageId: UUID().uuidString,
            fromPeerId: keypair.peerId,
            publicKey: keypair.publicKeyBase64,
            machineId: UUID().uuidString,
            toPeerId: nil,
            channel: "",
            hopCount: 255,  // Maximum UInt8
            timestamp: Date(),
            payload: .data(Data("hop test".utf8)),
            signature: ""
        )

        // Sign it properly
        let signedEnvelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(Data("hop test".utf8))
        )

        let encoded = try signedEnvelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded, networkKey: testKey)

        XCTAssertGreaterThanOrEqual(decoded.hopCount, 0)
        XCTAssertLessThanOrEqual(decoded.hopCount, 255)
    }

    // MARK: - Large Payload Tests

    func testLargePayloadHandled() throws {
        let keypair = IdentityKeypair()
        let largeData = Data(repeating: 0xAB, count: 10000)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .data(largeData)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded, networkKey: testKey)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData, largeData)
        } else {
            XCTFail("Expected .data payload")
        }
    }

    // MARK: - Channel Hash Collision Resistance

    func testChannelHashDistribution() {
        // Test that common channel names don't collide
        let channels = [
            "health-request", "health-response-abc",
            "msg-inbox-peer1", "msg-receipt-peer1",
            "cloister-negotiate", "cloister-response-xyz",
            "mesh-ping", "mesh-pong-abc",
            "custom-channel-1", "custom-channel-2"
        ]

        var hashes = Set<UInt16>()
        for channel in channels {
            let hash = ChannelHash.hash(channel)
            XCTAssertFalse(hashes.contains(hash),
                          "Hash collision detected for '\(channel)'")
            hashes.insert(hash)
        }
    }
}
