import XCTest
@testable import OmertaMesh

final class BinaryEnvelopeV2Tests: XCTestCase {

    // Test key (32 bytes)
    let testKey = Data(repeating: 0x42, count: 32)

    // MARK: - Basic Encode/Decode

    func testEncodeDecodeRoundTrip() throws {
        let keypair = IdentityKeypair()
        let machineId = UUID().uuidString
        let payload = MeshMessage.ping(recentPeers: [], myNATType: .unknown, requestFullList: false)
        let channel = "test-channel"

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: machineId,
            to: "recipient-peer-id",
            channel: channel,
            payload: payload
        )

        // Encode to v2 format
        let encoded = try envelope.encodeV2(networkKey: testKey)

        // Verify it starts with magic and version
        XCTAssertEqual(encoded.prefix(4), BinaryEnvelopeV2.magic)
        XCTAssertEqual(encoded[4], BinaryEnvelopeV2.version)

        // Decode from v2 format with hash
        let (decoded, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded, networkKey: testKey)

        // Verify all fields match (except channel which is hashed)
        XCTAssertEqual(decoded.messageId, envelope.messageId)
        XCTAssertEqual(decoded.fromPeerId, envelope.fromPeerId)
        XCTAssertEqual(decoded.publicKey, envelope.publicKey)
        XCTAssertEqual(decoded.machineId, envelope.machineId)
        XCTAssertEqual(decoded.toPeerId, envelope.toPeerId)
        XCTAssertEqual(decoded.hopCount, envelope.hopCount)
        XCTAssertEqual(decoded.signature, envelope.signature)
        XCTAssertEqual(decoded.timestamp.timeIntervalSinceReferenceDate,
                       envelope.timestamp.timeIntervalSinceReferenceDate,
                       accuracy: 0.001)

        // Channel hash should match the hash of the original channel
        XCTAssertEqual(channelHash, ChannelHash.hash(channel))

        // Signature should still be valid
        XCTAssertTrue(decoded.verifySignature())
    }

    func testEncodeDecodeWithoutRecipient() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,  // Broadcast
            channel: "",
            payload: .pong(recentPeers: [], yourEndpoint: "1.2.3.4:5678", myNATType: .fullCone)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let (decoded, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded, networkKey: testKey)

        XCTAssertNil(decoded.toPeerId)
        // Empty channel hashes to 0
        XCTAssertEqual(channelHash, 0)
        XCTAssertTrue(decoded.verifySignature())
    }

    // MARK: - Format Detection

    func testIsValidPrefix() {
        // Valid v2 prefix
        var validData = Data("OMRT".utf8)
        validData.append(0x02)
        validData.append(contentsOf: [UInt8](repeating: 0, count: 100))
        XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(validData))

        // Wrong magic
        var wrongMagic = Data("XXXX".utf8)
        wrongMagic.append(0x02)
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(wrongMagic))

        // Wrong version
        var wrongVersion = Data("OMRT".utf8)
        wrongVersion.append(0x01)  // v1
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(wrongVersion))

        // Too short
        let tooShort = Data("OMR".utf8)
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(tooShort))

        // Empty
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(Data()))
    }

    // MARK: - Network Hash

    func testNetworkHashComputation() {
        let hash1 = BinaryEnvelopeV2.computeNetworkHash(testKey)
        let hash2 = BinaryEnvelopeV2.computeNetworkHash(testKey)

        // Should be deterministic
        XCTAssertEqual(hash1, hash2)

        // Should be 8 bytes
        XCTAssertEqual(hash1.count, 8)

        // Different keys should produce different hashes
        let differentKey = Data(repeating: 0x43, count: 32)
        let hash3 = BinaryEnvelopeV2.computeNetworkHash(differentKey)
        XCTAssertNotEqual(hash1, hash3)
    }

    // MARK: - Network Mismatch

    func testWrongNetworkKeyRejected() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data([1, 2, 3]))
        )

        // Encode with one key
        let encoded = try envelope.encodeV2(networkKey: testKey)

        // Try to decode with different key
        let wrongKey = Data(repeating: 0x99, count: 32)

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: wrongKey)) { error in
            // Should fail with some crypto error (authentication failure or network mismatch)
            // The exact error depends on whether decryption fails first or network hash check fails
            // Just verify that it throws - the specific error type depends on implementation
            _ = error  // Acknowledge error was thrown
        }
    }

    // MARK: - Error Cases

    func testDecodeInvalidMagic() {
        var data = Data("XXXX".utf8)  // Wrong magic
        data.append(0x02)
        data.append(contentsOf: [UInt8](repeating: 0, count: 200))

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(data, networkKey: testKey)) { error in
            guard case EnvelopeError.invalidMagic = error else {
                XCTFail("Expected invalidMagic error, got \(error)")
                return
            }
        }
    }

    func testDecodeUnsupportedVersion() {
        var data = Data("OMRT".utf8)
        data.append(0xFF)  // Unsupported version
        data.append(contentsOf: [UInt8](repeating: 0, count: 200))

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(data, networkKey: testKey)) { error in
            guard case EnvelopeError.unsupportedVersion(0xFF) = error else {
                XCTFail("Expected unsupportedVersion error, got \(error)")
                return
            }
        }
    }

    func testDecodeTruncatedPacket() {
        // Minimum valid v2 packet is much larger than 5 bytes
        var data = Data("OMRT".utf8)
        data.append(0x02)
        // Missing nonce, tag, header, payload

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(data, networkKey: testKey)) { error in
            guard case EnvelopeError.truncatedPacket = error else {
                XCTFail("Expected truncatedPacket error, got \(error)")
                return
            }
        }
    }

    // MARK: - Various Payload Types

    func testDataPayload() throws {
        let keypair = IdentityKeypair()
        let largeData = Data(repeating: 0xAB, count: 10000)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-123",
            payload: .data(largeData)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded, networkKey: testKey)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData.count, 10000)
            XCTAssertEqual(decodedData, largeData)
        } else {
            XCTFail("Expected .data payload")
        }
    }

    func testChannelDataPayload() throws {
        let keypair = IdentityKeypair()
        let channelPayload = Data([1, 2, 3, 4, 5])
        let channel = "vm-request"

        // Channel-based data uses .data payload with a channel name
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-456",
            channel: channel,
            payload: .data(channelPayload)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let (decoded, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded, networkKey: testKey)

        // Channel hash should match the hash of the original channel
        XCTAssertEqual(channelHash, ChannelHash.hash(channel))

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData, channelPayload)
        } else {
            XCTFail("Expected .data payload")
        }
    }

    // MARK: - Edge Cases

    func testEmptyChannel() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .ping(recentPeers: [], myNATType: .unknown, requestFullList: false)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let (_, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded, networkKey: testKey)

        // Empty channel hashes to 0
        XCTAssertEqual(channelHash, 0)
    }

    func testMaxLengthChannel() throws {
        let keypair = IdentityKeypair()
        let maxChannel = String(repeating: "a", count: 64)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: maxChannel,
            payload: .data(Data())
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let (_, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded, networkKey: testKey)

        // Channel hash should match the hash of the original long channel
        XCTAssertEqual(channelHash, ChannelHash.hash(maxChannel))
    }

    func testHopCountPreserved() throws {
        let keypair = IdentityKeypair()

        var envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data())
        )

        // Set a specific hop count
        envelope = MeshEnvelope(
            messageId: envelope.messageId,
            fromPeerId: envelope.fromPeerId,
            publicKey: envelope.publicKey,
            machineId: envelope.machineId,
            toPeerId: envelope.toPeerId,
            channel: envelope.channel,
            hopCount: 42,
            timestamp: envelope.timestamp,
            payload: envelope.payload,
            signature: envelope.signature
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded, networkKey: testKey)

        XCTAssertEqual(decoded.hopCount, 42)
    }

    func testHopCountClamped() throws {
        let keypair = IdentityKeypair()

        var envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data())
        )

        // Set hop count > 255
        envelope = MeshEnvelope(
            messageId: envelope.messageId,
            fromPeerId: envelope.fromPeerId,
            publicKey: envelope.publicKey,
            machineId: envelope.machineId,
            toPeerId: envelope.toPeerId,
            channel: envelope.channel,
            hopCount: 300,
            timestamp: envelope.timestamp,
            payload: envelope.payload,
            signature: envelope.signature
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded, networkKey: testKey)

        // Should be clamped to 255
        XCTAssertEqual(decoded.hopCount, 255)
    }

    // MARK: - Security

    func testDifferentNoncesPerEncode() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data([1, 2, 3]))
        )

        // Encode the same envelope twice
        let encoded1 = try envelope.encodeV2(networkKey: testKey)
        let encoded2 = try envelope.encodeV2(networkKey: testKey)

        // The nonces should be different (random)
        // Nonce is at bytes 5-16
        let nonce1 = encoded1[5..<17]
        let nonce2 = encoded2[5..<17]
        XCTAssertNotEqual(nonce1, nonce2)

        // Both should still decode correctly
        let decoded1 = try MeshEnvelope.decodeV2(encoded1, networkKey: testKey)
        let decoded2 = try MeshEnvelope.decodeV2(encoded2, networkKey: testKey)

        XCTAssertEqual(decoded1.messageId, decoded2.messageId)
    }

    func testTamperedDataRejected() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data([1, 2, 3, 4, 5]))
        )

        var encoded = try envelope.encodeV2(networkKey: testKey)

        // Tamper with a byte in the encrypted payload area
        let tamperedIndex = encoded.count - 20  // Near the end, in the payload
        encoded[tamperedIndex] ^= 0xFF

        // Should fail to decode (authentication failure)
        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: testKey))
    }
}
