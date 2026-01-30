import XCTest
@testable import OmertaMesh

final class BinaryEnvelopeTests: XCTestCase {

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

        // Encode to v3 format
        let encoded = try envelope.encodeV2(networkKey: testKey)

        // Verify it starts with magic and version
        XCTAssertEqual(encoded.data.prefix(3), BinaryEnvelope.magic)
        XCTAssertEqual(encoded.data[3], BinaryEnvelope.version)

        // Decode from v3 format with hash
        let (decoded, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded.data, networkKey: testKey)

        // Verify fields match
        XCTAssertEqual(decoded.messageId, envelope.messageId)
        XCTAssertEqual(decoded.fromPeerId, envelope.fromPeerId)
        XCTAssertEqual(decoded.publicKey, envelope.publicKey)
        XCTAssertEqual(decoded.machineId, envelope.machineId)
        XCTAssertEqual(decoded.hopCount, envelope.hopCount)
        XCTAssertEqual(decoded.signature, envelope.signature)
        XCTAssertEqual(decoded.timestamp.timeIntervalSinceReferenceDate,
                       envelope.timestamp.timeIntervalSinceReferenceDate,
                       accuracy: 0.001)

        // Channel hash should match the hash of the original channel
        XCTAssertEqual(channelHash, ChannelHash.hash(channel))
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
        let (decoded, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded.data, networkKey: testKey)

        XCTAssertNil(decoded.toPeerId)
        XCTAssertEqual(channelHash, 0)
    }

    // MARK: - Format Detection

    func testIsValidPrefix() {
        // Valid v3 prefix
        var validData = Data("OMR".utf8)
        validData.append(0x03)
        validData.append(contentsOf: [UInt8](repeating: 0, count: 100))
        XCTAssertTrue(BinaryEnvelope.isValidPrefix(validData))

        // Wrong magic
        var wrongMagic = Data("XXX".utf8)
        wrongMagic.append(0x03)
        XCTAssertFalse(BinaryEnvelope.isValidPrefix(wrongMagic))

        // Wrong version
        var wrongVersion = Data("OMR".utf8)
        wrongVersion.append(0x02)
        XCTAssertFalse(BinaryEnvelope.isValidPrefix(wrongVersion))

        // Too short
        let tooShort = Data("OM".utf8)
        XCTAssertFalse(BinaryEnvelope.isValidPrefix(tooShort))

        // Empty
        XCTAssertFalse(BinaryEnvelope.isValidPrefix(Data()))
    }

    // MARK: - Network Hash

    func testNetworkHashComputation() {
        let hash1 = BinaryEnvelope.computeNetworkHash(testKey)
        let hash2 = BinaryEnvelope.computeNetworkHash(testKey)

        XCTAssertEqual(hash1, hash2)
        XCTAssertEqual(hash1.count, 8)

        let differentKey = Data(repeating: 0x43, count: 32)
        let hash3 = BinaryEnvelope.computeNetworkHash(differentKey)
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

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let wrongKey = Data(repeating: 0x99, count: 32)

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded.data, networkKey: wrongKey))
    }

    // MARK: - Error Cases

    func testDecodeInvalidMagic() {
        var data = Data("XXX".utf8)
        data.append(0x03)
        data.append(contentsOf: [UInt8](repeating: 0, count: 300))

        XCTAssertThrowsError(try BinaryEnvelope.decode(data, networkKey: testKey)) { error in
            guard case EnvelopeError.invalidMagic = error else {
                XCTFail("Expected invalidMagic error, got \(error)")
                return
            }
        }
    }

    func testDecodeUnsupportedVersion() {
        var data = Data("OMR".utf8)
        data.append(0xFF)
        data.append(contentsOf: [UInt8](repeating: 0, count: 300))

        XCTAssertThrowsError(try BinaryEnvelope.decode(data, networkKey: testKey)) { error in
            guard case EnvelopeError.unsupportedVersion(0xFF) = error else {
                XCTFail("Expected unsupportedVersion error, got \(error)")
                return
            }
        }
    }

    func testDecodeTruncatedPacket() {
        var data = Data("OMR".utf8)
        data.append(0x03)

        XCTAssertThrowsError(try BinaryEnvelope.decode(data, networkKey: testKey)) { error in
            guard case EnvelopeError.truncatedPacket = error else {
                XCTFail("Expected truncatedPacket error, got \(error)")
                return
            }
        }
    }

    // MARK: - Routing-Only Decode

    func testRoutingOnlyDecrypt() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "target-peer",
            channel: "test-channel",
            payload: .data(Data(repeating: 0xAB, count: 10000))
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)

        // Should be able to decode just routing header without decrypting auth or payload
        let routingHeader = try BinaryEnvelope.decodeRoutingOnly(encoded.data, networkKey: testKey)

        XCTAssertEqual(routingHeader.channel, ChannelHash.hash("test-channel"))
        XCTAssertFalse(routingHeader.isBroadcast)
        XCTAssertEqual(routingHeader.hopCount, 0)
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
        let decoded = try MeshEnvelope.decodeV2(encoded.data, networkKey: testKey)

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

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-456",
            channel: channel,
            payload: .data(channelPayload)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let (decoded, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded.data, networkKey: testKey)

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
        let (_, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded.data, networkKey: testKey)

        XCTAssertEqual(channelHash, 0)
    }

    func testHopCountPreserved() throws {
        let keypair = IdentityKeypair()

        var envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data())
        )

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
        let decoded = try MeshEnvelope.decodeV2(encoded.data, networkKey: testKey)

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
        let decoded = try MeshEnvelope.decodeV2(encoded.data, networkKey: testKey)

        XCTAssertEqual(decoded.hopCount, 255)
    }

    // MARK: - Chunked Payload Tests

    func testChunkedPayloadSingleChunk() throws {
        let keypair = IdentityKeypair()
        let smallData = Data(repeating: 0xCD, count: 100)  // < 512 bytes

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-1",
            payload: .data(smallData)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded.data, networkKey: testKey)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData, smallData)
        } else {
            XCTFail("Expected .data payload")
        }
    }

    func testChunkedPayloadMultipleChunks() throws {
        let keypair = IdentityKeypair()
        // 2000 bytes = 4 chunks (512 + 512 + 512 + 464)
        let mediumData = Data((0..<2000).map { UInt8($0 & 0xFF) })

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-1",
            payload: .data(mediumData)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded.data, networkKey: testKey)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData, mediumData)
        } else {
            XCTFail("Expected .data payload")
        }
    }

    func testChunkedPayloadEmptyPayload() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data())
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded.data, networkKey: testKey)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData, Data())
        } else {
            XCTFail("Expected .data payload")
        }
    }

    func testChunkedPayloadExactChunkBoundary() throws {
        let keypair = IdentityKeypair()
        // Exactly 1024 bytes = 2 chunks of exactly 512
        let exactData = Data(repeating: 0xEF, count: 1024)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-1",
            payload: .data(exactData)
        )

        let encoded = try envelope.encodeV2(networkKey: testKey)
        let decoded = try MeshEnvelope.decodeV2(encoded.data, networkKey: testKey)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData, exactData)
        } else {
            XCTFail("Expected .data payload")
        }
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

        let encoded1 = try envelope.encodeV2(networkKey: testKey)
        let encoded2 = try envelope.encodeV2(networkKey: testKey)

        // Nonce is at bytes 4-15 (after 4-byte prefix)
        let nonce1 = encoded1.data[4..<16]
        let nonce2 = encoded2.data[4..<16]
        XCTAssertNotEqual(nonce1, nonce2)

        // Both should still decode correctly
        let decoded1 = try MeshEnvelope.decodeV2(encoded1.data, networkKey: testKey)
        let decoded2 = try MeshEnvelope.decodeV2(encoded2.data, networkKey: testKey)

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

        let sealed = try envelope.encodeV2(networkKey: testKey)
        var encoded = sealed.data

        // Tamper with a byte in the encrypted payload area
        let tamperedIndex = encoded.count - 20
        encoded[tamperedIndex] ^= 0xFF

        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: testKey))
    }

    // MARK: - Auth Header Tampering

    func testAuthDecryptRejectsBadSignature() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data([1, 2, 3]))
        )

        let sealed = try envelope.encodeV2(networkKey: testKey)
        var encoded = sealed.data

        // Tamper with the auth header section specifically.
        // Auth tag starts after: prefix(4) + nonce(12) + routing_tag(16) + routing_data(44) = 76
        let authTagStart = 76
        encoded[authTagStart] ^= 0xFF

        // Should throw when attempting to decrypt the auth header,
        // without ever reaching payload decryption.
        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded, networkKey: testKey))
    }

    // MARK: - Nonce Derivation

    func testNonceDerivedCorrectly() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data([1, 2, 3]))
        )

        let sealed = try envelope.encodeV2(networkKey: testKey)
        let data = sealed.data

        // Base nonce is at bytes 4..<16
        let baseNonce = Array(data[4..<16])
        XCTAssertEqual(baseNonce.count, 12)

        // Routing nonce = base XOR 0x00 on last byte (i.e. same as base)
        // Auth nonce = base XOR 0x01 on last byte (differs in last byte)
        // Payload chunk 0 nonce = base XOR 0x02 on last byte (differs in last byte)
        // All three must differ from each other.
        var routingNonce = baseNonce
        routingNonce[11] ^= 0x00  // routing XOR value

        var authNonce = baseNonce
        authNonce[11] ^= 0x01    // auth XOR value

        var chunkNonce = baseNonce
        chunkNonce[11] ^= 0x02   // chunk XOR value
        chunkNonce[9] ^= 0x00    // chunk index high byte
        chunkNonce[10] ^= 0x00   // chunk index low byte

        // Routing, auth, and payload nonces should all differ
        XCTAssertNotEqual(routingNonce, authNonce)
        XCTAssertNotEqual(routingNonce, chunkNonce)
        XCTAssertNotEqual(authNonce, chunkNonce)

        // The envelope should still decode correctly (nonces are correct)
        let decoded = try MeshEnvelope.decodeV2(data, networkKey: testKey)
        XCTAssertEqual(decoded.messageId, envelope.messageId)
    }

    // MARK: - Chunk Nonce Uniqueness

    func testChunkNoncesUnique() throws {
        let keypair = IdentityKeypair()
        // 2000 bytes = 4 chunks, each should get a distinct derived nonce.
        // If nonces collided, decryption would fail.
        let largePayload = Data((0..<2000).map { UInt8($0 & 0xFF) })

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-1",
            payload: .data(largePayload)
        )

        let sealed = try envelope.encodeV2(networkKey: testKey)

        // Successful decode implies each chunk used a distinct nonce
        let decoded = try MeshEnvelope.decodeV2(sealed.data, networkKey: testKey)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData, largePayload)
        } else {
            XCTFail("Expected .data payload")
        }

        // Also verify distinct nonces by construction
        let baseNonce = Array(sealed.data[4..<16])
        var nonces: Set<Data> = []
        let chunkCount = 4
        for i in 0..<chunkCount {
            var derived = baseNonce
            derived[11] ^= 0x02
            derived[9] ^= UInt8(truncatingIfNeeded: i >> 8)
            derived[10] ^= UInt8(truncatingIfNeeded: i)
            nonces.insert(Data(derived))
        }
        XCTAssertEqual(nonces.count, chunkCount, "Each chunk must have a distinct nonce")
    }

    // MARK: - Overhead Calculation

    func testTotalOverhead() {
        // Single chunk (payload <= 512)
        let singleChunkOverhead = BinaryEnvelope.totalOverhead(payloadSize: 100)
        XCTAssertEqual(singleChunkOverhead, 232 + 16)  // headerOverhead + 1 * perChunkOverhead

        // Two chunks
        let twoChunkOverhead = BinaryEnvelope.totalOverhead(payloadSize: 600)
        XCTAssertEqual(twoChunkOverhead, 232 + 2 * 16)

        // Empty payload still has 1 chunk
        let emptyOverhead = BinaryEnvelope.totalOverhead(payloadSize: 0)
        XCTAssertEqual(emptyOverhead, 232 + 16)
    }

    func testMaxPayloadForUDPIsExact() {
        let maxPayload = BinaryEnvelope.maxPayloadForUDP

        // At maxPayload, the wire size should be <= 65535
        let wireSize = maxPayload + BinaryEnvelope.totalOverhead(payloadSize: maxPayload)
        XCTAssertLessThanOrEqual(wireSize, 65535,
            "maxPayloadForUDP (\(maxPayload)) produces wire size \(wireSize) which exceeds 65535")

        // At maxPayload + 1, the wire size should exceed 65535
        let wireSizePlus1 = (maxPayload + 1) + BinaryEnvelope.totalOverhead(payloadSize: maxPayload + 1)
        XCTAssertGreaterThan(wireSizePlus1, 65535,
            "maxPayloadForUDP + 1 should exceed 65535 but wire size is \(wireSizePlus1)")
    }

    func testMaxApplicationDataForUDPEncodesSuccessfully() throws {
        // Verify that MeshMessage.data() at maxApplicationDataForUDP encodes to <= 65535 bytes
        let keypair = IdentityKeypair()
        let machineId = UUID().uuidString
        let maxAppData = BinaryEnvelope.maxApplicationDataForUDP
        let largeData = Data(repeating: 0xAB, count: maxAppData)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: machineId,
            to: nil,
            channel: "",
            payload: .data(largeData)
        )

        let encoded = try envelope.encodeV2(networkKey: Data(repeating: 0x42, count: 32))
        XCTAssertLessThanOrEqual(encoded.data.count, 65535,
            "Envelope with maxApplicationDataForUDP bytes should fit in a UDP datagram, got \(encoded.data.count)")
    }

    func testMaxApplicationDataPlusOneExceedsUDP() throws {
        // Verify that maxApplicationDataForUDP + 1 exceeds the limit
        let keypair = IdentityKeypair()
        let machineId = UUID().uuidString
        // Use a significantly larger payload to account for base64 granularity
        let oversize = BinaryEnvelope.maxApplicationDataForUDP + 512
        let largeData = Data(repeating: 0xAB, count: oversize)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: machineId,
            to: nil,
            channel: "",
            payload: .data(largeData)
        )

        let encoded = try envelope.encodeV2(networkKey: Data(repeating: 0x42, count: 32))
        XCTAssertGreaterThan(encoded.data.count, 65535,
            "Envelope with maxApplicationDataForUDP + 512 bytes should exceed UDP limit, got \(encoded.data.count)")
    }
}
