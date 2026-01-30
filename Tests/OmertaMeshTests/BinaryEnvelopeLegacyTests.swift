import XCTest
@testable import OmertaMesh

final class BinaryEnvelopeLegacyTests: XCTestCase {

    // MARK: - Basic Encoding/Decoding

    func testBinaryEncodeDecode() throws {
        let keypair = IdentityKeypair()
        let machineId = UUID().uuidString
        let payload = MeshMessage.ping(recentPeers: [], myNATType: .unknown, requestFullList: false)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: machineId,
            to: "recipient-peer-id",
            channel: "test-channel",
            payload: payload
        )

        // Encode to binary
        let binaryData = try envelope.encodeBinary()

        // Verify it starts with version byte
        XCTAssertEqual(binaryData.first, BinaryEnvelopeVersion)

        // Decode from binary
        let decoded = try MeshEnvelope.decodeBinary(binaryData)

        // Verify all fields match
        XCTAssertEqual(decoded.messageId, envelope.messageId)
        XCTAssertEqual(decoded.fromPeerId, envelope.fromPeerId)
        XCTAssertEqual(decoded.publicKey, envelope.publicKey)
        XCTAssertEqual(decoded.machineId, envelope.machineId)
        XCTAssertEqual(decoded.toPeerId, envelope.toPeerId)
        XCTAssertEqual(decoded.channel, envelope.channel)
        XCTAssertEqual(decoded.hopCount, envelope.hopCount)
        XCTAssertEqual(decoded.signature, envelope.signature)

        // Timestamp should be exactly preserved (binary uses raw Double bits)
        XCTAssertEqual(decoded.timestamp, envelope.timestamp)

        // Debug: Print timestamp details if signature fails
        let originalDataToSign = try envelope.dataToSign()
        let decodedDataToSign = try decoded.dataToSign()

        if originalDataToSign != decodedDataToSign {
            print("Original timestamp: \(envelope.timestamp.timeIntervalSince1970)")
            print("Decoded timestamp: \(decoded.timestamp.timeIntervalSince1970)")
            print("Original dataToSign: \(String(data: originalDataToSign, encoding: .utf8) ?? "nil")")
            print("Decoded dataToSign: \(String(data: decodedDataToSign, encoding: .utf8) ?? "nil")")
        }

        // Verify signature is still valid after decode
        XCTAssertTrue(decoded.verifySignature(), "Signature verification failed - timestamps or other fields may differ")
    }

    func testBinaryEncodeDecodeWithoutRecipient() throws {
        let keypair = IdentityKeypair()
        let machineId = UUID().uuidString

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: machineId,
            to: nil,  // No recipient (broadcast)
            channel: "",
            payload: .pong(recentPeers: [], yourEndpoint: "1.2.3.4:5678", myNATType: .fullCone)
        )

        let binaryData = try envelope.encodeBinary()
        let decoded = try MeshEnvelope.decodeBinary(binaryData)

        XCTAssertNil(decoded.toPeerId)
        XCTAssertEqual(decoded.channel, "")
        XCTAssertTrue(decoded.verifySignature())
    }

    // MARK: - Format Detection

    func testFormatDetectionJSON() {
        let jsonData = Data("{}".utf8)
        XCTAssertEqual(EnvelopeWireFormat.detect(jsonData), .json)

        let jsonEnvelope = Data("{\"messageId\":\"test\"}".utf8)
        XCTAssertEqual(EnvelopeWireFormat.detect(jsonEnvelope), .json)
    }

    func testFormatDetectionBinary() throws {
        var binaryData = Data()
        binaryData.append(BinaryEnvelopeVersion)  // Start with version byte
        binaryData.append(contentsOf: [0, 0, 0])  // Some padding

        XCTAssertEqual(EnvelopeWireFormat.detect(binaryData), .binary)
    }

    func testFormatDetectionEmptyData() {
        let emptyData = Data()
        XCTAssertEqual(EnvelopeWireFormat.detect(emptyData), .json)  // Default to JSON
    }

    // MARK: - Unified Encode/Decode

    func testUnifiedEncodeDecodeJSON() throws {
        let keypair = IdentityKeypair()
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-123",
            payload: .data(Data([1, 2, 3, 4]))
        )

        // Encode as JSON
        let jsonData = try envelope.encode(format: EnvelopeWireFormat.json)
        XCTAssertEqual(jsonData.first, 0x7B)  // '{'

        // Decode with auto-detection
        let decoded = try MeshEnvelope.decode(jsonData)
        XCTAssertEqual(decoded.messageId, envelope.messageId)
        XCTAssertTrue(decoded.verifySignature())
    }

    func testUnifiedEncodeDecodeBinary() throws {
        let keypair = IdentityKeypair()
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-456",
            payload: .data(Data([5, 6, 7, 8]))
        )

        // Encode as binary
        let binaryData = try envelope.encode(format: EnvelopeWireFormat.binary)
        XCTAssertEqual(binaryData.first, BinaryEnvelopeVersion)

        // Decode with auto-detection
        let decoded = try MeshEnvelope.decode(binaryData)
        XCTAssertEqual(decoded.messageId, envelope.messageId)
        XCTAssertTrue(decoded.verifySignature())
    }

    // MARK: - Size Comparison

    func testBinaryVsJSONSize() throws {
        let keypair = IdentityKeypair()
        let payload = MeshMessage.ping(
            recentPeers: [
                PeerEndpointInfo(peerId: "peer-1", machineId: "machine-1", endpoint: "1.2.3.4:5678", natType: .fullCone, isFirstHand: true),
                PeerEndpointInfo(peerId: "peer-2", machineId: "machine-2", endpoint: "5.6.7.8:9012", natType: .restrictedCone, isFirstHand: false)
            ],
            myNATType: .portRestrictedCone,
            requestFullList: true
        )

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "recipient-id",
            channel: "vm-request",
            payload: payload
        )

        let jsonData = try envelope.encode(format: EnvelopeWireFormat.json)
        let binaryData = try envelope.encode(format: EnvelopeWireFormat.binary)

        // Binary should generally be smaller than JSON (no field names, less base64)
        // But both should encode the same data
        print("JSON size: \(jsonData.count) bytes")
        print("Binary size: \(binaryData.count) bytes")

        // Verify both decode to equivalent envelopes
        let jsonDecoded = try MeshEnvelope.decode(jsonData)
        let binaryDecoded = try MeshEnvelope.decode(binaryData)

        XCTAssertEqual(jsonDecoded.messageId, binaryDecoded.messageId)
        XCTAssertEqual(jsonDecoded.fromPeerId, binaryDecoded.fromPeerId)
        XCTAssertEqual(jsonDecoded.channel, binaryDecoded.channel)
    }

    // MARK: - Error Cases

    func testDecodeInvalidVersion() {
        var data = Data()
        data.append(0xFF)  // Invalid version
        data.append(contentsOf: Array(repeating: 0, count: 100))

        XCTAssertThrowsError(try MeshEnvelope.decodeBinary(data)) { error in
            guard case BinaryEnvelopeError.invalidVersion(0xFF) = error else {
                XCTFail("Expected invalidVersion error")
                return
            }
        }
    }

    func testDecodeTruncatedData() {
        var data = Data()
        data.append(BinaryEnvelopeVersion)
        data.append(10)  // Length 10, but no actual data

        XCTAssertThrowsError(try MeshEnvelope.decodeBinary(data)) { error in
            guard case BinaryEnvelopeError.truncatedData = error else {
                XCTFail("Expected truncatedData error")
                return
            }
        }
    }

    func testEncodeStringTooLong() throws {
        let keypair = IdentityKeypair()
        let longChannel = String(repeating: "x", count: 300)  // Too long

        // This should fail because channel is > 255 bytes
        let envelope = MeshEnvelope(
            fromPeerId: keypair.peerId,
            publicKey: keypair.publicKeyBase64,
            machineId: UUID().uuidString,
            toPeerId: nil,
            channel: longChannel,
            payload: .data(Data())
        )

        XCTAssertThrowsError(try envelope.encodeBinary()) { error in
            guard case BinaryEnvelopeError.stringTooLong(field: "channel", _, _) = error else {
                XCTFail("Expected stringTooLong error for channel")
                return
            }
        }
    }

    // MARK: - Edge Cases

    func testEmptyChannel() throws {
        let keypair = IdentityKeypair()
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",  // Empty channel (mesh protocol messages)
            payload: .ping(recentPeers: [], myNATType: .unknown, requestFullList: false)
        )

        let binaryData = try envelope.encodeBinary()
        let decoded = try MeshEnvelope.decodeBinary(binaryData)

        XCTAssertEqual(decoded.channel, "")
    }

    func testMaxLengthChannel() throws {
        let keypair = IdentityKeypair()
        let maxChannel = String(repeating: "a", count: 64)  // Max allowed by ChannelUtils

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: maxChannel,
            payload: .data(Data())
        )

        let binaryData = try envelope.encodeBinary()
        let decoded = try MeshEnvelope.decodeBinary(binaryData)

        XCTAssertEqual(decoded.channel, maxChannel)
    }

    func testHopCountClamp() throws {
        let keypair = IdentityKeypair()

        // Create envelope with hopCount > 255
        var envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data())
        )

        // Manually set hopCount to large value (this is for testing internal behavior)
        envelope = MeshEnvelope(
            messageId: envelope.messageId,
            fromPeerId: envelope.fromPeerId,
            publicKey: envelope.publicKey,
            machineId: envelope.machineId,
            toPeerId: envelope.toPeerId,
            channel: envelope.channel,
            hopCount: 300,  // > 255
            timestamp: envelope.timestamp,
            payload: envelope.payload,
            signature: envelope.signature
        )

        let binaryData = try envelope.encodeBinary()
        let decoded = try MeshEnvelope.decodeBinary(binaryData)

        // Should be clamped to 255
        XCTAssertEqual(decoded.hopCount, 255)
    }

    func testLargePayload() throws {
        let keypair = IdentityKeypair()

        // Create a larger payload
        let largeData = Data(repeating: 0xAB, count: 10000)
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-123",
            payload: .data(largeData)
        )

        let binaryData = try envelope.encodeBinary()
        let decoded = try MeshEnvelope.decodeBinary(binaryData)

        if case .data(let decodedData) = decoded.payload {
            XCTAssertEqual(decodedData.count, 10000)
            XCTAssertEqual(decodedData, largeData)
        } else {
            XCTFail("Expected .data payload")
        }
    }
}
