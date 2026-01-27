import XCTest
@testable import OmertaMesh

final class ChannelTests: XCTestCase {

    // MARK: - Channel Validation Tests

    func testChannelValidation() {
        // Valid channels
        XCTAssertTrue(ChannelUtils.isValid(""))  // Empty is valid (mesh protocol)
        XCTAssertTrue(ChannelUtils.isValid("vm-request"))
        XCTAssertTrue(ChannelUtils.isValid("vm_request"))
        XCTAssertTrue(ChannelUtils.isValid("channel123"))
        XCTAssertTrue(ChannelUtils.isValid("ABC-xyz_123"))

        // Max length (64 chars)
        XCTAssertTrue(ChannelUtils.isValid(String(repeating: "a", count: 64)))

        // Invalid channels
        XCTAssertFalse(ChannelUtils.isValid(String(repeating: "a", count: 65)))  // Too long
        XCTAssertFalse(ChannelUtils.isValid("channel with spaces"))
        XCTAssertFalse(ChannelUtils.isValid("channel.with.dots"))
        XCTAssertFalse(ChannelUtils.isValid("channel/with/slashes"))
        XCTAssertFalse(ChannelUtils.isValid("channel:colon"))
        XCTAssertFalse(ChannelUtils.isValid("emoji😀"))
    }

    func testChannelMaxLength() {
        XCTAssertEqual(ChannelUtils.maxLength, 64)
    }

    // MARK: - Channel Hash Tests

    func testChannelHashDeterministic() {
        let hash1 = ChannelUtils.hash("vm-request")
        let hash2 = ChannelUtils.hash("vm-request")
        XCTAssertEqual(hash1, hash2)
    }

    func testChannelHashUnique() {
        let channels = ["vm-request", "vm-release", "heartbeat", "ack", "response-123"]
        var hashes = Set<UInt64>()

        for channel in channels {
            let hash = ChannelUtils.hash(channel)
            XCTAssertFalse(hashes.contains(hash), "Hash collision for '\(channel)'")
            hashes.insert(hash)
        }
    }

    func testEmptyChannelHash() {
        XCTAssertEqual(ChannelUtils.hash(""), 0)
    }

    func testChannelHashDistribution() {
        // Verify similar channel names produce different hashes
        let hash1 = ChannelUtils.hash("channel-1")
        let hash2 = ChannelUtils.hash("channel-2")
        let hash3 = ChannelUtils.hash("channel-3")

        XCTAssertNotEqual(hash1, hash2)
        XCTAssertNotEqual(hash2, hash3)
        XCTAssertNotEqual(hash1, hash3)
    }

    // MARK: - Channel Field in MeshEnvelope Tests

    func testEnvelopeWithChannel() throws {
        let keypair = IdentityKeypair()
        let machineId = UUID().uuidString

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: machineId,
            to: "peer-123",
            channel: "vm-request",
            payload: .data(Data([1, 2, 3]))
        )

        XCTAssertEqual(envelope.channel, "vm-request")

        // Test JSON roundtrip preserves channel
        let encoded = try JSONCoding.encoder.encode(envelope)
        let decoded = try JSONCoding.decoder.decode(MeshEnvelope.self, from: encoded)

        XCTAssertEqual(decoded.channel, "vm-request")
    }

    func testEnvelopeWithEmptyChannel() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",  // Mesh protocol channel
            payload: .ping(recentPeers: [], myNATType: .unknown, requestFullList: false)
        )

        XCTAssertEqual(envelope.channel, "")
        XCTAssertEqual(envelope.channel, MeshEnvelope.meshChannel)
    }

    func testEnvelopeDefaultChannel() throws {
        let keypair = IdentityKeypair()

        // Channel should default to empty string
        let envelope = MeshEnvelope(
            fromPeerId: keypair.peerId,
            publicKey: keypair.publicKeyBase64,
            machineId: UUID().uuidString,
            toPeerId: nil,
            payload: .data(Data())
        )

        XCTAssertEqual(envelope.channel, "")
    }

    // MARK: - Channel Signing Tests

    func testChannelIncludedInSignature() throws {
        let keypair = IdentityKeypair()
        let machineId = UUID().uuidString

        // Create two envelopes with different channels
        var envelope1 = try MeshEnvelope.signed(
            messageId: "same-id",
            from: keypair,
            machineId: machineId,
            to: "peer-123",
            channel: "channel-A",
            payload: .data(Data([1, 2, 3]))
        )

        var envelope2 = try MeshEnvelope.signed(
            messageId: "same-id",
            from: keypair,
            machineId: machineId,
            to: "peer-123",
            channel: "channel-B",
            payload: .data(Data([1, 2, 3]))
        )

        // Signatures should be different because channel is different
        XCTAssertNotEqual(envelope1.signature, envelope2.signature)

        // Both should verify with their own signatures
        XCTAssertTrue(envelope1.verifySignature())
        XCTAssertTrue(envelope2.verifySignature())

        // Swapping signatures should fail verification
        let temp = envelope1.signature
        envelope1.signature = envelope2.signature
        envelope2.signature = temp

        XCTAssertFalse(envelope1.verifySignature())
        XCTAssertFalse(envelope2.verifySignature())
    }

    // MARK: - Response Channel Pattern Tests

    func testResponseChannelFormat() {
        // Verify the response channel format used by VM protocol
        let peerId = "abc123def456"
        let responseChannel = "vm-response-\(peerId)"

        XCTAssertEqual(responseChannel, "vm-response-abc123def456")
        XCTAssertTrue(ChannelUtils.isValid(responseChannel))
    }

    func testLongPeerIdInResponseChannel() {
        // Real peer IDs are base64 encoded public key hashes (44 chars typically)
        let longPeerId = String(repeating: "a", count: 44)
        let responseChannel = "vm-response-\(longPeerId)"

        // 12 (prefix) + 44 (peerId) = 56 chars, should be valid
        XCTAssertEqual(responseChannel.count, 56)
        XCTAssertTrue(ChannelUtils.isValid(responseChannel))
    }

    // MARK: - Integration Tests

    func testChannelInBinaryFormat() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-123",
            channel: "test-channel",
            payload: .data(Data([1, 2, 3, 4, 5]))
        )

        // Encode to binary
        let binaryData = try envelope.encodeBinary()

        // Decode from binary
        let decoded = try MeshEnvelope.decodeBinary(binaryData)

        // Channel should be preserved
        XCTAssertEqual(decoded.channel, "test-channel")
        XCTAssertTrue(decoded.verifySignature())
    }

    func testChannelInJSONFormat() throws {
        let keypair = IdentityKeypair()

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "peer-123",
            channel: "vm-request",
            payload: .data(Data([1, 2, 3, 4, 5]))
        )

        // Encode to JSON
        let jsonData = try JSONCoding.encoder.encode(envelope)

        // Verify JSON contains channel field
        let jsonString = String(data: jsonData, encoding: .utf8)!
        XCTAssertTrue(jsonString.contains("\"channel\""))
        XCTAssertTrue(jsonString.contains("vm-request"))

        // Decode from JSON
        let decoded = try JSONCoding.decoder.decode(MeshEnvelope.self, from: jsonData)

        // Channel should be preserved
        XCTAssertEqual(decoded.channel, "vm-request")
        XCTAssertTrue(decoded.verifySignature())
    }

    // MARK: - Stress Tests

    func testManyChannelHashes() {
        // Generate hashes for many channels to check for collisions
        var hashes = [UInt64: String]()
        var collisions = 0

        for i in 0..<10000 {
            let channel = "channel-\(i)"
            let hash = ChannelUtils.hash(channel)

            if let existing = hashes[hash] {
                print("Collision: '\(channel)' and '\(existing)' both hash to \(hash)")
                collisions += 1
            } else {
                hashes[hash] = channel
            }
        }

        // FNV-1a should have very few collisions for 10k unique strings
        XCTAssertEqual(collisions, 0, "Expected no collisions in 10k channels")
    }

    func testHashPerformance() {
        let channel = "vm-request-abc123"

        measure {
            for _ in 0..<100000 {
                _ = ChannelUtils.hash(channel)
            }
        }
    }
}
