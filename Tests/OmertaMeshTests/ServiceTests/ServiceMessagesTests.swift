import XCTest
@testable import OmertaMesh

final class ServiceMessagesTests: XCTestCase {

    // MARK: - Health Service Messages

    func testHealthRequestRoundTrip() throws {
        let original = HealthRequest(
            requestId: UUID(),
            includeMetrics: true
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(HealthRequest.self, from: encoded)

        XCTAssertEqual(decoded.requestId, original.requestId)
        XCTAssertEqual(decoded.includeMetrics, original.includeMetrics)
    }

    func testHealthResponseRoundTrip() throws {
        let metrics = HealthMetrics(
            peerCount: 42,
            directConnectionCount: 30,
            relayCount: 12,
            natType: .restrictedCone,
            publicEndpoint: "192.168.1.1:8080",
            uptimeSeconds: 86400,
            averageLatencyMs: 33.7
        )

        let original = HealthResponse(
            requestId: UUID(),
            status: .healthy,
            metrics: metrics,
            timestamp: Date()
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(HealthResponse.self, from: encoded)

        XCTAssertEqual(decoded.requestId, original.requestId)
        XCTAssertEqual(decoded.status, original.status)
        XCTAssertEqual(decoded.metrics?.peerCount, 42)
        XCTAssertEqual(decoded.metrics?.natType, .restrictedCone)
    }

    func testHealthResponseWithoutMetrics() throws {
        let original = HealthResponse(
            requestId: UUID(),
            status: .unknown,
            metrics: nil
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(HealthResponse.self, from: encoded)

        XCTAssertEqual(decoded.status, .unknown)
        XCTAssertNil(decoded.metrics)
    }

    // MARK: - Message Service Messages

    func testPeerMessageRoundTrip() throws {
        let original = PeerMessage(
            messageId: UUID(),
            content: Data("Hello, World!".utf8),
            sentAt: Date(),
            requestReceipt: true,
            messageType: "greeting"
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(PeerMessage.self, from: encoded)

        XCTAssertEqual(decoded.messageId, original.messageId)
        XCTAssertEqual(decoded.content, original.content)
        XCTAssertEqual(decoded.requestReceipt, original.requestReceipt)
        XCTAssertEqual(decoded.messageType, original.messageType)
    }

    func testPeerMessageWithBinaryContent() throws {
        let binaryData = Data([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD])

        let original = PeerMessage(
            content: binaryData,
            requestReceipt: false,
            messageType: nil
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(PeerMessage.self, from: encoded)

        XCTAssertEqual(decoded.content, binaryData)
        XCTAssertNil(decoded.messageType)
    }

    func testMessageReceiptRoundTrip() throws {
        let original = MessageReceipt(
            messageId: UUID(),
            status: .read,
            receivedAt: Date()
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(MessageReceipt.self, from: encoded)

        XCTAssertEqual(decoded.messageId, original.messageId)
        XCTAssertEqual(decoded.status, original.status)
    }

    // MARK: - Cloister Service Messages

    func testCloisterRequestRoundTrip() throws {
        let publicKey = Data(repeating: 0x42, count: 32)

        let original = CloisterRequest(
            requestId: UUID(),
            networkName: "private-network",
            ephemeralPublicKey: publicKey,
            proposedBootstraps: ["1.2.3.4:5000", "5.6.7.8:6000"]
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(CloisterRequest.self, from: encoded)

        XCTAssertEqual(decoded.requestId, original.requestId)
        XCTAssertEqual(decoded.networkName, original.networkName)
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertEqual(decoded.proposedBootstraps, ["1.2.3.4:5000", "5.6.7.8:6000"])
    }

    func testCloisterResponseAccepted() throws {
        let publicKey = Data(repeating: 0x43, count: 32)
        let confirmation = Data("confirmed".utf8)

        let original = CloisterResponse(
            requestId: UUID(),
            accepted: true,
            ephemeralPublicKey: publicKey,
            encryptedConfirmation: confirmation,
            rejectReason: nil
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(CloisterResponse.self, from: encoded)

        XCTAssertEqual(decoded.requestId, original.requestId)
        XCTAssertTrue(decoded.accepted)
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertEqual(decoded.encryptedConfirmation, confirmation)
        XCTAssertNil(decoded.rejectReason)
    }

    func testCloisterResponseRejected() throws {
        let original = CloisterResponse(
            requestId: UUID(),
            accepted: false,
            ephemeralPublicKey: nil,
            encryptedConfirmation: nil,
            rejectReason: "Request denied by policy"
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(CloisterResponse.self, from: encoded)

        XCTAssertFalse(decoded.accepted)
        XCTAssertNil(decoded.ephemeralPublicKey)
        XCTAssertEqual(decoded.rejectReason, "Request denied by policy")
    }

    func testNetworkInviteShareRoundTrip() throws {
        let publicKey = Data(repeating: 0x44, count: 32)
        let encryptedInvite = Data(repeating: 0x55, count: 64)

        let original = NetworkInviteShare(
            requestId: UUID(),
            ephemeralPublicKey: publicKey,
            encryptedInvite: encryptedInvite,
            networkNameHint: "shared-network"
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(NetworkInviteShare.self, from: encoded)

        XCTAssertEqual(decoded.requestId, original.requestId)
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertEqual(decoded.encryptedInvite, encryptedInvite)
        XCTAssertEqual(decoded.networkNameHint, "shared-network")
    }

    func testNetworkInviteAckRoundTrip() throws {
        let publicKey = Data(repeating: 0x66, count: 32)

        let original = NetworkInviteAck(
            requestId: UUID(),
            ephemeralPublicKey: publicKey,
            accepted: true,
            joinedNetworkId: "abc123def456",
            rejectReason: nil
        )

        let encoded = try JSONCoding.encoder.encode(original)
        let decoded = try JSONCoding.decoder.decode(NetworkInviteAck.self, from: encoded)

        XCTAssertEqual(decoded.requestId, original.requestId)
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertTrue(decoded.accepted)
        XCTAssertEqual(decoded.joinedNetworkId, "abc123def456")
    }

    // MARK: - Channel Names Tests

    func testHealthChannelNames() {
        let peerId = "test-peer-abc123"

        let request = HealthChannels.request
        let response = HealthChannels.response(for: peerId)

        XCTAssertEqual(request, "health-request")
        XCTAssertTrue(response.contains(peerId))
        XCTAssertTrue(response.hasPrefix("health-response-"))

        // Channels should be valid
        XCTAssertTrue(ChannelUtils.isValid(request))
        XCTAssertTrue(ChannelUtils.isValid(response))
    }

    func testCloisterChannelNames() {
        let peerId = "cloister-peer-xyz"

        let negotiate = CloisterChannels.negotiate
        let response = CloisterChannels.response(for: peerId)
        let share = CloisterChannels.share
        let shareAck = CloisterChannels.shareAck(for: peerId)

        XCTAssertEqual(negotiate, "cloister-negotiate")
        XCTAssertEqual(share, "cloister-share")
        XCTAssertTrue(response.contains(peerId))
        XCTAssertTrue(shareAck.contains(peerId))

        // All channels should be valid
        XCTAssertTrue(ChannelUtils.isValid(negotiate))
        XCTAssertTrue(ChannelUtils.isValid(response))
        XCTAssertTrue(ChannelUtils.isValid(share))
        XCTAssertTrue(ChannelUtils.isValid(shareAck))
    }
}
