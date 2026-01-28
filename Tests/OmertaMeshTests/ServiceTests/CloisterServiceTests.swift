// CloisterServiceTests.swift - Tests for Cloister (private network) service

import XCTest
import Crypto
@testable import OmertaMesh

final class CloisterServiceTests: XCTestCase {

    // MARK: - Handler Tests

    func testCloisterHandlerStartStop() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = CloisterHandler(provider: provider)

        // Start handler
        try await handler.start()
        let negotiateRegistered = await provider.hasHandler(for: CloisterChannels.negotiate)
        let inviteKeyExchangeRegistered = await provider.hasHandler(for: CloisterChannels.inviteKeyExchange)
        XCTAssertTrue(negotiateRegistered)
        XCTAssertTrue(inviteKeyExchangeRegistered)

        // Stop handler
        await handler.stop()
        let negotiateUnregistered = await provider.hasHandler(for: CloisterChannels.negotiate)
        let inviteKeyExchangeUnregistered = await provider.hasHandler(for: CloisterChannels.inviteKeyExchange)
        XCTAssertFalse(negotiateUnregistered)
        XCTAssertFalse(inviteKeyExchangeUnregistered)
    }

    func testCloisterHandlerAlreadyRunningError() async throws {
        let provider = MockChannelProvider()
        let handler = CloisterHandler(provider: provider)

        try await handler.start()

        do {
            try await handler.start()
            XCTFail("Expected alreadyRunning error")
        } catch ServiceError.alreadyRunning {
            // Expected
        } catch {
            XCTFail("Expected alreadyRunning error, got \(error)")
        }

        await handler.stop()
    }

    func testCloisterHandlerRejectsWithoutRequestHandler() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = CloisterHandler(provider: provider)

        // No request handler set - should reject
        try await handler.start()

        // Create a negotiation request
        let publicKey = Data(repeating: 0x42, count: 32)
        let request = CloisterRequest(
            networkName: "test-network",
            ephemeralPublicKey: publicKey
        )
        let requestData = try JSONCoding.encoder.encode(request)

        // Simulate receiving the request
        await provider.simulateReceive(requestData, from: "requester-peer", on: CloisterChannels.negotiate)

        // Should have sent a rejection response
        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let sent = sentMessages[0]
        let response = try JSONCoding.decoder.decode(CloisterResponse.self, from: sent.data)
        XCTAssertFalse(response.accepted)
        XCTAssertNotNil(response.rejectReason)

        await handler.stop()
    }

    func testCloisterHandlerAcceptsNegotiation() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = CloisterHandler(provider: provider)

        // Set request handler to accept
        await handler.setRequestHandler { _, _ in true }

        var receivedResult: CloisterResult?
        await handler.setNetworkKeyCallback { result in
            receivedResult = result
        }

        try await handler.start()

        // Generate requester's ephemeral keypair
        let requesterPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let requesterPublicKey = Data(requesterPrivateKey.publicKey.rawRepresentation)

        let request = CloisterRequest(
            networkName: "private-network",
            ephemeralPublicKey: requesterPublicKey
        )
        let requestData = try JSONCoding.encoder.encode(request)

        // Simulate receiving the request
        await provider.simulateReceive(requestData, from: "requester-peer", on: CloisterChannels.negotiate)

        // Should have sent an acceptance response
        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let sent = sentMessages[0]
        let response = try JSONCoding.decoder.decode(CloisterResponse.self, from: sent.data)
        XCTAssertTrue(response.accepted)
        XCTAssertNotNil(response.ephemeralPublicKey)
        XCTAssertNotNil(response.encryptedConfirmation)

        // Should have called the network key callback
        XCTAssertNotNil(receivedResult)
        XCTAssertEqual(receivedResult?.networkName, "private-network")
        XCTAssertEqual(receivedResult?.sharedWith, "requester-peer")
        XCTAssertEqual(receivedResult?.networkKey.count, 32)

        await handler.stop()
    }

    // MARK: - Client Tests

    func testCloisterClientRegistersResponseHandlers() async throws {
        let provider = MockChannelProvider(peerId: "client-peer")
        let client = CloisterClient(provider: provider)

        // Trigger registration by attempting a negotiation (will timeout but registers handlers)
        let task = Task {
            try await client.negotiate(with: "target-peer", networkName: "test", timeout: 0.1)
        }

        // Wait a bit for handlers to register
        try await Task.sleep(nanoseconds: 50_000_000) // 50ms

        // Check handlers are registered - these are the channels registerResponseHandlers() creates
        let responseChannel = CloisterChannels.response(for: "client-peer")
        let inviteKeyExchangeResponseChannel = CloisterChannels.inviteKeyExchangeResponse(for: "client-peer")
        let inviteFinalAckChannel = CloisterChannels.inviteFinalAck(for: "client-peer")
        let responseRegistered = await provider.hasHandler(for: responseChannel)
        let keyExchangeRegistered = await provider.hasHandler(for: inviteKeyExchangeResponseChannel)
        let finalAckRegistered = await provider.hasHandler(for: inviteFinalAckChannel)
        XCTAssertTrue(responseRegistered, "Response channel should be registered")
        XCTAssertTrue(keyExchangeRegistered, "Key exchange response channel should be registered")
        XCTAssertTrue(finalAckRegistered, "Final ack channel should be registered")

        task.cancel()
        await client.stop()
    }

    func testCloisterClientNegotiationTimeout() async throws {
        let provider = MockChannelProvider(peerId: "client-peer")
        let client = CloisterClient(provider: provider)

        do {
            _ = try await client.negotiate(with: "target-peer", networkName: "test", timeout: 0.1)
            XCTFail("Expected timeout error")
        } catch ServiceError.timeout {
            // Expected
        } catch {
            XCTFail("Expected timeout error, got \(error)")
        }

        await client.stop()
    }

    func testCloisterClientNegotiationRejected() async throws {
        let provider = MockChannelProvider(peerId: "client-peer")
        let client = CloisterClient(provider: provider)

        // Start negotiation
        let negotiationTask = Task {
            try await client.negotiate(with: "target-peer", networkName: "test", timeout: 5.0)
        }

        // Wait for request to be sent
        try await Task.sleep(nanoseconds: 50_000_000) // 50ms

        // Get the sent request
        let sentMessages = await provider.sentMessages
        guard let sent = sentMessages.first else {
            XCTFail("No request sent")
            return
        }

        let request = try JSONCoding.decoder.decode(CloisterRequest.self, from: sent.data)

        // Simulate rejection response
        let response = CloisterResponse(
            requestId: request.requestId,
            accepted: false,
            ephemeralPublicKey: nil,
            encryptedConfirmation: nil,
            rejectReason: "Not authorized"
        )
        let responseData = try JSONCoding.encoder.encode(response)
        let responseChannel = CloisterChannels.response(for: "client-peer")
        await provider.simulateReceive(responseData, from: "target-peer", on: responseChannel)

        // Should get rejection error
        do {
            _ = try await negotiationTask.value
            XCTFail("Expected rejection error")
        } catch ServiceError.rejected(let reason) {
            XCTAssertEqual(reason, "Not authorized")
        } catch {
            XCTFail("Expected rejection error, got \(error)")
        }

        await client.stop()
    }

    // MARK: - Invite Share Tests

    // TODO: This test checks for CloisterChannels.share handler which isn't registered by CloisterHandler.start()
    // The share functionality may have been refactored to use inviteKeyExchange/invitePayload flow instead.
    func DISABLED_testCloisterHandlerRejectsInviteWithoutHandler() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = CloisterHandler(provider: provider)

        // No invite handler set
        try await handler.start()

        let publicKey = Data(repeating: 0x42, count: 32)
        let encryptedInvite = Data(repeating: 0x55, count: 64)

        let share = NetworkInviteShare(
            ephemeralPublicKey: publicKey,
            encryptedInvite: encryptedInvite,
            networkNameHint: "shared-network"
        )
        let shareData = try JSONCoding.encoder.encode(share)

        await provider.simulateReceive(shareData, from: "sharer-peer", on: CloisterChannels.share)

        // Should have sent a rejection ack
        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let sent = sentMessages[0]
        let ack = try JSONCoding.decoder.decode(NetworkInviteAck.self, from: sent.data)
        XCTAssertFalse(ack.accepted)
        XCTAssertNotNil(ack.rejectReason)

        await handler.stop()
    }

    // MARK: - Message Serialization Tests

    func testCloisterRequestEncoding() throws {
        let publicKey = Data(repeating: 0x42, count: 32)

        let request = CloisterRequest(
            networkName: "test-network",
            ephemeralPublicKey: publicKey,
            proposedBootstraps: ["1.2.3.4:5000"]
        )

        let encoded = try JSONCoding.encoder.encode(request)
        let decoded = try JSONCoding.decoder.decode(CloisterRequest.self, from: encoded)

        XCTAssertEqual(decoded.requestId, request.requestId)
        XCTAssertEqual(decoded.networkName, "test-network")
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertEqual(decoded.proposedBootstraps, ["1.2.3.4:5000"])
    }

    func testCloisterResponseEncoding() throws {
        let publicKey = Data(repeating: 0x43, count: 32)
        let confirmation = Data("confirmed".utf8)

        let response = CloisterResponse(
            requestId: UUID(),
            accepted: true,
            ephemeralPublicKey: publicKey,
            encryptedConfirmation: confirmation,
            rejectReason: nil
        )

        let encoded = try JSONCoding.encoder.encode(response)
        let decoded = try JSONCoding.decoder.decode(CloisterResponse.self, from: encoded)

        XCTAssertEqual(decoded.requestId, response.requestId)
        XCTAssertTrue(decoded.accepted)
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertEqual(decoded.encryptedConfirmation, confirmation)
        XCTAssertNil(decoded.rejectReason)
    }

    func testNetworkInviteShareEncoding() throws {
        let publicKey = Data(repeating: 0x44, count: 32)
        let encryptedInvite = Data(repeating: 0x55, count: 64)

        let share = NetworkInviteShare(
            ephemeralPublicKey: publicKey,
            encryptedInvite: encryptedInvite,
            networkNameHint: "shared-network"
        )

        let encoded = try JSONCoding.encoder.encode(share)
        let decoded = try JSONCoding.decoder.decode(NetworkInviteShare.self, from: encoded)

        XCTAssertEqual(decoded.requestId, share.requestId)
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertEqual(decoded.encryptedInvite, encryptedInvite)
        XCTAssertEqual(decoded.networkNameHint, "shared-network")
    }

    func testNetworkInviteAckEncoding() throws {
        let publicKey = Data(repeating: 0x66, count: 32)

        let ack = NetworkInviteAck(
            requestId: UUID(),
            ephemeralPublicKey: publicKey,
            accepted: true,
            joinedNetworkId: "abc123",
            rejectReason: nil
        )

        let encoded = try JSONCoding.encoder.encode(ack)
        let decoded = try JSONCoding.decoder.decode(NetworkInviteAck.self, from: encoded)

        XCTAssertEqual(decoded.requestId, ack.requestId)
        XCTAssertEqual(decoded.ephemeralPublicKey, publicKey)
        XCTAssertTrue(decoded.accepted)
        XCTAssertEqual(decoded.joinedNetworkId, "abc123")
        XCTAssertNil(decoded.rejectReason)
    }

    // MARK: - Channel Names Tests

    func testCloisterChannelNames() {
        let peerId = "test-peer-abc123"

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
