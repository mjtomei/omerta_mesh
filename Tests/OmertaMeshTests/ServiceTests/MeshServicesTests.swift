// MeshServicesTests.swift - Integration tests for MeshServices coordinator

import XCTest
@testable import OmertaMesh

final class MeshServicesTests: XCTestCase {

    // MARK: - Lifecycle Tests

    func testMeshServicesInit() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        // Just verify it can be created
        XCTAssertNotNil(services)
    }

    func testMeshServicesStartAllHandlers() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        // Start all handlers
        try await services.startAllHandlers()

        // Verify all service channels are registered
        let healthRegistered = await provider.hasHandler(for: HealthChannels.request)
        let messageRegistered = await provider.hasHandler(for: MessageChannels.inbox(for: "services-peer"))
        let cloisterNegotiateRegistered = await provider.hasHandler(for: CloisterChannels.negotiate)
        let cloisterShareRegistered = await provider.hasHandler(for: CloisterChannels.share)

        XCTAssertTrue(healthRegistered, "Health handler should be registered")
        XCTAssertTrue(messageRegistered, "Message handler should be registered")
        XCTAssertTrue(cloisterNegotiateRegistered, "Cloister negotiate handler should be registered")
        XCTAssertTrue(cloisterShareRegistered, "Cloister share handler should be registered")

        await services.stopAllHandlers()
    }

    func testMeshServicesStopAllHandlers() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        try await services.startAllHandlers()
        await services.stopAllHandlers()

        // Verify all channels are unregistered
        let healthRegistered = await provider.hasHandler(for: HealthChannels.request)
        let messageRegistered = await provider.hasHandler(for: MessageChannels.inbox(for: "services-peer"))
        let cloisterNegotiateRegistered = await provider.hasHandler(for: CloisterChannels.negotiate)
        let cloisterShareRegistered = await provider.hasHandler(for: CloisterChannels.share)

        XCTAssertFalse(healthRegistered, "Health handler should be unregistered")
        XCTAssertFalse(messageRegistered, "Message handler should be unregistered")
        XCTAssertFalse(cloisterNegotiateRegistered, "Cloister negotiate handler should be unregistered")
        XCTAssertFalse(cloisterShareRegistered, "Cloister share handler should be unregistered")
    }

    func testMeshServicesStartIndividualHandlers() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        // Start only health handler
        try await services.startHealthHandler()
        let healthRegistered = await provider.hasHandler(for: HealthChannels.request)
        XCTAssertTrue(healthRegistered)

        // Start message handler
        try await services.startMessageHandler()
        let messageRegistered = await provider.hasHandler(for: MessageChannels.inbox(for: "services-peer"))
        XCTAssertTrue(messageRegistered)

        // Start cloister handler
        try await services.startCloisterHandler()
        let cloisterRegistered = await provider.hasHandler(for: CloisterChannels.negotiate)
        XCTAssertTrue(cloisterRegistered)

        await services.stopAllHandlers()
    }

    // MARK: - Client Creation Tests

    func testMeshServicesHealthClient() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        let client = try await services.healthClient()
        XCTAssertNotNil(client)
    }

    func testMeshServicesMessageClient() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        let client = try await services.messageClient()
        XCTAssertNotNil(client)
    }

    func testMeshServicesCloisterClient() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        let client = try await services.cloisterClient()
        XCTAssertNotNil(client)
    }

    // MARK: - Handler Configuration Tests

    func testMeshServicesSetHealthMetricsProvider() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        try await services.startHealthHandler()

        await services.setHealthMetricsProvider {
            HealthMetrics(
                peerCount: 42,
                directConnectionCount: 30,
                relayCount: 12,
                natType: .fullCone,
                publicEndpoint: "1.2.3.4:5000",
                uptimeSeconds: 3600,
                averageLatencyMs: 25.0
            )
        }

        // Send a health request and verify response contains custom metrics
        let request = HealthRequest(includeMetrics: true)
        let requestData = try JSONCoding.encoder.encode(request)
        await provider.simulateReceive(requestData, from: "requester", on: HealthChannels.request)

        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let response = try JSONCoding.decoder.decode(HealthResponse.self, from: sentMessages[0].data)
        XCTAssertEqual(response.metrics?.peerCount, 42)
        XCTAssertEqual(response.metrics?.directConnectionCount, 30)

        await services.stopAllHandlers()
    }

    func testMeshServicesSetMessageHandler() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        var receivedMessage: PeerMessage?
        var receivedFrom: PeerId?

        try await services.startMessageHandler()

        await services.setMessageHandler { from, message in
            receivedMessage = message
            receivedFrom = from
        }

        // Send a message
        let message = PeerMessage(
            content: Data("Hello".utf8),
            requestReceipt: false,
            messageType: "greeting"
        )
        let messageData = try JSONCoding.encoder.encode(message)
        await provider.simulateReceive(messageData, from: "sender-peer", on: MessageChannels.inbox(for: "services-peer"))

        XCTAssertNotNil(receivedMessage)
        XCTAssertEqual(receivedMessage?.content, Data("Hello".utf8))
        XCTAssertEqual(receivedFrom, "sender-peer")

        await services.stopAllHandlers()
    }

    func testMeshServicesSetCloisterRequestHandler() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        try await services.startCloisterHandler()

        await services.setCloisterRequestHandler { from, networkName in
            // Accept requests for "allowed-network"
            return networkName == "allowed-network"
        }

        // Send a request for allowed network
        let allowedKey = Data(repeating: 0x42, count: 32)
        let allowedRequest = CloisterRequest(
            networkName: "allowed-network",
            ephemeralPublicKey: allowedKey
        )
        let allowedData = try JSONCoding.encoder.encode(allowedRequest)
        await provider.simulateReceive(allowedData, from: "requester", on: CloisterChannels.negotiate)

        // Should be accepted
        var sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)
        var response = try JSONCoding.decoder.decode(CloisterResponse.self, from: sentMessages[0].data)
        XCTAssertTrue(response.accepted)

        // Clear sent messages
        await provider.clearSentMessages()

        // Send a request for disallowed network
        let disallowedRequest = CloisterRequest(
            networkName: "disallowed-network",
            ephemeralPublicKey: allowedKey
        )
        let disallowedData = try JSONCoding.encoder.encode(disallowedRequest)
        await provider.simulateReceive(disallowedData, from: "requester2", on: CloisterChannels.negotiate)

        // Should be rejected
        sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)
        response = try JSONCoding.decoder.decode(CloisterResponse.self, from: sentMessages[0].data)
        XCTAssertFalse(response.accepted)

        await services.stopAllHandlers()
    }

    // MARK: - Idempotency Tests

    func testMeshServicesDoubleStartHandlers() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        try await services.startAllHandlers()

        // Second start should throw or be idempotent
        do {
            try await services.startAllHandlers()
            // If it doesn't throw, that's also acceptable (idempotent)
        } catch ServiceError.alreadyRunning {
            // Expected for strict implementations
        }

        await services.stopAllHandlers()
    }

    func testMeshServicesDoubleStop() async throws {
        let provider = MockChannelProvider(peerId: "services-peer")
        let services = MeshServices(provider: provider)

        try await services.startAllHandlers()
        await services.stopAllHandlers()

        // Second stop should be safe (idempotent)
        await services.stopAllHandlers()

        // Should still be stopped
        let healthRegistered = await provider.hasHandler(for: HealthChannels.request)
        XCTAssertFalse(healthRegistered)
    }
}

// MARK: - MockChannelProvider Extension

extension MockChannelProvider {
    func clearSentMessages() async {
        sentMessages.removeAll()
    }
}
