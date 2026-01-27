import XCTest
@testable import OmertaMesh

final class HealthServiceTests: XCTestCase {

    // MARK: - Health Handler Tests

    func testHealthHandlerStartStop() async throws {
        let provider = MockChannelProvider()
        let handler = HealthHandler(provider: provider)

        // Start handler
        try await handler.start()
        let isRegistered = await provider.hasHandler(for: HealthChannels.request)
        XCTAssertTrue(isRegistered)

        // Stop handler
        await handler.stop()
        let isUnregistered = await provider.hasHandler(for: HealthChannels.request)
        XCTAssertFalse(isUnregistered)
    }

    func testHealthHandlerAlreadyRunningError() async throws {
        let provider = MockChannelProvider()
        let handler = HealthHandler(provider: provider)

        try await handler.start()

        // Should throw when trying to start again
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

    func testHealthHandlerRespondsToRequest() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = HealthHandler(provider: provider)

        // Set a custom metrics provider
        await handler.setMetricsProvider {
            HealthMetrics(
                peerCount: 5,
                directConnectionCount: 3,
                relayCount: 2,
                natType: .fullCone,
                publicEndpoint: "1.2.3.4:5678",
                uptimeSeconds: 3600,
                averageLatencyMs: 25.5
            )
        }

        try await handler.start()

        // Create a health request
        let request = HealthRequest(includeMetrics: true)
        let requestData = try JSONCoding.encoder.encode(request)

        // Simulate receiving the request
        await provider.simulateReceive(requestData, from: "requester-peer", on: HealthChannels.request)

        // Check that a response was sent
        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let sent = sentMessages[0]
        XCTAssertEqual(sent.target, "requester-peer")
        XCTAssertEqual(sent.channel, HealthChannels.response(for: "requester-peer"))

        // Decode and verify response
        let response = try JSONCoding.decoder.decode(HealthResponse.self, from: sent.data)
        XCTAssertEqual(response.requestId, request.requestId)
        XCTAssertEqual(response.status, .healthy)
        XCTAssertNotNil(response.metrics)
        XCTAssertEqual(response.metrics?.peerCount, 5)
        XCTAssertEqual(response.metrics?.directConnectionCount, 3)

        await handler.stop()
    }

    func testHealthHandlerDetermineDegradedStatus() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = HealthHandler(provider: provider)

        // Set metrics that indicate degraded status (no direct connections, only relay)
        await handler.setMetricsProvider {
            HealthMetrics(
                peerCount: 2,
                directConnectionCount: 0,
                relayCount: 2,
                natType: .symmetric,
                publicEndpoint: nil,
                uptimeSeconds: 100,
                averageLatencyMs: 150
            )
        }

        try await handler.start()

        let request = HealthRequest(includeMetrics: true)
        let requestData = try JSONCoding.encoder.encode(request)

        await provider.simulateReceive(requestData, from: "requester", on: HealthChannels.request)

        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let response = try JSONCoding.decoder.decode(HealthResponse.self, from: sentMessages[0].data)
        XCTAssertEqual(response.status, .degraded)

        await handler.stop()
    }

    // MARK: - Service Messages Tests

    func testHealthRequestEncoding() throws {
        let request = HealthRequest(requestId: UUID(), includeMetrics: true)

        let encoded = try JSONCoding.encoder.encode(request)
        let decoded = try JSONCoding.decoder.decode(HealthRequest.self, from: encoded)

        XCTAssertEqual(decoded.requestId, request.requestId)
        XCTAssertEqual(decoded.includeMetrics, request.includeMetrics)
    }

    func testHealthResponseEncoding() throws {
        let metrics = HealthMetrics(
            peerCount: 10,
            directConnectionCount: 7,
            relayCount: 3,
            natType: .portRestrictedCone,
            publicEndpoint: "5.6.7.8:9999",
            uptimeSeconds: 7200,
            averageLatencyMs: 50.0
        )

        let response = HealthResponse(
            requestId: UUID(),
            status: .healthy,
            metrics: metrics
        )

        let encoded = try JSONCoding.encoder.encode(response)
        let decoded = try JSONCoding.decoder.decode(HealthResponse.self, from: encoded)

        XCTAssertEqual(decoded.requestId, response.requestId)
        XCTAssertEqual(decoded.status, response.status)
        XCTAssertEqual(decoded.metrics?.peerCount, 10)
        XCTAssertEqual(decoded.metrics?.natType, .portRestrictedCone)
    }

    func testHealthStatusValues() {
        let statuses: [HealthStatus] = [.healthy, .degraded, .unhealthy, .unknown]

        for status in statuses {
            // Ensure all statuses are valid strings
            XCTAssertFalse(status.rawValue.isEmpty)
        }
    }
}
