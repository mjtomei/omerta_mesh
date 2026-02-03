// MultiEndpointHandshakeTests.swift - Tests for multi-endpoint handshake negotiation

import XCTest
@testable import OmertaTunnel
@testable import OmertaMesh

final class MultiEndpointHandshakeTests: XCTestCase {

    // MARK: - Handshake Negotiation

    func testHandshakeWithExtraEndpointsRequested() async throws {
        let provider = MockChannelProvider()
        let config = TunnelManagerConfig(extraEndpoints: 2)
        let manager = TunnelManager(provider: provider, config: config)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        // Verify handshake includes extraEndpointsRequested
        let handshakeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-handshake" }
        XCTAssertEqual(handshakeMessages.count, 1)

        let handshake = try JSONDecoder().decode(SessionHandshake.self, from: handshakeMessages[0].data)
        XCTAssertEqual(handshake.type, .request)
        XCTAssertEqual(handshake.extraEndpointsRequested, 2)

        await manager.stop()
    }

    func testHandshakeWithoutExtraEndpoints() async throws {
        // Default config has extraEndpoints = 0
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        let handshakeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-handshake" }
        let handshake = try JSONDecoder().decode(SessionHandshake.self, from: handshakeMessages[0].data)
        XCTAssertNil(handshake.extraEndpointsRequested, "Default config should not request extra endpoints")

        await manager.stop()
    }

    func testHandshakeExtraEndpointsZero() async throws {
        let provider = MockChannelProvider()
        let config = TunnelManagerConfig(extraEndpoints: 0)
        let manager = TunnelManager(provider: provider, config: config)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        let handshakeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-handshake" }
        let handshake = try JSONDecoder().decode(SessionHandshake.self, from: handshakeMessages[0].data)
        XCTAssertNil(handshake.extraEndpointsRequested)

        await manager.stop()
    }

    func testEndpointOfferExchange() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        // Simulate receiving an endpointOffer from remote
        let offer = SessionHandshake(type: .endpointOffer, channel: "data",
                                     extraEndpoints: ["10.0.0.1:6000", "10.0.0.1:6001"])
        let data = try JSONEncoder().encode(offer)
        await provider.simulateMessage(from: "machine-1", on: "tunnel-handshake", data: data)

        // Verify endpoints were added to the EndpointSet
        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        let endpointSet = await manager.getEndpointSet(for: key)
        XCTAssertNotNil(endpointSet)

        let addresses = await endpointSet!.activeAddresses
        XCTAssertTrue(addresses.contains("10.0.0.1:6000"))
        XCTAssertTrue(addresses.contains("10.0.0.1:6001"))

        await manager.stop()
    }

    func testBothSidesPopulateEndpointSet() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Initiator creates session
        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        // Simulate ack with extra endpoints
        let ack = SessionHandshake(type: .ack, channel: "data", sessionId: "abc",
                                   extraEndpoints: ["10.0.0.1:7000"])
        let ackData = try JSONEncoder().encode(ack)
        await provider.simulateMessage(from: "machine-1", on: "tunnel-handshake", data: ackData)

        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        let endpointSet = await manager.getEndpointSet(for: key)
        let addresses = await endpointSet!.activeAddresses
        XCTAssertTrue(addresses.contains("10.0.0.1:7000"))

        await manager.stop()
    }

    // MARK: - Backward Compatibility

    func testOldStyleRequestStillWorks() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Old-style request without extra endpoint fields
        let handshake = SessionHandshake(type: .request, channel: "data", sessionId: "old123")
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "remote-peer", on: "tunnel-handshake", data: data)

        let count = await manager.sessionCount
        XCTAssertEqual(count, 1, "Old-style handshake should still create a session")

        await manager.stop()
    }

    func testSessionHasEndpointSetAfterCreation() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let session = try await manager.getSession(machineId: "machine-1", channel: "data")
        let endpointSet = await session.getEndpointSet()
        XCTAssertNotNil(endpointSet, "Session should have an EndpointSet after creation")

        await manager.stop()
    }

    func testInboundSessionHasEndpointSet() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Simulate inbound request
        let handshake = SessionHandshake(type: .request, channel: "data", sessionId: "inb1")
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "remote-peer", on: "tunnel-handshake", data: data)

        let key = TunnelSessionKey(remoteMachineId: "remote-peer", channel: "data")
        let endpointSet = await manager.getEndpointSet(for: key)
        XCTAssertNotNil(endpointSet, "Inbound session should have an EndpointSet")

        await manager.stop()
    }

    func testEndpointSetCleanedUpOnSessionClose() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data")
        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")

        // Verify set exists
        let setBefore = await manager.getEndpointSet(for: key)
        XCTAssertNotNil(setBefore)

        // Close session
        await manager.closeSession(key: key)

        // Verify set cleaned up
        let setAfter = await manager.getEndpointSet(for: key)
        XCTAssertNil(setAfter)

        await manager.stop()
    }
}
