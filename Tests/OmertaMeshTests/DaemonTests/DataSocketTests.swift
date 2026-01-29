// DataSocketTests.swift - Tests for high-performance data socket

import XCTest
@testable import OmertaMesh

final class DataSocketTests: XCTestCase {

    // Test socket path
    var testSocketPath: String {
        "\(NSTemporaryDirectory())omerta-data-test-\(UUID().uuidString.prefix(8)).sock"
    }

    // MARK: - Server Tests

    func testDataServerStartAndStop() async throws {
        let socketPath = testSocketPath
        let server = DataSocketServer(socketPath: socketPath)

        try await server.start()

        // Check socket exists
        XCTAssertTrue(DaemonSocketPaths.socketExists(socketPath))

        // Check state
        let state = await server.currentState
        XCTAssertEqual(state, .running)

        await server.stop()

        // Socket should be cleaned up
        XCTAssertFalse(DaemonSocketPaths.socketExists(socketPath))

        let stoppedState = await server.currentState
        XCTAssertEqual(stoppedState, .stopped)
    }

    func testDataServerRejectsDoubleStart() async throws {
        let socketPath = testSocketPath
        let server = DataSocketServer(socketPath: socketPath)

        try await server.start()

        defer {
            Task {
                await server.stop()
            }
        }

        do {
            try await server.start()
            XCTFail("Expected error for double start")
        } catch {
            // Expected
        }
    }

    // MARK: - Tunnel Registration Tests

    func testTunnelRegistration() async throws {
        let socketPath = testSocketPath
        let server = DataSocketServer(socketPath: socketPath)

        try await server.start()

        defer {
            Task {
                await server.stop()
            }
        }

        let tunnelId = UUID()

        // Initially no tunnels
        let beforeCount = await server.tunnelCount
        XCTAssertEqual(beforeCount, 0)

        let isRegisteredBefore = await server.isTunnelRegistered(tunnelId)
        XCTAssertFalse(isRegisteredBefore)

        // Register tunnel
        await server.registerTunnel(tunnelId) { _, _ in }

        let afterCount = await server.tunnelCount
        XCTAssertEqual(afterCount, 1)

        let isRegisteredAfter = await server.isTunnelRegistered(tunnelId)
        XCTAssertTrue(isRegisteredAfter)

        // Unregister tunnel
        await server.unregisterTunnel(tunnelId)

        let finalCount = await server.tunnelCount
        XCTAssertEqual(finalCount, 0)
    }

    func testMultipleTunnelRegistration() async throws {
        let socketPath = testSocketPath
        let server = DataSocketServer(socketPath: socketPath)

        try await server.start()

        defer {
            Task {
                await server.stop()
            }
        }

        let tunnelId1 = UUID()
        let tunnelId2 = UUID()
        let tunnelId3 = UUID()

        await server.registerTunnel(tunnelId1) { _, _ in }
        await server.registerTunnel(tunnelId2) { _, _ in }
        await server.registerTunnel(tunnelId3) { _, _ in }

        let count = await server.tunnelCount
        XCTAssertEqual(count, 3)

        await server.unregisterTunnel(tunnelId2)

        let countAfter = await server.tunnelCount
        XCTAssertEqual(countAfter, 2)

        let isRegistered1 = await server.isTunnelRegistered(tunnelId1)
        let isRegistered2 = await server.isTunnelRegistered(tunnelId2)
        let isRegistered3 = await server.isTunnelRegistered(tunnelId3)

        XCTAssertTrue(isRegistered1)
        XCTAssertFalse(isRegistered2)
        XCTAssertTrue(isRegistered3)
    }

    // MARK: - Client Tests

    func testDataClientState() async throws {
        let socketPath = testSocketPath
        let server = DataSocketServer(socketPath: socketPath)

        try await server.start()

        defer {
            Task {
                await server.stop()
            }
        }

        let client = DataSocketClient(socketPath: socketPath)

        let stateBefore = await client.currentState
        XCTAssertEqual(stateBefore, .disconnected)

        let isConnectedBefore = await client.isConnected
        XCTAssertFalse(isConnectedBefore)
    }

    func testDataClientConnectToNonexistent() async throws {
        let nonExistentPath = "\(NSTemporaryDirectory())omerta-data-nonexistent-\(UUID().uuidString).sock"
        let client = DataSocketClient(socketPath: nonExistentPath)

        do {
            try await client.connect { _, _ in }
            XCTFail("Expected connection to fail")
        } catch {
            // Expected
            if case IPCError.connectionFailed = error {
                // Good
            } else {
                XCTFail("Expected connectionFailed error, got \(error)")
            }
        }
    }

    // MARK: - Connection Count Tests

    func testServerInitialConnectionCountIsZero() async throws {
        let socketPath = testSocketPath
        let server = DataSocketServer(socketPath: socketPath)

        try await server.start()

        defer {
            Task {
                await server.stop()
            }
        }

        let count = await server.connectionCount
        XCTAssertEqual(count, 0)
    }

    // MARK: - Packet Size Tests

    func testMaxPacketSizeConstant() {
        XCTAssertEqual(DataSocketServer.maxPacketSize, 65535)
    }

    // MARK: - TunnelPacket Tests

    func testTunnelPacketCreation() {
        let tunnelId = UUID()
        let data = Data([0x01, 0x02, 0x03])

        let packet = TunnelPacket(tunnelId: tunnelId, data: data)

        XCTAssertEqual(packet.tunnelId, tunnelId)
        XCTAssertEqual(packet.data, data)
    }

    func testTunnelPacketWithEmptyData() {
        let tunnelId = UUID()
        let packet = TunnelPacket(tunnelId: tunnelId, data: Data())

        XCTAssertEqual(packet.tunnelId, tunnelId)
        XCTAssertTrue(packet.data.isEmpty)
    }

    // MARK: - Factory Method Tests

    func testMeshDaemonClientFactory() {
        let client = DataSocketClient.meshDaemon(networkId: "test-network")
        // Just verify it doesn't crash and creates a client
        XCTAssertNotNil(client)
    }
}
