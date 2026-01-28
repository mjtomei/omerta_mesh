// DaemonIntegrationTests.swift - Integration tests for daemon functionality

import XCTest
@testable import OmertaMesh

/// Integration tests for the daemon infrastructure
final class DaemonIntegrationTests: XCTestCase {

    // Test socket path
    var testSocketPath: String {
        "/tmp/omerta-integration-test-\(UUID().uuidString.prefix(8)).sock"
    }

    // MARK: - Full Command Round-Trip Tests

    func testStatusCommandRoundTrip() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        // Server responds with status
        try await server.start { (command: BaseDaemonCommand, _: ClientConnection) async -> BaseDaemonResponse in
            switch command {
            case .status:
                return .status(DaemonStatusData(
                    isRunning: true,
                    daemonType: "test-daemon",
                    networkId: "test-net-123",
                    uptime: 42.5,
                    additionalInfo: ["key": "value"]
                ))
            case .shutdown:
                return .shutdownAck(ShutdownAckData(accepted: true))
            }
        }

        defer {
            Task { await server.stop() }
        }

        // Client sends status request
        let client = ControlSocketClient(socketPath: socketPath)
        try await client.connect()

        let response: BaseDaemonResponse = try await client.send(BaseDaemonCommand.status)

        switch response {
        case .status(let status):
            XCTAssertTrue(status.isRunning)
            XCTAssertEqual(status.daemonType, "test-daemon")
            XCTAssertEqual(status.networkId, "test-net-123")
            XCTAssertEqual(status.uptime, 42.5)
            XCTAssertEqual(status.additionalInfo["key"], "value")
        default:
            XCTFail("Expected status response, got \(response)")
        }

        await client.disconnect()
    }

    func testShutdownCommandRoundTrip() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        try await server.start { (command: BaseDaemonCommand, _: ClientConnection) async -> BaseDaemonResponse in
            switch command {
            case .status:
                return .status(DaemonStatusData(isRunning: true, daemonType: "test", networkId: "test"))
            case .shutdown(let graceful, let timeout):
                return .shutdownAck(ShutdownAckData(
                    accepted: true,
                    reason: nil,
                    estimatedSeconds: graceful ? timeout : 0
                ))
            }
        }

        defer {
            Task { await server.stop() }
        }

        let client = ControlSocketClient(socketPath: socketPath)
        try await client.connect()

        let response: BaseDaemonResponse = try await client.send(
            BaseDaemonCommand.shutdown(graceful: true, timeoutSeconds: 10)
        )

        switch response {
        case .shutdownAck(let ack):
            XCTAssertTrue(ack.accepted)
            XCTAssertEqual(ack.estimatedSeconds, 10)
        default:
            XCTFail("Expected shutdownAck response")
        }

        await client.disconnect()
    }

    // MARK: - Error Response Tests

    func testErrorResponse() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        try await server.start { (command: String, _: ClientConnection) async -> BaseDaemonResponse in
            return .error("Test error: \(command)")
        }

        defer {
            Task { await server.stop() }
        }

        let client = ControlSocketClient(socketPath: socketPath)
        try await client.connect()

        let response: BaseDaemonResponse = try await client.send("trigger-error")

        switch response {
        case .error(let message):
            XCTAssertTrue(message.contains("trigger-error"))
        default:
            XCTFail("Expected error response")
        }

        await client.disconnect()
    }

    // MARK: - Complex Type Tests

    func testPeerDataResponse() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        let testPeers = [
            PeerData(
                peerId: "peer1",
                endpoint: "192.168.1.1:9999",
                natType: "cone",
                lastSeen: Date(timeIntervalSince1970: 1700000000),
                isConnected: true,
                isDirect: true
            ),
            PeerData(
                peerId: "peer2",
                endpoint: "192.168.1.2:9999",
                natType: "symmetric",
                lastSeen: Date(timeIntervalSince1970: 1700000001),
                isConnected: false,
                isDirect: false
            )
        ]

        try await server.start { (command: String, _: ClientConnection) async -> [PeerData] in
            return testPeers
        }

        defer {
            Task { await server.stop() }
        }

        let client = ControlSocketClient(socketPath: socketPath)
        try await client.connect()

        let response: [PeerData] = try await client.send("get-peers")

        XCTAssertEqual(response.count, 2)
        XCTAssertEqual(response[0].peerId, "peer1")
        XCTAssertEqual(response[0].endpoint, "192.168.1.1:9999")
        XCTAssertTrue(response[0].isConnected)
        XCTAssertEqual(response[1].peerId, "peer2")
        XCTAssertFalse(response[1].isConnected)

        await client.disconnect()
    }

    // MARK: - Sequential Request Tests

    func testMultipleSequentialRequests() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        var requestCount = 0

        try await server.start { (command: Int, _: ClientConnection) async -> Int in
            requestCount += 1
            return command * 2 + requestCount
        }

        defer {
            Task { await server.stop() }
        }

        let client = ControlSocketClient(socketPath: socketPath)
        try await client.connect()

        // Send multiple requests sequentially
        let r1: Int = try await client.send(10)
        let r2: Int = try await client.send(20)
        let r3: Int = try await client.send(30)

        XCTAssertEqual(r1, 21)  // 10*2 + 1
        XCTAssertEqual(r2, 42)  // 20*2 + 2
        XCTAssertEqual(r3, 63)  // 30*2 + 3

        await client.disconnect()
    }

    // MARK: - Connection Lifecycle Tests

    func testClientCanReconnect() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        try await server.start { (command: String, _: ClientConnection) async -> String in
            return "received: \(command)"
        }

        defer {
            Task { await server.stop() }
        }

        let client = ControlSocketClient(socketPath: socketPath)

        // First connection
        try await client.connect()
        let r1: String = try await client.send("first")
        XCTAssertEqual(r1, "received: first")
        await client.disconnect()

        // Second connection
        try await client.connect()
        let r2: String = try await client.send("second")
        XCTAssertEqual(r2, "received: second")
        await client.disconnect()
    }

    // MARK: - Socket Path Tests

    func testSocketPathsAreCorrect() {
        let networkId = "my-test-network"

        let controlPath = DaemonSocketPaths.meshDaemonControl(networkId: networkId)
        let dataPath = DaemonSocketPaths.meshDaemonData(networkId: networkId)

        XCTAssertEqual(controlPath, "/tmp/omerta-meshd-my-test-network.sock")
        XCTAssertEqual(dataPath, "/tmp/omerta-meshd-my-test-network.data.sock")
    }

    func testSocketExistsCheck() async throws {
        let socketPath = testSocketPath

        // Socket shouldn't exist yet
        XCTAssertFalse(DaemonSocketPaths.socketExists(socketPath))

        let server = ControlSocketServer(socketPath: socketPath)
        try await server.start { (cmd: String, _: ClientConnection) async -> String in cmd }

        // Socket should exist now
        XCTAssertTrue(DaemonSocketPaths.socketExists(socketPath))

        await server.stop()

        // Socket should be cleaned up
        XCTAssertFalse(DaemonSocketPaths.socketExists(socketPath))
    }
}
