// ControlSocketTests.swift - Tests for control socket server and client

import XCTest
@testable import OmertaMesh

final class ControlSocketTests: XCTestCase {

    // Test socket path
    var testSocketPath: String {
        "\(NSTemporaryDirectory())omerta-test-\(UUID().uuidString.prefix(8)).sock"
    }

    // MARK: - Server Tests

    func testServerStartAndStop() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        // Start server with a simple echo handler
        try await server.start { (command: String, _: ClientConnection) async -> String in
            return "echo: \(command)"
        }

        // Check socket exists
        XCTAssertTrue(DaemonSocketPaths.socketExists(socketPath))

        // Stop server
        await server.stop()

        // Socket should be cleaned up
        XCTAssertFalse(DaemonSocketPaths.socketExists(socketPath))
    }

    func testServerState() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        let beforeState = await server.currentState
        XCTAssertEqual(beforeState, .stopped)

        try await server.start { (command: String, _: ClientConnection) async -> String in
            return command
        }

        let runningState = await server.currentState
        XCTAssertEqual(runningState, .running)

        await server.stop()

        let afterState = await server.currentState
        XCTAssertEqual(afterState, .stopped)
    }

    func testServerRejectsDoubleStart() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        try await server.start { (command: String, _: ClientConnection) async -> String in
            return command
        }

        defer {
            Task {
                await server.stop()
            }
        }

        // Second start should throw
        do {
            try await server.start { (command: String, _: ClientConnection) async -> String in
                return command
            }
            XCTFail("Expected error for double start")
        } catch {
            // Expected
            if case IPCError.socketError = error {
                // Good
            } else {
                XCTFail("Expected socketError, got \(error)")
            }
        }
    }

    // MARK: - Client Tests

    func testClientConnectToNonexistent() async throws {
        let nonExistentPath = "\(NSTemporaryDirectory())omerta-nonexistent-\(UUID().uuidString).sock"
        let client = ControlSocketClient(socketPath: nonExistentPath)

        do {
            try await client.connect()
            XCTFail("Expected connection to fail")
        } catch {
            // Expected - socket doesn't exist
            if case IPCError.connectionFailed = error {
                // Good
            } else {
                XCTFail("Expected connectionFailed error, got \(error)")
            }
        }
    }

    func testClientState() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        try await server.start { (command: String, _: ClientConnection) async -> String in
            return command
        }

        defer {
            Task {
                await server.stop()
            }
        }

        let client = ControlSocketClient(socketPath: socketPath)

        let beforeState = await client.isConnected
        XCTAssertFalse(beforeState)

        try await client.connect()

        let connectedState = await client.isConnected
        XCTAssertTrue(connectedState)

        await client.disconnect()

        let afterState = await client.isConnected
        XCTAssertFalse(afterState)
    }

    // MARK: - Server Client Count Tests

    func testServerInitialClientCountIsZero() async throws {
        let socketPath = testSocketPath
        let server = ControlSocketServer(socketPath: socketPath)

        try await server.start { (command: String, _: ClientConnection) async -> String in
            return command
        }

        defer {
            Task {
                await server.stop()
            }
        }

        let count = await server.clientCount
        XCTAssertEqual(count, 0)
    }
}
