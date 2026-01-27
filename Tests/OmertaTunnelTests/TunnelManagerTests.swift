// TunnelManagerTests.swift - Tests for TunnelManager and TunnelSession

import XCTest
@testable import OmertaTunnel
@testable import OmertaMesh

// Mock ChannelProvider for testing
actor MockChannelProvider: ChannelProvider {
    let peerId: PeerId = "test-peer-\(UUID().uuidString.prefix(8))"
    let machineId: MachineId = "test-machine-\(UUID().uuidString.prefix(8))"

    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]
    private var sentMessages: [(to: String, channel: String, data: Data)] = []

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        sentMessages.append((to: peerId, channel: channel, data: data))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        sentMessages.append((to: machineId, channel: channel, data: data))
    }

    // Test helpers
    func getRegisteredChannels() -> [String] {
        Array(handlers.keys)
    }

    func getSentMessages() -> [(to: String, channel: String, data: Data)] {
        sentMessages
    }

    func clearSentMessages() {
        sentMessages.removeAll()
    }

    func simulateMessage(from sender: MachineId, on channel: String, data: Data) async {
        if let handler = handlers[channel] {
            await handler(sender, data)
        }
    }
}

final class TunnelManagerTests: XCTestCase {

    func testManagerInitialization() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        // Manager should not be started yet
        let session = await manager.currentSession()
        XCTAssertNil(session)
    }

    func testManagerStartStop() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        // Start the manager
        try await manager.start()

        // Check handshake channel is registered
        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel-handshake"))

        // Stop the manager
        await manager.stop()

        // Channel should be unregistered
        let channelsAfterStop = await provider.getRegisteredChannels()
        XCTAssertFalse(channelsAfterStop.contains("tunnel-handshake"))
    }

    func testCreateSession() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        try await manager.start()

        // Create session with a machine
        let session = try await manager.createSession(withMachine: "remote-machine-123")

        // Verify session was created
        XCTAssertNotNil(session)
        let remoteMachineId = await session.remoteMachineId
        XCTAssertEqual(remoteMachineId, "remote-machine-123")

        // Verify handshake was sent
        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].to, "remote-machine-123")
        XCTAssertEqual(messages[0].channel, "tunnel-handshake")

        await manager.stop()
    }

    func testSetSessionRequestHandler() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        var requestReceived = false
        await manager.setSessionRequestHandler { machineId in
            requestReceived = true
            return true
        }

        try await manager.start()
        await manager.stop()

        // Handler is set but not called yet (would need to simulate incoming handshake)
        XCTAssertFalse(requestReceived)
    }

    func testCloseSession() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        try await manager.start()

        let session = try await manager.createSession(withMachine: "remote-machine-123")
        XCTAssertNotNil(session)

        await provider.clearSentMessages()

        // Close the session
        await manager.closeSession()

        // Verify close handshake was sent
        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].channel, "tunnel-handshake")

        // Session should be nil
        let currentSession = await manager.currentSession()
        XCTAssertNil(currentSession)

        await manager.stop()
    }

    // MARK: - Handshake Protocol Tests

    func testIncomingSessionRequest() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        var handlerCalled = false
        var receivedMachineId: MachineId?

        await manager.setSessionRequestHandler { machineId in
            handlerCalled = true
            receivedMachineId = machineId
            return true
        }

        var establishedSession: TunnelSession?
        await manager.setSessionEstablishedHandler { session in
            establishedSession = session
        }

        try await manager.start()

        // Simulate incoming session request
        let handshake = SessionHandshake(type: .request)
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "remote-initiator", on: "tunnel-handshake", data: data)

        // Handler should have been called
        XCTAssertTrue(handlerCalled)
        XCTAssertEqual(receivedMachineId, "remote-initiator")

        // Session should be established
        XCTAssertNotNil(establishedSession)
        let remoteMachineId = await establishedSession?.remoteMachineId
        XCTAssertEqual(remoteMachineId, "remote-initiator")

        // Ack should have been sent
        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].to, "remote-initiator")
        XCTAssertEqual(messages[0].channel, "tunnel-handshake")

        // Verify it's an ack
        let sentHandshake = try JSONDecoder().decode(SessionHandshake.self, from: messages[0].data)
        XCTAssertEqual(sentHandshake.type, .ack)

        await manager.stop()
    }

    func testIncomingSessionRejected() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        // Handler rejects the session
        await manager.setSessionRequestHandler { _ in
            return false
        }

        try await manager.start()

        // Simulate incoming session request
        let handshake = SessionHandshake(type: .request)
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "unwanted-machine", on: "tunnel-handshake", data: data)

        // No session should be created
        let currentSession = await manager.currentSession()
        XCTAssertNil(currentSession)

        // Reject should have been sent
        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)
        let sentHandshake = try JSONDecoder().decode(SessionHandshake.self, from: messages[0].data)
        XCTAssertEqual(sentHandshake.type, .reject)

        await manager.stop()
    }

    func testReceiveCloseFromRemote() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        try await manager.start()

        // Create a session
        let session = try await manager.createSession(withMachine: "remote-machine")
        XCTAssertNotNil(session)

        // Simulate remote closing the session
        let closeHandshake = SessionHandshake(type: .close)
        let data = try JSONEncoder().encode(closeHandshake)
        await provider.simulateMessage(from: "remote-machine", on: "tunnel-handshake", data: data)

        // Session should be nil now
        let currentSession = await manager.currentSession()
        XCTAssertNil(currentSession)

        // Original session should be disconnected
        let state = await session.state
        XCTAssertEqual(state, .disconnected)

        await manager.stop()
    }

    func testDefaultAcceptsWithoutHandler() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        // No handler set - should accept by default
        try await manager.start()

        let handshake = SessionHandshake(type: .request)
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "any-machine", on: "tunnel-handshake", data: data)

        // Session should be created
        let currentSession = await manager.currentSession()
        XCTAssertNotNil(currentSession)

        await manager.stop()
    }

    // MARK: - Edge Cases

    func testCreateSessionBeforeStart() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        // Try to create session before starting
        do {
            _ = try await manager.createSession(withMachine: "machine")
            XCTFail("Expected error")
        } catch {
            XCTAssertEqual(error as? TunnelError, .notConnected)
        }
    }

    func testNewSessionClosesExisting() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        try await manager.start()

        // Create first session
        let session1 = try await manager.createSession(withMachine: "machine-1")
        let state1Before = await session1.state
        XCTAssertEqual(state1Before, .active)

        // Create second session
        let session2 = try await manager.createSession(withMachine: "machine-2")

        // First session should be disconnected
        let state1After = await session1.state
        XCTAssertEqual(state1After, .disconnected)

        // Second session should be active
        let state2 = await session2.state
        XCTAssertEqual(state2, .active)

        // Current session should be the second one
        let current = await manager.currentSession()
        let currentMachine = await current?.remoteMachineId
        XCTAssertEqual(currentMachine, "machine-2")

        await manager.stop()
    }

    func testDoubleStartIsIdempotent() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        try await manager.start()
        try await manager.start() // Should not throw

        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel-handshake"))

        await manager.stop()
    }

    func testDoubleStopIsIdempotent() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        try await manager.start()
        await manager.stop()
        await manager.stop() // Should not crash

        let channels = await provider.getRegisteredChannels()
        XCTAssertFalse(channels.contains("tunnel-handshake"))
    }
}

final class TunnelSessionTests: XCTestCase {

    func testSessionInitialization() async throws {
        let provider = MockChannelProvider()

        let session = TunnelSession(
            remoteMachineId: "machine-123",
            channel: "data",
            provider: provider
        )

        // Check initial state
        let state = await session.state
        XCTAssertEqual(state, .connecting)

        let remoteMachineId = await session.remoteMachineId
        XCTAssertEqual(remoteMachineId, "machine-123")

        let channel = await session.channel
        XCTAssertEqual(channel, "data")
    }

    func testSessionKey() async throws {
        let provider = MockChannelProvider()

        let session = TunnelSession(
            remoteMachineId: "machine-456",
            channel: "packets",
            provider: provider
        )

        let key = await session.key
        XCTAssertEqual(key.remoteMachineId, "machine-456")
        XCTAssertEqual(key.channel, "packets")
        XCTAssertEqual(key, TunnelSessionKey(remoteMachineId: "machine-456", channel: "packets"))
    }

    func testSessionActivation() async throws {
        let provider = MockChannelProvider()

        let session = TunnelSession(
            remoteMachineId: "machine-123",
            channel: "data",
            provider: provider
        )

        // Activate the session
        await session.activate()

        // Check state is now active
        let state = await session.state
        XCTAssertEqual(state, .active)

        // Check that channel handler was registered
        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel:data"))
    }

    func testSendRequiresActiveState() async throws {
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        // Try to send without activating - should fail
        do {
            try await session.send(Data([1, 2, 3]))
            XCTFail("Expected error")
        } catch {
            XCTAssertEqual(error as? TunnelError, .notConnected)
        }
    }

    func testSendMessage() async throws {
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        await session.activate()

        // Send a message
        try await session.send(Data([1, 2, 3]))

        // Check message was sent
        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].to, "machine-1")
        XCTAssertEqual(messages[0].channel, "tunnel:data")
        XCTAssertEqual(messages[0].data, Data([1, 2, 3]))
    }

    func testCloseSession() async throws {
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        await session.activate()

        // Close the session
        await session.close()

        // State should be disconnected
        let state = await session.state
        XCTAssertEqual(state, .disconnected)

        // Channel handler should be deregistered
        let channels = await provider.getRegisteredChannels()
        XCTAssertFalse(channels.contains("tunnel:data"))
    }

    func testReceiveCallback() async throws {
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        var receivedData: Data?
        await session.onReceive { data in
            receivedData = data
        }

        await session.activate()

        // Simulate incoming message
        await provider.simulateMessage(
            from: "machine-1",
            on: "tunnel:data",
            data: Data([1, 2, 3, 4])
        )

        XCTAssertEqual(receivedData, Data([1, 2, 3, 4]))
    }

    func testReceiveFiltersByMachine() async throws {
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        var receivedData: Data?
        await session.onReceive { data in
            receivedData = data
        }

        await session.activate()

        // Simulate message from wrong machine - should be ignored
        await provider.simulateMessage(
            from: "wrong-machine",
            on: "tunnel:data",
            data: Data([9, 9, 9])
        )

        XCTAssertNil(receivedData)

        // Simulate message from correct machine
        await provider.simulateMessage(
            from: "machine-1",
            on: "tunnel:data",
            data: Data([1, 2, 3])
        )

        XCTAssertEqual(receivedData, Data([1, 2, 3]))
    }

    func testSessionStatistics() async throws {
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        await session.activate()

        // Send some data
        try await session.send(Data(repeating: 0x42, count: 100))
        try await session.send(Data(repeating: 0x43, count: 50))

        let stats = await session.stats
        XCTAssertEqual(stats.packetsSent, 2)
        XCTAssertEqual(stats.bytesSent, 150)
        XCTAssertEqual(stats.packetsReceived, 0)
        XCTAssertEqual(stats.bytesReceived, 0)
    }

    func testSendAfterClose() async throws {
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        await session.activate()
        await session.close()

        do {
            try await session.send(Data([1, 2, 3]))
            XCTFail("Expected error")
        } catch {
            XCTAssertEqual(error as? TunnelError, .notConnected)
        }
    }

    func testMultipleChannelsSameMachine() async throws {
        let provider = MockChannelProvider()

        let controlSession = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "control",
            provider: provider
        )

        let dataSession = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )

        await controlSession.activate()
        await dataSession.activate()

        // Different channels should register different handlers
        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel:control"))
        XCTAssertTrue(channels.contains("tunnel:data"))

        // Keys should be different
        let controlKey = await controlSession.key
        let dataKey = await dataSession.key
        XCTAssertNotEqual(controlKey, dataKey)
    }
}

final class TunnelConfigTests: XCTestCase {

    func testTunnelSessionKeyEquality() {
        let key1 = TunnelSessionKey(remoteMachineId: "m1", channel: "data")
        let key2 = TunnelSessionKey(remoteMachineId: "m1", channel: "data")
        let key3 = TunnelSessionKey(remoteMachineId: "m1", channel: "control")
        let key4 = TunnelSessionKey(remoteMachineId: "m2", channel: "data")

        XCTAssertEqual(key1, key2)
        XCTAssertNotEqual(key1, key3)
        XCTAssertNotEqual(key1, key4)
    }

    func testTunnelSessionKeyHashable() {
        var set = Set<TunnelSessionKey>()
        set.insert(TunnelSessionKey(remoteMachineId: "m1", channel: "data"))
        set.insert(TunnelSessionKey(remoteMachineId: "m1", channel: "data"))
        set.insert(TunnelSessionKey(remoteMachineId: "m1", channel: "control"))

        XCTAssertEqual(set.count, 2)
    }

    func testTunnelStateEquality() {
        XCTAssertEqual(TunnelState.connecting, TunnelState.connecting)
        XCTAssertEqual(TunnelState.active, TunnelState.active)
        XCTAssertEqual(TunnelState.disconnected, TunnelState.disconnected)
        XCTAssertEqual(TunnelState.failed("error"), TunnelState.failed("error"))
        XCTAssertNotEqual(TunnelState.failed("error1"), TunnelState.failed("error2"))
    }

    func testTunnelErrorDescriptions() {
        XCTAssertNotNil(TunnelError.notConnected.errorDescription)
        XCTAssertNotNil(TunnelError.alreadyConnected.errorDescription)
        XCTAssertNotNil(TunnelError.machineNotFound("machine").errorDescription)
        XCTAssertNotNil(TunnelError.timeout.errorDescription)
        XCTAssertNotNil(TunnelError.sessionRejected.errorDescription)
    }
}
