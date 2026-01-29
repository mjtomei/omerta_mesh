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

        // Manager should have no sessions
        let count = await manager.sessionCount
        XCTAssertEqual(count, 0)
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

        // Handler is set but not called yet
        XCTAssertFalse(requestReceived)
    }

    func testCloseSession() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        try await manager.start()

        let session = try await manager.createSession(withMachine: "remote-machine-123")
        XCTAssertNotNil(session)

        await provider.clearSentMessages()

        // Close all sessions
        await manager.closeSession()

        // Verify close handshake was sent
        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].channel, "tunnel-handshake")

        // Session count should be 0
        let count = await manager.sessionCount
        XCTAssertEqual(count, 0)

        await manager.stop()
    }

    // MARK: - Session Pool Tests

    func testGetOrCreateSession() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // First call creates
        let session1 = try await manager.getSession(machineId: "machine-1", channel: "data")
        let count1 = await manager.sessionCount
        XCTAssertEqual(count1, 1)

        // Second call returns same session
        let session2 = try await manager.getSession(machineId: "machine-1", channel: "data")
        let count2 = await manager.sessionCount
        XCTAssertEqual(count2, 1)

        // Same object
        let id1 = await session1.remoteMachineId
        let id2 = await session2.remoteMachineId
        XCTAssertEqual(id1, id2)

        await manager.stop()
    }

    func testDifferentChannelsDifferentSessions() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let dataSession = try await manager.getSession(machineId: "machine-1", channel: "data")
        let controlSession = try await manager.getSession(machineId: "machine-1", channel: "control")

        let count = await manager.sessionCount
        XCTAssertEqual(count, 2)

        let dataCh = await dataSession.channel
        let controlCh = await controlSession.channel
        XCTAssertEqual(dataCh, "data")
        XCTAssertEqual(controlCh, "control")

        await manager.stop()
    }

    func testCloseAllSessionsToMachine() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Create sessions to two machines
        _ = try await manager.getSession(machineId: "machine-1", channel: "data")
        _ = try await manager.getSession(machineId: "machine-1", channel: "control")
        _ = try await manager.getSession(machineId: "machine-2", channel: "data")

        let countBefore = await manager.sessionCount
        XCTAssertEqual(countBefore, 3)

        // Close all sessions to machine-1
        await manager.closeAllSessions(to: "machine-1")

        let countAfter = await manager.sessionCount
        XCTAssertEqual(countAfter, 1)

        // machine-2 session should still exist
        let key = TunnelSessionKey(remoteMachineId: "machine-2", channel: "data")
        let remaining = await manager.getExistingSession(key: key)
        XCTAssertNotNil(remaining)

        await manager.stop()
    }

    func testSessionEstablishedCallback() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        var establishedSession: TunnelSession?
        await manager.setSessionEstablishedHandler { session in
            establishedSession = session
        }

        try await manager.start()

        // Simulate incoming session request
        let handshake = SessionHandshake(type: .request, channel: "data")
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "remote-initiator", on: "tunnel-handshake", data: data)

        XCTAssertNotNil(establishedSession)
        let remoteMachineId = await establishedSession?.remoteMachineId
        XCTAssertEqual(remoteMachineId, "remote-initiator")

        await manager.stop()
    }

    func testCloseSpecificSession() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data")
        _ = try await manager.getSession(machineId: "machine-1", channel: "control")

        let countBefore = await manager.sessionCount
        XCTAssertEqual(countBefore, 2)

        // Close only the data session
        let dataKey = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        await manager.closeSession(key: dataKey)

        let countAfter = await manager.sessionCount
        XCTAssertEqual(countAfter, 1)

        // Control session should still exist
        let controlKey = TunnelSessionKey(remoteMachineId: "machine-1", channel: "control")
        let remaining = await manager.getExistingSession(key: controlKey)
        XCTAssertNotNil(remaining)

        await manager.stop()
    }

    func testSessionCount() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let count0 = await manager.sessionCount
        XCTAssertEqual(count0, 0)

        _ = try await manager.getSession(machineId: "m1", channel: "data")
        let count1 = await manager.sessionCount
        XCTAssertEqual(count1, 1)

        _ = try await manager.getSession(machineId: "m2", channel: "data")
        let count2 = await manager.sessionCount
        XCTAssertEqual(count2, 2)

        await manager.closeAllSessions(to: "m1")
        let count3 = await manager.sessionCount
        XCTAssertEqual(count3, 1)

        await manager.stop()
        let count4 = await manager.sessionCount
        XCTAssertEqual(count4, 0)
    }

    func testSessionLimitPerMachine() async throws {
        let config = TunnelManagerConfig(maxSessionsPerMachine: 2, maxTotalSessions: 100)
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider, config: config)
        try await manager.start()

        _ = try await manager.getSession(machineId: "m1", channel: "ch1")
        _ = try await manager.getSession(machineId: "m1", channel: "ch2")

        do {
            _ = try await manager.getSession(machineId: "m1", channel: "ch3")
            XCTFail("Expected sessionLimitReached error")
        } catch {
            XCTAssertEqual(error as? TunnelError, .sessionLimitReached)
        }

        await manager.stop()
    }

    func testSessionLimitTotal() async throws {
        let config = TunnelManagerConfig(maxSessionsPerMachine: 10, maxTotalSessions: 2)
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider, config: config)
        try await manager.start()

        _ = try await manager.getSession(machineId: "m1", channel: "data")
        _ = try await manager.getSession(machineId: "m2", channel: "data")

        do {
            _ = try await manager.getSession(machineId: "m3", channel: "data")
            XCTFail("Expected sessionLimitReached error")
        } catch {
            XCTAssertEqual(error as? TunnelError, .sessionLimitReached)
        }

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
        let handshake = SessionHandshake(type: .request, channel: "data")
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
        let handshake = SessionHandshake(type: .request, channel: "data")
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "unwanted-machine", on: "tunnel-handshake", data: data)

        // No session should be created
        let count = await manager.sessionCount
        XCTAssertEqual(count, 0)

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
        let closeHandshake = SessionHandshake(type: .close, channel: "data")
        let data = try JSONEncoder().encode(closeHandshake)
        await provider.simulateMessage(from: "remote-machine", on: "tunnel-handshake", data: data)

        // Session count should be 0
        let count = await manager.sessionCount
        XCTAssertEqual(count, 0)

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

        let handshake = SessionHandshake(type: .request, channel: "data")
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "any-machine", on: "tunnel-handshake", data: data)

        // Session should be created
        let count = await manager.sessionCount
        XCTAssertEqual(count, 1)

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

    func testHandshakeIncludesChannel() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "control")

        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)

        let handshake = try JSONDecoder().decode(SessionHandshake.self, from: messages[0].data)
        XCTAssertEqual(handshake.channel, "control")

        await manager.stop()
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
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Creating a session via TunnelManager should register the wire channel
        let session = try await manager.getSession(machineId: "machine-123", channel: "data")

        let state = await session.state
        XCTAssertEqual(state, .active)

        // Wire channel should be registered by the manager
        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel-data"))

        await manager.stop()
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
        XCTAssertEqual(messages[0].channel, "tunnel-data")
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
    }

    func testReceiveCallback() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let session = try await manager.getSession(machineId: "machine-1", channel: "data")

        var receivedData: Data?
        await session.onReceive { data in
            receivedData = data
        }

        // Simulate incoming message — TunnelManager dispatches to the correct session
        await provider.simulateMessage(
            from: "machine-1",
            on: "tunnel-data",
            data: Data([1, 2, 3, 4])
        )

        XCTAssertEqual(receivedData, Data([1, 2, 3, 4]))

        await manager.stop()
    }

    func testReceiveFiltersByMachine() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let session = try await manager.getSession(machineId: "machine-1", channel: "data")

        var receivedData: Data?
        await session.onReceive { data in
            receivedData = data
        }

        // Simulate message from wrong machine - no session exists for it, so dispatch drops it
        await provider.simulateMessage(
            from: "wrong-machine",
            on: "tunnel-data",
            data: Data([9, 9, 9])
        )

        XCTAssertNil(receivedData)

        // Simulate message from correct machine
        await provider.simulateMessage(
            from: "machine-1",
            on: "tunnel-data",
            data: Data([1, 2, 3])
        )

        XCTAssertEqual(receivedData, Data([1, 2, 3]))

        await manager.stop()
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
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let controlSession = try await manager.getSession(machineId: "machine-1", channel: "control")
        let dataSession = try await manager.getSession(machineId: "machine-1", channel: "data")

        // TunnelManager should register wire channels for both
        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel-control"))
        XCTAssertTrue(channels.contains("tunnel-data"))

        // Keys should be different
        let controlKey = await controlSession.key
        let dataKey = await dataSession.key
        XCTAssertNotEqual(controlKey, dataKey)

        await manager.stop()
    }

    // MARK: - Wire Channel Dispatch Tests

    func testWireChannelStaysRegisteredWhenOneSessionCloses() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Two sessions on the same channel but different machines
        _ = try await manager.getSession(machineId: "machine-1", channel: "data")
        _ = try await manager.getSession(machineId: "machine-2", channel: "data")

        // Close one session
        let key1 = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        await manager.closeSession(key: key1)

        // Wire channel should still be registered (machine-2 still needs it)
        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel-data"))

        await manager.stop()
    }

    func testWireChannelsDeregisteredOnStop() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data")
        _ = try await manager.getSession(machineId: "machine-1", channel: "control")

        let channelsBefore = await provider.getRegisteredChannels()
        XCTAssertTrue(channelsBefore.contains("tunnel-data"))
        XCTAssertTrue(channelsBefore.contains("tunnel-control"))

        await manager.stop()

        // All wire channels should be deregistered
        let channelsAfter = await provider.getRegisteredChannels()
        XCTAssertFalse(channelsAfter.contains("tunnel-data"))
        XCTAssertFalse(channelsAfter.contains("tunnel-control"))
        XCTAssertFalse(channelsAfter.contains("tunnel-handshake"))
    }

    func testDispatchRoutesToCorrectSession() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Two sessions on same channel, different machines
        let session1 = try await manager.getSession(machineId: "machine-1", channel: "data")
        let session2 = try await manager.getSession(machineId: "machine-2", channel: "data")

        var received1: Data?
        var received2: Data?
        await session1.onReceive { data in received1 = data }
        await session2.onReceive { data in received2 = data }

        // Send to machine-1's session
        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: Data([0xAA]))

        XCTAssertEqual(received1, Data([0xAA]))
        XCTAssertNil(received2)

        // Send to machine-2's session
        await provider.simulateMessage(from: "machine-2", on: "tunnel-data", data: Data([0xBB]))

        XCTAssertEqual(received2, Data([0xBB]))
        // machine-1 should still have its original data
        XCTAssertEqual(received1, Data([0xAA]))

        await manager.stop()
    }

    func testDispatchDropsDataForUnknownMachine() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let session = try await manager.getSession(machineId: "machine-1", channel: "data")

        var receivedData: Data?
        await session.onReceive { data in receivedData = data }

        // Message from unknown machine — should be silently dropped
        await provider.simulateMessage(from: "unknown-machine", on: "tunnel-data", data: Data([0xFF]))

        XCTAssertNil(receivedData)

        await manager.stop()
    }

    func testDispatchAfterSessionCloseDropsData() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let session = try await manager.getSession(machineId: "machine-1", channel: "data")

        var receivedData: Data?
        await session.onReceive { data in receivedData = data }

        // Close the session
        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        await manager.closeSession(key: key)

        // Wire channel still registered, but session removed — data should be dropped
        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: Data([0xCC]))

        XCTAssertNil(receivedData)

        await manager.stop()
    }

    func testWireChannelRegisteredOnceForMultipleSessions() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Create multiple sessions on the same channel
        _ = try await manager.getSession(machineId: "machine-1", channel: "data")
        _ = try await manager.getSession(machineId: "machine-2", channel: "data")
        _ = try await manager.getSession(machineId: "machine-3", channel: "data")

        // Only one "tunnel-data" handler should be registered
        let channels = await provider.getRegisteredChannels()
        let dataCount = channels.filter { $0 == "tunnel-data" }.count
        XCTAssertEqual(dataCount, 1)

        await manager.stop()
    }

    func testWireChannelRegisteredForIncomingHandshake() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Simulate incoming session request
        let handshake = SessionHandshake(type: .request, channel: "packet")
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "remote-peer", on: "tunnel-handshake", data: data)

        // Wire channel should be registered for the accepted session's channel
        let channels = await provider.getRegisteredChannels()
        XCTAssertTrue(channels.contains("tunnel-packet"))

        await manager.stop()
    }

    func testDispatchUpdatesSessionStats() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        let session = try await manager.getSession(machineId: "machine-1", channel: "data")
        await session.onReceive { _ in }

        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: Data([1, 2, 3]))
        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: Data([4, 5]))

        let stats = await session.stats
        XCTAssertEqual(stats.packetsReceived, 2)
        XCTAssertEqual(stats.bytesReceived, 5)

        await manager.stop()
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
        XCTAssertNotNil(TunnelError.sessionLimitReached.errorDescription)
    }

    func testTunnelManagerConfigDefaults() {
        let config = TunnelManagerConfig.default
        XCTAssertEqual(config.maxSessionsPerMachine, 10)
        XCTAssertEqual(config.maxTotalSessions, 1000)
    }

    func testTunnelManagerConfigCustom() {
        let config = TunnelManagerConfig(maxSessionsPerMachine: 5, maxTotalSessions: 50)
        XCTAssertEqual(config.maxSessionsPerMachine, 5)
        XCTAssertEqual(config.maxTotalSessions, 50)
    }
}
