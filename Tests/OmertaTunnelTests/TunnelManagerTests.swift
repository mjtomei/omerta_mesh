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
    private(set) var sendToEndpointCalls: [(endpoint: String, port: UInt16?, machineId: String, channel: String, data: Data)] = []

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        try await onChannel(channel, handler: handler)
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

    func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws {
        try await sendOnChannel(data, to: peerId, channel: channel)
    }

    func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        try await sendOnChannel(data, toMachine: machineId, channel: channel)
    }

    func sendOnChannel(_ data: Data, toEndpoint endpoint: String, viaPort localPort: UInt16?, toMachine machineId: MachineId, channel: String) async throws {
        sendToEndpointCalls.append((endpoint: endpoint, port: localPort, machineId: machineId, channel: channel, data: data))
        sentMessages.append((to: machineId, channel: channel, data: data))
    }

    func flushChannel(_ channel: String) async throws {}

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

        // Verify handshake was sent (filter to handshake channel — health probes may also be sent)
        let handshakeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-handshake" }
        XCTAssertEqual(handshakeMessages.count, 1)
        XCTAssertEqual(handshakeMessages[0].to, "remote-machine-123")

        await manager.stop()
    }

    func testSetInboundSessionHandler() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        var requestReceived = false
        await manager.setInboundSessionHandler { machineId, channel in
            requestReceived = true
            return { _ in }
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

        // Verify close handshake was sent (filter — health probes may also appear)
        let handshakeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-handshake" }
        XCTAssertEqual(handshakeMessages.count, 1)

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

    func testInboundSessionHandlerCallback() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        var handlerCalledWithMachine: MachineId?
        await manager.setInboundSessionHandler { machineId, channel in
            handlerCalledWithMachine = machineId
            return { _ in }
        }

        try await manager.start()

        // Simulate incoming session request
        let handshake = SessionHandshake(type: .request, channel: "data")
        let data = try JSONEncoder().encode(handshake)
        await provider.simulateMessage(from: "remote-initiator", on: "tunnel-handshake", data: data)

        XCTAssertEqual(handlerCalledWithMachine, "remote-initiator")

        // Session should be created
        let count = await manager.sessionCount
        XCTAssertEqual(count, 1)

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

        await manager.setInboundSessionHandler { machineId, channel in
            handlerCalled = true
            receivedMachineId = machineId
            return { _ in }
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
        let count = await manager.sessionCount
        XCTAssertEqual(count, 1)

        // Ack should have been sent (filter to handshake channel — health probes may also be sent)
        let handshakeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-handshake" }
        XCTAssertEqual(handshakeMessages.count, 1)
        XCTAssertEqual(handshakeMessages[0].to, "remote-initiator")

        // Verify it's an ack
        let sentHandshake = try JSONDecoder().decode(SessionHandshake.self, from: handshakeMessages[0].data)
        XCTAssertEqual(sentHandshake.type, .ack)

        await manager.stop()
    }

    func testIncomingSessionRejected() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)

        // Handler rejects the session by returning nil
        await manager.setInboundSessionHandler { _, _ in
            return nil
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

    // MARK: - Health Monitoring Suspend/Resume Tests

    func testSuspendHealthMonitoring() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Create a session — this should start a health monitor
        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        // Suspend health monitoring
        await manager.suspendHealthMonitoring()

        await provider.clearSentMessages()

        // Wait to verify no probes are sent while suspended
        try await Task.sleep(for: .seconds(1.5))
        let probeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-health-probe" }
        XCTAssertEqual(probeMessages.count, 0, "No probes should be sent while monitoring is suspended")

        // Create another session — should NOT start a new monitor
        _ = try await manager.getSession(machineId: "machine-2", channel: "data")
        await provider.clearSentMessages()

        try await Task.sleep(for: .seconds(1.5))
        let probeMessages2 = await provider.getSentMessages().filter { $0.channel == "tunnel-health-probe" }
        XCTAssertEqual(probeMessages2.count, 0, "No probes for new sessions while monitoring is suspended")

        await manager.stop()
    }

    func testResumeHealthMonitoring() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Suspend, then resume
        await manager.suspendHealthMonitoring()
        await manager.resumeHealthMonitoring()

        // Create a session — should start a health monitor since monitoring is resumed
        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        // Wait for a probe
        try await Task.sleep(for: .seconds(1.5))
        let probeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-health-probe" }
        XCTAssertGreaterThan(probeMessages.count, 0, "Probes should resume after resumeHealthMonitoring")

        await manager.stop()
    }

    func testSendProbeToAllEndpoints() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Create a session — manager auto-creates an EndpointSet
        _ = try await manager.getSession(machineId: "machine-1", channel: "data")

        // Add extra endpoints to the session's EndpointSet
        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        if let endpointSet = await manager.getEndpointSet(for: key) {
            await endpointSet.add(address: "primary", localPort: nil)
            await endpointSet.add(address: "10.0.0.2:5000", localPort: nil)
        }

        await provider.clearSentMessages()

        // Wait for a probe cycle
        try await Task.sleep(for: .seconds(1.5))

        // Should have sent probes — at least one on the primary health probe channel
        let probeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-health-probe" }
        XCTAssertGreaterThan(probeMessages.count, 0, "Should have sent at least one health probe")

        // Check if endpoint-specific sends happened (probes to extra endpoints)
        let endpointCalls = await provider.sendToEndpointCalls.filter { $0.channel == "tunnel-health-probe" }
        XCTAssertGreaterThan(endpointCalls.count, 0, "Should have sent probes to extra endpoints")

        await manager.stop()
    }

    func testHandshakeIncludesChannel() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "control")

        // Filter to handshake channel — health probes may also be sent
        let messages = await provider.getSentMessages().filter { $0.channel == "tunnel-handshake" }
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

        // Send a message (sendAndFlush for immediate send)
        try await session.sendAndFlush(Data([1, 2, 3]))

        // Check message was sent
        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].to, "machine-1")
        XCTAssertEqual(messages[0].channel, "tunnel-data")
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

        var receivedData: Data?
        let session = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { data in
            receivedData = data
        })

        // Simulate incoming message — TunnelManager dispatches to the correct session
        // Data must be wrapped in BatchWireFormat since deliverIncoming unpacks it
        await provider.simulateMessage(
            from: "machine-1",
            on: "tunnel-data",
            data: BatchWireFormat.packSingle(Data([1, 2, 3, 4]))
        )

        XCTAssertEqual(receivedData, Data([1, 2, 3, 4]))

        await manager.stop()
    }

    func testReceiveFiltersByMachine() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        var receivedData: Data?
        let session = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { data in
            receivedData = data
        })

        // Simulate message from wrong machine - no session exists for it, so dispatch drops it
        await provider.simulateMessage(
            from: "wrong-machine",
            on: "tunnel-data",
            data: BatchWireFormat.packSingle(Data([9, 9, 9]))
        )

        XCTAssertNil(receivedData)

        // Simulate message from correct machine
        await provider.simulateMessage(
            from: "machine-1",
            on: "tunnel-data",
            data: BatchWireFormat.packSingle(Data([1, 2, 3]))
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

        // Send some data (send() buffers, flush() sends)
        try await session.sendAndFlush(Data(repeating: 0x42, count: 100))
        try await session.sendAndFlush(Data(repeating: 0x43, count: 50))

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
        var received1: Data?
        var received2: Data?
        let session1 = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { data in received1 = data })
        let session2 = try await manager.getSession(machineId: "machine-2", channel: "data", receiveHandler: { data in received2 = data })

        // Send to machine-1's session
        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: BatchWireFormat.packSingle(Data([0xAA])))

        XCTAssertEqual(received1, Data([0xAA]))
        XCTAssertNil(received2)

        // Send to machine-2's session
        await provider.simulateMessage(from: "machine-2", on: "tunnel-data", data: BatchWireFormat.packSingle(Data([0xBB])))

        XCTAssertEqual(received2, Data([0xBB]))
        // machine-1 should still have its original data
        XCTAssertEqual(received1, Data([0xAA]))

        await manager.stop()
    }

    func testDispatchDropsDataForUnknownMachine() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        var receivedData: Data?
        let session = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { data in receivedData = data })

        // Message from unknown machine — should be silently dropped
        await provider.simulateMessage(from: "unknown-machine", on: "tunnel-data", data: BatchWireFormat.packSingle(Data([0xFF])))

        XCTAssertNil(receivedData)

        await manager.stop()
    }

    func testDispatchAfterSessionCloseDropsData() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        var receivedData: Data?
        let session = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { data in receivedData = data })

        // Close the session
        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        await manager.closeSession(key: key)

        // Wire channel still registered, but session removed — data should be dropped
        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: BatchWireFormat.packSingle(Data([0xCC])))

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

        let session = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { _ in })

        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: BatchWireFormat.packSingle(Data([1, 2, 3])))
        await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: BatchWireFormat.packSingle(Data([4, 5])))

        let stats = await session.stats
        XCTAssertEqual(stats.packetsReceived, 2)
        XCTAssertEqual(stats.bytesReceived, 5)

        await manager.stop()
    }
}

// MARK: - Probe / Delivered Stats Tests

final class TunnelProbeTests: XCTestCase {

    func testProbePayloadEncoding() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Create a session and dispatch some data to it
        _ = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { _ in })
        await provider.clearSentMessages()

        // Dispatch data to accumulate receive stats
        for _ in 0..<5 {
            await provider.simulateMessage(from: "machine-1", on: "tunnel-data", data: BatchWireFormat.packSingle(Data(repeating: 0xAA, count: 100)))
        }

        // Wait briefly then trigger a probe by creating a second session to same machine on different channel
        // Instead, just check the probe messages sent so far
        // The health monitor sends probes periodically. Let's wait a bit for one.
        try await Task.sleep(for: .seconds(1))

        // Check probe messages
        let probeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-health-probe" }
        XCTAssertGreaterThan(probeMessages.count, 0, "Expected at least one probe to be sent")

        // Parse the last probe
        let lastProbe = probeMessages.last!.data
        XCTAssertGreaterThanOrEqual(lastProbe.count, 1)

        // First byte is channel count
        let channelCount = Int(lastProbe[0])
        XCTAssertGreaterThanOrEqual(channelCount, 0)
        // If data was accumulated, we should see a channel
        if channelCount > 0 {
            let nameLen = Int(lastProbe[1])
            let nameBytes = lastProbe[2..<(2 + nameLen)]
            let name = String(bytes: nameBytes, encoding: .utf8)
            XCTAssertEqual(name, "data")
        }

        await manager.stop()
    }

    func testProbePayloadDecoding() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        // Create a session so the manager has context
        _ = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { _ in })

        // Build a fake probe payload from "machine-1" reporting stats for channel "data"
        var payload = Data()
        payload.append(1) // 1 channel
        let channelName = "data"
        let nameBytes = Array(channelName.utf8)
        payload.append(UInt8(nameBytes.count))
        payload.append(contentsOf: nameBytes)
        var bps: UInt64 = 50000
        var pps: UInt64 = 100
        payload.append(Data(bytes: &bps, count: 8)) // already LE on LE platforms
        payload.append(Data(bytes: &pps, count: 8))

        // Simulate receiving this probe
        await provider.simulateMessage(from: "machine-1", on: "tunnel-health-probe", data: payload)

        // Check delivered stats
        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        let stats = await manager.deliveredTrafficStats(for: key)
        XCTAssertNotNil(stats)
        XCTAssertEqual(stats?.bytesPerSecond, 50000)
        XCTAssertEqual(stats?.packetsPerSecond, 100)

        await manager.stop()
    }

    func testRoundRobinProbeChannels() async throws {
        let config = TunnelManagerConfig(maxSessionsPerMachine: 20, maxTotalSessions: 100)
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider, config: config)
        try await manager.start()

        // Create 12 sessions to one machine
        for i in 0..<12 {
            _ = try await manager.getSession(machineId: "machine-1", channel: "ch-\(String(format: "%02d", i))", receiveHandler: { _ in })
        }

        // Dispatch data on all channels so accumulators exist
        for i in 0..<12 {
            await provider.simulateMessage(from: "machine-1", on: "tunnel-ch-\(String(format: "%02d", i))", data: BatchWireFormat.packSingle(Data([0x01])))
        }

        await provider.clearSentMessages()

        // Wait for probe
        try await Task.sleep(for: .seconds(1.5))

        let probeMessages = await provider.getSentMessages().filter { $0.channel == "tunnel-health-probe" }
        guard let firstProbe = probeMessages.first else {
            XCTFail("No probe sent")
            return
        }

        let channelCount = Int(firstProbe.data[0])
        XCTAssertLessThanOrEqual(channelCount, 10, "Should include at most 10 channels per probe")

        await manager.stop()
    }

    func testDeliveredStatsCleanedOnClose() async throws {
        let provider = MockChannelProvider()
        let manager = TunnelManager(provider: provider)
        try await manager.start()

        _ = try await manager.getSession(machineId: "machine-1", channel: "data", receiveHandler: { _ in })

        // Simulate a probe with delivered stats
        var payload = Data()
        payload.append(1)
        let nameBytes = Array("data".utf8)
        payload.append(UInt8(nameBytes.count))
        payload.append(contentsOf: nameBytes)
        var bps: UInt64 = 1000
        var pps: UInt64 = 10
        payload.append(Data(bytes: &bps, count: 8))
        payload.append(Data(bytes: &pps, count: 8))
        await provider.simulateMessage(from: "machine-1", on: "tunnel-health-probe", data: payload)

        let key = TunnelSessionKey(remoteMachineId: "machine-1", channel: "data")
        let statsBefore = await manager.deliveredTrafficStats(for: key)
        XCTAssertNotNil(statsBefore)

        // Close the session
        await manager.closeSession(key: key)

        let statsAfter = await manager.deliveredTrafficStats(for: key)
        XCTAssertNil(statsAfter)

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
