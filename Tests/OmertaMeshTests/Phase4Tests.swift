// Phase4Tests.swift - Tests for Relay Infrastructure (Phase 4)

import XCTest
import Foundation
@testable import OmertaMesh

final class Phase4Tests: XCTestCase {

    // MARK: - RelaySession Tests

    /// Test session lifecycle states
    func testRelaySessionLifecycle() async throws {
        let session = RelaySession(
            sessionId: "test-session-1",
            localPeerId: "local-peer",
            remotePeerId: "remote-peer",
            relayPeerId: "relay-peer"
        )

        // Initial state is pending
        let initialState = await session.state
        XCTAssertEqual(initialState, .pending)

        // Activate
        await session.activate()
        let activeState = await session.state
        XCTAssertEqual(activeState, .active)
        let isActive = await session.isActive
        XCTAssertTrue(isActive)

        // Begin closing
        await session.beginClosing()
        let closingState = await session.state
        XCTAssertEqual(closingState, .closing)

        // Close
        await session.close()
        let closedState = await session.state
        XCTAssertEqual(closedState, .closed)
    }

    /// Test session data tracking
    func testRelaySessionDataTracking() async throws {
        let session = RelaySession(
            sessionId: "test-session-2",
            localPeerId: "local-peer",
            remotePeerId: "remote-peer",
            relayPeerId: "relay-peer"
        )

        await session.activate()

        // Record outgoing data
        let outData = Data(repeating: 0x55, count: 100)
        await session.recordOutgoingData(outData)

        let bytesSent = await session.bytesSent
        XCTAssertEqual(bytesSent, 100)

        // Handle incoming data
        let inData = Data(repeating: 0xAA, count: 200)
        await session.handleIncomingData(inData)

        let bytesReceived = await session.bytesReceived
        XCTAssertEqual(bytesReceived, 200)
    }

    /// Test session metrics
    func testRelaySessionMetrics() async throws {
        let session = RelaySession(
            sessionId: "metrics-session",
            localPeerId: "local-peer",
            remotePeerId: "remote-peer",
            relayPeerId: "relay-peer"
        )

        await session.activate()

        let data = Data(repeating: 0x11, count: 50)
        await session.recordOutgoingData(data)
        await session.handleIncomingData(data)

        let metrics = await session.metrics
        XCTAssertEqual(metrics.sessionId, "metrics-session")
        XCTAssertEqual(metrics.localPeerId, "local-peer")
        XCTAssertEqual(metrics.remotePeerId, "remote-peer")
        XCTAssertEqual(metrics.relayPeerId, "relay-peer")
        XCTAssertEqual(metrics.state, .active)
        XCTAssertEqual(metrics.bytesSent, 50)
        XCTAssertEqual(metrics.bytesReceived, 50)
        XCTAssertGreaterThan(metrics.duration, 0)
    }

    /// Test session ignores data when not active
    func testRelaySessionIgnoresDataWhenInactive() async throws {
        let session = RelaySession(
            sessionId: "inactive-session",
            localPeerId: "local-peer",
            remotePeerId: "remote-peer",
            relayPeerId: "relay-peer"
        )

        // Still pending, not active
        let data = Data(repeating: 0x22, count: 100)
        await session.handleIncomingData(data)

        let bytesReceived = await session.bytesReceived
        XCTAssertEqual(bytesReceived, 0, "Should not record data when not active")
    }

    /// Test session data handler callback
    func testRelaySessionDataHandler() async throws {
        let session = RelaySession(
            sessionId: "handler-session",
            localPeerId: "local-peer",
            remotePeerId: "remote-peer",
            relayPeerId: "relay-peer"
        )

        await session.activate()

        var receivedData: Data?
        await session.onData { data in
            receivedData = data
        }

        let testData = Data([0x01, 0x02, 0x03, 0x04])
        await session.handleIncomingData(testData)

        XCTAssertNotNil(receivedData)
        XCTAssertEqual(receivedData, testData)
    }

    // MARK: - RelaySessionManager Tests

    /// Test session creation
    func testSessionManagerCreateSession() async throws {
        let manager = RelaySessionManager(maxSessions: 10)

        let session = try await manager.createSession(
            sessionId: "session-1",
            localPeerId: "local",
            remotePeerId: "remote",
            relayPeerId: "relay"
        )

        // sessionId is a let constant on an actor, access it via await
        let sessionId = await session.sessionId
        XCTAssertEqual(sessionId, "session-1")
        let count = await manager.activeCount
        XCTAssertEqual(count, 1)
    }

    /// Test session retrieval
    func testSessionManagerGetSession() async throws {
        let manager = RelaySessionManager(maxSessions: 10)

        _ = try await manager.createSession(
            sessionId: "session-get",
            localPeerId: "local",
            remotePeerId: "remote",
            relayPeerId: "relay"
        )

        let retrieved = await manager.getSession("session-get")
        XCTAssertNotNil(retrieved)
        if let retrieved = retrieved {
            let sessionId = await retrieved.sessionId
            XCTAssertEqual(sessionId, "session-get")
        }

        let notFound = await manager.getSession("nonexistent")
        XCTAssertNil(notFound)
    }

    /// Test session removal
    func testSessionManagerRemoveSession() async throws {
        let manager = RelaySessionManager(maxSessions: 10)

        _ = try await manager.createSession(
            sessionId: "session-remove",
            localPeerId: "local",
            remotePeerId: "remote",
            relayPeerId: "relay"
        )

        var count = await manager.activeCount
        XCTAssertEqual(count, 1)

        await manager.removeSession("session-remove")

        count = await manager.activeCount
        XCTAssertEqual(count, 0)

        let removed = await manager.getSession("session-remove")
        XCTAssertNil(removed)
    }

    /// Test session capacity limit
    func testSessionManagerCapacityLimit() async throws {
        let manager = RelaySessionManager(maxSessions: 2)

        _ = try await manager.createSession(
            sessionId: "session-a",
            localPeerId: "local",
            remotePeerId: "remote-a",
            relayPeerId: "relay"
        )

        _ = try await manager.createSession(
            sessionId: "session-b",
            localPeerId: "local",
            remotePeerId: "remote-b",
            relayPeerId: "relay"
        )

        // Third session should fail
        do {
            _ = try await manager.createSession(
                sessionId: "session-c",
                localPeerId: "local",
                remotePeerId: "remote-c",
                relayPeerId: "relay"
            )
            XCTFail("Should throw atCapacity error")
        } catch let error as RelayError {
            if case .atCapacity = error {
                // Expected
            } else {
                XCTFail("Wrong error type: \(error)")
            }
        }
    }

    /// Test sessions lookup by peer
    func testSessionManagerSessionsByPeer() async throws {
        let manager = RelaySessionManager(maxSessions: 10)

        _ = try await manager.createSession(
            sessionId: "s1",
            localPeerId: "peer-a",
            remotePeerId: "peer-b",
            relayPeerId: "relay-1"
        )

        _ = try await manager.createSession(
            sessionId: "s2",
            localPeerId: "peer-a",
            remotePeerId: "peer-c",
            relayPeerId: "relay-1"
        )

        _ = try await manager.createSession(
            sessionId: "s3",
            localPeerId: "peer-d",
            remotePeerId: "peer-e",
            relayPeerId: "relay-2"
        )

        let peerASessions = await manager.sessions(withPeer: "peer-a")
        XCTAssertEqual(peerASessions.count, 2)

        let relay1Sessions = await manager.sessions(viaRelay: "relay-1")
        XCTAssertEqual(relay1Sessions.count, 2)

        let relay2Sessions = await manager.sessions(viaRelay: "relay-2")
        XCTAssertEqual(relay2Sessions.count, 1)
    }

    /// Test all sessions retrieval
    func testSessionManagerAllSessions() async throws {
        let manager = RelaySessionManager(maxSessions: 10)

        for i in 1...5 {
            _ = try await manager.createSession(
                sessionId: "all-\(i)",
                localPeerId: "local",
                remotePeerId: "remote-\(i)",
                relayPeerId: "relay"
            )
        }

        let allSessions = await manager.allSessions
        XCTAssertEqual(allSessions.count, 5)
    }

    // MARK: - RelayCandidate Tests

    /// Test relay candidate scoring
    func testRelayCandidateScoring() {
        // High RTT candidate should score lower
        let highRTT = RelayCandidate(
            peerId: "high-rtt",
            endpoint: "1.2.3.4:5000",
            rtt: 0.5,  // 500ms
            availableCapacity: 50,
            isDirect: false,
            natType: .unknown
        )

        // Low RTT candidate should score higher
        let lowRTT = RelayCandidate(
            peerId: "low-rtt",
            endpoint: "5.6.7.8:5000",
            rtt: 0.05,  // 50ms
            availableCapacity: 50,
            isDirect: false,
            natType: .unknown
        )

        XCTAssertGreaterThan(lowRTT.score, highRTT.score)
    }

    /// Test direct connectivity bonus in scoring
    func testRelayCandidateDirectBonus() {
        let indirect = RelayCandidate(
            peerId: "indirect",
            endpoint: "1.2.3.4:5000",
            rtt: 0.1,
            availableCapacity: 50,
            isDirect: false,
            natType: .unknown
        )

        let direct = RelayCandidate(
            peerId: "direct",
            endpoint: "5.6.7.8:5000",
            rtt: 0.1,  // Same RTT
            availableCapacity: 50,
            isDirect: true,
            natType: .unknown
        )

        XCTAssertGreaterThan(direct.score, indirect.score)
    }

    /// Test NAT type bonus in scoring
    func testRelayCandidateNATTypeBonus() {
        let symmetric = RelayCandidate(
            peerId: "symmetric",
            endpoint: "1.2.3.4:5000",
            rtt: 0.1,
            availableCapacity: 50,
            isDirect: false,
            natType: .symmetric
        )

        let publicNAT = RelayCandidate(
            peerId: "public",
            endpoint: "5.6.7.8:5000",
            rtt: 0.1,  // Same RTT
            availableCapacity: 50,
            isDirect: false,
            natType: .public
        )

        let fullCone = RelayCandidate(
            peerId: "fullcone",
            endpoint: "9.10.11.12:5000",
            rtt: 0.1,  // Same RTT
            availableCapacity: 50,
            isDirect: false,
            natType: .fullCone
        )

        XCTAssertGreaterThan(publicNAT.score, fullCone.score)
        XCTAssertGreaterThan(fullCone.score, symmetric.score)
    }

    /// Test capacity affects scoring
    func testRelayCandidateCapacityBonus() {
        let lowCapacity = RelayCandidate(
            peerId: "low-cap",
            endpoint: "1.2.3.4:5000",
            rtt: 0.1,
            availableCapacity: 10,
            isDirect: false,
            natType: .unknown
        )

        let highCapacity = RelayCandidate(
            peerId: "high-cap",
            endpoint: "5.6.7.8:5000",
            rtt: 0.1,  // Same RTT
            availableCapacity: 100,
            isDirect: false,
            natType: .unknown
        )

        XCTAssertGreaterThan(highCapacity.score, lowCapacity.score)
    }

    // MARK: - RelaySelectionCriteria Tests

    /// Test default criteria values
    func testRelaySelectionCriteriaDefaults() {
        let criteria = RelaySelectionCriteria.default

        XCTAssertEqual(criteria.maxRTT, 0.5)
        XCTAssertEqual(criteria.minCapacity, 10)
        XCTAssertTrue(criteria.preferDirect)
        XCTAssertEqual(criteria.count, 3)
    }

    /// Test custom criteria
    func testRelaySelectionCriteriaCustom() {
        let criteria = RelaySelectionCriteria(
            maxRTT: 0.2,
            minCapacity: 50,
            preferDirect: false,
            count: 5
        )

        XCTAssertEqual(criteria.maxRTT, 0.2)
        XCTAssertEqual(criteria.minCapacity, 50)
        XCTAssertFalse(criteria.preferDirect)
        XCTAssertEqual(criteria.count, 5)
    }

    // MARK: - RelayConnectionState Tests

    /// Test connection state equality
    func testRelayConnectionStateEquality() {
        XCTAssertEqual(RelayConnectionState.disconnected, RelayConnectionState.disconnected)
        XCTAssertEqual(RelayConnectionState.connecting, RelayConnectionState.connecting)
        XCTAssertEqual(RelayConnectionState.connected, RelayConnectionState.connected)
        XCTAssertEqual(RelayConnectionState.failed("error"), RelayConnectionState.failed("error"))
        XCTAssertNotEqual(RelayConnectionState.failed("error1"), RelayConnectionState.failed("error2"))
        XCTAssertNotEqual(RelayConnectionState.disconnected, RelayConnectionState.connected)
    }

    // MARK: - RelayError Tests

    /// Test error descriptions
    func testRelayErrorDescriptions() {
        XCTAssertEqual(RelayError.notConnected.description, "Not connected to relay")
        XCTAssertEqual(RelayError.unexpectedResponse.description, "Unexpected response from relay")
        XCTAssertEqual(RelayError.atCapacity.description, "Relay at capacity")
        XCTAssertEqual(RelayError.denied("test reason").description, "Relay denied request: test reason")
        XCTAssertEqual(RelayError.sessionIdMismatch.description, "Session ID mismatch")
        XCTAssertEqual(RelayError.sessionNotFound.description, "Session not found")
        XCTAssertEqual(RelayError.timeout.description, "Relay request timed out")
    }

    // MARK: - RelaySessionState Tests

    /// Test session state equality
    func testRelaySessionStateEquality() {
        XCTAssertEqual(RelaySessionState.pending, RelaySessionState.pending)
        XCTAssertEqual(RelaySessionState.active, RelaySessionState.active)
        XCTAssertEqual(RelaySessionState.closing, RelaySessionState.closing)
        XCTAssertEqual(RelaySessionState.closed, RelaySessionState.closed)
        XCTAssertNotEqual(RelaySessionState.pending, RelaySessionState.active)
    }

    // MARK: - RelayManagerConfig Tests

    /// Test config defaults
    func testRelayManagerConfigDefaults() {
        let config = RelayManagerConfig()

        XCTAssertEqual(config.minRelays, 3)
        XCTAssertEqual(config.maxRelays, 5)
        XCTAssertEqual(config.healthCheckInterval, 30.0)
        XCTAssertEqual(config.maxTotalSessions, 50)
    }

    /// Test custom config
    func testRelayManagerConfigCustom() {
        let config = RelayManagerConfig(
            minRelays: 2,
            maxRelays: 10,
            healthCheckInterval: 60.0,
            maxTotalSessions: 100
        )

        XCTAssertEqual(config.minRelays, 2)
        XCTAssertEqual(config.maxRelays, 10)
        XCTAssertEqual(config.healthCheckInterval, 60.0)
        XCTAssertEqual(config.maxTotalSessions, 100)
    }

    // MARK: - RelayConnection Metrics Tests

    /// Test connection metrics structure
    func testRelayConnectionMetricsStructure() {
        let metrics = RelayConnectionMetrics(
            relayPeerId: "relay-peer",
            endpoint: "1.2.3.4:5000",
            state: .connected,
            rtt: 0.05,
            activeSessions: 3,
            lastHeartbeat: Date()
        )

        XCTAssertEqual(metrics.relayPeerId, "relay-peer")
        XCTAssertEqual(metrics.endpoint, "1.2.3.4:5000")
        XCTAssertEqual(metrics.state, .connected)
        XCTAssertEqual(metrics.rtt, 0.05)
        XCTAssertEqual(metrics.activeSessions, 3)
        XCTAssertNotNil(metrics.lastHeartbeat)
    }

    // MARK: - Session Idle Tests

    /// Test session idle detection
    func testSessionIdleDetection() async throws {
        let session = RelaySession(
            sessionId: "idle-test",
            localPeerId: "local",
            remotePeerId: "remote",
            relayPeerId: "relay"
        )

        await session.activate()

        // Just activated, should not be idle
        let isIdle = await session.isIdle
        XCTAssertFalse(isIdle, "Freshly activated session should not be idle")
    }

    /// Test session duration tracking
    func testSessionDurationTracking() async throws {
        let session = RelaySession(
            sessionId: "duration-test",
            localPeerId: "local",
            remotePeerId: "remote",
            relayPeerId: "relay"
        )

        await session.activate()

        // Wait a tiny bit
        try await Task.sleep(nanoseconds: 10_000_000)  // 10ms

        let duration = await session.duration
        XCTAssertGreaterThan(duration, 0)
    }
}
