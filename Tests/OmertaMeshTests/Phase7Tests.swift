// Phase7Tests.swift - Tests for Phase 7: Public API and Integration

import XCTest
@testable import OmertaMesh

final class Phase7Tests: XCTestCase {

    /// Test encryption key used throughout tests
    private var testKey: Data {
        Data(repeating: 0x42, count: 32)
    }

    // MARK: - MeshConfig Tests

    func testDefaultConfig() throws {
        let config = MeshConfig(encryptionKey: testKey)

        XCTAssertEqual(config.port, 0)
        XCTAssertFalse(config.canRelay)
        XCTAssertFalse(config.canCoordinateHolePunch)
        XCTAssertEqual(config.targetRelayCount, 3)
        XCTAssertEqual(config.maxRelayCount, 5)
        XCTAssertEqual(config.keepaliveInterval, 15)
        XCTAssertEqual(config.connectionTimeout, 10)
    }

    func testRelayNodeConfig() throws {
        let config = MeshConfig.relayNode(encryptionKey: testKey)

        XCTAssertTrue(config.canRelay)
        XCTAssertTrue(config.canCoordinateHolePunch)
        XCTAssertEqual(config.targetRelayCount, 0)
        XCTAssertEqual(config.maxRelayCount, 0)
        XCTAssertEqual(config.maxRelaySessions, 100)
    }

    func testServerConfig() throws {
        let config = MeshConfig.server(encryptionKey: testKey)

        XCTAssertTrue(config.canRelay)
        XCTAssertTrue(config.canCoordinateHolePunch)
        XCTAssertEqual(config.targetRelayCount, 5)
        XCTAssertEqual(config.maxRelayCount, 10)
        XCTAssertEqual(config.maxCachedPeers, 1000)
    }

    func testConfigValidation() throws {
        // Valid config should pass
        var config = MeshConfig(encryptionKey: testKey)
        XCTAssertNoThrow(try config.validate())

        // Invalid port
        config.port = 70000
        XCTAssertThrowsError(try config.validate())

        // Fix port, invalid relay counts
        config.port = 8080
        config.targetRelayCount = 10
        config.maxRelayCount = 5
        XCTAssertThrowsError(try config.validate())

        // Fix relay counts - config should now be valid
        config.targetRelayCount = 3
        config.maxRelayCount = 5
        XCTAssertNoThrow(try config.validate())
    }

    func testConfigBuilder() throws {
        let config = try MeshConfig.builder(encryptionKey: testKey)
            .port(8080)
            .canRelay(true)
            .keepaliveInterval(30)
            .bootstrapPeers(["peer1@localhost:9000"])
            .build()

        XCTAssertEqual(config.port, 8080)
        XCTAssertTrue(config.canRelay)
        XCTAssertEqual(config.keepaliveInterval, 30)
        XCTAssertEqual(config.bootstrapPeers.count, 1)
    }

    // MARK: - MeshError Tests

    func testMeshErrorDescription() {
        let peerNotFound = MeshError.peerNotFound(peerId: "test-peer")
        XCTAssertTrue(peerNotFound.description.contains("test-peer"))

        let timeout = MeshError.timeout(operation: "connect")
        XCTAssertTrue(timeout.description.contains("connect"))

        let holePunchFailed = MeshError.holePunchFailed(peerId: "peer", reason: "timeout")
        XCTAssertTrue(holePunchFailed.description.contains("peer"))
        XCTAssertTrue(holePunchFailed.description.contains("timeout"))
    }

    func testMeshErrorRecoverable() {
        XCTAssertTrue(MeshError.timeout(operation: "test").isRecoverable)
        XCTAssertTrue(MeshError.connectionFailed(peerId: "p", reason: "r").isRecoverable)
        XCTAssertTrue(MeshError.noRelaysAvailable.isRecoverable)

        XCTAssertFalse(MeshError.notStarted.isRecoverable)
        XCTAssertFalse(MeshError.alreadyStarted.isRecoverable)
        XCTAssertFalse(MeshError.invalidConfiguration(reason: "bad").isRecoverable)
    }

    func testMeshErrorShouldRetry() {
        XCTAssertTrue(MeshError.timeout(operation: "test").shouldRetry)
        XCTAssertTrue(MeshError.connectionFailed(peerId: "p", reason: "r").shouldRetry)
        XCTAssertTrue(MeshError.sendFailed(reason: "network").shouldRetry)

        XCTAssertFalse(MeshError.notStarted.shouldRetry)
        XCTAssertFalse(MeshError.peerNotFound(peerId: "p").shouldRetry)
    }

    // MARK: - MeshEvent Tests

    func testMeshEventDescription() {
        let started = MeshEvent.started(localPeerId: "test-peer")
        XCTAssertTrue(started.description.contains("test-peer"))

        let natDetected = MeshEvent.natDetected(type: .portRestrictedCone, publicEndpoint: "1.2.3.4:5000")
        XCTAssertTrue(natDetected.description.contains("portRestrictedCone"))
        XCTAssertTrue(natDetected.description.contains("1.2.3.4:5000"))

        let peerConnected = MeshEvent.peerConnected(peerId: "peer", endpoint: "127.0.0.1:8000", isDirect: true)
        XCTAssertTrue(peerConnected.description.contains("peer"))
        XCTAssertTrue(peerConnected.description.contains("direct: true"))
    }

    func testDisconnectReasonDescription() {
        XCTAssertEqual(DisconnectReason.peerClosed.description, "Peer closed connection")
        XCTAssertEqual(DisconnectReason.timeout.description, "Connection timed out")
        XCTAssertTrue(DisconnectReason.networkError("test").description.contains("test"))
    }

    // MARK: - MeshEventPublisher Tests

    func testEventPublisher() async {
        let publisher = MeshEventPublisher()

        // Subscribe
        let stream = await publisher.subscribe()
        let count1 = await publisher.subscriberCount
        XCTAssertEqual(count1, 1)

        // Publish event
        await publisher.publish(.stopped)

        // Check we receive it
        var iterator = stream.makeAsyncIterator()
        let event = await iterator.next()
        XCTAssertNotNil(event)
        if case .stopped = event {
            // Expected
        } else {
            XCTFail("Unexpected event: \(String(describing: event))")
        }

        // Finish
        await publisher.finish()
    }

    func testEventPublisherMultipleSubscribers() async {
        let publisher = MeshEventPublisher()

        let stream1 = await publisher.subscribe()
        let stream2 = await publisher.subscribe()

        let count2 = await publisher.subscriberCount
        XCTAssertEqual(count2, 2)

        await publisher.publish(.stopped)

        // Both should receive
        var iter1 = stream1.makeAsyncIterator()
        var iter2 = stream2.makeAsyncIterator()

        let event1 = await iter1.next()
        let event2 = await iter2.next()

        XCTAssertNotNil(event1)
        XCTAssertNotNil(event2)

        await publisher.finish()
    }

    // MARK: - DirectConnection Tests

    func testDirectConnectionCreation() {
        let connection = DirectConnection(
            peerId: "test-peer",
            endpoint: "192.168.1.1:8080",
            isDirect: true,
            natType: .portRestrictedCone,
            rttMs: 45.5,
            method: .holePunch
        )

        XCTAssertEqual(connection.peerId, "test-peer")
        XCTAssertEqual(connection.endpoint, "192.168.1.1:8080")
        XCTAssertTrue(connection.isDirect)
        XCTAssertNil(connection.relayPeerId)
        XCTAssertEqual(connection.natType, .portRestrictedCone)
        XCTAssertEqual(connection.rttMs, 45.5)
        XCTAssertEqual(connection.method, .holePunch)
    }

    func testDirectConnectionQuality() {
        // Excellent RTT
        let excellent = DirectConnection(
            peerId: "p", endpoint: "e", isDirect: true, rttMs: 30
        )
        XCTAssertEqual(excellent.quality, .excellent)

        // Good RTT
        let good = DirectConnection(
            peerId: "p", endpoint: "e", isDirect: true, rttMs: 75
        )
        XCTAssertEqual(good.quality, .good)

        // Fair RTT
        let fair = DirectConnection(
            peerId: "p", endpoint: "e", isDirect: true, rttMs: 150
        )
        XCTAssertEqual(fair.quality, .fair)

        // Poor RTT
        let poor = DirectConnection(
            peerId: "p", endpoint: "e", isDirect: true, rttMs: 300
        )
        XCTAssertEqual(poor.quality, .poor)

        // Relayed
        let relayed = DirectConnection(
            peerId: "p", endpoint: "e", isDirect: false, relayPeerId: "relay", rttMs: 50
        )
        XCTAssertEqual(relayed.quality, .relayed)
    }

    func testDirectConnectionHostPort() {
        let connection = DirectConnection(
            peerId: "p", endpoint: "192.168.1.1:8080", isDirect: true
        )

        XCTAssertEqual(connection.host, "192.168.1.1")
        XCTAssertEqual(connection.port, 8080)
    }

    func testDirectConnectionWireGuardConfig() {
        let connection = DirectConnection(
            peerId: "test-peer-public-key",
            endpoint: "1.2.3.4:51820",
            isDirect: true
        )

        let config = connection.wireGuardPeerConfig()
        XCTAssertTrue(config.contains("PublicKey = test-peer-public-key"))
        XCTAssertTrue(config.contains("Endpoint = 1.2.3.4:51820"))
        XCTAssertTrue(config.contains("AllowedIPs"))
    }

    func testDirectConnectionStale() {
        var connection = DirectConnection(
            peerId: "p", endpoint: "e", isDirect: true,
            establishedAt: Date(),
            lastCommunication: Date()
        )

        // Fresh connection
        XCTAssertFalse(connection.isStale(threshold: 300))

        // Stale connection
        connection = DirectConnection(
            peerId: "p", endpoint: "e", isDirect: true,
            establishedAt: Date().addingTimeInterval(-600),
            lastCommunication: Date().addingTimeInterval(-400)
        )
        XCTAssertTrue(connection.isStale(threshold: 300))
    }

    // MARK: - DirectConnectionTracker Tests

    func testConnectionTracker() async {
        let tracker = DirectConnectionTracker()

        let connection = DirectConnection(
            peerId: "peer1",
            endpoint: "1.2.3.4:8080",
            isDirect: true
        )

        await tracker.setConnection(connection)

        // Get connection
        let retrieved = await tracker.getConnection(for: "peer1")
        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.endpoint, "1.2.3.4:8080")

        // Count
        let count = await tracker.count
        XCTAssertEqual(count, 1)

        // Remove
        await tracker.removeConnection(for: "peer1")
        let removed = await tracker.getConnection(for: "peer1")
        XCTAssertNil(removed)
    }

    func testConnectionTrackerDirectVsRelayed() async {
        let tracker = DirectConnectionTracker()

        let direct = DirectConnection(
            peerId: "peer1", endpoint: "1.1.1.1:8080", isDirect: true
        )
        let relayed = DirectConnection(
            peerId: "peer2", endpoint: "2.2.2.2:8080", isDirect: false, relayPeerId: "relay"
        )

        await tracker.setConnection(direct)
        await tracker.setConnection(relayed)

        let directConns = await tracker.directConnections
        let relayedConns = await tracker.relayedConnections

        XCTAssertEqual(directConns.count, 1)
        XCTAssertEqual(relayedConns.count, 1)
        XCTAssertEqual(directConns[0].peerId, "peer1")
        XCTAssertEqual(relayedConns[0].peerId, "peer2")
    }

    func testConnectionTrackerState() async {
        let tracker = DirectConnectionTracker()

        let connection = DirectConnection(
            peerId: "peer1", endpoint: "1.2.3.4:8080", isDirect: true
        )
        await tracker.setConnection(connection)

        // Default state is connected
        let state1 = await tracker.getState(for: "peer1")
        XCTAssertEqual(state1, .connected)

        // Update state
        await tracker.setState(.degraded, for: "peer1")
        let state2 = await tracker.getState(for: "peer1")
        XCTAssertEqual(state2, .degraded)

        // Active connections includes both connected and degraded
        let active = await tracker.activeConnections
        XCTAssertEqual(active.count, 1)

        // Failed state removes from active
        await tracker.setState(.failed(reason: "test"), for: "peer1")
        let active2 = await tracker.activeConnections
        XCTAssertEqual(active2.count, 0)
    }

    // MARK: - ConnectionQuality Tests

    func testConnectionQualityComparable() {
        XCTAssertTrue(ConnectionQuality.unknown < ConnectionQuality.relayed)
        XCTAssertTrue(ConnectionQuality.relayed < ConnectionQuality.poor)
        XCTAssertTrue(ConnectionQuality.poor < ConnectionQuality.fair)
        XCTAssertTrue(ConnectionQuality.fair < ConnectionQuality.good)
        XCTAssertTrue(ConnectionQuality.good < ConnectionQuality.excellent)
    }

    // MARK: - ConnectionMethod Tests

    func testConnectionMethodAllCases() {
        let allMethods = ConnectionMethod.allCases
        XCTAssertEqual(allMethods.count, 5)
        XCTAssertTrue(allMethods.contains(.bootstrap))
        XCTAssertTrue(allMethods.contains(.discovery))
        XCTAssertTrue(allMethods.contains(.holePunch))
        XCTAssertTrue(allMethods.contains(.relay))
        XCTAssertTrue(allMethods.contains(.manual))
    }

    // MARK: - DirectConnectionState Tests

    func testDirectConnectionStateIsActive() {
        XCTAssertTrue(DirectConnectionState.connected.isActive)
        XCTAssertTrue(DirectConnectionState.degraded.isActive)

        XCTAssertFalse(DirectConnectionState.connecting.isActive)
        XCTAssertFalse(DirectConnectionState.reconnecting.isActive)
        XCTAssertFalse(DirectConnectionState.failed(reason: "test").isActive)
        XCTAssertFalse(DirectConnectionState.closed.isActive)
    }

    // MARK: - MeshNode.Config Tests

    func testMeshNodeConfig() {
        let config = MeshNode.Config(
            encryptionKey: testKey,
            port: 8080,
            targetRelays: 5,
            maxRelays: 10,
            canRelay: true,
            canCoordinateHolePunch: true
        )

        XCTAssertEqual(config.port, 8080)
        XCTAssertEqual(config.targetRelays, 5)
        XCTAssertEqual(config.maxRelays, 10)
        XCTAssertTrue(config.canRelay)
        XCTAssertTrue(config.canCoordinateHolePunch)
    }

    func testMeshNodeConfigDefaults() {
        let config = MeshNode.Config(encryptionKey: testKey)

        XCTAssertEqual(config.port, 0)
        XCTAssertEqual(config.targetRelays, 3)
        XCTAssertEqual(config.maxRelays, 5)
        XCTAssertFalse(config.canRelay)
        XCTAssertFalse(config.canCoordinateHolePunch)
    }

    // MARK: - MeshNode.CachedPeerInfo Tests

    func testCachedPeerInfo() {
        let info = MeshNode.CachedPeerInfo(
            peerId: "peer1",
            endpoint: "1.2.3.4:8080",
            natType: .portRestrictedCone
        )

        XCTAssertEqual(info.peerId, "peer1")
        XCTAssertEqual(info.endpoint, "1.2.3.4:8080")
        XCTAssertEqual(info.natType, .portRestrictedCone)
    }

    // MARK: - MeshStatistics Tests

    func testMeshStatistics() {
        let stats = MeshStatistics(
            peerCount: 10,
            connectionCount: 5,
            directConnectionCount: 3,
            relayCount: 2,
            natType: .portRestrictedCone,
            publicEndpoint: "1.2.3.4:8080",
            uptime: 3600
        )

        XCTAssertEqual(stats.peerCount, 10)
        XCTAssertEqual(stats.connectionCount, 5)
        XCTAssertEqual(stats.directConnectionCount, 3)
        XCTAssertEqual(stats.relayCount, 2)
        XCTAssertEqual(stats.natType, .portRestrictedCone)
        XCTAssertEqual(stats.publicEndpoint, "1.2.3.4:8080")
        XCTAssertEqual(stats.uptime, 3600)
    }

    func testMeshStatisticsDefaults() {
        let stats = MeshStatistics()

        XCTAssertEqual(stats.peerCount, 0)
        XCTAssertEqual(stats.connectionCount, 0)
        XCTAssertEqual(stats.natType, .unknown)
        XCTAssertNil(stats.publicEndpoint)
    }

    // MARK: - MeshNetworkState Tests

    func testMeshNetworkStateIsActive() {
        XCTAssertTrue(MeshNetworkState.running.isActive)

        XCTAssertFalse(MeshNetworkState.stopped.isActive)
        XCTAssertFalse(MeshNetworkState.starting.isActive)
        XCTAssertFalse(MeshNetworkState.detectingNAT.isActive)
        XCTAssertFalse(MeshNetworkState.bootstrapping.isActive)
        XCTAssertFalse(MeshNetworkState.stopping.isActive)
    }

    // MARK: - MeshNetwork Creation Tests

    /// Test key for all tests
    private var testEncryptionKey: Data {
        Data(repeating: 0x42, count: 32)
    }

    func testMeshNetworkCreation() async {
        let identity = IdentityKeypair()
        let config = MeshConfig(encryptionKey: testEncryptionKey)
        let network = MeshNetwork(identity: identity, config: config)
        let state = await network.state
        XCTAssertEqual(state, .stopped)
        // Verify peer ID is 16 hex chars (SHA256-based)
        let peerId = await network.peerId
        XCTAssertEqual(peerId.count, 16)
        XCTAssertTrue(peerId.allSatisfy { $0.isHexDigit })
    }

    func testMeshNetworkCreateConvenience() async {
        let config = MeshConfig(encryptionKey: testEncryptionKey)
        let network = MeshNetwork.create(config: config)
        let state = await network.state
        XCTAssertEqual(state, .stopped)
    }

    func testMeshNetworkCreateRelay() async {
        let identity = IdentityKeypair()
        let network = MeshNetwork.createRelay(identity: identity, encryptionKey: testEncryptionKey, port: 8080)
        let config = await network.config
        XCTAssertTrue(config.canRelay)
        XCTAssertTrue(config.canCoordinateHolePunch)
        XCTAssertEqual(config.port, 8080)
    }

    func testMeshNetworkCreateServer() async {
        let identity = IdentityKeypair()
        let network = MeshNetwork.createServer(identity: identity, encryptionKey: testEncryptionKey, port: 9000)
        let config = await network.config
        XCTAssertTrue(config.canRelay)
        XCTAssertTrue(config.canCoordinateHolePunch)
        XCTAssertEqual(config.port, 9000)
    }

    // MARK: - MeshError to MeshNodeError Conversion Tests

    func testMeshNodeErrorConversion() {
        let stopped = MeshNodeError.stopped.asMeshError
        if case .notStarted = stopped {
            // Expected
        } else {
            XCTFail("Expected .notStarted")
        }

        let timeout = MeshNodeError.timeout.asMeshError
        if case .timeout = timeout {
            // Expected
        } else {
            XCTFail("Expected .timeout")
        }
    }

    // MARK: - HolePunchFailure to MeshError Conversion Tests

    func testHolePunchFailureConversion() {
        let peerId = "test-peer"

        let timeout = HolePunchFailure.timeout.asMeshError(for: peerId)
        if case .holePunchFailed(let p, let r) = timeout {
            XCTAssertEqual(p, peerId)
            XCTAssertTrue(r.contains("timeout"))
        } else {
            XCTFail("Expected .holePunchFailed")
        }

        let bothSymmetric = HolePunchFailure.bothSymmetric.asMeshError(for: peerId)
        if case .holePunchImpossible(let p) = bothSymmetric {
            XCTAssertEqual(p, peerId)
        } else {
            XCTFail("Expected .holePunchImpossible")
        }
    }
}
