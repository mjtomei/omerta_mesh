// GossipTests.swift - Tests for peer gossip protocol
//
// Tests the gossip implementation from docs/protocol/GOSSIP.md:
// - New peer contacted → send ALL known peers
// - Learning new peer → add to propagation queue with fanout
// - Propagation items included in responses, counts decrement

import XCTest
@testable import OmertaMesh

final class GossipTests: XCTestCase {

    // MARK: - Test Fixtures

    /// Create a test encryption key
    private func createTestKey() -> Data {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }

    /// Create a MeshNode for testing
    private func createTestNode(
        canRelay: Bool = false,
        canCoordinateHolePunch: Bool = false
    ) throws -> MeshNode {
        let identity = IdentityKeypair()
        let config = MeshNode.Config(
            encryptionKey: createTestKey(),
            port: 0,
            canRelay: canRelay,
            canCoordinateHolePunch: canCoordinateHolePunch,
            endpointValidationMode: .allowAll  // Allow test endpoints
        )
        return try MeshNode(identity: identity, config: config)
    }

    /// Create peer endpoint info for testing
    private func createPeerInfo(index: Int) -> PeerEndpointInfo {
        PeerEndpointInfo(
            peerId: "peer\(index)-\(UUID().uuidString.prefix(8))",
            machineId: "machine\(index)-\(UUID().uuidString.prefix(8))",
            endpoint: "192.168.1.\(index):999\(index)"
        )
    }

    // MARK: - Propagation Queue Tests

    /// Test that the propagation queue starts empty
    func testPropagationQueueStartsEmpty() async throws {
        let node = try createTestNode()

        // Build peer list - should be empty (no peers known, no propagation items)
        let peers = await node.buildPeerEndpointInfoList()
        XCTAssertTrue(peers.isEmpty, "New node should have no peers")

        // Queue should be empty
        let queueSize = await node.propagationQueueCount
        XCTAssertEqual(queueSize, 0, "Queue should start empty")
    }

    /// Test adding peer to propagation queue
    func testAddToPropagationQueue() async throws {
        let node = try createTestNode()
        let peerInfo = createPeerInfo(index: 1)

        // Add peer to propagation queue
        await node.addToPropagationQueue(peerInfo)

        // Check queue contains the peer
        let queueSize = await node.propagationQueueCount
        XCTAssertEqual(queueSize, 1, "Queue should have 1 item")

        let storedInfo = await node.getPropagationInfo(for: peerInfo.peerId)
        XCTAssertNotNil(storedInfo, "Item should exist in queue")
        XCTAssertEqual(storedInfo?.peerId, peerInfo.peerId, "Peer ID should match")
        XCTAssertEqual(storedInfo?.endpoint, peerInfo.endpoint, "Endpoint should match")
    }

    /// Test propagation queue fanout count
    func testPropagationQueueFanout() async throws {
        let node = try createTestNode()
        let peerInfo = createPeerInfo(index: 1)

        // Add peer to propagation queue
        await node.addToPropagationQueue(peerInfo)

        // Get the count - should be gossipFanout (5)
        let count = await node.getPropagationCount(for: peerInfo.peerId)
        let fanout = await node.gossipFanout
        XCTAssertEqual(count, fanout, "Initial propagation count should be fanout (5)")
    }

    /// Test that adding same peer twice doesn't reset count
    func testAddDuplicatePeerKeepsCount() async throws {
        let node = try createTestNode()
        let peerInfo = createPeerInfo(index: 1)

        // Add peer to propagation queue
        await node.addToPropagationQueue(peerInfo)

        // Manually set count to simulate partial propagation
        await node.setPropagationCount(for: peerInfo.peerId, count: 3)

        let countAfterDecrement = await node.getPropagationCount(for: peerInfo.peerId)
        XCTAssertEqual(countAfterDecrement, 3, "Count should be 3 after manual set")

        // Add same peer again (with maybe different endpoint)
        let updatedPeerInfo = PeerEndpointInfo(
            peerId: peerInfo.peerId,
            machineId: peerInfo.machineId,
            endpoint: "192.168.2.100:8888"  // Different endpoint
        )
        await node.addToPropagationQueue(updatedPeerInfo)

        // Count should still be 3 (not reset to 5)
        let countAfterReadd = await node.getPropagationCount(for: peerInfo.peerId)
        XCTAssertEqual(countAfterReadd, 3, "Re-adding peer should not reset count")

        // But endpoint should be updated
        let updatedInfo = await node.getPropagationInfo(for: peerInfo.peerId)
        XCTAssertEqual(updatedInfo?.endpoint, "192.168.2.100:8888", "Endpoint should be updated")
    }

    /// Test that node doesn't add itself to propagation queue
    func testDoesNotAddSelf() async throws {
        let node = try createTestNode()
        let selfPeerId = await node.peerId

        // Try to add self to propagation queue
        let selfInfo = PeerEndpointInfo(
            peerId: selfPeerId,
            machineId: "self-machine",
            endpoint: "127.0.0.1:9999"
        )
        await node.addToPropagationQueue(selfInfo)

        // Queue should still be empty
        let queueSize = await node.propagationQueueCount
        XCTAssertEqual(queueSize, 0, "Should not add self to queue")
    }

    // MARK: - Peer List Building Tests

    /// Test building peer list with propagation items
    func testBuildPeerListWithPropagation() async throws {
        let node = try createTestNode()

        // Add multiple peers to propagation queue
        let peer1 = createPeerInfo(index: 1)
        let peer2 = createPeerInfo(index: 2)
        let peer3 = createPeerInfo(index: 3)

        await node.addToPropagationQueue(peer1)
        await node.addToPropagationQueue(peer2)
        await node.addToPropagationQueue(peer3)

        // Build peer list (excluding some peer ID)
        let excludePeerId = "some-other-peer"
        let peers = await node.buildPeerEndpointInfoListWithPropagation(excluding: excludePeerId)

        // Should include all 3 peers from propagation queue
        XCTAssertEqual(peers.count, 3, "Should have 3 peers from propagation queue")
        XCTAssertTrue(peers.contains { $0.peerId == peer1.peerId }, "Should contain peer1")
        XCTAssertTrue(peers.contains { $0.peerId == peer2.peerId }, "Should contain peer2")
        XCTAssertTrue(peers.contains { $0.peerId == peer3.peerId }, "Should contain peer3")
    }

    /// Test that excluded peer is not in result
    func testBuildPeerListExcludesPeer() async throws {
        let node = try createTestNode()

        let peer1 = createPeerInfo(index: 1)
        let peer2 = createPeerInfo(index: 2)

        await node.addToPropagationQueue(peer1)
        await node.addToPropagationQueue(peer2)

        // Build peer list excluding peer1
        let peers = await node.buildPeerEndpointInfoListWithPropagation(excluding: peer1.peerId)

        // Should only include peer2
        XCTAssertEqual(peers.count, 1, "Should have 1 peer (peer1 excluded)")
        XCTAssertTrue(peers.contains { $0.peerId == peer2.peerId }, "Should contain peer2")
        XCTAssertFalse(peers.contains { $0.peerId == peer1.peerId }, "Should NOT contain peer1")
    }

    /// Test that building peer list decrements propagation counts
    func testBuildPeerListDecrementsCounts() async throws {
        let node = try createTestNode()

        let peer1 = createPeerInfo(index: 1)
        await node.addToPropagationQueue(peer1)

        // Initial count should be 5
        var count = await node.getPropagationCount(for: peer1.peerId)
        XCTAssertEqual(count, 5, "Initial count should be 5")

        // Build peer list (this should decrement count)
        _ = await node.buildPeerEndpointInfoListWithPropagation(excluding: "other-peer")

        // Count should now be 4
        count = await node.getPropagationCount(for: peer1.peerId)
        XCTAssertEqual(count, 4, "Count should be 4 after one build")
    }

    /// Test propagation queue exhaustion through building
    func testPropagationQueueExhaustionThroughBuilding() async throws {
        let node = try createTestNode()

        let peer1 = createPeerInfo(index: 1)
        await node.addToPropagationQueue(peer1)

        // Build 5 times (fanout)
        for i in 0..<5 {
            let peers = await node.buildPeerEndpointInfoListWithPropagation(excluding: "other-peer")
            if i < 4 {
                XCTAssertTrue(peers.contains { $0.peerId == peer1.peerId }, "Should contain peer1 on iteration \(i)")
            }
        }

        // Peer should be removed from queue
        let queueSize = await node.propagationQueueCount
        XCTAssertEqual(queueSize, 0, "Queue should be empty after 5 builds")
    }

    // MARK: - Integration Tests

    /// Test multiple peers with staggered exhaustion
    func testMultiplePeersStaggeredExhaustion() async throws {
        let node = try createTestNode()

        let peer1 = createPeerInfo(index: 1)
        let peer2 = createPeerInfo(index: 2)

        await node.addToPropagationQueue(peer1)

        // Build twice (peer1 count: 5 -> 4 -> 3)
        _ = await node.buildPeerEndpointInfoListWithPropagation(excluding: "other")
        _ = await node.buildPeerEndpointInfoListWithPropagation(excluding: "other")

        // Add peer2 (peer1 count: 3, peer2 count: 5)
        await node.addToPropagationQueue(peer2)

        var peer1Count = await node.getPropagationCount(for: peer1.peerId)
        var peer2Count = await node.getPropagationCount(for: peer2.peerId)
        XCTAssertEqual(peer1Count, 3, "peer1 should have count 3")
        XCTAssertEqual(peer2Count, 5, "peer2 should have count 5")

        // Build 3 more times
        // peer1: 3 -> 2 -> 1 -> 0 (removed)
        // peer2: 5 -> 4 -> 3 -> 2
        for _ in 0..<3 {
            _ = await node.buildPeerEndpointInfoListWithPropagation(excluding: "other")
        }

        // peer1 should be gone, peer2 should remain
        let queueSize = await node.propagationQueueCount
        XCTAssertEqual(queueSize, 1, "Only peer2 should remain")

        peer2Count = await node.getPropagationCount(for: peer2.peerId)
        XCTAssertEqual(peer2Count, 2, "peer2 should have count 2")

        peer1Count = await node.getPropagationCount(for: peer1.peerId)
        XCTAssertNil(peer1Count, "peer1 should not be in queue")
    }

    /// Test that gossip fanout is 5
    func testGossipFanoutValue() async throws {
        let node = try createTestNode()
        let fanout = await node.gossipFanout
        XCTAssertEqual(fanout, 5, "Gossip fanout should be 5 as per protocol")
    }

    // MARK: - Reconnecting Peer Detection Tests

    /// Test that FreshnessManager tracks contacts correctly
    func testFreshnessManagerTracksContacts() async throws {
        let freshnessManager = FreshnessManager()

        let testPeerId = "test-peer-\(UUID().uuidString.prefix(8))"

        // Initially no recent contact
        let hasContactBefore = await freshnessManager.hasRecentContact(testPeerId, maxAgeSeconds: 60)
        XCTAssertFalse(hasContactBefore, "Should have no contact before recording")

        // Record a contact
        await freshnessManager.recordContact(
            peerId: testPeerId,
            reachability: .direct(endpoint: "192.168.1.100:9999"),
            latencyMs: 50,
            connectionType: .direct
        )

        // Now should have recent contact
        let hasContactAfter = await freshnessManager.hasRecentContact(testPeerId, maxAgeSeconds: 60)
        XCTAssertTrue(hasContactAfter, "Should have recent contact after recording")
    }

    /// Test that hasRecentContact respects maxAgeSeconds
    func testFreshnessManagerRespectsMaxAge() async throws {
        let freshnessManager = FreshnessManager()

        let testPeerId = "test-peer-\(UUID().uuidString.prefix(8))"

        // Record a contact
        await freshnessManager.recordContact(
            peerId: testPeerId,
            reachability: .direct(endpoint: "192.168.1.100:9999"),
            latencyMs: 50,
            connectionType: .direct
        )

        // Should have recent contact with 60s window
        let hasRecentContact = await freshnessManager.hasRecentContact(testPeerId, maxAgeSeconds: 60)
        XCTAssertTrue(hasRecentContact, "Should have recent contact within 60s")

        // Should also have recent contact with very short window (just recorded)
        let hasVeryRecentContact = await freshnessManager.hasRecentContact(testPeerId, maxAgeSeconds: 1)
        XCTAssertTrue(hasVeryRecentContact, "Should have recent contact within 1s (just recorded)")
    }

    /// Test that unknown peer has no recent contact
    func testFreshnessManagerUnknownPeerNoContact() async throws {
        let freshnessManager = FreshnessManager()

        let unknownPeerId = "unknown-peer-\(UUID().uuidString.prefix(8))"

        let hasContact = await freshnessManager.hasRecentContact(unknownPeerId, maxAgeSeconds: 60)
        XCTAssertFalse(hasContact, "Unknown peer should have no recent contact")
    }

    /// Test reconnecting peer detection logic
    /// A peer is "reconnecting" if we have their endpoint but no recent contact (60s)
    func testReconnectingPeerDetection() async throws {
        let node = try createTestNode()
        try await node.start()
        defer { Task { await node.stop() } }

        let testPeerId = "test-peer-\(UUID().uuidString.prefix(8))"
        let testMachineId = "test-machine-\(UUID().uuidString.prefix(8))"
        let testEndpoint = "192.168.1.100:9999"

        // Record endpoint (simulating previous connection)
        await node.endpointManager.recordMessageReceived(
            from: testPeerId,
            machineId: testMachineId,
            endpoint: testEndpoint
        )

        // Check we have the endpoint
        let endpoints = await node.endpointManager.getAllEndpoints(peerId: testPeerId)
        XCTAssertFalse(endpoints.isEmpty, "Should have endpoint recorded")

        // But no recent contact (we recorded endpoint but not freshness)
        let hasRecentContact = await node.freshnessManager.hasRecentContact(testPeerId, maxAgeSeconds: 60)
        XCTAssertFalse(hasRecentContact, "Should have no recent contact (only endpoint, no freshness)")

        // This is the reconnecting peer scenario: hasEndpoint but !hasRecentContact
        let hasEndpoints = !endpoints.isEmpty
        let isReconnecting = hasEndpoints && !hasRecentContact
        XCTAssertTrue(isReconnecting, "Peer should be detected as reconnecting")
    }

    /// Test new peer detection (no endpoint, no contact)
    func testNewPeerDetection() async throws {
        let node = try createTestNode()
        try await node.start()
        defer { Task { await node.stop() } }

        let unknownPeerId = "unknown-peer-\(UUID().uuidString.prefix(8))"

        // No endpoints
        let endpoints = await node.endpointManager.getAllEndpoints(peerId: unknownPeerId)
        XCTAssertTrue(endpoints.isEmpty, "Should have no endpoints for new peer")

        // No recent contact
        let hasRecentContact = await node.freshnessManager.hasRecentContact(unknownPeerId, maxAgeSeconds: 60)
        XCTAssertFalse(hasRecentContact, "Should have no recent contact for new peer")

        // This is the new peer scenario
        let hasEndpoints = !endpoints.isEmpty
        let isNewOrReconnecting = !hasEndpoints || !hasRecentContact
        XCTAssertTrue(isNewOrReconnecting, "New peer should be detected as new/reconnecting")
    }

    /// Test known peer with recent contact (normal keepalive)
    func testKnownPeerWithRecentContact() async throws {
        let node = try createTestNode()
        try await node.start()
        defer { Task { await node.stop() } }

        let testPeerId = "test-peer-\(UUID().uuidString.prefix(8))"
        let testMachineId = "test-machine-\(UUID().uuidString.prefix(8))"
        let testEndpoint = "192.168.1.100:9999"

        // Record endpoint
        await node.endpointManager.recordMessageReceived(
            from: testPeerId,
            machineId: testMachineId,
            endpoint: testEndpoint
        )

        // Record recent contact
        await node.freshnessManager.recordContact(
            peerId: testPeerId,
            reachability: .direct(endpoint: testEndpoint),
            latencyMs: 50,
            connectionType: .direct
        )

        // Should have endpoint
        let endpoints = await node.endpointManager.getAllEndpoints(peerId: testPeerId)
        XCTAssertFalse(endpoints.isEmpty, "Should have endpoint")

        // Should have recent contact
        let hasRecentContact = await node.freshnessManager.hasRecentContact(testPeerId, maxAgeSeconds: 60)
        XCTAssertTrue(hasRecentContact, "Should have recent contact")

        // This is NOT a new/reconnecting peer
        let hasEndpoints = !endpoints.isEmpty
        let isNewOrReconnecting = !hasEndpoints || !hasRecentContact
        XCTAssertFalse(isNewOrReconnecting, "Known peer with recent contact should not be new/reconnecting")
    }
}
