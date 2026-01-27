// GossipEfficiencyTests.swift - Tests for Phase 3: Gossip Efficiency

import XCTest
import Foundation
@testable import OmertaMesh

final class GossipEfficiencyTests: XCTestCase {

    // MARK: - Reconnection Threshold Tests

    /// Test that 10 minute (600 second) reconnection threshold is used
    func testReconnectionThreshold() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // Record a contact
        await node.freshnessManager.recordContact(
            peerId: "peer1",
            reachability: .direct(endpoint: "1.2.3.4:5000"),
            latencyMs: 10,
            connectionType: .direct
        )

        // Check within 600 seconds - should have recent contact
        let hasRecent = await node.freshnessManager.hasRecentContact("peer1", maxAgeSeconds: 600)
        XCTAssertTrue(hasRecent, "Contact within 600 seconds should be considered recent")
    }

    // MARK: - Propagation Queue Tests

    func testPropagationQueueAddsNewPeers() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        let peerInfo = PeerEndpointInfo(
            peerId: "new-peer",
            machineId: "new-machine",
            endpoint: "1.2.3.4:5000",
            natType: .public,
            isFirstHand: true
        )

        await node.addToPropagationQueue(peerInfo)

        // Check propagation queue
        let queueItem = await node.peerPropagationQueue["new-peer"]
        XCTAssertNotNil(queueItem, "New peer should be in propagation queue")
        XCTAssertEqual(queueItem?.info.peerId, "new-peer")
    }

    func testDoesNotAddSelfToPropagationQueue() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")
        let nodePeerId = await node.peerId

        let selfInfo = PeerEndpointInfo(
            peerId: nodePeerId,
            machineId: "self-machine",
            endpoint: "1.2.3.4:5000",
            natType: .public,
            isFirstHand: true
        )

        await node.addToPropagationQueue(selfInfo)

        let queueItem = await node.peerPropagationQueue[nodePeerId]
        XCTAssertNil(queueItem, "Self should not be added to propagation queue")
    }

    // MARK: - Request Full List Tests

    func testRequestFullListFlagSerialization() throws {
        // Test that requestFullList is properly serialized
        let pingWithFullList = MeshMessage.ping(
            recentPeers: [],
            myNATType: .public,
            requestFullList: true
        )

        let encoded = try JSONEncoder().encode(pingWithFullList)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)

        if case .ping(_, _, let requestFullList) = decoded {
            XCTAssertTrue(requestFullList, "requestFullList should be preserved through serialization")
        } else {
            XCTFail("Expected ping message")
        }
    }

    func testRequestFullListFlagDefaultsFalse() throws {
        let pingDefault = MeshMessage.ping(recentPeers: [], myNATType: .public)

        let encoded = try JSONEncoder().encode(pingDefault)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)

        if case .ping(_, _, let requestFullList) = decoded {
            XCTAssertFalse(requestFullList, "requestFullList should default to false")
        } else {
            XCTFail("Expected ping message")
        }
    }

    // MARK: - Gossip Fanout Tests

    func testGossipFanoutConstant() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        // The gossip fanout should be 5 (number of peers to forward new peer info to)
        let fanout = await node.gossipFanout
        XCTAssertEqual(fanout, 5, "Gossip fanout should be 5")
    }

    // MARK: - Helper

    private func createTestMeshNode(peerId: String) async throws -> MeshNode {
        let identity = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let config = MeshNode.Config(encryptionKey: testKey, port: 0)
        return try MeshNode(identity: identity, config: config)
    }
}
