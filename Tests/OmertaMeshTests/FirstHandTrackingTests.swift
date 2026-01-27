// FirstHandTrackingTests.swift - Tests for Phase 4: First-Hand Tracking

import XCTest
import Foundation
@testable import OmertaMesh

final class FirstHandTrackingTests: XCTestCase {

    // MARK: - Direct Contact Recording Tests

    func testHasDirectContactInitiallyFalse() async throws {
        let node = try await createTestMeshNode(peerId: "test-node")

        let hasContact = await node.hasDirectContact(with: "unknown-machine")
        XCTAssertFalse(hasContact, "Should not have direct contact with unknown machine")
    }

    // MARK: - isFirstHand in PeerEndpointInfo Tests

    func testIsFirstHandDefaultsFalse() {
        let info = PeerEndpointInfo(
            peerId: "peer1",
            machineId: "machine1",
            endpoint: "1.2.3.4:5000",
            natType: .public
        )
        XCTAssertFalse(info.isFirstHand, "isFirstHand should default to false")
    }

    func testIsFirstHandCanBeSetTrue() {
        let info = PeerEndpointInfo(
            peerId: "peer1",
            machineId: "machine1",
            endpoint: "1.2.3.4:5000",
            natType: .public,
            isFirstHand: true
        )
        XCTAssertTrue(info.isFirstHand, "isFirstHand should be true when set")
    }

    func testIsFirstHandPreservedInEncoding() throws {
        let infoTrue = PeerEndpointInfo(
            peerId: "peer1", machineId: "machine1",
            endpoint: "1.2.3.4:5000", natType: .public, isFirstHand: true
        )
        let infoFalse = PeerEndpointInfo(
            peerId: "peer2", machineId: "machine2",
            endpoint: "2.2.2.2:5000", natType: .public, isFirstHand: false
        )

        let encodedTrue = try JSONEncoder().encode(infoTrue)
        let encodedFalse = try JSONEncoder().encode(infoFalse)

        let decodedTrue = try JSONDecoder().decode(PeerEndpointInfo.self, from: encodedTrue)
        let decodedFalse = try JSONDecoder().decode(PeerEndpointInfo.self, from: encodedFalse)

        XCTAssertTrue(decodedTrue.isFirstHand, "isFirstHand=true should be preserved")
        XCTAssertFalse(decodedFalse.isFirstHand, "isFirstHand=false should be preserved")
    }

    // MARK: - Gossip with First-Hand Info Tests

    func testPingContainsIsFirstHand() throws {
        let peers = [
            PeerEndpointInfo(peerId: "p1", machineId: "m1", endpoint: "1.1.1.1:5000", natType: .public, isFirstHand: true),
            PeerEndpointInfo(peerId: "p2", machineId: "m2", endpoint: "2.2.2.2:5000", natType: .public, isFirstHand: false)
        ]

        let ping = MeshMessage.ping(recentPeers: peers, myNATType: .public)

        if case .ping(let recentPeers, _, _) = ping {
            XCTAssertEqual(recentPeers.count, 2)
            XCTAssertTrue(recentPeers[0].isFirstHand)
            XCTAssertFalse(recentPeers[1].isFirstHand)
        } else {
            XCTFail("Expected ping message")
        }
    }

    func testPongContainsIsFirstHand() throws {
        let peers = [
            PeerEndpointInfo(peerId: "p1", machineId: "m1", endpoint: "1.1.1.1:5000", natType: .public, isFirstHand: true)
        ]

        let pong = MeshMessage.pong(recentPeers: peers, yourEndpoint: "5.5.5.5:5000", myNATType: .public)

        if case .pong(let recentPeers, _, _) = pong {
            XCTAssertEqual(recentPeers.count, 1)
            XCTAssertTrue(recentPeers[0].isFirstHand)
        } else {
            XCTFail("Expected pong message")
        }
    }

    // MARK: - Helper

    private func createTestMeshNode(peerId: String) async throws -> MeshNode {
        let identity = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let config = MeshNode.Config(encryptionKey: testKey, port: 0)
        return try MeshNode(identity: identity, config: config)
    }
}
