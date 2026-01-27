// MessageStructureTests.swift - Tests for Phase 1: Message Structure Updates

import XCTest
import Foundation
@testable import OmertaMesh

final class MessageStructureTests: XCTestCase {

    // MARK: - PeerEndpointInfo Tests

    /// Test PeerEndpointInfo includes isFirstHand
    func testPeerEndpointInfoIncludesIsFirstHand() throws {
        let info = PeerEndpointInfo(
            peerId: "peer1",
            machineId: "machine1",
            endpoint: "1.2.3.4:5000",
            natType: .public,
            isFirstHand: true
        )
        XCTAssertTrue(info.isFirstHand)

        // Test encoding/decoding preserves isFirstHand
        let encoded = try JSONEncoder().encode(info)
        let decoded = try JSONDecoder().decode(PeerEndpointInfo.self, from: encoded)
        XCTAssertTrue(decoded.isFirstHand)
    }

    func testPeerEndpointInfoDefaultsIsFirstHandToFalse() {
        let info = PeerEndpointInfo(
            peerId: "peer1",
            machineId: "machine1",
            endpoint: "1.2.3.4:5000",
            natType: .public
        )
        XCTAssertFalse(info.isFirstHand)
    }

    func testPeerEndpointInfoEquality() {
        let info1 = PeerEndpointInfo(
            peerId: "peer1", machineId: "machine1",
            endpoint: "1.2.3.4:5000", natType: .public, isFirstHand: true
        )
        let info2 = PeerEndpointInfo(
            peerId: "peer1", machineId: "machine1",
            endpoint: "1.2.3.4:5000", natType: .public, isFirstHand: true
        )
        let info3 = PeerEndpointInfo(
            peerId: "peer1", machineId: "machine1",
            endpoint: "1.2.3.4:5000", natType: .public, isFirstHand: false
        )

        XCTAssertEqual(info1, info2)
        XCTAssertNotEqual(info1, info3, "isFirstHand should affect equality")
    }

    // MARK: - Ping Message Tests

    /// Test ping message includes requestFullList
    func testPingIncludesRequestFullList() throws {
        let ping = MeshMessage.ping(recentPeers: [], myNATType: .public, requestFullList: true)
        if case .ping(_, _, let requestFullList) = ping {
            XCTAssertTrue(requestFullList)
        } else {
            XCTFail("Expected ping message")
        }

        // Test encoding/decoding
        let encoded = try JSONEncoder().encode(ping)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)
        if case .ping(_, _, let requestFullList) = decoded {
            XCTAssertTrue(requestFullList)
        } else {
            XCTFail("Expected ping message after decode")
        }
    }

    func testPingDefaultsRequestFullListToFalse() throws {
        let ping = MeshMessage.ping(recentPeers: [], myNATType: .public)
        if case .ping(_, _, let requestFullList) = ping {
            XCTAssertFalse(requestFullList)
        } else {
            XCTFail("Expected ping message")
        }
    }

    func testPingWithPeersAndRequestFullList() throws {
        let peers = [
            PeerEndpointInfo(peerId: "p1", machineId: "m1", endpoint: "1.1.1.1:5000", natType: .public, isFirstHand: true),
            PeerEndpointInfo(peerId: "p2", machineId: "m2", endpoint: "2.2.2.2:5000", natType: .symmetric, isFirstHand: false)
        ]
        let ping = MeshMessage.ping(recentPeers: peers, myNATType: .fullCone, requestFullList: true)

        if case .ping(let recentPeers, let natType, let requestFullList) = ping {
            XCTAssertEqual(recentPeers.count, 2)
            XCTAssertEqual(natType, .fullCone)
            XCTAssertTrue(requestFullList)
            XCTAssertTrue(recentPeers[0].isFirstHand)
            XCTAssertFalse(recentPeers[1].isFirstHand)
        } else {
            XCTFail("Expected ping message")
        }
    }

    // MARK: - HolePunchExecute Message Tests

    func testHolePunchExecuteIncludesSimultaneousSend() throws {
        let execute = MeshMessage.holePunchExecute(
            targetEndpoint: "1.2.3.4:5000",
            peerEndpoint: "5.6.7.8:6000",
            simultaneousSend: true
        )

        if case .holePunchExecute(let targetEndpoint, let peerEndpoint, let simultaneousSend) = execute {
            XCTAssertEqual(targetEndpoint, "1.2.3.4:5000")
            XCTAssertEqual(peerEndpoint, "5.6.7.8:6000")
            XCTAssertTrue(simultaneousSend)
        } else {
            XCTFail("Expected holePunchExecute message")
        }

        // Test encoding/decoding
        let encoded = try JSONEncoder().encode(execute)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)
        if case .holePunchExecute(let targetEndpoint, let peerEndpoint, let simultaneousSend) = decoded {
            XCTAssertEqual(targetEndpoint, "1.2.3.4:5000")
            XCTAssertEqual(peerEndpoint, "5.6.7.8:6000")
            XCTAssertTrue(simultaneousSend)
        } else {
            XCTFail("Expected holePunchExecute message after decode")
        }
    }

    func testHolePunchExecuteDefaults() throws {
        let execute = MeshMessage.holePunchExecute(targetEndpoint: "1.2.3.4:5000")

        if case .holePunchExecute(let targetEndpoint, let peerEndpoint, let simultaneousSend) = execute {
            XCTAssertEqual(targetEndpoint, "1.2.3.4:5000")
            XCTAssertNil(peerEndpoint)
            XCTAssertFalse(simultaneousSend)
        } else {
            XCTFail("Expected holePunchExecute message")
        }
    }
}
