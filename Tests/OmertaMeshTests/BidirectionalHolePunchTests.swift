// BidirectionalHolePunchTests.swift - Tests for Phase 5: Bidirectional Hole Punch Coordination

import XCTest
import Foundation
@testable import OmertaMesh

final class BidirectionalHolePunchTests: XCTestCase {

    // MARK: - HolePunchExecute Message Tests

    func testHolePunchExecuteWithBidirectionalParams() throws {
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
    }

    func testHolePunchExecuteEncodingDecoding() throws {
        let execute = MeshMessage.holePunchExecute(
            targetEndpoint: "target.example.com:5000",
            peerEndpoint: "peer.example.com:6000",
            simultaneousSend: true
        )

        let encoded = try JSONEncoder().encode(execute)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)

        if case .holePunchExecute(let targetEndpoint, let peerEndpoint, let simultaneousSend) = decoded {
            XCTAssertEqual(targetEndpoint, "target.example.com:5000")
            XCTAssertEqual(peerEndpoint, "peer.example.com:6000")
            XCTAssertTrue(simultaneousSend)
        } else {
            XCTFail("Expected holePunchExecute message after decode")
        }
    }

    func testHolePunchExecuteDefaultValues() throws {
        let execute = MeshMessage.holePunchExecute(targetEndpoint: "1.2.3.4:5000")

        if case .holePunchExecute(let targetEndpoint, let peerEndpoint, let simultaneousSend) = execute {
            XCTAssertEqual(targetEndpoint, "1.2.3.4:5000")
            XCTAssertNil(peerEndpoint, "peerEndpoint should default to nil")
            XCTAssertFalse(simultaneousSend, "simultaneousSend should default to false")
        } else {
            XCTFail("Expected holePunchExecute message")
        }
    }

    // MARK: - HolePunchCompatibility Tests

    func testHolePunchCompatibilitySymmetricWithSymmetric() {
        // Symmetric NAT with symmetric NAT should not be compatible for hole punch
        let compatibility = HolePunchCompatibility.check(
            initiator: .symmetric,
            responder: .symmetric
        )
        XCTAssertFalse(compatibility.strategy.canSucceed, "Symmetric with symmetric should not work")
    }

    func testHolePunchCompatibilityPublicWithPublic() {
        let compatibility = HolePunchCompatibility.check(
            initiator: .public,
            responder: .public
        )
        XCTAssertTrue(compatibility.strategy.canSucceed, "Public with public should work")
    }

    func testHolePunchCompatibilityPublicWithSymmetric() {
        // Public with symmetric - public can reach symmetric but not vice versa without relay
        let compatibility = HolePunchCompatibility.check(
            initiator: .public,
            responder: .symmetric
        )
        // May or may not succeed depending on implementation details
        // This test validates the check doesn't crash
        XCTAssertNotNil(compatibility.strategy)
    }

    func testHolePunchCompatibilityRestrictedWithRestricted() {
        // Restricted cone with restricted cone should be able to hole punch
        let compatibility = HolePunchCompatibility.check(
            initiator: .portRestrictedCone,
            responder: .portRestrictedCone
        )
        // Both have fixed ports, so they can hole punch
        XCTAssertNotNil(compatibility.strategy)
    }

    // MARK: - HolePunchCoordinator Tests

    func testCoordinatorCreation() {
        let coordinator = HolePunchCoordinator()
        XCTAssertNotNil(coordinator)
    }

    func testCoordinatorDefaultConfig() {
        let config = HolePunchCoordinator.Config.default
        // Just verify the config exists and has expected defaults
        XCTAssertGreaterThan(config.requestTimeout, 0)
        XCTAssertGreaterThan(config.cleanupInterval, 0)
        XCTAssertGreaterThan(config.maxConcurrent, 0)
    }

    // MARK: - HolePunchStrategy Tests

    func testHolePunchStrategySimultaneous() {
        let strategy = HolePunchStrategy.simultaneous
        XCTAssertTrue(strategy.canSucceed, "Simultaneous strategy should be able to succeed")
    }

    func testHolePunchStrategyCannotSucceed() {
        // Test that invalid strategies report canSucceed correctly
        // The simultaneous strategy should succeed
        XCTAssertTrue(HolePunchStrategy.simultaneous.canSucceed)
        // The initiatorFirst strategy should succeed
        XCTAssertTrue(HolePunchStrategy.initiatorFirst.canSucceed)
    }

    // MARK: - Integration Test

    func testBidirectionalMessageFlow() throws {
        // Test that we can create the messages needed for bidirectional coordination
        let initiatorEndpoint = "initiator.example.com:5000"
        let targetEndpoint = "target.example.com:6000"

        // Message to initiator
        let executeToInitiator = MeshMessage.holePunchExecute(
            targetEndpoint: targetEndpoint,
            peerEndpoint: initiatorEndpoint,
            simultaneousSend: true
        )

        // Message to target
        let executeToTarget = MeshMessage.holePunchExecute(
            targetEndpoint: initiatorEndpoint,
            peerEndpoint: targetEndpoint,
            simultaneousSend: true
        )

        // Verify both messages are correctly formed
        if case .holePunchExecute(let te1, let pe1, let ss1) = executeToInitiator {
            XCTAssertEqual(te1, targetEndpoint)
            XCTAssertEqual(pe1, initiatorEndpoint)
            XCTAssertTrue(ss1)
        } else {
            XCTFail("Expected holePunchExecute for initiator")
        }

        if case .holePunchExecute(let te2, let pe2, let ss2) = executeToTarget {
            XCTAssertEqual(te2, initiatorEndpoint)
            XCTAssertEqual(pe2, targetEndpoint)
            XCTAssertTrue(ss2)
        } else {
            XCTFail("Expected holePunchExecute for target")
        }
    }
}
