// NATPredictorTests.swift - Unit tests for peer-based NAT prediction

import XCTest
@testable import OmertaMesh

final class NATPredictorTests: XCTestCase {

    // MARK: - Basic Prediction Tests

    /// Test prediction with same endpoint from multiple peers (cone NAT)
    func testPredictConeNAT() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .portRestrictedCone)
        XCTAssertEqual(result.publicEndpoint, "1.2.3.4:5000")
        XCTAssertGreaterThanOrEqual(result.confidence, 2)
    }

    /// Test prediction with same IP but different ports (symmetric NAT)
    func testPredictSymmetricNAT() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5001", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .symmetric)
        XCTAssertNil(result.publicEndpoint) // No stable endpoint for symmetric
    }

    /// Test prediction with different IPs (also symmetric NAT)
    func testPredictSymmetricNATDifferentIPs() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "5.6.7.8:5000", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .symmetric)
        XCTAssertNil(result.publicEndpoint)
    }

    /// Test that single observation is insufficient
    func testMinimumObservationsRequired() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .unknown)
        XCTAssertEqual(result.confidence, 1)
    }

    /// Test confidence increases with more observations
    func testConfidenceIncreases() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        let result1 = await predictor.predictNATType()

        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerC", isBootstrap: false)
        let result2 = await predictor.predictNATType()
        XCTAssertGreaterThan(result2.confidence, result1.confidence)
    }

    /// Test public IP detection (no NAT)
    func testPredictPublicIP() async throws {
        let predictor = NATPredictor(localEndpoint: "1.2.3.4:5000")
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .public)
        XCTAssertEqual(result.publicEndpoint, "1.2.3.4:5000")
    }

    /// Test reset clears observations
    func testReset() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        await predictor.reset()
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .unknown)
        XCTAssertEqual(result.confidence, 0)
    }

    /// Test observation from same peer updates rather than duplicates
    func testObservationUpdate() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5001", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5001", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        // Should use latest observation from peerA (5001) + peerB (5001) = cone
        XCTAssertEqual(result.type, .portRestrictedCone)
        XCTAssertEqual(result.publicEndpoint, "1.2.3.4:5001")
    }

    // MARK: - Helper Method Tests

    /// Test observation count
    func testObservationCount() async throws {
        let predictor = NATPredictor()
        let count1 = await predictor.observationCount
        XCTAssertEqual(count1, 0)

        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        let count2 = await predictor.observationCount
        XCTAssertEqual(count2, 1)

        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        let count3 = await predictor.observationCount
        XCTAssertEqual(count3, 2)
    }

    /// Test hasObservation
    func testHasObservation() async throws {
        let predictor = NATPredictor()
        let has1 = await predictor.hasObservation(from: "peerA")
        XCTAssertFalse(has1)

        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        let has2 = await predictor.hasObservation(from: "peerA")
        XCTAssertTrue(has2)

        let has3 = await predictor.hasObservation(from: "peerB")
        XCTAssertFalse(has3)
    }

    /// Test mostCommonEndpoint
    func testMostCommonEndpoint() async throws {
        let predictor = NATPredictor()

        // Empty case
        let empty = await predictor.mostCommonEndpoint
        XCTAssertNil(empty)

        // Single observation
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        let single = await predictor.mostCommonEndpoint
        XCTAssertEqual(single, "1.2.3.4:5000")

        // Multiple with same endpoint
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5001", from: "peerC", isBootstrap: true)
        let common = await predictor.mostCommonEndpoint
        XCTAssertEqual(common, "1.2.3.4:5000") // 2 vs 1
    }

    /// Test setLocalEndpoint
    func testSetLocalEndpoint() async throws {
        let predictor = NATPredictor()

        // Without local endpoint, same IP:port is cone NAT
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        let result1 = await predictor.predictNATType()
        XCTAssertEqual(result1.type, .portRestrictedCone)

        // Reset and set local endpoint
        await predictor.reset()
        await predictor.setLocalEndpoint("1.2.3.4:5000")
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)
        let result2 = await predictor.predictNATType()
        XCTAssertEqual(result2.type, .public)
    }

    // MARK: - Edge Cases

    /// Test IPv6 endpoint parsing
    func testIPv6EndpointParsing() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "[2001:db8::1]:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "[2001:db8::1]:5000", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .portRestrictedCone)
        XCTAssertEqual(result.publicEndpoint, "[2001:db8::1]:5000")
    }

    /// Test IPv6 symmetric detection
    func testIPv6SymmetricNAT() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "[2001:db8::1]:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "[2001:db8::1]:5001", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        XCTAssertEqual(result.type, .symmetric)
    }

    /// Test custom minimum observations
    func testCustomMinimumObservations() async throws {
        let predictor = NATPredictor(minimumObservations: 3)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerB", isBootstrap: true)

        let result1 = await predictor.predictNATType()
        XCTAssertEqual(result1.type, .unknown) // Only 2 observations, need 3

        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerC", isBootstrap: true)
        let result2 = await predictor.predictNATType()
        XCTAssertEqual(result2.type, .portRestrictedCone) // Now have 3
    }

    /// Test malformed endpoint handling
    func testMalformedEndpoint() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "invalid", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "also-invalid", from: "peerB", isBootstrap: true)
        let result = await predictor.predictNATType()
        // Should handle gracefully - can't parse so returns unknown
        XCTAssertEqual(result.type, .unknown)
        XCTAssertEqual(result.confidence, 0)
    }

    /// Test mixed valid/invalid endpoints
    func testMixedValidInvalidEndpoints() async throws {
        let predictor = NATPredictor()
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerA", isBootstrap: true)
        await predictor.recordObservation(endpoint: "invalid", from: "peerB", isBootstrap: true)
        await predictor.recordObservation(endpoint: "1.2.3.4:5000", from: "peerC", isBootstrap: true)
        let result = await predictor.predictNATType()
        // Should still work with the 2 valid endpoints
        XCTAssertEqual(result.type, .portRestrictedCone)
        XCTAssertEqual(result.publicEndpoint, "1.2.3.4:5000")
    }
}
