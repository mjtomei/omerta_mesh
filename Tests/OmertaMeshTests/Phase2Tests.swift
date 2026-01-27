// Phase2Tests.swift - Tests for NAT types (Phase 2)
//
// NOTE: STUN-based NAT detection has been replaced with peer-based NAT prediction.
// See NATPredictorTests.swift for the new NAT prediction tests.
// This file retains tests for NATType properties and compatibility.

import XCTest
@testable import OmertaMesh

final class Phase2Tests: XCTestCase {

    // MARK: - NATType Tests

    /// Test NATType properties
    func testNATTypeProperties() {
        // Hole punchable types
        XCTAssertTrue(NATType.public.holePunchable)
        XCTAssertTrue(NATType.fullCone.holePunchable)
        XCTAssertTrue(NATType.restrictedCone.holePunchable)
        XCTAssertTrue(NATType.portRestrictedCone.holePunchable)
        XCTAssertFalse(NATType.symmetric.holePunchable)
        XCTAssertFalse(NATType.unknown.holePunchable)

        // Can relay
        XCTAssertTrue(NATType.public.canRelay)
        XCTAssertTrue(NATType.fullCone.canRelay)
        XCTAssertFalse(NATType.restrictedCone.canRelay)
        XCTAssertFalse(NATType.symmetric.canRelay)
    }

    /// Test NATType encoding
    func testNATTypeCodable() throws {
        let types: [NATType] = [.public, .fullCone, .restrictedCone, .portRestrictedCone, .symmetric, .unknown]

        for type in types {
            let encoded = try JSONEncoder().encode(type)
            let decoded = try JSONDecoder().decode(NATType.self, from: encoded)
            XCTAssertEqual(type, decoded)
        }
    }

    /// Test hole punch compatibility between NAT types
    func testHolePunchCompatibility() {
        // Public to public should have low difficulty
        let publicToPublic = HolePunchCompatibility.check(initiator: .public, responder: .public)
        XCTAssertTrue(publicToPublic.likely)
        XCTAssertEqual(publicToPublic.difficulty, 0)

        // Public to port restricted cone should be possible
        let publicToCone = HolePunchCompatibility.check(initiator: .public, responder: .portRestrictedCone)
        XCTAssertTrue(publicToCone.likely)

        // Symmetric to symmetric should be impossible
        let symmetricToSymmetric = HolePunchCompatibility.check(initiator: .symmetric, responder: .symmetric)
        XCTAssertFalse(symmetricToSymmetric.likely)
        XCTAssertEqual(symmetricToSymmetric.strategy, .impossible)

        // Unknown has high difficulty
        let unknownResult = HolePunchCompatibility.check(initiator: .unknown, responder: .public)
        XCTAssertGreaterThan(unknownResult.difficulty, 0)
    }

    /// Test NATType rawValue
    func testNATTypeRawValue() {
        XCTAssertEqual(NATType.public.rawValue, "public")
        XCTAssertEqual(NATType.fullCone.rawValue, "fullCone")
        XCTAssertEqual(NATType.restrictedCone.rawValue, "restrictedCone")
        XCTAssertEqual(NATType.portRestrictedCone.rawValue, "portRestrictedCone")
        XCTAssertEqual(NATType.symmetric.rawValue, "symmetric")
        XCTAssertEqual(NATType.unknown.rawValue, "unknown")
    }

    /// Test NATType initialization from rawValue
    func testNATTypeFromRawValue() {
        XCTAssertEqual(NATType(rawValue: "public"), .public)
        XCTAssertEqual(NATType(rawValue: "fullCone"), .fullCone)
        XCTAssertEqual(NATType(rawValue: "restrictedCone"), .restrictedCone)
        XCTAssertEqual(NATType(rawValue: "portRestrictedCone"), .portRestrictedCone)
        XCTAssertEqual(NATType(rawValue: "symmetric"), .symmetric)
        XCTAssertEqual(NATType(rawValue: "unknown"), .unknown)
        XCTAssertNil(NATType(rawValue: "invalid"))
    }
}
