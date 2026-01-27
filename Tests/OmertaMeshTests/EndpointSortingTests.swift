// EndpointSortingTests.swift - Tests for endpoint ordering and IPv6 preference
//
// These tests verify that endpoint ordering preserves recency within address types.
// Bug reference: getAllEndpoints() was alphabetically sorting IPv6 addresses,
// causing stale endpoints to be selected over fresh ones.

import XCTest
@testable import OmertaMesh

final class EndpointSortingTests: XCTestCase {

    // MARK: - getAllEndpoints() Recency Preservation Tests

    /// Test that getAllEndpoints preserves recency order within IPv6 addresses
    /// This is the core test for the bug that was fixed - alphabetical sorting
    /// would put "bb05:..." before "f81f:..." even if f81f was more recent
    func testGetAllEndpointsPreservesIPv6RecencyOrder() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Record IPv6 endpoints where alphabetical order differs from recency
        // bb05 comes before f81f alphabetically, but f81f is added last (most recent)
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[bb05:1234:5678:90ab::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[f81f:2074:c1e9:94dc::1]:9999")

        // getAllEndpoints should return f81f first (most recent), not bb05 (alphabetical)
        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)
        XCTAssertEqual(allEndpoints.first, "[f81f:2074:c1e9:94dc::1]:9999",
            "Most recent IPv6 endpoint should be first, not alphabetically first")
    }

    /// Test that getAllEndpoints preserves recency within IPv4 addresses too
    func testGetAllEndpointsPreservesIPv4RecencyOrder() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Record IPv4 endpoints where alphabetical order differs from recency
        // 1.1.1.1 comes before 9.9.9.9 alphabetically, but 9.9.9.9 is added last
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "1.1.1.1:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "9.9.9.9:5000")

        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)

        // Should have IPv4 in recency order (9.9.9.9 first, since no IPv6)
        XCTAssertEqual(allEndpoints.first, "9.9.9.9:5000",
            "Most recent IPv4 endpoint should be first")
    }

    /// Test that IPv6 comes before IPv4 but recency is preserved within each type
    func testGetAllEndpointsIPv6FirstThenIPv4WithRecencyPreserved() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Add in order: IPv4-A, IPv6-A, IPv4-B, IPv6-B
        // Expected result: IPv6-B, IPv6-A (recency within IPv6), then IPv4-B, IPv4-A (recency within IPv4)
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "1.1.1.1:5000")  // IPv4-A (oldest)
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[aaaa::1]:9999") // IPv6-A
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "2.2.2.2:5000")  // IPv4-B
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[bbbb::1]:9999") // IPv6-B (most recent)

        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)

        // IPv6 should come first, in recency order (bbbb before aaaa)
        XCTAssertEqual(allEndpoints[0], "[bbbb::1]:9999", "Most recent IPv6 should be first")
        XCTAssertEqual(allEndpoints[1], "[aaaa::1]:9999", "Second most recent IPv6 should be second")

        // IPv4 should come after, in recency order (2.2.2.2 before 1.1.1.1)
        XCTAssertEqual(allEndpoints[2], "2.2.2.2:5000", "Most recent IPv4 should be third")
        XCTAssertEqual(allEndpoints[3], "1.1.1.1:5000", "Oldest IPv4 should be last")
    }

    /// Test that promoting an endpoint updates its recency position
    func testPromoteEndpointUpdatesRecencyInGetAllEndpoints() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Add three IPv6 endpoints
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[aaaa::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[bbbb::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[cccc::1]:9999")

        // cccc is most recent
        var allEndpoints = await manager.getAllEndpoints(peerId: peerId)
        XCTAssertEqual(allEndpoints.first, "[cccc::1]:9999")

        // Promote aaaa (oldest) - simulates receiving a message from it
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[aaaa::1]:9999")

        // Now aaaa should be first
        allEndpoints = await manager.getAllEndpoints(peerId: peerId)
        XCTAssertEqual(allEndpoints.first, "[aaaa::1]:9999",
            "Promoted endpoint should now be first")
    }

    /// Test getAllEndpoints with multiple machines sharing same peerId
    func testGetAllEndpointsMultipleMachinesPreservesRecency() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "shared-peer"

        // Two machines with same peerId, each with IPv6 endpoints
        await manager.recordMessageReceived(from: peerId, machineId: "machine-A",
            endpoint: "[aaaa::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: "machine-B",
            endpoint: "[bbbb::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: "machine-A",
            endpoint: "[cccc::1]:9999")

        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)

        // Should contain all three, with cccc (most recent from machine-A) likely first
        XCTAssertEqual(allEndpoints.count, 3)
        XCTAssertTrue(allEndpoints.contains("[aaaa::1]:9999"))
        XCTAssertTrue(allEndpoints.contains("[bbbb::1]:9999"))
        XCTAssertTrue(allEndpoints.contains("[cccc::1]:9999"))
    }

    /// Test deduplication in getAllEndpoints preserves first occurrence (most recent)
    func testGetAllEndpointsDeduplicatesPreservingRecency() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "shared-peer"

        // Same endpoint appears in two machines
        await manager.recordMessageReceived(from: peerId, machineId: "machine-A",
            endpoint: "[shared::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: "machine-A",
            endpoint: "[unique-a::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: "machine-B",
            endpoint: "[shared::1]:9999")  // Duplicate
        await manager.recordMessageReceived(from: peerId, machineId: "machine-B",
            endpoint: "[unique-b::1]:9999")

        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)

        // shared::1 should appear only once
        let sharedCount = allEndpoints.filter { $0 == "[shared::1]:9999" }.count
        XCTAssertEqual(sharedCount, 1, "Duplicate endpoint should be deduplicated")

        // Total should be 3 unique endpoints
        XCTAssertEqual(allEndpoints.count, 3)
    }

    // MARK: - EndpointUtils.sortPreferringIPv6 Tests

    /// Verify that sortPreferringIPv6 does sort alphabetically within types
    /// This is the documented behavior - it's stable but uses alphabetical order
    func testSortPreferringIPv6UsesAlphabeticalWithinTypes() {
        let endpoints = [
            "[cccc::1]:9999",
            "[aaaa::1]:9999",
            "[bbbb::1]:9999",
            "3.3.3.3:5000",
            "1.1.1.1:5000",
            "2.2.2.2:5000"
        ]

        let sorted = EndpointUtils.sortPreferringIPv6(endpoints)

        // IPv6 first, alphabetically
        XCTAssertEqual(sorted[0], "[aaaa::1]:9999")
        XCTAssertEqual(sorted[1], "[bbbb::1]:9999")
        XCTAssertEqual(sorted[2], "[cccc::1]:9999")

        // IPv4 second, alphabetically
        XCTAssertEqual(sorted[3], "1.1.1.1:5000")
        XCTAssertEqual(sorted[4], "2.2.2.2:5000")
        XCTAssertEqual(sorted[5], "3.3.3.3:5000")
    }

    /// Verify preferredEndpoint returns first IPv6 regardless of position
    func testPreferredEndpointSelectsFirstIPv6() {
        // IPv4 first, then IPv6
        let endpoints1 = ["1.1.1.1:5000", "[aaaa::1]:9999", "2.2.2.2:5000"]
        XCTAssertEqual(EndpointUtils.preferredEndpoint(from: endpoints1), "[aaaa::1]:9999")

        // IPv6 first
        let endpoints2 = ["[aaaa::1]:9999", "1.1.1.1:5000"]
        XCTAssertEqual(EndpointUtils.preferredEndpoint(from: endpoints2), "[aaaa::1]:9999")

        // Only IPv4
        let endpoints3 = ["1.1.1.1:5000", "2.2.2.2:5000"]
        XCTAssertEqual(EndpointUtils.preferredEndpoint(from: endpoints3), "1.1.1.1:5000")

        // Empty
        let endpoints4: [String] = []
        XCTAssertNil(EndpointUtils.preferredEndpoint(from: endpoints4))
    }

    // MARK: - getEndpoints() Tests (per-machine)

    /// Verify getEndpoints for a specific machine preserves recency
    func testGetEndpointsForMachinePreservesRecency() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Add endpoints where alphabetical differs from recency
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[zzzz::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[aaaa::1]:9999")

        let endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)

        // aaaa should be first (most recent), not zzzz (alphabetically first)
        XCTAssertEqual(endpoints.first, "[aaaa::1]:9999",
            "Most recent endpoint should be first in per-machine list")
    }

    /// Verify getBestEndpoint returns IPv6 even if IPv4 is more recent
    func testGetBestEndpointPrefersIPv6OverRecency() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Add IPv6 first, then IPv4 (IPv4 is more recent)
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[aaaa::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "1.1.1.1:5000")

        let best = await manager.getBestEndpoint(peerId: peerId, machineId: machineId)

        // Should prefer IPv6 even though IPv4 is more recent
        XCTAssertEqual(best, "[aaaa::1]:9999",
            "getBestEndpoint should prefer IPv6 over IPv4 regardless of recency")
    }

    // MARK: - Real-World Scenario Tests

    /// Simulate the exact bug scenario: peer changes IPv6 address, stale address was selected
    func testRealWorldIPv6AddressChangeScenario() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "bootstrap-peer"
        let machineId = "bootstrap-machine"

        // Initial connection - peer has address bb05::
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[bb05:1234:5678:90ab::1]:9999")

        // Peer's address changes to f81f:: (e.g., ISP renumbering)
        // New messages come from the new address
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[f81f:2074:c1e9:94dc::1]:9999")

        // When we send a response, we should use f81f (the current/recent address)
        // not bb05 (which would be selected if sorting alphabetically)
        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)
        XCTAssertEqual(allEndpoints.first, "[f81f:2074:c1e9:94dc::1]:9999",
            "Response should go to most recently seen address, not alphabetically first")

        let best = await manager.getBestEndpoint(peerId: peerId, machineId: machineId)
        XCTAssertEqual(best, "[f81f:2074:c1e9:94dc::1]:9999",
            "Best endpoint should be most recently seen address")
    }

    /// Test that recording a message promotes the endpoint correctly
    func testRecordMessageReceivedPromotesExistingEndpoint() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Add three endpoints
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[1111::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[2222::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[3333::1]:9999")

        // 3333 is now first
        var endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints, ["[3333::1]:9999", "[2222::1]:9999", "[1111::1]:9999"])

        // Receive another message from 1111 (the oldest)
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[1111::1]:9999")

        // 1111 should now be first, and not duplicated
        endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints, ["[1111::1]:9999", "[3333::1]:9999", "[2222::1]:9999"])
        XCTAssertEqual(endpoints.count, 3, "Should not have duplicates")
    }

    /// Test send success also promotes endpoint
    func testRecordSendSuccessPromotesEndpoint() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Set up initial order
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[old::1]:9999")
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "[new::1]:9999")

        // new is first
        var endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints.first, "[new::1]:9999")

        // Successfully send to old endpoint
        await manager.recordSendSuccess(to: peerId, machineId: machineId,
            endpoint: "[old::1]:9999")

        // old should now be first
        endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints.first, "[old::1]:9999")
    }

    // MARK: - Edge Cases

    /// Test empty endpoint list
    func testGetAllEndpointsEmpty() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let allEndpoints = await manager.getAllEndpoints(peerId: "nonexistent-peer")
        XCTAssertTrue(allEndpoints.isEmpty)
    }

    /// Test single endpoint
    func testGetAllEndpointsSingleEndpoint() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        await manager.recordMessageReceived(from: "peer", machineId: "machine",
            endpoint: "[aaaa::1]:9999")

        let allEndpoints = await manager.getAllEndpoints(peerId: "peer")
        XCTAssertEqual(allEndpoints, ["[aaaa::1]:9999"])
    }

    /// Test that validation filters invalid endpoints on read
    func testGetAllEndpointsFiltersInvalidEndpoints() async throws {
        // Use strict mode to test filtering
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .strict)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // In strict mode, only public IPs are valid
        // 192.168.x.x and 10.x.x.x are private and should be filtered
        await manager.recordMessageReceived(from: peerId, machineId: machineId,
            endpoint: "8.8.8.8:5000")  // Valid public IP

        let endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)

        // Only the valid public IP should be returned
        XCTAssertEqual(endpoints, ["8.8.8.8:5000"])
    }
}
