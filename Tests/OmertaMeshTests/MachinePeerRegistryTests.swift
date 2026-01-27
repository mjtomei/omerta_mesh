// MachinePeerRegistryTests.swift - Tests for machine-peer association tracking

import XCTest
@testable import OmertaMesh

final class MachinePeerRegistryTests: XCTestCase {

    // MARK: - Basic Registration Tests

    func testEmptyRegistryHasNoAssociations() async {
        let registry = MachinePeerRegistry()

        let peer = await registry.getMostRecentPeer(for: "machine-1")
        XCTAssertNil(peer, "Empty registry should return nil for unknown machine")

        let machine = await registry.getMostRecentMachine(for: "peer-1")
        XCTAssertNil(machine, "Empty registry should return nil for unknown peer")

        let machineCount = await registry.machineCount
        XCTAssertEqual(machineCount, 0)

        let peerCount = await registry.peerCount
        XCTAssertEqual(peerCount, 0)
    }

    func testBasicRegistration() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("machine-1", peer: "peer-1")

        let peer = await registry.getMostRecentPeer(for: "machine-1")
        XCTAssertEqual(peer, "peer-1")

        let machine = await registry.getMostRecentMachine(for: "peer-1")
        XCTAssertEqual(machine, "machine-1")

        let hasPeer = await registry.hasPeer(for: "machine-1")
        XCTAssertTrue(hasPeer)

        let hasMachine = await registry.hasMachine(for: "peer-1")
        XCTAssertTrue(hasMachine)
    }

    func testSubscriptAccess() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("machine-1", peer: "peer-1")

        let peer = await registry[machine: "machine-1"]
        XCTAssertEqual(peer, "peer-1")

        let unknownPeer = await registry[machine: "unknown-machine"]
        XCTAssertNil(unknownPeer)
    }

    // MARK: - Multiple Peers Per Machine (Identity Changes)

    func testOneMachineMultiplePeers() async {
        let registry = MachinePeerRegistry()

        // Same machine, different peers over time (simulates identity change)
        await registry.setMachine("machine-1", peer: "peer-old")
        try? await Task.sleep(nanoseconds: 1_000_000) // 1ms to ensure different timestamps
        await registry.setMachine("machine-1", peer: "peer-new")

        // Most recent peer should be returned
        let mostRecentPeer = await registry.getMostRecentPeer(for: "machine-1")
        XCTAssertEqual(mostRecentPeer, "peer-new", "Most recent peer should be returned")

        // All peers should be tracked
        let allPeers = await registry.getAllPeers(for: "machine-1")
        XCTAssertEqual(allPeers.count, 2, "Both peers should be tracked")
        XCTAssertEqual(allPeers[0].peerId, "peer-new", "Most recent peer should be first")
        XCTAssertEqual(allPeers[1].peerId, "peer-old", "Older peer should be second")
    }

    func testMachineIdentityChangeUpdatesRecency() async {
        let registry = MachinePeerRegistry()

        // Register in order: A, B, A again
        await registry.setMachine("machine-1", peer: "peer-A")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("machine-1", peer: "peer-B")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("machine-1", peer: "peer-A") // A is now most recent

        let mostRecentPeer = await registry.getMostRecentPeer(for: "machine-1")
        XCTAssertEqual(mostRecentPeer, "peer-A", "Re-registering should update recency")

        let allPeers = await registry.getAllPeers(for: "machine-1")
        XCTAssertEqual(allPeers.count, 2, "Should still only have 2 unique peers")
        XCTAssertEqual(allPeers[0].peerId, "peer-A", "Re-registered peer should be first")
        XCTAssertEqual(allPeers[1].peerId, "peer-B", "Other peer should be second")
    }

    // MARK: - Multiple Machines Per Peer (Same User, Different Computers)

    func testOnePeerMultipleMachines() async {
        let registry = MachinePeerRegistry()

        // Same peer, different machines (same user on laptop and desktop)
        await registry.setMachine("laptop", peer: "alice")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("desktop", peer: "alice")

        // Most recent machine should be returned
        let mostRecentMachine = await registry.getMostRecentMachine(for: "alice")
        XCTAssertEqual(mostRecentMachine, "desktop", "Most recent machine should be returned")

        // All machines should be tracked
        let allMachines = await registry.getAllMachines(for: "alice")
        XCTAssertEqual(allMachines.count, 2, "Both machines should be tracked")
        XCTAssertEqual(allMachines[0].machineId, "desktop", "Most recent machine should be first")
        XCTAssertEqual(allMachines[1].machineId, "laptop", "Older machine should be second")
    }

    func testPeerActivityOnDifferentMachinesUpdatesRecency() async {
        let registry = MachinePeerRegistry()

        // Register peer on multiple machines, then activity on first machine again
        await registry.setMachine("laptop", peer: "alice")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("desktop", peer: "alice")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("laptop", peer: "alice") // Laptop is now most recent

        let mostRecentMachine = await registry.getMostRecentMachine(for: "alice")
        XCTAssertEqual(mostRecentMachine, "laptop", "Re-registering should update recency")

        let allMachines = await registry.getAllMachines(for: "alice")
        XCTAssertEqual(allMachines.count, 2)
        XCTAssertEqual(allMachines[0].machineId, "laptop")
        XCTAssertEqual(allMachines[1].machineId, "desktop")
    }

    // MARK: - Complex Scenarios

    func testManyToManyRelationships() async {
        let registry = MachinePeerRegistry()

        // Alice uses laptop and desktop
        await registry.setMachine("laptop-1", peer: "alice")
        await registry.setMachine("desktop-1", peer: "alice")

        // Bob uses a different laptop and the same desktop (shared computer!)
        await registry.setMachine("laptop-2", peer: "bob")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("desktop-1", peer: "bob") // Bob now on shared desktop

        // Desktop should now show Bob as most recent peer
        let desktopPeer = await registry.getMostRecentPeer(for: "desktop-1")
        XCTAssertEqual(desktopPeer, "bob", "Most recent user of shared desktop should be Bob")

        // Desktop should have both Alice and Bob in history
        let desktopPeers = await registry.getAllPeers(for: "desktop-1")
        XCTAssertEqual(desktopPeers.count, 2)
        XCTAssertEqual(desktopPeers[0].peerId, "bob")
        XCTAssertEqual(desktopPeers[1].peerId, "alice")

        // Alice should still have 2 machines (desktop history preserved)
        let aliceMachines = await registry.getAllMachines(for: "alice")
        XCTAssertEqual(aliceMachines.count, 2)
    }

    // MARK: - Timestamp Tracking

    func testTimestampsAreRecorded() async {
        let registry = MachinePeerRegistry()

        let beforeRegistration = Date()
        try? await Task.sleep(nanoseconds: 1_000_000)

        await registry.setMachine("machine-1", peer: "peer-1")

        try? await Task.sleep(nanoseconds: 1_000_000)
        let afterRegistration = Date()

        let association = await registry.getAssociation(machineId: "machine-1", peerId: "peer-1")
        XCTAssertNotNil(association)

        if let assoc = association {
            XCTAssertTrue(assoc.lastSeen > beforeRegistration, "Timestamp should be after start")
            XCTAssertTrue(assoc.lastSeen < afterRegistration, "Timestamp should be before end")
        }
    }

    func testTimestampUpdatesOnReRegistration() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("machine-1", peer: "peer-1")

        let firstAssociation = await registry.getAssociation(machineId: "machine-1", peerId: "peer-1")
        let firstTimestamp = firstAssociation?.lastSeen

        try? await Task.sleep(nanoseconds: 10_000_000) // 10ms

        await registry.setMachine("machine-1", peer: "peer-1") // Re-register same pair

        let secondAssociation = await registry.getAssociation(machineId: "machine-1", peerId: "peer-1")
        let secondTimestamp = secondAssociation?.lastSeen

        XCTAssertNotNil(firstTimestamp)
        XCTAssertNotNil(secondTimestamp)
        if let first = firstTimestamp, let second = secondTimestamp {
            XCTAssertTrue(second > first, "Timestamp should be updated on re-registration")
        }
    }

    // MARK: - Stale Cleanup Tests

    func testRemoveStaleAssociations() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("machine-1", peer: "peer-1")

        // Wait a bit
        try? await Task.sleep(nanoseconds: 50_000_000) // 50ms

        // Add another association
        await registry.setMachine("machine-2", peer: "peer-2")

        // Remove associations older than 25ms (should remove first, keep second)
        await registry.removeStale(olderThan: 0.025)

        let peer1 = await registry.getMostRecentPeer(for: "machine-1")
        let peer2 = await registry.getMostRecentPeer(for: "machine-2")

        XCTAssertNil(peer1, "Old association should be removed")
        XCTAssertEqual(peer2, "peer-2", "Recent association should be kept")
    }

    func testRemoveStalePreservesRecentAssociationsForSameMachine() async {
        let registry = MachinePeerRegistry()

        // Old peer on machine
        await registry.setMachine("machine-1", peer: "peer-old")

        try? await Task.sleep(nanoseconds: 50_000_000) // 50ms

        // New peer on same machine
        await registry.setMachine("machine-1", peer: "peer-new")

        // Remove stale (older than 25ms)
        await registry.removeStale(olderThan: 0.025)

        let allPeers = await registry.getAllPeers(for: "machine-1")
        XCTAssertEqual(allPeers.count, 1, "Only recent peer should remain")
        XCTAssertEqual(allPeers[0].peerId, "peer-new")
    }

    // MARK: - Statistics Tests

    func testMachineAndPeerCounts() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("machine-1", peer: "peer-1")
        await registry.setMachine("machine-2", peer: "peer-2")
        await registry.setMachine("machine-3", peer: "peer-1") // Same peer, different machine

        let machineCount = await registry.machineCount
        let peerCount = await registry.peerCount

        XCTAssertEqual(machineCount, 3, "Should have 3 unique machines")
        XCTAssertEqual(peerCount, 2, "Should have 2 unique peers")
    }

    // MARK: - Edge Cases

    func testEmptyMachineIdAndPeerId() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("", peer: "")

        let peer = await registry.getMostRecentPeer(for: "")
        XCTAssertEqual(peer, "", "Empty strings should work as keys")

        let machine = await registry.getMostRecentMachine(for: "")
        XCTAssertEqual(machine, "")
    }

    func testHasPeerAndHasMachineForUnknown() async {
        let registry = MachinePeerRegistry()

        let hasPeer = await registry.hasPeer(for: "unknown-machine")
        XCTAssertFalse(hasPeer)

        let hasMachine = await registry.hasMachine(for: "unknown-peer")
        XCTAssertFalse(hasMachine)
    }

    func testGetAssociationReturnsNilForUnknownPair() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("machine-1", peer: "peer-1")

        // Known machine, unknown peer
        let assoc1 = await registry.getAssociation(machineId: "machine-1", peerId: "peer-2")
        XCTAssertNil(assoc1)

        // Unknown machine, known peer
        let assoc2 = await registry.getAssociation(machineId: "machine-2", peerId: "peer-1")
        XCTAssertNil(assoc2)

        // Both unknown
        let assoc3 = await registry.getAssociation(machineId: "machine-2", peerId: "peer-2")
        XCTAssertNil(assoc3)

        // Known pair should work
        let assoc4 = await registry.getAssociation(machineId: "machine-1", peerId: "peer-1")
        XCTAssertNotNil(assoc4)
    }

    // MARK: - Concurrency Tests

    func testConcurrentRegistrations() async {
        let registry = MachinePeerRegistry()

        // Simulate concurrent registrations from multiple sources
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<100 {
                group.addTask {
                    let machineId = "machine-\(i % 10)"
                    let peerId = "peer-\(i % 5)"
                    await registry.setMachine(machineId, peer: peerId)
                }
            }
        }

        // Verify registry is consistent
        let machineCount = await registry.machineCount
        let peerCount = await registry.peerCount

        XCTAssertEqual(machineCount, 10, "Should have 10 unique machines")
        XCTAssertEqual(peerCount, 5, "Should have 5 unique peers")
    }

    // MARK: - Require Methods Tests

    func testRequirePeerThrowsWhenNotFound() async {
        let registry = MachinePeerRegistry()

        do {
            _ = try await registry.requirePeer(for: "unknown-machine")
            XCTFail("Expected RegistryError.peerNotFound")
        } catch let error as RegistryError {
            switch error {
            case .peerNotFound(let machineId):
                XCTAssertEqual(machineId, "unknown-machine")
            default:
                XCTFail("Expected peerNotFound, got \(error)")
            }
        } catch {
            XCTFail("Expected RegistryError, got \(error)")
        }
    }

    func testRequirePeerSucceedsWhenFound() async throws {
        let registry = MachinePeerRegistry()
        await registry.setMachine("machine-1", peer: "peer-1")

        let peerId = try await registry.requirePeer(for: "machine-1")
        XCTAssertEqual(peerId, "peer-1")
    }

    func testRequireMachineThrowsWhenNotFound() async {
        let registry = MachinePeerRegistry()

        do {
            _ = try await registry.requireMachine(for: "unknown-peer")
            XCTFail("Expected RegistryError.machineNotFound")
        } catch let error as RegistryError {
            switch error {
            case .machineNotFound(let peerId):
                XCTAssertEqual(peerId, "unknown-peer")
            default:
                XCTFail("Expected machineNotFound, got \(error)")
            }
        } catch {
            XCTFail("Expected RegistryError, got \(error)")
        }
    }

    func testRequireMachineSucceedsWhenFound() async throws {
        let registry = MachinePeerRegistry()
        await registry.setMachine("machine-1", peer: "peer-1")

        let machineId = try await registry.requireMachine(for: "peer-1")
        XCTAssertEqual(machineId, "machine-1")
    }

    func testRegistryErrorDescriptions() {
        let peerNotFound = RegistryError.peerNotFound(machineId: "test-machine-12345678")
        XCTAssertTrue(peerNotFound.errorDescription?.contains("test-machine") ?? false)

        let machineNotFound = RegistryError.machineNotFound(peerId: "test-peer-12345678")
        XCTAssertTrue(machineNotFound.errorDescription?.contains("test-peer") ?? false)
    }

    // MARK: - Bidirectional Consistency Tests

    func testBidirectionalConsistency() async {
        let registry = MachinePeerRegistry()

        await registry.setMachine("machine-A", peer: "peer-1")
        await registry.setMachine("machine-B", peer: "peer-1")
        await registry.setMachine("machine-A", peer: "peer-2")

        // Check from machine perspective
        let machineAPeers = await registry.getAllPeers(for: "machine-A")
        XCTAssertEqual(machineAPeers.count, 2)
        XCTAssertEqual(machineAPeers[0].peerId, "peer-2") // Most recent
        XCTAssertEqual(machineAPeers[1].peerId, "peer-1")

        // Check from peer perspective - peer-1 should have both machines
        let peer1Machines = await registry.getAllMachines(for: "peer-1")
        XCTAssertEqual(peer1Machines.count, 2)

        // peer-2 should only have machine-A
        let peer2Machines = await registry.getAllMachines(for: "peer-2")
        XCTAssertEqual(peer2Machines.count, 1)
        XCTAssertEqual(peer2Machines[0].machineId, "machine-A")
    }

    // MARK: - Usage Pattern Tests

    /// This test demonstrates why responses should use machineId, not peerId.
    /// When a peer has multiple machines, using peerId for responses could
    /// send the response to the wrong machine.
    func testPeerWithMultipleMachinesRequiresMachineIdForResponses() async {
        let registry = MachinePeerRegistry()

        // Alice has a laptop and desktop
        await registry.setMachine("alice-laptop", peer: "alice")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("alice-desktop", peer: "alice")

        // When receiving a request from alice-laptop, we have the machineId
        let requestFromMachineId: MachineId = "alice-laptop"

        // Looking up peer identity (if needed for authorization) is fine
        let peerIdentity = await registry.getMostRecentPeer(for: requestFromMachineId)
        XCTAssertEqual(peerIdentity, "alice", "Should correctly identify Alice")

        // BUT: If we try to get a machineId from peerId for responding, we get the WRONG machine!
        let mostRecentMachineForAlice = await registry.getMostRecentMachine(for: "alice")
        XCTAssertEqual(mostRecentMachineForAlice, "alice-desktop",
                       "getMostRecentMachine returns desktop, not laptop!")
        XCTAssertNotEqual(mostRecentMachineForAlice, requestFromMachineId,
                          "This demonstrates why using getMostRecentMachine for responses is wrong!")

        // CORRECT: Use the machineId from the handler directly for responses
        // requestFromMachineId == "alice-laptop" is the correct target
    }

    /// This test validates that getMostRecentMachine should only be used for
    /// initiating new connections, not for responding.
    func testGetMostRecentMachineForNewConnections() async {
        let registry = MachinePeerRegistry()

        // Bob uses his desktop most recently
        await registry.setMachine("bob-laptop", peer: "bob")
        try? await Task.sleep(nanoseconds: 1_000_000)
        await registry.setMachine("bob-desktop", peer: "bob")

        // When initiating a NEW connection to Bob (not responding):
        // - We don't have a machineId from a handler
        // - We want to reach Bob on his most active machine
        let machineToConnect = await registry.getMostRecentMachine(for: "bob")
        XCTAssertEqual(machineToConnect, "bob-desktop",
                       "For new connections, getMostRecentMachine picks the most active machine")

        // This is the ONLY appropriate use of getMostRecentMachine
    }
}
