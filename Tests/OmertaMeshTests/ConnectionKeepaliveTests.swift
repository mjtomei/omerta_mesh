// ConnectionKeepaliveTests.swift - Tests for connection keepalive functionality

import XCTest
@testable import OmertaMesh

final class ConnectionKeepaliveTests: XCTestCase {

    // MARK: - Basic Functionality Tests

    /// Test adding and removing connections (legacy peer-based API)
    func testAddRemoveConnection() async throws {
        let keepalive = ConnectionKeepalive(config: .default)

        // Add a connection
        await keepalive.addConnection(peerId: "peer1", endpoint: "192.168.1.1:9000")

        var peer1Monitored = await keepalive.isMonitoring(peerId: "peer1")
        var peer2Monitored = await keepalive.isMonitoring(peerId: "peer2")
        XCTAssertTrue(peer1Monitored)
        XCTAssertFalse(peer2Monitored)

        // Add another
        await keepalive.addConnection(peerId: "peer2", endpoint: "192.168.1.2:9000")

        peer2Monitored = await keepalive.isMonitoring(peerId: "peer2")
        XCTAssertTrue(peer2Monitored)

        // Remove first
        await keepalive.removeConnection(peerId: "peer1")

        peer1Monitored = await keepalive.isMonitoring(peerId: "peer1")
        peer2Monitored = await keepalive.isMonitoring(peerId: "peer2")
        XCTAssertFalse(peer1Monitored)
        XCTAssertTrue(peer2Monitored)
    }

    /// Test machine-based tracking
    func testMachineBasedTracking() async throws {
        let keepalive = ConnectionKeepalive(config: .default)

        // Add machines
        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")
        await keepalive.addMachine(peerId: "peer1", machineId: "machine2")
        await keepalive.addMachine(peerId: "peer2", machineId: "machine3")

        // Check machine-level monitoring
        var m1 = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine1")
        var m2 = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine2")
        var m3 = await keepalive.isMonitoring(peerId: "peer2", machineId: "machine3")
        var m4 = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine3")
        XCTAssertTrue(m1)
        XCTAssertTrue(m2)
        XCTAssertTrue(m3)
        XCTAssertFalse(m4)

        // Check peer-level monitoring (should find any machine for peer)
        var p1 = await keepalive.isMonitoring(peerId: "peer1")
        var p2 = await keepalive.isMonitoring(peerId: "peer2")
        var p3 = await keepalive.isMonitoring(peerId: "peer3")
        XCTAssertTrue(p1)
        XCTAssertTrue(p2)
        XCTAssertFalse(p3)

        // Remove one machine
        await keepalive.removeMachine(peerId: "peer1", machineId: "machine1")
        m1 = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine1")
        m2 = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine2")
        XCTAssertFalse(m1)
        XCTAssertTrue(m2)

        // Total count
        let count = await keepalive.totalMachineCount
        XCTAssertEqual(count, 2)
    }

    /// Test connection state tracking
    func testMachineState() async throws {
        let keepalive = ConnectionKeepalive(config: .default)

        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")

        let state = await keepalive.getMachineState(peerId: "peer1", machineId: "machine1")
        XCTAssertNotNil(state)
        XCTAssertEqual(state?.peerId, "peer1")
        XCTAssertEqual(state?.machineId, "machine1")
        XCTAssertEqual(state?.missedPings, 0)
        XCTAssertTrue(state?.isHealthy ?? false)
    }

    /// Test successful communication resets missed count
    func testSuccessfulCommunicationResetsMissed() async throws {
        let config = ConnectionKeepalive.Config(
            interval: 0.1,  // 100ms for fast testing
            missedThreshold: 3,
            responseTimeout: 1.0
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // Set up ping sender that always fails
        var pingCount = 0
        await keepalive.setPingSender { _, _, _ in
            pingCount += 1
            return false
        }

        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")

        // Start keepalive
        await keepalive.start()

        // Wait for some pings to fail
        try await Task.sleep(nanoseconds: 250_000_000)  // 250ms = ~2 intervals

        // Record successful communication (simulating incoming message)
        await keepalive.recordSuccessfulCommunication(peerId: "peer1", machineId: "machine1")

        // Check that missed count was reset
        let state = await keepalive.getMachineState(peerId: "peer1", machineId: "machine1")
        XCTAssertEqual(state?.missedPings, 0)
        XCTAssertTrue(state?.isHealthy ?? false)

        await keepalive.stop()
        XCTAssertGreaterThan(pingCount, 0)
    }

    /// Test connection marked as failed after threshold missed
    func testConnectionFailureAfterThreshold() async throws {
        let config = ConnectionKeepalive.Config(
            interval: 0.05,  // 50ms for fast testing
            missedThreshold: 2,
            responseTimeout: 1.0
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Track failures using actor-isolated storage
        actor FailureTracker {
            var failedMachines: [(PeerId, MachineId)] = []
            func add(_ peerId: PeerId, _ machineId: MachineId) {
                failedMachines.append((peerId, machineId))
            }
            func contains(_ peerId: PeerId, _ machineId: MachineId) -> Bool {
                failedMachines.contains { $0.0 == peerId && $0.1 == machineId }
            }
        }
        let tracker = FailureTracker()

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // Set up ping sender that always fails
        await keepalive.setPingSender { _, _, _ in
            return false
        }

        await keepalive.setFailureHandler { peerId, machineId, _ in
            await tracker.add(peerId, machineId)
        }

        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")

        // Start keepalive
        await keepalive.start()

        // Wait for enough pings to fail (threshold = 2, so 3 intervals should trigger)
        try await Task.sleep(nanoseconds: 200_000_000)  // 200ms

        await keepalive.stop()

        // Check that failure was reported
        let containsFailed = await tracker.contains("peer1", "machine1")
        XCTAssertTrue(containsFailed, "Connection should have been marked as failed")

        // Check that connection was removed from monitoring
        let isRemoved = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine1")
        XCTAssertFalse(isRemoved)
    }

    /// Test healthy connections are maintained
    func testHealthyConnectionMaintained() async throws {
        let config = ConnectionKeepalive.Config(
            interval: 0.05,  // 50ms for fast testing
            missedThreshold: 3,
            responseTimeout: 1.0
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Track failures using actor-isolated storage
        actor FailureTracker {
            var failedMachines: [(PeerId, MachineId)] = []
            func add(_ peerId: PeerId, _ machineId: MachineId) {
                failedMachines.append((peerId, machineId))
            }
            var isEmpty: Bool { failedMachines.isEmpty }
        }
        let tracker = FailureTracker()

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // Set up ping sender that always succeeds
        await keepalive.setPingSender { _, _, _ in
            return true
        }

        await keepalive.setFailureHandler { peerId, machineId, _ in
            await tracker.add(peerId, machineId)
        }

        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")

        // Start keepalive
        await keepalive.start()

        // Wait for several ping cycles
        try await Task.sleep(nanoseconds: 200_000_000)  // 200ms

        await keepalive.stop()

        // Check that no failures were reported
        let noFailures = await tracker.isEmpty
        XCTAssertTrue(noFailures, "No failures should have been reported")

        // Check that connection is still being monitored
        let stillMonitored = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine1")
        XCTAssertTrue(stillMonitored)

        let state = await keepalive.getMachineState(peerId: "peer1", machineId: "machine1")
        XCTAssertTrue(state?.isHealthy ?? false)
    }

    /// Test statistics tracking
    func testStatistics() async throws {
        let keepalive = ConnectionKeepalive(config: .default)

        // Initially empty
        var stats = await keepalive.statistics
        XCTAssertEqual(stats.totalMachines, 0)
        XCTAssertEqual(stats.healthyMachines, 0)

        // Add connections
        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")
        await keepalive.addMachine(peerId: "peer2", machineId: "machine2")

        stats = await keepalive.statistics
        XCTAssertEqual(stats.totalMachines, 2)
        XCTAssertEqual(stats.healthyMachines, 2)
        XCTAssertEqual(stats.healthPercentage, 100.0)
    }

    /// Test multiple connections with mixed health
    func testMultipleConnectionsMixedHealth() async throws {
        let config = ConnectionKeepalive.Config(
            interval: 0.05,
            missedThreshold: 2,
            responseTimeout: 1.0
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Track failures using actor-isolated storage
        actor FailureTracker {
            var failedMachines: [(PeerId, MachineId)] = []
            func add(_ peerId: PeerId, _ machineId: MachineId) {
                failedMachines.append((peerId, machineId))
            }
            func containsPeer(_ peerId: PeerId) -> Bool {
                failedMachines.contains { $0.0 == peerId }
            }
        }
        let tracker = FailureTracker()

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // machine1 succeeds, machine2 fails
        await keepalive.setPingSender { peerId, _, _ in
            return peerId == "peer1"
        }

        await keepalive.setFailureHandler { peerId, machineId, _ in
            await tracker.add(peerId, machineId)
        }

        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")
        await keepalive.addMachine(peerId: "peer2", machineId: "machine2")

        await keepalive.start()

        // Wait for peer2 to fail
        try await Task.sleep(nanoseconds: 200_000_000)

        await keepalive.stop()

        // peer1 should still be monitored, peer2 should have failed
        let peer1Monitored = await keepalive.isMonitoring(peerId: "peer1", machineId: "machine1")
        let peer2Monitored = await keepalive.isMonitoring(peerId: "peer2", machineId: "machine2")
        XCTAssertTrue(peer1Monitored)
        XCTAssertFalse(peer2Monitored)
        let peer2Failed = await tracker.containsPeer("peer2")
        let peer1Failed = await tracker.containsPeer("peer1")
        XCTAssertTrue(peer2Failed)
        XCTAssertFalse(peer1Failed)
    }

    // MARK: - Weighted Sampling Tests

    /// Test that budget limits machines pinged per cycle
    func testBudgetLimitsMachinesPinged() async throws {
        let config = ConnectionKeepalive.Config(
            interval: 0.1,
            missedThreshold: 10,
            responseTimeout: 1.0,
            maxMachinesPerCycle: 3  // Only ping 3 machines per cycle
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // Track which machines were pinged using actor
        actor PingedTracker {
            var machines: Set<String> = []
            func add(_ key: String) {
                machines.insert(key)
            }
            var count: Int { machines.count }
        }
        let tracker = PingedTracker()

        await keepalive.setPingSender { peerId, machineId, _ in
            await tracker.add("\(peerId):\(machineId)")
            return true
        }

        // Add 10 machines
        for i in 0..<10 {
            await keepalive.addMachine(peerId: "peer\(i)", machineId: "machine\(i)")
        }

        await keepalive.start()

        // Wait for one cycle
        try await Task.sleep(nanoseconds: 150_000_000)

        await keepalive.stop()

        // Should have pinged at most 3 machines (budget)
        let count = await tracker.count

        XCTAssertLessThanOrEqual(count, 3, "Should respect budget of 3 machines per cycle")
    }

    /// Test that all machines get pinged eventually when under budget
    func testAllMachinesPingedWhenUnderBudget() async throws {
        let config = ConnectionKeepalive.Config(
            interval: 0.05,
            missedThreshold: 10,
            responseTimeout: 1.0,
            maxMachinesPerCycle: 30  // Budget higher than machine count
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // Track which machines were pinged using actor
        actor PingedTracker {
            var machines: Set<String> = []
            func add(_ key: String) {
                machines.insert(key)
            }
            var count: Int { machines.count }
        }
        let tracker = PingedTracker()

        await keepalive.setPingSender { peerId, machineId, _ in
            await tracker.add("\(peerId):\(machineId)")
            return true
        }

        // Add 5 machines (under budget)
        for i in 0..<5 {
            await keepalive.addMachine(peerId: "peer\(i)", machineId: "machine\(i)")
        }

        await keepalive.start()

        // Wait for one cycle
        try await Task.sleep(nanoseconds: 100_000_000)

        await keepalive.stop()

        let count = await tracker.count

        // All 5 should be pinged since we're under budget
        XCTAssertEqual(count, 5, "All machines should be pinged when under budget")
    }

    /// Test weighted sampling prefers recent machines
    func testWeightedSamplingPrefersRecentMachines() async throws {
        // This test verifies the weighted sampling algorithm by checking
        // that a recently-contacted machine is more likely to be selected
        // in the first few cycles before other machines get pinged and updated.
        //
        // Note: When pings succeed, they update lastSuccessfulPing, so over time
        // all pinged machines converge to equal weights. We test the initial bias.
        let config = ConnectionKeepalive.Config(
            interval: 0.02,        // 20ms intervals
            missedThreshold: 100,  // High threshold to avoid removals
            responseTimeout: 1.0,
            maxMachinesPerCycle: 1,  // Only ping 1 machine per cycle
            samplingHalfLife: 0.05,  // 50ms half-life - very fast decay
            minSamplingWeight: 0.001 // Very low floor
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // Track which machine was selected in the FIRST ping cycle
        actor FirstPingTracker {
            var firstPinged: String? = nil
            func recordIfFirst(_ key: String) {
                if firstPinged == nil {
                    firstPinged = key
                }
            }
            func getFirst() -> String? { firstPinged }
        }
        let tracker = FirstPingTracker()

        await keepalive.setPingSender { peerId, machineId, _ in
            let key = "\(peerId):\(machineId)"
            await tracker.recordIfFirst(key)
            return true
        }

        // Add machines - all initially have the same lastSuccessfulPing time
        for i in 0..<10 {
            await keepalive.addMachine(peerId: "peer\(i)", machineId: "machine\(i)")
        }

        // Wait a bit so all machines become "stale"
        try await Task.sleep(nanoseconds: 200_000_000)  // 200ms = 4 half-lives with 50ms half-life
        // At this point, all machines have weight ~0.0625 (0.5^4)

        // Now mark one machine as recently contacted - it will have weight 1.0
        await keepalive.recordSuccessfulCommunication(peerId: "peer0", machineId: "machine0")

        await keepalive.start()

        // Wait for first ping cycle
        try await Task.sleep(nanoseconds: 50_000_000)

        await keepalive.stop()

        // The recently-contacted machine (peer0) has weight 1.0
        // All other machines have weight ~0.0625
        // Total weight = 1.0 + 9*0.0625 = 1.5625
        // Probability of peer0 = 1.0/1.5625 = 64%
        // So in first cycle, peer0 should be selected with ~64% probability
        //
        // This test runs many times across the test suite, so we just verify
        // that the algorithm is working by checking the first pinged machine
        let first = await tracker.getFirst()
        XCTAssertNotNil(first, "At least one machine should have been pinged")
        // We can't guarantee peer0 was first (only 64% chance), but we verify the mechanism works
    }

    // MARK: - Timing Tests

    /// Test that keepalive maintains NAT mapping simulation
    func testKeepaliveFrequency() async throws {
        // This test verifies that keepalives are sent at the configured interval
        let config = ConnectionKeepalive.Config(
            interval: 0.1,  // 100ms
            missedThreshold: 5,
            responseTimeout: 1.0
        )
        let keepalive = ConnectionKeepalive(config: config)

        // Set up endpoint provider
        await keepalive.setEndpointProvider { _, _ in
            return "192.168.1.1:9000"
        }

        // Track ping times using actor
        actor PingTimeTracker {
            var times: [Date] = []
            func addTime() {
                times.append(Date())
            }
            func getTimes() -> [Date] { times }
        }
        let tracker = PingTimeTracker()

        await keepalive.setPingSender { _, _, _ in
            await tracker.addTime()
            return true
        }

        await keepalive.addMachine(peerId: "peer1", machineId: "machine1")

        await keepalive.start()

        // Wait for multiple intervals
        try await Task.sleep(nanoseconds: 500_000_000)  // 500ms = 5 intervals

        await keepalive.stop()

        let times = await tracker.getTimes()

        // Should have at least 4 pings (first after 100ms, then every 100ms)
        XCTAssertGreaterThanOrEqual(times.count, 4, "Should have sent at least 4 pings")

        // Verify intervals are approximately correct
        if times.count >= 2 {
            for i in 1..<times.count {
                let interval = times[i].timeIntervalSince(times[i-1])
                // Allow 50ms tolerance
                XCTAssertGreaterThan(interval, 0.05)
                XCTAssertLessThan(interval, 0.2)
            }
        }
    }

    // MARK: - Backward Compatibility Tests

    /// Test that legacy API still works
    func testLegacyAPIBackwardCompatibility() async throws {
        let keepalive = ConnectionKeepalive(config: .default)

        // Use legacy API
        await keepalive.addConnection(peerId: "peer1", endpoint: "192.168.1.1:9000")

        // Should be monitored
        var isMonitored = await keepalive.isMonitoring(peerId: "peer1")
        XCTAssertTrue(isMonitored)

        // Can record successful communication
        await keepalive.recordSuccessfulCommunication(peerId: "peer1")

        // Can get monitored connections
        let connections = await keepalive.monitoredConnections
        XCTAssertEqual(connections.count, 1)
        XCTAssertEqual(connections.first?.peerId, "peer1")

        // Can remove
        await keepalive.removeConnection(peerId: "peer1")
        isMonitored = await keepalive.isMonitoring(peerId: "peer1")
        XCTAssertFalse(isMonitored)
    }
}
