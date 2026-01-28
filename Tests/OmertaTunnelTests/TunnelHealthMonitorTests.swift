// TunnelHealthMonitorTests.swift - Tests for TunnelHealthMonitor

import XCTest
@testable import OmertaTunnel

final class TunnelHealthMonitorTests: XCTestCase {

    func testProbeWhenIdle() async throws {
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 3
        )

        var probeSent = false
        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in probeSent = true },
            onFailure: { _ in }
        )

        // Wait for at least one probe cycle
        try await Task.sleep(for: .milliseconds(150))
        await monitor.stopMonitoring()

        XCTAssertTrue(probeSent, "Probe should be sent when idle")
    }

    func testBackoffOnSuccess() async throws {
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(5),
            failureThreshold: 3
        )

        var probeCount = 0
        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                // Simulate remote responding: call onPacketReceived after each probe
                await monitor.onPacketReceived()
            },
            onFailure: { _ in }
        )

        // Wait long enough for a few probes — with backoff, fewer probes fire
        try await Task.sleep(for: .milliseconds(400))
        await monitor.stopMonitoring()

        // With 50ms min doubling to 100, 200, 400... we expect ~3-4 probes in 400ms
        // Without backoff at 50ms we'd get ~8
        XCTAssertGreaterThan(probeCount, 0)
        XCTAssertLessThan(probeCount, 8, "Backoff should reduce probe frequency")
    }

    func testResetOnTraffic() async throws {
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(5),
            failureThreshold: 3
        )

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in },
            onFailure: { _ in }
        )

        // Let interval grow
        try await Task.sleep(for: .milliseconds(200))

        // Simulate traffic
        await monitor.onPacketReceived()

        let interval = await monitor._currentProbeInterval
        XCTAssertEqual(interval, .milliseconds(50), "Interval should reset to min on traffic")

        let failures = await monitor._consecutiveFailures
        XCTAssertEqual(failures, 0, "Failures should reset on traffic")

        await monitor.stopMonitoring()
    }

    func testSingleFailureNoCallback() async throws {
        // One missed probe cycle should not trigger failure (threshold=3).
        // After one idle cycle with no response, simulate remote coming back.
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 3
        )

        var failureCalled = false
        var probeCount = 0

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                if probeCount >= 2 {
                    // Remote responds after first missed probe
                    await monitor.onPacketReceived()
                }
            },
            onFailure: { _ in failureCalled = true }
        )

        try await Task.sleep(for: .milliseconds(300))
        await monitor.stopMonitoring()

        XCTAssertFalse(failureCalled, "Single failure should not trigger onFailure")
    }

    func testConsecutiveFailuresCallback() async throws {
        // No onPacketReceived ever called — remote is dead
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 3
        )

        var failureCalled = false
        var failedMachineId: String?

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                // Probe sends but remote never responds (no onPacketReceived)
            },
            onFailure: { machineId in
                failureCalled = true
                failedMachineId = machineId
            }
        )

        // Wait for 3 failures at ~50ms each
        try await Task.sleep(for: .milliseconds(500))
        await monitor.stopMonitoring()

        XCTAssertTrue(failureCalled, "Should call onFailure after 3 consecutive failures")
        XCTAssertEqual(failedMachineId, "test-machine")
    }

    func testFailureResetOnSuccess() async throws {
        // Miss 2 probes, then remote responds every other probe — never reaches 3 consecutive
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 3
        )

        var failureCalled = false
        var probeCount = 0

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                // Respond on every 3rd probe (after 2 misses), resetting the counter each time
                if probeCount % 3 == 0 {
                    await monitor.onPacketReceived()
                }
            },
            onFailure: { _ in failureCalled = true }
        )

        try await Task.sleep(for: .milliseconds(600))
        await monitor.stopMonitoring()

        // Pattern: miss, miss, respond, miss, miss, respond — never 3 consecutive
        XCTAssertFalse(failureCalled, "Success between failures should reset counter")
    }

    func testFailureDetectedWhenSendSucceedsButNoIncoming() async throws {
        // Probe sends succeed (UDP doesn't error) but remote never sends anything back.
        // This is the key scenario: one-way packet loss or remote is down.
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 3
        )

        var failureCalled = false
        var probeCount = 0

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                // Send succeeds — but no onPacketReceived ever called
            },
            onFailure: { _ in failureCalled = true }
        )

        try await Task.sleep(for: .milliseconds(500))
        await monitor.stopMonitoring()

        XCTAssertTrue(failureCalled, "Should detect failure when sends succeed but no packets received")
        XCTAssertGreaterThanOrEqual(probeCount, 3, "Should have sent at least 3 probes")
    }

    func testIncomingTrafficWithoutProbingPreventsFailure() async throws {
        // Remote sends us packets (probes/data) so onPacketReceived fires,
        // even though we never explicitly probe. Should stay healthy.
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 3
        )

        var failureCalled = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in },
            onFailure: { _ in failureCalled = true }
        )

        // Simulate remote sending us packets every 30ms (faster than probe interval)
        for _ in 0..<15 {
            try await Task.sleep(for: .milliseconds(30))
            await monitor.onPacketReceived()
        }

        await monitor.stopMonitoring()

        XCTAssertFalse(failureCalled, "Regular incoming traffic should prevent failure")
        let failures = await monitor._consecutiveFailures
        XCTAssertEqual(failures, 0)
    }

    func testThresholdOfOne() async throws {
        // With threshold=1, a single missed interval should trigger failure
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 1
        )

        var failureCalled = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in },
            onFailure: { _ in failureCalled = true }
        )

        try await Task.sleep(for: .milliseconds(200))
        await monitor.stopMonitoring()

        XCTAssertTrue(failureCalled, "Threshold of 1 should trigger on first missed interval")
    }

    func testPacketDuringProbeSendRescuesFailure() async throws {
        // Probe fires because we're idle, but during the send a packet arrives
        // (e.g., the remote's own probe reaches us). Should not count as failure.
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(1),
            failureThreshold: 3
        )

        var failureCalled = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                // Every probe send is accompanied by an incoming packet
                await monitor.onPacketReceived()
            },
            onFailure: { _ in failureCalled = true }
        )

        try await Task.sleep(for: .milliseconds(500))
        await monitor.stopMonitoring()

        XCTAssertFalse(failureCalled, "Packet arriving during probe send should prevent failure")
        let failures = await monitor._consecutiveFailures
        XCTAssertEqual(failures, 0, "No failures should accumulate when packets arrive with probes")
    }
}
