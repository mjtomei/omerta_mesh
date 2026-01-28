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
            sendProbe: { _ in probeCount += 1 },
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
                if probeCount == 1 {
                    throw NSError(domain: "test", code: 1)
                }
                // Subsequent probes succeed
            },
            onFailure: { _ in failureCalled = true }
        )

        try await Task.sleep(for: .milliseconds(300))
        await monitor.stopMonitoring()

        XCTAssertFalse(failureCalled, "Single failure should not trigger onFailure")
    }

    func testConsecutiveFailuresCallback() async throws {
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
                throw NSError(domain: "test", code: 1)
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
                // Fail first 2, then succeed, then fail 2 more
                if probeCount <= 2 || (probeCount >= 4 && probeCount <= 5) {
                    throw NSError(domain: "test", code: 1)
                }
            },
            onFailure: { _ in failureCalled = true }
        )

        // Enough time for ~6 probes
        try await Task.sleep(for: .milliseconds(600))
        await monitor.stopMonitoring()

        // Failures: 2, then success resets, then 2 more — never reaches 3 consecutive
        XCTAssertFalse(failureCalled, "Success between failures should reset counter")
    }
}
