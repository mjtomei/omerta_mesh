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

        let probeExpectation = expectation(description: "Probe sent")
        probeExpectation.assertForOverFulfill = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in probeExpectation.fulfill() },
            onFailure: { _ in }
        )

        await fulfillment(of: [probeExpectation], timeout: 5)
        await monitor.stopMonitoring()
    }

    func testBackoffOnSuccess() async throws {
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(5),
            failureThreshold: 3
        )

        var probeCount = 0
        // Use an expectation for "enough probes fired to measure backoff"
        let enoughProbes = expectation(description: "Enough probes for backoff measurement")
        enoughProbes.assertForOverFulfill = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                // Simulate remote responding: call onPacketReceived after each probe
                await monitor.onPacketReceived()
                if probeCount >= 3 {
                    enoughProbes.fulfill()
                }
            },
            onFailure: { _ in }
        )

        await fulfillment(of: [enoughProbes], timeout: 5)
        // Give a bit more time for any rapid probes that would fire without backoff
        try await Task.sleep(for: .milliseconds(200))
        await monitor.stopMonitoring()

        // With 50ms min doubling to 100, 200, 400... we expect ~3-5 probes
        // Without backoff at 50ms we'd get many more
        XCTAssertGreaterThan(probeCount, 0)
        XCTAssertLessThan(probeCount, 12, "Backoff should reduce probe frequency")
    }

    func testResetOnTraffic() async throws {
        let monitor = TunnelHealthMonitor(
            minProbeInterval: .milliseconds(50),
            maxProbeInterval: .seconds(5),
            failureThreshold: 3
        )

        // Wait for at least one probe so the interval has grown
        let probed = expectation(description: "At least one probe sent")
        probed.assertForOverFulfill = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in probed.fulfill() },
            onFailure: { _ in }
        )

        await fulfillment(of: [probed], timeout: 5)

        // Simulate traffic — should reset interval to min
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
        // Wait until remote has "responded" (probe >= 2), then check no failure
        let respondedExpectation = expectation(description: "Remote responded after first miss")
        respondedExpectation.assertForOverFulfill = false
        var probeCount = 0

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                if probeCount >= 2 {
                    // Remote responds after first missed probe
                    await monitor.onPacketReceived()
                    respondedExpectation.fulfill()
                }
            },
            onFailure: { _ in failureCalled = true }
        )

        await fulfillment(of: [respondedExpectation], timeout: 5)
        // Let one more cycle pass to confirm no failure fires
        try await Task.sleep(for: .milliseconds(100))
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

        let failureExpectation = expectation(description: "Failure callback fired")
        var failedMachineId: String?

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                // Probe sends but remote never responds (no onPacketReceived)
            },
            onFailure: { machineId in
                failedMachineId = machineId
                failureExpectation.fulfill()
            }
        )

        await fulfillment(of: [failureExpectation], timeout: 10)
        await monitor.stopMonitoring()

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
        // Wait for enough cycles to confirm the pattern works
        let enoughCycles = expectation(description: "Enough probe cycles completed")
        enoughCycles.assertForOverFulfill = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                // Respond on every 3rd probe (after 2 misses), resetting the counter each time
                if probeCount % 3 == 0 {
                    await monitor.onPacketReceived()
                }
                // After 9 probes (3 full cycles of miss-miss-respond), we've proven the pattern
                if probeCount >= 9 {
                    enoughCycles.fulfill()
                }
            },
            onFailure: { _ in failureCalled = true }
        )

        await fulfillment(of: [enoughCycles], timeout: 10)
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

        let failureExpectation = expectation(description: "Failure detected")
        var probeCount = 0

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                // Send succeeds — but no onPacketReceived ever called
            },
            onFailure: { _ in failureExpectation.fulfill() }
        )

        await fulfillment(of: [failureExpectation], timeout: 10)
        await monitor.stopMonitoring()

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

        let failureExpectation = expectation(description: "Threshold-1 failure fired")

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in },
            onFailure: { _ in failureExpectation.fulfill() }
        )

        await fulfillment(of: [failureExpectation], timeout: 10)
        await monitor.stopMonitoring()
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
        var probeCount = 0
        // Wait for enough probe cycles to confirm no failure accumulates
        let enoughProbes = expectation(description: "Enough probes with rescue")
        enoughProbes.assertForOverFulfill = false

        await monitor.startMonitoring(
            machineId: "test-machine",
            sendProbe: { _ in
                probeCount += 1
                // Every probe send is accompanied by an incoming packet
                await monitor.onPacketReceived()
                if probeCount >= 6 {
                    enoughProbes.fulfill()
                }
            },
            onFailure: { _ in failureCalled = true }
        )

        await fulfillment(of: [enoughProbes], timeout: 10)
        await monitor.stopMonitoring()

        XCTAssertFalse(failureCalled, "Packet arriving during probe send should prevent failure")
        let failures = await monitor._consecutiveFailures
        XCTAssertEqual(failures, 0, "No failures should accumulate when packets arrive with probes")
    }
}
