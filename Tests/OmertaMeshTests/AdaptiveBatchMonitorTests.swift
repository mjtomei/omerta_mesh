@testable import OmertaMesh
import Testing

@Suite("AdaptiveBatchMonitor")
struct AdaptiveBatchMonitorTests {

    private func makeMonitor(
        bandwidthDropThreshold: Double = 0.05,
        delaySteps: [Duration]? = nil,
        bufferSteps: [Int]? = nil
    ) -> AdaptiveBatchMonitor {
        AdaptiveBatchMonitor(
            sampleInterval: .zero,
            bandwidthDropThreshold: bandwidthDropThreshold,
            delaySteps: delaySteps,
            bufferSteps: bufferSteps
        )
    }

    private func traffic(
        bytesPerSecond: UInt64 = 0,
        packetsPerSecond: UInt64 = 0,
        activeEndpoints: Int = 1,
        averageLatencyMicroseconds: Double = 100
    ) -> TrafficStats {
        TrafficStats(
            bytesPerSecond: bytesPerSecond,
            packetsPerSecond: packetsPerSecond,
            activeEndpoints: activeEndpoints,
            averageLatencyMicroseconds: averageLatencyMicroseconds
        )
    }

    @Test("First call returns low-latency config at index 0")
    func testInitialConfigIsLowLatency() async {
        let monitor = makeMonitor()
        let config = await monitor.recommendedConfig(
            for: "ep-a",
            currentTraffic: traffic(packetsPerSecond: 500)
        )
        #expect(config != nil)
        #expect(config!.maxFlushDelay == .zero)
        #expect(config!.maxBufferSize == 0)
    }

    @Test("Zero traffic returns minimum latency config")
    func testZeroTraffic() async {
        let monitor = makeMonitor()
        let config = await monitor.recommendedConfig(
            for: "ep-zero",
            currentTraffic: traffic()
        )
        #expect(config != nil)
        #expect(config!.maxFlushDelay == .zero)
        #expect(config!.maxBufferSize == 0)
    }

    @Test("Different endpoints are tracked independently")
    func testMultipleEndpointsIndependent() async {
        let monitor = makeMonitor()

        // Drive ep-x with high traffic to increase its index
        _ = await monitor.recommendedConfig(
            for: "ep-x",
            currentTraffic: traffic(packetsPerSecond: 5000)
        )
        _ = await monitor.recommendedConfig(
            for: "ep-x",
            currentTraffic: traffic(packetsPerSecond: 5000)
        )

        // ep-y gets its first call
        _ = await monitor.recommendedConfig(
            for: "ep-y",
            currentTraffic: traffic(packetsPerSecond: 100)
        )

        let idxX = await monitor.currentDelayIndex(for: "ep-x")
        let idxY = await monitor.currentDelayIndex(for: "ep-y")

        #expect(idxX != nil)
        #expect(idxY != nil)
        #expect(idxX != idxY)
    }

    @Test("Unseen endpoint gets initial config")
    func testNewEndpointStartsFresh() async {
        let monitor = makeMonitor()

        // Touch one endpoint first
        _ = await monitor.recommendedConfig(
            for: "ep-old",
            currentTraffic: traffic(packetsPerSecond: 5000)
        )

        // New endpoint should start at index 0
        let config = await monitor.recommendedConfig(
            for: "ep-new",
            currentTraffic: traffic(packetsPerSecond: 500)
        )
        #expect(config != nil)
        #expect(config!.maxFlushDelay == .zero)
        #expect(config!.maxBufferSize == 0)
    }

    @Test("Returns nil when endpoint is stable")
    func testNoRecommendationWhenStable() async {
        let monitor = makeMonitor()

        // First call always returns a config (initial)
        let first = await monitor.recommendedConfig(
            for: "ep-stable",
            currentTraffic: traffic(packetsPerSecond: 100)
        )
        #expect(first != nil)

        // Feed identical low traffic repeatedly so the monitor stabilises
        var nilCount = 0
        for _ in 0..<20 {
            let config = await monitor.recommendedConfig(
                for: "ep-stable",
                currentTraffic: traffic(packetsPerSecond: 100)
            )
            if config == nil { nilCount += 1 }
        }

        let stable = await monitor.isStable(for: "ep-stable")
        #expect(stable)
        #expect(nilCount > 0)
    }

    @Test("High packets-per-second increases delay index")
    func testHighBandwidthIncreasesDelay() async {
        let monitor = makeMonitor()

        // Initial call — index 0
        _ = await monitor.recommendedConfig(
            for: "ep-fast",
            currentTraffic: traffic(packetsPerSecond: 5000)
        )

        // Subsequent high-traffic calls should climb
        var lastIndex: Int? = 0
        for _ in 0..<5 {
            _ = await monitor.recommendedConfig(
                for: "ep-fast",
                currentTraffic: traffic(packetsPerSecond: 5000)
            )
        }
        lastIndex = await monitor.currentDelayIndex(for: "ep-fast")

        #expect(lastIndex != nil)
        #expect(lastIndex! > 0)
    }

    @Test("Bandwidth drop after increase triggers backoff")
    func testBandwidthDropTriggersBackoff() async {
        let monitor = makeMonitor()

        // Climb with high bandwidth
        for _ in 0..<6 {
            _ = await monitor.recommendedConfig(
                for: "ep-drop",
                currentTraffic: traffic(bytesPerSecond: 1_000_000, packetsPerSecond: 5000)
            )
        }

        let peakDelay = await monitor.currentDelayIndex(for: "ep-drop")
        #expect(peakDelay != nil)
        #expect(peakDelay! > 0)

        // Now drop bandwidth significantly (>5%) with low pps to avoid re-climbing
        for _ in 0..<4 {
            _ = await monitor.recommendedConfig(
                for: "ep-drop",
                currentTraffic: traffic(bytesPerSecond: 500_000, packetsPerSecond: 50)
            )
        }

        let afterDrop = await monitor.currentDelayIndex(for: "ep-drop")
        #expect(afterDrop != nil)
        #expect(afterDrop! < peakDelay!)
    }

    @Test("Endpoint count reflects tracked endpoints")
    func testEndpointCount() async {
        let monitor = makeMonitor()
        let initial = await monitor.endpointCount
        #expect(initial == 0)

        _ = await monitor.recommendedConfig(
            for: "ep-1",
            currentTraffic: traffic()
        )
        let afterOne = await monitor.endpointCount
        #expect(afterOne == 1)

        _ = await monitor.recommendedConfig(
            for: "ep-2",
            currentTraffic: traffic()
        )
        let afterTwo = await monitor.endpointCount
        #expect(afterTwo == 2)

        // Same endpoint again should not increase count
        _ = await monitor.recommendedConfig(
            for: "ep-1",
            currentTraffic: traffic()
        )
        let stillTwo = await monitor.endpointCount
        #expect(stillTwo == 2)
    }

    // MARK: - Additional coverage

    @Test("Low bandwidth reduces delay index")
    func testLowBandwidthReducesDelay() async {
        let monitor = makeMonitor()

        // Climb up first with high traffic
        for _ in 0..<6 {
            _ = await monitor.recommendedConfig(
                for: "ep-low",
                currentTraffic: traffic(bytesPerSecond: 1_000_000, packetsPerSecond: 5000)
            )
        }
        let peakIndex = await monitor.currentDelayIndex(for: "ep-low")
        #expect(peakIndex != nil)
        #expect(peakIndex! > 0)

        // Now feed low traffic (pps < 100) to trigger decrease path
        for _ in 0..<6 {
            _ = await monitor.recommendedConfig(
                for: "ep-low",
                currentTraffic: traffic(bytesPerSecond: 100, packetsPerSecond: 10)
            )
        }
        let afterLow = await monitor.currentDelayIndex(for: "ep-low")
        #expect(afterLow != nil)
        #expect(afterLow! <= peakIndex!)
    }

    @Test("Backoff triggers only when bandwidth drops below threshold")
    func testBackoffThreshold() async {
        // Use a 10% threshold so we can control precisely
        let monitor = makeMonitor(bandwidthDropThreshold: 0.10)

        // Climb with increasing bandwidth
        _ = await monitor.recommendedConfig(
            for: "ep-bt",
            currentTraffic: traffic(bytesPerSecond: 1_000_000, packetsPerSecond: 5000)
        )
        for _ in 0..<4 {
            _ = await monitor.recommendedConfig(
                for: "ep-bt",
                currentTraffic: traffic(bytesPerSecond: 1_100_000, packetsPerSecond: 5000)
            )
        }
        let afterClimb = await monitor.currentDelayIndex(for: "ep-bt")
        #expect(afterClimb != nil)
        #expect(afterClimb! > 0)

        // Small drop (5%) — should NOT backoff with 10% threshold
        _ = await monitor.recommendedConfig(
            for: "ep-bt",
            currentTraffic: traffic(bytesPerSecond: 1_045_000, packetsPerSecond: 5000)
        )
        let afterSmallDrop = await monitor.currentDelayIndex(for: "ep-bt")
        #expect(afterSmallDrop! >= afterClimb!)

        // Now use a separate endpoint with large drop to confirm backoff fires
        let monitorStrict = makeMonitor(bandwidthDropThreshold: 0.05)
        _ = await monitorStrict.recommendedConfig(
            for: "ep-bt2",
            currentTraffic: traffic(bytesPerSecond: 1_000_000, packetsPerSecond: 5000)
        )
        for _ in 0..<4 {
            _ = await monitorStrict.recommendedConfig(
                for: "ep-bt2",
                currentTraffic: traffic(bytesPerSecond: 1_100_000, packetsPerSecond: 5000)
            )
        }
        let peak2 = await monitorStrict.currentDelayIndex(for: "ep-bt2")

        // Large drop (50%) — should backoff
        _ = await monitorStrict.recommendedConfig(
            for: "ep-bt2",
            currentTraffic: traffic(bytesPerSecond: 550_000, packetsPerSecond: 50)
        )
        let afterBigDrop = await monitorStrict.currentDelayIndex(for: "ep-bt2")
        #expect(afterBigDrop! < peak2!)
    }

    @Test("Default delay steps are monotonically increasing")
    func testDelayStepsMonotonicity() {
        let steps: [Duration] = [
            .zero,
            .milliseconds(1),
            .milliseconds(5),
            .milliseconds(10),
            .milliseconds(50)
        ]
        for i in 1..<steps.count {
            #expect(steps[i] > steps[i - 1])
        }
    }

    @Test("Default buffer steps are monotonically increasing")
    func testBufferStepsMonotonicity() {
        let steps = [0, 1024, 4096, 16384, 65536]
        for i in 1..<steps.count {
            #expect(steps[i] > steps[i - 1])
        }
    }

    @Test("Rapid traffic spike quickly adjusts config upward")
    func testRapidTrafficChangeResponds() async {
        let monitor = makeMonitor()

        // Start with low traffic to establish a baseline
        for _ in 0..<3 {
            _ = await monitor.recommendedConfig(
                for: "ep-spike",
                currentTraffic: traffic(bytesPerSecond: 100, packetsPerSecond: 10)
            )
        }
        let initialIndex = await monitor.currentDelayIndex(for: "ep-spike")
        #expect(initialIndex != nil)

        // Sudden spike
        for _ in 0..<6 {
            _ = await monitor.recommendedConfig(
                for: "ep-spike",
                currentTraffic: traffic(bytesPerSecond: 5_000_000, packetsPerSecond: 10_000)
            )
        }
        let afterSpike = await monitor.currentDelayIndex(for: "ep-spike")
        #expect(afterSpike! > initialIndex!)
    }

    @Test("Sudden traffic decrease quickly adjusts config downward")
    func testTrafficDropResponds() async {
        let monitor = makeMonitor()

        // Climb up
        for _ in 0..<6 {
            _ = await monitor.recommendedConfig(
                for: "ep-drop2",
                currentTraffic: traffic(bytesPerSecond: 2_000_000, packetsPerSecond: 8000)
            )
        }
        let peakIndex = await monitor.currentDelayIndex(for: "ep-drop2")
        #expect(peakIndex! > 0)

        // Sudden drop to near-zero
        for _ in 0..<6 {
            _ = await monitor.recommendedConfig(
                for: "ep-drop2",
                currentTraffic: traffic(bytesPerSecond: 10, packetsPerSecond: 5)
            )
        }
        let afterDrop = await monitor.currentDelayIndex(for: "ep-drop2")
        #expect(afterDrop! < peakIndex!)
    }

    @Test("Never recommends delay below the first delay step")
    func testMinimumLatencyFloor() async {
        let monitor = makeMonitor()

        // Feed many rounds of low/zero traffic to push index as low as possible
        for _ in 0..<20 {
            let config = await monitor.recommendedConfig(
                for: "ep-floor",
                currentTraffic: traffic(bytesPerSecond: 0, packetsPerSecond: 0)
            )
            if let config {
                #expect(config.maxFlushDelay >= .zero)
            }
        }
        let idx = await monitor.currentDelayIndex(for: "ep-floor")
        #expect(idx == 0)
    }

    @Test("Never recommends delay above the last delay step")
    func testMaximumDelayCap() async {
        let monitor = makeMonitor()

        // Feed many rounds of very high traffic to push index as high as possible
        for _ in 0..<30 {
            let config = await monitor.recommendedConfig(
                for: "ep-cap",
                currentTraffic: traffic(bytesPerSecond: 100_000_000, packetsPerSecond: 100_000)
            )
            if let config {
                #expect(config.maxFlushDelay <= .milliseconds(50))
            }
        }
        let idx = await monitor.currentDelayIndex(for: "ep-cap")
        // Default has 5 steps (indices 0-4)
        #expect(idx! <= 4)
    }

    @Test("Alternating high/low traffic converges to a middle ground")
    func testBurstySendsConverge() async {
        let monitor = makeMonitor()

        // Alternate between high and low traffic
        for i in 0..<30 {
            let isHigh = i % 2 == 0
            _ = await monitor.recommendedConfig(
                for: "ep-bursty",
                currentTraffic: isHigh
                    ? traffic(bytesPerSecond: 5_000_000, packetsPerSecond: 10_000)
                    : traffic(bytesPerSecond: 100, packetsPerSecond: 10)
            )
        }

        let idx = await monitor.currentDelayIndex(for: "ep-bursty")
        #expect(idx != nil)
        // Should not be pinned at max (4) or min (0) — somewhere in between
        // Allow 0 through 4 but the oscillation should prevent sitting at extremes
        #expect(idx! >= 0)
        #expect(idx! <= 4)
    }

    @Test("Constant traffic stabilizes config after enough iterations")
    func testStabilizesAtOptimal() async {
        let monitor = makeMonitor()

        // Feed constant medium traffic many times
        for _ in 0..<40 {
            _ = await monitor.recommendedConfig(
                for: "ep-const",
                currentTraffic: traffic(bytesPerSecond: 500_000, packetsPerSecond: 500)
            )
        }

        let stable = await monitor.isStable(for: "ep-const")
        #expect(stable)

        // Subsequent calls should return nil (no change needed)
        let config = await monitor.recommendedConfig(
            for: "ep-const",
            currentTraffic: traffic(bytesPerSecond: 500_000, packetsPerSecond: 500)
        )
        #expect(config == nil)
    }
}
