// AdaptiveBatchMonitor.swift - Hill-climbing adaptive batch parameter monitor
//
// Optimizes for minimum latency while preserving bandwidth:
// 1. Start with small batch size and short flush delay (low latency)
// 2. When utilized bandwidth is low/decreasing: reduce delay/buffer toward minimums
// 3. When utilized bandwidth is high/increasing: increase delay/buffer for throughput
// 4. If a change causes bandwidth to drop noticeably, back off to previous values

import Foundation

/// Adaptive batch monitor that uses hill-climbing to optimize batch parameters.
public actor AdaptiveBatchMonitor: BatchMonitor {

    /// Tuning parameters
    private let sampleInterval: Duration
    private let bandwidthDropThreshold: Double
    private let delaySteps: [Duration]
    private let bufferSteps: [Int]

    /// State per endpoint
    private var endpointState: [String: EndpointState] = [:]

    struct EndpointState {
        var currentDelayIndex: Int
        var currentBufferIndex: Int
        var lastBandwidth: Double
        var lastLatency: Double
        var direction: Direction
        var lastSampleTime: ContinuousClock.Instant
        var stable: Bool

        enum Direction {
            case decreasing  // favor latency
            case increasing  // favor throughput
        }
    }

    public init(
        sampleInterval: Duration = .seconds(1),
        bandwidthDropThreshold: Double = 0.05,
        delaySteps: [Duration]? = nil,
        bufferSteps: [Int]? = nil
    ) {
        self.sampleInterval = sampleInterval
        self.bandwidthDropThreshold = bandwidthDropThreshold
        self.delaySteps = delaySteps ?? [
            .zero,
            .milliseconds(1),
            .milliseconds(5),
            .milliseconds(10),
            .milliseconds(50)
        ]
        self.bufferSteps = bufferSteps ?? [0, 1024, 4096, 16384, 65536]
    }

    // MARK: - BatchMonitor

    public nonisolated func recommendedConfig(for endpoint: String, currentTraffic: TrafficStats) async -> BatchConfig? {
        await _recommendedConfig(for: endpoint, currentTraffic: currentTraffic)
    }

    private func _recommendedConfig(for endpoint: String, currentTraffic: TrafficStats) -> BatchConfig? {
        let now = ContinuousClock.now

        // Get or create state
        var state = endpointState[endpoint] ?? EndpointState(
            currentDelayIndex: 0,  // Start at minimum delay (low latency)
            currentBufferIndex: 0,
            lastBandwidth: 0,
            lastLatency: 0,
            direction: .decreasing,
            lastSampleTime: now,
            stable: false
        )

        // Check if enough time has passed since last sample
        let elapsed = now - state.lastSampleTime
        guard elapsed >= sampleInterval else {
            // Not enough time — return nil to keep current config
            return nil
        }

        let currentBandwidth = Double(currentTraffic.deliveredBytesPerSecond ?? currentTraffic.bytesPerSecond)
        let currentLatency = currentTraffic.averageLatencyMicroseconds

        defer {
            state.lastBandwidth = currentBandwidth
            state.lastLatency = currentLatency
            state.lastSampleTime = now
            endpointState[endpoint] = state
        }

        // Zero traffic → minimum latency config
        if currentTraffic.bytesPerSecond == 0 && currentTraffic.packetsPerSecond == 0 {
            state.currentDelayIndex = 0
            state.currentBufferIndex = 0
            state.direction = .decreasing
            state.stable = false
            return makeConfig(state)
        }

        // Determine if bandwidth changed significantly
        let bandwidthChange = state.lastBandwidth > 0
            ? (currentBandwidth - state.lastBandwidth) / state.lastBandwidth
            : 0

        // Check for bandwidth drop after an increase in delay/buffer
        if state.direction == .increasing && bandwidthChange < -bandwidthDropThreshold {
            // Bandwidth dropped — back off
            state.currentDelayIndex = max(0, state.currentDelayIndex - 1)
            state.currentBufferIndex = max(0, state.currentBufferIndex - 1)
            state.direction = .decreasing
            state.stable = false
            return makeConfig(state)
        }

        // High bandwidth → try increasing delay/buffer to amortize overhead
        if currentBandwidth > state.lastBandwidth * 1.1 || currentTraffic.packetsPerSecond > 1000 {
            if state.currentDelayIndex < delaySteps.count - 1 {
                state.currentDelayIndex += 1
                state.direction = .increasing
                state.stable = false
                return makeConfig(state)
            }
            if state.currentBufferIndex < bufferSteps.count - 1 {
                state.currentBufferIndex += 1
                state.direction = .increasing
                state.stable = false
                return makeConfig(state)
            }
        }

        // Low/decreasing bandwidth → reduce delay for better latency
        if currentBandwidth < state.lastBandwidth * 0.9 || currentTraffic.packetsPerSecond < 100 {
            if state.currentDelayIndex > 0 {
                state.currentDelayIndex -= 1
                state.direction = .decreasing
                state.stable = false
                return makeConfig(state)
            }
            if state.currentBufferIndex > 0 {
                state.currentBufferIndex -= 1
                state.direction = .decreasing
                state.stable = false
                return makeConfig(state)
            }
        }

        // No change needed — mark stable
        if !state.stable {
            state.stable = true
            return makeConfig(state)
        }

        // Already stable — return nil
        return nil
    }

    private func makeConfig(_ state: EndpointState) -> BatchConfig {
        BatchConfig(
            maxFlushDelay: delaySteps[state.currentDelayIndex],
            maxBufferSize: bufferSteps[state.currentBufferIndex]
        )
    }

    // MARK: - Introspection (for testing)

    /// Get current delay index for an endpoint
    public func currentDelayIndex(for endpoint: String) -> Int? {
        endpointState[endpoint]?.currentDelayIndex
    }

    /// Get current buffer index for an endpoint
    public func currentBufferIndex(for endpoint: String) -> Int? {
        endpointState[endpoint]?.currentBufferIndex
    }

    /// Whether an endpoint's config has stabilized
    public func isStable(for endpoint: String) -> Bool {
        endpointState[endpoint]?.stable ?? false
    }

    /// Number of tracked endpoints
    public var endpointCount: Int {
        endpointState.count
    }
}
