// TunnelHealthMonitor.swift - Adaptive health probing for tunnel machines
//
// Per-machine health monitor (not per-session). Multiple sessions to the same
// machine share health state. Probes only when idle, backs off on success,
// and calls onFailure after consecutive probe failures exceed threshold.
//
// Liveness is determined by whether we've received any packet (probes, data,
// etc.) from the remote machine recently. Both sides run monitors and send
// probes, so a healthy remote will always be sending us packets. If we
// haven't heard anything after sending a probe and waiting an interval,
// that's a failure.

import Foundation
import OmertaMesh

public actor TunnelHealthMonitor {
    private var lastPacketTime: ContinuousClock.Instant
    private var currentProbeInterval: Duration
    private var consecutiveFailures: Int = 0
    private var monitoringTask: Task<Void, Never>?

    private let minProbeInterval: Duration
    private let maxProbeInterval: Duration
    private let failureThreshold: Int
    private let graceIntervals: Int

    public init(
        minProbeInterval: Duration = .milliseconds(500),
        maxProbeInterval: Duration = .seconds(15),
        failureThreshold: Int = 3,
        graceIntervals: Int = 0
    ) {
        self.minProbeInterval = minProbeInterval
        self.maxProbeInterval = maxProbeInterval
        self.failureThreshold = failureThreshold
        self.graceIntervals = graceIntervals
        self.currentProbeInterval = minProbeInterval
        self.lastPacketTime = ContinuousClock.now - minProbeInterval
    }

    /// Called when any packet arrives from the remote machine (application data, probes, etc.)
    /// Resets probe interval to minimum and clears failure count.
    public func onPacketReceived() {
        lastPacketTime = ContinuousClock.now
        currentProbeInterval = minProbeInterval
        consecutiveFailures = 0
    }

    /// Start the monitoring loop
    public func startMonitoring(
        machineId: MachineId,
        sendProbe: @escaping (MachineId) async throws -> Void,
        onFailure: @escaping (MachineId) async -> Void
    ) {
        monitoringTask?.cancel()
        monitoringTask = Task { [weak self] in
            guard let self else { return }
            await self.monitorLoop(machineId: machineId, sendProbe: sendProbe, onFailure: onFailure)
        }
    }

    /// Stop monitoring
    public func stopMonitoring() {
        monitoringTask?.cancel()
        monitoringTask = nil
    }

    // Exposed for testing
    public var _consecutiveFailures: Int { consecutiveFailures }
    public var _currentProbeInterval: Duration { currentProbeInterval }

    // MARK: - Private

    private func monitorLoop(
        machineId: MachineId,
        sendProbe: @escaping (MachineId) async throws -> Void,
        onFailure: @escaping (MachineId) async -> Void
    ) async {
        var graceRemaining = graceIntervals

        while !Task.isCancelled {
            // Snapshot the last packet time before sleeping
            let packetTimeBefore = lastPacketTime
            let interval = currentProbeInterval

            // Send our probe so the remote knows we're alive
            try? await sendProbe(machineId)

            // Wait for the probe interval
            try? await Task.sleep(for: interval)
            guard !Task.isCancelled else { break }

            // During grace period, don't count failures
            if graceRemaining > 0 {
                graceRemaining -= 1
                continue
            }

            // Check: did we receive ANY packet between the previous and current check?
            if lastPacketTime > packetTimeBefore {
                // Remote is alive — back off probe frequency
                consecutiveFailures = 0
                currentProbeInterval = min(currentProbeInterval * 2, maxProbeInterval)
                continue
            }

            // No packet received since last check — count as failure
            consecutiveFailures += 1
            if consecutiveFailures >= failureThreshold {
                await onFailure(machineId)
                break
            }
        }
    }
}
