// TunnelHealthMonitor.swift - Adaptive health probing for tunnel machines
//
// Per-machine health monitor (not per-session). Multiple sessions to the same
// machine share health state. Probes only when idle, backs off on success,
// and calls onDegraded/onFailure after consecutive probe failures exceed thresholds.
//
// Liveness is determined by whether we've received any packet (probes, data,
// etc.) from the remote machine recently. Both sides run monitors and send
// probes, so a healthy remote will always be sending us packets. If we
// haven't heard anything after sending a probe and waiting an interval,
// that's a failure.

import Foundation
import Logging
import OmertaMesh

public actor TunnelHealthMonitor {
    private let logger = Logger(label: "io.omerta.tunnel.health")
    private var lastPacketTime: ContinuousClock.Instant
    private var currentProbeInterval: Duration
    private var consecutiveFailures: Int = 0
    private var monitoringTask: Task<Void, Never>?

    private let minProbeInterval: Duration
    private let maxProbeInterval: Duration
    private let degradedThreshold: Int
    private let failureThreshold: Int
    private let graceIntervals: Int

    public init(
        minProbeInterval: Duration = .milliseconds(500),
        maxProbeInterval: Duration = .seconds(15),
        degradedThreshold: Int = 3,
        failureThreshold: Int = 6,
        graceIntervals: Int = 0
    ) {
        self.minProbeInterval = minProbeInterval
        self.maxProbeInterval = maxProbeInterval
        self.degradedThreshold = degradedThreshold
        self.failureThreshold = failureThreshold
        self.graceIntervals = graceIntervals
        self.currentProbeInterval = minProbeInterval
        self.lastPacketTime = ContinuousClock.now - minProbeInterval
    }

    /// Called when any packet arrives from the remote machine (application data, probes, etc.)
    /// Resets probe interval to minimum and clears failure count.
    public func onPacketReceived() {
        let wasDegraded = consecutiveFailures >= degradedThreshold
        lastPacketTime = ContinuousClock.now
        currentProbeInterval = minProbeInterval
        consecutiveFailures = 0
        if wasDegraded {
            pendingRecovery = true
        }
    }

    /// Start the monitoring loop
    public func startMonitoring(
        machineId: MachineId,
        sendProbe: @escaping (MachineId) async throws -> Void,
        onDegraded: @escaping (MachineId) async -> Void = { _ in },
        onFailure: @escaping (MachineId) async -> Void,
        onRecovered: @escaping (MachineId) async -> Void = { _ in }
    ) {
        monitoringTask?.cancel()
        monitoringTask = Task { [weak self] in
            guard let self else { return }
            await self.monitorLoop(
                machineId: machineId,
                sendProbe: sendProbe,
                onDegraded: onDegraded,
                onFailure: onFailure,
                onRecovered: onRecovered
            )
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

    private var pendingRecovery = false
    private var degradedFired = false

    private func monitorLoop(
        machineId: MachineId,
        sendProbe: @escaping (MachineId) async throws -> Void,
        onDegraded: @escaping (MachineId) async -> Void,
        onFailure: @escaping (MachineId) async -> Void,
        onRecovered: @escaping (MachineId) async -> Void
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

            // Check for pending recovery (set by onPacketReceived)
            if pendingRecovery {
                pendingRecovery = false
                if degradedFired {
                    degradedFired = false
                    await onRecovered(machineId)
                }
            }

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
                logger.debug("Health OK for \(machineId.prefix(8)): interval=\(currentProbeInterval)")
                continue
            }

            // No packet received since last check — count as failure
            consecutiveFailures += 1
            logger.warning("Health MISS for \(machineId.prefix(8)): failures=\(consecutiveFailures)/\(failureThreshold), interval=\(interval)")

            if consecutiveFailures == degradedThreshold && !degradedFired {
                degradedFired = true
                logger.warning("Health DEGRADED for \(machineId.prefix(8)): triggering onDegraded")
                await onDegraded(machineId)
            }

            if consecutiveFailures >= failureThreshold {
                logger.warning("Health FAIL for \(machineId.prefix(8)): triggering onFailure")
                await onFailure(machineId)
                break
            }
        }
    }
}
