// TunnelHealthMonitor.swift - Adaptive health probing for tunnel machines
//
// Per-machine health monitor (not per-session). Multiple sessions to the same
// machine share health state. Probes only when idle, backs off on success,
// and calls onFailure after consecutive probe failures exceed threshold.

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

    public init(
        minProbeInterval: Duration = .milliseconds(500),
        maxProbeInterval: Duration = .seconds(15),
        failureThreshold: Int = 3
    ) {
        self.minProbeInterval = minProbeInterval
        self.maxProbeInterval = maxProbeInterval
        self.failureThreshold = failureThreshold
        self.currentProbeInterval = minProbeInterval
        self.lastPacketTime = ContinuousClock.now
    }

    /// Called by TunnelManager when any packet arrives from this machine
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
    var _consecutiveFailures: Int { consecutiveFailures }
    var _currentProbeInterval: Duration { currentProbeInterval }

    // MARK: - Private

    private func monitorLoop(
        machineId: MachineId,
        sendProbe: @escaping (MachineId) async throws -> Void,
        onFailure: @escaping (MachineId) async -> Void
    ) async {
        while !Task.isCancelled {
            let interval = currentProbeInterval
            try? await Task.sleep(for: interval)
            guard !Task.isCancelled else { break }

            let elapsed = ContinuousClock.now - lastPacketTime
            if elapsed < interval {
                // Traffic received recently — no probe needed, back off
                currentProbeInterval = min(currentProbeInterval * 2, maxProbeInterval)
                continue
            }

            // Idle — send probe
            do {
                try await sendProbe(machineId)
                // Probe succeeded
                consecutiveFailures = 0
                currentProbeInterval = min(currentProbeInterval * 2, maxProbeInterval)
            } catch {
                consecutiveFailures += 1
                if consecutiveFailures >= failureThreshold {
                    await onFailure(machineId)
                    break
                }
            }
        }
    }
}
