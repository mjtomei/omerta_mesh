// FaultInjector.swift - Fault injection for testing resilience

import Foundation
@testable import OmertaMesh

/// Injects faults into a test network for resilience testing
public actor FaultInjector {
    /// Active faults currently being injected
    private var activeFaults: [FaultID: ActiveFault] = [:]

    /// Counter for generating fault IDs
    private var nextFaultId: Int = 0

    /// Types of faults that can be injected
    public enum Fault: Sendable, Equatable {
        /// Network partition between two groups
        case networkPartition(group1: [String], group2: [String])

        /// Latency spike on a node
        case latencySpike(nodeId: String, additionalMs: Int, duration: TimeInterval)

        /// Packet loss on a node
        case packetLoss(nodeId: String, percent: Double, duration: TimeInterval)

        /// NAT mapping expiry
        case natMappingExpiry(nodeId: String)

        /// Node failure (complete)
        case nodeFailure(nodeId: String)

        /// Link failure between two nodes
        case linkFailure(from: String, to: String, duration: TimeInterval)

        /// Bandwidth throttle
        case bandwidthThrottle(nodeId: String, bytesPerSecond: Int, duration: TimeInterval)

        /// Clock skew (simulated)
        case clockSkew(nodeId: String, offsetSeconds: TimeInterval, duration: TimeInterval)

        /// Jitter (variable latency)
        case jitter(nodeId: String, minMs: Int, maxMs: Int, duration: TimeInterval)

        /// Reorder packets
        case packetReorder(nodeId: String, percent: Double, maxDelayMs: Int, duration: TimeInterval)

        /// Duplicate packets
        case packetDuplicate(nodeId: String, percent: Double, duration: TimeInterval)

        /// NAT rebinding (change external port)
        case natRebind(nodeId: String)

        /// Intermittent connectivity
        case flappingConnection(nodeId: String, upDuration: TimeInterval, downDuration: TimeInterval, cycles: Int)
    }

    /// Unique identifier for an active fault
    public struct FaultID: Hashable, Sendable {
        let id: Int
    }

    /// An active fault with metadata
    private struct ActiveFault {
        let fault: Fault
        let startedAt: Date
        let expiresAt: Date?
        var cleanupTask: Task<Void, Never>?
    }

    public init() {}

    // MARK: - Fault Injection

    /// Inject a fault into the network
    @discardableResult
    public func inject(_ fault: Fault, into network: TestNetwork) async -> FaultID {
        let id = FaultID(id: nextFaultId)
        nextFaultId += 1

        let expiresAt = faultDuration(fault).map { Date().addingTimeInterval($0) }

        var activeFault = ActiveFault(
            fault: fault,
            startedAt: Date(),
            expiresAt: expiresAt,
            cleanupTask: nil
        )

        // Apply the fault
        await applyFault(fault, to: network)

        // Schedule cleanup if duration-based
        if let duration = faultDuration(fault) {
            let cleanupTask = Task {
                try? await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))
                await self.removeFault(id, from: network)
            }
            activeFault.cleanupTask = cleanupTask
        }

        activeFaults[id] = activeFault
        return id
    }

    /// Remove a specific fault
    public func removeFault(_ id: FaultID, from network: TestNetwork) async {
        guard let fault = activeFaults.removeValue(forKey: id) else { return }
        fault.cleanupTask?.cancel()
        await unapplyFault(fault.fault, from: network)
    }

    /// Remove all faults
    public func removeAllFaults(from network: TestNetwork) async {
        for (id, fault) in activeFaults {
            fault.cleanupTask?.cancel()
            await unapplyFault(fault.fault, from: network)
            activeFaults.removeValue(forKey: id)
        }
    }

    /// Get all active fault IDs
    public func getActiveFaultIds() -> [FaultID] {
        Array(activeFaults.keys)
    }

    /// Check if a specific fault type is active
    public func isActive(_ check: (Fault) -> Bool) -> Bool {
        activeFaults.values.contains { check($0.fault) }
    }

    // MARK: - Fault Application

    private func applyFault(_ fault: Fault, to network: TestNetwork) async {
        switch fault {
        case .networkPartition(let group1, let group2):
            await network.partition(group1: group1, group2: group2)

        case .latencySpike(let nodeId, let additionalMs, _):
            await network.addLatency(to: nodeId, ms: additionalMs)

        case .packetLoss(let nodeId, let percent, _):
            await network.setPacketLoss(for: nodeId, percent: percent)

        case .natMappingExpiry(let nodeId):
            if let nat = network.nat(for: nodeId) {
                await nat.expireAllMappings()
            }

        case .nodeFailure(let nodeId):
            await network.killNode(nodeId)

        case .linkFailure(let from, let to, _):
            await network.virtualNetwork.disableLink(from: from, to: to)

        case .bandwidthThrottle(let nodeId, _, _):
            // TODO: Implement bandwidth throttling in VirtualNetwork
            _ = nodeId

        case .clockSkew(let nodeId, _, _):
            // Clock skew would require test node to use injected time
            _ = nodeId

        case .jitter(let nodeId, let minMs, let maxMs, _):
            // Apply average latency - jitter simulation needs VirtualNetwork enhancement
            let avgMs = (minMs + maxMs) / 2
            await network.addLatency(to: nodeId, ms: avgMs)

        case .packetReorder(let nodeId, _, _, _):
            // Reordering needs VirtualNetwork enhancement
            _ = nodeId

        case .packetDuplicate(let nodeId, _, _):
            // Duplication needs VirtualNetwork enhancement
            _ = nodeId

        case .natRebind(let nodeId):
            if let nat = network.nat(for: nodeId) {
                await nat.expireAllMappings()
            }

        case .flappingConnection(let nodeId, let upDuration, let downDuration, let cycles):
            Task {
                for _ in 0..<cycles {
                    // Up phase
                    await network.removeLatency(from: nodeId)
                    await network.setPacketLoss(for: nodeId, percent: 0)
                    try? await Task.sleep(nanoseconds: UInt64(upDuration * 1_000_000_000))

                    // Down phase
                    await network.setPacketLoss(for: nodeId, percent: 100)
                    try? await Task.sleep(nanoseconds: UInt64(downDuration * 1_000_000_000))
                }
                // Restore
                await network.setPacketLoss(for: nodeId, percent: 0)
            }
        }
    }

    private func unapplyFault(_ fault: Fault, from network: TestNetwork) async {
        switch fault {
        case .networkPartition:
            await network.healPartition()

        case .latencySpike(let nodeId, _, _):
            await network.removeLatency(from: nodeId)

        case .packetLoss(let nodeId, _, _):
            await network.setPacketLoss(for: nodeId, percent: 0)

        case .natMappingExpiry:
            // Can't un-expire mappings
            break

        case .nodeFailure:
            // Can't un-fail a node
            break

        case .linkFailure(let from, let to, _):
            await network.virtualNetwork.enableLink(from: from, to: to)

        case .bandwidthThrottle:
            // TODO: Remove throttle
            break

        case .clockSkew:
            // TODO: Reset clock
            break

        case .jitter(let nodeId, _, _, _):
            await network.removeLatency(from: nodeId)

        case .packetReorder:
            break

        case .packetDuplicate:
            break

        case .natRebind:
            // NAT will create new mappings naturally
            break

        case .flappingConnection(let nodeId, _, _, _):
            await network.setPacketLoss(for: nodeId, percent: 0)
        }
    }

    /// Get the duration of a fault (nil = permanent until removed)
    private func faultDuration(_ fault: Fault) -> TimeInterval? {
        switch fault {
        case .latencySpike(_, _, let duration),
             .packetLoss(_, _, let duration),
             .linkFailure(_, _, let duration),
             .bandwidthThrottle(_, _, let duration),
             .clockSkew(_, _, let duration),
             .jitter(_, _, _, let duration),
             .packetReorder(_, _, _, let duration),
             .packetDuplicate(_, _, let duration):
            return duration

        case .flappingConnection(_, let up, let down, let cycles):
            return (up + down) * TimeInterval(cycles)

        case .networkPartition, .natMappingExpiry, .nodeFailure, .natRebind:
            return nil
        }
    }
}

// MARK: - Fault Scenarios

extension FaultInjector {
    /// Inject a sequence of faults with delays between them
    public func injectSequence(
        _ faults: [(fault: Fault, delayBefore: TimeInterval)],
        into network: TestNetwork
    ) async -> [FaultID] {
        var ids: [FaultID] = []

        for (fault, delay) in faults {
            if delay > 0 {
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
            let id = await inject(fault, into: network)
            ids.append(id)
        }

        return ids
    }

    /// Inject random faults from a set
    public func injectRandom(
        from faultTypes: [Fault],
        into network: TestNetwork,
        count: Int,
        intervalMs: Int
    ) async -> [FaultID] {
        var ids: [FaultID] = []

        for _ in 0..<count {
            guard let fault = faultTypes.randomElement() else { continue }
            let id = await inject(fault, into: network)
            ids.append(id)

            try? await Task.sleep(nanoseconds: UInt64(intervalMs) * 1_000_000)
        }

        return ids
    }
}

// MARK: - Network Health Monitoring

extension FaultInjector {
    /// Monitor network health during fault injection
    public func measureImpact(
        on network: TestNetwork,
        during duration: TimeInterval,
        sampleIntervalMs: Int = 100
    ) async -> FaultImpactReport {
        var samples: [HealthSample] = []
        let startTime = Date()
        let endTime = startTime.addingTimeInterval(duration)

        while Date() < endTime {
            let sample = await captureHealthSample(network)
            samples.append(sample)
            try? await Task.sleep(nanoseconds: UInt64(sampleIntervalMs) * 1_000_000)
        }

        return FaultImpactReport(samples: samples)
    }

    private func captureHealthSample(_ network: TestNetwork) async -> HealthSample {
        let nodeIds = network.nodeIds
        var reachablePairs = 0
        var totalPairs = 0

        // Sample connectivity (simplified)
        for i in 0..<min(nodeIds.count, 5) {
            for j in (i+1)..<min(nodeIds.count, 5) {
                totalPairs += 1
                // In a real test, we'd actually probe connectivity
                // For now, assume if no partition, all reachable
                if !isActive({ fault in
                    if case .networkPartition = fault { return true }
                    return false
                }) {
                    reachablePairs += 1
                }
            }
        }

        return HealthSample(
            timestamp: Date(),
            activeFaultCount: activeFaults.count,
            nodeCount: nodeIds.count,
            connectivityPercent: totalPairs > 0 ? Double(reachablePairs) / Double(totalPairs) * 100 : 100
        )
    }
}

/// A snapshot of network health
public struct HealthSample: Sendable {
    public let timestamp: Date
    public let activeFaultCount: Int
    public let nodeCount: Int
    public let connectivityPercent: Double
}

/// Report of fault impact
public struct FaultImpactReport: Sendable {
    public let samples: [HealthSample]

    public var avgConnectivity: Double {
        guard !samples.isEmpty else { return 100 }
        return samples.map(\.connectivityPercent).reduce(0, +) / Double(samples.count)
    }

    public var minConnectivity: Double {
        samples.map(\.connectivityPercent).min() ?? 100
    }

    public var maxFaultCount: Int {
        samples.map(\.activeFaultCount).max() ?? 0
    }

    public var duration: TimeInterval {
        guard let first = samples.first, let last = samples.last else { return 0 }
        return last.timestamp.timeIntervalSince(first.timestamp)
    }
}
