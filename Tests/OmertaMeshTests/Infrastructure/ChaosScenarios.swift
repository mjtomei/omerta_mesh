// ChaosScenarios.swift - Predefined chaos test scenarios

import Foundation
@testable import OmertaMesh

/// Predefined chaos testing scenarios
public struct ChaosScenarios {

    // MARK: - Scenario Definitions

    /// A chaos scenario configuration
    public struct Scenario: Sendable {
        /// Name of the scenario
        public let name: String

        /// Description of what this scenario tests
        public let description: String

        /// Faults to inject
        public let faults: [FaultInjector.Fault]

        /// Duration of the scenario in seconds
        public let duration: TimeInterval

        /// Expected behavior
        public let expectedBehavior: ExpectedBehavior

        public init(
            name: String,
            description: String,
            faults: [FaultInjector.Fault],
            duration: TimeInterval,
            expectedBehavior: ExpectedBehavior
        ) {
            self.name = name
            self.description = description
            self.faults = faults
            self.duration = duration
            self.expectedBehavior = expectedBehavior
        }
    }

    /// Expected behavior during/after chaos
    public struct ExpectedBehavior: Sendable {
        /// Minimum connectivity during chaos (0-100%)
        public let minConnectivityDuringChaos: Double

        /// Minimum connectivity after recovery (0-100%)
        public let minConnectivityAfterRecovery: Double

        /// Maximum acceptable message loss (0-100%)
        public let maxMessageLoss: Double

        /// Maximum time to recover in seconds
        public let maxRecoveryTime: TimeInterval

        public init(
            minConnectivityDuringChaos: Double = 50,
            minConnectivityAfterRecovery: Double = 90,
            maxMessageLoss: Double = 20,
            maxRecoveryTime: TimeInterval = 30
        ) {
            self.minConnectivityDuringChaos = minConnectivityDuringChaos
            self.minConnectivityAfterRecovery = minConnectivityAfterRecovery
            self.maxMessageLoss = maxMessageLoss
            self.maxRecoveryTime = maxRecoveryTime
        }

        public static let strict = ExpectedBehavior(
            minConnectivityDuringChaos: 80,
            minConnectivityAfterRecovery: 99,
            maxMessageLoss: 5,
            maxRecoveryTime: 10
        )

        public static let lenient = ExpectedBehavior(
            minConnectivityDuringChaos: 30,
            minConnectivityAfterRecovery: 80,
            maxMessageLoss: 40,
            maxRecoveryTime: 60
        )
    }

    // MARK: - Standard Scenarios

    /// Network partition: splits network in half
    public static func networkSplit(nodeIds: [String]) -> Scenario {
        let mid = nodeIds.count / 2
        let group1 = Array(nodeIds.prefix(mid))
        let group2 = Array(nodeIds.suffix(from: mid))

        return Scenario(
            name: "Network Split",
            description: "Splits network into two isolated partitions",
            faults: [.networkPartition(group1: group1, group2: group2)],
            duration: 30,
            expectedBehavior: ExpectedBehavior(
                minConnectivityDuringChaos: 25,
                minConnectivityAfterRecovery: 90
            )
        )
    }

    /// Latency storm: random nodes get high latency
    public static func latencyStorm(nodeIds: [String], durationPerNode: TimeInterval = 5) -> Scenario {
        let faults = nodeIds.prefix(3).map { nodeId in
            FaultInjector.Fault.latencySpike(
                nodeId: nodeId,
                additionalMs: Int.random(in: 200...1000),
                duration: durationPerNode
            )
        }

        return Scenario(
            name: "Latency Storm",
            description: "Multiple nodes experience high latency spikes",
            faults: faults,
            duration: durationPerNode * Double(faults.count),
            expectedBehavior: ExpectedBehavior(
                minConnectivityDuringChaos: 70,
                maxMessageLoss: 30
            )
        )
    }

    /// Rolling failures: nodes fail one at a time
    public static func rollingFailures(nodeIds: [String]) -> Scenario {
        let faults = nodeIds.prefix(2).map { nodeId in
            FaultInjector.Fault.nodeFailure(nodeId: nodeId)
        }

        return Scenario(
            name: "Rolling Failures",
            description: "Nodes fail sequentially",
            faults: faults,
            duration: 60,
            expectedBehavior: ExpectedBehavior(
                minConnectivityDuringChaos: 50,
                minConnectivityAfterRecovery: 70
            )
        )
    }

    /// NAT chaos: all NAT nodes experience mapping expiry
    public static func natChaos(natNodeIds: [String]) -> Scenario {
        let faults = natNodeIds.map { nodeId in
            FaultInjector.Fault.natMappingExpiry(nodeId: nodeId)
        }

        return Scenario(
            name: "NAT Chaos",
            description: "All NAT mappings expire simultaneously",
            faults: faults,
            duration: 30,
            expectedBehavior: ExpectedBehavior(
                minConnectivityDuringChaos: 40,
                minConnectivityAfterRecovery: 85,
                maxRecoveryTime: 45
            )
        )
    }

    /// Packet loss: random packet loss across network
    public static func packetLossStorm(nodeIds: [String], lossPercent: Double = 30) -> Scenario {
        let faults = nodeIds.prefix(4).map { nodeId in
            FaultInjector.Fault.packetLoss(
                nodeId: nodeId,
                percent: lossPercent,
                duration: 20
            )
        }

        return Scenario(
            name: "Packet Loss Storm",
            description: "Multiple nodes experience packet loss",
            faults: faults,
            duration: 20,
            expectedBehavior: ExpectedBehavior(
                minConnectivityDuringChaos: 60,
                maxMessageLoss: 50
            )
        )
    }

    /// Flapping connections
    public static func flappingConnections(nodeIds: [String]) -> Scenario {
        let faults = nodeIds.prefix(2).map { nodeId in
            FaultInjector.Fault.flappingConnection(
                nodeId: nodeId,
                upDuration: 3,
                downDuration: 2,
                cycles: 5
            )
        }

        return Scenario(
            name: "Flapping Connections",
            description: "Connections repeatedly go up and down",
            faults: faults,
            duration: 25,
            expectedBehavior: ExpectedBehavior(
                minConnectivityDuringChaos: 30,
                minConnectivityAfterRecovery: 90
            )
        )
    }

    /// Combined chaos: multiple fault types at once
    public static func combinedChaos(nodeIds: [String]) -> Scenario {
        guard nodeIds.count >= 4 else {
            return Scenario(
                name: "Combined Chaos",
                description: "Not enough nodes",
                faults: [],
                duration: 0,
                expectedBehavior: .lenient
            )
        }

        var faults: [FaultInjector.Fault] = []

        // Partition
        faults.append(.networkPartition(
            group1: [nodeIds[0]],
            group2: Array(nodeIds.dropFirst())
        ))

        // Latency
        faults.append(.latencySpike(
            nodeId: nodeIds[1],
            additionalMs: 500,
            duration: 15
        ))

        // Packet loss
        faults.append(.packetLoss(
            nodeId: nodeIds[2],
            percent: 25,
            duration: 15
        ))

        return Scenario(
            name: "Combined Chaos",
            description: "Multiple fault types occur simultaneously",
            faults: faults,
            duration: 30,
            expectedBehavior: .lenient
        )
    }

    /// Gradual degradation: network slowly gets worse
    public static func gradualDegradation(nodeIds: [String]) -> Scenario {
        var faults: [FaultInjector.Fault] = []

        for (i, nodeId) in nodeIds.enumerated() where i < 5 {
            faults.append(.latencySpike(
                nodeId: nodeId,
                additionalMs: 100 * (i + 1),
                duration: 30
            ))
        }

        return Scenario(
            name: "Gradual Degradation",
            description: "Network performance slowly degrades",
            faults: faults,
            duration: 30,
            expectedBehavior: ExpectedBehavior(
                minConnectivityDuringChaos: 60,
                maxMessageLoss: 25
            )
        )
    }
}

// MARK: - Chaos Runner

/// Runs chaos scenarios and collects results
public actor ChaosRunner {
    private let injector = FaultInjector()

    public init() {}

    /// Run a scenario and return results
    public func run(
        _ scenario: ChaosScenarios.Scenario,
        on network: TestNetwork
    ) async -> ChaosResult {
        let startTime = Date()

        // Inject all faults
        var faultIds: [FaultInjector.FaultID] = []
        for fault in scenario.faults {
            let id = await injector.inject(fault, into: network)
            faultIds.append(id)
        }

        // Monitor during chaos
        let impactReport = await injector.measureImpact(
            on: network,
            during: scenario.duration
        )

        // Remove all faults
        await injector.removeAllFaults(from: network)

        // Allow recovery
        try? await Task.sleep(nanoseconds: UInt64(scenario.expectedBehavior.maxRecoveryTime * 1_000_000_000))

        // Check final connectivity
        let finalConnectivity = await measureConnectivity(network)

        let endTime = Date()

        return ChaosResult(
            scenario: scenario,
            startTime: startTime,
            endTime: endTime,
            impactReport: impactReport,
            finalConnectivity: finalConnectivity,
            faultsInjected: faultIds.count
        )
    }

    /// Run multiple scenarios sequentially
    public func runAll(
        _ scenarios: [ChaosScenarios.Scenario],
        on network: TestNetwork
    ) async -> [ChaosResult] {
        var results: [ChaosResult] = []

        for scenario in scenarios {
            let result = await run(scenario, on: network)
            results.append(result)

            // Brief pause between scenarios
            try? await Task.sleep(nanoseconds: 2_000_000_000)
        }

        return results
    }

    private func measureConnectivity(_ network: TestNetwork) async -> Double {
        // Simplified connectivity measurement
        let nodeIds = network.nodeIds
        guard nodeIds.count >= 2 else { return 100 }

        // In a real implementation, we'd actually probe connectivity
        // For now, return a placeholder
        return 95.0
    }
}

/// Result of running a chaos scenario
public struct ChaosResult: Sendable {
    public let scenario: ChaosScenarios.Scenario
    public let startTime: Date
    public let endTime: Date
    public let impactReport: FaultImpactReport
    public let finalConnectivity: Double
    public let faultsInjected: Int

    public var duration: TimeInterval {
        endTime.timeIntervalSince(startTime)
    }

    public var passed: Bool {
        let expected = scenario.expectedBehavior
        return impactReport.avgConnectivity >= expected.minConnectivityDuringChaos &&
               finalConnectivity >= expected.minConnectivityAfterRecovery
    }

    public var summary: String {
        """
        Scenario: \(scenario.name)
        Duration: \(String(format: "%.1f", duration))s
        Faults: \(faultsInjected)
        Avg Connectivity: \(String(format: "%.1f", impactReport.avgConnectivity))%
        Min Connectivity: \(String(format: "%.1f", impactReport.minConnectivity))%
        Final Connectivity: \(String(format: "%.1f", finalConnectivity))%
        Result: \(passed ? "PASSED" : "FAILED")
        """
    }
}

// MARK: - Chaos Test Helpers

extension TestNetwork {
    /// Run a quick chaos test
    public func runChaosTest(
        _ scenario: ChaosScenarios.Scenario
    ) async -> ChaosResult {
        let runner = ChaosRunner()
        return await runner.run(scenario, on: self)
    }

    /// Run standard chaos scenarios
    public func runStandardChaosTests() async -> [ChaosResult] {
        let scenarios = [
            ChaosScenarios.networkSplit(nodeIds: nodeIds),
            ChaosScenarios.latencyStorm(nodeIds: nodeIds),
            ChaosScenarios.packetLossStorm(nodeIds: nodeIds)
        ]

        let runner = ChaosRunner()
        return await runner.runAll(scenarios, on: self)
    }
}
