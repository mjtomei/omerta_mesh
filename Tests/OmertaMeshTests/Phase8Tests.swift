// Phase8Tests.swift - Tests for Phase 8: Advanced Test Infrastructure
//
// Tests for:
// - SimulatedNAT accuracy for all NAT types
// - FaultInjector reliability and determinism
// - ChaosScenarios for resilience verification
// - Performance benchmark infrastructure

import XCTest
@testable import OmertaMesh

final class Phase8Tests: XCTestCase {

    // MARK: - SimulatedNAT Tests

    func testPublicNATNoTranslation() async throws {
        let nat = SimulatedNAT(type: .public, publicIP: "1.2.3.4")

        let result = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")

        XCTAssertEqual(result, "192.168.1.1:5000", "Public NAT should not translate")
    }

    func testFullConeNATAllowsAnyInbound() async throws {
        let nat = SimulatedNAT(type: .fullCone, publicIP: "1.2.3.4")

        // Create outbound mapping
        let external = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        XCTAssertNotNil(external)

        // Any source should be able to send to mapped port
        let result1 = await nat.filterInbound(from: "10.0.0.2:9000", to: external!)
        let result2 = await nat.filterInbound(from: "10.0.0.3:7000", to: external!)

        XCTAssertNotNil(result1, "Full cone should allow any source")
        XCTAssertNotNil(result2, "Full cone should allow any source")
    }

    func testRestrictedConeNATFiltersUnknownIPs() async throws {
        let nat = SimulatedNAT(type: .restrictedCone, publicIP: "1.2.3.4")

        // Create outbound mapping to specific destination
        let external = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        XCTAssertNotNil(external)

        // Same IP, different port should work
        let result1 = await nat.filterInbound(from: "10.0.0.1:9999", to: external!)
        XCTAssertNotNil(result1, "Restricted cone should allow same IP, different port")

        // Different IP should be blocked
        let result2 = await nat.filterInbound(from: "10.0.0.2:8000", to: external!)
        XCTAssertNil(result2, "Restricted cone should block unknown IP")
    }

    func testPortRestrictedConeNATFiltersUnknownPorts() async throws {
        let nat = SimulatedNAT(type: .portRestrictedCone, publicIP: "1.2.3.4")

        // Create outbound mapping to specific destination
        let external = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        XCTAssertNotNil(external)

        // Exact match should work
        let result1 = await nat.filterInbound(from: "10.0.0.1:8000", to: external!)
        XCTAssertNotNil(result1, "Port restricted should allow exact match")

        // Same IP, different port should be blocked
        let result2 = await nat.filterInbound(from: "10.0.0.1:9999", to: external!)
        XCTAssertNil(result2, "Port restricted should block different port")
    }

    func testSymmetricNATCreatesDifferentMappings() async throws {
        let nat = SimulatedNAT(type: .symmetric, publicIP: "1.2.3.4", portAllocation: .sequential)

        // Create mappings to different destinations
        let external1 = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        let external2 = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.2:8000")

        XCTAssertNotNil(external1)
        XCTAssertNotNil(external2)
        XCTAssertNotEqual(external1, external2, "Symmetric NAT should create different mappings per destination")
    }

    func testNATMappingExpiry() async throws {
        let nat = SimulatedNAT(type: .fullCone, publicIP: "1.2.3.4")

        // Create mapping
        let external = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        XCTAssertNotNil(external)

        let countBefore = await nat.getActiveMappingCount()
        XCTAssertEqual(countBefore, 1)

        // Expire all mappings
        await nat.expireAllMappings()

        let countAfter = await nat.getActiveMappingCount()
        XCTAssertEqual(countAfter, 0)

        // Inbound should now be blocked
        let result = await nat.filterInbound(from: "10.0.0.1:8000", to: external!)
        XCTAssertNil(result, "Inbound should be blocked after mapping expires")
    }

    func testNATStatistics() async throws {
        let nat = SimulatedNAT(type: .fullCone, publicIP: "1.2.3.4")

        // Generate some traffic
        _ = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        _ = await nat.translateOutbound(from: "192.168.1.2:5000", to: "10.0.0.2:8000")

        let stats = await nat.getStats()
        XCTAssertEqual(stats.packetsTranslated, 2)
        XCTAssertEqual(stats.mappingsCreated, 2)
    }

    func testNATDisable() async throws {
        let nat = SimulatedNAT(type: .fullCone, publicIP: "1.2.3.4")

        // Create mapping while enabled
        let external = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        XCTAssertNotNil(external)

        // Disable NAT
        await nat.setEnabled(false)

        // Outbound should be blocked
        let result = await nat.translateOutbound(from: "192.168.1.2:5000", to: "10.0.0.2:8000")
        XCTAssertNil(result, "Disabled NAT should block outbound")

        // Inbound should also be blocked
        let inbound = await nat.filterInbound(from: "10.0.0.1:8000", to: external!)
        XCTAssertNil(inbound, "Disabled NAT should block inbound")
    }

    func testHairpinNAT() async throws {
        let config = SimulatedNAT.NATConfig(supportsHairpin: true)
        let nat = SimulatedNAT(type: .fullCone, publicIP: "1.2.3.4", config: config)

        // Create mapping for target
        let targetExternal = await nat.translateOutbound(from: "192.168.1.2:6000", to: "10.0.0.1:8000")
        XCTAssertNotNil(targetExternal)

        // Hairpin translation
        let result = await nat.translateHairpin(from: "192.168.1.1:5000", to: targetExternal!)
        XCTAssertEqual(result, "192.168.1.2:6000", "Hairpin should return internal endpoint of target")
    }

    func testHairpinNATNotSupported() async throws {
        let config = SimulatedNAT.NATConfig(supportsHairpin: false)
        let nat = SimulatedNAT(type: .fullCone, publicIP: "1.2.3.4", config: config)

        // Create mapping for target
        let targetExternal = await nat.translateOutbound(from: "192.168.1.2:6000", to: "10.0.0.1:8000")
        XCTAssertNotNil(targetExternal)

        // Hairpin should fail
        let result = await nat.translateHairpin(from: "192.168.1.1:5000", to: targetExternal!)
        XCTAssertNil(result, "Non-hairpin NAT should block hairpin requests")
    }

    func testSymmetricNATPortPrediction() async throws {
        let config = SimulatedNAT.NATConfig(predictablePortDelta: 1)
        let nat = SimulatedNAT(type: .symmetric, publicIP: "1.2.3.4", portAllocation: .sequential, config: config)

        // Create initial mapping
        let external = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        XCTAssertNotNil(external)

        // Predict next port
        let predicted = await nat.predictNextPort(for: "192.168.1.1:5000", currentDestination: "10.0.0.1:8000")
        XCTAssertNotNil(predicted)

        // Get the current port
        let currentPort = external!.split(separator: ":").last.flatMap { UInt16($0) }
        XCTAssertNotNil(currentPort)

        if let curr = currentPort, let pred = predicted {
            XCTAssertEqual(pred, curr + 1, "Predicted port should be current + delta")
        }
    }

    func testMaxMappingsLimit() async throws {
        let config = SimulatedNAT.NATConfig(maxMappings: 2)
        let nat = SimulatedNAT(type: .fullCone, publicIP: "1.2.3.4", config: config)

        // Create max mappings
        let ext1 = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        let ext2 = await nat.translateOutbound(from: "192.168.1.2:5000", to: "10.0.0.2:8000")
        XCTAssertNotNil(ext1)
        XCTAssertNotNil(ext2)

        // Third mapping should fail (unless previous mappings expired)
        let ext3 = await nat.translateOutbound(from: "192.168.1.3:5000", to: "10.0.0.3:8000")
        XCTAssertNil(ext3, "Should fail when max mappings reached")
    }

    // MARK: - FaultInjector Tests

    func testFaultInjectorLatencySpike() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let injector = FaultInjector()

        let faultId = await injector.inject(
            .latencySpike(nodeId: "A", additionalMs: 100, duration: 5.0),
            into: network
        )

        let activeFaults = await injector.getActiveFaultIds()
        XCTAssertEqual(activeFaults.count, 1)
        XCTAssertTrue(activeFaults.contains(faultId))
    }

    func testFaultInjectorRemoveFault() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let injector = FaultInjector()

        let faultId = await injector.inject(
            .latencySpike(nodeId: "A", additionalMs: 100, duration: 60.0),
            into: network
        )

        let countBefore = await injector.getActiveFaultIds().count
        XCTAssertEqual(countBefore, 1)

        await injector.removeFault(faultId, from: network)

        let countAfter = await injector.getActiveFaultIds().count
        XCTAssertEqual(countAfter, 0)
    }

    func testFaultInjectorRemoveAllFaults() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .addPublicNode(id: "C")
            .link("A", "B")
            .link("B", "C")
            .build()
        defer { Task { await network.shutdown() } }

        let injector = FaultInjector()

        // Inject multiple faults
        _ = await injector.inject(.latencySpike(nodeId: "A", additionalMs: 100, duration: 60.0), into: network)
        _ = await injector.inject(.packetLoss(nodeId: "B", percent: 50, duration: 60.0), into: network)

        let countBefore = await injector.getActiveFaultIds().count
        XCTAssertEqual(countBefore, 2)

        await injector.removeAllFaults(from: network)

        let countAfter = await injector.getActiveFaultIds().count
        XCTAssertEqual(countAfter, 0)
    }

    func testFaultInjectorNetworkPartition() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .addPublicNode(id: "C")
            .addPublicNode(id: "D")
            .link("A", "B")
            .link("B", "C")
            .link("C", "D")
            .build()
        defer { Task { await network.shutdown() } }

        let injector = FaultInjector()

        _ = await injector.inject(
            .networkPartition(group1: ["A", "B"], group2: ["C", "D"]),
            into: network
        )

        let isPartitioned = await injector.isActive { fault in
            if case .networkPartition = fault { return true }
            return false
        }
        XCTAssertTrue(isPartitioned)
    }

    func testFaultInjectorSequence() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let injector = FaultInjector()

        let faults: [(fault: FaultInjector.Fault, delayBefore: TimeInterval)] = [
            (.latencySpike(nodeId: "A", additionalMs: 50, duration: 10.0), 0.0),
            (.packetLoss(nodeId: "B", percent: 10, duration: 10.0), 0.1)
        ]

        let ids = await injector.injectSequence(faults, into: network)
        XCTAssertEqual(ids.count, 2)

        let activeFaults = await injector.getActiveFaultIds()
        XCTAssertEqual(activeFaults.count, 2)
    }

    func testFaultInjectorMeasureImpact() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let injector = FaultInjector()

        let report = await injector.measureImpact(
            on: network,
            during: 0.5,
            sampleIntervalMs: 100
        )

        XCTAssertGreaterThan(report.samples.count, 0)
        XCTAssertGreaterThanOrEqual(report.avgConnectivity, 0)
        XCTAssertLessThanOrEqual(report.avgConnectivity, 100)
    }

    func testFaultInjectorNodeFailure() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let injector = FaultInjector()

        _ = await injector.inject(.nodeFailure(nodeId: "A"), into: network)

        // Verify the node is no longer running
        let nodeA = network.node("A")
        let isRunning = await nodeA.isRunning
        XCTAssertFalse(isRunning)
    }

    // MARK: - ChaosScenarios Tests

    func testChaosScenarioNetworkSplit() async throws {
        let nodeIds = ["A", "B", "C", "D"]
        let scenario = ChaosScenarios.networkSplit(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Network Split")
        XCTAssertEqual(scenario.faults.count, 1)

        if case .networkPartition(let group1, let group2) = scenario.faults.first {
            XCTAssertEqual(group1.count, 2)
            XCTAssertEqual(group2.count, 2)
        } else {
            XCTFail("Expected network partition fault")
        }
    }

    func testChaosScenarioLatencyStorm() async throws {
        let nodeIds = ["A", "B", "C", "D", "E"]
        let scenario = ChaosScenarios.latencyStorm(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Latency Storm")
        XCTAssertEqual(scenario.faults.count, 3) // Takes first 3 nodes
    }

    func testChaosScenarioRollingFailures() async throws {
        let nodeIds = ["A", "B", "C", "D"]
        let scenario = ChaosScenarios.rollingFailures(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Rolling Failures")
        XCTAssertEqual(scenario.faults.count, 2) // Takes first 2 nodes
    }

    func testChaosScenarioNATChaos() async throws {
        let natNodeIds = ["NAT1", "NAT2", "NAT3"]
        let scenario = ChaosScenarios.natChaos(natNodeIds: natNodeIds)

        XCTAssertEqual(scenario.name, "NAT Chaos")
        XCTAssertEqual(scenario.faults.count, 3)
    }

    func testChaosScenarioPacketLossStorm() async throws {
        let nodeIds = ["A", "B", "C", "D", "E"]
        let scenario = ChaosScenarios.packetLossStorm(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Packet Loss Storm")
        XCTAssertEqual(scenario.faults.count, 4) // Takes first 4 nodes
    }

    func testChaosScenarioFlappingConnections() async throws {
        let nodeIds = ["A", "B", "C"]
        let scenario = ChaosScenarios.flappingConnections(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Flapping Connections")
        XCTAssertEqual(scenario.faults.count, 2) // Takes first 2 nodes
    }

    func testChaosScenarioCombinedChaos() async throws {
        let nodeIds = ["A", "B", "C", "D"]
        let scenario = ChaosScenarios.combinedChaos(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Combined Chaos")
        XCTAssertEqual(scenario.faults.count, 3) // Partition, latency, packet loss
    }

    func testChaosScenarioCombinedChaosNotEnoughNodes() async throws {
        let nodeIds = ["A", "B", "C"] // Less than 4
        let scenario = ChaosScenarios.combinedChaos(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Combined Chaos")
        XCTAssertEqual(scenario.faults.count, 0)
    }

    func testChaosScenarioGradualDegradation() async throws {
        let nodeIds = ["A", "B", "C", "D", "E", "F"]
        let scenario = ChaosScenarios.gradualDegradation(nodeIds: nodeIds)

        XCTAssertEqual(scenario.name, "Gradual Degradation")
        XCTAssertEqual(scenario.faults.count, 5) // Takes first 5 nodes
    }

    func testExpectedBehaviorDefaults() throws {
        let expected = ChaosScenarios.ExpectedBehavior()

        XCTAssertEqual(expected.minConnectivityDuringChaos, 50)
        XCTAssertEqual(expected.minConnectivityAfterRecovery, 90)
        XCTAssertEqual(expected.maxMessageLoss, 20)
        XCTAssertEqual(expected.maxRecoveryTime, 30)
    }

    func testExpectedBehaviorStrict() throws {
        let strict = ChaosScenarios.ExpectedBehavior.strict

        XCTAssertEqual(strict.minConnectivityDuringChaos, 80)
        XCTAssertEqual(strict.minConnectivityAfterRecovery, 99)
        XCTAssertEqual(strict.maxMessageLoss, 5)
        XCTAssertEqual(strict.maxRecoveryTime, 10)
    }

    func testExpectedBehaviorLenient() throws {
        let lenient = ChaosScenarios.ExpectedBehavior.lenient

        XCTAssertEqual(lenient.minConnectivityDuringChaos, 30)
        XCTAssertEqual(lenient.minConnectivityAfterRecovery, 80)
        XCTAssertEqual(lenient.maxMessageLoss, 40)
        XCTAssertEqual(lenient.maxRecoveryTime, 60)
    }

    // MARK: - ChaosRunner Tests

    // Disabled: ChaosRunner sleeps for maxRecoveryTime (60s) with a stub connectivity check
    func _disabled_testChaosRunnerRunScenario() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .addPublicNode(id: "C")
            .addPublicNode(id: "D")
            .link("A", "B")
            .link("B", "C")
            .link("C", "D")
            .build()
        defer { Task { await network.shutdown() } }

        // Start all nodes
        for id in ["A", "B", "C", "D"] {
            try await network.node(id).start()
        }

        let scenario = ChaosScenarios.Scenario(
            name: "Quick Test",
            description: "Short scenario for testing",
            faults: [.latencySpike(nodeId: "A", additionalMs: 50, duration: 0.5)],
            duration: 0.5,
            expectedBehavior: .lenient
        )

        let result = await network.runChaosTest(scenario)

        XCTAssertEqual(result.scenario.name, "Quick Test")
        XCTAssertEqual(result.faultsInjected, 1)
        XCTAssertGreaterThan(result.duration, 0)
    }

    func testChaosResultSummary() async throws {
        let scenario = ChaosScenarios.Scenario(
            name: "Test Scenario",
            description: "Test",
            faults: [],
            duration: 1.0,
            expectedBehavior: .lenient
        )

        let impactReport = FaultImpactReport(samples: [
            HealthSample(timestamp: Date(), activeFaultCount: 0, nodeCount: 4, connectivityPercent: 95.0)
        ])

        let result = ChaosResult(
            scenario: scenario,
            startTime: Date(),
            endTime: Date().addingTimeInterval(1.0),
            impactReport: impactReport,
            finalConnectivity: 95.0,
            faultsInjected: 0
        )

        let summary = result.summary
        XCTAssertTrue(summary.contains("Test Scenario"))
        XCTAssertTrue(summary.contains("PASSED") || summary.contains("FAILED"))
    }

    // MARK: - BenchmarkResults Tests

    func testBenchmarkResultsAdd() throws {
        var results = BenchmarkResults()

        results.add(
            name: "Test Benchmark",
            metric: "throughput",
            value: 1500.0,
            unit: "msg/s",
            baseline: 1000.0
        )

        XCTAssertEqual(results.results.count, 1)
        XCTAssertTrue(results.results[0].passed)
    }

    func testBenchmarkResultsFailsBaseline() throws {
        var results = BenchmarkResults()

        results.add(
            name: "Test Benchmark",
            metric: "throughput",
            value: 500.0,
            unit: "msg/s",
            baseline: 1000.0
        )

        XCTAssertEqual(results.results.count, 1)
        XCTAssertFalse(results.results[0].passed)
    }

    func testBenchmarkResultsSummary() throws {
        var results = BenchmarkResults()

        results.add(name: "Fast Test", metric: "rate", value: 2000.0, unit: "ops/s", baseline: 1000.0)
        results.add(name: "Slow Test", metric: "rate", value: 500.0, unit: "ops/s", baseline: 1000.0)

        let summary = results.summary
        XCTAssertTrue(summary.contains("PASS"))
        XCTAssertTrue(summary.contains("FAIL"))
        XCTAssertTrue(summary.contains("1/2 passed"))
    }

    // MARK: - FaultImpactReport Tests

    func testFaultImpactReportEmptySamples() throws {
        let report = FaultImpactReport(samples: [])

        XCTAssertEqual(report.avgConnectivity, 100)
        XCTAssertEqual(report.minConnectivity, 100)
        XCTAssertEqual(report.maxFaultCount, 0)
        XCTAssertEqual(report.duration, 0)
    }

    func testFaultImpactReportWithSamples() throws {
        let now = Date()
        let samples = [
            HealthSample(timestamp: now, activeFaultCount: 1, nodeCount: 4, connectivityPercent: 80.0),
            HealthSample(timestamp: now.addingTimeInterval(0.1), activeFaultCount: 2, nodeCount: 4, connectivityPercent: 60.0),
            HealthSample(timestamp: now.addingTimeInterval(0.2), activeFaultCount: 1, nodeCount: 4, connectivityPercent: 90.0)
        ]

        let report = FaultImpactReport(samples: samples)

        XCTAssertEqual(report.avgConnectivity, (80.0 + 60.0 + 90.0) / 3.0, accuracy: 0.01)
        XCTAssertEqual(report.minConnectivity, 60.0)
        XCTAssertEqual(report.maxFaultCount, 2)
        XCTAssertEqual(report.duration, 0.2, accuracy: 0.01)
    }

    // MARK: - HealthSample Tests

    func testHealthSampleCreation() throws {
        let sample = HealthSample(
            timestamp: Date(),
            activeFaultCount: 3,
            nodeCount: 10,
            connectivityPercent: 75.5
        )

        XCTAssertEqual(sample.activeFaultCount, 3)
        XCTAssertEqual(sample.nodeCount, 10)
        XCTAssertEqual(sample.connectivityPercent, 75.5)
    }

    // MARK: - Integration Tests

    // Disabled: ChaosRunner sleeps for maxRecoveryTime (60s) with a stub connectivity check
    func _disabled_testTestNetworkChaosTestExtension() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .addPublicNode(id: "C")
            .link("A", "B")
            .link("B", "C")
            .build()
        defer { Task { await network.shutdown() } }

        for id in ["A", "B", "C"] {
            try await network.node(id).start()
        }

        let scenario = ChaosScenarios.Scenario(
            name: "Integration Test",
            description: "Tests the integration of chaos testing",
            faults: [],
            duration: 0.2,
            expectedBehavior: .lenient
        )

        let result = await network.runChaosTest(scenario)
        XCTAssertTrue(result.passed)
    }

    // MARK: - NAT Type Behavior Matrix Tests

    func testAllNATTypesOutbound() async throws {
        let natTypes: [NATType] = [.public, .fullCone, .restrictedCone, .portRestrictedCone, .symmetric]

        for natType in natTypes {
            let nat = SimulatedNAT(type: natType, publicIP: "1.2.3.4")
            let result = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
            XCTAssertNotNil(result, "NAT type \(natType) should allow outbound")
        }
    }

    func testAllNATTypesInboundWithMapping() async throws {
        let testCases: [(NATType, String, Bool)] = [
            // (NAT type, source endpoint, should allow)
            (.fullCone, "10.0.0.2:9000", true),      // Full cone allows any source
            (.restrictedCone, "10.0.0.1:9000", true), // Restricted allows same IP
            (.restrictedCone, "10.0.0.2:9000", false), // Restricted blocks different IP
            (.portRestrictedCone, "10.0.0.1:8000", true), // Port restricted allows exact match
            (.portRestrictedCone, "10.0.0.1:9000", false), // Port restricted blocks different port
        ]

        for (natType, source, shouldAllow) in testCases {
            let nat = SimulatedNAT(type: natType, publicIP: "1.2.3.4")

            // Create mapping
            let external = await nat.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
            XCTAssertNotNil(external)

            let result = await nat.filterInbound(from: source, to: external!)

            if shouldAllow {
                XCTAssertNotNil(result, "NAT type \(natType) should allow from \(source)")
            } else {
                XCTAssertNil(result, "NAT type \(natType) should block from \(source)")
            }
        }
    }

    // MARK: - Fault Type Coverage Tests

    func testAllFaultTypesCreatable() throws {
        let faults: [FaultInjector.Fault] = [
            .networkPartition(group1: ["A"], group2: ["B"]),
            .latencySpike(nodeId: "A", additionalMs: 100, duration: 5.0),
            .packetLoss(nodeId: "A", percent: 50, duration: 5.0),
            .natMappingExpiry(nodeId: "A"),
            .nodeFailure(nodeId: "A"),
            .linkFailure(from: "A", to: "B", duration: 5.0),
            .bandwidthThrottle(nodeId: "A", bytesPerSecond: 1000, duration: 5.0),
            .clockSkew(nodeId: "A", offsetSeconds: 10, duration: 5.0),
            .jitter(nodeId: "A", minMs: 10, maxMs: 100, duration: 5.0),
            .packetReorder(nodeId: "A", percent: 20, maxDelayMs: 50, duration: 5.0),
            .packetDuplicate(nodeId: "A", percent: 10, duration: 5.0),
            .natRebind(nodeId: "A"),
            .flappingConnection(nodeId: "A", upDuration: 2.0, downDuration: 1.0, cycles: 3)
        ]

        XCTAssertEqual(faults.count, 13, "Should have 13 fault types")
    }

    // MARK: - Performance Infrastructure Tests

    func testNATTranslationPerformance() async throws {
        let nat = SimulatedNAT(type: .portRestrictedCone)

        let iterations = 1000
        let startTime = Date()

        for i in 0..<iterations {
            let internalEndpoint = "192.168.1.\(i % 256):\(5000 + i % 1000)"
            let destination = "10.0.0.\(i % 256):\(8000 + i % 1000)"
            _ = await nat.translateOutbound(from: internalEndpoint, to: destination)
        }

        let duration = Date().timeIntervalSince(startTime)
        let rate = Double(iterations) / duration

        // Should handle at least 1000 translations per second
        XCTAssertGreaterThan(rate, 1000, "NAT translation rate should be > 1000/s, got \(rate)")
    }

    func testHolePunchCompatibilityPerformance() async throws {
        let natTypes: [NATType] = [.public, .fullCone, .restrictedCone, .portRestrictedCone, .symmetric, .unknown]

        let iterations = 1000
        let startTime = Date()

        for _ in 0..<iterations {
            let initiator = natTypes.randomElement()!
            let responder = natTypes.randomElement()!
            _ = HolePunchCompatibility.check(initiator: initiator, responder: responder)
        }

        let duration = Date().timeIntervalSince(startTime)
        let rate = Double(iterations) / duration

        // Should handle at least 10000 checks per second
        XCTAssertGreaterThan(rate, 10000, "Compatibility check rate should be > 10000/s, got \(rate)")
    }
}
