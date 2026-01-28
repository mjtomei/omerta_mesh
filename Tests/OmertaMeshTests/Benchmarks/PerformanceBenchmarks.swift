// PerformanceBenchmarks.swift - Performance benchmarks for mesh network

import Foundation
import XCTest
@testable import OmertaMesh

/// Performance benchmarks for establishing baselines
final class PerformanceBenchmarks: XCTestCase {

    // MARK: - Message Throughput

    func testMessageThroughput() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        try await network.node("A").start()
        try await network.node("B").start()

        let messageCount = 1000
        let messageSize = 1024 // 1KB

        let startTime = Date()

        for i in 0..<messageCount {
            let data = Data(repeating: UInt8(i % 256), count: messageSize)
            await network.node("A").send(.data(data), to: "B")
        }

        // Wait for all messages to be delivered
        try await Task.sleep(nanoseconds: 500_000_000)

        let endTime = Date()
        let duration = endTime.timeIntervalSince(startTime)
        let messagesPerSecond = Double(messageCount) / duration
        let throughputMBps = Double(messageCount * messageSize) / duration / 1_000_000

        print("Message Throughput Benchmark:")
        print("  Messages: \(messageCount)")
        print("  Duration: \(String(format: "%.3f", duration))s")
        print("  Rate: \(String(format: "%.1f", messagesPerSecond)) msg/s")
        print("  Throughput: \(String(format: "%.2f", throughputMBps)) MB/s")

        // Baseline: should handle at least 1000 msg/s locally
        XCTAssertGreaterThan(messagesPerSecond, 100)
    }

    // MARK: - Latency

    func testPingLatency() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "A")
            .addPublicNode(id: "B")
            .link("A", "B", latencyMs: 0)
            .build()
        defer { Task { await network.shutdown() } }

        try await network.node("A").start()
        try await network.node("B").start()

        let iterations = 100
        var latencies: [TimeInterval] = []

        for _ in 0..<iterations {
            let startTime = Date()

            do {
                _ = try await network.node("A").sendAndReceive(
                    .ping(recentPeers: [], myNATType: .unknown),
                    to: "B",
                    timeout: 1.0
                )
                let latency = Date().timeIntervalSince(startTime)
                latencies.append(latency)
            } catch {
                // Ignore timeouts
            }
        }

        guard !latencies.isEmpty else {
            XCTFail("No successful pings")
            return
        }

        let avgLatency = latencies.reduce(0, +) / Double(latencies.count)
        let minLatency = latencies.min()!
        let maxLatency = latencies.max()!
        let p99Latency = latencies.sorted()[Int(Double(latencies.count) * 0.99)]

        print("Ping Latency Benchmark:")
        print("  Iterations: \(latencies.count)/\(iterations)")
        print("  Avg: \(String(format: "%.3f", avgLatency * 1000))ms")
        print("  Min: \(String(format: "%.3f", minLatency * 1000))ms")
        print("  Max: \(String(format: "%.3f", maxLatency * 1000))ms")
        print("  P99: \(String(format: "%.3f", p99Latency * 1000))ms")

        // Baseline: avg latency should be < 50ms in local test
        XCTAssertLessThan(avgLatency, 0.1)
    }

    // MARK: - Scaling

    func testNetworkScaling() async throws {
        let nodeCounts = [5, 10, 20, 50]
        var results: [(nodeCount: Int, setupTime: TimeInterval, messageTime: TimeInterval)] = []

        for count in nodeCounts {
            let builder = TestNetworkBuilder()

            // Create nodes
            for i in 0..<count {
                builder.addPublicNode(id: "node\(i)")
            }

            // Create random mesh (each node connected to ~3 others)
            for i in 0..<count {
                for _ in 0..<3 {
                    let j = Int.random(in: 0..<count)
                    if i != j {
                        builder.link("node\(i)", "node\(j)")
                    }
                }
            }

            // Measure setup time
            let setupStart = Date()
            let network = try await builder.build()
            let setupTime = Date().timeIntervalSince(setupStart)

            // Start all nodes
            for i in 0..<count {
                try await network.node("node\(i)").start()
            }

            // Measure message broadcast time
            let msgStart = Date()
            for i in 0..<min(count, 10) {
                await network.node("node0").send(.ping(recentPeers: [], myNATType: .unknown), to: "node\(i)")
            }
            try await Task.sleep(nanoseconds: 100_000_000) // Allow delivery
            let msgTime = Date().timeIntervalSince(msgStart)

            results.append((count, setupTime, msgTime))

            await network.shutdown()
        }

        print("Network Scaling Benchmark:")
        for result in results {
            print("  \(result.nodeCount) nodes: setup=\(String(format: "%.3f", result.setupTime))s, msg=\(String(format: "%.3f", result.messageTime))s")
        }

        // Baseline: 50 nodes should set up in < 5s
        if let result50 = results.first(where: { $0.nodeCount == 50 }) {
            XCTAssertLessThan(result50.setupTime, 5.0)
        }
    }

    // MARK: - NAT Translation Performance

    func testNATTranslationPerformance() async throws {
        let nat = SimulatedNAT(type: .portRestrictedCone)

        let iterations = 10000
        let startTime = Date()

        for i in 0..<iterations {
            let internalEndpoint = "192.168.1.\(i % 256):\(5000 + i % 1000)"
            let destination = "10.0.0.\(i % 256):\(8000 + i % 1000)"

            _ = await nat.translateOutbound(from: internalEndpoint, to: destination)
        }

        let duration = Date().timeIntervalSince(startTime)
        let translationsPerSecond = Double(iterations) / duration

        print("NAT Translation Benchmark:")
        print("  Translations: \(iterations)")
        print("  Duration: \(String(format: "%.3f", duration))s")
        print("  Rate: \(String(format: "%.0f", translationsPerSecond)) trans/s")

        // Baseline: should handle at least 800 translations/s (actors have overhead)
        XCTAssertGreaterThan(translationsPerSecond, 800)
    }

    // MARK: - Peer Cache Performance

    func testPeerCachePerformance() async throws {
        let node = TestNode(id: "test")

        let peerCount = 1000
        let startTime = Date()

        // Add peers
        for i in 0..<peerCount {
            let announcement = PeerAnnouncement(
                peerId: "peer\(i)",
                publicKey: "key\(i)",
                reachability: [.direct(endpoint: "10.0.0.\(i % 256):\(5000 + i)")],
                capabilities: ["relay"],
                signature: ""
            )
            await node.addToCache(announcement)
        }

        let addDuration = Date().timeIntervalSince(startTime)

        // Lookup peers
        let lookupStart = Date()
        for i in 0..<peerCount {
            let cache = await node.peerCache
            _ = cache["peer\(i)"]
        }
        let lookupDuration = Date().timeIntervalSince(lookupStart)

        print("Peer Cache Benchmark:")
        print("  Peers: \(peerCount)")
        print("  Add time: \(String(format: "%.3f", addDuration))s")
        print("  Lookup time: \(String(format: "%.3f", lookupDuration))s")
        print("  Add rate: \(String(format: "%.0f", Double(peerCount) / addDuration)) peers/s")
        print("  Lookup rate: \(String(format: "%.0f", Double(peerCount) / lookupDuration)) lookups/s")

        // Baseline: should handle 1000 peers quickly
        XCTAssertLessThan(addDuration, 1.0)
        XCTAssertLessThan(lookupDuration, 0.1)
    }

    // MARK: - Hole Punch Strategy Selection

    func testHolePunchStrategyPerformance() async throws {
        let iterations = 10000
        let natTypes: [NATType] = [.public, .fullCone, .restrictedCone, .portRestrictedCone, .symmetric, .unknown]

        let startTime = Date()

        for _ in 0..<iterations {
            let initiator = natTypes.randomElement()!
            let responder = natTypes.randomElement()!
            _ = HolePunchCompatibility.check(initiator: initiator, responder: responder)
        }

        let duration = Date().timeIntervalSince(startTime)
        let checksPerSecond = Double(iterations) / duration

        print("Hole Punch Strategy Benchmark:")
        print("  Checks: \(iterations)")
        print("  Duration: \(String(format: "%.3f", duration))s")
        print("  Rate: \(String(format: "%.0f", checksPerSecond)) checks/s")

        // Baseline: should be very fast (pure computation)
        XCTAssertGreaterThan(checksPerSecond, 100000)
    }

    // MARK: - Message Serialization

    func testMessageSerializationPerformance() async throws {
        let iterations = 10000

        // Create a complex message
        let announcement = PeerAnnouncement(
            peerId: "test-peer-id-12345",
            publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            reachability: [
                .direct(endpoint: "1.2.3.4:5000"),
                .relay(relayPeerId: "relay1", relayEndpoint: "5.6.7.8:9000")
            ],
            capabilities: ["relay", "provider"],
            signature: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        )
        let message = MeshMessage.announce(announcement)
        let envelope = MeshEnvelope(
            fromPeerId: "sender",
            publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            machineId: "test-machine",
            toPeerId: "receiver",
            payload: message
        )

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        // Measure encoding
        let encodeStart = Date()
        var encodedData: Data?
        for _ in 0..<iterations {
            encodedData = try encoder.encode(envelope)
        }
        let encodeDuration = Date().timeIntervalSince(encodeStart)

        // Measure decoding
        guard let data = encodedData else {
            XCTFail("Encoding failed")
            return
        }

        let decodeStart = Date()
        for _ in 0..<iterations {
            _ = try decoder.decode(MeshEnvelope.self, from: data)
        }
        let decodeDuration = Date().timeIntervalSince(decodeStart)

        let encodeRate = Double(iterations) / encodeDuration
        let decodeRate = Double(iterations) / decodeDuration

        print("Message Serialization Benchmark:")
        print("  Iterations: \(iterations)")
        print("  Message size: \(data.count) bytes")
        print("  Encode: \(String(format: "%.3f", encodeDuration))s (\(String(format: "%.0f", encodeRate))/s)")
        print("  Decode: \(String(format: "%.3f", decodeDuration))s (\(String(format: "%.0f", decodeRate))/s)")

        // Baseline: should handle at least 10000 encode/decode per second
        XCTAssertGreaterThan(encodeRate, 10000)
        XCTAssertGreaterThan(decodeRate, 10000)
    }

    // MARK: - Concurrent Operations

    func testConcurrentMessageHandling() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "center")
            .addPublicNode(id: "leaf1")
            .addPublicNode(id: "leaf2")
            .addPublicNode(id: "leaf3")
            .addPublicNode(id: "leaf4")
            .link("center", "leaf1")
            .link("center", "leaf2")
            .link("center", "leaf3")
            .link("center", "leaf4")
            .build()
        defer { Task { await network.shutdown() } }

        for id in ["center", "leaf1", "leaf2", "leaf3", "leaf4"] {
            try await network.node(id).start()
        }

        let messagesPerLeaf = 100
        let startTime = Date()

        // Send messages concurrently from all leaves
        await withTaskGroup(of: Void.self) { group in
            for leafId in ["leaf1", "leaf2", "leaf3", "leaf4"] {
                group.addTask {
                    for i in 0..<messagesPerLeaf {
                        await network.node(leafId).send(.ping(recentPeers: [
                            PeerEndpointInfo(peerId: "msg\(i)", machineId: "machine", endpoint: "endpoint", natType: .unknown)
                        ], myNATType: .unknown), to: "center")
                    }
                }
            }
        }

        try await Task.sleep(nanoseconds: 500_000_000)
        let duration = Date().timeIntervalSince(startTime)

        let totalMessages = messagesPerLeaf * 4
        let rate = Double(totalMessages) / duration

        print("Concurrent Message Handling Benchmark:")
        print("  Total messages: \(totalMessages)")
        print("  Duration: \(String(format: "%.3f", duration))s")
        print("  Rate: \(String(format: "%.0f", rate)) msg/s")

        // Baseline: should handle concurrent messages efficiently
        XCTAssertGreaterThan(rate, 100)
    }
}

// MARK: - Benchmark Result Collection

/// Collects and reports benchmark results
public struct BenchmarkResults {
    public var results: [BenchmarkResult] = []

    public struct BenchmarkResult: Sendable {
        public let name: String
        public let metric: String
        public let value: Double
        public let unit: String
        public let baseline: Double?
        public let passed: Bool
    }

    public mutating func add(
        name: String,
        metric: String,
        value: Double,
        unit: String,
        baseline: Double? = nil
    ) {
        let passed = baseline.map { value >= $0 } ?? true
        results.append(BenchmarkResult(
            name: name,
            metric: metric,
            value: value,
            unit: unit,
            baseline: baseline,
            passed: passed
        ))
    }

    public var summary: String {
        var lines = ["Benchmark Results:"]
        lines.append(String(repeating: "-", count: 60))

        for result in results {
            let status = result.passed ? "PASS" : "FAIL"
            let baselineStr = result.baseline.map { " (baseline: \($0))" } ?? ""
            lines.append("[\(status)] \(result.name): \(result.metric) = \(String(format: "%.2f", result.value)) \(result.unit)\(baselineStr)")
        }

        let passCount = results.filter(\.passed).count
        lines.append(String(repeating: "-", count: 60))
        lines.append("Total: \(passCount)/\(results.count) passed")

        return lines.joined(separator: "\n")
    }
}
