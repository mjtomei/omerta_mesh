// MultiEndpointTests.swift - Tests for multi-endpoint peer management

import XCTest
import NIOCore
import NIOPosix
@testable import OmertaMesh

final class MultiEndpointTests: XCTestCase {

    // MARK: - PeerEndpointManager Unit Tests

    func testEndpointPriorityPromotion() async throws {
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .strict)
        let peerId = "test-peer-123"
        let machineId = "test-machine-456"

        // Record three endpoints in order (using public IPs)
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "1.1.1.1:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "2.2.2.2:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "3.3.3.3:5000")

        // Most recent should be first
        let endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints, ["3.3.3.3:5000", "2.2.2.2:5000", "1.1.1.1:5000"])

        // Promote the oldest endpoint
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "1.1.1.1:5000")

        // Now it should be first
        let reordered = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(reordered, ["1.1.1.1:5000", "3.3.3.3:5000", "2.2.2.2:5000"])
    }

    func testMultipleMachinesSamePeerId() async throws {
        // Use permissive mode to allow private IPs for LAN testing
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .permissive)
        let peerId = "shared-peer-id"
        let machineA = "machine-A"
        let machineB = "machine-B"

        // Two machines share same peerId but different machineIds
        await manager.recordMessageReceived(from: peerId, machineId: machineA, endpoint: "10.0.0.1:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineB, endpoint: "10.0.0.2:5000")

        // Each machine has its own endpoint list
        let endpointsA = await manager.getEndpoints(peerId: peerId, machineId: machineA)
        let endpointsB = await manager.getEndpoints(peerId: peerId, machineId: machineB)

        XCTAssertEqual(endpointsA, ["10.0.0.1:5000"])
        XCTAssertEqual(endpointsB, ["10.0.0.2:5000"])

        // getAllEndpoints returns all endpoints for all machines with this peerId
        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)
        XCTAssertTrue(allEndpoints.contains("10.0.0.1:5000"))
        XCTAssertTrue(allEndpoints.contains("10.0.0.2:5000"))
    }

    func testBestEndpointReturnsFirst() async throws {
        // Use allowAll to test with hostname-like endpoints
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "old.endpoint:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "new.endpoint:5000")

        let best = await manager.getBestEndpoint(peerId: peerId, machineId: machineId)
        XCTAssertEqual(best, "new.endpoint:5000")
    }

    func testSendSuccessPromotesEndpoint() async throws {
        // Use allowAll to test with hostname-like endpoints
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .allowAll)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Set up initial order
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "A:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "B:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "C:5000")

        // C is now first
        let bestBefore = await manager.getBestEndpoint(peerId: peerId, machineId: machineId)
        XCTAssertEqual(bestBefore, "C:5000")

        // Successful send to A promotes it
        await manager.recordSendSuccess(to: peerId, machineId: machineId, endpoint: "A:5000")

        // A is now first
        let bestAfter = await manager.getBestEndpoint(peerId: peerId, machineId: machineId)
        XCTAssertEqual(bestAfter, "A:5000")
    }

    func testMaxEndpointsPerMachine() async throws {
        // Use permissive mode to allow private IPs
        let manager = PeerEndpointManager(networkId: "test-network", validationMode: .permissive)
        let peerId = "test-peer"
        let machineId = "test-machine"

        // Add 1005 endpoints (max is 1000)
        for i in 1...1005 {
            // Use format that creates valid IPs across multiple octets
            let octet3 = i / 256
            let octet4 = i % 256
            await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "10.0.\(octet3).\(octet4):5000")
        }

        let endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints.count, 1000)

        // Most recent should be first (1005 = 3.237)
        XCTAssertEqual(endpoints.first, "10.0.3.237:5000")

        // Oldest should have been dropped (1 = 0.1, 5 = 0.5)
        XCTAssertFalse(endpoints.contains("10.0.0.1:5000"))
        XCTAssertFalse(endpoints.contains("10.0.0.5:5000"))
    }

    // MARK: - MeshNode Integration Tests

    func testMeshNodeRecordsEndpointOnReceive() async throws {
        // Create two nodes
        let nodeA = try await makeTestNode()
        let nodeB = try await makeTestNode()

        try await nodeA.start()
        try await nodeB.start()

        defer {
            Task {
                await nodeA.stop()
                await nodeB.stop()
            }
        }

        let portB = await nodeB.port!
        let peerIdA = await nodeA.peerId
        let machineIdA = await nodeA.machineId

        // A sends ping to B - B should record A's endpoint
        _ = try await nodeA.sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "127.0.0.1:\(portB)",
            timeout: 5.0
        )

        // B should have recorded A's endpoint in its endpoint manager
        let endpointsOnB = await nodeB.endpointManager.getEndpoints(peerId: peerIdA, machineId: machineIdA)
        XCTAssertFalse(endpointsOnB.isEmpty, "B should have recorded A's endpoint")
    }

    func testMeshNodeSendToPeerWithFallback() async throws {
        let nodeA = try await makeTestNode()
        let nodeB = try await makeTestNode()

        try await nodeA.start()
        try await nodeB.start()

        let portB = await nodeB.port!
        let peerIdB = await nodeB.peerId
        let machineIdB = await nodeB.machineId

        // Add a bad endpoint first (highest priority after this)
        await nodeA.endpointManager.recordMessageReceived(
            from: peerIdB,
            machineId: machineIdB,
            endpoint: "127.0.0.1:\(portB)"  // Good endpoint first
        )
        await nodeA.endpointManager.recordMessageReceived(
            from: peerIdB,
            machineId: machineIdB,
            endpoint: "192.0.2.1:9999"  // Bad endpoint - TEST-NET, non-routable
        )

        // Bad endpoint is now first (most recent)
        let endpointsBefore = await nodeA.endpointManager.getEndpoints(peerId: peerIdB, machineId: machineIdB)
        XCTAssertEqual(endpointsBefore.first, "192.0.2.1:9999")

        // Send with fallback - should try bad endpoint first, fail, then succeed with good endpoint
        let response = try await nodeA.sendToPeerWithFallback(
            .ping(recentPeers: [], myNATType: .unknown),
            peerId: peerIdB,
            machineId: machineIdB,
            timeout: 1.0
        )

        if case .pong = response {
            // Success - fallback worked
        } else {
            XCTFail("Expected pong response")
        }

        // Good endpoint should now be promoted to first (due to success)
        let endpointsAfter = await nodeA.endpointManager.getEndpoints(peerId: peerIdB, machineId: machineIdB)
        XCTAssertEqual(endpointsAfter.first, "127.0.0.1:\(portB)")

        await nodeA.stop()
        await nodeB.stop()
    }

    func testSendToPeerWithFallbackAllEndpointsFail() async throws {
        let nodeA = try await makeTestNode()

        try await nodeA.start()

        defer {
            Task {
                await nodeA.stop()
            }
        }

        let peerId = "nonexistent-peer"
        let machineId = "nonexistent-machine"

        // Add only bad endpoints
        await nodeA.endpointManager.recordMessageReceived(
            from: peerId,
            machineId: machineId,
            endpoint: "192.0.2.1:9999"  // TEST-NET, non-routable
        )
        await nodeA.endpointManager.recordMessageReceived(
            from: peerId,
            machineId: machineId,
            endpoint: "192.0.2.2:9999"  // TEST-NET, non-routable
        )

        // Send should fail after trying all endpoints
        do {
            _ = try await nodeA.sendToPeerWithFallback(
                .ping(recentPeers: [], myNATType: .unknown),
                peerId: peerId,
                machineId: machineId,
                timeout: 0.5
            )
            XCTFail("Should have thrown when all endpoints fail")
        } catch {
            // Expected - all endpoints failed
        }
    }

    func testSendToPeerWithFallbackNoEndpoints() async throws {
        let nodeA = try await makeTestNode()

        try await nodeA.start()

        defer {
            Task {
                await nodeA.stop()
            }
        }

        // No endpoints registered for this peer
        do {
            _ = try await nodeA.sendToPeerWithFallback(
                .ping(recentPeers: [], myNATType: .unknown),
                peerId: "unknown-peer",
                machineId: "unknown-machine",
                timeout: 1.0
            )
            XCTFail("Should have thrown peerNotFound")
        } catch MeshNodeError.peerNotFound {
            // Expected
        } catch {
            XCTFail("Expected peerNotFound, got \(error)")
        }
    }

    // MARK: - Sliding Window Algorithm Tests

    func testSlidingWindowExpands() async throws {
        // Test that window expands from 1 to fullWidth
        let endpoints = ["A", "B", "C", "D", "E"]
        let maxRetries = 3
        let fullWidth = min(maxRetries, endpoints.count)  // 3

        var rounds: [[String]] = []
        var windowStart = 0
        var windowEnd = 1

        while windowStart < endpoints.count && rounds.count < 10 {
            let window = Array(endpoints[windowStart..<windowEnd])
            rounds.append(window)

            // Simulate all failures
            if windowEnd - windowStart < fullWidth && windowEnd < endpoints.count {
                windowEnd += 1  // Expand
            } else if windowEnd < endpoints.count {
                windowStart += 1  // Slide
                windowEnd += 1
            } else {
                windowStart += 1  // Contract
            }
        }

        // Verify expansion phase
        XCTAssertEqual(rounds[0], ["A"])           // Round 1: expanding
        XCTAssertEqual(rounds[1], ["A", "B"])      // Round 2: expanding
        XCTAssertEqual(rounds[2], ["A", "B", "C"]) // Round 3: full width

        // Verify sliding phase
        XCTAssertEqual(rounds[3], ["B", "C", "D"]) // Round 4: sliding
        XCTAssertEqual(rounds[4], ["C", "D", "E"]) // Round 5: sliding

        // Verify contraction phase
        XCTAssertEqual(rounds[5], ["D", "E"])      // Round 6: contracting
        XCTAssertEqual(rounds[6], ["E"])           // Round 7: contracting
    }

    func testEachEndpointTriedMaxRetryTimes() async throws {
        // Verify each endpoint gets exactly maxRetries attempts
        let endpoints = ["A", "B", "C", "D", "E"]
        let maxRetries = 3

        var attemptCounts: [String: Int] = [:]
        for ep in endpoints { attemptCounts[ep] = 0 }

        var windowStart = 0
        var windowEnd = 1
        let fullWidth = min(maxRetries, endpoints.count)

        while windowStart < endpoints.count {
            let window = Array(endpoints[windowStart..<windowEnd])
            for ep in window {
                attemptCounts[ep]! += 1
            }

            if windowEnd - windowStart < fullWidth && windowEnd < endpoints.count {
                windowEnd += 1
            } else if windowEnd < endpoints.count {
                windowStart += 1
                windowEnd += 1
            } else {
                windowStart += 1
            }
        }

        // Each endpoint should be tried exactly maxRetries times
        for ep in endpoints {
            XCTAssertEqual(attemptCounts[ep], maxRetries,
                          "Endpoint \(ep) should be tried \(maxRetries) times, was tried \(attemptCounts[ep]!) times")
        }
    }

    func testSlidingWindowFewerEndpointsThanRetries() async throws {
        // When endpoints < maxRetries, each endpoint tried endpoints times
        let endpoints = ["A", "B"]
        let maxRetries = 5

        var attemptCounts: [String: Int] = [:]
        for ep in endpoints { attemptCounts[ep] = 0 }

        var windowStart = 0
        var windowEnd = 1
        let fullWidth = min(maxRetries, endpoints.count)  // 2

        while windowStart < endpoints.count {
            let window = Array(endpoints[windowStart..<windowEnd])
            for ep in window {
                attemptCounts[ep]! += 1
            }

            if windowEnd - windowStart < fullWidth && windowEnd < endpoints.count {
                windowEnd += 1
            } else if windowEnd < endpoints.count {
                windowStart += 1
                windowEnd += 1
            } else {
                windowStart += 1
            }
        }

        // Each endpoint should be tried fullWidth times (2, not 5)
        for ep in endpoints {
            XCTAssertEqual(attemptCounts[ep], fullWidth,
                          "Endpoint \(ep) should be tried \(fullWidth) times, was tried \(attemptCounts[ep]!) times")
        }
    }

    // MARK: - Persistence Tests

    func testEndpointManagerPersistence() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let storagePath = tempDir.appendingPathComponent("peer_endpoints.json")
        let networkId = "test-persistence-network"

        // Create manager and add endpoints (using consistent networkId)
        let manager1 = PeerEndpointManager(networkId: networkId, validationMode: .strict, storagePath: storagePath)
        await manager1.recordMessageReceived(from: "peer1", machineId: "machine1", endpoint: "1.1.1.1:5000")
        await manager1.recordMessageReceived(from: "peer1", machineId: "machine1", endpoint: "2.2.2.2:5000")
        try await manager1.save()

        // Create new manager with same networkId and load
        let manager2 = PeerEndpointManager(networkId: networkId, validationMode: .strict, storagePath: storagePath)
        try await manager2.load()

        // Should have same endpoints in same order
        let endpoints = await manager2.getEndpoints(peerId: "peer1", machineId: "machine1")
        XCTAssertEqual(endpoints, ["2.2.2.2:5000", "1.1.1.1:5000"])
    }

    func testEndpointManagerPersistenceMultipleMachines() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let storagePath = tempDir.appendingPathComponent("peer_endpoints.json")
        let networkId = "test-persistence-network"

        // Create manager and add endpoints for multiple machines (using consistent networkId)
        let manager1 = PeerEndpointManager(networkId: networkId, validationMode: .strict, storagePath: storagePath)
        await manager1.recordMessageReceived(from: "peer1", machineId: "machineA", endpoint: "1.1.1.1:5000")
        await manager1.recordMessageReceived(from: "peer1", machineId: "machineB", endpoint: "2.2.2.2:5000")
        await manager1.recordMessageReceived(from: "peer2", machineId: "machineC", endpoint: "3.3.3.3:5000")
        try await manager1.save()

        // Create new manager with same networkId and load
        let manager2 = PeerEndpointManager(networkId: networkId, validationMode: .strict, storagePath: storagePath)
        try await manager2.load()

        // All machines should be restored
        let endpointsA = await manager2.getEndpoints(peerId: "peer1", machineId: "machineA")
        let endpointsB = await manager2.getEndpoints(peerId: "peer1", machineId: "machineB")
        let endpointsC = await manager2.getEndpoints(peerId: "peer2", machineId: "machineC")

        XCTAssertEqual(endpointsA, ["1.1.1.1:5000"])
        XCTAssertEqual(endpointsB, ["2.2.2.2:5000"])
        XCTAssertEqual(endpointsC, ["3.3.3.3:5000"])
    }

    // MARK: - Helper Methods

    private func makeTestNode(port: UInt16 = 0) async throws -> MeshNode {
        let identity = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        // Use allowAll validation mode for localhost testing
        let config = MeshNode.Config(encryptionKey: testKey, port: port, endpointValidationMode: .allowAll)
        return try MeshNode(identity: identity, config: config)
    }
}
