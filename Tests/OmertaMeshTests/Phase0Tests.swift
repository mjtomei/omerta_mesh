// Phase0Tests.swift - Tests for test infrastructure (Phase 0)

import XCTest
@testable import OmertaMesh

final class Phase0Tests: XCTestCase {

    // MARK: - Virtual Network Tests

    /// Test that packets route between two connected nodes
    func testTwoNodeRouting() async throws {
        let network = try await TestNetworkBuilder()
            .addNode(id: "A")
            .addNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let nodeA = network.node("A")
        let nodeB = network.node("B")

        // Set up receiver
        var receivedMessage: MeshMessage? = nil
        await nodeB.onMessage { message, from in
            receivedMessage = message
            return .pong(recentPeers: [], yourEndpoint: "test-endpoint", myNATType: .unknown)
        }

        // Send from A to B
        let response = try await nodeA.sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "B",
            timeout: 5.0
        )

        // Verify
        XCTAssertNotNil(receivedMessage)
        if case .ping = receivedMessage! {
            // Good
        } else {
            XCTFail("Expected ping message")
        }

        if case .pong = response {
            // Good
        } else {
            XCTFail("Expected pong response")
        }
    }

    /// Test that packets don't route without a link
    func testNoLinkNoRouting() async throws {
        let network = try await TestNetworkBuilder()
            .addNode(id: "A")
            .addNode(id: "B")
            // No link!
            .build()
        defer { Task { await network.shutdown() } }

        let nodeA = network.node("A")

        // Try to send - should timeout
        do {
            _ = try await nodeA.sendAndReceive(
                .ping(recentPeers: [], myNATType: .unknown),
                to: "B",
                timeout: 0.5
            )
            XCTFail("Should have timed out")
        } catch TestNodeError.timeout {
            // Expected
        }
    }

    /// Test three-node routing (A-B-C where A can reach B, B can reach C)
    func testThreeNodeTopology() async throws {
        let network = try await TestNetworkBuilder()
            .addNode(id: "A")
            .addNode(id: "B")
            .addNode(id: "C")
            .link("A", "B")
            .link("B", "C")
            .build()
        defer { Task { await network.shutdown() } }

        // A can reach B
        let responseAB = try await network.node("A").sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "B",
            timeout: 1.0
        )
        if case .pong = responseAB {
            // Good - got a pong response
        } else {
            XCTFail("Expected pong response, got \(responseAB)")
        }

        // B can reach C
        let responseBC = try await network.node("B").sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "C",
            timeout: 1.0
        )
        if case .pong = responseBC {
            // Good - got a pong response
        } else {
            XCTFail("Expected pong response, got \(responseBC)")
        }

        // A cannot directly reach C (no link)
        do {
            _ = try await network.node("A").sendAndReceive(
                .ping(recentPeers: [], myNATType: .unknown),
                to: "C",
                timeout: 0.5
            )
            XCTFail("Should have timed out - no direct link")
        } catch TestNodeError.timeout {
            // Expected
        }
    }

    // MARK: - Network Partition Tests

    /// Test that partitions block communication
    func testNetworkPartition() async throws {
        let network = try await TestNetworkBuilder()
            .addNode(id: "A")
            .addNode(id: "B")
            .addNode(id: "C")
            .link("A", "B")
            .link("B", "C")
            .link("A", "C")
            .build()
        defer { Task { await network.shutdown() } }

        // Initially A can reach C
        let response1 = try await network.node("A").sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "C",
            timeout: 1.0
        )
        if case .pong = response1 {
            // Good - got a pong response
        } else {
            XCTFail("Expected pong response, got \(response1)")
        }

        // Partition: A alone, B and C together
        await network.partition(group1: ["A"], group2: ["B", "C"])

        // Now A cannot reach C
        do {
            _ = try await network.node("A").sendAndReceive(
                .ping(recentPeers: [], myNATType: .unknown),
                to: "C",
                timeout: 0.5
            )
            XCTFail("Should have timed out during partition")
        } catch TestNodeError.timeout {
            // Expected
        }

        // B can still reach C (same partition)
        let response2 = try await network.node("B").sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "C",
            timeout: 1.0
        )
        if case .pong = response2 {
            // Good - got a pong response
        } else {
            XCTFail("Expected pong response, got \(response2)")
        }

        // Heal partition
        await network.healPartition()

        // A can reach C again
        let response3 = try await network.node("A").sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "C",
            timeout: 1.0
        )
        if case .pong = response3 {
            // Good - got a pong response
        } else {
            XCTFail("Expected pong response, got \(response3)")
        }
    }

    // MARK: - Simulated NAT Tests

    /// Test public NAT allows all traffic
    func testPublicNATAllowsAll() async throws {
        let nat = SimulatedNAT(type: .public, publicIP: "1.2.3.4")

        // Outbound translation is pass-through
        let external = await nat.translateOutbound(
            from: "192.168.1.1:5000",
            to: "8.8.8.8:53"
        )
        XCTAssertEqual(external, "192.168.1.1:5000")

        // Inbound is pass-through
        let internal1 = await nat.filterInbound(
            from: "8.8.8.8:53",
            to: "192.168.1.1:5000"
        )
        XCTAssertEqual(internal1, "192.168.1.1:5000")
    }

    /// Test full cone NAT behavior
    func testFullConeNAT() async throws {
        let nat = SimulatedNAT(type: .fullCone, publicIP: "10.0.0.1")

        // First outbound creates mapping
        let external = await nat.translateOutbound(
            from: "192.168.1.1:5000",
            to: "8.8.8.8:53"
        )
        XCTAssertTrue(external!.starts(with: "10.0.0.1:"))

        // Any external host can send to mapped port
        let internal1 = await nat.filterInbound(
            from: "1.1.1.1:80",  // Different host
            to: external!
        )
        XCTAssertEqual(internal1, "192.168.1.1:5000")
    }

    /// Test restricted cone NAT behavior
    func testRestrictedConeNAT() async throws {
        let nat = SimulatedNAT(type: .restrictedCone, publicIP: "10.0.0.1")

        // Outbound to 8.8.8.8
        let external = await nat.translateOutbound(
            from: "192.168.1.1:5000",
            to: "8.8.8.8:53"
        )!

        // 8.8.8.8 can reply (any port)
        let internal1 = await nat.filterInbound(
            from: "8.8.8.8:1234",  // Different port OK
            to: external
        )
        XCTAssertEqual(internal1, "192.168.1.1:5000")

        // Different IP cannot send
        let internal2 = await nat.filterInbound(
            from: "1.1.1.1:53",
            to: external
        )
        XCTAssertNil(internal2)
    }

    /// Test port-restricted cone NAT behavior
    func testPortRestrictedConeNAT() async throws {
        let nat = SimulatedNAT(type: .portRestrictedCone, publicIP: "10.0.0.1")

        // Outbound to 8.8.8.8:53
        let external = await nat.translateOutbound(
            from: "192.168.1.1:5000",
            to: "8.8.8.8:53"
        )!

        // 8.8.8.8:53 can reply (exact match)
        let internal1 = await nat.filterInbound(
            from: "8.8.8.8:53",
            to: external
        )
        XCTAssertEqual(internal1, "192.168.1.1:5000")

        // 8.8.8.8:54 cannot (different port)
        let internal2 = await nat.filterInbound(
            from: "8.8.8.8:54",
            to: external
        )
        XCTAssertNil(internal2)
    }

    /// Test symmetric NAT behavior
    func testSymmetricNAT() async throws {
        let nat = SimulatedNAT(type: .symmetric, publicIP: "10.0.0.1")

        // Outbound to 8.8.8.8:53
        let external1 = await nat.translateOutbound(
            from: "192.168.1.1:5000",
            to: "8.8.8.8:53"
        )!

        // Outbound to 1.1.1.1:53 gets DIFFERENT external port
        let external2 = await nat.translateOutbound(
            from: "192.168.1.1:5000",
            to: "1.1.1.1:53"
        )!

        XCTAssertNotEqual(external1, external2)

        // 8.8.8.8:53 can reply to first mapping
        let internal1 = await nat.filterInbound(
            from: "8.8.8.8:53",
            to: external1
        )
        XCTAssertEqual(internal1, "192.168.1.1:5000")

        // 1.1.1.1:53 can reply to second mapping
        let internal2 = await nat.filterInbound(
            from: "1.1.1.1:53",
            to: external2
        )
        XCTAssertEqual(internal2, "192.168.1.1:5000")

        // But cross-replies don't work
        let internal3 = await nat.filterInbound(
            from: "1.1.1.1:53",
            to: external1  // Wrong mapping
        )
        XCTAssertNil(internal3)
    }

    // MARK: - TestNetworkBuilder Tests

    /// Test linear topology
    func testLinearTopology() async throws {
        let network = try await TestNetworkBuilder()
            .addLinearTopology(count: 5)
            .build()
        defer { Task { await network.shutdown() } }

        // Should have 5 nodes: node0, node1, node2, node3, node4
        XCTAssertEqual(network.nodeIds.count, 5)
        XCTAssertTrue(network.nodeIds.contains("node0"))
        XCTAssertTrue(network.nodeIds.contains("node4"))

        // node0 can reach node1
        let response = try await network.node("node0").sendAndReceive(
            .ping(recentPeers: [], myNATType: .unknown),
            to: "node1",
            timeout: 1.0
        )
        if case .pong = response {
            // Good - got a pong response
        } else {
            XCTFail("Expected pong response, got \(response)")
        }
    }

    /// Test star topology
    func testStarTopology() async throws {
        let network = try await TestNetworkBuilder()
            .addStarTopology(centerID: "hub", leafCount: 3)
            .build()
        defer { Task { await network.shutdown() } }

        // Should have 4 nodes: hub, leaf0, leaf1, leaf2
        XCTAssertEqual(network.nodeIds.count, 4)

        // All leaves can reach hub
        for i in 0..<3 {
            let response = try await network.node("leaf\(i)").sendAndReceive(
                .ping(recentPeers: [], myNATType: .unknown),
                to: "hub",
                timeout: 1.0
            )
            if case .pong = response {
                // Good - got a pong response
            } else {
                XCTFail("Expected pong response from hub for leaf\(i), got \(response)")
            }
        }
    }

    /// Test building network with NAT nodes
    func testBuildingWithNATNodes() async throws {
        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "relay")
            .addNATNode(id: "symmetric", natType: .symmetric)
            .addNATNode(id: "restricted", natType: .restrictedCone)
            .link("symmetric", "relay")
            .link("restricted", "relay")
            .build()
        defer { Task { await network.shutdown() } }

        // Check NAT types
        let symmetricNode = network.node("symmetric")
        let restrictedNode = network.node("restricted")
        let relayNode = network.node("relay")

        XCTAssertEqual(symmetricNode.natType, .symmetric)
        XCTAssertEqual(restrictedNode.natType, .restrictedCone)
        XCTAssertEqual(relayNode.natType, .public)

        // Check NAT instances exist
        XCTAssertNotNil(network.nat(for: "symmetric"))
        XCTAssertNotNil(network.nat(for: "restricted"))
        XCTAssertNil(network.nat(for: "relay"))
    }

    // MARK: - Message Handling Tests

    /// Test default ping/pong handling
    func testDefaultPingPong() async throws {
        let network = try await TestNetworkBuilder()
            .addNode(id: "A")
            .addNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        // No custom handler set - should use default
        let response = try await network.node("A").sendAndReceive(
            .ping(recentPeers: [
                PeerEndpointInfo(peerId: "X", machineId: "machine-X", endpoint: "endpoint1", natType: .unknown),
                PeerEndpointInfo(peerId: "Y", machineId: "machine-Y", endpoint: "endpoint2", natType: .unknown)
            ], myNATType: .unknown),
            to: "B",
            timeout: 1.0
        )

        if case .pong(let recentPeers, _, _) = response {
            // B should respond with its recent peers (empty initially)
            XCTAssertTrue(recentPeers.isEmpty || recentPeers.contains { $0.peerId == "A" })
        } else {
            XCTFail("Expected pong response")
        }
    }

    /// Test peer cache operations
    func testPeerCache() async throws {
        let network = try await TestNetworkBuilder()
            .addNode(id: "A")
            .addNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let nodeA = network.node("A")

        // Add to cache
        let announcement = PeerAnnouncement(
            peerId: "testPeer",
            publicKey: "testKey",
            reachability: [.direct(endpoint: "1.2.3.4:5000")],
            capabilities: ["relay"]
        )
        await nodeA.addToCache(announcement)

        // Retrieve from cache
        let cached = await nodeA.peerCache["testPeer"]
        XCTAssertNotNil(cached)
        XCTAssertEqual(cached?.peerId, "testPeer")
    }

    /// Test announcement gossip
    func testAnnouncementGossip() async throws {
        let network = try await TestNetworkBuilder()
            .addNode(id: "A")
            .addNode(id: "B")
            .link("A", "B")
            .build()
        defer { Task { await network.shutdown() } }

        let nodeB = network.node("B")

        // A sends announcement to B
        let announcement = PeerAnnouncement(
            peerId: "A",
            publicKey: "keyA",
            reachability: [.direct(endpoint: "1.2.3.4:5000")],
            capabilities: []
        )

        await network.node("A").send(.announce(announcement), to: "B")

        // Wait for delivery
        try await Task.sleep(nanoseconds: 100_000_000)

        // B should have cached the announcement
        let cached = await nodeB.peerCache["A"]
        XCTAssertNotNil(cached)
        XCTAssertEqual(cached?.publicKey, "keyA")
    }
}
