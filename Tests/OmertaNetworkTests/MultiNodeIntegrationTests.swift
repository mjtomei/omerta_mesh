// MultiNodeIntegrationTests.swift - Comprehensive multi-node network integration tests
//
// Tests the full stack: NetworkInterface → PacketRouter → VirtualNetwork → TunnelManager
// with multiple nodes exchanging packets through mock mesh connections.

import XCTest
@testable import OmertaNetwork
@testable import OmertaTunnel
@testable import OmertaMesh

// MARK: - Test Network Infrastructure

/// A complete test node with all components wired together
actor TestNode {
    let id: String
    let machineId: MachineId
    let ip: String

    let interface: MockNetworkInterface
    let virtualNetwork: VirtualNetwork
    let tunnelManager: TunnelManager
    let provider: TestChannelProvider
    var router: PacketRouter?

    init(id: String, machineId: MachineId, ip: String) {
        self.id = id
        self.machineId = machineId
        self.ip = ip

        self.provider = TestChannelProvider(machineId: machineId)
        self.interface = MockNetworkInterface(localIP: ip)
        self.virtualNetwork = VirtualNetwork(localMachineId: machineId)
        self.tunnelManager = TunnelManager(provider: provider)
    }

    func setup() async throws {
        await virtualNetwork.setLocalAddress(ip)
        try await tunnelManager.start()

        router = PacketRouter(
            localInterface: interface,
            virtualNetwork: virtualNetwork,
            tunnelManager: tunnelManager
        )
        try await router?.start()
    }

    func registerPeer(ip peerIP: String, machineId peerMachineId: MachineId) async {
        await virtualNetwork.registerAddress(ip: peerIP, machineId: peerMachineId)
    }

    func setGateway(ip gatewayIP: String, machineId gatewayMachineId: MachineId) async {
        await virtualNetwork.setGateway(machineId: gatewayMachineId, ip: gatewayIP)
    }

    func sendPacket(to destIP: String, payload: String = "test") async {
        let packet = PacketRouter.createIPv4Packet(
            src: ip,
            dst: destIP,
            payload: Data(payload.utf8)
        )!
        await interface.simulateAppSend(packet)
    }

    func getReceivedPackets() async -> [Data] {
        await interface.getAllAppReceived()
    }

    func getStats() async -> PacketRouter.Stats? {
        await router?.getStats()
    }

    func stop() async {
        await router?.stop()
        await tunnelManager.stop()
    }
}

/// Channel provider that can be connected to other providers for message relay
actor TestChannelProvider: ChannelProvider {
    let _machineId: MachineId
    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]
    private(set) var sentMessages: [(data: Data, target: MachineId, channel: String)] = []

    init(machineId: MachineId) {
        self._machineId = machineId
    }

    var peerId: PeerId {
        get async { "peer-\(_machineId)" }
    }

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        // Extract machineId from peerId format
        let machineId = peerId.hasPrefix("peer-") ? String(peerId.dropFirst(5)) : peerId
        sentMessages.append((data, machineId, channel))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        sentMessages.append((data, machineId, channel))
    }

    func deliverMessage(_ data: Data, from senderMachineId: MachineId, on channel: String) async {
        if let handler = handlers[channel] {
            await handler(senderMachineId, data)
        }
    }

    func clearSentMessages() {
        sentMessages.removeAll()
    }
}

/// Manages connections between test nodes and relays messages
actor TestNetworkMesh {
    private var nodes: [MachineId: TestNode] = [:]
    private var relayTask: Task<Void, Never>?

    func addNode(_ node: TestNode) async {
        let machineId = await node.machineId
        nodes[machineId] = node
    }

    func startRelay() {
        relayTask = Task {
            while !Task.isCancelled {
                await relayMessages()
                try? await Task.sleep(for: .milliseconds(5))
            }
        }
    }

    func stopRelay() {
        relayTask?.cancel()
        relayTask = nil
    }

    private func relayMessages() async {
        // Collect all pending messages from all nodes
        var pendingMessages: [(from: MachineId, to: MachineId, data: Data, channel: String)] = []

        for (machineId, node) in nodes {
            let provider = await node.provider
            let messages = await provider.sentMessages
            for msg in messages {
                pendingMessages.append((machineId, msg.target, msg.data, msg.channel))
            }
            await provider.clearSentMessages()
        }

        // Deliver messages to target nodes
        for msg in pendingMessages {
            if let targetNode = nodes[msg.to] {
                let targetProvider = await targetNode.provider
                await targetProvider.deliverMessage(msg.data, from: msg.from, on: msg.channel)
            }
        }
    }
}

// MARK: - Integration Tests

final class MultiNodeIntegrationTests: XCTestCase {

    // MARK: - Two Node Tests

    func testTwoNodesBidirectionalCommunication() async throws {
        // Create two nodes
        let node1 = TestNode(id: "node1", machineId: "m1", ip: "10.0.0.1")
        let node2 = TestNode(id: "node2", machineId: "m2", ip: "10.0.0.2")

        // Register each other as peers
        await node1.registerPeer(ip: "10.0.0.2", machineId: "m2")
        await node2.registerPeer(ip: "10.0.0.1", machineId: "m1")

        // Start nodes
        try await node1.setup()
        try await node2.setup()

        // Create mesh and start relay
        let mesh = TestNetworkMesh()
        await mesh.addNode(node1)
        await mesh.addNode(node2)
        await mesh.startRelay()

        // Node 1 sends to Node 2
        await node1.sendPacket(to: "10.0.0.2", payload: "hello from node1")

        // Wait for delivery
        try await Task.sleep(for: .milliseconds(300))

        // Check node 1 stats
        let stats1 = await node1.getStats()
        XCTAssertEqual(stats1?.packetsToPeer, 1)

        // Node 2 sends to Node 1
        await node2.sendPacket(to: "10.0.0.1", payload: "hello from node2")

        try await Task.sleep(for: .milliseconds(300))

        let stats2 = await node2.getStats()
        XCTAssertEqual(stats2?.packetsToPeer, 1)

        // Cleanup
        await mesh.stopRelay()
        await node1.stop()
        await node2.stop()
    }

    func testMultiplePacketsBetweenTwoNodes() async throws {
        let node1 = TestNode(id: "node1", machineId: "m1", ip: "10.0.0.1")
        let node2 = TestNode(id: "node2", machineId: "m2", ip: "10.0.0.2")

        await node1.registerPeer(ip: "10.0.0.2", machineId: "m2")
        await node2.registerPeer(ip: "10.0.0.1", machineId: "m1")

        try await node1.setup()
        try await node2.setup()

        let mesh = TestNetworkMesh()
        await mesh.addNode(node1)
        await mesh.addNode(node2)
        await mesh.startRelay()

        // Send 10 packets from node1 to node2
        for i in 0..<10 {
            await node1.sendPacket(to: "10.0.0.2", payload: "packet-\(i)")
        }

        try await Task.sleep(for: .milliseconds(500))

        let stats1 = await node1.getStats()
        XCTAssertEqual(stats1?.packetsToPeer, 10)

        await mesh.stopRelay()
        await node1.stop()
        await node2.stop()
    }

    // MARK: - Three Node Tests

    func testThreeNodeFullMesh() async throws {
        // Create three nodes
        let node1 = TestNode(id: "node1", machineId: "m1", ip: "10.0.0.1")
        let node2 = TestNode(id: "node2", machineId: "m2", ip: "10.0.0.2")
        let node3 = TestNode(id: "node3", machineId: "m3", ip: "10.0.0.3")

        // Full mesh: each node knows about all others
        await node1.registerPeer(ip: "10.0.0.2", machineId: "m2")
        await node1.registerPeer(ip: "10.0.0.3", machineId: "m3")

        await node2.registerPeer(ip: "10.0.0.1", machineId: "m1")
        await node2.registerPeer(ip: "10.0.0.3", machineId: "m3")

        await node3.registerPeer(ip: "10.0.0.1", machineId: "m1")
        await node3.registerPeer(ip: "10.0.0.2", machineId: "m2")

        try await node1.setup()
        try await node2.setup()
        try await node3.setup()

        let mesh = TestNetworkMesh()
        await mesh.addNode(node1)
        await mesh.addNode(node2)
        await mesh.addNode(node3)
        await mesh.startRelay()

        // Node 1 sends to Node 2
        await node1.sendPacket(to: "10.0.0.2", payload: "1->2")

        // Node 1 sends to Node 3
        await node1.sendPacket(to: "10.0.0.3", payload: "1->3")

        // Node 2 sends to Node 3
        await node2.sendPacket(to: "10.0.0.3", payload: "2->3")

        try await Task.sleep(for: .milliseconds(500))

        let stats1 = await node1.getStats()
        let stats2 = await node2.getStats()

        XCTAssertEqual(stats1?.packetsToPeer, 2) // Sent to node2 and node3
        XCTAssertEqual(stats2?.packetsToPeer, 1) // Sent to node3

        await mesh.stopRelay()
        await node1.stop()
        await node2.stop()
        await node3.stop()
    }

    // MARK: - Gateway Tests

    func testGatewayRouting() async throws {
        // Create gateway and peer
        let gateway = TestNode(id: "gateway", machineId: "gw", ip: "10.0.0.1")
        let peer = TestNode(id: "peer", machineId: "p1", ip: "10.0.0.100")

        // Peer knows about gateway
        await peer.registerPeer(ip: "10.0.0.1", machineId: "gw")
        await peer.setGateway(ip: "10.0.0.1", machineId: "gw")

        // Gateway knows about peer
        await gateway.registerPeer(ip: "10.0.0.100", machineId: "p1")

        try await gateway.setup()
        try await peer.setup()

        let mesh = TestNetworkMesh()
        await mesh.addNode(gateway)
        await mesh.addNode(peer)
        await mesh.startRelay()

        // Peer sends to external IP (should go to gateway)
        await peer.sendPacket(to: "8.8.8.8", payload: "internet-bound")

        try await Task.sleep(for: .milliseconds(300))

        let peerStats = await peer.getStats()
        XCTAssertEqual(peerStats?.packetsToGateway, 1)

        // Peer sends to gateway's IP directly
        await peer.sendPacket(to: "10.0.0.1", payload: "to-gateway")

        try await Task.sleep(for: .milliseconds(300))

        let peerStats2 = await peer.getStats()
        XCTAssertEqual(peerStats2?.packetsToPeer, 1) // Gateway is also a peer

        await mesh.stopRelay()
        await gateway.stop()
        await peer.stop()
    }

    func testNoGatewayDropsExternalPackets() async throws {
        let node = TestNode(id: "node1", machineId: "m1", ip: "10.0.0.1")
        // No gateway configured

        try await node.setup()

        // Send to external IP with no gateway
        await node.sendPacket(to: "8.8.8.8", payload: "nowhere")

        try await Task.sleep(for: .milliseconds(100))

        let stats = await node.getStats()
        XCTAssertEqual(stats?.packetsDropped, 1)

        await node.stop()
    }

    // MARK: - Local Routing Tests

    func testLocalLoopback() async throws {
        let node = TestNode(id: "node1", machineId: "m1", ip: "10.0.0.1")

        try await node.setup()

        // Send packet to self
        await node.sendPacket(to: "10.0.0.1", payload: "loopback")

        try await Task.sleep(for: .milliseconds(100))

        let stats = await node.getStats()
        XCTAssertEqual(stats?.packetsToLocal, 1)

        // Packet should be delivered back to interface
        let received = await node.getReceivedPackets()
        XCTAssertEqual(received.count, 1)

        await node.stop()
    }

    // MARK: - Unknown Address Tests

    func testUnknownAddressInSubnetDropped() async throws {
        let node = TestNode(id: "node1", machineId: "m1", ip: "10.0.0.1")

        try await node.setup()

        // Send to unknown address in same subnet
        await node.sendPacket(to: "10.0.0.99", payload: "unknown")

        try await Task.sleep(for: .milliseconds(100))

        let stats = await node.getStats()
        XCTAssertEqual(stats?.packetsDropped, 1)

        await node.stop()
    }

    // MARK: - Five Node Network Test

    func testFiveNodeNetwork() async throws {
        // Create 5 nodes simulating a small mesh network
        let nodes = (1...5).map { i in
            TestNode(id: "node\(i)", machineId: "m\(i)", ip: "10.0.0.\(i)")
        }

        // Full mesh: every node knows about every other node
        for node in nodes {
            let nodeIP = await node.ip
            let nodeMachineId = await node.machineId

            for peer in nodes {
                let peerIP = await peer.ip
                let peerMachineId = await peer.machineId

                if nodeIP != peerIP {
                    await node.registerPeer(ip: peerIP, machineId: peerMachineId)
                }
            }
        }

        // Start all nodes
        for node in nodes {
            try await node.setup()
        }

        // Create mesh
        let mesh = TestNetworkMesh()
        for node in nodes {
            await mesh.addNode(node)
        }
        await mesh.startRelay()

        // Each node sends one packet to every other node
        for (i, sender) in nodes.enumerated() {
            for (j, receiver) in nodes.enumerated() {
                if i != j {
                    let receiverIP = await receiver.ip
                    await sender.sendPacket(to: receiverIP, payload: "from\(i+1)-to\(j+1)")
                }
            }
        }

        // Wait for all packets to be delivered
        try await Task.sleep(for: .milliseconds(1000))

        // Each node should have sent 4 packets (to 4 other nodes)
        for (i, node) in nodes.enumerated() {
            let stats = await node.getStats()
            XCTAssertEqual(stats?.packetsToPeer, 4, "Node \(i+1) should have sent 4 packets")
        }

        // Cleanup
        await mesh.stopRelay()
        for node in nodes {
            await node.stop()
        }
    }

    // MARK: - Concurrent Packet Test

    func testConcurrentPacketSending() async throws {
        let node1 = TestNode(id: "node1", machineId: "m1", ip: "10.0.0.1")
        let node2 = TestNode(id: "node2", machineId: "m2", ip: "10.0.0.2")

        await node1.registerPeer(ip: "10.0.0.2", machineId: "m2")
        await node2.registerPeer(ip: "10.0.0.1", machineId: "m1")

        try await node1.setup()
        try await node2.setup()

        let mesh = TestNetworkMesh()
        await mesh.addNode(node1)
        await mesh.addNode(node2)
        await mesh.startRelay()

        // Send packets concurrently from both nodes
        await withTaskGroup(of: Void.self) { group in
            // Node 1 sends 20 packets
            group.addTask {
                for i in 0..<20 {
                    await node1.sendPacket(to: "10.0.0.2", payload: "n1-\(i)")
                }
            }

            // Node 2 sends 20 packets
            group.addTask {
                for i in 0..<20 {
                    await node2.sendPacket(to: "10.0.0.1", payload: "n2-\(i)")
                }
            }
        }

        try await Task.sleep(for: .milliseconds(1000))

        let stats1 = await node1.getStats()
        let stats2 = await node2.getStats()

        XCTAssertEqual(stats1?.packetsToPeer, 20)
        XCTAssertEqual(stats2?.packetsToPeer, 20)

        await mesh.stopRelay()
        await node1.stop()
        await node2.stop()
    }
}
