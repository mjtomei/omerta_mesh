// DHCPIntegrationTests.swift - Integration tests for DHCP + VirtualNetwork
//
// Tests the full flow: peers join the mesh, obtain IPs via native DHCP,
// register addresses in VirtualNetwork, and verify routing decisions.

import XCTest
@testable import OmertaNetwork
@testable import OmertaMesh

// MARK: - Test Infrastructure

/// A simulated mesh node with DHCP and VirtualNetwork wired together
actor TestMeshNode {
    nonisolated let machineId: MachineId
    nonisolated let provider: TestMeshProvider
    nonisolated let virtualNetwork: VirtualNetwork

    // Only gateway has a DHCP service
    var dhcpService: DHCPService?
    var dhcpClient: DHCPClient?

    var assignedIP: String?

    init(machineId: MachineId, isGateway: Bool, networkConfig: VirtualNetworkConfig) {
        self.machineId = machineId
        self.provider = TestMeshProvider(machineId: machineId)
        self.virtualNetwork = VirtualNetwork(localMachineId: machineId, config: networkConfig)

        if isGateway {
            let serviceConfig = DHCPServiceConfig(from: networkConfig)
            dhcpService = DHCPService(config: serviceConfig, provider: provider)
        }
    }

    func startGateway() async throws {
        guard let service = dhcpService else { return }
        try await service.start()

        // Gateway assigns itself the gateway IP
        let config = await virtualNetwork.getConfig()
        assignedIP = config.gatewayIP
        await virtualNetwork.setLocalAddress(config.gatewayIP)
    }

    func startClient(gatewayMachineId: MachineId, hostname: String? = nil) async throws {
        let clientConfig = NativeDHCPClientConfig(
            gatewayMachineId: gatewayMachineId,
            timeout: 5,
            retries: 2,
            autoRenew: false,
            hostname: hostname
        )
        let client = DHCPClient(machineId: machineId, config: clientConfig, provider: provider)
        dhcpClient = client
        try await client.start()
    }

    func requestAddress() async throws -> DHCPResponse {
        guard let client = dhcpClient else {
            throw DHCPError.notRunning
        }
        let response = try await client.requestAddress()
        assignedIP = response.assignedIP
        await virtualNetwork.setLocalAddress(response.assignedIP)
        return response
    }

    func renewLease() async throws -> DHCPResponse {
        guard let client = dhcpClient else {
            throw DHCPError.notRunning
        }
        return try await client.renewLease()
    }

    func releaseLease() async throws {
        guard let client = dhcpClient else { return }
        try await client.releaseLease()
        assignedIP = nil
    }

    func registerPeer(ip: String, machineId: MachineId) async {
        await virtualNetwork.registerAddress(ip: ip, machineId: machineId)
    }

    func route(to ip: String) async -> RouteDecision {
        await virtualNetwork.route(destinationIP: ip)
    }

    func stop() async {
        await dhcpClient?.stop()
        await dhcpService?.stop()
    }
}

/// Test channel provider that supports message relay between nodes
actor TestMeshProvider: ChannelProvider {
    let _machineId: MachineId
    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]
    var outbox: [(data: Data, target: MachineId, channel: String)] = []

    init(machineId: MachineId) {
        self._machineId = machineId
    }

    var peerId: PeerId {
        get async { _machineId }
    }

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        try await onChannel(channel, handler: handler)
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        outbox.append((data, peerId, channel))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        outbox.append((data, machineId, channel))
    }

    func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws {
        try await sendOnChannel(data, to: peerId, channel: channel)
    }

    func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        try await sendOnChannel(data, toMachine: machineId, channel: channel)
    }

    func flushChannel(_ channel: String) async throws {}

    func deliver(_ data: Data, from sender: MachineId, on channel: String) async {
        if let handler = handlers[channel] {
            await handler(sender, data)
        }
    }

    func drainOutbox() -> [(data: Data, target: MachineId, channel: String)] {
        let messages = outbox
        outbox.removeAll()
        return messages
    }
}

/// Message relay that routes messages between TestMeshNodes
actor TestMeshRelay {
    private var nodes: [MachineId: TestMeshProvider] = [:]
    private var relayTask: Task<Void, Never>?

    func register(_ provider: TestMeshProvider, as machineId: MachineId) {
        nodes[machineId] = provider
    }

    func start() {
        relayTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.relayOnce()
                try? await Task.sleep(for: .milliseconds(5))
            }
        }
    }

    func stop() {
        relayTask?.cancel()
        relayTask = nil
    }

    private func relayOnce() async {
        for (senderId, provider) in nodes {
            let messages = await provider.drainOutbox()
            for msg in messages {
                if let targetProvider = nodes[msg.target] {
                    await targetProvider.deliver(msg.data, from: senderId, on: msg.channel)
                }
            }
        }
    }
}

// MARK: - Integration Tests

final class DHCPIntegrationTests: XCTestCase {

    let networkConfig = VirtualNetworkConfig(
        subnet: "10.0.0.0",
        netmask: "255.255.0.0",
        prefixLength: 16,
        gatewayIP: "10.0.0.1",
        poolStart: "10.0.0.100",
        poolEnd: "10.0.0.200"
    )

    // MARK: - Basic Flow

    func testPeerJoinsAndGetsIP() async throws {
        let relay = TestMeshRelay()

        // Create gateway
        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        // Create peer
        let peer = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer.provider, as: "p1")
        try await peer.startClient(gatewayMachineId: "gw", hostname: "peer1")

        await relay.start()

        // Peer requests IP
        let response = try await peer.requestAddress()

        XCTAssertEqual(response.netmask, "255.255.0.0")
        XCTAssertEqual(response.gateway, "10.0.0.1")
        XCTAssertTrue(response.assignedIP.hasPrefix("10.0.0."))

        // Verify peer's virtual network is configured
        let localIP = await peer.virtualNetwork.getLocalIP()
        XCTAssertEqual(localIP, response.assignedIP)

        // Verify routing to self
        let selfRoute = await peer.route(to: response.assignedIP)
        XCTAssertEqual(selfRoute, .local)

        await relay.stop()
        await gateway.stop()
        await peer.stop()
    }

    func testTwoPeersGetUniqueIPs() async throws {
        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        let peer1 = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer1.provider, as: "p1")
        try await peer1.startClient(gatewayMachineId: "gw", hostname: "peer1")

        let peer2 = TestMeshNode(machineId: "p2", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer2.provider, as: "p2")
        try await peer2.startClient(gatewayMachineId: "gw", hostname: "peer2")

        await relay.start()

        let resp1 = try await peer1.requestAddress()
        let resp2 = try await peer2.requestAddress()

        // Unique IPs
        XCTAssertNotEqual(resp1.assignedIP, resp2.assignedIP)

        // Both in valid range
        XCTAssertTrue(resp1.assignedIP.hasPrefix("10.0.0."))
        XCTAssertTrue(resp2.assignedIP.hasPrefix("10.0.0."))

        await relay.stop()
        await gateway.stop()
        await peer1.stop()
        await peer2.stop()
    }

    // MARK: - DHCP + VirtualNetwork Routing

    func testDHCPAddressesEnableRouting() async throws {
        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        let peer1 = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer1.provider, as: "p1")
        try await peer1.startClient(gatewayMachineId: "gw")

        let peer2 = TestMeshNode(machineId: "p2", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer2.provider, as: "p2")
        try await peer2.startClient(gatewayMachineId: "gw")

        await relay.start()

        // Both peers get IPs
        let resp1 = try await peer1.requestAddress()
        let resp2 = try await peer2.requestAddress()

        // Simulate address gossip: each peer learns about the other
        await peer1.registerPeer(ip: resp2.assignedIP, machineId: "p2")
        await peer2.registerPeer(ip: resp1.assignedIP, machineId: "p1")

        // Also register gateway
        await peer1.registerPeer(ip: "10.0.0.1", machineId: "gw")
        await peer2.registerPeer(ip: "10.0.0.1", machineId: "gw")

        // Peer1 routing
        let p1ToSelf = await peer1.route(to: resp1.assignedIP)
        let p1ToPeer2 = await peer1.route(to: resp2.assignedIP)
        let p1ToGateway = await peer1.route(to: "10.0.0.1")
        XCTAssertEqual(p1ToSelf, .local)
        XCTAssertEqual(p1ToPeer2, .peer("p2"))
        XCTAssertEqual(p1ToGateway, .peer("gw"))

        // Peer2 routing
        let p2ToSelf = await peer2.route(to: resp2.assignedIP)
        let p2ToPeer1 = await peer2.route(to: resp1.assignedIP)
        XCTAssertEqual(p2ToSelf, .local)
        XCTAssertEqual(p2ToPeer1, .peer("p1"))

        await relay.stop()
        await gateway.stop()
        await peer1.stop()
        await peer2.stop()
    }

    func testGatewayKnowsAllPeerAddresses() async throws {
        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        await relay.start()

        // Create and register 5 peers
        var peers: [TestMeshNode] = []
        var assignedIPs: [String] = []

        for i in 1...5 {
            let peer = TestMeshNode(machineId: "p\(i)", isGateway: false, networkConfig: networkConfig)
            await relay.register(await peer.provider, as: "p\(i)")
            try await peer.startClient(gatewayMachineId: "gw", hostname: "host\(i)")
            peers.append(peer)
        }

        // Each peer requests an IP
        for peer in peers {
            let response = try await peer.requestAddress()
            assignedIPs.append(response.assignedIP)
        }

        // All IPs unique
        XCTAssertEqual(Set(assignedIPs).count, 5)

        // Register all peer addresses on the gateway's VirtualNetwork
        for (i, ip) in assignedIPs.enumerated() {
            await gateway.registerPeer(ip: ip, machineId: "p\(i + 1)")
        }

        // Gateway can route to all peers
        for (i, ip) in assignedIPs.enumerated() {
            let decision = await gateway.route(to: ip)
            XCTAssertEqual(decision, .peer("p\(i + 1)"))
        }

        // Gateway's DHCP service tracks leases
        let leases = await gateway.dhcpService!.getActiveLeases()
        XCTAssertEqual(leases.count, 5)

        await relay.stop()
        await gateway.stop()
        for peer in peers {
            await peer.stop()
        }
    }

    // MARK: - Lease Lifecycle

    func testLeaseRenewalPreservesIP() async throws {
        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        let peer = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer.provider, as: "p1")
        try await peer.startClient(gatewayMachineId: "gw")

        await relay.start()

        // Get initial IP
        let initial = try await peer.requestAddress()
        let initialIP = initial.assignedIP

        // Renew
        let renewed = try await peer.renewLease()
        XCTAssertEqual(renewed.assignedIP, initialIP)

        // VirtualNetwork still has the same local IP
        let localIP = await peer.virtualNetwork.getLocalIP()
        XCTAssertEqual(localIP, initialIP)

        await relay.stop()
        await gateway.stop()
        await peer.stop()
    }

    func testReleaseAndReacquire() async throws {
        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        let peer = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer.provider, as: "p1")
        try await peer.startClient(gatewayMachineId: "gw")

        await relay.start()

        let poolBefore = await gateway.dhcpService!.availableIPCount()

        // Get IP
        let response1 = try await peer.requestAddress()
        let poolAfterAlloc = await gateway.dhcpService!.availableIPCount()
        XCTAssertEqual(poolAfterAlloc, poolBefore - 1)

        // Release
        try await peer.releaseLease()

        // Wait for relay
        try await Task.sleep(for: .milliseconds(50))

        let poolAfterRelease = await gateway.dhcpService!.availableIPCount()
        XCTAssertEqual(poolAfterRelease, poolBefore)

        // Re-acquire (may get same or different IP)
        let response2 = try await peer.requestAddress()
        XCTAssertNotNil(response2.assignedIP)

        let poolAfterReacquire = await gateway.dhcpService!.availableIPCount()
        XCTAssertEqual(poolAfterReacquire, poolBefore - 1)

        await relay.stop()
        await gateway.stop()
        await peer.stop()
    }

    func testRequestPreferredIP() async throws {
        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        let peer = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer.provider, as: "p1")

        let clientConfig = NativeDHCPClientConfig(
            gatewayMachineId: "gw",
            timeout: 5,
            retries: 1,
            autoRenew: false
        )
        let client = DHCPClient(machineId: "p1", config: clientConfig, provider: await peer.provider)
        try await client.start()

        await relay.start()

        // Request a specific IP
        let response = try await client.requestAddress(requestedIP: "10.0.0.150")
        XCTAssertEqual(response.assignedIP, "10.0.0.150")

        await relay.stop()
        await client.stop()
        await gateway.stop()
    }

    // MARK: - Returning Peer

    func testReturningPeerGetsSameIP() async throws {
        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        let peer = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        await relay.register(await peer.provider, as: "p1")
        try await peer.startClient(gatewayMachineId: "gw")

        await relay.start()

        // First request
        let resp1 = try await peer.requestAddress()
        let firstIP = resp1.assignedIP

        // Second request from same machine (e.g., reconnect without releasing)
        // Service should return same lease
        let resp2 = try await peer.requestAddress()
        XCTAssertEqual(resp2.assignedIP, firstIP)

        await relay.stop()
        await gateway.stop()
        await peer.stop()
    }

    // MARK: - Full Mesh with Routing

    func testFullMeshSetup() async throws {
        let relay = TestMeshRelay()

        // Gateway
        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: networkConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        // 3 peers
        let peer1 = TestMeshNode(machineId: "p1", isGateway: false, networkConfig: networkConfig)
        let peer2 = TestMeshNode(machineId: "p2", isGateway: false, networkConfig: networkConfig)
        let peer3 = TestMeshNode(machineId: "p3", isGateway: false, networkConfig: networkConfig)

        for (id, peer) in [("p1", peer1), ("p2", peer2), ("p3", peer3)] {
            await relay.register(await peer.provider, as: id)
            try await peer.startClient(gatewayMachineId: "gw")
        }

        await relay.start()

        // All peers get IPs
        let ip1 = try await peer1.requestAddress().assignedIP
        let ip2 = try await peer2.requestAddress().assignedIP
        let ip3 = try await peer3.requestAddress().assignedIP

        // Verify all unique
        let ips = Set([ip1, ip2, ip3])
        XCTAssertEqual(ips.count, 3)

        // Simulate full mesh address discovery (gossip)
        let allNodes: [(String, String, TestMeshNode)] = [
            ("gw", "10.0.0.1", gateway),
            ("p1", ip1, peer1),
            ("p2", ip2, peer2),
            ("p3", ip3, peer3),
        ]

        for (_, _, node) in allNodes {
            for (peerId, peerIP, _) in allNodes {
                if peerId != node.machineId {
                    await node.registerPeer(ip: peerIP, machineId: peerId)
                }
            }
            // Set gateway for external routing
            await node.virtualNetwork.setGateway(machineId: "gw", ip: "10.0.0.1")
        }

        // Verify full mesh routing
        // Peer1 can route to everyone
        let p1Self = await peer1.route(to: ip1)
        let p1ToP2 = await peer1.route(to: ip2)
        let p1ToP3 = await peer1.route(to: ip3)
        let p1ToGW = await peer1.route(to: "10.0.0.1")
        XCTAssertEqual(p1Self, .local)
        XCTAssertEqual(p1ToP2, .peer("p2"))
        XCTAssertEqual(p1ToP3, .peer("p3"))
        XCTAssertEqual(p1ToGW, .peer("gw"))

        // Peer2 can route to everyone
        let p2Self = await peer2.route(to: ip2)
        let p2ToP1 = await peer2.route(to: ip1)
        let p2ToP3 = await peer2.route(to: ip3)
        XCTAssertEqual(p2Self, .local)
        XCTAssertEqual(p2ToP1, .peer("p1"))
        XCTAssertEqual(p2ToP3, .peer("p3"))

        // External traffic routes to gateway
        let p1Ext = await peer1.route(to: "8.8.8.8")
        let p2Ext = await peer2.route(to: "1.1.1.1")
        let p3Ext = await peer3.route(to: "8.8.4.4")
        XCTAssertEqual(p1Ext, .gateway)
        XCTAssertEqual(p2Ext, .gateway)
        XCTAssertEqual(p3Ext, .gateway)

        // Gateway routes to all peers
        let gwToP1 = await gateway.route(to: ip1)
        let gwToP2 = await gateway.route(to: ip2)
        let gwToP3 = await gateway.route(to: ip3)
        let gwToSelf = await gateway.route(to: "10.0.0.1")
        XCTAssertEqual(gwToP1, .peer("p1"))
        XCTAssertEqual(gwToP2, .peer("p2"))
        XCTAssertEqual(gwToP3, .peer("p3"))
        XCTAssertEqual(gwToSelf, .local)

        await relay.stop()
        await gateway.stop()
        await peer1.stop()
        await peer2.stop()
        await peer3.stop()
    }

    // MARK: - Edge Cases

    func testPeerLeavesAndIPIsRecycled() async throws {
        // Use a tiny pool to test recycling
        let tinyConfig = VirtualNetworkConfig(
            subnet: "10.0.0.0",
            netmask: "255.255.0.0",
            prefixLength: 16,
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.102"  // Only 3 IPs
        )

        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: tinyConfig)
        await relay.register(await gateway.provider, as: "gw")
        try await gateway.startGateway()

        await relay.start()

        // Create 3 peers and exhaust the pool
        var peers: [TestMeshNode] = []
        for i in 1...3 {
            let peer = TestMeshNode(machineId: "p\(i)", isGateway: false, networkConfig: tinyConfig)
            await relay.register(await peer.provider, as: "p\(i)")
            try await peer.startClient(gatewayMachineId: "gw")
            peers.append(peer)
            _ = try await peer.requestAddress()
        }

        // Pool should be exhausted
        let available = await gateway.dhcpService!.availableIPCount()
        XCTAssertEqual(available, 0)

        // Peer 2 leaves
        try await peers[1].releaseLease()
        try await Task.sleep(for: .milliseconds(50))

        // Pool should have 1 IP back
        let availableAfter = await gateway.dhcpService!.availableIPCount()
        XCTAssertEqual(availableAfter, 1)

        // New peer can now join
        let newPeer = TestMeshNode(machineId: "p4", isGateway: false, networkConfig: tinyConfig)
        await relay.register(await newPeer.provider, as: "p4")
        try await newPeer.startClient(gatewayMachineId: "gw")
        let response = try await newPeer.requestAddress()
        XCTAssertNotNil(response.assignedIP)

        await relay.stop()
        await gateway.stop()
        for peer in peers { await peer.stop() }
        await newPeer.stop()
    }

    func testExpiredLeaseCleanup() async throws {
        // Use 1-second leases
        let shortLeaseConfig = VirtualNetworkConfig(
            subnet: "10.0.0.0",
            netmask: "255.255.0.0",
            prefixLength: 16,
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.102"  // Only 3 IPs
        )

        let relay = TestMeshRelay()

        let gateway = TestMeshNode(machineId: "gw", isGateway: true, networkConfig: shortLeaseConfig)
        // Override with 1-second lease
        let serviceConfig = DHCPServiceConfig(from: shortLeaseConfig, leaseTime: 1)
        let service = DHCPService(config: serviceConfig, provider: await gateway.provider)
        // We need to use the service directly since TestMeshNode creates its own
        await relay.register(await gateway.provider, as: "gw")
        try await service.start()

        await relay.start()

        // Allocate all 3 IPs
        for i in 1...3 {
            let peer = TestMeshNode(machineId: "p\(i)", isGateway: false, networkConfig: shortLeaseConfig)
            await relay.register(await peer.provider, as: "p\(i)")
            try await peer.startClient(gatewayMachineId: "gw")
            _ = try await peer.requestAddress()
            await peer.stop()
        }

        // Pool should be exhausted
        let before = await service.availableIPCount()
        XCTAssertEqual(before, 0)

        // Wait for leases to expire
        try await Task.sleep(for: .seconds(2))

        // Cleanup expired leases
        await service.cleanupExpiredLeases()

        // All 3 IPs should be back in the pool
        let after = await service.availableIPCount()
        XCTAssertEqual(after, 3)

        let activeLeases = await service.getActiveLeases()
        XCTAssertTrue(activeLeases.isEmpty)

        await relay.stop()
        await service.stop()
    }

    func testDNSServersPassedToClients() async throws {
        let configWithDNS = VirtualNetworkConfig(
            subnet: "10.0.0.0",
            netmask: "255.255.0.0",
            prefixLength: 16,
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let serviceConfig = DHCPServiceConfig(
            from: configWithDNS,
            dnsServers: ["8.8.8.8", "1.1.1.1"]
        )

        let relay = TestMeshRelay()

        let gatewayProvider = TestMeshProvider(machineId: "gw")
        await relay.register(gatewayProvider, as: "gw")
        let service = DHCPService(config: serviceConfig, provider: gatewayProvider)
        try await service.start()

        let peerProvider = TestMeshProvider(machineId: "p1")
        await relay.register(peerProvider, as: "p1")
        let clientConfig = NativeDHCPClientConfig(
            gatewayMachineId: "gw",
            timeout: 5,
            retries: 1,
            autoRenew: false
        )
        let client = DHCPClient(machineId: "p1", config: clientConfig, provider: peerProvider)
        try await client.start()

        await relay.start()

        let response = try await client.requestAddress()
        XCTAssertEqual(response.dnsServers, ["8.8.8.8", "1.1.1.1"])

        await relay.stop()
        await client.stop()
        await service.stop()
    }
}
