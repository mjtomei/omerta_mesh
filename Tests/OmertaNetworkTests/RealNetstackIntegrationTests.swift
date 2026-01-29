// RealNetstackIntegrationTests.swift - End-to-end tests with real netstack bridges
//
// Tests the full virtual network path using a real gVisor netstack bridge on
// the gateway to make actual internet connections:
//   Peer MockNetworkInterface → PacketRouter → VirtualNetwork → TunnelSession
//   → mesh relay → Gateway PacketRouter → GatewayService → real NetstackBridge
//   → actual internet → response back through the full reverse chain
//
// These tests require:
// - libnetstack.a (built by the BuildNetstack plugin)
// - Internet access (makes real DNS/HTTP requests)

import XCTest
@testable import OmertaNetwork
@testable import OmertaTunnel
@testable import OmertaMesh

final class RealNetstackIntegrationTests: XCTestCase {

    // MARK: - End-to-End DNS Query Through Gateway

    /// Full stack test: peer sends a raw UDP DNS query packet, it routes through
    /// the virtual network to the gateway, gateway's real netstack forwards it to
    /// a real DNS server (8.8.8.8), and the DNS response flows back to the peer.
    func testEndToEndDNSQueryThroughGateway() async throws {
        // --- Create real netstack bridge for the gateway ---

        let gatewayBridge: NetstackBridge
        do {
            gatewayBridge = try NetstackBridge(config: .init(gatewayIP: "10.200.0.1"))
        } catch {
            throw XCTSkip("NetstackBridge unavailable (libnetstack.a not built?): \(error)")
        }

        // --- Peer node: MockNetworkInterface + PacketRouter ---

        let peerProvider = E2EChannelProvider(machineId: "peer")
        let peerInterface = MockNetworkInterface(localIP: "10.0.0.100")
        let peerVNet = VirtualNetwork(localMachineId: "peer")
        await peerVNet.setLocalAddress("10.0.0.100")
        await peerVNet.setGateway(machineId: "gw", ip: "10.0.0.1")

        let peerTunnelManager = TunnelManager(provider: peerProvider)
        try await peerTunnelManager.start()

        let peerRouter = PacketRouter(
            localInterface: peerInterface,
            virtualNetwork: peerVNet,
            tunnelManager: peerTunnelManager
        )

        // --- Gateway node: MockNetworkInterface + GatewayService with real netstack ---

        let gwProvider = E2EChannelProvider(machineId: "gw")
        let gwInterface = MockNetworkInterface(localIP: "10.0.0.1")
        let gwVNet = VirtualNetwork(localMachineId: "gw")
        await gwVNet.setLocalAddress("10.0.0.1")
        await gwVNet.setGateway(machineId: "gw", ip: "10.0.0.1")
        await gwVNet.registerAddress(ip: "10.0.0.100", machineId: "peer")

        let gwGatewayService = GatewayService(bridge: gatewayBridge)

        let gwTunnelManager = TunnelManager(provider: gwProvider)
        try await gwTunnelManager.start()

        let gwRouter = PacketRouter(
            localInterface: gwInterface,
            virtualNetwork: gwVNet,
            tunnelManager: gwTunnelManager,
            gatewayService: gwGatewayService
        )

        // --- Wire mesh relay ---

        let relay = E2ERelay()
        await relay.register(machineId: "peer", provider: peerProvider)
        await relay.register(machineId: "gw", provider: gwProvider)
        await relay.startRelay()

        // --- Start everything ---

        try await gwGatewayService.start()
        try await peerRouter.start()
        try await gwRouter.start()

        // --- Send a DNS query from the peer ---
        //
        // The peer sends a raw IPv4/UDP packet to 8.8.8.8:53 with a DNS query
        // for "example.com". The packet flows:
        //   1. MockNetworkInterface.simulateAppSend()
        //   2. PacketRouter.readPacket() → routeOutbound()
        //   3. VirtualNetwork.route("8.8.8.8") → .gateway
        //   4. TunnelSession.send() → mesh relay → gateway
        //   5. Gateway PacketRouter → GatewayService.forwardToInternet()
        //   6. Real NetstackBridge.injectPacket() → gVisor UDP forwarder
        //   7. Go net.Dial("udp", "8.8.8.8:53") → real DNS query
        //   8. DNS response → netstack return callback
        //   9. GatewayService NAT → tunnel → peer PacketRouter
        //  10. Peer interface.writePacket() → MockNetworkInterface inbound queue

        let dnsQuery = Self.buildDNSQueryPacket(
            srcIP: "10.0.0.100",
            dstIP: "8.8.8.8",
            srcPort: 12345,
            dstPort: 53,
            domain: "example.com"
        )

        // Small delay to ensure PacketRouter's outbound loop is waiting on readPacket()
        try await Task.sleep(for: .milliseconds(100))

        await peerInterface.simulateAppSend(dnsQuery)

        // Wait for the response to flow back
        var response: Data?
        for i in 0..<100 { // poll for up to 10 seconds
            try await Task.sleep(for: .milliseconds(100))
            let received = await peerInterface.getAllAppReceived()
            if let pkt = received.first(where: { Self.isDNSResponse($0) }) {
                response = pkt
                break
            }
        }

        // --- Validate ---

        XCTAssertNotNil(response, "Should have received a DNS response packet")

        if let response {
            // Verify it's a valid IPv4 UDP packet from 8.8.8.8 to 10.0.0.100
            XCTAssertGreaterThanOrEqual(response.count, 28, "Response should be at least an IP+UDP header")

            // Check IP header: src should be 8.8.8.8, dst should be 10.0.0.100
            let srcIP = Self.extractIPString(from: response, offset: 12)
            let dstIP = Self.extractIPString(from: response, offset: 16)
            XCTAssertEqual(srcIP, "8.8.8.8", "Response source should be DNS server")
            XCTAssertEqual(dstIP, "10.0.0.100", "Response destination should be peer")

            // Check protocol is UDP (17)
            XCTAssertEqual(response[9], 17, "Response should be UDP")

            // DNS response should have answer count > 0 (bytes 34-35 of the packet,
            // assuming 20-byte IP header + 8-byte UDP header + DNS header)
            if response.count >= 36 {
                let answerCount = UInt16(response[34]) << 8 | UInt16(response[35])
                XCTAssertGreaterThan(answerCount, 0, "DNS response should have answers")
            }
        }

        // Verify packets flowed through the gateway
        let peerStats = await peerRouter.getStats()
        XCTAssertGreaterThan(peerStats.packetsToGateway, 0, "Peer should have sent packets to gateway")

        let gwStats = await gwRouter.getStats()
        XCTAssertGreaterThan(gwStats.packetsFromPeers, 0, "Gateway should have received packets from peer")

        // --- Cleanup ---

        await relay.stopRelay()
        await peerRouter.stop()
        await gwRouter.stop()
        await gwGatewayService.stop()
        await peerTunnelManager.stop()
        await gwTunnelManager.stop()
    }

    // MARK: - DNS Packet Helpers

    /// Build a raw IPv4/UDP DNS query packet
    static func buildDNSQueryPacket(
        srcIP: String, dstIP: String,
        srcPort: UInt16, dstPort: UInt16,
        domain: String
    ) -> Data {
        // DNS payload
        var dns = Data()
        dns.append(contentsOf: [0xAB, 0xCD]) // Transaction ID
        dns.append(contentsOf: [0x01, 0x00]) // Flags: standard query, recursion desired
        dns.append(contentsOf: [0x00, 0x01]) // Questions: 1
        dns.append(contentsOf: [0x00, 0x00]) // Answers: 0
        dns.append(contentsOf: [0x00, 0x00]) // Authority: 0
        dns.append(contentsOf: [0x00, 0x00]) // Additional: 0

        // QNAME: encode domain as labels
        for label in domain.split(separator: ".") {
            dns.append(UInt8(label.count))
            dns.append(contentsOf: label.utf8)
        }
        dns.append(0x00) // Root label

        dns.append(contentsOf: [0x00, 0x01]) // QTYPE: A
        dns.append(contentsOf: [0x00, 0x01]) // QCLASS: IN

        // UDP header
        let udpLength = UInt16(8 + dns.count)
        var udp = Data()
        udp.append(UInt8(srcPort >> 8)); udp.append(UInt8(srcPort & 0xFF))
        udp.append(UInt8(dstPort >> 8)); udp.append(UInt8(dstPort & 0xFF))
        udp.append(UInt8(udpLength >> 8)); udp.append(UInt8(udpLength & 0xFF))
        udp.append(contentsOf: [0x00, 0x00]) // Checksum (0 = disabled for IPv4 UDP)
        udp.append(dns)

        // IPv4 header
        let totalLength = UInt16(20 + udp.count)
        var ip = Data()
        ip.append(0x45) // Version 4, IHL 5
        ip.append(0x00) // DSCP
        ip.append(UInt8(totalLength >> 8)); ip.append(UInt8(totalLength & 0xFF))
        ip.append(contentsOf: [0x00, 0x01]) // Identification
        ip.append(contentsOf: [0x00, 0x00]) // Flags + Fragment
        ip.append(64)   // TTL
        ip.append(17)   // Protocol: UDP
        ip.append(contentsOf: [0x00, 0x00]) // Checksum placeholder

        // Source IP
        for octet in srcIP.split(separator: ".") {
            ip.append(UInt8(octet)!)
        }
        // Destination IP
        for octet in dstIP.split(separator: ".") {
            ip.append(UInt8(octet)!)
        }

        // Calculate and set IPv4 header checksum
        var sum: UInt32 = 0
        for i in stride(from: 0, to: 20, by: 2) {
            sum += UInt32(ip[i]) << 8 | UInt32(ip[i + 1])
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        let checksum = ~UInt16(sum)
        ip[10] = UInt8(checksum >> 8)
        ip[11] = UInt8(checksum & 0xFF)

        ip.append(udp)
        return ip
    }

    /// Check if a packet looks like a DNS response (IPv4 UDP from port 53)
    static func isDNSResponse(_ packet: Data) -> Bool {
        guard packet.count >= 28 else { return false }
        guard packet[0] >> 4 == 4 else { return false } // IPv4
        guard packet[9] == 17 else { return false } // UDP
        let ihl = Int(packet[0] & 0x0F) * 4
        guard packet.count >= ihl + 4 else { return false }
        // Source port should be 53
        let srcPort = UInt16(packet[ihl]) << 8 | UInt16(packet[ihl + 1])
        return srcPort == 53
    }

    /// Extract an IP address string from packet at the given offset
    static func extractIPString(from packet: Data, offset: Int) -> String {
        guard packet.count > offset + 3 else { return "?" }
        return "\(packet[offset]).\(packet[offset+1]).\(packet[offset+2]).\(packet[offset+3])"
    }
}

// MARK: - Test Infrastructure

/// Channel provider for end-to-end tests.
private actor E2EChannelProvider: ChannelProvider {
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

    func drainSentMessages() -> [(data: Data, target: MachineId, channel: String)] {
        let msgs = sentMessages
        sentMessages.removeAll()
        return msgs
    }

    func clearSentMessages() {
        sentMessages.removeAll()
    }
}

/// Relay that shuttles messages between E2EChannelProviders, simulating the mesh.
private actor E2ERelay {
    private var providers: [MachineId: E2EChannelProvider] = [:]
    private var relayTask: Task<Void, Never>?

    func register(machineId: MachineId, provider: E2EChannelProvider) {
        providers[machineId] = provider
    }

    func startRelay() {
        relayTask = Task {
            while !Task.isCancelled {
                await relayMessages()
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
    }

    func stopRelay() {
        relayTask?.cancel()
        relayTask = nil
    }

    private func relayMessages() async {
        var pending: [(from: MachineId, to: MachineId, data: Data, channel: String)] = []

        for (machineId, provider) in providers {
            for msg in await provider.drainSentMessages() {
                pending.append((machineId, msg.target, msg.data, msg.channel))
            }
        }

        for msg in pending {
            if let target = providers[msg.to] {
                await target.deliverMessage(msg.data, from: msg.from, on: msg.channel)
            }
        }
    }
}
