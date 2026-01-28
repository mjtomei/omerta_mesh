import XCTest
import OmertaMesh
@testable import OmertaNetwork

// MARK: - Auto-Responding Bridge

/// Wraps StubNetstackBridge to automatically generate response packets when packets are injected.
private actor AutoRespondingBridge: NetstackBridgeProtocol {
    private let stub = StubNetstackBridge()
    private var returnCallback: (@Sendable (Data) -> Void)?

    func start() async throws {
        try await stub.start()
        await stub.setReturnCallback { [weak self] packet in
            guard let self else { return }
            Task { await self.returnCallback?(packet) }
        }
    }

    func stop() async {
        await stub.stop()
    }

    func injectPacket(_ packet: Data) async throws {
        try await stub.injectPacket(packet)

        // Auto-generate a response by swapping src/dst
        if let response = Self.createResponse(for: packet) {
            await stub.simulateOutbound(response)
        }
    }

    func setReturnCallback(_ callback: @escaping @Sendable (Data) -> Void) async {
        returnCallback = callback
    }

    func dialTCP(host: String, port: UInt16) async throws -> TCPConnection {
        throw InterfaceError.notSupported
    }

    /// Simulate outbound without auto-response (for manual control)
    func simulateOutbound(_ packet: Data) async {
        await stub.simulateOutbound(packet)
    }

    func getInjectedPackets() async -> [Data] {
        await stub.getInjectedPackets()
    }

    /// Create a response packet by swapping src/dst IP and ports.
    private static func createResponse(for packet: Data) -> Data? {
        guard packet.count >= 24 else { return nil }
        let versionIHL = packet[packet.startIndex]
        guard (versionIHL >> 4) == 4 else { return nil }
        let ihl = Int(versionIHL & 0x0F) * 4
        guard packet.count >= ihl + 4 else { return nil }

        let proto = packet[packet.startIndex + 9]
        let srcIP = packet[(packet.startIndex + 12)..<(packet.startIndex + 16)]
        let dstIP = packet[(packet.startIndex + 16)..<(packet.startIndex + 20)]
        let srcPort = packet[(packet.startIndex + ihl)..<(packet.startIndex + ihl + 2)]
        let dstPort = packet[(packet.startIndex + ihl + 2)..<(packet.startIndex + ihl + 4)]

        return GatewayServiceTests.createIPv4Packet(
            src: formatIP(Array(dstIP)),
            srcPort: UInt16(dstPort[dstPort.startIndex]) << 8 | UInt16(dstPort[dstPort.startIndex + 1]),
            dst: formatIP(Array(srcIP)),
            dstPort: UInt16(srcPort[srcPort.startIndex]) << 8 | UInt16(srcPort[srcPort.startIndex + 1]),
            proto: proto
        )
    }

    private static func formatIP(_ bytes: [UInt8]) -> String {
        bytes.map { String($0) }.joined(separator: ".")
    }
}

// MARK: - Result Collectors

private actor PacketCollector {
    var results: [(Data, MachineId)] = []
    func append(_ packet: Data, _ machineId: MachineId) {
        results.append((packet, machineId))
    }
    var machineIds: [MachineId] { results.map(\.1) }
    var count: Int { results.count }
}

// MARK: - Integration Tests

final class GatewayServiceIntegrationTests: XCTestCase {

    private func createPacket(
        src: String, srcPort: UInt16,
        dst: String, dstPort: UInt16,
        proto: UInt8 = 6
    ) -> Data {
        GatewayServiceTests.createIPv4Packet(
            src: src, srcPort: srcPort,
            dst: dst, dstPort: dstPort,
            proto: proto
        )!
    }

    // MARK: - 1. Single peer accesses internet

    func testSinglePeerAccessesInternet() async throws {
        let bridge = AutoRespondingBridge()
        let gw = GatewayService(bridge: bridge)

        let expectation = XCTestExpectation(description: "response returned")
        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
            expectation.fulfill()
        }

        try await gw.start()

        let packet = createPacket(src: "10.0.0.1", srcPort: 12345, dst: "8.8.8.8", dstPort: 443)
        await gw.forwardToInternet(packet, from: "m1")

        await fulfillment(of: [expectation], timeout: 2)
        let ids = await collector.machineIds
        XCTAssertEqual(ids, ["m1"])
    }

    // MARK: - 2. Multiple peers access internet

    func testMultiplePeersAccessInternet() async throws {
        let bridge = AutoRespondingBridge()
        let gw = GatewayService(bridge: bridge)

        let expectation = XCTestExpectation(description: "all responses")
        expectation.expectedFulfillmentCount = 3
        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
            expectation.fulfill()
        }

        try await gw.start()

        await gw.forwardToInternet(createPacket(src: "10.0.0.1", srcPort: 1001, dst: "8.8.8.8", dstPort: 443), from: "m1")
        await gw.forwardToInternet(createPacket(src: "10.0.0.2", srcPort: 1002, dst: "1.1.1.1", dstPort: 80), from: "m2")
        await gw.forwardToInternet(createPacket(src: "10.0.0.3", srcPort: 1003, dst: "9.9.9.9", dstPort: 53), from: "m3")

        await fulfillment(of: [expectation], timeout: 2)
        let ids = await collector.machineIds
        XCTAssertTrue(ids.contains("m1"))
        XCTAssertTrue(ids.contains("m2"))
        XCTAssertTrue(ids.contains("m3"))
    }

    // MARK: - 3. Same peer multiple connections

    func testSamePeerMultipleConnections() async throws {
        let bridge = AutoRespondingBridge()
        let gw = GatewayService(bridge: bridge)

        let expectation = XCTestExpectation(description: "3 responses")
        expectation.expectedFulfillmentCount = 3
        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
            expectation.fulfill()
        }

        try await gw.start()

        await gw.forwardToInternet(createPacket(src: "10.0.0.1", srcPort: 2001, dst: "93.184.216.34", dstPort: 80), from: "m1")
        await gw.forwardToInternet(createPacket(src: "10.0.0.1", srcPort: 2002, dst: "142.250.80.46", dstPort: 443), from: "m1")
        await gw.forwardToInternet(createPacket(src: "10.0.0.1", srcPort: 2003, dst: "104.16.132.229", dstPort: 8080), from: "m1")

        await fulfillment(of: [expectation], timeout: 2)
        let ids = await collector.machineIds
        XCTAssertEqual(ids.count, 3)
        XCTAssertTrue(ids.allSatisfy { $0 == "m1" })
    }

    // MARK: - 4. Concurrent peer traffic

    func testConcurrentPeerTraffic() async throws {
        let bridge = AutoRespondingBridge()
        let gw = GatewayService(bridge: bridge)

        let expectation = XCTestExpectation(description: "concurrent responses")
        expectation.expectedFulfillmentCount = 5
        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
            expectation.fulfill()
        }

        try await gw.start()

        await withTaskGroup(of: Void.self) { group in
            for i in 0..<5 {
                let peerIP = "10.0.0.\(i + 1)"
                let port = UInt16(3000 + i)
                let machineId = "m\(i + 1)"
                let packet = createPacket(src: peerIP, srcPort: port, dst: "8.8.8.8", dstPort: 443)
                group.addTask {
                    await gw.forwardToInternet(packet, from: machineId)
                }
            }
        }

        await fulfillment(of: [expectation], timeout: 3)
        let ids = await collector.machineIds
        XCTAssertEqual(Set(ids).count, 5)
    }

    // MARK: - 5. Burst traffic from peer

    func testBurstTrafficFromPeer() async throws {
        let bridge = AutoRespondingBridge()
        let gw = GatewayService(bridge: bridge)

        let expectation = XCTestExpectation(description: "50 responses")
        expectation.expectedFulfillmentCount = 50
        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
            expectation.fulfill()
        }

        try await gw.start()

        for i in 0..<50 {
            let packet = createPacket(src: "10.0.0.1", srcPort: UInt16(4000 + i), dst: "8.8.8.8", dstPort: 443)
            await gw.forwardToInternet(packet, from: "m1")
        }

        await fulfillment(of: [expectation], timeout: 5)
        let count = await collector.count
        XCTAssertEqual(count, 50)
    }

    // MARK: - 6. NAT expiry drops late response

    func testPeerTrafficAfterNATExpiry() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub, natTimeout: 0.01)

        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
        }

        try await gw.start()

        let packet = createPacket(src: "10.0.0.1", srcPort: 5000, dst: "8.8.8.8", dstPort: 443)
        await gw.forwardToInternet(packet, from: "m1")

        // Wait for NAT to expire, then cleanup
        try await Task.sleep(nanoseconds: 20_000_000)
        await gw.cleanupExpiredEntries()

        // Late response arrives after NAT expired
        let response = createPacket(src: "8.8.8.8", srcPort: 443, dst: "10.0.0.1", dstPort: 5000)
        await stub.simulateOutbound(response)

        try await Task.sleep(nanoseconds: 50_000_000)
        let count = await collector.count
        XCTAssertEqual(count, 0, "Late response after NAT expiry should be dropped")
    }

    // MARK: - 7. Mixed TCP and UDP traffic

    func testMixedTCPAndUDPTraffic() async throws {
        let bridge = AutoRespondingBridge()
        let gw = GatewayService(bridge: bridge)

        let expectation = XCTestExpectation(description: "TCP and UDP responses")
        expectation.expectedFulfillmentCount = 2
        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
            expectation.fulfill()
        }

        try await gw.start()

        let tcpPacket = createPacket(src: "10.0.0.1", srcPort: 6001, dst: "93.184.216.34", dstPort: 443, proto: 6)
        let udpPacket = createPacket(src: "10.0.0.2", srcPort: 6002, dst: "8.8.8.8", dstPort: 53, proto: 17)

        await gw.forwardToInternet(tcpPacket, from: "m1")
        await gw.forwardToInternet(udpPacket, from: "m2")

        await fulfillment(of: [expectation], timeout: 2)
        let ids = await collector.machineIds
        XCTAssertTrue(ids.contains("m1"))
        XCTAssertTrue(ids.contains("m2"))
    }

    // MARK: - 8. Real NetstackBridge integration

    func testRealNetstackBridgeStartStop() async throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1")
        let bridge: NetstackBridge
        do {
            bridge = try NetstackBridge(config: config)
        } catch {
            // C library not available — skip gracefully
            throw XCTSkip("NetstackBridge C library not available: \(error)")
        }

        let gw = GatewayService(bridge: bridge)
        try await gw.start()

        let packet = createPacket(src: "10.0.0.1", srcPort: 12345, dst: "8.8.8.8", dstPort: 443)
        await gw.forwardToInternet(packet, from: "m1")

        let count = await gw.natEntryCount()
        XCTAssertEqual(count, 1, "NAT entry should be created with real bridge")

        await gw.stop()
    }

    // MARK: - 9. Gateway stop mid-traffic

    func testGatewayStopMidTraffic() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)

        let collector = PacketCollector()
        await gw.setReturnHandler { [collector] packet, machineId in
            await collector.append(packet, machineId)
        }

        try await gw.start()

        let packet = createPacket(src: "10.0.0.1", srcPort: 7000, dst: "8.8.8.8", dstPort: 443)
        await gw.forwardToInternet(packet, from: "m1")

        // Stop before bridge responds
        await gw.stop()

        // Late response after stop — should not crash
        let response = createPacket(src: "8.8.8.8", srcPort: 443, dst: "10.0.0.1", dstPort: 7000)
        await stub.simulateOutbound(response)

        try await Task.sleep(nanoseconds: 50_000_000)
        // No crash is the success condition; response may or may not be delivered
    }
}
