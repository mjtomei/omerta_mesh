import XCTest
import OmertaMesh
@testable import OmertaNetwork

final class GatewayServiceTests: XCTestCase {

    // MARK: - Packet Helper

    static func createIPv4Packet(
        src: String, srcPort: UInt16,
        dst: String, dstPort: UInt16,
        proto: UInt8 = 6,
        payload: Data = Data()
    ) -> Data? {
        guard let srcParts = parseIP(src), let dstParts = parseIP(dst) else { return nil }

        var packet = Data()
        packet.append(0x45)
        packet.append(0x00)
        let totalLength = UInt16(20 + 4 + payload.count)
        packet.append(UInt8(totalLength >> 8))
        packet.append(UInt8(totalLength & 0xFF))
        packet.append(contentsOf: [0x00, 0x00])
        packet.append(contentsOf: [0x00, 0x00])
        packet.append(64)
        packet.append(proto)
        packet.append(contentsOf: [0x00, 0x00])
        packet.append(contentsOf: srcParts)
        packet.append(contentsOf: dstParts)
        packet.append(UInt8(srcPort >> 8))
        packet.append(UInt8(srcPort & 0xFF))
        packet.append(UInt8(dstPort >> 8))
        packet.append(UInt8(dstPort & 0xFF))
        packet.append(payload)
        return packet
    }

    private static func parseIP(_ ip: String) -> [UInt8]? {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        return parts.count == 4 ? parts : nil
    }

    // MARK: - Tests

    func testForwardInjectsPacketIntoBridge() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)
        try await gw.start()

        let packet = Self.createIPv4Packet(src: "10.0.0.1", srcPort: 12345, dst: "1.1.1.1", dstPort: 80)!
        await gw.forwardToInternet(packet, from: "m1")

        let injected = await stub.getInjectedPackets()
        XCTAssertEqual(injected.count, 1)
        XCTAssertEqual(injected[0], packet)
    }

    func testNATEntryCreatedOnForward() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)
        try await gw.start()

        let packet = Self.createIPv4Packet(src: "10.0.0.1", srcPort: 12345, dst: "1.1.1.1", dstPort: 80)!
        await gw.forwardToInternet(packet, from: "m1")

        let count = await gw.natEntryCount()
        XCTAssertEqual(count, 1)
    }

    func testReturnPacketRoutedToOriginalPeer() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)

        let expectation = XCTestExpectation(description: "return handler called")
        let collector = ResultCollector()
        await gw.setReturnHandler { [collector] _, machineId in
            await collector.set(machineId: machineId)
            expectation.fulfill()
        }

        try await gw.start()

        let outbound = Self.createIPv4Packet(src: "10.0.0.1", srcPort: 12345, dst: "1.1.1.1", dstPort: 80)!
        await gw.forwardToInternet(outbound, from: "m1")

        let inbound = Self.createIPv4Packet(src: "1.1.1.1", srcPort: 80, dst: "10.0.0.1", dstPort: 12345)!
        await stub.simulateOutbound(inbound)

        await fulfillment(of: [expectation], timeout: 2)
        let machine = await collector.machineId
        XCTAssertEqual(machine, "m1")
    }

    func testMultiplePeersDifferentSrcPorts() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)

        let expectation = XCTestExpectation(description: "both returns received")
        expectation.expectedFulfillmentCount = 2
        let collector = MultiResultCollector()

        await gw.setReturnHandler { [collector] _, machineId in
            await collector.append(machineId: machineId)
            expectation.fulfill()
        }

        try await gw.start()

        let p1 = Self.createIPv4Packet(src: "10.0.0.1", srcPort: 1001, dst: "8.8.8.8", dstPort: 443)!
        let p2 = Self.createIPv4Packet(src: "10.0.0.2", srcPort: 1002, dst: "8.8.8.8", dstPort: 443)!
        await gw.forwardToInternet(p1, from: "m1")
        await gw.forwardToInternet(p2, from: "m2")

        let r1 = Self.createIPv4Packet(src: "8.8.8.8", srcPort: 443, dst: "10.0.0.1", dstPort: 1001)!
        let r2 = Self.createIPv4Packet(src: "8.8.8.8", srcPort: 443, dst: "10.0.0.2", dstPort: 1002)!
        await stub.simulateOutbound(r1)
        await stub.simulateOutbound(r2)

        await fulfillment(of: [expectation], timeout: 2)
        let machines = await collector.machineIds
        XCTAssertTrue(machines.contains("m1"))
        XCTAssertTrue(machines.contains("m2"))
    }

    func testNATEntryExpiry() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub, natTimeout: 0.01)
        try await gw.start()

        let packet = Self.createIPv4Packet(src: "10.0.0.1", srcPort: 5000, dst: "1.1.1.1", dstPort: 80)!
        await gw.forwardToInternet(packet, from: "m1")
        let count1 = await gw.natEntryCount()
        XCTAssertEqual(count1, 1)

        try await Task.sleep(nanoseconds: 20_000_000)
        await gw.cleanupExpiredEntries()
        let count2 = await gw.natEntryCount()
        XCTAssertEqual(count2, 0)
    }

    func testUDPForwarding() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)

        let expectation = XCTestExpectation(description: "UDP return")
        let collector = ResultCollector()
        await gw.setReturnHandler { [collector] _, machineId in
            await collector.set(machineId: machineId)
            expectation.fulfill()
        }

        try await gw.start()

        let outbound = Self.createIPv4Packet(src: "10.0.0.1", srcPort: 5353, dst: "8.8.8.8", dstPort: 53, proto: 17)!
        await gw.forwardToInternet(outbound, from: "m1")

        let inbound = Self.createIPv4Packet(src: "8.8.8.8", srcPort: 53, dst: "10.0.0.1", dstPort: 5353, proto: 17)!
        await stub.simulateOutbound(inbound)

        await fulfillment(of: [expectation], timeout: 2)
        let machine = await collector.machineId
        XCTAssertEqual(machine, "m1")
    }

    func testUnknownReturnDropped() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)

        let collector = ResultCollector()
        await gw.setReturnHandler { [collector] _, machineId in
            await collector.set(machineId: machineId)
        }

        try await gw.start()

        let packet = Self.createIPv4Packet(src: "1.1.1.1", srcPort: 80, dst: "10.0.0.1", dstPort: 9999)!
        await stub.simulateOutbound(packet)

        try await Task.sleep(nanoseconds: 50_000_000)
        let machine = await collector.machineId
        XCTAssertNil(machine)
    }

    func testStartStop() async throws {
        let stub = StubNetstackBridge()
        let gw = GatewayService(bridge: stub)
        try await gw.start()
        await gw.stop()

        let packet = Self.createIPv4Packet(src: "10.0.0.1", srcPort: 1000, dst: "1.1.1.1", dstPort: 80)!
        await gw.forwardToInternet(packet, from: "m1")

        let injected = await stub.getInjectedPackets()
        XCTAssertEqual(injected.count, 0)
        let count = await gw.natEntryCount()
        XCTAssertEqual(count, 0)
    }
}

// MARK: - Sendable test helpers

private actor ResultCollector {
    var machineId: MachineId?
    func set(machineId: MachineId) { self.machineId = machineId }
}

private actor MultiResultCollector {
    var machineIds: [MachineId] = []
    func append(machineId: MachineId) { machineIds.append(machineId) }
}
