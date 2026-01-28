// NetworkInterfaceTests.swift - Tests for NetworkInterface abstraction

import XCTest
@testable import OmertaNetwork

final class MockNetworkInterfaceTests: XCTestCase {

    func testMockInterfaceCreation() async {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        let ip = await interface.localIP
        XCTAssertEqual(ip, "10.0.0.5")
    }

    func testMockInterfaceStartStop() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")

        // Should throw before start
        do {
            _ = try await interface.readPacket()
            XCTFail("Should throw when not started")
        } catch InterfaceError.notStarted {
            // Expected
        }

        try await interface.start()

        // Should throw if started twice
        do {
            try await interface.start()
            XCTFail("Should throw when already started")
        } catch InterfaceError.alreadyStarted {
            // Expected
        }

        await interface.stop()
    }

    func testMockInterfaceRoundtrip() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        try await interface.start()

        // Simulate app sending
        let packet = Data("test packet".utf8)
        await interface.simulateAppSend(packet)

        // Should be readable
        let read = try await interface.readPacket()
        XCTAssertEqual(read, packet)

        await interface.stop()
    }

    func testMockInterfaceReceive() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        try await interface.start()

        // Write packet (as if from network)
        let packet = Data("incoming".utf8)
        try await interface.writePacket(packet)

        // App should receive it
        let received = await interface.getAppReceived()
        XCTAssertEqual(received, packet)

        await interface.stop()
    }

    func testMockInterfaceMultiplePackets() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        try await interface.start()

        // Send multiple packets
        await interface.simulateAppSend(Data("packet1".utf8))
        await interface.simulateAppSend(Data("packet2".utf8))
        await interface.simulateAppSend(Data("packet3".utf8))

        // Should receive in order
        let p1 = try await interface.readPacket()
        let p2 = try await interface.readPacket()
        let p3 = try await interface.readPacket()

        XCTAssertEqual(p1, Data("packet1".utf8))
        XCTAssertEqual(p2, Data("packet2".utf8))
        XCTAssertEqual(p3, Data("packet3".utf8))

        await interface.stop()
    }

    func testMockInterfaceGetAllReceived() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        try await interface.start()

        try await interface.writePacket(Data("p1".utf8))
        try await interface.writePacket(Data("p2".utf8))

        let all = await interface.getAllAppReceived()
        XCTAssertEqual(all.count, 2)
        XCTAssertEqual(all[0], Data("p1".utf8))
        XCTAssertEqual(all[1], Data("p2".utf8))

        // Should be empty now
        let empty = await interface.getAllAppReceived()
        XCTAssertTrue(empty.isEmpty)

        await interface.stop()
    }

    func testMockInterfaceDialTCP() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        try await interface.start()

        let conn = try await interface.dialTCP(host: "10.0.0.10", port: 22)
        XCTAssertNotNil(conn)

        let dialed = await interface.getDialedConnections()
        XCTAssertEqual(dialed.count, 1)
        XCTAssertEqual(dialed[0].host, "10.0.0.10")
        XCTAssertEqual(dialed[0].port, 22)

        await interface.stop()
    }

    func testMockInterfaceReset() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        try await interface.start()

        await interface.simulateAppSend(Data("outbound".utf8))
        try await interface.writePacket(Data("inbound".utf8))
        _ = try await interface.dialTCP(host: "10.0.0.10", port: 80)

        await interface.reset()

        let outbound = await interface.pendingOutboundCount()
        let inbound = await interface.receivedInboundCount()
        let conns = await interface.getDialedConnections()

        XCTAssertEqual(outbound, 0)
        XCTAssertEqual(inbound, 0)
        XCTAssertTrue(conns.isEmpty)

        await interface.stop()
    }

    func testMockInterfaceAsyncRead() async throws {
        let interface = MockNetworkInterface(localIP: "10.0.0.5")
        try await interface.start()

        // Start reading before packet is available
        let readTask = Task {
            try await interface.readPacket()
        }

        // Small delay then send packet
        try await Task.sleep(for: .milliseconds(20))
        await interface.simulateAppSend(Data("delayed".utf8))

        let packet = try await readTask.value
        XCTAssertEqual(packet, Data("delayed".utf8))

        await interface.stop()
    }
}

final class MockTCPConnectionTests: XCTestCase {

    func testConnectionCreation() async {
        let conn = MockTCPConnection(host: "10.0.0.10", port: 443)
        let host = await conn.remoteHost
        let port = await conn.remotePort

        XCTAssertEqual(host, "10.0.0.10")
        XCTAssertEqual(port, 443)
    }

    func testConnectionReadWrite() async throws {
        let conn = MockTCPConnection(host: "10.0.0.10", port: 22)

        // Write some data
        try await conn.write(Data("hello".utf8))
        try await conn.write(Data("world".utf8))

        let written = await conn.getWrittenData()
        XCTAssertEqual(written.count, 2)
        XCTAssertEqual(written[0], Data("hello".utf8))
        XCTAssertEqual(written[1], Data("world".utf8))
    }

    func testConnectionRead() async throws {
        let conn = MockTCPConnection(host: "10.0.0.10", port: 22)

        // Simulate incoming data
        await conn.simulateIncoming(Data("response".utf8))

        let data = try await conn.read()
        XCTAssertEqual(data, Data("response".utf8))
    }

    func testConnectionClose() async throws {
        let conn = MockTCPConnection(host: "10.0.0.10", port: 22)

        await conn.close()

        // Should throw after close
        do {
            try await conn.write(Data("test".utf8))
            XCTFail("Should throw when closed")
        } catch InterfaceError.closed {
            // Expected
        }
    }
}

final class NetworkInterfaceConfigTests: XCTestCase {

    func testConfigDefaults() {
        let config = NetworkInterfaceConfig(localIP: "10.0.0.5")

        XCTAssertEqual(config.localIP, "10.0.0.5")
        XCTAssertEqual(config.netmask, "255.255.0.0")
        XCTAssertEqual(config.mtu, 1400)
        XCTAssertEqual(config.interfaceName, "omerta0")
    }

    func testConfigCustomValues() {
        let config = NetworkInterfaceConfig(
            localIP: "10.42.0.100",
            netmask: "255.255.255.0",
            mtu: 1500,
            interfaceName: "tun0"
        )

        XCTAssertEqual(config.localIP, "10.42.0.100")
        XCTAssertEqual(config.netmask, "255.255.255.0")
        XCTAssertEqual(config.mtu, 1500)
        XCTAssertEqual(config.interfaceName, "tun0")
    }
}

final class NetstackInterfaceTests: XCTestCase {

    func testNetstackWithStubBridge() async throws {
        let bridge = StubNetstackBridge()
        let interface = NetstackInterface(localIP: "10.0.0.5", bridge: bridge)

        let ip = await interface.localIP
        XCTAssertEqual(ip, "10.0.0.5")

        try await interface.start()

        // Write a packet
        try await interface.writePacket(Data("test".utf8))

        // Verify it was injected into bridge
        let injected = await bridge.getInjectedPackets()
        XCTAssertEqual(injected.count, 1)
        XCTAssertEqual(injected[0], Data("test".utf8))

        await interface.stop()
    }

    func testNetstackOutboundPackets() async throws {
        let bridge = StubNetstackBridge()
        let interface = NetstackInterface(localIP: "10.0.0.5", bridge: bridge)
        try await interface.start()

        // Start reading
        let readTask = Task {
            try await interface.readPacket()
        }

        // Simulate bridge sending an outbound packet
        try await Task.sleep(for: .milliseconds(20))
        await bridge.simulateOutbound(Data("outbound".utf8))

        let packet = try await readTask.value
        XCTAssertEqual(packet, Data("outbound".utf8))

        await interface.stop()
    }

    func testNetstackDialTCPNotSupported() async throws {
        let bridge = StubNetstackBridge()
        let interface = NetstackInterface(localIP: "10.0.0.5", bridge: bridge)
        try await interface.start()

        // Stub bridge doesn't support dialTCP
        do {
            _ = try await interface.dialTCP(host: "10.0.0.10", port: 22)
            XCTFail("Should throw notSupported")
        } catch InterfaceError.notSupported {
            // Expected for stub
        }

        await interface.stop()
    }

    func testNetstackNotStarted() async throws {
        let bridge = StubNetstackBridge()
        let interface = NetstackInterface(localIP: "10.0.0.5", bridge: bridge)

        // Should throw when not started
        do {
            _ = try await interface.readPacket()
            XCTFail("Should throw notStarted")
        } catch InterfaceError.notStarted {
            // Expected
        }
    }
}

final class StubNetstackBridgeTests: XCTestCase {

    func testStubBridgeStartStop() async throws {
        let bridge = StubNetstackBridge()
        try await bridge.start()
        await bridge.stop()
    }

    func testStubBridgeInjectPacket() async throws {
        let bridge = StubNetstackBridge()
        try await bridge.start()

        try await bridge.injectPacket(Data("p1".utf8))
        try await bridge.injectPacket(Data("p2".utf8))

        let packets = await bridge.getInjectedPackets()
        XCTAssertEqual(packets.count, 2)

        await bridge.stop()
    }

    func testStubBridgeReturnCallback() async throws {
        let bridge = StubNetstackBridge()

        var received: Data?
        await bridge.setReturnCallback { packet in
            received = packet
        }

        try await bridge.start()
        await bridge.simulateOutbound(Data("callback".utf8))

        XCTAssertEqual(received, Data("callback".utf8))

        await bridge.stop()
    }
}

final class TwoInterfacesConnectedTests: XCTestCase {

    func testTwoMockInterfacesConnected() async throws {
        let if1 = MockNetworkInterface(localIP: "10.0.0.1")
        let if2 = MockNetworkInterface(localIP: "10.0.0.2")

        try await if1.start()
        try await if2.start()

        // Wire them together: if1 outbound -> if2 inbound
        let relayTask = Task {
            while true {
                do {
                    let packet = try await if1.readPacket()
                    try await if2.writePacket(packet)
                } catch {
                    break
                }
            }
        }

        // if1 sends, if2 receives
        await if1.simulateAppSend(Data("hello".utf8))
        try await Task.sleep(for: .milliseconds(50))

        let received = await if2.getAppReceived()
        XCTAssertEqual(received, Data("hello".utf8))

        relayTask.cancel()
        await if1.stop()
        await if2.stop()
    }

    func testBidirectionalRelay() async throws {
        let if1 = MockNetworkInterface(localIP: "10.0.0.1")
        let if2 = MockNetworkInterface(localIP: "10.0.0.2")

        try await if1.start()
        try await if2.start()

        // Wire bidirectionally
        let relay1to2 = Task {
            while true {
                do {
                    let packet = try await if1.readPacket()
                    try await if2.writePacket(packet)
                } catch { break }
            }
        }

        let relay2to1 = Task {
            while true {
                do {
                    let packet = try await if2.readPacket()
                    try await if1.writePacket(packet)
                } catch { break }
            }
        }

        // Send both directions
        await if1.simulateAppSend(Data("from1".utf8))
        await if2.simulateAppSend(Data("from2".utf8))

        try await Task.sleep(for: .milliseconds(50))

        let at2 = await if2.getAppReceived()
        let at1 = await if1.getAppReceived()

        XCTAssertEqual(at2, Data("from1".utf8))
        XCTAssertEqual(at1, Data("from2".utf8))

        relay1to2.cancel()
        relay2to1.cancel()
        await if1.stop()
        await if2.stop()
    }
}
