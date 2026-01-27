// NetstackBridgeTests.swift - Tests for NetstackBridge
//
// Note: These tests require the Go netstack library to be built first.
// Run: cd Sources/OmertaTunnel/Netstack && make

import XCTest
@testable import OmertaTunnel

final class NetstackBridgeTests: XCTestCase {

    func testNetstackInit() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1")
        let bridge = try NetstackBridge(config: config)

        // Should not crash
        bridge.stop()
    }

    func testNetstackStartStop() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1")
        let bridge = try NetstackBridge(config: config)

        try bridge.start()

        // Get stats to verify it's running
        let stats = bridge.getStats()
        XCTAssertNotNil(stats)
        XCTAssertEqual(stats?.tcpConnections, 0)
        XCTAssertEqual(stats?.udpConnections, 0)

        bridge.stop()
    }

    func testInjectWithoutStart() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1")
        let bridge = try NetstackBridge(config: config)

        // Should fail because not started
        let packet = Data([0x45, 0x00, 0x00, 0x14]) // Minimal IPv4 header start
        XCTAssertThrowsError(try bridge.injectPacket(packet)) { error in
            XCTAssertEqual(error as? NetstackError, NetstackError.notStarted)
        }

        bridge.stop()
    }

    func testInjectEmptyPacket() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1")
        let bridge = try NetstackBridge(config: config)
        try bridge.start()

        // Empty packet should fail
        XCTAssertThrowsError(try bridge.injectPacket(Data())) { error in
            XCTAssertEqual(error as? NetstackError, NetstackError.invalidPacket)
        }

        bridge.stop()
    }

    func testReturnCallback() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1")
        let bridge = try NetstackBridge(config: config)

        let expectation = XCTestExpectation(description: "Return callback called")
        expectation.isInverted = true // We don't expect it to be called with invalid packets

        bridge.setReturnCallback { packet in
            expectation.fulfill()
        }

        try bridge.start()

        // Inject a malformed packet - should not trigger callback
        let badPacket = Data([0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00])
        try? bridge.injectPacket(badPacket)

        wait(for: [expectation], timeout: 0.5)

        bridge.stop()
    }

    func testMultipleStartStop() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1")
        let bridge = try NetstackBridge(config: config)

        // Start/stop multiple times should not crash
        try bridge.start()
        try bridge.start() // Should be idempotent
        bridge.stop()
        bridge.stop() // Should be idempotent
    }

    func testCustomMTU() throws {
        let config = NetstackBridge.Config(gatewayIP: "10.200.0.1", mtu: 9000)
        let bridge = try NetstackBridge(config: config)
        try bridge.start()

        let stats = bridge.getStats()
        XCTAssertNotNil(stats)

        bridge.stop()
    }
}
