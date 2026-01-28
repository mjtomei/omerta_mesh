// VirtualNetworkTests.swift - Tests for VirtualNetwork routing and address mapping

import XCTest
@testable import OmertaNetwork
@testable import OmertaMesh

final class VirtualNetworkTests: XCTestCase {

    func testRouteToLocalAddress() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.5")

        let decision = await vnet.route(destinationIP: "10.0.0.5")
        XCTAssertEqual(decision, .local)
    }

    func testRouteToPeer() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.5")
        await vnet.registerAddress(ip: "10.0.0.10", machineId: "peer-m")

        let decision = await vnet.route(destinationIP: "10.0.0.10")
        XCTAssertEqual(decision, .peer("peer-m"))
    }

    func testRouteToGateway() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.5")
        await vnet.setGateway(machineId: "gateway-m", ip: "10.0.0.1")

        // External IP should route to gateway
        let decision = await vnet.route(destinationIP: "8.8.8.8")
        XCTAssertEqual(decision, .gateway)
    }

    func testRouteUnknownInSubnet() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.5")

        // Unknown IP in mesh range, no gateway
        let decision = await vnet.route(destinationIP: "10.0.0.99")
        if case .drop(let reason) = decision {
            XCTAssertTrue(reason.contains("Unknown"))
        } else {
            XCTFail("Expected .drop, got \(decision)")
        }
    }

    func testRouteNoGateway() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.5")

        // External IP with no gateway
        let decision = await vnet.route(destinationIP: "8.8.8.8")
        if case .drop(let reason) = decision {
            XCTAssertTrue(reason.contains("no gateway"))
        } else {
            XCTFail("Expected .drop, got \(decision)")
        }
    }

    func testAddressLookup() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.registerAddress(ip: "10.0.0.50", machineId: "m50")

        let machine = await vnet.lookupMachine(ip: "10.0.0.50")
        XCTAssertEqual(machine, "m50")

        let ip = await vnet.lookupIP(machineId: "m50")
        XCTAssertEqual(ip, "10.0.0.50")
    }

    func testAddressLookupUnknown() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")

        let m = await vnet.lookupMachine(ip: "10.0.0.99")
        XCTAssertNil(m)
        let ip = await vnet.lookupIP(machineId: "unknown")
        XCTAssertNil(ip)
    }

    func testRemoveAddress() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.registerAddress(ip: "10.0.0.50", machineId: "m50")

        await vnet.removeAddress(machineId: "m50")

        let m = await vnet.lookupMachine(ip: "10.0.0.50")
        XCTAssertNil(m)
        let ip = await vnet.lookupIP(machineId: "m50")
        XCTAssertNil(ip)
    }

    func testSetLocalAddressRegistersInMaps() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.5")

        let machine = await vnet.lookupMachine(ip: "10.0.0.5")
        XCTAssertEqual(machine, "local-m")

        let ip = await vnet.lookupIP(machineId: "local-m")
        XCTAssertEqual(ip, "10.0.0.5")

        let localIP = await vnet.getLocalIP()
        XCTAssertEqual(localIP, "10.0.0.5")
    }

    func testSetGatewayRegistersAddress() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setGateway(machineId: "gw", ip: "10.0.0.1")

        let machine = await vnet.lookupMachine(ip: "10.0.0.1")
        XCTAssertEqual(machine, "gw")
    }

    func testGatewayRoutedAsPeer() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.5")
        await vnet.setGateway(machineId: "gw", ip: "10.0.0.1")

        // Gateway IP itself should route as peer
        let decision = await vnet.route(destinationIP: "10.0.0.1")
        XCTAssertEqual(decision, .peer("gw"))
    }

    func testMultiplePeers() async throws {
        let vnet = VirtualNetwork(localMachineId: "local-m")
        await vnet.setLocalAddress("10.0.0.1")
        await vnet.registerAddress(ip: "10.0.0.2", machineId: "m2")
        await vnet.registerAddress(ip: "10.0.0.3", machineId: "m3")
        await vnet.registerAddress(ip: "10.0.0.4", machineId: "m4")

        let d1 = await vnet.route(destinationIP: "10.0.0.1")
        let d2 = await vnet.route(destinationIP: "10.0.0.2")
        let d3 = await vnet.route(destinationIP: "10.0.0.3")
        let d4 = await vnet.route(destinationIP: "10.0.0.4")
        XCTAssertEqual(d1, .local)
        XCTAssertEqual(d2, .peer("m2"))
        XCTAssertEqual(d3, .peer("m3"))
        XCTAssertEqual(d4, .peer("m4"))

        let count = await vnet.addressCount()
        XCTAssertEqual(count, 4)
    }

    func testSubnetCheck() async throws {
        // Custom config with 10.0.0.0/16
        let config = VirtualNetworkConfig(subnet: "10.0.0.0", netmask: "255.255.0.0")
        let vnet = VirtualNetwork(localMachineId: "local-m", config: config)
        await vnet.setLocalAddress("10.0.0.5")

        // 10.0.x.x is in subnet - should drop (unknown)
        let d1 = await vnet.route(destinationIP: "10.0.1.50")
        if case .drop = d1 {} else { XCTFail("Expected .drop for 10.0.1.50") }

        // 10.1.0.1 is NOT in 10.0.0.0/16 - should drop with "no gateway"
        let d2 = await vnet.route(destinationIP: "10.1.0.1")
        if case .drop(let reason) = d2 {
            XCTAssertTrue(reason.contains("no gateway"))
        } else {
            XCTFail("Expected .drop for 10.1.0.1")
        }
    }

    func testRouteDecisionEquality() {
        XCTAssertEqual(RouteDecision.local, RouteDecision.local)
        XCTAssertEqual(RouteDecision.gateway, RouteDecision.gateway)
        XCTAssertEqual(RouteDecision.peer("m1"), RouteDecision.peer("m1"))
        XCTAssertNotEqual(RouteDecision.peer("m1"), RouteDecision.peer("m2"))
        XCTAssertEqual(RouteDecision.drop("reason"), RouteDecision.drop("reason"))
        XCTAssertNotEqual(RouteDecision.local, RouteDecision.gateway)
    }

    func testVirtualNetworkConfigDefaults() {
        let config = VirtualNetworkConfig.default
        XCTAssertEqual(config.subnet, "10.0.0.0")
        XCTAssertEqual(config.netmask, "255.255.0.0")
        XCTAssertEqual(config.gatewayIP, "10.0.0.1")
    }
}
