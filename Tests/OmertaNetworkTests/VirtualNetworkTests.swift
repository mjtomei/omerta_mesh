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
        XCTAssertEqual(config.prefixLength, 16)
        XCTAssertEqual(config.gatewayIP, "10.0.0.1")
        XCTAssertEqual(config.poolStart, "10.0.0.100")
        XCTAssertEqual(config.poolEnd, "10.0.255.254")
    }

    func testDynamicSubnetRouting() async throws {
        // Verify routing works with a dynamically generated subnet
        let generated = GeneratedSubnet(
            subnet: "10.42.0.0", prefixLength: 16, netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1", poolStart: "10.42.0.100", poolEnd: "10.42.255.254"
        )
        let config = VirtualNetworkConfig(generated: generated)
        let vnet = VirtualNetwork(localMachineId: "local-m", config: config)
        await vnet.setLocalAddress("10.42.0.5")
        await vnet.registerAddress(ip: "10.42.0.10", machineId: "peer-m")

        let decision = await vnet.route(destinationIP: "10.42.0.10")
        XCTAssertEqual(decision, .peer("peer-m"))

        // 10.0.x should NOT be in our subnet
        let outside = await vnet.route(destinationIP: "10.0.0.5")
        if case .drop(let reason) = outside {
            XCTAssertTrue(reason.contains("no gateway"))
        } else {
            XCTFail("Expected .drop for address outside subnet")
        }
    }
}

// MARK: - SubnetSelector Tests

final class SubnetSelectorTests: XCTestCase {

    func testGeneratedSubnetAvoidsLocalLAN() throws {
        // Mock: host has 10.0.0.0/16 on its LAN
        let locals = [SubnetSelector.SubnetInfo(
            address: "10.0.1.50", prefixLength: 16,
            networkAddress: 0x0A000000 // 10.0.0.0
        )]
        let generated = try SubnetSelector.generateSubnet(avoiding: locals)
        // Should NOT be 10.0.x.x
        XCTAssertFalse(generated.subnet.hasPrefix("10.0."))
        XCTAssertEqual(generated.prefixLength, 16)
    }

    func testGeneratedSubnetNoConflicts() throws {
        // No local subnets — should still generate a valid /16
        let generated = try SubnetSelector.generateSubnet(avoiding: [])
        XCTAssertEqual(generated.prefixLength, 16)
        XCTAssertTrue(generated.gatewayIP.hasSuffix(".1"))
    }

    func testConflictDetection() {
        let locals = [SubnetSelector.SubnetInfo(
            address: "10.42.1.1", prefixLength: 16,
            networkAddress: 0x0A2A0000 // 10.42.0.0
        )]
        // 10.42.0.0/16 should conflict
        XCTAssertTrue(SubnetSelector.conflicts(
            subnet: 0x0A2A0000, prefixLength: 16, with: locals))
        // 10.99.0.0/16 should not
        XCTAssertFalse(SubnetSelector.conflicts(
            subnet: 0x0A630000, prefixLength: 16, with: locals))
    }

    func testFallsBackTo172Range() throws {
        // Mock: all 256 10.x.0.0/16 blocks are in use (extreme case)
        let locals = (0..<256).map { i in
            SubnetSelector.SubnetInfo(
                address: "10.\(i).0.1", prefixLength: 16,
                networkAddress: UInt32(0x0A000000 + (i << 16))
            )
        }
        let generated = try SubnetSelector.generateSubnet(avoiding: locals)
        // Should fall back to 172.16-31.x range
        XCTAssertTrue(generated.subnet.hasPrefix("172."))
    }

    func testNoAvailableSubnetThrows() {
        // All 10.x and 172.16-31.x are taken
        var locals = (0..<256).map { i in
            SubnetSelector.SubnetInfo(
                address: "10.\(i).0.1", prefixLength: 16,
                networkAddress: UInt32(0x0A000000 + (i << 16))
            )
        }
        locals += (16..<32).map { i in
            SubnetSelector.SubnetInfo(
                address: "172.\(i).0.1", prefixLength: 16,
                networkAddress: UInt32(0xAC000000 + (i << 16))
            )
        }

        XCTAssertThrowsError(try SubnetSelector.generateSubnet(avoiding: locals)) { error in
            XCTAssertTrue(error is SubnetSelectorError)
        }
    }

    func testDetectLocalSubnets() {
        // Just verify it doesn't crash and returns something
        let locals = SubnetSelector.detectLocalSubnets()
        // Should have at least one interface (loopback)
        XCTAssertGreaterThan(locals.count, 0)
    }

    func testParseIPv4() {
        XCTAssertEqual(SubnetSelector.parseIPv4("10.0.0.1"), 0x0A000001)
        XCTAssertEqual(SubnetSelector.parseIPv4("192.168.1.1"), 0xC0A80101)
        XCTAssertEqual(SubnetSelector.parseIPv4("255.255.255.255"), 0xFFFFFFFF)
        XCTAssertEqual(SubnetSelector.parseIPv4("0.0.0.0"), 0x00000000)
        XCTAssertNil(SubnetSelector.parseIPv4("invalid"))
        XCTAssertNil(SubnetSelector.parseIPv4("10.0.0"))
    }

    func testCidrsOverlap() {
        // Same network
        XCTAssertTrue(SubnetSelector.cidrsOverlap(
            net1: 0x0A000000, prefix1: 16,
            net2: 0x0A000000, prefix2: 16))

        // Different networks, same prefix
        XCTAssertFalse(SubnetSelector.cidrsOverlap(
            net1: 0x0A000000, prefix1: 16,
            net2: 0x0A010000, prefix2: 16))

        // Overlapping (one contains the other)
        XCTAssertTrue(SubnetSelector.cidrsOverlap(
            net1: 0x0A000000, prefix1: 8,   // 10.0.0.0/8
            net2: 0x0A2A0000, prefix2: 16)) // 10.42.0.0/16

        // Non-overlapping different sizes
        XCTAssertFalse(SubnetSelector.cidrsOverlap(
            net1: 0x0A000000, prefix1: 16,  // 10.0.0.0/16
            net2: 0xAC100000, prefix2: 16)) // 172.16.0.0/16
    }

    func testGeneratedSubnetStructure() throws {
        let generated = try SubnetSelector.generateSubnet(avoiding: [])

        XCTAssertEqual(generated.prefixLength, 16)
        XCTAssertEqual(generated.netmask, "255.255.0.0")
        XCTAssertTrue(generated.gatewayIP.hasSuffix(".0.1"))
        XCTAssertTrue(generated.poolStart.hasSuffix(".0.100"))
        XCTAssertTrue(generated.poolEnd.hasSuffix(".255.254"))
    }

    func testConfigFromGenerated() throws {
        let generated = GeneratedSubnet(
            subnet: "10.99.0.0", prefixLength: 16, netmask: "255.255.0.0",
            gatewayIP: "10.99.0.1", poolStart: "10.99.0.100", poolEnd: "10.99.255.254"
        )
        let config = VirtualNetworkConfig(generated: generated)

        XCTAssertEqual(config.subnet, "10.99.0.0")
        XCTAssertEqual(config.prefixLength, 16)
        XCTAssertEqual(config.netmask, "255.255.0.0")
        XCTAssertEqual(config.gatewayIP, "10.99.0.1")
        XCTAssertEqual(config.poolStart, "10.99.0.100")
        XCTAssertEqual(config.poolEnd, "10.99.255.254")
    }
}
