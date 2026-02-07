// DHCPIntegrationTests.swift - Integration tests for packet-based DHCP
//
// Tests the full DHCP flow using DHCPService and DHCPClient together
// as pure packet processors (no ChannelProvider, no mesh).

import XCTest
@testable import OmertaNetwork

// MARK: - DHCP Integration Tests

final class DHCPIntegrationTests: XCTestCase {

    let serviceConfig = DHCPServiceConfig(
        netmask: "255.255.0.0",
        gatewayIP: "10.0.0.1",
        poolStart: "10.0.0.100",
        poolEnd: "10.0.0.200",
        leaseTime: 3600,
        dnsServers: ["8.8.8.8"]
    )

    /// Run a complete DORA (Discover→Offer→Request→Ack) flow between client and service
    private func runDORA(client: DHCPClient, service: DHCPService) async throws -> DHCPClientAction {
        // 1. Client builds DISCOVER
        let discoverData = client.buildDiscover()
        XCTAssertEqual(client.state, .discovering)

        // 2. Service processes DISCOVER → returns OFFER
        let offerData = await service.handlePacket(discoverData)
        XCTAssertNotNil(offerData, "Service should respond to DISCOVER with OFFER")

        // 3. Client processes OFFER → returns sendPacket(REQUEST)
        let offerAction = client.handlePacket(offerData!)
        XCTAssertEqual(client.state, .requesting)

        guard case .sendPacket(let requestData) = offerAction else {
            XCTFail("Expected sendPacket action from OFFER handling")
            throw DHCPError.invalidPacket("Unexpected action")
        }

        // 4. Service processes REQUEST → returns ACK
        let ackData = await service.handlePacket(requestData)
        XCTAssertNotNil(ackData, "Service should respond to REQUEST with ACK")

        // 5. Client processes ACK → returns configured
        let ackAction = client.handlePacket(ackData!)
        XCTAssertNotNil(ackAction)
        return ackAction!
    }

    // MARK: - Basic Flow

    func testSingleClientDORA() async throws {
        let service = DHCPService(config: serviceConfig)
        let client = DHCPClient(machineId: "m1", hostname: "peer1")

        let action = try await runDORA(client: client, service: service)

        XCTAssertEqual(client.state, .bound)

        if case .configured(let ip, let netmask, let gateway, let dns, let leaseTime) = action {
            XCTAssertTrue(ip.hasPrefix("10.0.0."))
            XCTAssertEqual(netmask, "255.255.0.0")
            XCTAssertEqual(gateway, "10.0.0.1")
            XCTAssertEqual(dns, ["8.8.8.8"])
            XCTAssertEqual(leaseTime, 3600)
        } else {
            XCTFail("Expected configured action, got \(action)")
        }

        // Verify lease was recorded
        let leases = await service.getActiveLeases()
        XCTAssertEqual(leases.count, 1)
    }

    func testMultipleClientsGetUniqueIPs() async throws {
        let service = DHCPService(config: serviceConfig)
        var assignedIPs: Set<String> = []

        for i in 1...5 {
            let client = DHCPClient(machineId: "m\(i)", hostname: "host\(i)")
            let action = try await runDORA(client: client, service: service)

            if case .configured(let ip, _, _, _, _) = action {
                assignedIPs.insert(ip)
            }
        }

        // All IPs should be unique
        XCTAssertEqual(assignedIPs.count, 5)

        // All in valid range
        for ip in assignedIPs {
            XCTAssertTrue(ip.hasPrefix("10.0.0."))
        }

        // Service tracks all leases
        let leases = await service.getActiveLeases()
        XCTAssertEqual(leases.count, 5)
    }

    // MARK: - Lease Lifecycle

    func testRenewalPreservesIP() async throws {
        let service = DHCPService(config: serviceConfig)
        let client = DHCPClient(machineId: "m1")

        // Initial DORA
        let action = try await runDORA(client: client, service: service)
        guard case .configured(let ip, _, _, _, _) = action else {
            XCTFail("Expected configured")
            return
        }

        // Renew
        let renewData = client.buildRenew()
        XCTAssertNotNil(renewData)
        XCTAssertEqual(client.state, .renewing)

        let renewAckData = await service.handlePacket(renewData!)
        XCTAssertNotNil(renewAckData)

        let renewAction = client.handlePacket(renewAckData!)
        XCTAssertEqual(client.state, .bound)

        if case .configured(let renewedIP, _, _, _, _) = renewAction {
            XCTAssertEqual(renewedIP, ip, "Renewal should preserve IP")
        } else {
            XCTFail("Expected configured action from renewal")
        }
    }

    func testReleaseReturnsIPToPool() async throws {
        let service = DHCPService(config: serviceConfig)
        let client = DHCPClient(machineId: "m1")

        let initialCount = await service.availableIPCount()

        // Get IP
        _ = try await runDORA(client: client, service: service)
        let afterAlloc = await service.availableIPCount()
        XCTAssertEqual(afterAlloc, initialCount - 1)

        // Release
        let releaseData = client.buildRelease()
        XCTAssertNotNil(releaseData)
        _ = await service.handlePacket(releaseData!)

        let afterRelease = await service.availableIPCount()
        XCTAssertEqual(afterRelease, initialCount)
        XCTAssertEqual(client.state, .initial)
    }

    func testReleaseAndReacquire() async throws {
        let service = DHCPService(config: serviceConfig)
        let client = DHCPClient(machineId: "m1")

        // First allocation
        let action1 = try await runDORA(client: client, service: service)
        guard case .configured(_, _, _, _, _) = action1 else {
            XCTFail("Expected configured")
            return
        }

        // Release
        let releaseData = client.buildRelease()!
        _ = await service.handlePacket(releaseData)

        // Re-acquire
        let action2 = try await runDORA(client: client, service: service)
        guard case .configured(let ip2, _, _, _, _) = action2 else {
            XCTFail("Expected configured")
            return
        }

        // IP may or may not be the same (depends on pool ordering)
        XCTAssertNotNil(ip2)
    }

    // MARK: - Returning Client

    func testReturningClientGetsSameIP() async throws {
        let service = DHCPService(config: serviceConfig)

        // First client session
        let client1 = DHCPClient(machineId: "m1")
        let action1 = try await runDORA(client: client1, service: service)
        guard case .configured(let firstIP, _, _, _, _) = action1 else {
            XCTFail("Expected configured")
            return
        }

        // "Reconnect" with new client instance but same machineId
        let client2 = DHCPClient(machineId: "m1")
        let action2 = try await runDORA(client: client2, service: service)
        guard case .configured(let secondIP, _, _, _, _) = action2 else {
            XCTFail("Expected configured")
            return
        }

        // Should get same IP (existing lease returned)
        XCTAssertEqual(firstIP, secondIP)
    }

    // MARK: - NAK Handling

    func testClientHandlesNAK() async throws {
        let service = DHCPService(config: serviceConfig)
        let client = DHCPClient(machineId: "m1")

        // Get through DISCOVER → OFFER
        let discoverData = client.buildDiscover()
        let offerData = await service.handlePacket(discoverData)!
        let offerAction = client.handlePacket(offerData)!
        guard case .sendPacket(_) = offerAction else {
            XCTFail("Expected sendPacket")
            return
        }
        XCTAssertEqual(client.state, .requesting)

        // Send NAK instead of ACK
        let chaddr = DHCPPacket.machineIdToChaddr("m1")
        let nak = DHCPPacket.buildNAK(
            xid: client.xid,
            clientChaddr: chaddr,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!
        )
        let action = client.handlePacket(nak)

        XCTAssertEqual(client.state, .initial)
        if case .restart = action {
            // Expected
        } else {
            XCTFail("Expected restart action")
        }
    }

    // MARK: - Pool Exhaustion

    func testPoolExhaustionAndRecovery() async throws {
        let tinyConfig = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.102",  // Only 3 IPs
            leaseTime: 3600
        )
        let service = DHCPService(config: tinyConfig)

        // Exhaust pool
        var clients: [DHCPClient] = []
        for i in 1...3 {
            let client = DHCPClient(machineId: "m\(i)")
            _ = try await runDORA(client: client, service: service)
            clients.append(client)
        }

        // 4th client: DISCOVER gets no OFFER
        let client4 = DHCPClient(machineId: "m4")
        let discoverData = client4.buildDiscover()
        let response = await service.handlePacket(discoverData)
        XCTAssertNil(response)

        // Release one IP
        let releaseData = clients[1].buildRelease()!
        _ = await service.handlePacket(releaseData)

        // Now 4th client can get an IP
        let action = try await runDORA(client: client4, service: service)
        if case .configured(let ip, _, _, _, _) = action {
            XCTAssertNotNil(ip)
        } else {
            XCTFail("Expected configured")
        }
    }

    // MARK: - DNS Servers

    func testDNSServersPassedToClients() async throws {
        let configWithDNS = DHCPServiceConfig(
            netmask: "255.255.0.0",
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600,
            dnsServers: ["8.8.8.8", "1.1.1.1"]
        )
        let service = DHCPService(config: configWithDNS)
        let client = DHCPClient(machineId: "m1")

        let action = try await runDORA(client: client, service: service)

        if case .configured(_, _, _, let dns, _) = action {
            XCTAssertEqual(dns, ["8.8.8.8", "1.1.1.1"])
        } else {
            XCTFail("Expected configured")
        }
    }

    // MARK: - Rebinding

    func testRebindFlow() async throws {
        let service = DHCPService(config: serviceConfig)
        let client = DHCPClient(machineId: "m1")

        // Initial DORA
        let action = try await runDORA(client: client, service: service)
        guard case .configured(let ip, _, _, _, _) = action else {
            XCTFail("Expected configured")
            return
        }

        // Transition through renewing to rebinding
        _ = client.buildRenew()
        XCTAssertEqual(client.state, .renewing)

        let rebindData = client.buildRebind()
        XCTAssertNotNil(rebindData)
        XCTAssertEqual(client.state, .rebinding)

        // Service processes rebind REQUEST
        let ackData = await service.handlePacket(rebindData!)
        XCTAssertNotNil(ackData)

        let ackAction = client.handlePacket(ackData!)
        XCTAssertEqual(client.state, .bound)

        if case .configured(let renewedIP, _, _, _, _) = ackAction {
            XCTAssertEqual(renewedIP, ip)
        } else {
            XCTFail("Expected configured")
        }
    }
}
