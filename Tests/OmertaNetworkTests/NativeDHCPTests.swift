// NativeDHCPTests.swift - Tests for RFC 2131 packet-based DHCP service and client

import XCTest
@testable import OmertaNetwork

// MARK: - DHCPPacket Tests

final class DHCPPacketTests: XCTestCase {

    // MARK: - Parse/Build Round-Trip

    func testPacketRoundTrip() throws {
        var packet = DHCPPacket()
        packet.op = DHCPPacket.bootRequest
        packet.htype = DHCPPacket.htypeEthernet
        packet.hlen = DHCPPacket.hlenEthernet
        packet.xid = 0xDEADBEEF
        packet.flags = DHCPPacket.broadcastFlag
        packet.chaddr = DHCPPacket.machineIdToChaddr("test-machine")

        packet.setMessageType(.discover)
        packet.setHostname("testhost")
        packet.options[DHCPOptionTag.parameterList.rawValue] = [1, 3, 6, 51]

        let data = packet.toData()
        let parsed = try DHCPPacket.parse(data)

        XCTAssertEqual(parsed.op, DHCPPacket.bootRequest)
        XCTAssertEqual(parsed.htype, DHCPPacket.htypeEthernet)
        XCTAssertEqual(parsed.hlen, DHCPPacket.hlenEthernet)
        XCTAssertEqual(parsed.xid, 0xDEADBEEF)
        XCTAssertEqual(parsed.flags, DHCPPacket.broadcastFlag)
        XCTAssertEqual(parsed.messageType, .discover)
        XCTAssertEqual(parsed.hostname, "testhost")
        XCTAssertEqual(Array(parsed.chaddr.prefix(6)), Array(packet.chaddr.prefix(6)))
    }

    func testMinimumPacketSize() {
        let packet = DHCPPacket()
        let data = packet.toData()

        // RFC 2131: minimum 552 bytes (236 header + 4 cookie + 312 options)
        XCTAssertGreaterThanOrEqual(data.count, DHCPPacket.minimumPacketSize)
    }

    func testMagicCookie() throws {
        let packet = DHCPPacket()
        let data = packet.toData()
        let bytes = [UInt8](data)

        // Magic cookie at offset 236 (after header)
        XCTAssertEqual(bytes[236], 99)
        XCTAssertEqual(bytes[237], 130)
        XCTAssertEqual(bytes[238], 83)
        XCTAssertEqual(bytes[239], 99)
    }

    func testInvalidMagicCookieThrows() {
        var bytes = [UInt8](repeating: 0, count: 300)
        bytes[0] = 1  // op
        // Don't set magic cookie
        let data = Data(bytes)

        XCTAssertThrowsError(try DHCPPacket.parse(data)) { error in
            if case DHCPError.invalidPacket(let msg) = error {
                XCTAssertTrue(msg.contains("magic cookie"))
            } else {
                XCTFail("Expected invalidPacket error, got \(error)")
            }
        }
    }

    func testTooShortPacketThrows() {
        let data = Data([1, 2, 3])  // Way too short
        XCTAssertThrowsError(try DHCPPacket.parse(data))
    }

    // MARK: - IP Address Helpers

    func testParseAndFormatIP() {
        let ip = DHCPPacket.parseIP("10.42.0.1")
        XCTAssertNotNil(ip)
        XCTAssertEqual(ip, 0x0A2A0001)

        let formatted = DHCPPacket.formatIP(0x0A2A0001)
        XCTAssertEqual(formatted, "10.42.0.1")
    }

    func testParseIPBroadcast() {
        let ip = DHCPPacket.parseIP("255.255.255.255")
        XCTAssertEqual(ip, 0xFFFFFFFF)
    }

    func testParseInvalidIP() {
        XCTAssertNil(DHCPPacket.parseIP("not.an.ip"))
        XCTAssertNil(DHCPPacket.parseIP("10.0.0"))
        XCTAssertNil(DHCPPacket.parseIP(""))
    }

    // MARK: - Machine ID to chaddr

    func testMachineIdToChaddr() {
        let chaddr = DHCPPacket.machineIdToChaddr("test-machine")

        // Should be 16 bytes
        XCTAssertEqual(chaddr.count, 16)

        // Locally-administered bit set, multicast bit cleared
        XCTAssertTrue(chaddr[0] & 0x02 != 0, "Locally-administered bit should be set")
        XCTAssertTrue(chaddr[0] & 0x01 == 0, "Multicast bit should be cleared")

        // Last 10 bytes should be zero (padding)
        for i in 6..<16 {
            XCTAssertEqual(chaddr[i], 0)
        }

        // Deterministic: same input → same output
        let chaddr2 = DHCPPacket.machineIdToChaddr("test-machine")
        XCTAssertEqual(chaddr, chaddr2)

        // Different input → different output
        let chaddr3 = DHCPPacket.machineIdToChaddr("other-machine")
        XCTAssertNotEqual(Array(chaddr.prefix(6)), Array(chaddr3.prefix(6)))
    }

    // MARK: - Option Accessors

    func testOptionAccessors() {
        var packet = DHCPPacket()

        packet.setMessageType(.offer)
        XCTAssertEqual(packet.messageType, .offer)

        packet.setSubnetMask(0xFFFF0000)
        XCTAssertEqual(packet.subnetMask, 0xFFFF0000)

        packet.setRouter(0x0A2A0001)
        XCTAssertEqual(packet.router, 0x0A2A0001)

        packet.setLeaseTime(3600)
        XCTAssertEqual(packet.leaseTime, 3600)

        packet.setServerIdentifier(0x0A2A0001)
        XCTAssertEqual(packet.serverIdentifier, 0x0A2A0001)

        packet.setRequestedIP(0x0A2A0064)
        XCTAssertEqual(packet.requestedIP, 0x0A2A0064)

        packet.setDNSServers([0x08080808, 0x08080404])
        XCTAssertEqual(packet.dnsServers, [0x08080808, 0x08080404])

        packet.setHostname("testhost")
        XCTAssertEqual(packet.hostname, "testhost")
    }

    // MARK: - IPv4/UDP Wrapping

    func testIPv4UDPRoundTrip() throws {
        var dhcp = DHCPPacket()
        dhcp.op = DHCPPacket.bootRequest
        dhcp.xid = 0x12345678
        dhcp.setMessageType(.discover)

        let wrapped = dhcp.toIPv4UDP(
            srcIP: 0,
            dstIP: 0xFFFFFFFF,
            srcPort: DHCPPacket.clientPort,
            dstPort: DHCPPacket.serverPort
        )

        let (parsed, srcIP, dstIP) = try DHCPPacket.fromIPv4UDP(wrapped)

        XCTAssertEqual(srcIP, 0)
        XCTAssertEqual(dstIP, 0xFFFFFFFF)
        XCTAssertEqual(parsed.xid, 0x12345678)
        XCTAssertEqual(parsed.messageType, .discover)
    }

    // MARK: - Packet Builders

    func testBuildDiscover() throws {
        let packet = DHCPPacket.buildDiscover(
            machineId: "test-machine",
            xid: 0xAABBCCDD,
            hostname: "myhost"
        )

        let (dhcp, srcIP, dstIP) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootRequest)
        XCTAssertEqual(dhcp.xid, 0xAABBCCDD)
        XCTAssertEqual(dhcp.messageType, .discover)
        XCTAssertEqual(dhcp.hostname, "myhost")
        XCTAssertEqual(dhcp.flags, DHCPPacket.broadcastFlag)
        XCTAssertEqual(srcIP, 0)
        XCTAssertEqual(dstIP, 0xFFFFFFFF)
    }

    func testBuildOffer() throws {
        let chaddr = DHCPPacket.machineIdToChaddr("test-machine")
        let packet = DHCPPacket.buildOffer(
            xid: 0x11223344,
            clientChaddr: chaddr,
            offeredIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: DHCPPacket.parseIP("255.255.0.0")!,
            router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [DHCPPacket.parseIP("8.8.8.8")!],
            leaseTime: 3600
        )

        let (dhcp, _, _) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootReply)
        XCTAssertEqual(dhcp.messageType, .offer)
        XCTAssertEqual(dhcp.yiaddr, DHCPPacket.parseIP("10.0.0.100"))
        XCTAssertEqual(dhcp.leaseTime, 3600)
        XCTAssertEqual(dhcp.subnetMask, DHCPPacket.parseIP("255.255.0.0"))
        XCTAssertEqual(dhcp.router, DHCPPacket.parseIP("10.0.0.1"))
    }

    func testBuildRequestSelecting() throws {
        let packet = DHCPPacket.buildRequest(
            machineId: "test-machine",
            xid: 0x55667788,
            requestedIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!
        )

        let (dhcp, srcIP, dstIP) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootRequest)
        XCTAssertEqual(dhcp.messageType, .request)
        XCTAssertEqual(dhcp.ciaddr, 0)  // Must be 0 in SELECTING
        XCTAssertEqual(dhcp.requestedIP, DHCPPacket.parseIP("10.0.0.100"))
        XCTAssertEqual(dhcp.serverIdentifier, DHCPPacket.parseIP("10.0.0.1"))
        XCTAssertEqual(srcIP, 0)
        XCTAssertEqual(dstIP, 0xFFFFFFFF)  // Broadcast
    }

    func testBuildRenewRequest() throws {
        let clientIP = DHCPPacket.parseIP("10.0.0.100")!
        let serverIP = DHCPPacket.parseIP("10.0.0.1")!

        let packet = DHCPPacket.buildRenewRequest(
            machineId: "test-machine",
            xid: 0x99AABBCC,
            clientIP: clientIP,
            serverIP: serverIP
        )

        let (dhcp, srcIP, dstIP) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootRequest)
        XCTAssertEqual(dhcp.messageType, .request)
        XCTAssertEqual(dhcp.ciaddr, clientIP)  // Must be filled in RENEWING
        XCTAssertNil(dhcp.requestedIP)          // Must NOT be set in RENEWING
        XCTAssertNil(dhcp.serverIdentifier)     // Must NOT be set in RENEWING
        XCTAssertEqual(srcIP, clientIP)
        XCTAssertEqual(dstIP, serverIP)  // Unicast to server
    }

    func testBuildRebindRequest() throws {
        let clientIP = DHCPPacket.parseIP("10.0.0.100")!

        let packet = DHCPPacket.buildRebindRequest(
            machineId: "test-machine",
            xid: 0xDDEEFF00,
            clientIP: clientIP
        )

        let (dhcp, _, dstIP) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootRequest)
        XCTAssertEqual(dhcp.messageType, .request)
        XCTAssertEqual(dhcp.ciaddr, clientIP)
        XCTAssertNil(dhcp.requestedIP)
        XCTAssertNil(dhcp.serverIdentifier)
        XCTAssertEqual(dstIP, 0xFFFFFFFF)  // Broadcast
    }

    func testBuildACK() throws {
        let chaddr = DHCPPacket.machineIdToChaddr("test-machine")
        let packet = DHCPPacket.buildACK(
            xid: 0x11111111,
            clientChaddr: chaddr,
            assignedIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: DHCPPacket.parseIP("255.255.0.0")!,
            router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [],
            leaseTime: 7200
        )

        let (dhcp, _, _) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootReply)
        XCTAssertEqual(dhcp.messageType, .ack)
        XCTAssertEqual(dhcp.yiaddr, DHCPPacket.parseIP("10.0.0.100"))
        XCTAssertEqual(dhcp.leaseTime, 7200)
    }

    func testBuildNAK() throws {
        let chaddr = DHCPPacket.machineIdToChaddr("test-machine")
        let packet = DHCPPacket.buildNAK(
            xid: 0x22222222,
            clientChaddr: chaddr,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!
        )

        let (dhcp, _, dstIP) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootReply)
        XCTAssertEqual(dhcp.messageType, .nak)
        XCTAssertEqual(dstIP, 0xFFFFFFFF)  // Must be broadcast
    }

    func testBuildRelease() throws {
        let clientIP = DHCPPacket.parseIP("10.0.0.100")!
        let serverIP = DHCPPacket.parseIP("10.0.0.1")!

        let packet = DHCPPacket.buildRelease(
            machineId: "test-machine",
            xid: 0x33333333,
            clientIP: clientIP,
            serverIP: serverIP
        )

        let (dhcp, srcIP, dstIP) = try DHCPPacket.fromIPv4UDP(packet)

        XCTAssertEqual(dhcp.op, DHCPPacket.bootRequest)
        XCTAssertEqual(dhcp.messageType, .release)
        XCTAssertEqual(dhcp.ciaddr, clientIP)
        XCTAssertEqual(srcIP, clientIP)
        XCTAssertEqual(dstIP, serverIP)  // Unicast
    }

    // MARK: - Constants

    func testT1T2Constants() {
        XCTAssertEqual(DHCPPacket.t1Factor, 0.5)
        XCTAssertEqual(DHCPPacket.t2Factor, 0.875)
    }
}

// MARK: - DHCPService Tests

final class DHCPServiceTests: XCTestCase {

    func testServiceInitializesPool() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.1",
            poolEnd: "10.0.0.10"
        )
        let service = DHCPService(config: config)

        let count = await service.availableIPCount()
        XCTAssertEqual(count, 10)
    }

    func testServiceHandleDiscover() async throws {
        let config = DHCPServiceConfig(
            netmask: "255.255.0.0",
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600
        )
        let service = DHCPService(config: config)

        // Build a DISCOVER
        let discover = DHCPPacket.buildDiscover(machineId: "m1", xid: 1)

        // Service should respond with OFFER
        let response = await service.handlePacket(discover)
        XCTAssertNotNil(response)

        let (dhcp, _, _) = try DHCPPacket.fromIPv4UDP(response!)
        XCTAssertEqual(dhcp.messageType, .offer)
        XCTAssertNotEqual(dhcp.yiaddr, 0)
        XCTAssertEqual(dhcp.leaseTime, 3600)
    }

    func testServiceHandleFullFlow() async throws {
        let config = DHCPServiceConfig(
            netmask: "255.255.0.0",
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600,
            dnsServers: ["8.8.8.8"]
        )
        let service = DHCPService(config: config)

        // DISCOVER
        let discover = DHCPPacket.buildDiscover(machineId: "m1", xid: 1)
        let offerData = await service.handlePacket(discover)
        XCTAssertNotNil(offerData)

        let (offer, _, _) = try DHCPPacket.fromIPv4UDP(offerData!)
        XCTAssertEqual(offer.messageType, .offer)

        // REQUEST for the offered IP
        let request = DHCPPacket.buildRequest(
            machineId: "m1",
            xid: 2,
            requestedIP: offer.yiaddr,
            serverIP: offer.serverIdentifier!
        )
        let ackData = await service.handlePacket(request)
        XCTAssertNotNil(ackData)

        let (ack, _, _) = try DHCPPacket.fromIPv4UDP(ackData!)
        XCTAssertEqual(ack.messageType, .ack)
        XCTAssertEqual(ack.yiaddr, offer.yiaddr)
        XCTAssertEqual(ack.leaseTime, 3600)

        // Verify lease was recorded
        let leases = await service.getActiveLeases()
        XCTAssertEqual(leases.count, 1)
        XCTAssertEqual(leases[0].ip, offer.yiaddr)
    }

    func testServiceHonorsRequestedIP() async throws {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let service = DHCPService(config: config)

        // DISCOVER with requested IP
        var discoverPacket = DHCPPacket()
        discoverPacket.op = DHCPPacket.bootRequest
        discoverPacket.xid = 1
        discoverPacket.flags = DHCPPacket.broadcastFlag
        discoverPacket.chaddr = DHCPPacket.machineIdToChaddr("m1")
        discoverPacket.setMessageType(.discover)
        discoverPacket.setRequestedIP(DHCPPacket.parseIP("10.0.0.150")!)

        let discoverData = discoverPacket.toIPv4UDP(
            srcIP: 0, dstIP: 0xFFFFFFFF,
            srcPort: DHCPPacket.clientPort, dstPort: DHCPPacket.serverPort
        )

        let offerData = await service.handlePacket(discoverData)
        XCTAssertNotNil(offerData)

        let (offer, _, _) = try DHCPPacket.fromIPv4UDP(offerData!)
        XCTAssertEqual(offer.yiaddr, DHCPPacket.parseIP("10.0.0.150"))
    }

    func testServiceReturnsSameIPForExistingClient() async throws {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let service = DHCPService(config: config)

        // First full DISCOVER→REQUEST flow
        let discover1 = DHCPPacket.buildDiscover(machineId: "m1", xid: 1)
        let offer1Data = await service.handlePacket(discover1)!
        let (offer1, _, _) = try DHCPPacket.fromIPv4UDP(offer1Data)

        let request1 = DHCPPacket.buildRequest(
            machineId: "m1", xid: 2,
            requestedIP: offer1.yiaddr, serverIP: offer1.serverIdentifier!
        )
        _ = await service.handlePacket(request1)

        // Second DISCOVER from same client
        let discover2 = DHCPPacket.buildDiscover(machineId: "m1", xid: 3)
        let offer2Data = await service.handlePacket(discover2)!
        let (offer2, _, _) = try DHCPPacket.fromIPv4UDP(offer2Data)

        // Should offer the same IP
        XCTAssertEqual(offer1.yiaddr, offer2.yiaddr)
    }

    func testServiceHandleRelease() async throws {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let service = DHCPService(config: config)
        let initialCount = await service.availableIPCount()

        // Allocate
        let discover = DHCPPacket.buildDiscover(machineId: "m1", xid: 1)
        let offerData = await service.handlePacket(discover)!
        let (offer, _, _) = try DHCPPacket.fromIPv4UDP(offerData)

        let request = DHCPPacket.buildRequest(
            machineId: "m1", xid: 2,
            requestedIP: offer.yiaddr, serverIP: offer.serverIdentifier!
        )
        _ = await service.handlePacket(request)

        let afterAlloc = await service.availableIPCount()
        XCTAssertEqual(afterAlloc, initialCount - 1)

        // Release
        let release = DHCPPacket.buildRelease(
            machineId: "m1", xid: 3,
            clientIP: offer.yiaddr, serverIP: offer.serverIdentifier!
        )
        _ = await service.handlePacket(release)

        let afterRelease = await service.availableIPCount()
        XCTAssertEqual(afterRelease, initialCount)

        let leases = await service.getLeases()
        XCTAssertTrue(leases.isEmpty)
    }

    func testServiceHandleRenewal() async throws {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600
        )
        let service = DHCPService(config: config)

        // Allocate via DISCOVER→REQUEST
        let discover = DHCPPacket.buildDiscover(machineId: "m1", xid: 1)
        let offerData = await service.handlePacket(discover)!
        let (offer, _, _) = try DHCPPacket.fromIPv4UDP(offerData)

        let request = DHCPPacket.buildRequest(
            machineId: "m1", xid: 2,
            requestedIP: offer.yiaddr, serverIP: offer.serverIdentifier!
        )
        _ = await service.handlePacket(request)

        // Renew (RENEWING state: ciaddr filled, no requestedIP/serverIdentifier)
        let renew = DHCPPacket.buildRenewRequest(
            machineId: "m1", xid: 4,
            clientIP: offer.yiaddr, serverIP: offer.serverIdentifier!
        )
        let renewAckData = await service.handlePacket(renew)
        XCTAssertNotNil(renewAckData)

        let (renewAck, _, _) = try DHCPPacket.fromIPv4UDP(renewAckData!)
        XCTAssertEqual(renewAck.messageType, .ack)
        XCTAssertEqual(renewAck.yiaddr, offer.yiaddr)
    }

    func testServicePoolExhaustion() async throws {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.1",
            poolEnd: "10.0.0.3"  // Only 3 IPs
        )
        let service = DHCPService(config: config)

        // Allocate all 3 IPs
        for i in 1...3 {
            let discover = DHCPPacket.buildDiscover(machineId: "m\(i)", xid: UInt32(i * 10))
            let offerData = await service.handlePacket(discover)
            XCTAssertNotNil(offerData)

            let (offer, _, _) = try DHCPPacket.fromIPv4UDP(offerData!)
            let request = DHCPPacket.buildRequest(
                machineId: "m\(i)", xid: UInt32(i * 10 + 1),
                requestedIP: offer.yiaddr, serverIP: offer.serverIdentifier!
            )
            _ = await service.handlePacket(request)
        }

        // 4th DISCOVER should get no response
        let discover4 = DHCPPacket.buildDiscover(machineId: "m4", xid: 40)
        let response = await service.handlePacket(discover4)
        XCTAssertNil(response)
    }

    func testServiceCleanupExpiredLeases() async throws {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 1  // 1 second lease
        )
        let service = DHCPService(config: config)
        let initialCount = await service.availableIPCount()

        // Allocate
        let discover = DHCPPacket.buildDiscover(machineId: "m1", xid: 1)
        let offerData = await service.handlePacket(discover)!
        let (offer, _, _) = try DHCPPacket.fromIPv4UDP(offerData)
        let request = DHCPPacket.buildRequest(
            machineId: "m1", xid: 2,
            requestedIP: offer.yiaddr, serverIP: offer.serverIdentifier!
        )
        _ = await service.handlePacket(request)

        // Wait for lease to expire
        try await Task.sleep(for: .seconds(2))

        await service.cleanupExpiredLeases()

        let afterCleanup = await service.availableIPCount()
        XCTAssertEqual(afterCleanup, initialCount)
    }

    func testServiceNAKsUnavailableIP() async throws {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let service = DHCPService(config: config)

        // Machine 1 gets 10.0.0.150 through DISCOVER→REQUEST
        let discover1 = DHCPPacket.buildDiscover(machineId: "m1", xid: 1)
        let offerData = await service.handlePacket(discover1)!
        let (offer, _, _) = try DHCPPacket.fromIPv4UDP(offerData)

        let req1 = DHCPPacket.buildRequest(
            machineId: "m1", xid: 2,
            requestedIP: offer.yiaddr, serverIP: offer.serverIdentifier!
        )
        _ = await service.handlePacket(req1)
        let allocatedIP = offer.yiaddr

        // Machine 2 tries to REQUEST the same IP directly
        let req2 = DHCPPacket.buildRequest(
            machineId: "m2", xid: 3,
            requestedIP: allocatedIP, serverIP: offer.serverIdentifier!
        )
        let nakData = await service.handlePacket(req2)
        XCTAssertNotNil(nakData)

        let (nak, _, _) = try DHCPPacket.fromIPv4UDP(nakData!)
        XCTAssertEqual(nak.messageType, .nak)
    }
}

// MARK: - DHCPClient Tests

final class DHCPClientTests: XCTestCase {

    func testClientInitialState() {
        let client = DHCPClient(machineId: "m1")
        XCTAssertEqual(client.state, .initial)
        XCTAssertNil(client.assignedIPString)
        XCTAssertNil(client.renewalTime)
        XCTAssertNil(client.rebindingTime)
        XCTAssertNil(client.leaseExpiry)
    }

    func testBuildDiscoverTransitionsToDiscovering() throws {
        let client = DHCPClient(machineId: "m1", hostname: "myhost")
        let data = client.buildDiscover()

        XCTAssertEqual(client.state, .discovering)

        let (dhcp, _, _) = try DHCPPacket.fromIPv4UDP(data)
        XCTAssertEqual(dhcp.messageType, .discover)
        XCTAssertEqual(dhcp.hostname, "myhost")
        XCTAssertNotEqual(client.xid, 0)
    }

    func testHandleOfferTransitionsToRequesting() throws {
        let client = DHCPClient(machineId: "m1")
        _ = client.buildDiscover()
        let clientXid = client.xid
        let chaddr = DHCPPacket.machineIdToChaddr("m1")

        // Build an OFFER matching the client's xid
        let offer = DHCPPacket.buildOffer(
            xid: clientXid,
            clientChaddr: chaddr,
            offeredIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: DHCPPacket.parseIP("255.255.0.0")!,
            router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [DHCPPacket.parseIP("8.8.8.8")!],
            leaseTime: 3600
        )

        let action = client.handlePacket(offer)

        XCTAssertEqual(client.state, .requesting)
        if case .sendPacket(let reqData) = action {
            let (req, _, _) = try DHCPPacket.fromIPv4UDP(reqData)
            XCTAssertEqual(req.messageType, .request)
            XCTAssertEqual(req.requestedIP, DHCPPacket.parseIP("10.0.0.100"))
        } else {
            XCTFail("Expected sendPacket action")
        }
    }

    func testFullDHCPFlow() throws {
        let client = DHCPClient(machineId: "m1")
        let config = DHCPServiceConfig(
            netmask: "255.255.0.0",
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600,
            dnsServers: ["8.8.8.8"]
        )

        // Simulate the full DORA flow using real service
        // We can't use async service here since client is synchronous,
        // so we simulate packet exchange manually

        // 1. DISCOVER
        let discoverData = client.buildDiscover()
        XCTAssertEqual(client.state, .discovering)
        let clientXid = client.xid
        let chaddr = DHCPPacket.machineIdToChaddr("m1")

        // 2. OFFER (simulated from server)
        let serverIP = DHCPPacket.parseIP("10.0.0.1")!
        let offeredIP = DHCPPacket.parseIP("10.0.0.100")!
        let offerPacket = DHCPPacket.buildOffer(
            xid: clientXid,
            clientChaddr: chaddr,
            offeredIP: offeredIP,
            serverIP: serverIP,
            subnetMask: DHCPPacket.parseIP("255.255.0.0")!,
            router: serverIP,
            dnsServers: [DHCPPacket.parseIP("8.8.8.8")!],
            leaseTime: 3600
        )

        let offerAction = client.handlePacket(offerPacket)
        XCTAssertEqual(client.state, .requesting)

        guard case .sendPacket(let requestData) = offerAction else {
            XCTFail("Expected sendPacket action from OFFER")
            return
        }

        // 3. ACK (simulated from server)
        let requestXid = client.xid
        let ackPacket = DHCPPacket.buildACK(
            xid: requestXid,
            clientChaddr: chaddr,
            assignedIP: offeredIP,
            serverIP: serverIP,
            subnetMask: DHCPPacket.parseIP("255.255.0.0")!,
            router: serverIP,
            dnsServers: [DHCPPacket.parseIP("8.8.8.8")!],
            leaseTime: 3600
        )

        let ackAction = client.handlePacket(ackPacket)
        XCTAssertEqual(client.state, .bound)

        if case .configured(let ip, let netmask, let gateway, let dns, let leaseTime) = ackAction {
            XCTAssertEqual(ip, "10.0.0.100")
            XCTAssertEqual(netmask, "255.255.0.0")
            XCTAssertEqual(gateway, "10.0.0.1")
            XCTAssertEqual(dns, ["8.8.8.8"])
            XCTAssertEqual(leaseTime, 3600)
        } else {
            XCTFail("Expected configured action from ACK")
        }

        // Verify state
        XCTAssertEqual(client.assignedIPString, "10.0.0.100")
        XCTAssertNotNil(client.renewalTime)
        XCTAssertNotNil(client.rebindingTime)
        XCTAssertNotNil(client.leaseExpiry)
    }

    func testHandleNAKRestartsClient() {
        let client = DHCPClient(machineId: "m1")
        _ = client.buildDiscover()
        let clientXid = client.xid
        let chaddr = DHCPPacket.machineIdToChaddr("m1")

        // Simulate receiving an OFFER
        let offer = DHCPPacket.buildOffer(
            xid: clientXid,
            clientChaddr: chaddr,
            offeredIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: 0xFFFF0000,
            router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [],
            leaseTime: 3600
        )
        _ = client.handlePacket(offer)
        XCTAssertEqual(client.state, .requesting)

        // Send NAK
        let requestXid = client.xid
        let nak = DHCPPacket.buildNAK(
            xid: requestXid,
            clientChaddr: chaddr,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!
        )

        let action = client.handlePacket(nak)

        XCTAssertEqual(client.state, .initial)
        if case .restart = action {
            // Expected
        } else {
            XCTFail("Expected restart action from NAK")
        }
    }

    func testIgnoresMismatchedXid() {
        let client = DHCPClient(machineId: "m1")
        _ = client.buildDiscover()
        let chaddr = DHCPPacket.machineIdToChaddr("m1")

        // OFFER with wrong xid
        let offer = DHCPPacket.buildOffer(
            xid: 0xBADBAD,  // Wrong xid
            clientChaddr: chaddr,
            offeredIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: 0xFFFF0000,
            router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [],
            leaseTime: 3600
        )

        let action = client.handlePacket(offer)
        XCTAssertNil(action)
        XCTAssertEqual(client.state, .discovering)  // Still discovering
    }

    func testIgnoresMismatchedChaddr() {
        let client = DHCPClient(machineId: "m1")
        _ = client.buildDiscover()
        let clientXid = client.xid

        // OFFER with different chaddr
        let otherChaddr = DHCPPacket.machineIdToChaddr("m2")
        let offer = DHCPPacket.buildOffer(
            xid: clientXid,
            clientChaddr: otherChaddr,  // Wrong client
            offeredIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: 0xFFFF0000,
            router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [],
            leaseTime: 3600
        )

        let action = client.handlePacket(offer)
        XCTAssertNil(action)
    }

    func testBuildRelease() throws {
        let client = DHCPClient(machineId: "m1")

        // Can't release without being bound
        XCTAssertNil(client.buildRelease())

        // Get bound (simulate DORA)
        _ = client.buildDiscover()
        let chaddr = DHCPPacket.machineIdToChaddr("m1")
        let offer = DHCPPacket.buildOffer(
            xid: client.xid, clientChaddr: chaddr,
            offeredIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: 0xFFFF0000, router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [], leaseTime: 3600
        )
        _ = client.handlePacket(offer)
        let ack = DHCPPacket.buildACK(
            xid: client.xid, clientChaddr: chaddr,
            assignedIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: 0xFFFF0000, router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [], leaseTime: 3600
        )
        _ = client.handlePacket(ack)
        XCTAssertEqual(client.state, .bound)

        // Release
        let releaseData = client.buildRelease()
        XCTAssertNotNil(releaseData)
        XCTAssertEqual(client.state, .initial)
        XCTAssertNil(client.assignedIPString)

        let (rel, _, _) = try DHCPPacket.fromIPv4UDP(releaseData!)
        XCTAssertEqual(rel.messageType, .release)
    }

    func testBuildRenewAndRebind() throws {
        let client = DHCPClient(machineId: "m1")

        // Can't renew without being bound
        XCTAssertNil(client.buildRenew())

        // Get bound
        _ = client.buildDiscover()
        let chaddr = DHCPPacket.machineIdToChaddr("m1")
        let offer = DHCPPacket.buildOffer(
            xid: client.xid, clientChaddr: chaddr,
            offeredIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: 0xFFFF0000, router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [], leaseTime: 3600
        )
        _ = client.handlePacket(offer)
        let ack = DHCPPacket.buildACK(
            xid: client.xid, clientChaddr: chaddr,
            assignedIP: DHCPPacket.parseIP("10.0.0.100")!,
            serverIP: DHCPPacket.parseIP("10.0.0.1")!,
            subnetMask: 0xFFFF0000, router: DHCPPacket.parseIP("10.0.0.1")!,
            dnsServers: [], leaseTime: 3600
        )
        _ = client.handlePacket(ack)
        XCTAssertEqual(client.state, .bound)

        // Renew
        let renewData = client.buildRenew()
        XCTAssertNotNil(renewData)
        XCTAssertEqual(client.state, .renewing)

        let (renReq, _, dstIP) = try DHCPPacket.fromIPv4UDP(renewData!)
        XCTAssertEqual(renReq.messageType, .request)
        XCTAssertEqual(dstIP, DHCPPacket.parseIP("10.0.0.1"))  // Unicast

        // Rebind
        let rebindData = client.buildRebind()
        XCTAssertNotNil(rebindData)
        XCTAssertEqual(client.state, .rebinding)

        let (rebReq, _, rebDstIP) = try DHCPPacket.fromIPv4UDP(rebindData!)
        XCTAssertEqual(rebReq.messageType, .request)
        XCTAssertEqual(rebDstIP, 0xFFFFFFFF)  // Broadcast
    }

    func testReset() {
        let client = DHCPClient(machineId: "m1")
        _ = client.buildDiscover()
        XCTAssertEqual(client.state, .discovering)

        client.reset()
        XCTAssertEqual(client.state, .initial)
    }
}

// MARK: - DHCPServiceLease Tests

final class DHCPServiceLeaseTests: XCTestCase {

    func testLeaseCreation() {
        let lease = DHCPServiceLease(
            ip: DHCPPacket.parseIP("10.0.0.100")!,
            chaddr: DHCPPacket.machineIdToChaddr("m1"),
            hostname: "host1",
            grantedAt: Date(),
            expiresAt: Date().addingTimeInterval(3600)
        )

        XCTAssertEqual(lease.ipString, "10.0.0.100")
        XCTAssertEqual(lease.hostname, "host1")
        XCTAssertFalse(lease.isExpired)
        XCTAssertGreaterThan(lease.remainingTime, 3590)
    }

    func testLeaseExpiration() {
        let lease = DHCPServiceLease(
            ip: DHCPPacket.parseIP("10.0.0.100")!,
            chaddr: DHCPPacket.machineIdToChaddr("m1"),
            hostname: nil,
            grantedAt: Date().addingTimeInterval(-7200),
            expiresAt: Date().addingTimeInterval(-3600)
        )

        XCTAssertTrue(lease.isExpired)
        XCTAssertEqual(lease.remainingTime, 0)
    }
}
