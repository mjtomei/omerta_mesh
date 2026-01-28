// NativeDHCPTests.swift - Tests for native DHCP service and client

import XCTest
@testable import OmertaNetwork
@testable import OmertaMesh

// MARK: - Mock Channel Provider for DHCP Tests

/// Mock channel provider that can route messages between service and client
actor MockDHCPChannelProvider: ChannelProvider {
    let _peerId: PeerId

    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]
    var sentMessages: [(data: Data, target: String, channel: String)] = []

    init(peerId: PeerId = "mock-peer") {
        self._peerId = peerId
    }

    var peerId: PeerId {
        get async { _peerId }
    }

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        sentMessages.append((data, peerId, channel))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        sentMessages.append((data, machineId, channel))
    }

    func simulateReceive(_ data: Data, from machineId: MachineId, on channel: String) async {
        if let handler = handlers[channel] {
            await handler(machineId, data)
        }
    }

    func clearMessages() {
        sentMessages.removeAll()
    }

    func clearMessages(for target: String) {
        sentMessages.removeAll { $0.target == target }
    }
}

// MARK: - DHCP Messages Tests

final class DHCPMessagesTests: XCTestCase {

    func testDHCPRequestEncoding() throws {
        let request = DHCPRequest(machineId: "machine-1", requestedIP: "10.0.0.50", hostname: "myhost")
        let message = DHCPMessage.request(request)

        let data = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(DHCPMessage.self, from: data)

        if case .request(let req) = decoded {
            XCTAssertEqual(req.machineId, "machine-1")
            XCTAssertEqual(req.requestedIP, "10.0.0.50")
            XCTAssertEqual(req.hostname, "myhost")
        } else {
            XCTFail("Expected request message")
        }
    }

    func testDHCPResponseEncoding() throws {
        let response = DHCPResponse(
            machineId: "machine-1",
            assignedIP: "10.0.0.50",
            netmask: "255.255.0.0",
            gateway: "10.0.0.1",
            dnsServers: ["8.8.8.8", "8.8.4.4"],
            leaseSeconds: 3600
        )
        let message = DHCPMessage.response(response)

        let data = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(DHCPMessage.self, from: data)

        if case .response(let resp) = decoded {
            XCTAssertEqual(resp.machineId, "machine-1")
            XCTAssertEqual(resp.assignedIP, "10.0.0.50")
            XCTAssertEqual(resp.netmask, "255.255.0.0")
            XCTAssertEqual(resp.gateway, "10.0.0.1")
            XCTAssertEqual(resp.dnsServers, ["8.8.8.8", "8.8.4.4"])
            XCTAssertEqual(resp.leaseSeconds, 3600)
        } else {
            XCTFail("Expected response message")
        }
    }

    func testDHCPReleaseEncoding() throws {
        let release = DHCPRelease(machineId: "machine-1", ip: "10.0.0.50")
        let message = DHCPMessage.release(release)

        let data = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(DHCPMessage.self, from: data)

        if case .release(let rel) = decoded {
            XCTAssertEqual(rel.machineId, "machine-1")
            XCTAssertEqual(rel.ip, "10.0.0.50")
        } else {
            XCTFail("Expected release message")
        }
    }

    func testDHCPRenewalEncoding() throws {
        let renewal = DHCPRenewal(machineId: "machine-1", currentIP: "10.0.0.50")
        let message = DHCPMessage.renewal(renewal)

        let data = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(DHCPMessage.self, from: data)

        if case .renewal(let ren) = decoded {
            XCTAssertEqual(ren.machineId, "machine-1")
            XCTAssertEqual(ren.currentIP, "10.0.0.50")
        } else {
            XCTFail("Expected renewal message")
        }
    }

    func testDHCPNakEncoding() throws {
        let message = DHCPMessage.nak("No addresses available")

        let data = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(DHCPMessage.self, from: data)

        if case .nak(let reason) = decoded {
            XCTAssertEqual(reason, "No addresses available")
        } else {
            XCTFail("Expected nak message")
        }
    }
}

// MARK: - DHCP Service Tests

final class NativeDHCPServiceTests: XCTestCase {

    func testServiceConfigFromVirtualNetworkConfig() {
        let vnetConfig = VirtualNetworkConfig(
            subnet: "10.42.0.0",
            netmask: "255.255.0.0",
            prefixLength: 16,
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.0.200"
        )

        let dhcpConfig = DHCPServiceConfig(from: vnetConfig, leaseTime: 7200, dnsServers: ["8.8.8.8"])

        XCTAssertEqual(dhcpConfig.subnet, "10.42.0.0")
        XCTAssertEqual(dhcpConfig.netmask, "255.255.0.0")
        XCTAssertEqual(dhcpConfig.gatewayIP, "10.42.0.1")
        XCTAssertEqual(dhcpConfig.poolStart, "10.42.0.100")
        XCTAssertEqual(dhcpConfig.poolEnd, "10.42.0.200")
        XCTAssertEqual(dhcpConfig.leaseTime, 7200)
        XCTAssertEqual(dhcpConfig.dnsServers, ["8.8.8.8"])
    }

    func testServiceInitializesPool() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.1",
            poolEnd: "10.0.0.10"
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        // Pool should have 10 IPs (1-10)
        let count = await service.availableIPCount()
        XCTAssertEqual(count, 10)
    }

    func testServiceHandleRequest() async {
        let config = DHCPServiceConfig(
            netmask: "255.255.0.0",
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        let request = DHCPRequest(machineId: "m1", requestedIP: nil, hostname: "host1")
        let response = await service.handleRequest(request)

        XCTAssertNotNil(response)
        XCTAssertEqual(response?.machineId, "m1")
        XCTAssertEqual(response?.netmask, "255.255.0.0")
        XCTAssertEqual(response?.gateway, "10.0.0.1")
        XCTAssertEqual(response?.leaseSeconds, 3600)

        // Should have allocated one IP
        let leases = await service.getLeases()
        XCTAssertEqual(leases.count, 1)
        XCTAssertEqual(leases[0].machineId, "m1")
        XCTAssertEqual(leases[0].hostname, "host1")
    }

    func testServiceReturnsExistingLease() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        // First request
        let request1 = DHCPRequest(machineId: "m1")
        let response1 = await service.handleRequest(request1)

        // Second request from same machine
        let request2 = DHCPRequest(machineId: "m1")
        let response2 = await service.handleRequest(request2)

        // Should return same IP
        XCTAssertEqual(response1?.assignedIP, response2?.assignedIP)

        // Should only have one lease
        let leases = await service.getLeases()
        XCTAssertEqual(leases.count, 1)
    }

    func testServiceHonorsRequestedIP() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        let request = DHCPRequest(machineId: "m1", requestedIP: "10.0.0.150")
        let response = await service.handleRequest(request)

        XCTAssertEqual(response?.assignedIP, "10.0.0.150")
    }

    func testServiceRejectsUnavailableRequestedIP() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        // First machine gets 10.0.0.150
        let request1 = DHCPRequest(machineId: "m1", requestedIP: "10.0.0.150")
        _ = await service.handleRequest(request1)

        // Second machine requests same IP
        let request2 = DHCPRequest(machineId: "m2", requestedIP: "10.0.0.150")
        let response2 = await service.handleRequest(request2)

        // Should get a different IP
        XCTAssertNotEqual(response2?.assignedIP, "10.0.0.150")
    }

    func testServiceHandleRelease() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        let initialCount = await service.availableIPCount()

        // Allocate
        let request = DHCPRequest(machineId: "m1")
        let response = await service.handleRequest(request)
        let allocatedIP = response!.assignedIP

        let afterAllocCount = await service.availableIPCount()
        XCTAssertEqual(afterAllocCount, initialCount - 1)

        // Release
        let release = DHCPRelease(machineId: "m1", ip: allocatedIP)
        await service.handleRelease(release)

        let afterReleaseCount = await service.availableIPCount()
        XCTAssertEqual(afterReleaseCount, initialCount)

        let leases = await service.getLeases()
        XCTAssertTrue(leases.isEmpty)
    }

    func testServiceHandleRenewal() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        // Allocate
        let request = DHCPRequest(machineId: "m1")
        let response = await service.handleRequest(request)
        let allocatedIP = response!.assignedIP

        // Renew
        let renewal = DHCPRenewal(machineId: "m1", currentIP: allocatedIP)
        let renewResponse = await service.handleRenewal(renewal)

        XCTAssertNotNil(renewResponse)
        XCTAssertEqual(renewResponse?.assignedIP, allocatedIP)
        XCTAssertEqual(renewResponse?.leaseSeconds, 3600)
    }

    func testServiceRejectsRenewalMismatch() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        // Allocate
        let request = DHCPRequest(machineId: "m1")
        _ = await service.handleRequest(request)

        // Try to renew with wrong IP
        let renewal = DHCPRenewal(machineId: "m1", currentIP: "10.0.0.199")
        let renewResponse = await service.handleRenewal(renewal)

        XCTAssertNil(renewResponse)
    }

    func testServiceRejectsUnknownRenewal() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        // Try to renew without allocation
        let renewal = DHCPRenewal(machineId: "m1", currentIP: "10.0.0.150")
        let response = await service.handleRenewal(renewal)

        XCTAssertNil(response)
    }

    func testServicePoolExhaustion() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.1",
            poolEnd: "10.0.0.3"  // Only 3 IPs
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        // Allocate 3 IPs
        for i in 1...3 {
            let request = DHCPRequest(machineId: "m\(i)")
            let response = await service.handleRequest(request)
            XCTAssertNotNil(response)
        }

        // 4th request should fail
        let request4 = DHCPRequest(machineId: "m4")
        let response4 = await service.handleRequest(request4)
        XCTAssertNil(response4)
    }

    func testServiceCleanupExpiredLeases() async {
        let config = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 1  // 1 second lease
        )
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        let initialCount = await service.availableIPCount()

        // Allocate
        let request = DHCPRequest(machineId: "m1")
        _ = await service.handleRequest(request)

        // Wait for lease to expire
        try? await Task.sleep(for: .seconds(2))

        // Cleanup
        await service.cleanupExpiredLeases()

        let afterCleanupCount = await service.availableIPCount()
        XCTAssertEqual(afterCleanupCount, initialCount)

        let leases = await service.getLeases()
        XCTAssertTrue(leases.isEmpty)
    }

    func testServiceStartStop() async throws {
        let config = DHCPServiceConfig()
        let provider = MockDHCPChannelProvider()
        let service = DHCPService(config: config, provider: provider)

        try await service.start()
        // Starting again should be no-op
        try await service.start()

        await service.stop()
        // Stopping again should be no-op
        await service.stop()
    }
}

// MARK: - DHCP Client Tests

final class NativeDHCPClientTests: XCTestCase {

    func testClientConfig() {
        let config = NativeDHCPClientConfig(
            gatewayMachineId: "gateway",
            timeout: 15,
            retries: 5,
            autoRenew: false,
            hostname: "myhost"
        )

        XCTAssertEqual(config.gatewayMachineId, "gateway")
        XCTAssertEqual(config.timeout, 15)
        XCTAssertEqual(config.retries, 5)
        XCTAssertFalse(config.autoRenew)
        XCTAssertEqual(config.hostname, "myhost")
    }

    func testClientStartStop() async throws {
        let config = NativeDHCPClientConfig(gatewayMachineId: "gateway")
        let provider = MockDHCPChannelProvider()
        let client = DHCPClient(machineId: "m1", config: config, provider: provider)

        try await client.start()
        // Starting again should be no-op
        try await client.start()

        await client.stop()
        // Stopping again should be no-op
        await client.stop()
    }

    func testClientInitiallyNoLease() async throws {
        let config = NativeDHCPClientConfig(gatewayMachineId: "gateway")
        let provider = MockDHCPChannelProvider()
        let client = DHCPClient(machineId: "m1", config: config, provider: provider)

        try await client.start()

        let lease = await client.getCurrentLease()
        XCTAssertNil(lease)

        let valid = await client.isLeaseValid()
        XCTAssertFalse(valid)

        let remaining = await client.leaseTimeRemaining()
        XCTAssertEqual(remaining, 0)

        await client.stop()
    }
}

// MARK: - DHCP Integration Tests

final class NativeDHCPIntegrationTests: XCTestCase {

    func testClientServerIntegration() async throws {
        // Set up service (gateway)
        let serviceConfig = DHCPServiceConfig(
            netmask: "255.255.0.0",
            gatewayIP: "10.0.0.1",
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600,
            dnsServers: ["8.8.8.8"]
        )
        let serviceProvider = MockDHCPChannelProvider(peerId: "gateway")
        let service = DHCPService(config: serviceConfig, provider: serviceProvider)
        try await service.start()

        // Set up client (peer)
        let clientConfig = NativeDHCPClientConfig(
            gatewayMachineId: "gateway",
            timeout: 5,
            retries: 1,
            autoRenew: false,
            hostname: "testhost"
        )
        let clientProvider = MockDHCPChannelProvider(peerId: "peer1")
        let client = DHCPClient(machineId: "m1", config: clientConfig, provider: clientProvider)
        try await client.start()

        // Wire up message relay between client and service
        let relayTask = Task {
            while !Task.isCancelled {
                // Relay client -> service
                let clientMsgs = await clientProvider.sentMessages
                for msg in clientMsgs where msg.target == "gateway" {
                    await serviceProvider.simulateReceive(msg.data, from: "m1", on: msg.channel)
                }
                await clientProvider.clearMessages()

                // Relay service -> client
                let serviceMsgs = await serviceProvider.sentMessages
                for msg in serviceMsgs where msg.target == "m1" {
                    await clientProvider.simulateReceive(msg.data, from: "gateway", on: msg.channel)
                }
                await serviceProvider.clearMessages()

                try? await Task.sleep(for: .milliseconds(10))
            }
        }

        // Request address
        let response = try await client.requestAddress()

        XCTAssertEqual(response.machineId, "m1")
        XCTAssertEqual(response.netmask, "255.255.0.0")
        XCTAssertEqual(response.gateway, "10.0.0.1")
        XCTAssertEqual(response.dnsServers, ["8.8.8.8"])
        XCTAssertEqual(response.leaseSeconds, 3600)

        // Verify client state
        let lease = await client.getCurrentLease()
        XCTAssertNotNil(lease)
        XCTAssertEqual(lease?.assignedIP, response.assignedIP)

        let valid = await client.isLeaseValid()
        XCTAssertTrue(valid)

        // Cleanup
        relayTask.cancel()
        await client.stop()
        await service.stop()
    }

    func testClientServerRenewal() async throws {
        let serviceConfig = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200",
            leaseTime: 3600
        )
        let serviceProvider = MockDHCPChannelProvider(peerId: "gateway")
        let service = DHCPService(config: serviceConfig, provider: serviceProvider)
        try await service.start()

        let clientConfig = NativeDHCPClientConfig(
            gatewayMachineId: "gateway",
            timeout: 5,
            retries: 1,
            autoRenew: false
        )
        let clientProvider = MockDHCPChannelProvider(peerId: "peer1")
        let client = DHCPClient(machineId: "m1", config: clientConfig, provider: clientProvider)
        try await client.start()

        let relayTask = Task {
            while !Task.isCancelled {
                let clientMsgs = await clientProvider.sentMessages
                for msg in clientMsgs where msg.target == "gateway" {
                    await serviceProvider.simulateReceive(msg.data, from: "m1", on: msg.channel)
                }
                await clientProvider.clearMessages()

                let serviceMsgs = await serviceProvider.sentMessages
                for msg in serviceMsgs where msg.target == "m1" {
                    await clientProvider.simulateReceive(msg.data, from: "gateway", on: msg.channel)
                }
                await serviceProvider.clearMessages()

                try? await Task.sleep(for: .milliseconds(10))
            }
        }

        // Request address
        let response = try await client.requestAddress()
        let assignedIP = response.assignedIP

        // Renew
        let renewed = try await client.renewLease()
        XCTAssertEqual(renewed.assignedIP, assignedIP)

        // Cleanup
        relayTask.cancel()
        await client.stop()
        await service.stop()
    }

    func testClientServerRelease() async throws {
        let serviceConfig = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let serviceProvider = MockDHCPChannelProvider(peerId: "gateway")
        let service = DHCPService(config: serviceConfig, provider: serviceProvider)
        try await service.start()

        let clientConfig = NativeDHCPClientConfig(
            gatewayMachineId: "gateway",
            timeout: 5,
            retries: 1,
            autoRenew: false
        )
        let clientProvider = MockDHCPChannelProvider(peerId: "peer1")
        let client = DHCPClient(machineId: "m1", config: clientConfig, provider: clientProvider)
        try await client.start()

        let relayTask = Task {
            while !Task.isCancelled {
                let clientMsgs = await clientProvider.sentMessages
                for msg in clientMsgs where msg.target == "gateway" {
                    await serviceProvider.simulateReceive(msg.data, from: "m1", on: msg.channel)
                }
                await clientProvider.clearMessages()

                let serviceMsgs = await serviceProvider.sentMessages
                for msg in serviceMsgs where msg.target == "m1" {
                    await clientProvider.simulateReceive(msg.data, from: "gateway", on: msg.channel)
                }
                await serviceProvider.clearMessages()

                try? await Task.sleep(for: .milliseconds(10))
            }
        }

        let initialCount = await service.availableIPCount()

        // Request address
        _ = try await client.requestAddress()

        let afterAllocCount = await service.availableIPCount()
        XCTAssertEqual(afterAllocCount, initialCount - 1)

        // Wait for release message to be sent
        try await Task.sleep(for: .milliseconds(50))

        // Release
        try await client.releaseLease()

        // Wait for release to be processed
        try await Task.sleep(for: .milliseconds(100))

        let afterReleaseCount = await service.availableIPCount()
        XCTAssertEqual(afterReleaseCount, initialCount)

        // Client should have no lease
        let lease = await client.getCurrentLease()
        XCTAssertNil(lease)

        // Cleanup
        relayTask.cancel()
        await client.stop()
        await service.stop()
    }

    func testMultipleClientsGetDifferentIPs() async throws {
        let serviceConfig = DHCPServiceConfig(
            poolStart: "10.0.0.100",
            poolEnd: "10.0.0.200"
        )
        let serviceProvider = MockDHCPChannelProvider(peerId: "gateway")
        let service = DHCPService(config: serviceConfig, provider: serviceProvider)
        try await service.start()

        // Create multiple clients
        var clients: [DHCPClient] = []
        var clientProviders: [MockDHCPChannelProvider] = []
        var assignedIPs: Set<String> = []

        for i in 1...5 {
            let clientConfig = NativeDHCPClientConfig(
                gatewayMachineId: "gateway",
                timeout: 5,
                retries: 1,
                autoRenew: false
            )
            let provider = MockDHCPChannelProvider(peerId: "peer\(i)")
            let client = DHCPClient(machineId: "m\(i)", config: clientConfig, provider: provider)
            try await client.start()
            clients.append(client)
            clientProviders.append(provider)
        }

        // Request addresses sequentially to ensure proper message routing
        for (i, client) in clients.enumerated() {
            let provider = clientProviders[i]
            let machineId = "m\(i + 1)"

            // Simple direct relay for this client
            // Only clear this client's messages to avoid racing with other clients
            let relayTask = Task {
                while !Task.isCancelled {
                    let msgs = await provider.sentMessages
                    for msg in msgs where msg.target == "gateway" {
                        await serviceProvider.simulateReceive(msg.data, from: machineId, on: msg.channel)
                    }
                    await provider.clearMessages()

                    let serviceMsgs = await serviceProvider.sentMessages
                    for msg in serviceMsgs where msg.target == machineId {
                        await provider.simulateReceive(msg.data, from: "gateway", on: msg.channel)
                    }
                    // Only clear messages targeted at this client
                    await serviceProvider.clearMessages(for: machineId)

                    try? await Task.sleep(for: .milliseconds(10))
                }
            }

            let response = try await client.requestAddress()
            assignedIPs.insert(response.assignedIP)

            relayTask.cancel()
        }

        // All IPs should be unique
        XCTAssertEqual(assignedIPs.count, 5)

        // Cleanup
        for client in clients {
            await client.stop()
        }
        await service.stop()
    }
}

// MARK: - Native DHCP Lease Tests

final class NativeDHCPLeaseTests: XCTestCase {

    func testLeaseCreation() {
        let lease = NativeDHCPLease(
            ip: "10.0.0.100",
            machineId: "m1",
            hostname: "host1",
            grantedAt: Date(),
            expiresAt: Date().addingTimeInterval(3600)
        )

        XCTAssertEqual(lease.ip, "10.0.0.100")
        XCTAssertEqual(lease.machineId, "m1")
        XCTAssertEqual(lease.hostname, "host1")
        XCTAssertFalse(lease.isExpired)
        XCTAssertGreaterThan(lease.remainingTime, 3590)
    }

    func testLeaseExpiration() {
        let lease = NativeDHCPLease(
            ip: "10.0.0.100",
            machineId: "m1",
            hostname: nil,
            grantedAt: Date().addingTimeInterval(-7200),
            expiresAt: Date().addingTimeInterval(-3600)
        )

        XCTAssertTrue(lease.isExpired)
        XCTAssertEqual(lease.remainingTime, 0)
    }

    func testLeaseEquatable() {
        let now = Date()
        let expires = now.addingTimeInterval(3600)

        let lease1 = NativeDHCPLease(ip: "10.0.0.100", machineId: "m1", hostname: "h1", grantedAt: now, expiresAt: expires)
        let lease2 = NativeDHCPLease(ip: "10.0.0.100", machineId: "m1", hostname: "h1", grantedAt: now, expiresAt: expires)
        let lease3 = NativeDHCPLease(ip: "10.0.0.101", machineId: "m1", hostname: "h1", grantedAt: now, expiresAt: expires)

        XCTAssertEqual(lease1, lease2)
        XCTAssertNotEqual(lease1, lease3)
    }
}
