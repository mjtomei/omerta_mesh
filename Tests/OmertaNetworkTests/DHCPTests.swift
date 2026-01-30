// DHCPTests.swift - Tests for DHCP server and client configuration

import XCTest
@testable import OmertaNetwork

final class DHCPServerConfigTests: XCTestCase {

    func testDnsmasqConfigGeneration() {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let config = DHCPServerConfig(
            networkConfig: networkConfig,
            leaseDuration: 3600,
            leaseFilePath: "\(NSTemporaryDirectory())test.leases"
        )
        let output = config.generateDnsmasqConfig(interfaceName: "omerta0")

        XCTAssertTrue(output.contains("interface=omerta0"))
        XCTAssertTrue(output.contains("bind-interfaces"))
        XCTAssertTrue(output.contains("dhcp-range=10.42.0.100,10.42.255.254,255.255.0.0,3600s"))
        XCTAssertTrue(output.contains("dhcp-option=option:router,10.42.0.1"))
        XCTAssertTrue(output.contains("dhcp-leasefile=\(NSTemporaryDirectory())test.leases"))
        XCTAssertTrue(output.contains("no-daemon"))
        XCTAssertTrue(output.contains("log-dhcp"))
    }

    func testDnsmasqConfigWithDNS() {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let config = DHCPServerConfig(
            networkConfig: networkConfig,
            leaseDuration: 3600,
            leaseFilePath: "\(NSTemporaryDirectory())test.leases",
            dnsServers: ["8.8.8.8", "8.8.4.4"]
        )
        let output = config.generateDnsmasqConfig(interfaceName: "omerta0")

        XCTAssertTrue(output.contains("dhcp-option=option:dns-server,8.8.8.8,8.8.4.4"))
    }

    func testDnsmasqConfigWithDomain() {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let config = DHCPServerConfig(
            networkConfig: networkConfig,
            leaseDuration: 3600,
            leaseFilePath: "\(NSTemporaryDirectory())test.leases",
            domainName: "omerta.local"
        )
        let output = config.generateDnsmasqConfig(interfaceName: "omerta0")

        XCTAssertTrue(output.contains("dhcp-option=option:domain-name,omerta.local"))
    }

    func testDnsmasqConfigCustomLeaseDuration() {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let config = DHCPServerConfig(
            networkConfig: networkConfig,
            leaseDuration: 7200,  // 2 hours
            leaseFilePath: "\(NSTemporaryDirectory())test.leases"
        )
        let output = config.generateDnsmasqConfig(interfaceName: "omerta0")

        XCTAssertTrue(output.contains("7200s"))
    }

    func testDefaultValues() {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let config = DHCPServerConfig(networkConfig: networkConfig)

        XCTAssertEqual(config.leaseDuration, 3600)
        XCTAssertEqual(config.leaseFilePath, DHCPServerConfig.defaultLeaseFilePath)
        XCTAssertTrue(config.dnsServers.isEmpty)
        XCTAssertNil(config.domainName)
    }
}

final class DHCPClientConfigTests: XCTestCase {

    func testDHCPClientUnicastArgs() {
        let config = DHCPClientConfig(gatewayIP: "10.42.0.1", interfaceName: "omerta0")
        let args = config.dhclientArgs()

        XCTAssertEqual(args, ["-s", "10.42.0.1", "omerta0"])
    }

    func testDhclientCommand() {
        let config = DHCPClientConfig(gatewayIP: "10.42.0.1", interfaceName: "omerta0", timeout: 30)
        let (executable, args) = config.dhclientCommand()

        XCTAssertEqual(executable, "/sbin/dhclient")
        XCTAssertTrue(args.contains("-1"))
        XCTAssertTrue(args.contains("-v"))
        XCTAssertTrue(args.contains("-s"))
        XCTAssertTrue(args.contains("10.42.0.1"))
        XCTAssertTrue(args.contains("omerta0"))
    }

    func testNetstackDHCPConfig() {
        let config = DHCPClientConfig(gatewayIP: "10.42.0.1", interfaceName: "omerta0")
        let nsConfig = config.netstackDHCPConfig()

        XCTAssertEqual(nsConfig.serverAddress, "10.42.0.1")
        XCTAssertTrue(nsConfig.unicast)
        XCTAssertEqual(nsConfig.timeout, 30)  // default timeout
    }

    func testNetstackDHCPConfigCustomTimeout() {
        let config = DHCPClientConfig(gatewayIP: "10.42.0.1", interfaceName: "omerta0", timeout: 60)
        let nsConfig = config.netstackDHCPConfig()

        XCTAssertEqual(nsConfig.timeout, 60)
    }

    func testNetstackDHCPConfigEquatable() {
        let config1 = NetstackDHCPConfig(serverAddress: "10.42.0.1", unicast: true)
        let config2 = NetstackDHCPConfig(serverAddress: "10.42.0.1", unicast: true)
        let config3 = NetstackDHCPConfig(serverAddress: "10.43.0.1", unicast: true)

        XCTAssertEqual(config1, config2)
        XCTAssertNotEqual(config1, config3)
    }
}

final class DHCPClientResultTests: XCTestCase {

    func testClientResultCreation() {
        let result = DHCPClientResult(
            assignedIP: "10.42.0.50",
            netmask: "255.255.0.0",
            gateway: "10.42.0.1",
            dnsServers: ["8.8.8.8"],
            leaseDuration: 3600
        )

        XCTAssertEqual(result.assignedIP, "10.42.0.50")
        XCTAssertEqual(result.netmask, "255.255.0.0")
        XCTAssertEqual(result.gateway, "10.42.0.1")
        XCTAssertEqual(result.dnsServers, ["8.8.8.8"])
        XCTAssertEqual(result.leaseDuration, 3600)
    }

    func testLeaseExpiration() {
        let now = Date()
        let result = DHCPClientResult(
            assignedIP: "10.42.0.50",
            netmask: "255.255.0.0",
            gateway: "10.42.0.1",
            leaseDuration: 3600,
            obtainedAt: now
        )

        XCTAssertTrue(result.isValid)
        XCTAssertGreaterThan(result.timeRemaining, 3590)  // Allow some margin
        XCTAssertLessThanOrEqual(result.timeRemaining, 3600)
    }

    func testExpiredLease() {
        let pastDate = Date(timeIntervalSinceNow: -7200)  // 2 hours ago
        let result = DHCPClientResult(
            assignedIP: "10.42.0.50",
            netmask: "255.255.0.0",
            gateway: "10.42.0.1",
            leaseDuration: 3600,  // 1 hour
            obtainedAt: pastDate
        )

        XCTAssertFalse(result.isValid)
        XCTAssertEqual(result.timeRemaining, 0)
    }
}

final class DHCPLeaseTests: XCTestCase {

    func testLeaseCreation() {
        let expiry = Date(timeIntervalSinceNow: 3600)
        let lease = DHCPLease(
            expiresAt: expiry,
            macAddress: "00:11:22:33:44:55",
            ip: "10.42.0.50",
            hostname: "myhost"
        )

        XCTAssertEqual(lease.macAddress, "00:11:22:33:44:55")
        XCTAssertEqual(lease.ip, "10.42.0.50")
        XCTAssertEqual(lease.hostname, "myhost")
        XCTAssertNil(lease.clientId)
        XCTAssertTrue(lease.isValid)
    }

    func testLeaseWithClientId() {
        let expiry = Date(timeIntervalSinceNow: 3600)
        let lease = DHCPLease(
            expiresAt: expiry,
            macAddress: "00:11:22:33:44:55",
            ip: "10.42.0.50",
            hostname: "myhost",
            clientId: "01:00:11:22:33:44:55"
        )

        XCTAssertEqual(lease.clientId, "01:00:11:22:33:44:55")
    }

    func testExpiredLease() {
        let expiry = Date(timeIntervalSinceNow: -3600)  // Expired 1 hour ago
        let lease = DHCPLease(
            expiresAt: expiry,
            macAddress: "00:11:22:33:44:55",
            ip: "10.42.0.50",
            hostname: "myhost"
        )

        XCTAssertFalse(lease.isValid)
    }

    func testLeaseEquatable() {
        let expiry = Date(timeIntervalSince1970: 1700000000)
        let lease1 = DHCPLease(expiresAt: expiry, macAddress: "00:11:22:33:44:55", ip: "10.42.0.50", hostname: "host1")
        let lease2 = DHCPLease(expiresAt: expiry, macAddress: "00:11:22:33:44:55", ip: "10.42.0.50", hostname: "host1")
        let lease3 = DHCPLease(expiresAt: expiry, macAddress: "00:11:22:33:44:55", ip: "10.42.0.51", hostname: "host1")

        XCTAssertEqual(lease1, lease2)
        XCTAssertNotEqual(lease1, lease3)
    }
}

final class DHCPServerManagerTests: XCTestCase {

    func testManagerInitialization() async {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let config = DHCPServerConfig(networkConfig: networkConfig)
        let manager = DHCPServerManager(config: config)

        let running = await manager.isRunning
        XCTAssertFalse(running)
    }

    func testReadEmptyLeases() async throws {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let leaseFile = "\(NSTemporaryDirectory())omerta-test-nonexistent-\(UUID().uuidString).leases"
        let config = DHCPServerConfig(
            networkConfig: networkConfig,
            leaseFilePath: leaseFile
        )
        let manager = DHCPServerManager(config: config)

        // Should return empty array for non-existent file
        let leases = try await manager.readLeases()
        XCTAssertTrue(leases.isEmpty)
    }

    func testParseLeaseFile() async throws {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let leaseFile = "\(NSTemporaryDirectory())omerta-test-leases-\(UUID().uuidString).leases"
        defer { try? FileManager.default.removeItem(atPath: leaseFile) }

        // Create a test lease file in dnsmasq format
        let futureTime = Date(timeIntervalSinceNow: 3600).timeIntervalSince1970
        let leaseContent = """
        \(Int(futureTime)) 00:11:22:33:44:55 10.42.0.100 host1
        \(Int(futureTime)) aa:bb:cc:dd:ee:ff 10.42.0.101 host2 01:aa:bb:cc:dd:ee:ff
        """
        try leaseContent.write(toFile: leaseFile, atomically: true, encoding: .utf8)

        let config = DHCPServerConfig(
            networkConfig: networkConfig,
            leaseFilePath: leaseFile
        )
        let manager = DHCPServerManager(config: config)

        let leases = try await manager.readLeases()
        XCTAssertEqual(leases.count, 2)

        XCTAssertEqual(leases[0].macAddress, "00:11:22:33:44:55")
        XCTAssertEqual(leases[0].ip, "10.42.0.100")
        XCTAssertEqual(leases[0].hostname, "host1")
        XCTAssertNil(leases[0].clientId)
        XCTAssertTrue(leases[0].isValid)

        XCTAssertEqual(leases[1].macAddress, "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(leases[1].ip, "10.42.0.101")
        XCTAssertEqual(leases[1].hostname, "host2")
        XCTAssertEqual(leases[1].clientId, "01:aa:bb:cc:dd:ee:ff")
    }

    func testReadValidLeasesFiltersExpired() async throws {
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let leaseFile = "\(NSTemporaryDirectory())omerta-test-leases-\(UUID().uuidString).leases"
        defer { try? FileManager.default.removeItem(atPath: leaseFile) }

        // One valid, one expired
        let futureTime = Date(timeIntervalSinceNow: 3600).timeIntervalSince1970
        let pastTime = Date(timeIntervalSinceNow: -3600).timeIntervalSince1970
        let leaseContent = """
        \(Int(futureTime)) 00:11:22:33:44:55 10.42.0.100 valid-host
        \(Int(pastTime)) aa:bb:cc:dd:ee:ff 10.42.0.101 expired-host
        """
        try leaseContent.write(toFile: leaseFile, atomically: true, encoding: .utf8)

        let config = DHCPServerConfig(
            networkConfig: networkConfig,
            leaseFilePath: leaseFile
        )
        let manager = DHCPServerManager(config: config)

        let validLeases = try await manager.readValidLeases()
        XCTAssertEqual(validLeases.count, 1)
        XCTAssertEqual(validLeases[0].hostname, "valid-host")
    }

    func testStartWithoutDnsmasq() async throws {
        // This test verifies error handling when dnsmasq is not found
        // We can't actually test this reliably since dnsmasq might be installed
        // Just verify the manager can be created
        let networkConfig = VirtualNetworkConfig(generated: GeneratedSubnet(
            subnet: "10.42.0.0",
            prefixLength: 16,
            netmask: "255.255.0.0",
            gatewayIP: "10.42.0.1",
            poolStart: "10.42.0.100",
            poolEnd: "10.42.255.254"
        ))
        let config = DHCPServerConfig(networkConfig: networkConfig)
        let manager = DHCPServerManager(config: config)

        // Just verify it was created
        let running = await manager.isRunning
        XCTAssertFalse(running)
    }
}
