// DHCPClientConfig.swift - Configures DHCP client for unicast to known gateway
//
// DHCP clients normally broadcast DISCOVER messages, but RFC 2131 Section 4.1
// allows unicast when the server address is known. The gateway always takes
// the .1 address, so peers can unicast directly to it.

import Foundation

/// Configuration for netstack DHCP client (userspace mode)
public struct NetstackDHCPConfig: Sendable, Equatable {
    /// The DHCP server address to unicast to
    public let serverAddress: String

    /// Whether to use unicast instead of broadcast
    public let unicast: Bool

    /// Timeout for DHCP operations in seconds
    public let timeout: TimeInterval

    /// Number of retries before giving up
    public let retries: Int

    public init(
        serverAddress: String,
        unicast: Bool = true,
        timeout: TimeInterval = 10,
        retries: Int = 3
    ) {
        self.serverAddress = serverAddress
        self.unicast = unicast
        self.timeout = timeout
        self.retries = retries
    }
}

/// Configuration for DHCP client (both TUN and netstack modes)
public struct DHCPClientConfig: Sendable {
    /// The gateway IP address (DHCP server)
    public let gatewayIP: String

    /// The interface name
    public let interfaceName: String

    /// Timeout for DHCP operations
    public let timeout: TimeInterval

    /// Initialize DHCP client configuration
    /// - Parameters:
    ///   - gatewayIP: The gateway IP (e.g., "10.42.0.1")
    ///   - interfaceName: The interface name (e.g., "omerta0")
    ///   - timeout: Timeout in seconds (default 30)
    public init(gatewayIP: String, interfaceName: String, timeout: TimeInterval = 30) {
        self.gatewayIP = gatewayIP
        self.interfaceName = interfaceName
        self.timeout = timeout
    }

    /// For TUN mode: generate dhclient command arguments
    /// Uses -s flag to specify server for unicast
    /// - Returns: Arguments for dhclient command
    public func dhclientArgs() -> [String] {
        ["-s", gatewayIP, interfaceName]
    }

    /// For TUN mode: generate full dhclient command with timeout
    /// - Returns: Tuple of executable path and arguments
    public func dhclientCommand() -> (executable: String, arguments: [String]) {
        // Use timeout command to limit dhclient runtime
        let args: [String]
        if timeout > 0 {
            args = [
                "-1",           // Try once then exit
                "-v",           // Verbose for debugging
                "-s", gatewayIP,
                interfaceName
            ]
        } else {
            args = ["-s", gatewayIP, interfaceName]
        }
        return ("/sbin/dhclient", args)
    }

    /// For netstack mode: generate configuration for gVisor's built-in DHCP client
    /// gVisor's tcpip/network/ipv4 package has DHCP support that can be
    /// configured to unicast to a known server
    /// - Returns: Netstack DHCP configuration
    public func netstackDHCPConfig() -> NetstackDHCPConfig {
        NetstackDHCPConfig(
            serverAddress: gatewayIP,
            unicast: true,
            timeout: timeout
        )
    }
}

/// Result of a DHCP client operation
public struct DHCPClientResult: Sendable, Equatable {
    /// The assigned IP address
    public let assignedIP: String

    /// The subnet mask
    public let netmask: String

    /// The gateway/router IP
    public let gateway: String

    /// DNS servers provided
    public let dnsServers: [String]

    /// Lease duration in seconds
    public let leaseDuration: TimeInterval

    /// When the lease was obtained
    public let obtainedAt: Date

    public init(
        assignedIP: String,
        netmask: String,
        gateway: String,
        dnsServers: [String] = [],
        leaseDuration: TimeInterval,
        obtainedAt: Date = Date()
    ) {
        self.assignedIP = assignedIP
        self.netmask = netmask
        self.gateway = gateway
        self.dnsServers = dnsServers
        self.leaseDuration = leaseDuration
        self.obtainedAt = obtainedAt
    }

    /// When the lease expires
    public var expiresAt: Date {
        obtainedAt.addingTimeInterval(leaseDuration)
    }

    /// Whether the lease is still valid
    public var isValid: Bool {
        expiresAt > Date()
    }

    /// Time remaining on the lease
    public var timeRemaining: TimeInterval {
        max(0, expiresAt.timeIntervalSinceNow)
    }
}
