// DHCPServerConfig.swift - Generates dnsmasq configuration for DHCP server
//
// The gateway runs dnsmasq bound to the virtual network interface.
// Peers unicast DHCP requests directly to the gateway's .1 address.

import Foundation

/// Configuration for dnsmasq DHCP server
public struct DHCPServerConfig: Sendable {
    /// Default lease file path under the user's home directory
    public static let defaultLeaseFilePath: String = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.omerta/dhcp/dnsmasq.leases"
    }()

    /// The virtual network configuration (subnet, gateway IP, pool range)
    public let networkConfig: VirtualNetworkConfig

    /// DHCP lease duration in seconds
    public let leaseDuration: TimeInterval

    /// Path to the dnsmasq lease file
    public let leaseFilePath: String

    /// DNS servers to advertise (optional)
    public let dnsServers: [String]

    /// Domain name for the network (optional)
    public let domainName: String?

    /// Initialize DHCP server configuration
    /// - Parameters:
    ///   - networkConfig: The virtual network configuration
    ///   - leaseDuration: Lease duration in seconds (default 3600 = 1 hour)
    ///   - leaseFilePath: Path to store leases (default ~/.omerta/dhcp/dnsmasq.leases)
    ///   - dnsServers: DNS servers to advertise (default empty, uses system)
    ///   - domainName: Optional domain name for the network
    public init(
        networkConfig: VirtualNetworkConfig,
        leaseDuration: TimeInterval = 3600,
        leaseFilePath: String = DHCPServerConfig.defaultLeaseFilePath,
        dnsServers: [String] = [],
        domainName: String? = nil
    ) {
        self.networkConfig = networkConfig
        self.leaseDuration = leaseDuration
        self.leaseFilePath = leaseFilePath
        self.dnsServers = dnsServers
        self.domainName = domainName
    }

    /// Generate a dnsmasq configuration file
    /// Works for both TUN interface and netstack-backed interface
    /// - Parameter interfaceName: The interface to bind to (e.g., "omerta0")
    /// - Returns: The complete dnsmasq.conf content
    public func generateDnsmasqConfig(interfaceName: String) -> String {
        var lines: [String] = []

        // Bind to specific interface only
        lines.append("interface=\(interfaceName)")
        lines.append("bind-interfaces")

        // DHCP range with lease duration
        let leaseSeconds = Int(leaseDuration)
        lines.append("dhcp-range=\(networkConfig.poolStart),\(networkConfig.poolEnd),\(networkConfig.netmask),\(leaseSeconds)s")

        // Router option (gateway)
        lines.append("dhcp-option=option:router,\(networkConfig.gatewayIP)")

        // DNS servers if specified
        if !dnsServers.isEmpty {
            lines.append("dhcp-option=option:dns-server,\(dnsServers.joined(separator: ","))")
        }

        // Domain name if specified
        if let domain = domainName {
            lines.append("dhcp-option=option:domain-name,\(domain)")
        }

        // Lease file
        lines.append("dhcp-leasefile=\(leaseFilePath)")

        // Run in foreground for process management
        lines.append("no-daemon")

        // Enable DHCP logging for debugging
        lines.append("log-dhcp")

        // Don't read /etc/hosts
        lines.append("no-hosts")

        // Don't use /etc/resolv.conf
        lines.append("no-resolv")

        return lines.joined(separator: "\n")
    }
}
