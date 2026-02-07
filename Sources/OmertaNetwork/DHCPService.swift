// DHCPService.swift - RFC 2131 DHCP server for mesh networks
//
// Runs on the gateway to allocate IP addresses to peers.
// Pure packet processor: receives raw IP/UDP/DHCP packets,
// returns response packets. No ChannelProvider dependency.
//
// PacketRouter calls handlePacket() when it sees UDP destined for port 67.

import Foundation
import Logging

/// Configuration for the native DHCP service
public struct DHCPServiceConfig: Sendable {
    /// The subnet (e.g., "10.42.0.0")
    public let subnet: String

    /// The netmask (e.g., "255.255.0.0")
    public let netmask: String

    /// The gateway IP (e.g., "10.42.0.1")
    public let gatewayIP: String

    /// Start of the IP pool (e.g., "10.42.0.100")
    public let poolStart: String

    /// End of the IP pool (e.g., "10.42.255.254")
    public let poolEnd: String

    /// Default lease time in seconds
    public let leaseTime: UInt32

    /// DNS servers to provide to clients
    public let dnsServers: [String]

    public init(
        subnet: String = "10.42.0.0",
        netmask: String = "255.255.0.0",
        gatewayIP: String = "10.42.0.1",
        poolStart: String = "10.42.0.100",
        poolEnd: String = "10.42.255.254",
        leaseTime: UInt32 = 3600,
        dnsServers: [String] = []
    ) {
        self.subnet = subnet
        self.netmask = netmask
        self.gatewayIP = gatewayIP
        self.poolStart = poolStart
        self.poolEnd = poolEnd
        self.leaseTime = leaseTime
        self.dnsServers = dnsServers
    }

    /// Create config from VirtualNetworkConfig
    public init(from networkConfig: VirtualNetworkConfig, leaseTime: UInt32 = 3600, dnsServers: [String] = []) {
        self.subnet = networkConfig.subnet
        self.netmask = networkConfig.netmask
        self.gatewayIP = networkConfig.gatewayIP
        self.poolStart = networkConfig.poolStart
        self.poolEnd = networkConfig.poolEnd
        self.leaseTime = leaseTime
        self.dnsServers = dnsServers
    }
}

/// A DHCP lease record keyed by client hardware address
public struct DHCPServiceLease: Sendable, Equatable {
    /// The assigned IP address (as UInt32)
    public let ip: UInt32

    /// Client hardware address (16 bytes from chaddr)
    public let chaddr: [UInt8]

    /// Hostname from option 12 (if provided)
    public let hostname: String?

    /// When the lease was granted
    public let grantedAt: Date

    /// When the lease expires
    public let expiresAt: Date

    /// The assigned IP as a dotted-quad string
    public var ipString: String { DHCPPacket.formatIP(ip) }

    /// Whether the lease has expired
    public var isExpired: Bool { Date() > expiresAt }

    /// Remaining time on the lease
    public var remainingTime: TimeInterval { max(0, expiresAt.timeIntervalSinceNow) }
}

/// RFC 2131 DHCP server — pure packet processor
///
/// Usage on gateway:
/// ```swift
/// let dhcp = DHCPService(config: config)
/// // In PacketRouter, when receiving UDP to port 67:
/// if let response = await dhcp.handlePacket(rawPacket) {
///     writeToInterface(response)
/// }
/// ```
public actor DHCPService {
    private let config: DHCPServiceConfig
    private let logger: Logger

    // Parsed IP values from config
    private let serverIP: UInt32
    private let subnetMask: UInt32
    private let routerIP: UInt32
    private let dnsServerIPs: [UInt32]
    private let poolStartIP: UInt32
    private let poolEndIP: UInt32

    /// Active leases keyed by chaddr (first 6 bytes as hex string for hashing)
    private var leases: [String: DHCPServiceLease] = [:]

    /// Available IP addresses in the pool
    private var availableIPs: Set<UInt32>

    /// Initialize the DHCP service
    /// - Parameter config: DHCP configuration including pool range
    public init(config: DHCPServiceConfig) {
        self.config = config
        self.logger = Logger(label: "io.omerta.dhcp.service")

        // Parse all IP addresses from config
        self.serverIP = DHCPPacket.parseIP(config.gatewayIP) ?? 0
        self.subnetMask = DHCPPacket.parseIP(config.netmask) ?? 0
        self.routerIP = DHCPPacket.parseIP(config.gatewayIP) ?? 0
        self.dnsServerIPs = config.dnsServers.compactMap { DHCPPacket.parseIP($0) }
        let startIP = DHCPPacket.parseIP(config.poolStart) ?? 0
        let endIP = DHCPPacket.parseIP(config.poolEnd) ?? 0
        self.poolStartIP = startIP
        self.poolEndIP = endIP

        // Initialize IP pool
        var pool = Set<UInt32>()
        if startIP > 0 && endIP >= startIP {
            var current = startIP
            while current <= endIP {
                pool.insert(current)
                current += 1
            }
        }
        self.availableIPs = pool
    }

    /// Process an inbound DHCP packet (raw IPv4/UDP/DHCP).
    /// Returns response packet (IPv4/UDP/DHCP), or nil if no response needed.
    public func handlePacket(_ packet: Data) -> Data? {
        // Parse the IPv4/UDP/DHCP packet
        guard let (dhcp, _, _) = try? DHCPPacket.fromIPv4UDP(packet) else {
            logger.debug("Failed to parse DHCP packet")
            return nil
        }

        // Must be a BOOTREQUEST
        guard dhcp.op == DHCPPacket.bootRequest else {
            return nil
        }

        guard let msgType = dhcp.messageType else {
            logger.debug("DHCP packet missing message type")
            return nil
        }

        switch msgType {
        case .discover:
            return handleDiscover(dhcp)
        case .request:
            return handleRequest(dhcp)
        case .release:
            handleRelease(dhcp)
            return nil
        case .decline:
            handleDecline(dhcp)
            return nil
        default:
            logger.debug("Ignoring DHCP message type: \(msgType)")
            return nil
        }
    }

    /// Get all leases
    public func getLeases() -> [DHCPServiceLease] {
        Array(leases.values)
    }

    /// Get active (non-expired) leases
    public func getActiveLeases() -> [DHCPServiceLease] {
        leases.values.filter { !$0.isExpired }
    }

    /// Get available IP count
    public func availableIPCount() -> Int {
        availableIPs.count
    }

    /// Expire old leases and return IPs to pool
    public func cleanupExpiredLeases() {
        let now = Date()
        var expired: [String] = []

        for (key, lease) in leases {
            if lease.expiresAt < now {
                expired.append(key)
                availableIPs.insert(lease.ip)
            }
        }

        for key in expired {
            leases.removeValue(forKey: key)
            logger.debug("Expired lease cleaned up", metadata: ["chaddr": "\(key)"])
        }
    }

    // MARK: - Private

    /// Handle DHCPDISCOVER: respond with DHCPOFFER
    private func handleDiscover(_ packet: DHCPPacket) -> Data? {
        let chaddrKey = chaddrToKey(packet.chaddr)

        // Check for existing lease for this client
        if let existing = leases[chaddrKey], !existing.isExpired {
            logger.debug("DISCOVER from known client, offering existing IP", metadata: [
                "ip": "\(existing.ipString)"
            ])
            return buildOffer(for: packet, offeredIP: existing.ip)
        }

        // Try requested IP from option 50 if available
        if let requestedIP = packet.requestedIP, availableIPs.contains(requestedIP) {
            return buildOffer(for: packet, offeredIP: requestedIP)
        }

        // Allocate from pool
        guard let ip = availableIPs.min() else {
            logger.warning("No IP addresses available in pool")
            return nil
        }

        return buildOffer(for: packet, offeredIP: ip)
    }

    /// Handle DHCPREQUEST: respond with DHCPACK or DHCPNAK
    private func handleRequest(_ packet: DHCPPacket) -> Data? {
        let chaddrKey = chaddrToKey(packet.chaddr)

        // Determine which IP the client is requesting
        let requestedIP: UInt32

        if let optionIP = packet.requestedIP {
            // SELECTING state: requestedIP option is present
            requestedIP = optionIP
        } else if packet.ciaddr != 0 {
            // RENEWING/REBINDING state: ciaddr is filled
            requestedIP = packet.ciaddr
        } else {
            logger.warning("REQUEST with no requested IP and no ciaddr")
            return buildNAK(for: packet)
        }

        // Check if it's a renewal of an existing lease
        if let existing = leases[chaddrKey], existing.ip == requestedIP {
            // Extend the lease
            let newLease = DHCPServiceLease(
                ip: requestedIP,
                chaddr: packet.chaddr,
                hostname: packet.hostname,
                grantedAt: existing.grantedAt,
                expiresAt: Date().addingTimeInterval(Double(config.leaseTime))
            )
            leases[chaddrKey] = newLease

            logger.debug("Lease renewed", metadata: [
                "ip": "\(DHCPPacket.formatIP(requestedIP))"
            ])
            return buildACK(for: packet, assignedIP: requestedIP)
        }

        // New allocation: verify the IP is available
        guard availableIPs.contains(requestedIP) else {
            logger.warning("Requested IP not available", metadata: [
                "ip": "\(DHCPPacket.formatIP(requestedIP))"
            ])
            return buildNAK(for: packet)
        }

        // Verify the IP is in our pool range
        guard requestedIP >= poolStartIP && requestedIP <= poolEndIP else {
            logger.warning("Requested IP outside pool range", metadata: [
                "ip": "\(DHCPPacket.formatIP(requestedIP))"
            ])
            return buildNAK(for: packet)
        }

        // Allocate
        availableIPs.remove(requestedIP)
        let lease = DHCPServiceLease(
            ip: requestedIP,
            chaddr: packet.chaddr,
            hostname: packet.hostname,
            grantedAt: Date(),
            expiresAt: Date().addingTimeInterval(Double(config.leaseTime))
        )
        leases[chaddrKey] = lease

        logger.info("IP allocated", metadata: [
            "ip": "\(DHCPPacket.formatIP(requestedIP))",
            "hostname": "\(packet.hostname ?? "none")"
        ])

        return buildACK(for: packet, assignedIP: requestedIP)
    }

    /// Handle DHCPRELEASE
    private func handleRelease(_ packet: DHCPPacket) {
        let chaddrKey = chaddrToKey(packet.chaddr)

        guard let lease = leases.removeValue(forKey: chaddrKey) else {
            logger.debug("Release for unknown client")
            return
        }

        availableIPs.insert(lease.ip)
        logger.info("IP released", metadata: [
            "ip": "\(lease.ipString)"
        ])
    }

    /// Handle DHCPDECLINE (client detected address conflict)
    private func handleDecline(_ packet: DHCPPacket) {
        let chaddrKey = chaddrToKey(packet.chaddr)

        if let lease = leases.removeValue(forKey: chaddrKey) {
            // Don't return the IP to the pool — it's conflicted
            logger.warning("IP declined (conflict)", metadata: [
                "ip": "\(lease.ipString)"
            ])
        }
    }

    /// Build a DHCPOFFER packet
    private func buildOffer(for request: DHCPPacket, offeredIP: UInt32) -> Data {
        DHCPPacket.buildOffer(
            xid: request.xid,
            clientChaddr: request.chaddr,
            offeredIP: offeredIP,
            serverIP: serverIP,
            subnetMask: subnetMask,
            router: routerIP,
            dnsServers: dnsServerIPs,
            leaseTime: config.leaseTime
        )
    }

    /// Build a DHCPACK packet
    private func buildACK(for request: DHCPPacket, assignedIP: UInt32) -> Data {
        DHCPPacket.buildACK(
            xid: request.xid,
            clientChaddr: request.chaddr,
            assignedIP: assignedIP,
            serverIP: serverIP,
            subnetMask: subnetMask,
            router: routerIP,
            dnsServers: dnsServerIPs,
            leaseTime: config.leaseTime
        )
    }

    /// Build a DHCPNAK packet
    private func buildNAK(for request: DHCPPacket) -> Data {
        DHCPPacket.buildNAK(
            xid: request.xid,
            clientChaddr: request.chaddr,
            serverIP: serverIP
        )
    }

    /// Convert chaddr to a string key for the leases dictionary.
    /// Uses hlen-significant bytes (typically first 6 for Ethernet).
    private func chaddrToKey(_ chaddr: [UInt8]) -> String {
        let significant = Array(chaddr.prefix(6))
        return significant.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}
