// DHCPService.swift - Native DHCP server for mesh networks
//
// Runs on the gateway to allocate IP addresses to peers.
// Listens on the "dhcp" mesh channel for requests and responds
// with assigned IP addresses from a configurable pool.

import Foundation
import OmertaMesh
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

/// A native DHCP lease record
public struct NativeDHCPLease: Sendable, Equatable {
    public let ip: String
    public let machineId: MachineId
    public let hostname: String?
    public let grantedAt: Date
    public let expiresAt: Date

    public var isExpired: Bool {
        Date() > expiresAt
    }

    public var remainingTime: TimeInterval {
        max(0, expiresAt.timeIntervalSinceNow)
    }
}

/// Native DHCP service for mesh networks
///
/// Usage on gateway:
/// ```swift
/// let dhcp = DHCPService(config: config, provider: meshNetwork)
/// try await dhcp.start()
/// // DHCP requests are now handled automatically
/// ```
public actor DHCPService {
    private let config: DHCPServiceConfig
    private let provider: any ChannelProvider
    private let logger: Logger

    /// Active leases keyed by machineId
    private var leases: [MachineId: NativeDHCPLease] = [:]

    /// Available IP addresses in the pool
    private var availableIPs: Set<String> = []

    /// Channel name for DHCP messages
    public static let channelName = "dhcp"

    private var isRunning = false

    /// Initialize the DHCP service
    /// - Parameters:
    ///   - config: DHCP configuration including pool range
    ///   - provider: Channel provider for receiving/sending messages
    public init(config: DHCPServiceConfig, provider: any ChannelProvider) {
        self.config = config
        self.provider = provider
        self.logger = Logger(label: "io.omerta.dhcp.service")

        // Initialize IP pool synchronously during init
        // This is safe because we're only modifying local state
        if let startIP = Self.parseIPStatic(config.poolStart),
           let endIP = Self.parseIPStatic(config.poolEnd) {
            var current = startIP
            while current <= endIP {
                availableIPs.insert(Self.formatIPStatic(current))
                current += 1
            }
        }
    }

    // Static versions for use in init
    private static func parseIPStatic(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        return (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16) | (UInt32(parts[2]) << 8) | UInt32(parts[3])
    }

    private static func formatIPStatic(_ ip: UInt32) -> String {
        let b0 = (ip >> 24) & 0xFF
        let b1 = (ip >> 16) & 0xFF
        let b2 = (ip >> 8) & 0xFF
        let b3 = ip & 0xFF
        return "\(b0).\(b1).\(b2).\(b3)"
    }

    /// Start the DHCP service
    public func start() async throws {
        guard !isRunning else { return }

        // Register handler for DHCP channel
        try await provider.onChannel(Self.channelName) { [weak self] machineId, data in
            await self?.handleMessage(from: machineId, data: data)
        }

        isRunning = true
        logger.info("DHCP service started", metadata: [
            "poolStart": "\(config.poolStart)",
            "poolEnd": "\(config.poolEnd)",
            "availableIPs": "\(availableIPs.count)"
        ])
    }

    /// Stop the DHCP service
    public func stop() async {
        guard isRunning else { return }

        await provider.offChannel(Self.channelName)
        isRunning = false
        logger.info("DHCP service stopped")
    }

    /// Handle a DHCP request directly (for testing without mesh)
    public func handleRequest(_ request: DHCPRequest) async -> DHCPResponse? {
        // Check for existing valid lease
        if let existing = leases[request.machineId], !existing.isExpired {
            logger.debug("Returning existing lease", metadata: [
                "machineId": "\(request.machineId)",
                "ip": "\(existing.ip)"
            ])
            return makeResponse(for: request.machineId, ip: existing.ip)
        }

        // Try requested IP if specified and available
        if let requestedIP = request.requestedIP, availableIPs.contains(requestedIP) {
            return allocate(ip: requestedIP, to: request.machineId, hostname: request.hostname)
        }

        // Allocate from pool
        guard let ip = availableIPs.first else {
            logger.warning("No IP addresses available in pool")
            return nil
        }

        return allocate(ip: ip, to: request.machineId, hostname: request.hostname)
    }

    /// Handle a DHCP release
    public func handleRelease(_ release: DHCPRelease) async {
        guard let lease = leases.removeValue(forKey: release.machineId) else {
            logger.debug("Release for unknown machine", metadata: ["machineId": "\(release.machineId)"])
            return
        }

        // Return IP to pool
        availableIPs.insert(lease.ip)

        logger.info("IP released", metadata: [
            "machineId": "\(release.machineId)",
            "ip": "\(lease.ip)"
        ])
    }

    /// Handle a lease renewal
    public func handleRenewal(_ renewal: DHCPRenewal) async -> DHCPResponse? {
        guard let existing = leases[renewal.machineId] else {
            logger.debug("Renewal for unknown lease", metadata: ["machineId": "\(renewal.machineId)"])
            return nil
        }

        guard existing.ip == renewal.currentIP else {
            logger.warning("Renewal IP mismatch", metadata: [
                "machineId": "\(renewal.machineId)",
                "requested": "\(renewal.currentIP)",
                "actual": "\(existing.ip)"
            ])
            return nil
        }

        // Extend lease
        let newLease = NativeDHCPLease(
            ip: existing.ip,
            machineId: renewal.machineId,
            hostname: existing.hostname,
            grantedAt: existing.grantedAt,
            expiresAt: Date().addingTimeInterval(Double(config.leaseTime))
        )
        leases[renewal.machineId] = newLease

        logger.debug("Lease renewed", metadata: [
            "machineId": "\(renewal.machineId)",
            "ip": "\(existing.ip)"
        ])

        return makeResponse(for: renewal.machineId, ip: existing.ip)
    }

    /// Get all active leases
    public func getLeases() -> [NativeDHCPLease] {
        Array(leases.values)
    }

    /// Get active (non-expired) leases
    public func getActiveLeases() -> [NativeDHCPLease] {
        leases.values.filter { !$0.isExpired }
    }

    /// Get available IP count
    public func availableIPCount() -> Int {
        availableIPs.count
    }

    /// Expire old leases and return IPs to pool
    public func cleanupExpiredLeases() {
        let now = Date()
        var expired: [MachineId] = []

        for (machineId, lease) in leases {
            if lease.expiresAt < now {
                expired.append(machineId)
                availableIPs.insert(lease.ip)
            }
        }

        for machineId in expired {
            leases.removeValue(forKey: machineId)
            logger.debug("Expired lease cleaned up", metadata: ["machineId": "\(machineId)"])
        }
    }

    // MARK: - Private

    private func handleMessage(from machineId: MachineId, data: Data) async {
        guard let message = try? JSONDecoder().decode(DHCPMessage.self, from: data) else {
            logger.warning("Invalid DHCP message", metadata: ["from": "\(machineId)"])
            return
        }

        switch message {
        case .request(let req):
            if let response = await handleRequest(req) {
                await sendResponse(.response(response), to: machineId)
            } else {
                await sendResponse(.nak("No addresses available"), to: machineId)
            }

        case .release(let rel):
            await handleRelease(rel)

        case .renewal(let ren):
            if let response = await handleRenewal(ren) {
                await sendResponse(.response(response), to: machineId)
            } else {
                await sendResponse(.nak("Renewal failed"), to: machineId)
            }

        case .response, .nak:
            // Service shouldn't receive these
            logger.warning("Unexpected message type from client", metadata: ["from": "\(machineId)"])
        }
    }

    private func sendResponse(_ message: DHCPMessage, to machineId: MachineId) async {
        guard let data = try? JSONEncoder().encode(message) else {
            logger.error("Failed to encode DHCP response")
            return
        }

        do {
            try await provider.sendOnChannel(data, toMachine: machineId, channel: Self.channelName)
        } catch {
            logger.error("Failed to send DHCP response: \(error)")
        }
    }

    private func allocate(ip: String, to machineId: MachineId, hostname: String?) -> DHCPResponse {
        availableIPs.remove(ip)

        let lease = NativeDHCPLease(
            ip: ip,
            machineId: machineId,
            hostname: hostname,
            grantedAt: Date(),
            expiresAt: Date().addingTimeInterval(Double(config.leaseTime))
        )
        leases[machineId] = lease

        logger.info("IP allocated", metadata: [
            "machineId": "\(machineId)",
            "ip": "\(ip)",
            "hostname": "\(hostname ?? "none")"
        ])

        return makeResponse(for: machineId, ip: ip)
    }

    private func makeResponse(for machineId: MachineId, ip: String) -> DHCPResponse {
        DHCPResponse(
            machineId: machineId,
            assignedIP: ip,
            netmask: config.netmask,
            gateway: config.gatewayIP,
            dnsServers: config.dnsServers,
            leaseSeconds: config.leaseTime
        )
    }

    private func parseIP(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        return (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16) | (UInt32(parts[2]) << 8) | UInt32(parts[3])
    }

    private func formatIP(_ ip: UInt32) -> String {
        let b0 = (ip >> 24) & 0xFF
        let b1 = (ip >> 16) & 0xFF
        let b2 = (ip >> 8) & 0xFF
        let b3 = ip & 0xFF
        return "\(b0).\(b1).\(b2).\(b3)"
    }
}
