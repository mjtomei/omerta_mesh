// PacketRouter.swift - Routes packets between NetworkInterface, VirtualNetwork, and TunnelManager
//
// PacketRouter is the glue that connects everything:
// - Reads packets from the local NetworkInterface
// - Uses VirtualNetwork to decide where they go (local, peer, gateway)
// - Sends packets through TunnelManager sessions
// - Delivers inbound packets from sessions to the local interface

import Foundation
import OmertaMesh
import OmertaTunnel
import Logging

/// Routes packets between the local network interface and mesh tunnel sessions.
///
/// Usage:
/// ```swift
/// let router = PacketRouter(
///     localInterface: interface,
///     virtualNetwork: vnet,
///     tunnelManager: tunnelManager
/// )
/// try await router.start()
/// // Packets now flow automatically between interface and mesh
/// ```
public actor PacketRouter {
    private let localInterface: any NetworkInterface
    private let virtualNetwork: VirtualNetwork
    private let tunnelManager: TunnelManager
    private let gatewayService: GatewayService?
    private let logger: Logger

    private var outboundTask: Task<Void, Never>?
    private var isRunning = false

    /// Statistics for the router
    public struct Stats: Sendable {
        public var packetsRouted: UInt64 = 0
        public var packetsDropped: UInt64 = 0
        public var packetsToLocal: UInt64 = 0
        public var packetsToPeer: UInt64 = 0
        public var packetsToGateway: UInt64 = 0
        public var packetsFromPeers: UInt64 = 0

        public init() {}
    }
    public private(set) var stats = Stats()

    /// Initialize the packet router
    /// - Parameters:
    ///   - localInterface: The network interface for local packet I/O
    ///   - virtualNetwork: The virtual network for routing decisions
    ///   - tunnelManager: The tunnel manager for peer sessions
    ///   - gatewayService: If non-nil, this node acts as the gateway and forwards internet-bound packets locally
    public init(
        localInterface: any NetworkInterface,
        virtualNetwork: VirtualNetwork,
        tunnelManager: TunnelManager,
        gatewayService: GatewayService? = nil
    ) {
        self.localInterface = localInterface
        self.virtualNetwork = virtualNetwork
        self.tunnelManager = tunnelManager
        self.gatewayService = gatewayService
        self.logger = Logger(label: "io.omerta.network.router")
    }

    /// Start routing packets
    public func start() async throws {
        guard !isRunning else { return }

        try await localInterface.start()

        // Start outbound routing loop
        outboundTask = Task { [weak self] in
            await self?.routeOutboundLoop()
        }

        // Register for new tunnel sessions to set up inbound routing
        await tunnelManager.setSessionEstablishedHandler { [weak self] session in
            await self?.setupInboundRouting(for: session)
        }

        // Wire gateway service return handler to route response packets back to peers
        if let gatewayService {
            let localMachineId = await virtualNetwork.getLocalMachineId()
            await gatewayService.setReturnHandler { [weak self] packet, machineId in
                guard let self else { return }
                if machineId == localMachineId {
                    await self.deliverLocalReturn(packet)
                } else {
                    await self.sendToPeer(packet, machineId: machineId, destIP: "gateway-return")
                }
            }
        }

        isRunning = true
        logger.info("Packet router started")
    }

    /// Stop routing and clean up
    public func stop() async {
        guard isRunning else { return }

        outboundTask?.cancel()
        outboundTask = nil

        await localInterface.stop()

        isRunning = false
        logger.info("Packet router stopped")
    }

    /// Get current statistics
    public func getStats() -> Stats {
        stats
    }

    // MARK: - Outbound Routing

    private func routeOutboundLoop() async {
        while !Task.isCancelled {
            do {
                let packet = try await localInterface.readPacket()
                await routeOutbound(packet)
            } catch {
                if !Task.isCancelled {
                    logger.trace("Read error: \(error)")
                }
            }
        }
    }

    private func routeOutbound(_ packet: Data) async {
        guard let destIP = extractDestinationIP(from: packet) else {
            logger.trace("Could not extract destination IP from packet")
            stats.packetsDropped += 1
            return
        }

        let decision = await virtualNetwork.route(destinationIP: destIP)
        stats.packetsRouted += 1

        switch decision {
        case .local:
            // Deliver locally (loopback)
            do {
                try await localInterface.writePacket(packet)
                stats.packetsToLocal += 1
                logger.trace("Routed to local", metadata: ["dest": "\(destIP)"])
            } catch {
                logger.trace("Failed to write local packet: \(error)")
                stats.packetsDropped += 1
            }

        case .peer(let machineId):
            // Send via tunnel session
            await sendToPeer(packet, machineId: machineId, destIP: destIP)

        case .gateway:
            // Send to gateway for internet forwarding
            await sendToGateway(packet, destIP: destIP)

        case .drop(let reason):
            stats.packetsDropped += 1
            logger.trace("Dropped packet", metadata: ["dest": "\(destIP)", "reason": "\(reason)"])
        }
    }

    private func sendToPeer(_ packet: Data, machineId: MachineId, destIP: String) async {
        // Look for existing session on "packet" channel
        let key = TunnelSessionKey(remoteMachineId: machineId, channel: "packet")
        if let session = await tunnelManager.getExistingSession(key: key) {
            do {
                try await session.send(packet)
                stats.packetsToPeer += 1
                logger.trace("Sent to peer", metadata: ["dest": "\(destIP)", "machine": "\(machineId.prefix(8))..."])
            } catch {
                logger.trace("Failed to send to peer: \(error)")
                stats.packetsDropped += 1
            }
        } else {
            // No session yet - try to create one
            do {
                let session = try await tunnelManager.getSession(machineId: machineId, channel: "packet")
                await setupInboundRouting(for: session)
                try await session.send(packet)
                stats.packetsToPeer += 1
                logger.trace("Created session and sent to peer", metadata: ["dest": "\(destIP)"])
            } catch {
                logger.trace("Failed to create session for peer: \(error)")
                stats.packetsDropped += 1
            }
        }
    }

    private func sendToGateway(_ packet: Data, destIP: String) async {
        // If we ARE the gateway, forward locally through our GatewayService
        if let gatewayService {
            guard let sourceIP = extractSourceIP(from: packet),
                  let machineId = await virtualNetwork.lookupMachine(ip: sourceIP) else {
                logger.trace("Could not resolve source machine for gateway-local forward")
                stats.packetsDropped += 1
                return
            }
            await gatewayService.forwardToInternet(packet, from: machineId)
            stats.packetsToGateway += 1
            logger.trace("Forwarded to local gateway", metadata: ["dest": "\(destIP)"])
            return
        }

        guard let gatewayMachineId = await virtualNetwork.getGatewayMachineId() else {
            logger.trace("No gateway configured, dropping packet to \(destIP)")
            stats.packetsDropped += 1
            return
        }

        // Send to gateway via tunnel
        let key = TunnelSessionKey(remoteMachineId: gatewayMachineId, channel: "packet")
        if let session = await tunnelManager.getExistingSession(key: key) {
            do {
                try await session.send(packet)
                stats.packetsToGateway += 1
                logger.trace("Sent to gateway", metadata: ["dest": "\(destIP)"])
            } catch {
                logger.trace("Failed to send to gateway: \(error)")
                stats.packetsDropped += 1
            }
        } else {
            // Create session to gateway
            do {
                let session = try await tunnelManager.getSession(machineId: gatewayMachineId, channel: "packet")
                await setupInboundRouting(for: session)
                try await session.send(packet)
                stats.packetsToGateway += 1
            } catch {
                logger.trace("Failed to create gateway session: \(error)")
                stats.packetsDropped += 1
            }
        }
    }

    // MARK: - Inbound Routing

    private func setupInboundRouting(for session: TunnelSession) async {
        // Only handle "packet" channel sessions
        let channel = await session.channel
        guard channel == "packet" else { return }

        let machineId = await session.remoteMachineId

        await session.onReceive { [weak self] packet in
            await self?.handleInboundPacket(packet, from: machineId)
        }

        logger.trace("Set up inbound routing", metadata: ["machine": "\(machineId.prefix(8))..."])
    }

    private func deliverLocalReturn(_ packet: Data) async {
        do {
            try await localInterface.writePacket(packet)
            stats.packetsFromPeers += 1
            logger.trace("Delivered gateway-local return", metadata: ["size": "\(packet.count)"])
        } catch {
            logger.trace("Failed to deliver gateway-local return: \(error)")
            stats.packetsDropped += 1
        }
    }

    private func handleInboundPacket(_ packet: Data, from machineId: MachineId) async {
        // If we are the gateway and this packet is internet-bound, forward it
        // through the GatewayService rather than delivering locally.
        if let gatewayService {
            if let destIP = extractDestinationIP(from: packet) {
                let decision = await virtualNetwork.route(destinationIP: destIP)
                if case .gateway = decision {
                    await gatewayService.forwardToInternet(packet, from: machineId)
                    stats.packetsFromPeers += 1
                    stats.packetsToGateway += 1
                    logger.trace("Gateway-forwarded inbound packet to internet", metadata: [
                        "from": "\(machineId.prefix(8))...",
                        "dest": "\(destIP)"
                    ])
                    return
                }
            }
        }

        do {
            try await localInterface.writePacket(packet)
            stats.packetsFromPeers += 1
            logger.trace("Delivered inbound packet", metadata: ["from": "\(machineId.prefix(8))...", "size": "\(packet.count)"])
        } catch {
            logger.trace("Failed to deliver inbound packet: \(error)")
            stats.packetsDropped += 1
        }
    }

    // MARK: - IP Packet Parsing

    /// Extract destination IP address from an IPv4 packet
    private func extractDestinationIP(from packet: Data) -> String? {
        // IPv4 header: destination IP is at bytes 16-19
        guard packet.count >= 20 else { return nil }

        // Check IP version (first nibble should be 4)
        let versionIHL = packet[0]
        let version = versionIHL >> 4
        guard version == 4 else { return nil }

        // Extract destination IP (bytes 16-19)
        let b0 = packet[16]
        let b1 = packet[17]
        let b2 = packet[18]
        let b3 = packet[19]

        return "\(b0).\(b1).\(b2).\(b3)"
    }

    /// Extract source IP address from an IPv4 packet
    public func extractSourceIP(from packet: Data) -> String? {
        // IPv4 header: source IP is at bytes 12-15
        guard packet.count >= 20 else { return nil }

        let versionIHL = packet[0]
        let version = versionIHL >> 4
        guard version == 4 else { return nil }

        let b0 = packet[12]
        let b1 = packet[13]
        let b2 = packet[14]
        let b3 = packet[15]

        return "\(b0).\(b1).\(b2).\(b3)"
    }
}

// MARK: - Test Helpers

extension PacketRouter {
    /// Create a minimal IPv4 packet for testing
    /// - Parameters:
    ///   - src: Source IP address
    ///   - dst: Destination IP address
    ///   - payload: Optional payload data
    /// - Returns: A valid IPv4 packet
    public static func createIPv4Packet(src: String, dst: String, payload: Data = Data()) -> Data? {
        guard let srcParts = parseIP(src), let dstParts = parseIP(dst) else {
            return nil
        }

        var packet = Data()

        // Version (4) + IHL (5 = 20 bytes header)
        packet.append(0x45)

        // DSCP + ECN
        packet.append(0x00)

        // Total length (header + payload)
        let totalLength = UInt16(20 + payload.count)
        packet.append(UInt8(totalLength >> 8))
        packet.append(UInt8(totalLength & 0xFF))

        // Identification
        packet.append(contentsOf: [0x00, 0x00])

        // Flags + Fragment offset
        packet.append(contentsOf: [0x00, 0x00])

        // TTL
        packet.append(64)

        // Protocol (UDP = 17)
        packet.append(17)

        // Header checksum (simplified - zeros for testing)
        packet.append(contentsOf: [0x00, 0x00])

        // Source IP
        packet.append(contentsOf: srcParts)

        // Destination IP
        packet.append(contentsOf: dstParts)

        // Payload
        packet.append(payload)

        return packet
    }

    private static func parseIP(_ ip: String) -> [UInt8]? {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        return parts
    }
}
