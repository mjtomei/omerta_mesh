// DHCPClient.swift - RFC 2131 DHCP client state machine
//
// Pure packet processor: builds outbound DHCP packets and processes inbound
// packets, returning actions for the caller (PacketRouter) to execute.
// No ChannelProvider dependency.
//
// State machine: initial → discovering → requesting → bound → renewing → rebinding
//
// PacketRouter feeds inbound UDP port 68 packets to handlePacket() and sends
// outbound packets that buildDiscover()/buildRenew()/buildRebind()/buildRelease()
// produce.

import Foundation
import Logging

/// RFC 2131 DHCP client — pure packet-based state machine
///
/// Usage:
/// ```swift
/// let client = DHCPClient(machineId: myMachineId)
///
/// // Start discovery
/// let discover = client.buildDiscover()
/// sendToInterface(discover)
///
/// // When packets arrive on UDP port 68:
/// if let action = client.handlePacket(inboundPacket) {
///     switch action {
///     case .sendPacket(let data):
///         sendToInterface(data)  // REQUEST in response to OFFER
///     case .configured(let ip, let netmask, let gateway, let dns, let leaseTime):
///         configureInterface(ip: ip, netmask: netmask)
///     case .restart:
///         let discover = client.buildDiscover()
///         sendToInterface(discover)
///     }
/// }
/// ```
public final class DHCPClient: @unchecked Sendable {
    // MARK: - Configuration (immutable)

    private let machineId: String
    private let hostname: String?
    private let chaddr: [UInt8]
    private let logger: Logger

    // MARK: - Mutable State (synchronized via lock)

    private let lock = NSLock()

    private struct State {
        var clientState: DHCPClientState = .initial
        var xid: UInt32 = 0
        var assignedIP: UInt32 = 0
        var serverIP: UInt32 = 0
        var leaseTime: UInt32 = 0
        var leaseStart: Date?
    }

    private var _state = State()

    // MARK: - Init

    /// Initialize the DHCP client
    /// - Parameters:
    ///   - machineId: Used to derive the client hardware address (chaddr)
    ///   - hostname: Optional hostname for DHCP requests (option 12)
    public init(machineId: String, hostname: String? = nil) {
        self.machineId = machineId
        self.hostname = hostname
        self.chaddr = DHCPPacket.machineIdToChaddr(machineId)
        self.logger = Logger(label: "io.omerta.dhcp.client")
    }

    // MARK: - Public State Accessors

    /// Current client state
    public var state: DHCPClientState {
        lock.lock()
        defer { lock.unlock() }
        return _state.clientState
    }

    /// Current transaction ID
    public var xid: UInt32 {
        lock.lock()
        defer { lock.unlock() }
        return _state.xid
    }

    /// The assigned IP (valid when state is .bound, .renewing, or .rebinding)
    public var assignedIP: UInt32 {
        lock.lock()
        defer { lock.unlock() }
        return _state.assignedIP
    }

    /// The assigned IP as a dotted-quad string, or nil if not bound
    public var assignedIPString: String? {
        lock.lock()
        defer { lock.unlock() }
        guard _state.assignedIP != 0 else { return nil }
        return DHCPPacket.formatIP(_state.assignedIP)
    }

    /// The server IP that granted the lease
    public var serverIP: UInt32 {
        lock.lock()
        defer { lock.unlock() }
        return _state.serverIP
    }

    /// When T1 (renewal) timer fires — 50% of lease time
    public var renewalTime: Date? {
        lock.lock()
        defer { lock.unlock() }
        guard let start = _state.leaseStart, _state.leaseTime > 0 else { return nil }
        return start.addingTimeInterval(Double(_state.leaseTime) * DHCPPacket.t1Factor)
    }

    /// When T2 (rebinding) timer fires — 87.5% of lease time
    public var rebindingTime: Date? {
        lock.lock()
        defer { lock.unlock() }
        guard let start = _state.leaseStart, _state.leaseTime > 0 else { return nil }
        return start.addingTimeInterval(Double(_state.leaseTime) * DHCPPacket.t2Factor)
    }

    /// When the lease expires
    public var leaseExpiry: Date? {
        lock.lock()
        defer { lock.unlock() }
        guard let start = _state.leaseStart, _state.leaseTime > 0 else { return nil }
        return start.addingTimeInterval(Double(_state.leaseTime))
    }

    // MARK: - Packet Builders

    /// Build a DHCP DISCOVER packet. Transitions state to .discovering.
    /// - Returns: Raw IPv4/UDP/DHCP DISCOVER packet
    public func buildDiscover() -> Data {
        lock.lock()
        _state.xid = UInt32.random(in: 1...UInt32.max)
        _state.clientState = .discovering
        let currentXid = _state.xid
        lock.unlock()

        logger.debug("Building DISCOVER", metadata: ["xid": "\(currentXid)"])

        return DHCPPacket.buildDiscover(
            machineId: machineId,
            xid: currentXid,
            hostname: hostname
        )
    }

    /// Build a DHCP RELEASE packet. Transitions state back to .initial.
    /// - Returns: Raw IPv4/UDP/DHCP RELEASE packet, or nil if not bound
    public func buildRelease() -> Data? {
        lock.lock()
        guard _state.assignedIP != 0, _state.serverIP != 0 else {
            lock.unlock()
            return nil
        }
        let ip = _state.assignedIP
        let server = _state.serverIP
        let xid = UInt32.random(in: 1...UInt32.max)
        _state.clientState = .initial
        _state.assignedIP = 0
        _state.serverIP = 0
        _state.leaseTime = 0
        _state.leaseStart = nil
        lock.unlock()

        logger.info("Building RELEASE", metadata: [
            "ip": "\(DHCPPacket.formatIP(ip))"
        ])

        return DHCPPacket.buildRelease(
            machineId: machineId,
            xid: xid,
            clientIP: ip,
            serverIP: server
        )
    }

    /// Build a DHCP REQUEST for T1 renewal (unicast to server).
    /// Transitions state to .renewing.
    /// - Returns: Raw IPv4/UDP/DHCP REQUEST packet, or nil if not bound
    public func buildRenew() -> Data? {
        lock.lock()
        guard _state.clientState == .bound,
              _state.assignedIP != 0,
              _state.serverIP != 0 else {
            lock.unlock()
            return nil
        }
        _state.clientState = .renewing
        _state.xid = UInt32.random(in: 1...UInt32.max)
        let currentXid = _state.xid
        let ip = _state.assignedIP
        let server = _state.serverIP
        lock.unlock()

        logger.debug("Building RENEW request", metadata: [
            "xid": "\(currentXid)",
            "ip": "\(DHCPPacket.formatIP(ip))"
        ])

        return DHCPPacket.buildRenewRequest(
            machineId: machineId,
            xid: currentXid,
            clientIP: ip,
            serverIP: server,
            hostname: hostname
        )
    }

    /// Build a DHCP REQUEST for T2 rebinding (broadcast).
    /// Transitions state to .rebinding.
    /// - Returns: Raw IPv4/UDP/DHCP REQUEST packet, or nil if not renewing
    public func buildRebind() -> Data? {
        lock.lock()
        guard _state.clientState == .renewing,
              _state.assignedIP != 0 else {
            lock.unlock()
            return nil
        }
        _state.clientState = .rebinding
        _state.xid = UInt32.random(in: 1...UInt32.max)
        let currentXid = _state.xid
        let ip = _state.assignedIP
        lock.unlock()

        logger.debug("Building REBIND request", metadata: [
            "xid": "\(currentXid)",
            "ip": "\(DHCPPacket.formatIP(ip))"
        ])

        return DHCPPacket.buildRebindRequest(
            machineId: machineId,
            xid: currentXid,
            clientIP: ip,
            hostname: hostname
        )
    }

    // MARK: - Packet Handler

    /// Process an inbound DHCP packet (raw IPv4/UDP/DHCP on port 68).
    /// Returns an action for the caller to execute, or nil if the packet is ignored.
    public func handlePacket(_ packet: Data) -> DHCPClientAction? {
        // Parse the packet
        guard let (dhcp, _, _) = try? DHCPPacket.fromIPv4UDP(packet) else {
            return nil
        }

        // Must be a BOOTREPLY
        guard dhcp.op == DHCPPacket.bootReply else {
            return nil
        }

        // Must match our xid
        lock.lock()
        let currentXid = _state.xid
        let currentState = _state.clientState
        lock.unlock()

        guard dhcp.xid == currentXid else {
            return nil
        }

        // Must match our chaddr
        guard Array(dhcp.chaddr.prefix(6)) == Array(chaddr.prefix(6)) else {
            return nil
        }

        guard let msgType = dhcp.messageType else {
            return nil
        }

        switch (currentState, msgType) {
        case (.discovering, .offer):
            return handleOffer(dhcp)
        case (.requesting, .ack):
            return handleACK(dhcp)
        case (.requesting, .nak):
            return handleNAK()
        case (.renewing, .ack), (.rebinding, .ack):
            return handleRenewalACK(dhcp)
        case (.renewing, .nak), (.rebinding, .nak):
            return handleNAK()
        default:
            logger.debug("Ignoring \(msgType) in state \(currentState)")
            return nil
        }
    }

    /// Reset the client to initial state (e.g., after lease expires)
    public func reset() {
        lock.lock()
        _state = State()
        lock.unlock()
    }

    // MARK: - Private Handlers

    /// Handle DHCPOFFER: transition to requesting, build REQUEST
    private func handleOffer(_ offer: DHCPPacket) -> DHCPClientAction? {
        guard offer.yiaddr != 0 else {
            logger.warning("OFFER with no yiaddr")
            return nil
        }

        guard let offerServerIP = offer.serverIdentifier else {
            logger.warning("OFFER with no server identifier")
            return nil
        }

        logger.debug("Received OFFER", metadata: [
            "ip": "\(DHCPPacket.formatIP(offer.yiaddr))",
            "server": "\(DHCPPacket.formatIP(offerServerIP))"
        ])

        // Transition to requesting
        lock.lock()
        _state.clientState = .requesting
        _state.xid = UInt32.random(in: 1...UInt32.max)
        let newXid = _state.xid
        lock.unlock()

        // Build REQUEST for the offered IP
        let request = DHCPPacket.buildRequest(
            machineId: machineId,
            xid: newXid,
            requestedIP: offer.yiaddr,
            serverIP: offerServerIP,
            hostname: hostname
        )

        return .sendPacket(request)
    }

    /// Handle DHCPACK after initial REQUEST: transition to bound
    private func handleACK(_ ack: DHCPPacket) -> DHCPClientAction? {
        guard ack.yiaddr != 0 else {
            logger.warning("ACK with no yiaddr")
            return nil
        }

        let assignedIP = ack.yiaddr
        let serverIdent = ack.serverIdentifier ?? 0
        let leaseTime = ack.leaseTime ?? 3600
        let netmask = ack.subnetMask ?? 0
        let gateway = ack.router ?? 0
        let dns = ack.dnsServers

        lock.lock()
        _state.clientState = .bound
        _state.assignedIP = assignedIP
        _state.serverIP = serverIdent
        _state.leaseTime = leaseTime
        _state.leaseStart = Date()
        lock.unlock()

        logger.info("Lease acquired", metadata: [
            "ip": "\(DHCPPacket.formatIP(assignedIP))",
            "lease": "\(leaseTime)s"
        ])

        return .configured(
            ip: DHCPPacket.formatIP(assignedIP),
            netmask: DHCPPacket.formatIP(netmask),
            gateway: DHCPPacket.formatIP(gateway),
            dns: dns.map { DHCPPacket.formatIP($0) },
            leaseTime: leaseTime
        )
    }

    /// Handle DHCPACK for renewal/rebinding: stay bound
    private func handleRenewalACK(_ ack: DHCPPacket) -> DHCPClientAction? {
        let leaseTime = ack.leaseTime ?? 3600
        let netmask = ack.subnetMask ?? 0
        let gateway = ack.router ?? 0
        let dns = ack.dnsServers

        lock.lock()
        let ip = _state.assignedIP
        _state.clientState = .bound
        _state.leaseTime = leaseTime
        _state.leaseStart = Date()
        lock.unlock()

        logger.info("Lease renewed", metadata: [
            "ip": "\(DHCPPacket.formatIP(ip))",
            "lease": "\(leaseTime)s"
        ])

        return .configured(
            ip: DHCPPacket.formatIP(ip),
            netmask: DHCPPacket.formatIP(netmask),
            gateway: DHCPPacket.formatIP(gateway),
            dns: dns.map { DHCPPacket.formatIP($0) },
            leaseTime: leaseTime
        )
    }

    /// Handle DHCPNAK: transition back to initial
    private func handleNAK() -> DHCPClientAction {
        logger.warning("Received NAK, restarting")

        lock.lock()
        _state = State()
        lock.unlock()

        return .restart
    }
}
