// DHCPPacket.swift - RFC 2131 DHCP packet parser/builder
//
// Handles standard DHCP packets: BOOTP header (236 bytes) + magic cookie
// (0x63825363) + TLV options. Supports DISCOVER, OFFER, REQUEST, ACK,
// NAK, RELEASE message types.
//
// Reference: https://www.rfc-editor.org/rfc/rfc2131

import Foundation
import Crypto

// MARK: - DHCP Message Type

/// RFC 2131 DHCP message types (option 53)
public enum DHCPMessageType: UInt8, Sendable, Equatable, CustomStringConvertible {
    case discover = 1
    case offer    = 2
    case request  = 3
    case decline  = 4
    case ack      = 5
    case nak      = 6
    case release  = 7
    case inform   = 8

    public var description: String {
        switch self {
        case .discover: return "DISCOVER"
        case .offer:    return "OFFER"
        case .request:  return "REQUEST"
        case .decline:  return "DECLINE"
        case .ack:      return "ACK"
        case .nak:      return "NAK"
        case .release:  return "RELEASE"
        case .inform:   return "INFORM"
        }
    }
}

// MARK: - DHCP Option Tags

/// Well-known DHCP option tags from RFC 2132
public enum DHCPOptionTag: UInt8, Sendable {
    case pad              = 0
    case subnetMask       = 1
    case router           = 3
    case dnsServer        = 6
    case hostname         = 12
    case requestedIP      = 50
    case leaseTime        = 51
    case messageType      = 53
    case serverIdentifier = 54
    case parameterList    = 55
    case end              = 255
}

// MARK: - DHCP Client State Machine

/// RFC 2131 client states
public enum DHCPClientState: String, Sendable, Equatable, CustomStringConvertible {
    case initial
    case discovering
    case requesting
    case bound
    case renewing
    case rebinding

    public var description: String { rawValue }
}

// MARK: - DHCP Client Action

/// Actions returned by DHCPClient.handlePacket()
public enum DHCPClientAction: Sendable {
    /// Client should send this packet (REQUEST in response to OFFER)
    case sendPacket(Data)
    /// Lease acquired/renewed — client is configured
    case configured(ip: String, netmask: String, gateway: String, dns: [String], leaseTime: UInt32)
    /// Lease rejected (NAK received) — client should restart
    case restart
}

// MARK: - DHCP Errors

/// Errors from DHCP operations
public enum DHCPError: Error, Sendable, Equatable {
    case noGateway
    case noAddressAvailable
    case leaseExpired
    case invalidPacket(String)
    case timeout
    case notRunning
}

// MARK: - DHCP Packet

/// RFC 2131 DHCP packet with BOOTP header and options.
///
/// BOOTP fixed header (236 bytes):
///   op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
///   ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128)
///
/// Followed by magic cookie (4 bytes: 99.130.83.99) and TLV options.
public struct DHCPPacket: Sendable, Equatable {
    // MARK: - Constants

    /// BOOTP fixed header size (before options)
    public static let headerSize = 236

    /// Magic cookie marking start of DHCP options: 0x63825363
    public static let magicCookie: [UInt8] = [99, 130, 83, 99]

    /// BOOTP op codes
    public static let bootRequest: UInt8 = 1
    public static let bootReply: UInt8 = 2

    /// Hardware type: Ethernet
    public static let htypeEthernet: UInt8 = 1

    /// Hardware address length for Ethernet
    public static let hlenEthernet: UInt8 = 6

    /// Broadcast flag (bit 15 of flags field)
    public static let broadcastFlag: UInt16 = 0x8000

    /// DHCP server port
    public static let serverPort: UInt16 = 67

    /// DHCP client port
    public static let clientPort: UInt16 = 68

    /// Minimum DHCP message size (header + cookie + 312-byte options field)
    public static let minimumPacketSize = headerSize + 4 + 312  // 552

    /// T1 renewal timer: 50% of lease time (RFC 2131 Section 4.4.5)
    public static let t1Factor: Double = 0.5

    /// T2 rebinding timer: 87.5% of lease time (RFC 2131 Section 4.4.5)
    public static let t2Factor: Double = 0.875

    // MARK: - Header Fields

    /// Operation: 1=BOOTREQUEST, 2=BOOTREPLY
    public var op: UInt8

    /// Hardware type (1=Ethernet)
    public var htype: UInt8

    /// Hardware address length
    public var hlen: UInt8

    /// Hops (set to 0 by client)
    public var hops: UInt8

    /// Transaction ID — random, used to match requests/replies
    public var xid: UInt32

    /// Seconds elapsed since client began acquisition
    public var secs: UInt16

    /// Flags (bit 15 = broadcast)
    public var flags: UInt16

    /// Client IP address (filled in BOUND/RENEW/REBINDING)
    public var ciaddr: UInt32

    /// "Your" IP address — server's offered/assigned IP
    public var yiaddr: UInt32

    /// Server IP address (next server in bootstrap)
    public var siaddr: UInt32

    /// Relay agent IP address
    public var giaddr: UInt32

    /// Client hardware address (16 bytes, zero-padded)
    public var chaddr: [UInt8]  // Always 16 bytes

    /// Server host name (64 bytes, zero-padded, usually unused)
    public var sname: [UInt8]   // Always 64 bytes

    /// Boot file name (128 bytes, zero-padded, usually unused)
    public var file: [UInt8]    // Always 128 bytes

    // MARK: - Options

    /// DHCP options as tag -> value pairs (raw bytes)
    public var options: [UInt8: [UInt8]]

    // MARK: - Init

    public init() {
        op = Self.bootRequest
        htype = Self.htypeEthernet
        hlen = Self.hlenEthernet
        hops = 0
        xid = 0
        secs = 0
        flags = 0
        ciaddr = 0
        yiaddr = 0
        siaddr = 0
        giaddr = 0
        chaddr = [UInt8](repeating: 0, count: 16)
        sname = [UInt8](repeating: 0, count: 64)
        file = [UInt8](repeating: 0, count: 128)
        options = [:]
    }

    // MARK: - Convenience Accessors

    /// Get the DHCP message type from options
    public var messageType: DHCPMessageType? {
        guard let data = options[DHCPOptionTag.messageType.rawValue],
              data.count == 1,
              let type = DHCPMessageType(rawValue: data[0]) else {
            return nil
        }
        return type
    }

    /// Set the DHCP message type option
    public mutating func setMessageType(_ type: DHCPMessageType) {
        options[DHCPOptionTag.messageType.rawValue] = [type.rawValue]
    }

    /// Get requested IP address from options (option 50)
    public var requestedIP: UInt32? {
        guard let data = options[DHCPOptionTag.requestedIP.rawValue], data.count == 4 else {
            return nil
        }
        return readUInt32(data, at: 0)
    }

    /// Set requested IP address option
    public mutating func setRequestedIP(_ ip: UInt32) {
        options[DHCPOptionTag.requestedIP.rawValue] = writeUInt32(ip)
    }

    /// Get server identifier from options (option 54)
    public var serverIdentifier: UInt32? {
        guard let data = options[DHCPOptionTag.serverIdentifier.rawValue], data.count == 4 else {
            return nil
        }
        return readUInt32(data, at: 0)
    }

    /// Set server identifier option
    public mutating func setServerIdentifier(_ ip: UInt32) {
        options[DHCPOptionTag.serverIdentifier.rawValue] = writeUInt32(ip)
    }

    /// Get subnet mask from options (option 1)
    public var subnetMask: UInt32? {
        guard let data = options[DHCPOptionTag.subnetMask.rawValue], data.count == 4 else {
            return nil
        }
        return readUInt32(data, at: 0)
    }

    /// Set subnet mask option
    public mutating func setSubnetMask(_ mask: UInt32) {
        options[DHCPOptionTag.subnetMask.rawValue] = writeUInt32(mask)
    }

    /// Get router (gateway) from options (option 3)
    public var router: UInt32? {
        guard let data = options[DHCPOptionTag.router.rawValue], data.count >= 4 else {
            return nil
        }
        return readUInt32(data, at: 0)
    }

    /// Set router option
    public mutating func setRouter(_ ip: UInt32) {
        options[DHCPOptionTag.router.rawValue] = writeUInt32(ip)
    }

    /// Get DNS servers from options (option 6)
    public var dnsServers: [UInt32] {
        guard let data = options[DHCPOptionTag.dnsServer.rawValue], data.count >= 4 else {
            return []
        }
        var servers: [UInt32] = []
        var offset = 0
        while offset + 4 <= data.count {
            servers.append(readUInt32(data, at: offset))
            offset += 4
        }
        return servers
    }

    /// Set DNS servers option
    public mutating func setDNSServers(_ servers: [UInt32]) {
        var data: [UInt8] = []
        for server in servers {
            data.append(contentsOf: writeUInt32(server))
        }
        options[DHCPOptionTag.dnsServer.rawValue] = data
    }

    /// Get lease time from options (option 51)
    public var leaseTime: UInt32? {
        guard let data = options[DHCPOptionTag.leaseTime.rawValue], data.count == 4 else {
            return nil
        }
        return readUInt32(data, at: 0)
    }

    /// Set lease time option
    public mutating func setLeaseTime(_ seconds: UInt32) {
        options[DHCPOptionTag.leaseTime.rawValue] = writeUInt32(seconds)
    }

    /// Get hostname from options (option 12)
    public var hostname: String? {
        guard let data = options[DHCPOptionTag.hostname.rawValue] else {
            return nil
        }
        return String(bytes: data, encoding: .ascii)
    }

    /// Set hostname option
    public mutating func setHostname(_ name: String) {
        if let bytes = name.data(using: .ascii) {
            options[DHCPOptionTag.hostname.rawValue] = [UInt8](bytes)
        }
    }

    // MARK: - Serialize

    /// Serialize the DHCP packet to raw bytes
    public func toData() -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(Self.headerSize + 4 + 128) // header + cookie + options estimate

        // BOOTP header (236 bytes)
        bytes.append(op)
        bytes.append(htype)
        bytes.append(hlen)
        bytes.append(hops)
        bytes.append(contentsOf: writeUInt32(xid))
        bytes.append(contentsOf: writeUInt16(secs))
        bytes.append(contentsOf: writeUInt16(flags))
        bytes.append(contentsOf: writeUInt32(ciaddr))
        bytes.append(contentsOf: writeUInt32(yiaddr))
        bytes.append(contentsOf: writeUInt32(siaddr))
        bytes.append(contentsOf: writeUInt32(giaddr))

        // chaddr (16 bytes)
        let paddedChaddr = padTo(chaddr, length: 16)
        bytes.append(contentsOf: paddedChaddr)

        // sname (64 bytes)
        let paddedSname = padTo(sname, length: 64)
        bytes.append(contentsOf: paddedSname)

        // file (128 bytes)
        let paddedFile = padTo(file, length: 128)
        bytes.append(contentsOf: paddedFile)

        // Magic cookie
        bytes.append(contentsOf: Self.magicCookie)

        // Options (sorted by tag for deterministic output)
        for tag in options.keys.sorted() {
            // Skip pad and end — we handle end explicitly
            if tag == DHCPOptionTag.pad.rawValue || tag == DHCPOptionTag.end.rawValue {
                continue
            }
            guard let value = options[tag] else { continue }
            bytes.append(tag)
            bytes.append(UInt8(min(value.count, 255)))
            bytes.append(contentsOf: value.prefix(255))
        }

        // End option
        bytes.append(DHCPOptionTag.end.rawValue)

        // Pad to minimum 552 bytes total per RFC 2131
        // (236 header + 4 cookie + 312 options field minimum)
        while bytes.count < Self.minimumPacketSize {
            bytes.append(0)
        }

        return Data(bytes)
    }

    // MARK: - Parse

    /// Parse a DHCP packet from raw bytes (just the DHCP payload, no IP/UDP headers)
    public static func parse(_ data: Data) throws -> DHCPPacket {
        let bytes = [UInt8](data)

        guard bytes.count >= headerSize + 4 else {
            throw DHCPError.invalidPacket("Packet too short: \(bytes.count) bytes (need \(headerSize + 4))")
        }

        var packet = DHCPPacket()

        // Parse BOOTP header
        packet.op = bytes[0]
        packet.htype = bytes[1]
        packet.hlen = bytes[2]
        packet.hops = bytes[3]
        packet.xid = readUInt32(bytes, at: 4)
        packet.secs = readUInt16(bytes, at: 8)
        packet.flags = readUInt16(bytes, at: 10)
        packet.ciaddr = readUInt32(bytes, at: 12)
        packet.yiaddr = readUInt32(bytes, at: 16)
        packet.siaddr = readUInt32(bytes, at: 20)
        packet.giaddr = readUInt32(bytes, at: 24)
        packet.chaddr = Array(bytes[28..<44])
        packet.sname = Array(bytes[44..<108])
        packet.file = Array(bytes[108..<236])

        // Verify magic cookie
        let cookieOffset = headerSize
        guard bytes[cookieOffset] == magicCookie[0],
              bytes[cookieOffset + 1] == magicCookie[1],
              bytes[cookieOffset + 2] == magicCookie[2],
              bytes[cookieOffset + 3] == magicCookie[3] else {
            throw DHCPError.invalidPacket("Invalid magic cookie")
        }

        // Parse options
        var offset = cookieOffset + 4
        while offset < bytes.count {
            let tag = bytes[offset]

            if tag == DHCPOptionTag.end.rawValue {
                break
            }

            if tag == DHCPOptionTag.pad.rawValue {
                offset += 1
                continue
            }

            offset += 1
            guard offset < bytes.count else { break }

            let length = Int(bytes[offset])
            offset += 1

            guard offset + length <= bytes.count else {
                throw DHCPError.invalidPacket("Option \(tag) extends beyond packet")
            }

            packet.options[tag] = Array(bytes[offset..<(offset + length)])
            offset += length
        }

        return packet
    }

    // MARK: - IP/UDP Wrapping

    /// Wrap a DHCP packet in a UDP/IPv4 packet
    /// - Parameters:
    ///   - srcIP: Source IPv4 address (0 for 0.0.0.0)
    ///   - dstIP: Destination IPv4 address (0xFFFFFFFF for broadcast)
    ///   - srcPort: Source UDP port (typically 68 for client, 67 for server)
    ///   - dstPort: Destination UDP port (typically 67 for server, 68 for client)
    /// - Returns: Complete IPv4/UDP/DHCP packet
    public func toIPv4UDP(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16) -> Data {
        let dhcpData = toData()
        let udpLength = UInt16(8 + dhcpData.count)
        let totalLength = UInt16(20 + udpLength)

        var packet = [UInt8]()
        packet.reserveCapacity(Int(totalLength))

        // IPv4 header (20 bytes, no options)
        packet.append(0x45) // Version 4, IHL 5
        packet.append(0x00) // DSCP + ECN
        packet.append(contentsOf: writeUInt16(totalLength))
        packet.append(contentsOf: [0x00, 0x00]) // Identification
        packet.append(contentsOf: [0x00, 0x00]) // Flags + Fragment offset
        packet.append(64) // TTL
        packet.append(17) // Protocol: UDP
        packet.append(contentsOf: [0x00, 0x00]) // Checksum (zero for now)
        packet.append(contentsOf: writeUInt32(srcIP))
        packet.append(contentsOf: writeUInt32(dstIP))

        // Compute IPv4 header checksum
        let checksum = computeIPv4Checksum(packet)
        packet[10] = UInt8(checksum >> 8)
        packet[11] = UInt8(checksum & 0xFF)

        // UDP header (8 bytes)
        packet.append(contentsOf: writeUInt16(srcPort))
        packet.append(contentsOf: writeUInt16(dstPort))
        packet.append(contentsOf: writeUInt16(udpLength))
        packet.append(contentsOf: [0x00, 0x00]) // UDP checksum (optional for IPv4)

        // DHCP payload
        packet.append(contentsOf: [UInt8](dhcpData))

        return Data(packet)
    }

    /// Extract a DHCP packet from an IPv4/UDP packet
    /// Validates it's UDP with the expected port, then parses the DHCP payload.
    /// - Parameter data: Raw IPv4 packet data
    /// - Returns: Tuple of (parsed DHCP packet, source IP, destination IP)
    public static func fromIPv4UDP(_ data: Data) throws -> (packet: DHCPPacket, srcIP: UInt32, dstIP: UInt32) {
        let bytes = [UInt8](data)

        // Validate IPv4
        guard bytes.count >= 20 else {
            throw DHCPError.invalidPacket("IP packet too short")
        }

        let versionIHL = bytes[0]
        guard versionIHL >> 4 == 4 else {
            throw DHCPError.invalidPacket("Not an IPv4 packet")
        }

        let ihl = Int(versionIHL & 0x0F) * 4
        guard bytes.count >= ihl + 8 else {
            throw DHCPError.invalidPacket("Packet too short for IP + UDP headers")
        }

        // Verify protocol is UDP
        guard bytes[9] == 17 else {
            throw DHCPError.invalidPacket("Not a UDP packet (protocol: \(bytes[9]))")
        }

        let srcIP = readUInt32(bytes, at: 12)
        let dstIP = readUInt32(bytes, at: 16)

        // Parse UDP header
        let udpOffset = ihl
        let dstPort = readUInt16(bytes, at: udpOffset + 2)

        // Verify DHCP port
        guard dstPort == Self.serverPort || dstPort == Self.clientPort else {
            throw DHCPError.invalidPacket("Not a DHCP port (dst: \(dstPort))")
        }

        // Extract DHCP payload
        let dhcpOffset = udpOffset + 8
        guard dhcpOffset < bytes.count else {
            throw DHCPError.invalidPacket("No DHCP payload")
        }

        let dhcpData = Data(bytes[dhcpOffset...])
        let packet = try parse(dhcpData)

        return (packet, srcIP, dstIP)
    }

    // MARK: - Machine ID to Hardware Address

    /// Generate a deterministic 6-byte hardware address from a machine ID.
    /// Uses first 6 bytes of SHA-256(machineId), with the locally-administered
    /// bit set (bit 1 of first byte) and multicast bit cleared (bit 0 of first byte).
    public static func machineIdToChaddr(_ machineId: String) -> [UInt8] {
        let hash = SHA256.hash(data: Data(machineId.utf8))
        var addr = Array(hash.prefix(6))
        // Set locally-administered bit, clear multicast bit
        addr[0] = (addr[0] | 0x02) & 0xFE
        // Pad to 16 bytes
        return addr + [UInt8](repeating: 0, count: 10)
    }

    // MARK: - Packet Builders

    /// Build a DHCP DISCOVER packet
    /// - Parameters:
    ///   - machineId: The machine ID (used to derive chaddr)
    ///   - xid: Transaction ID
    ///   - hostname: Optional hostname to include
    /// - Returns: Complete IPv4/UDP/DHCP DISCOVER packet
    public static func buildDiscover(machineId: String, xid: UInt32, hostname: String? = nil) -> Data {
        var packet = DHCPPacket()
        packet.op = bootRequest
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.flags = broadcastFlag
        packet.chaddr = machineIdToChaddr(machineId)

        packet.setMessageType(.discover)

        // Request common parameters
        packet.options[DHCPOptionTag.parameterList.rawValue] = [
            DHCPOptionTag.subnetMask.rawValue,
            DHCPOptionTag.router.rawValue,
            DHCPOptionTag.dnsServer.rawValue,
            DHCPOptionTag.leaseTime.rawValue,
        ]

        if let hostname = hostname {
            packet.setHostname(hostname)
        }

        return packet.toIPv4UDP(
            srcIP: 0x00000000,          // 0.0.0.0
            dstIP: 0xFFFFFFFF,          // 255.255.255.255
            srcPort: clientPort,
            dstPort: serverPort
        )
    }

    /// Build a DHCP OFFER packet
    public static func buildOffer(
        xid: UInt32,
        clientChaddr: [UInt8],
        offeredIP: UInt32,
        serverIP: UInt32,
        subnetMask: UInt32,
        router: UInt32,
        dnsServers: [UInt32],
        leaseTime: UInt32
    ) -> Data {
        var packet = DHCPPacket()
        packet.op = bootReply
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.yiaddr = offeredIP
        packet.siaddr = serverIP
        packet.chaddr = clientChaddr

        packet.setMessageType(.offer)
        packet.setSubnetMask(subnetMask)
        packet.setRouter(router)
        packet.setLeaseTime(leaseTime)
        packet.setServerIdentifier(serverIP)

        if !dnsServers.isEmpty {
            packet.setDNSServers(dnsServers)
        }

        return packet.toIPv4UDP(
            srcIP: serverIP,
            dstIP: 0xFFFFFFFF,          // Broadcast (client doesn't have IP yet)
            srcPort: serverPort,
            dstPort: clientPort
        )
    }

    /// Build a DHCP REQUEST packet (SELECTING state — after receiving OFFER)
    /// Includes requestedIP and serverIdentifier per RFC 2131 Section 4.3.2.
    public static func buildRequest(
        machineId: String,
        xid: UInt32,
        requestedIP: UInt32,
        serverIP: UInt32,
        hostname: String? = nil
    ) -> Data {
        var packet = DHCPPacket()
        packet.op = bootRequest
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.ciaddr = 0  // MUST be 0 in SELECTING state
        packet.flags = broadcastFlag
        packet.chaddr = machineIdToChaddr(machineId)

        packet.setMessageType(.request)
        packet.setRequestedIP(requestedIP)
        packet.setServerIdentifier(serverIP)

        if let hostname = hostname {
            packet.setHostname(hostname)
        }

        return packet.toIPv4UDP(
            srcIP: 0x00000000,
            dstIP: 0xFFFFFFFF,  // Broadcast in SELECTING state
            srcPort: Self.clientPort,
            dstPort: Self.serverPort
        )
    }

    /// Build a DHCP REQUEST packet for RENEWING state (unicast to server).
    /// Per RFC 2131 Section 4.3.2: MUST NOT include requestedIP or serverIdentifier.
    public static func buildRenewRequest(
        machineId: String,
        xid: UInt32,
        clientIP: UInt32,
        serverIP: UInt32,
        hostname: String? = nil
    ) -> Data {
        var packet = DHCPPacket()
        packet.op = bootRequest
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.ciaddr = clientIP  // MUST be filled in RENEWING
        packet.flags = 0  // No broadcast — unicast to server
        packet.chaddr = machineIdToChaddr(machineId)

        packet.setMessageType(.request)
        // MUST NOT include requestedIP or serverIdentifier in RENEWING

        if let hostname = hostname {
            packet.setHostname(hostname)
        }

        return packet.toIPv4UDP(
            srcIP: clientIP,
            dstIP: serverIP,  // Unicast to server in RENEWING
            srcPort: Self.clientPort,
            dstPort: Self.serverPort
        )
    }

    /// Build a DHCP REQUEST packet for REBINDING state (broadcast).
    /// Per RFC 2131 Section 4.3.2: MUST NOT include requestedIP or serverIdentifier.
    public static func buildRebindRequest(
        machineId: String,
        xid: UInt32,
        clientIP: UInt32,
        hostname: String? = nil
    ) -> Data {
        var packet = DHCPPacket()
        packet.op = bootRequest
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.ciaddr = clientIP  // MUST be filled in REBINDING
        packet.flags = broadcastFlag
        packet.chaddr = machineIdToChaddr(machineId)

        packet.setMessageType(.request)
        // MUST NOT include requestedIP or serverIdentifier in REBINDING

        if let hostname = hostname {
            packet.setHostname(hostname)
        }

        return packet.toIPv4UDP(
            srcIP: clientIP,
            dstIP: 0xFFFFFFFF,  // Broadcast in REBINDING
            srcPort: Self.clientPort,
            dstPort: Self.serverPort
        )
    }

    /// Build a DHCP ACK packet
    public static func buildACK(
        xid: UInt32,
        clientChaddr: [UInt8],
        assignedIP: UInt32,
        serverIP: UInt32,
        subnetMask: UInt32,
        router: UInt32,
        dnsServers: [UInt32],
        leaseTime: UInt32
    ) -> Data {
        var packet = DHCPPacket()
        packet.op = bootReply
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.yiaddr = assignedIP
        packet.siaddr = serverIP
        packet.chaddr = clientChaddr

        packet.setMessageType(.ack)
        packet.setSubnetMask(subnetMask)
        packet.setRouter(router)
        packet.setLeaseTime(leaseTime)
        packet.setServerIdentifier(serverIP)

        if !dnsServers.isEmpty {
            packet.setDNSServers(dnsServers)
        }

        return packet.toIPv4UDP(
            srcIP: serverIP,
            dstIP: 0xFFFFFFFF,
            srcPort: serverPort,
            dstPort: clientPort
        )
    }

    /// Build a DHCP NAK packet
    public static func buildNAK(
        xid: UInt32,
        clientChaddr: [UInt8],
        serverIP: UInt32
    ) -> Data {
        var packet = DHCPPacket()
        packet.op = bootReply
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.chaddr = clientChaddr

        packet.setMessageType(.nak)
        packet.setServerIdentifier(serverIP)

        return packet.toIPv4UDP(
            srcIP: serverIP,
            dstIP: 0xFFFFFFFF,
            srcPort: serverPort,
            dstPort: clientPort
        )
    }

    /// Build a DHCP RELEASE packet
    public static func buildRelease(
        machineId: String,
        xid: UInt32,
        clientIP: UInt32,
        serverIP: UInt32
    ) -> Data {
        var packet = DHCPPacket()
        packet.op = bootRequest
        packet.htype = htypeEthernet
        packet.hlen = hlenEthernet
        packet.xid = xid
        packet.ciaddr = clientIP
        packet.chaddr = machineIdToChaddr(machineId)

        packet.setMessageType(.release)
        packet.setServerIdentifier(serverIP)

        return packet.toIPv4UDP(
            srcIP: clientIP,
            dstIP: serverIP,
            srcPort: Self.clientPort,
            dstPort: Self.serverPort
        )
    }
}

// MARK: - IP Address Helpers

extension DHCPPacket {
    /// Parse dotted-quad IP string to UInt32 (network byte order value)
    public static func parseIP(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        return (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16) | (UInt32(parts[2]) << 8) | UInt32(parts[3])
    }

    /// Format UInt32 IP to dotted-quad string
    public static func formatIP(_ ip: UInt32) -> String {
        let b0 = (ip >> 24) & 0xFF
        let b1 = (ip >> 16) & 0xFF
        let b2 = (ip >> 8) & 0xFF
        let b3 = ip & 0xFF
        return "\(b0).\(b1).\(b2).\(b3)"
    }
}

// MARK: - Byte Helpers (internal)

/// Read a UInt32 from a byte array at the given offset (big-endian)
func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    return (UInt32(bytes[offset]) << 24)
         | (UInt32(bytes[offset + 1]) << 16)
         | (UInt32(bytes[offset + 2]) << 8)
         |  UInt32(bytes[offset + 3])
}

/// Read a UInt16 from a byte array at the given offset (big-endian)
func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
    return (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
}

/// Write a UInt32 as big-endian bytes
func writeUInt32(_ value: UInt32) -> [UInt8] {
    [
        UInt8((value >> 24) & 0xFF),
        UInt8((value >> 16) & 0xFF),
        UInt8((value >> 8) & 0xFF),
        UInt8(value & 0xFF),
    ]
}

/// Write a UInt16 as big-endian bytes
func writeUInt16(_ value: UInt16) -> [UInt8] {
    [UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
}

/// Pad or truncate an array to the given length
func padTo(_ array: [UInt8], length: Int) -> [UInt8] {
    if array.count >= length {
        return Array(array.prefix(length))
    }
    return array + [UInt8](repeating: 0, count: length - array.count)
}

/// Compute IPv4 header checksum (RFC 791)
func computeIPv4Checksum(_ header: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    let len = min(header.count, 20) // Only checksum the IP header (20 bytes typical)
    var i = 0
    while i < len {
        let word = (UInt32(header[i]) << 8) | UInt32(header[i + 1])
        sum += word
        i += 2
    }
    // Add carry
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~UInt16(sum & 0xFFFF)
}
