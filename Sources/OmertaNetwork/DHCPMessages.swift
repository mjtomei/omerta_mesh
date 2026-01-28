// DHCPMessages.swift - DHCP message types for mesh channel communication
//
// These messages are exchanged over the "dhcp" mesh channel between
// DHCPClient (peers) and DHCPService (gateway). Using JSON over mesh
// channels avoids the complexity of RFC 2131 packet format and works
// in both TUN and userspace modes.

import Foundation
import OmertaMesh

/// DHCP request sent by a peer to obtain an IP address
public struct DHCPRequest: Codable, Sendable, Equatable {
    /// The requesting machine's ID
    public let machineId: MachineId

    /// Optional preferred IP address
    public let requestedIP: String?

    /// Optional hostname for the machine
    public let hostname: String?

    public init(machineId: MachineId, requestedIP: String? = nil, hostname: String? = nil) {
        self.machineId = machineId
        self.requestedIP = requestedIP
        self.hostname = hostname
    }
}

/// DHCP response sent by the gateway with assigned IP
public struct DHCPResponse: Codable, Sendable, Equatable {
    /// The machine this response is for
    public let machineId: MachineId

    /// The assigned IP address
    public let assignedIP: String

    /// The subnet mask (e.g., "255.255.0.0")
    public let netmask: String

    /// The gateway IP address (usually .1)
    public let gateway: String

    /// DNS servers (optional)
    public let dnsServers: [String]

    /// Lease duration in seconds
    public let leaseSeconds: UInt32

    public init(
        machineId: MachineId,
        assignedIP: String,
        netmask: String,
        gateway: String,
        dnsServers: [String] = [],
        leaseSeconds: UInt32
    ) {
        self.machineId = machineId
        self.assignedIP = assignedIP
        self.netmask = netmask
        self.gateway = gateway
        self.dnsServers = dnsServers
        self.leaseSeconds = leaseSeconds
    }
}

/// DHCP release message sent when a peer releases its IP
public struct DHCPRelease: Codable, Sendable, Equatable {
    /// The machine releasing the IP
    public let machineId: MachineId

    /// The IP being released
    public let ip: String

    public init(machineId: MachineId, ip: String) {
        self.machineId = machineId
        self.ip = ip
    }
}

/// DHCP renewal request (extends lease)
public struct DHCPRenewal: Codable, Sendable, Equatable {
    /// The machine requesting renewal
    public let machineId: MachineId

    /// The current IP to renew
    public let currentIP: String

    public init(machineId: MachineId, currentIP: String) {
        self.machineId = machineId
        self.currentIP = currentIP
    }
}

/// Wrapper for all DHCP message types
public enum DHCPMessage: Codable, Sendable {
    case request(DHCPRequest)
    case response(DHCPResponse)
    case release(DHCPRelease)
    case renewal(DHCPRenewal)
    case nak(String)  // Negative acknowledgment with reason

    private enum CodingKeys: String, CodingKey {
        case type, payload
    }

    private enum MessageType: String, Codable {
        case request, response, release, renewal, nak
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(MessageType.self, forKey: .type)

        switch type {
        case .request:
            let payload = try container.decode(DHCPRequest.self, forKey: .payload)
            self = .request(payload)
        case .response:
            let payload = try container.decode(DHCPResponse.self, forKey: .payload)
            self = .response(payload)
        case .release:
            let payload = try container.decode(DHCPRelease.self, forKey: .payload)
            self = .release(payload)
        case .renewal:
            let payload = try container.decode(DHCPRenewal.self, forKey: .payload)
            self = .renewal(payload)
        case .nak:
            let reason = try container.decode(String.self, forKey: .payload)
            self = .nak(reason)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        switch self {
        case .request(let req):
            try container.encode(MessageType.request, forKey: .type)
            try container.encode(req, forKey: .payload)
        case .response(let resp):
            try container.encode(MessageType.response, forKey: .type)
            try container.encode(resp, forKey: .payload)
        case .release(let rel):
            try container.encode(MessageType.release, forKey: .type)
            try container.encode(rel, forKey: .payload)
        case .renewal(let ren):
            try container.encode(MessageType.renewal, forKey: .type)
            try container.encode(ren, forKey: .payload)
        case .nak(let reason):
            try container.encode(MessageType.nak, forKey: .type)
            try container.encode(reason, forKey: .payload)
        }
    }
}

/// Errors from DHCP operations
public enum DHCPError: Error, Sendable {
    case noGateway
    case noAddressAvailable
    case leaseExpired
    case invalidRequest(String)
    case timeout
    case encodingFailed
    case decodingFailed
    case notRunning
}
