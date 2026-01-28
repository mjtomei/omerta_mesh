// DaemonProtocol.swift - Base protocol types for daemon IPC communication
//
// This defines the standardized IPC interface that both omerta-meshd and omertad implement.

import Foundation

// MARK: - Protocol Version

/// Current daemon protocol version for compatibility checking
public let daemonProtocolVersion: Int = 1

// MARK: - Base Commands (implemented by all daemons)

/// Commands that every daemon supports
public enum BaseDaemonCommand: Codable, Sendable, Equatable {
    /// Get daemon status
    case status

    /// Shutdown the daemon
    case shutdown(graceful: Bool, timeoutSeconds: Int)
}

// MARK: - Base Responses

/// Responses that every daemon can return
public enum BaseDaemonResponse: Codable, Sendable, Equatable {
    /// Status response
    case status(DaemonStatusData)

    /// Shutdown acknowledgment
    case shutdownAck(ShutdownAckData)

    /// Error response
    case error(String)
}

// MARK: - Status Data

/// Data returned by status command
public struct DaemonStatusData: Codable, Sendable, Equatable {
    /// Whether the daemon is running
    public let isRunning: Bool

    /// Type of daemon ("meshd" or "omertad")
    public let daemonType: String

    /// Network ID this daemon is operating on
    public let networkId: String

    /// Daemon uptime in seconds
    public let uptime: TimeInterval?

    /// Protocol version
    public let protocolVersion: Int

    /// Additional daemon-specific info
    public let additionalInfo: [String: String]

    public init(
        isRunning: Bool,
        daemonType: String,
        networkId: String,
        uptime: TimeInterval? = nil,
        protocolVersion: Int = daemonProtocolVersion,
        additionalInfo: [String: String] = [:]
    ) {
        self.isRunning = isRunning
        self.daemonType = daemonType
        self.networkId = networkId
        self.uptime = uptime
        self.protocolVersion = protocolVersion
        self.additionalInfo = additionalInfo
    }
}

/// Data returned by shutdown acknowledgment
public struct ShutdownAckData: Codable, Sendable, Equatable {
    /// Whether shutdown was accepted
    public let accepted: Bool

    /// Reason if not accepted
    public let reason: String?

    /// Estimated time until shutdown completes (if graceful)
    public let estimatedSeconds: Int?

    public init(accepted: Bool, reason: String? = nil, estimatedSeconds: Int? = nil) {
        self.accepted = accepted
        self.reason = reason
        self.estimatedSeconds = estimatedSeconds
    }
}

// MARK: - Peer Data

/// Information about a peer
public struct PeerData: Codable, Sendable, Equatable {
    public let peerId: String
    public let machineId: String?
    public let endpoint: String
    public let natType: String
    public let lastSeen: Date?
    public let isConnected: Bool
    public let isDirect: Bool
    public let rttMs: Double?

    public init(
        peerId: String,
        machineId: String? = nil,
        endpoint: String,
        natType: String = "unknown",
        lastSeen: Date? = nil,
        isConnected: Bool = false,
        isDirect: Bool = false,
        rttMs: Double? = nil
    ) {
        self.peerId = peerId
        self.machineId = machineId
        self.endpoint = endpoint
        self.natType = natType
        self.lastSeen = lastSeen
        self.isConnected = isConnected
        self.isDirect = isDirect
        self.rttMs = rttMs
    }
}

// MARK: - Ping Result Data

/// Result of a ping operation
public struct PingResultData: Codable, Sendable, Equatable {
    public let peerId: String
    public let rttMs: Double
    public let endpoint: String?
    public let natType: String?
    public let peersDiscovered: Int

    public init(
        peerId: String,
        rttMs: Double,
        endpoint: String? = nil,
        natType: String? = nil,
        peersDiscovered: Int = 0
    ) {
        self.peerId = peerId
        self.rttMs = rttMs
        self.endpoint = endpoint
        self.natType = natType
        self.peersDiscovered = peersDiscovered
    }
}

// MARK: - Connect Result Data

/// Result of a connection attempt
public struct ConnectResultData: Codable, Sendable, Equatable {
    public let success: Bool
    public let peerId: String
    public let endpoint: String?
    public let isDirect: Bool
    public let method: String  // "discovery", "holePunch", "relay"
    public let rttMs: Double?
    public let error: String?

    public init(
        success: Bool,
        peerId: String,
        endpoint: String? = nil,
        isDirect: Bool = false,
        method: String = "",
        rttMs: Double? = nil,
        error: String? = nil
    ) {
        self.success = success
        self.peerId = peerId
        self.endpoint = endpoint
        self.isDirect = isDirect
        self.method = method
        self.rttMs = rttMs
        self.error = error
    }
}

// MARK: - Network Info Data

/// Basic network information
public struct NetworkInfoData: Codable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let isActive: Bool
    public let joinedAt: Date
    public let bootstrapPeerCount: Int

    public init(
        id: String,
        name: String,
        isActive: Bool = true,
        joinedAt: Date = Date(),
        bootstrapPeerCount: Int = 0
    ) {
        self.id = id
        self.name = name
        self.isActive = isActive
        self.joinedAt = joinedAt
        self.bootstrapPeerCount = bootstrapPeerCount
    }
}

/// Detailed network information
public struct NetworkDetailData: Codable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let isActive: Bool
    public let joinedAt: Date
    public let bootstrapPeers: [String]
    public let inviteLink: String?
    public let peerCount: Int
    public let connectedPeerCount: Int

    public init(
        id: String,
        name: String,
        isActive: Bool = true,
        joinedAt: Date = Date(),
        bootstrapPeers: [String] = [],
        inviteLink: String? = nil,
        peerCount: Int = 0,
        connectedPeerCount: Int = 0
    ) {
        self.id = id
        self.name = name
        self.isActive = isActive
        self.joinedAt = joinedAt
        self.bootstrapPeers = bootstrapPeers
        self.inviteLink = inviteLink
        self.peerCount = peerCount
        self.connectedPeerCount = connectedPeerCount
    }
}

// MARK: - Message Result Data

/// Result of sending a message
public struct SendMessageResultData: Codable, Sendable, Equatable {
    public let success: Bool
    public let messageId: String?
    public let deliveryConfirmed: Bool
    public let error: String?

    public init(
        success: Bool,
        messageId: String? = nil,
        deliveryConfirmed: Bool = false,
        error: String? = nil
    ) {
        self.success = success
        self.messageId = messageId
        self.deliveryConfirmed = deliveryConfirmed
        self.error = error
    }
}

// MARK: - Health Check Result Data

/// Result of a health check
public struct HealthCheckResultData: Codable, Sendable, Equatable {
    public let peerId: String
    public let isHealthy: Bool
    public let rttMs: Double?
    public let lastSeen: Date?
    public let error: String?

    public init(
        peerId: String,
        isHealthy: Bool,
        rttMs: Double? = nil,
        lastSeen: Date? = nil,
        error: String? = nil
    ) {
        self.peerId = peerId
        self.isHealthy = isHealthy
        self.rttMs = rttMs
        self.lastSeen = lastSeen
        self.error = error
    }
}

// MARK: - Negotiate Result Data

/// Result of network negotiation
public struct NegotiateResultData: Codable, Sendable, Equatable {
    public let success: Bool
    public let networkId: String?
    public let networkName: String?
    public let error: String?

    public init(
        success: Bool,
        networkId: String? = nil,
        networkName: String? = nil,
        error: String? = nil
    ) {
        self.success = success
        self.networkId = networkId
        self.networkName = networkName
        self.error = error
    }
}

// MARK: - Share Invite Result Data

/// Result of sharing an invite
public struct ShareInviteResultData: Codable, Sendable, Equatable {
    public let success: Bool
    public let inviteAccepted: Bool
    public let error: String?

    public init(
        success: Bool,
        inviteAccepted: Bool = false,
        error: String? = nil
    ) {
        self.success = success
        self.inviteAccepted = inviteAccepted
        self.error = error
    }
}

// MARK: - Socket Path Utilities

/// Utilities for daemon socket paths
public enum DaemonSocketPaths {
    /// Base directory for daemon sockets
    public static let socketDir = "/tmp"

    /// Control socket path for mesh daemon
    public static func meshDaemonControl(networkId: String) -> String {
        "\(socketDir)/omerta-meshd-\(networkId).sock"
    }

    /// Data socket path for mesh daemon (binary tunnel packets)
    public static func meshDaemonData(networkId: String) -> String {
        "\(socketDir)/omerta-meshd-\(networkId).data.sock"
    }

    /// Control socket path for VM daemon
    public static func vmDaemonControl(networkId: String) -> String {
        "\(socketDir)/omertad-\(networkId).sock"
    }

    /// Check if a socket file exists
    public static func socketExists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    /// Remove a socket file (for cleanup)
    public static func removeSocket(_ path: String) throws {
        if socketExists(path) {
            try FileManager.default.removeItem(atPath: path)
        }
    }
}

// MARK: - IPC Message Framing

/// Length-prefixed JSON message for IPC
/// Frame format: [4-byte length (big-endian)] [JSON payload]
public struct IPCMessage: Sendable {
    /// Maximum message size (16 MB)
    public static let maxMessageSize: Int = 16 * 1024 * 1024

    /// Encode a Codable value to a framed message
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let json = try encoder.encode(value)

        guard json.count <= maxMessageSize else {
            throw IPCError.messageTooLarge(json.count)
        }

        var frame = Data(capacity: 4 + json.count)
        var length = UInt32(json.count).bigEndian
        frame.append(Data(bytes: &length, count: 4))
        frame.append(json)
        return frame
    }

    /// Decode a Codable value from JSON data (without frame header)
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: data)
    }

    /// Read the length prefix from frame header
    public static func readLength(from data: Data) -> UInt32? {
        guard data.count >= 4 else { return nil }
        return data.withUnsafeBytes { ptr in
            ptr.load(as: UInt32.self).bigEndian
        }
    }
}

/// IPC communication errors
public enum IPCError: Error, Sendable, CustomStringConvertible {
    case connectionFailed(String)
    case connectionClosed
    case timeout
    case messageTooLarge(Int)
    case invalidMessage(String)
    case encodingFailed(String)
    case decodingFailed(String)
    case socketError(String)

    public var description: String {
        switch self {
        case .connectionFailed(let reason):
            return "Connection failed: \(reason)"
        case .connectionClosed:
            return "Connection closed"
        case .timeout:
            return "Operation timed out"
        case .messageTooLarge(let size):
            return "Message too large: \(size) bytes (max: \(IPCMessage.maxMessageSize))"
        case .invalidMessage(let reason):
            return "Invalid message: \(reason)"
        case .encodingFailed(let reason):
            return "Encoding failed: \(reason)"
        case .decodingFailed(let reason):
            return "Decoding failed: \(reason)"
        case .socketError(let reason):
            return "Socket error: \(reason)"
        }
    }
}
