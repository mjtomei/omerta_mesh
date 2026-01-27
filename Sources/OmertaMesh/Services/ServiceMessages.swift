// ServiceMessages.swift - Message types for utility services
//
// All service messages are Codable and Sendable for channel transport.

import Foundation

// MARK: - Health Service Messages

/// Health check request
public struct HealthRequest: Codable, Sendable {
    /// Unique request ID for response matching
    public let requestId: UUID

    /// Whether to include detailed metrics
    public let includeMetrics: Bool

    public init(requestId: UUID = UUID(), includeMetrics: Bool = true) {
        self.requestId = requestId
        self.includeMetrics = includeMetrics
    }
}

/// Health check response
public struct HealthResponse: Codable, Sendable {
    /// Matching request ID
    public let requestId: UUID

    /// Overall health status
    public let status: HealthStatus

    /// Detailed metrics (if requested)
    public let metrics: HealthMetrics?

    /// Response timestamp
    public let timestamp: Date

    public init(
        requestId: UUID,
        status: HealthStatus,
        metrics: HealthMetrics? = nil,
        timestamp: Date = Date()
    ) {
        self.requestId = requestId
        self.status = status
        self.metrics = metrics
        self.timestamp = timestamp
    }
}

/// Health status enumeration
public enum HealthStatus: String, Codable, Sendable {
    case healthy
    case degraded
    case unhealthy
    case unknown
}

/// Detailed health metrics
public struct HealthMetrics: Codable, Sendable {
    /// Number of connected peers
    public let peerCount: Int

    /// Number of direct connections
    public let directConnectionCount: Int

    /// Number of relay connections
    public let relayCount: Int

    /// NAT type
    public let natType: NATType

    /// Public endpoint (if known)
    public let publicEndpoint: String?

    /// Uptime in seconds
    public let uptimeSeconds: TimeInterval

    /// Average latency to peers in milliseconds
    public let averageLatencyMs: Double?

    public init(
        peerCount: Int,
        directConnectionCount: Int,
        relayCount: Int,
        natType: NATType,
        publicEndpoint: String?,
        uptimeSeconds: TimeInterval,
        averageLatencyMs: Double?
    ) {
        self.peerCount = peerCount
        self.directConnectionCount = directConnectionCount
        self.relayCount = relayCount
        self.natType = natType
        self.publicEndpoint = publicEndpoint
        self.uptimeSeconds = uptimeSeconds
        self.averageLatencyMs = averageLatencyMs
    }
}

// MARK: - Message Service Messages

/// Peer-to-peer message
public struct PeerMessage: Codable, Sendable {
    /// Unique message ID
    public let messageId: UUID

    /// Message content
    public let content: Data

    /// When the message was sent
    public let sentAt: Date

    /// Whether delivery receipt is requested
    public let requestReceipt: Bool

    /// Application-defined message type (optional)
    public let messageType: String?

    public init(
        messageId: UUID = UUID(),
        content: Data,
        sentAt: Date = Date(),
        requestReceipt: Bool = false,
        messageType: String? = nil
    ) {
        self.messageId = messageId
        self.content = content
        self.sentAt = sentAt
        self.requestReceipt = requestReceipt
        self.messageType = messageType
    }
}

/// Message delivery receipt
public struct MessageReceipt: Codable, Sendable {
    /// ID of the message this receipt is for
    public let messageId: UUID

    /// Delivery status
    public let status: MessageStatus

    /// When the message was received
    public let receivedAt: Date

    public init(
        messageId: UUID,
        status: MessageStatus,
        receivedAt: Date = Date()
    ) {
        self.messageId = messageId
        self.status = status
        self.receivedAt = receivedAt
    }
}

/// Message delivery status
public enum MessageStatus: String, Codable, Sendable {
    case delivered
    case read
    case rejected
    case failed
}

// MARK: - Cloister Service Messages

/// Network key negotiation request
public struct CloisterRequest: Codable, Sendable {
    /// Unique request ID
    public let requestId: UUID

    /// Proposed network name
    public let networkName: String

    /// Ephemeral X25519 public key (32 bytes, base64 encoded)
    public let ephemeralPublicKey: Data

    /// Optional list of initial bootstrap peers
    public let proposedBootstraps: [String]?

    public init(
        requestId: UUID = UUID(),
        networkName: String,
        ephemeralPublicKey: Data,
        proposedBootstraps: [String]? = nil
    ) {
        self.requestId = requestId
        self.networkName = networkName
        self.ephemeralPublicKey = ephemeralPublicKey
        self.proposedBootstraps = proposedBootstraps
    }
}

/// Network key negotiation response
public struct CloisterResponse: Codable, Sendable {
    /// Matching request ID
    public let requestId: UUID

    /// Whether the request was accepted
    public let accepted: Bool

    /// Ephemeral X25519 public key (32 bytes, base64 encoded), nil if rejected
    public let ephemeralPublicKey: Data?

    /// Encrypted confirmation (proves key derivation succeeded)
    public let encryptedConfirmation: Data?

    /// Rejection reason (if not accepted)
    public let rejectReason: String?

    public init(
        requestId: UUID,
        accepted: Bool,
        ephemeralPublicKey: Data? = nil,
        encryptedConfirmation: Data? = nil,
        rejectReason: String? = nil
    ) {
        self.requestId = requestId
        self.accepted = accepted
        self.ephemeralPublicKey = ephemeralPublicKey
        self.encryptedConfirmation = encryptedConfirmation
        self.rejectReason = rejectReason
    }
}

/// Secure network invite share
public struct NetworkInviteShare: Codable, Sendable {
    /// Unique request ID
    public let requestId: UUID

    /// Ephemeral X25519 public key for key exchange
    public let ephemeralPublicKey: Data

    /// Encrypted invite data (ChaCha20-Poly1305 encrypted Cloister JSON)
    public let encryptedInvite: Data

    /// Optional unencrypted hint about the network name
    public let networkNameHint: String?

    public init(
        requestId: UUID = UUID(),
        ephemeralPublicKey: Data,
        encryptedInvite: Data,
        networkNameHint: String? = nil
    ) {
        self.requestId = requestId
        self.ephemeralPublicKey = ephemeralPublicKey
        self.encryptedInvite = encryptedInvite
        self.networkNameHint = networkNameHint
    }
}

/// Network invite share acknowledgment
public struct NetworkInviteAck: Codable, Sendable {
    /// Matching request ID
    public let requestId: UUID

    /// Ephemeral public key for key derivation
    public let ephemeralPublicKey: Data

    /// Whether the invite was accepted
    public let accepted: Bool

    /// Network ID if joined
    public let joinedNetworkId: String?

    /// Rejection reason
    public let rejectReason: String?

    public init(
        requestId: UUID,
        ephemeralPublicKey: Data,
        accepted: Bool,
        joinedNetworkId: String? = nil,
        rejectReason: String? = nil
    ) {
        self.requestId = requestId
        self.ephemeralPublicKey = ephemeralPublicKey
        self.accepted = accepted
        self.joinedNetworkId = joinedNetworkId
        self.rejectReason = rejectReason
    }
}

// MARK: - Two-Round Invite Protocol Messages

/// Initial invite request (round 1: client sends public key)
public struct InviteKeyExchangeRequest: Codable, Sendable {
    /// Unique request ID
    public let requestId: UUID

    /// Client's ephemeral X25519 public key
    public let ephemeralPublicKey: Data

    /// Optional unencrypted hint about the network name
    public let networkNameHint: String?

    public init(
        requestId: UUID = UUID(),
        ephemeralPublicKey: Data,
        networkNameHint: String? = nil
    ) {
        self.requestId = requestId
        self.ephemeralPublicKey = ephemeralPublicKey
        self.networkNameHint = networkNameHint
    }
}

/// Invite key exchange response (round 1: handler sends public key + accept/reject)
public struct InviteKeyExchangeResponse: Codable, Sendable {
    /// Matching request ID
    public let requestId: UUID

    /// Handler's ephemeral X25519 public key
    public let ephemeralPublicKey: Data

    /// Whether the handler accepted the invite request
    public let accepted: Bool

    /// Rejection reason (if not accepted)
    public let rejectReason: String?

    public init(
        requestId: UUID,
        ephemeralPublicKey: Data,
        accepted: Bool,
        rejectReason: String? = nil
    ) {
        self.requestId = requestId
        self.ephemeralPublicKey = ephemeralPublicKey
        self.accepted = accepted
        self.rejectReason = rejectReason
    }
}

/// Encrypted invite payload (round 2: client sends encrypted network key)
public struct InvitePayload: Codable, Sendable {
    /// Matching request ID
    public let requestId: UUID

    /// Network key encrypted with derived invite key (ChaCha20-Poly1305)
    public let encryptedNetworkKey: Data

    /// Optional encrypted network name
    public let encryptedNetworkName: Data?

    public init(
        requestId: UUID,
        encryptedNetworkKey: Data,
        encryptedNetworkName: Data? = nil
    ) {
        self.requestId = requestId
        self.encryptedNetworkKey = encryptedNetworkKey
        self.encryptedNetworkName = encryptedNetworkName
    }
}

/// Final invite acknowledgment (round 2: handler confirms receipt)
public struct InviteFinalAck: Codable, Sendable {
    /// Matching request ID
    public let requestId: UUID

    /// Whether the invite was successfully processed
    public let success: Bool

    /// Network ID that the handler joined
    public let joinedNetworkId: String?

    /// Error message if not successful
    public let error: String?

    public init(
        requestId: UUID,
        success: Bool,
        joinedNetworkId: String? = nil,
        error: String? = nil
    ) {
        self.requestId = requestId
        self.success = success
        self.joinedNetworkId = joinedNetworkId
        self.error = error
    }
}

/// Result of a successful cloister negotiation
public struct CloisterResult: Sendable {
    /// The derived network key
    public let networkKey: Data

    /// Network ID derived from the key
    public let networkId: String

    /// Network name
    public let networkName: String

    /// The machine we negotiated with
    public let sharedWith: MachineId

    public init(
        networkKey: Data,
        networkId: String,
        networkName: String,
        sharedWith: MachineId
    ) {
        self.networkKey = networkKey
        self.networkId = networkId
        self.networkName = networkName
        self.sharedWith = sharedWith
    }
}

/// Result of sharing a network invite
public struct NetworkInviteResult: Sendable {
    /// Whether the invite was accepted
    public let accepted: Bool

    /// Network ID the peer joined (if accepted)
    public let joinedNetworkId: String?

    /// Rejection reason (if not accepted)
    public let rejectReason: String?

    public init(
        accepted: Bool,
        joinedNetworkId: String? = nil,
        rejectReason: String? = nil
    ) {
        self.accepted = accepted
        self.joinedNetworkId = joinedNetworkId
        self.rejectReason = rejectReason
    }
}
