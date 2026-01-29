// MeshError.swift - Error types for the mesh network public API

import Foundation

/// Errors that can occur in mesh network operations
public enum MeshError: Error, Sendable, Equatable, CustomStringConvertible {
    // MARK: - Connection Errors

    /// The specified peer was not found
    case peerNotFound(peerId: PeerId)

    /// Connection to the peer failed
    case connectionFailed(peerId: PeerId, reason: String)

    /// Connection timed out
    case timeout(operation: String)

    /// The peer is unreachable (all paths failed)
    case peerUnreachable(peerId: PeerId)

    // MARK: - Network Errors

    /// The mesh network is not started
    case notStarted

    /// The mesh network is already started
    case alreadyStarted

    /// Failed to bind to the specified port
    case bindFailed(port: Int, reason: String)

    /// NAT detection failed
    case natDetectionFailed(reason: String)

    /// No relays available
    case noRelaysAvailable

    /// No bootstrap peers available
    case noBootstrapPeers

    // MARK: - Hole Punch Errors

    /// Hole punching failed
    case holePunchFailed(peerId: PeerId, reason: String)

    /// Hole punching is not possible (both peers have symmetric NAT)
    case holePunchImpossible(peerId: PeerId)

    /// No coordinator available for hole punching
    case noCoordinatorAvailable

    // MARK: - Message Errors

    /// Failed to send message
    case sendFailed(reason: String)

    /// Invalid message format
    case invalidMessage(reason: String)

    /// Message was rejected by peer
    case messageRejected(reason: String)

    // MARK: - Configuration Errors

    /// Invalid configuration
    case invalidConfiguration(reason: String)

    // MARK: - Internal Errors

    /// An internal error occurred
    case internalError(reason: String)

    // MARK: - CustomStringConvertible

    public var description: String {
        switch self {
        case .peerNotFound(let peerId):
            return "Peer not found: \(peerId)"
        case .connectionFailed(let peerId, let reason):
            return "Connection to \(peerId) failed: \(reason)"
        case .timeout(let operation):
            return "Operation timed out: \(operation)"
        case .peerUnreachable(let peerId):
            return "Peer unreachable: \(peerId)"
        case .notStarted:
            return "Mesh network not started"
        case .alreadyStarted:
            return "Mesh network already started"
        case .bindFailed(let port, let reason):
            return "Failed to bind to port \(port): \(reason)"
        case .natDetectionFailed(let reason):
            return "NAT detection failed: \(reason)"
        case .noRelaysAvailable:
            return "No relay servers available"
        case .noBootstrapPeers:
            return "No bootstrap peers available"
        case .holePunchFailed(let peerId, let reason):
            return "Hole punch to \(peerId) failed: \(reason)"
        case .holePunchImpossible(let peerId):
            return "Hole punch to \(peerId) impossible (symmetric NAT)"
        case .noCoordinatorAvailable:
            return "No hole punch coordinator available"
        case .sendFailed(let reason):
            return "Failed to send message: \(reason)"
        case .invalidMessage(let reason):
            return "Invalid message: \(reason)"
        case .messageRejected(let reason):
            return "Message rejected: \(reason)"
        case .invalidConfiguration(let reason):
            return "Invalid configuration: \(reason)"
        case .internalError(let reason):
            return "Internal error: \(reason)"
        }
    }

    // MARK: - Categorization

    /// Whether this error is recoverable
    public var isRecoverable: Bool {
        switch self {
        case .timeout, .connectionFailed, .holePunchFailed,
             .sendFailed, .noRelaysAvailable, .noCoordinatorAvailable:
            return true
        case .peerNotFound, .peerUnreachable, .notStarted, .alreadyStarted,
             .bindFailed, .natDetectionFailed, .noBootstrapPeers,
             .holePunchImpossible, .invalidMessage, .messageRejected,
             .invalidConfiguration, .internalError:
            return false
        }
    }

    /// Whether this error should trigger a retry
    public var shouldRetry: Bool {
        switch self {
        case .timeout, .connectionFailed, .sendFailed:
            return true
        default:
            return false
        }
    }
}

/// Extension to convert internal errors to MeshError
extension MeshNodeError {
    /// Convert to MeshError
    public var asMeshError: MeshError {
        switch self {
        case .stopped:
            return .notStarted
        case .timeout:
            return .timeout(operation: "network operation")
        case .peerNotFound:
            return .peerNotFound(peerId: "unknown")
        case .sendFailed(let error):
            return .sendFailed(reason: error.localizedDescription)
        case .noRelayAvailable:
            return .sendFailed(reason: "No relay available for symmetric NAT peer")
        case .invalidChannel(let channel):
            return .sendFailed(reason: "Invalid channel '\(channel)': must be max 64 chars, alphanumeric/-/_ only")
        }
    }
}

/// Extension to convert hole punch failures to MeshError
extension HolePunchFailure {
    /// Convert to MeshError for a specific peer
    public func asMeshError(for peerId: PeerId) -> MeshError {
        switch self {
        case .timeout:
            return .holePunchFailed(peerId: peerId, reason: "timeout")
        case .bothSymmetric:
            return .holePunchImpossible(peerId: peerId)
        case .bindFailed:
            return .holePunchFailed(peerId: peerId, reason: "bind failed")
        case .invalidEndpoint(let ep):
            return .holePunchFailed(peerId: peerId, reason: "invalid endpoint: \(ep)")
        case .cancelled:
            return .holePunchFailed(peerId: peerId, reason: "cancelled")
        case .socketError(let msg):
            return .holePunchFailed(peerId: peerId, reason: msg)
        case .noServices:
            return .holePunchFailed(peerId: peerId, reason: "no services available")
        }
    }
}
