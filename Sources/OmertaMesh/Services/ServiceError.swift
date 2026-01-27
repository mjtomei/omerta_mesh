// ServiceError.swift - Error types for utility services

import Foundation

/// Errors that can occur in utility services
public enum ServiceError: Error, LocalizedError, Sendable {
    /// Request timed out waiting for response
    case timeout

    /// Peer is unreachable
    case peerUnreachable(PeerId)

    /// Response was invalid or couldn't be decoded
    case invalidResponse

    /// Request was rejected by the peer
    case rejected(reason: String)

    /// Service has not been started
    case notStarted

    /// Service is already running
    case alreadyRunning

    /// Channel registration failed
    case channelRegistrationFailed(String)

    /// Encoding/decoding failed
    case encodingFailed(String)

    /// Key exchange failed
    case keyExchangeFailed(String)

    /// Cryptographic operation failed
    case cryptoFailed(String)

    /// Invalid request parameters
    case invalidRequest(String)

    /// Handler not set
    case noHandler

    public var errorDescription: String? {
        switch self {
        case .timeout:
            return "Request timed out"
        case .peerUnreachable(let peerId):
            return "Peer \(peerId.prefix(8))... is unreachable"
        case .invalidResponse:
            return "Received invalid response"
        case .rejected(let reason):
            return "Request rejected: \(reason)"
        case .notStarted:
            return "Service has not been started"
        case .alreadyRunning:
            return "Service is already running"
        case .channelRegistrationFailed(let channel):
            return "Failed to register channel: \(channel)"
        case .encodingFailed(let detail):
            return "Encoding failed: \(detail)"
        case .keyExchangeFailed(let detail):
            return "Key exchange failed: \(detail)"
        case .cryptoFailed(let detail):
            return "Cryptographic operation failed: \(detail)"
        case .invalidRequest(let detail):
            return "Invalid request: \(detail)"
        case .noHandler:
            return "No handler registered for this request"
        }
    }
}
