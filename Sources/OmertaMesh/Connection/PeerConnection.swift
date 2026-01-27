// PeerConnection.swift - Represents a connection to a mesh peer

import Foundation
import Crypto
import NIOCore

/// Represents a connection to a mesh peer
public actor PeerConnection {
    /// The peer's ID (derived from public key)
    public let peerId: PeerId

    /// The peer's public key for signature verification
    public let publicKey: Curve25519.Signing.PublicKey

    /// The currently active endpoint (endpoint management now handled by PeerEndpointManager)
    public private(set) var activeEndpoint: String?

    /// Connection state
    public private(set) var state: ConnectionState = .disconnected

    /// When we last heard from this peer
    public private(set) var lastSeen: Date?

    /// Round-trip time estimate in milliseconds
    public private(set) var rttMs: Int?

    /// Message IDs we've already seen (for deduplication)
    private var seenMessageIds: Set<String> = []

    /// Maximum message IDs to track
    private let maxSeenMessages = 10000

    /// Pending requests awaiting responses
    private var pendingRequests: [String: CheckedContinuation<MeshMessage, Error>] = [:]

    /// Connection states
    public enum ConnectionState: Sendable {
        case disconnected
        case connecting
        case connected
        case failed(Error)
    }

    public init(peerId: PeerId, publicKey: Curve25519.Signing.PublicKey) {
        self.peerId = peerId
        self.publicKey = publicKey
    }

    /// Create from public key data
    public init(publicKeyData: Data) throws {
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        self.peerId = publicKey.peerId
        self.publicKey = publicKey
    }

    /// Create from base64 public key
    public init(publicKeyBase64: String) throws {
        guard let keyData = Data(base64Encoded: publicKeyBase64),
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData) else {
            throw PeerConnectionError.invalidPublicKey
        }
        self.peerId = publicKey.peerId
        self.publicKey = publicKey
    }

    // MARK: - Endpoint Management

    /// Set the active endpoint
    public func setActiveEndpoint(_ endpoint: String?) {
        activeEndpoint = endpoint
    }

    // MARK: - Connection State

    /// Mark as connecting
    public func markConnecting() {
        state = .connecting
    }

    /// Mark as connected
    public func markConnected() {
        state = .connected
        lastSeen = Date()
    }

    /// Mark as disconnected
    public func markDisconnected() {
        state = .disconnected
    }

    /// Mark as failed
    public func markFailed(_ error: Error) {
        state = .failed(error)
    }

    /// Update last seen time
    public func updateLastSeen() {
        lastSeen = Date()
        if case .connected = state {
            // Already connected
        } else {
            state = .connected
        }
    }

    /// Update RTT estimate
    public func updateRTT(_ ms: Int) {
        if let current = rttMs {
            // Exponential moving average
            rttMs = (current * 7 + ms) / 8
        } else {
            rttMs = ms
        }
    }

    // MARK: - Message Deduplication

    /// Check if we've seen this message ID before
    public func hasSeenMessage(_ messageId: String) -> Bool {
        seenMessageIds.contains(messageId)
    }

    /// Mark a message ID as seen
    public func markMessageSeen(_ messageId: String) {
        seenMessageIds.insert(messageId)

        // Prune if too large (simple strategy: clear half)
        if seenMessageIds.count > maxSeenMessages {
            let toRemove = seenMessageIds.prefix(maxSeenMessages / 2)
            for id in toRemove {
                seenMessageIds.remove(id)
            }
        }
    }

    // MARK: - Signature Verification

    /// Verify a signature from this peer
    public func verifySignature(_ signature: Signature, for data: Data) -> Bool {
        signature.verify(data, publicKey: publicKey)
    }

    // MARK: - Request/Response

    /// Store a pending request
    public func storePendingRequest(id: String, continuation: CheckedContinuation<MeshMessage, Error>) {
        pendingRequests[id] = continuation
    }

    /// Complete a pending request
    public func completePendingRequest(id: String, with response: MeshMessage) -> Bool {
        guard let continuation = pendingRequests.removeValue(forKey: id) else {
            return false
        }
        continuation.resume(returning: response)
        return true
    }

    /// Fail a pending request
    public func failPendingRequest(id: String, with error: Error) -> Bool {
        guard let continuation = pendingRequests.removeValue(forKey: id) else {
            return false
        }
        continuation.resume(throwing: error)
        return true
    }

    /// Fail all pending requests
    public func failAllPendingRequests(with error: Error) {
        for (_, continuation) in pendingRequests {
            continuation.resume(throwing: error)
        }
        pendingRequests.removeAll()
    }
}

/// Errors from peer connection operations
public enum PeerConnectionError: Error, CustomStringConvertible {
    case invalidPublicKey
    case noEndpoint
    case timeout
    case signatureVerificationFailed

    public var description: String {
        switch self {
        case .invalidPublicKey:
            return "Invalid public key"
        case .noEndpoint:
            return "No endpoint available for peer"
        case .timeout:
            return "Connection timed out"
        case .signatureVerificationFailed:
            return "Signature verification failed"
        }
    }
}
