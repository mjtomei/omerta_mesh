// NetworkKey.swift - Shareable network invite key

import Foundation
import Crypto

#if canImport(Security)
import Security
#endif

/// Network key structure (encoded as JSON, then base64)
/// Contains the symmetric encryption key, network name, and bootstrap peers
public struct NetworkKey: Sendable, Codable, Equatable {
    /// 256-bit symmetric key for message encryption
    public let networkKey: Data

    /// Human-readable network name
    public let networkName: String

    /// Bootstrap peers for initial discovery (array of "host:port" strings)
    public let bootstrapPeers: [String]

    /// When this key was created
    public let createdAt: Date

    public init(
        networkKey: Data,
        networkName: String,
        bootstrapPeers: [String],
        createdAt: Date = Date()
    ) {
        self.networkKey = networkKey
        self.networkName = networkName
        self.bootstrapPeers = bootstrapPeers
        self.createdAt = createdAt
    }

    // MARK: - Encoding/Decoding

    /// Encode network key as base64 string with omerta:// prefix
    public func encode() throws -> String {
        let jsonData = try JSONCoding.iso8601Encoder.encode(self)
        let base64 = jsonData.base64EncodedString()
        return "omerta://join/\(base64)"
    }

    /// Decode network key from omerta:// string
    public static func decode(from string: String) throws -> NetworkKey {
        guard string.hasPrefix("omerta://join/") else {
            throw NetworkKeyError.invalidFormat
        }

        let base64 = String(string.dropFirst("omerta://join/".count))
        guard let jsonData = Data(base64Encoded: base64) else {
            throw NetworkKeyError.invalidBase64
        }

        do {
            return try JSONCoding.iso8601Decoder.decode(NetworkKey.self, from: jsonData)
        } catch {
            throw NetworkKeyError.decodingFailed
        }
    }

    // MARK: - Generation

    /// Generate a new random network key
    public static func generate(
        networkName: String,
        bootstrapPeers: [String] = []
    ) -> NetworkKey {
        var keyData = Data(count: 32)  // 256 bits
        #if canImport(Security)
        _ = keyData.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, 32, bytes.baseAddress!)
        }
        #else
        // On Linux, use SystemRandomNumberGenerator
        var rng = SystemRandomNumberGenerator()
        keyData = Data((0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) })
        #endif

        return NetworkKey(
            networkKey: keyData,
            networkName: networkName,
            bootstrapPeers: bootstrapPeers
        )
    }

    // MARK: - Derived Values

    /// Derive network ID from key (SHA256 hash, first 8 bytes hex-encoded)
    /// Format matches peer ID format: 16 lowercase hex characters
    public func deriveNetworkId() -> String {
        let hash = SHA256.hash(data: networkKey)
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Bootstrap Peer Management

    /// Create a copy with different bootstrap peers
    /// - Parameter peers: New list of bootstrap peers (format: "peerId@host:port")
    /// - Returns: New NetworkKey with same encryption key but different bootstrap peers
    public func withBootstrapPeers(_ peers: [String]) -> NetworkKey {
        NetworkKey(
            networkKey: networkKey,
            networkName: networkName,
            bootstrapPeers: peers,
            createdAt: createdAt
        )
    }

    /// Create a copy with an additional bootstrap peer
    /// - Parameter peer: Bootstrap peer to add (format: "peerId@host:port")
    /// - Returns: New NetworkKey with the peer added (if not already present)
    public func addingBootstrapPeer(_ peer: String) -> NetworkKey {
        if bootstrapPeers.contains(peer) {
            return self
        }
        return withBootstrapPeers(bootstrapPeers + [peer])
    }

    /// Create a copy with a bootstrap peer removed
    /// - Parameter peer: Bootstrap peer to remove
    /// - Returns: New NetworkKey with the peer removed
    public func removingBootstrapPeer(_ peer: String) -> NetworkKey {
        withBootstrapPeers(bootstrapPeers.filter { $0 != peer })
    }
}

// MARK: - Errors

/// Network key errors
public enum NetworkKeyError: Error, LocalizedError {
    case invalidFormat
    case invalidBase64
    case decodingFailed

    public var errorDescription: String? {
        switch self {
        case .invalidFormat:
            return "Invalid network key format (expected omerta://join/...)"
        case .invalidBase64:
            return "Invalid base64 encoding in network key"
        case .decodingFailed:
            return "Failed to decode network key data"
        }
    }
}
