// KeyExchange.swift - Shared X25519 key exchange state machine
//
// Provides a common key exchange implementation for both negotiate() and shareInvite()
// protocols. Ensures both sides derive identical shared secrets.

import Foundation
import Crypto

/// Shared state machine for X25519 key exchange
/// Used by both negotiate() and shareInvite() protocols
public actor KeyExchangeSession {
    /// Our ephemeral private key
    private let privateKey: Curve25519.KeyAgreement.PrivateKey

    /// Our public key to send to peer
    public let publicKey: Data

    /// Peer's public key (set after exchange)
    private var peerPublicKey: Data?

    /// Computed shared secret (set after exchange)
    private var sharedSecret: SharedSecret?

    /// Initialize a new key exchange session with a fresh ephemeral keypair
    public init() {
        self.privateKey = Curve25519.KeyAgreement.PrivateKey()
        self.publicKey = Data(privateKey.publicKey.rawRepresentation)
    }

    /// Set peer's public key and compute the shared secret
    /// - Parameter peerPublicKey: The peer's X25519 public key (32 bytes)
    /// - Throws: KeyExchangeError if the key is invalid
    public func completeExchange(peerPublicKey: Data) throws {
        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        self.peerPublicKey = peerPublicKey
        self.sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerKey)
    }

    /// Derive a symmetric key for a specific purpose using HKDF
    /// - Parameter info: Context string for key derivation (e.g., "omerta-network-key")
    /// - Returns: A 256-bit symmetric key
    /// - Throws: KeyExchangeError if exchange not complete
    public func deriveKey(info: String) throws -> SymmetricKey {
        guard let secret = sharedSecret else {
            throw KeyExchangeError.exchangeNotComplete
        }
        return secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(info.utf8),
            outputByteCount: 32
        )
    }

    /// Derive network key (for negotiate protocol)
    /// - Returns: 32-byte network key as Data
    /// - Throws: KeyExchangeError if exchange not complete
    public func deriveNetworkKey() throws -> Data {
        let key = try deriveKey(info: "omerta-network-key")
        return key.withUnsafeBytes { Data($0) }
    }

    /// Derive invite encryption key (for shareInvite protocol)
    /// - Returns: SymmetricKey for ChaCha20-Poly1305 encryption
    /// - Throws: KeyExchangeError if exchange not complete
    public func deriveInviteKey() throws -> SymmetricKey {
        return try deriveKey(info: "omerta-invite-key")
    }

    /// Check if the key exchange has been completed
    public var isComplete: Bool {
        sharedSecret != nil
    }
}

/// Errors that can occur during key exchange
public enum KeyExchangeError: Error, LocalizedError {
    case exchangeNotComplete
    case invalidPublicKey

    public var errorDescription: String? {
        switch self {
        case .exchangeNotComplete:
            return "Key exchange has not been completed"
        case .invalidPublicKey:
            return "Invalid public key format"
        }
    }
}
