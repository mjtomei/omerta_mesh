// IdentityKeypair.swift - Ed25519 keypair for mesh node identity

import Foundation
@preconcurrency import Crypto

/// A mesh node's cryptographic identity using Ed25519
public struct IdentityKeypair: Sendable {
    /// The private signing key
    private let privateKey: Curve25519.Signing.PrivateKey

    /// The public verification key
    public let publicKey: Curve25519.Signing.PublicKey

    /// The peer ID derived from the public key (SHA256 first 8 bytes, hex encoded)
    /// Format: 16 lowercase hex characters (compatible with OmertaCore)
    public var peerId: PeerId {
        Self.derivePeerId(from: publicKey.rawRepresentation)
    }

    /// Derive peer ID from public key data
    /// Returns 16 lowercase hex characters (first 8 bytes of SHA256)
    public static func derivePeerId(from publicKeyData: Data) -> PeerId {
        let hash = SHA256.hash(data: publicKeyData)
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// Verify that a peer ID was correctly derived from a public key
    public static func verifyPeerIdDerivation(peerId: PeerId, publicKeyBase64: String) -> Bool {
        guard let keyData = Data(base64Encoded: publicKeyBase64) else { return false }
        let expected = derivePeerId(from: keyData)
        return peerId == expected
    }

    /// Create a new random keypair
    public init() {
        self.privateKey = Curve25519.Signing.PrivateKey()
        self.publicKey = privateKey.publicKey
    }

    /// Create from existing private key data
    public init(privateKeyData: Data) throws {
        self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        self.publicKey = privateKey.publicKey
    }

    /// Create from base64-encoded private key
    public init(privateKeyBase64: String) throws {
        guard let data = Data(base64Encoded: privateKeyBase64) else {
            throw IdentityError.invalidKeyFormat
        }
        try self.init(privateKeyData: data)
    }

    // MARK: - Signing

    /// Sign data and return the signature
    public func sign(_ data: Data) throws -> Signature {
        let signatureData = try privateKey.signature(for: data)
        return Signature(data: signatureData)
    }

    /// Sign a string message
    public func sign(_ message: String) throws -> Signature {
        guard let data = message.data(using: .utf8) else {
            throw IdentityError.encodingError
        }
        return try sign(data)
    }

    // MARK: - Serialization

    /// Export private key as raw bytes
    public var privateKeyData: Data {
        privateKey.rawRepresentation
    }

    /// Export private key as base64 string
    public var privateKeyBase64: String {
        privateKeyData.base64EncodedString()
    }

    /// Export public key as raw bytes
    public var publicKeyData: Data {
        publicKey.rawRepresentation
    }

    /// Export public key as base64 string
    public var publicKeyBase64: String {
        publicKeyData.base64EncodedString()
    }
}

/// A cryptographic signature
public struct Signature: Sendable, Codable, Equatable {
    /// The raw signature bytes
    public let data: Data

    /// Create from raw signature data
    public init(data: Data) {
        self.data = data
    }

    /// Create from base64-encoded signature
    public init?(base64: String) {
        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        self.data = data
    }

    /// Base64 representation
    public var base64: String {
        data.base64EncodedString()
    }

    /// Verify this signature against data using a public key
    public func verify(_ data: Data, publicKey: Curve25519.Signing.PublicKey) -> Bool {
        publicKey.isValidSignature(self.data, for: data)
    }

    /// Verify this signature against data using a public key from raw bytes
    public func verify(_ data: Data, publicKeyData: Data) -> Bool {
        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else {
            return false
        }
        return verify(data, publicKey: publicKey)
    }

    /// Verify this signature against data using a base64-encoded public key
    public func verify(_ data: Data, publicKeyBase64: String) -> Bool {
        guard let keyData = Data(base64Encoded: publicKeyBase64) else {
            return false
        }
        return verify(data, publicKeyData: keyData)
    }
}

/// Errors from identity operations
public enum IdentityError: Error, CustomStringConvertible {
    case invalidKeyFormat
    case encodingError
    case signatureVerificationFailed

    public var description: String {
        switch self {
        case .invalidKeyFormat:
            return "Invalid key format"
        case .encodingError:
            return "Failed to encode data"
        case .signatureVerificationFailed:
            return "Signature verification failed"
        }
    }
}

// MARK: - Public Key Utilities

extension Curve25519.Signing.PublicKey {
    /// Create from base64-encoded string
    public init?(base64: String) {
        guard let data = Data(base64Encoded: base64) else {
            return nil
        }
        try? self.init(rawRepresentation: data)
    }

    /// Peer ID derived from this public key (SHA256 first 8 bytes, hex encoded)
    public var peerId: PeerId {
        IdentityKeypair.derivePeerId(from: rawRepresentation)
    }
}
