// MessageEncryption.swift - ChaCha20-Poly1305 message encryption

import Foundation
import Crypto

/// Symmetric message encryption using ChaCha20-Poly1305
public enum MessageEncryption {

    /// Encrypt data using ChaCha20-Poly1305
    /// - Parameters:
    ///   - data: The plaintext data to encrypt
    ///   - key: 256-bit (32 byte) symmetric key
    /// - Returns: Combined format: [12-byte nonce][ciphertext][16-byte tag]
    public static func encrypt(_ data: Data, key: Data) throws -> Data {
        guard key.count == 32 else {
            throw MessageEncryptionError.invalidKeySize
        }

        let symmetricKey = SymmetricKey(data: key)
        let nonce = ChaChaPoly.Nonce()
        let sealedBox = try ChaChaPoly.seal(data, using: symmetricKey, nonce: nonce)

        return sealedBox.combined
    }

    /// Decrypt data using ChaCha20-Poly1305
    /// - Parameters:
    ///   - data: Combined format: [12-byte nonce][ciphertext][16-byte tag]
    ///   - key: 256-bit (32 byte) symmetric key
    /// - Returns: Decrypted plaintext data
    public static func decrypt(_ data: Data, key: Data) throws -> Data {
        guard key.count == 32 else {
            throw MessageEncryptionError.invalidKeySize
        }

        guard data.count >= 28 else {  // 12 (nonce) + 16 (tag) minimum
            throw MessageEncryptionError.dataTooShort
        }

        let symmetricKey = SymmetricKey(data: key)
        let sealedBox = try ChaChaPoly.SealedBox(combined: data)

        return try ChaChaPoly.open(sealedBox, using: symmetricKey)
    }
}

// MARK: - Errors

public enum MessageEncryptionError: Error, LocalizedError {
    case invalidKeySize
    case dataTooShort
    case decryptionFailed

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize:
            return "Encryption key must be 32 bytes (256 bits)"
        case .dataTooShort:
            return "Encrypted data is too short to contain nonce and tag"
        case .decryptionFailed:
            return "Failed to decrypt message (wrong key or corrupted data)"
        }
    }
}
