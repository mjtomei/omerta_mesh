// BinaryEnvelopeV2.swift - Wire Format v2 with layered encryption
//
// Format structure:
// UNENCRYPTED PREFIX (5 bytes):
//   [4 bytes] magic "OMRT"
//   [1 byte]  version 0x02
//
// HEADER SECTION:
//   [12 bytes] nonce
//   [8 bytes]  header_tag (truncated Poly1305)
//   [2 bytes]  header_length
//   [N bytes]  encrypted header data
//
// PAYLOAD SECTION:
//   [4 bytes]  payload_length
//   [M bytes]  encrypted payload data
//   [16 bytes] payload_tag (full Poly1305)

import Foundation
import Crypto

/// Encrypted data ready for network transmission.
/// Can only be constructed by BinaryEnvelopeV2 encryption methods.
public struct SealedEnvelope: Sendable {
    /// The encrypted bytes. Read-only for sending.
    public let data: Data

    /// Only constructible from within this file (encryption methods).
    fileprivate init(data: Data) {
        self.data = data
    }

    /// Wrap data that is already encrypted (e.g., relay forwarding).
    /// Internal-only: callers within the module can vouch for already-encrypted data.
    internal init(trustedData: Data) {
        self.data = trustedData
    }
}

/// Wire format v2 implementation with layered encryption
public enum BinaryEnvelopeV2 {
    /// Magic bytes identifying Omerta packets
    public static let magic = Data("OMRT".utf8)

    /// Wire format version
    public static let version: UInt8 = 0x02

    /// Size of the unencrypted prefix (magic + version)
    public static let prefixSize = 5

    /// Size of the nonce
    public static let nonceSize = 12

    /// Size of the truncated header authentication tag
    public static let headerTagSize = 8

    /// Size of the header length field
    public static let headerLengthSize = 2

    /// Size of the payload length field
    public static let payloadLengthSize = 4

    /// Size of the full payload authentication tag
    public static let payloadTagSize = 16

    /// HKDF info string for header key derivation
    private static let headerKeyInfo = Data("omerta-header-v2".utf8)

    // MARK: - Network Hash

    /// Compute the 8-byte network hash from the network key
    public static func computeNetworkHash(_ networkKey: Data) -> Data {
        let hash = SHA256.hash(data: networkKey)
        return Data(hash.prefix(8))
    }

    // MARK: - Key Derivation

    /// Derive the header encryption key from the network key
    private static func deriveHeaderKey(from networkKey: Data) -> SymmetricKey {
        let inputKey = SymmetricKey(data: networkKey)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            info: headerKeyInfo,
            outputByteCount: 32
        )
    }

    // MARK: - Encoding

    /// Encode a complete envelope with layered encryption
    /// - Parameters:
    ///   - header: The envelope header
    ///   - payload: The payload data (already JSON-encoded MeshMessage)
    ///   - networkKey: The 256-bit network encryption key
    /// - Returns: The complete encrypted packet
    public static func encode(
        header: EnvelopeHeader,
        payload: Data,
        networkKey: Data
    ) throws -> SealedEnvelope {
        // Generate random nonce using ChaChaPoly's nonce generator
        let headerNonceValue = ChaChaPoly.Nonce()
        let headerNonce = Array(headerNonceValue)

        // Derive body nonce (XOR last byte with 0x01)
        var bodyNonce = headerNonce
        bodyNonce[11] ^= 0x01

        // Derive header key
        let headerKey = deriveHeaderKey(from: networkKey)
        let payloadKey = SymmetricKey(data: networkKey)

        // Encode header to binary
        let headerData = try header.encode()

        // Encrypt header with ChaCha20-Poly1305
        let headerSealedBox = try ChaChaPoly.seal(headerData, using: headerKey, nonce: headerNonceValue)

        // Encrypt payload with ChaCha20-Poly1305
        let bodyNonceValue = try ChaChaPoly.Nonce(data: bodyNonce)
        let payloadSealedBox = try ChaChaPoly.seal(payload, using: payloadKey, nonce: bodyNonceValue)

        // Build the packet
        var writer = BinaryWriter(capacity: prefixSize + nonceSize + headerTagSize + headerLengthSize +
                                           headerData.count + payloadLengthSize + payload.count + payloadTagSize + 50)

        // Unencrypted prefix
        writer.writeBytes(magic)
        writer.writeByte(version)

        // Header section
        writer.writeBytes(Data(headerNonce))
        writer.writeBytes(headerSealedBox.tag.prefix(headerTagSize))  // Truncated tag
        writer.writeUInt16(UInt16(headerSealedBox.ciphertext.count))
        writer.writeBytes(headerSealedBox.ciphertext)

        // Payload section
        writer.writeUInt32(UInt32(payloadSealedBox.ciphertext.count))
        writer.writeBytes(payloadSealedBox.ciphertext)
        writer.writeBytes(payloadSealedBox.tag)  // Full 16-byte tag

        return SealedEnvelope(data: writer.data)
    }

    // MARK: - Fast Path Rejection

    /// Check if data has valid magic and version (O(1) check)
    /// Use this for fast rejection of non-Omerta packets
    public static func isValidPrefix(_ data: Data) -> Bool {
        guard data.count >= prefixSize else { return false }
        return data.prefix(4) == magic && data[4] == version
    }

    // MARK: - Full Decoding

    /// Decode the complete envelope (header + payload)
    /// Use this when you need the full message content
    public static func decode(
        _ data: Data,
        networkKey: Data
    ) throws -> (header: EnvelopeHeader, payload: Data) {
        // For the initial implementation, use full 16-byte tags for both
        // This simplifies the crypto at the cost of 8 extra bytes

        // Check minimum size
        let minSize = prefixSize + nonceSize + 16 + headerLengthSize
        guard data.count >= minSize else {
            throw EnvelopeError.truncatedPacket
        }

        // Verify magic
        guard data.prefix(4) == magic else {
            throw EnvelopeError.invalidMagic
        }

        // Verify version
        let packetVersion = data[4]
        guard packetVersion == version else {
            throw EnvelopeError.unsupportedVersion(packetVersion)
        }

        // Extract header nonce
        let nonceStart = 5
        let headerNonce = Array(data[nonceStart..<(nonceStart + nonceSize)])

        // Derive body nonce
        var bodyNonce = headerNonce
        bodyNonce[11] ^= 0x01

        // Extract header tag (full 16 bytes for now)
        let headerTagStart = nonceStart + nonceSize
        let headerTag = Data(data[headerTagStart..<(headerTagStart + 16)])

        // Extract header length
        let lengthStart = headerTagStart + 16
        let headerLength = UInt16(data[lengthStart]) << 8 | UInt16(data[lengthStart + 1])

        // Extract encrypted header
        let headerDataStart = lengthStart + headerLengthSize
        let headerDataEnd = headerDataStart + Int(headerLength)
        guard data.count >= headerDataEnd else {
            throw EnvelopeError.truncatedPacket
        }
        let encryptedHeader = Data(data[headerDataStart..<headerDataEnd])

        // Decrypt header
        let headerKey = deriveHeaderKey(from: networkKey)
        let headerNonceValue = try ChaChaPoly.Nonce(data: headerNonce)
        let headerSealedBox = try ChaChaPoly.SealedBox(
            nonce: headerNonceValue,
            ciphertext: encryptedHeader,
            tag: headerTag
        )
        let headerData = try ChaChaPoly.open(headerSealedBox, using: headerKey)
        let header = try EnvelopeHeader.decode(from: headerData)

        // Verify network hash
        let expectedHash = computeNetworkHash(networkKey)
        guard header.networkHash == expectedHash else {
            throw EnvelopeError.networkMismatch
        }

        // Extract payload length
        let payloadLengthStart = headerDataEnd
        guard data.count >= payloadLengthStart + payloadLengthSize else {
            throw EnvelopeError.truncatedPacket
        }
        var reader = BinaryReader(data)
        reader.offset = payloadLengthStart
        let payloadLength = try reader.readUInt32()

        // Extract encrypted payload and tag
        let payloadDataStart = payloadLengthStart + payloadLengthSize
        let payloadDataEnd = payloadDataStart + Int(payloadLength)
        let payloadTagEnd = payloadDataEnd + payloadTagSize
        guard data.count >= payloadTagEnd else {
            throw EnvelopeError.truncatedPacket
        }
        let encryptedPayload = Data(data[payloadDataStart..<payloadDataEnd])
        let payloadTag = Data(data[payloadDataEnd..<payloadTagEnd])

        // Decrypt payload
        let payloadKey = SymmetricKey(data: networkKey)
        let bodyNonceValue = try ChaChaPoly.Nonce(data: bodyNonce)
        let payloadSealedBox = try ChaChaPoly.SealedBox(
            nonce: bodyNonceValue,
            ciphertext: encryptedPayload,
            tag: payloadTag
        )
        let payload = try ChaChaPoly.open(payloadSealedBox, using: payloadKey)

        return (header, payload)
    }
}

// MARK: - Updated Encode with Full Header Tag

extension BinaryEnvelopeV2 {
    /// Encode with full 16-byte header tag (matches decode expectations)
    public static func encodeV2(
        header: EnvelopeHeader,
        payload: Data,
        networkKey: Data
    ) throws -> SealedEnvelope {
        // Generate random nonce using ChaChaPoly's nonce generator
        let headerNonceValue = ChaChaPoly.Nonce()
        let headerNonce = Array(headerNonceValue)

        // Derive body nonce (XOR last byte with 0x01)
        var bodyNonce = headerNonce
        bodyNonce[11] ^= 0x01

        // Derive header key
        let headerKey = deriveHeaderKey(from: networkKey)
        let payloadKey = SymmetricKey(data: networkKey)

        // Encode header to binary
        let headerData = try header.encode()

        // Encrypt header with ChaCha20-Poly1305
        let headerSealedBox = try ChaChaPoly.seal(headerData, using: headerKey, nonce: headerNonceValue)

        // Encrypt payload with ChaCha20-Poly1305
        let bodyNonceValue = try ChaChaPoly.Nonce(data: bodyNonce)
        let payloadSealedBox = try ChaChaPoly.seal(payload, using: payloadKey, nonce: bodyNonceValue)

        // Build the packet with full 16-byte header tag
        var writer = BinaryWriter(capacity: prefixSize + nonceSize + 16 + headerLengthSize +
                                           headerData.count + payloadLengthSize + payload.count + payloadTagSize + 50)

        // Unencrypted prefix
        writer.writeBytes(magic)
        writer.writeByte(version)

        // Header section (with full 16-byte tag)
        writer.writeBytes(Data(headerNonce))
        writer.writeBytes(headerSealedBox.tag)  // Full 16-byte tag
        writer.writeUInt16(UInt16(headerSealedBox.ciphertext.count))
        writer.writeBytes(headerSealedBox.ciphertext)

        // Payload section
        writer.writeUInt32(UInt32(payloadSealedBox.ciphertext.count))
        writer.writeBytes(payloadSealedBox.ciphertext)
        writer.writeBytes(payloadSealedBox.tag)  // Full 16-byte tag

        return SealedEnvelope(data: writer.data)
    }
}

// MARK: - MeshEnvelope Integration

extension MeshEnvelope {
    /// Encode envelope using v2 wire format
    public func encodeV2(networkKey: Data) throws -> SealedEnvelope {
        // Create header from envelope fields
        let networkHash = BinaryEnvelopeV2.computeNetworkHash(networkKey)

        // Convert channel string to UInt16 hash
        let channelHash = ChannelHash.hash(channel)

        // Convert messageId string to UUID (parse if valid UUID, or generate deterministically)
        let messageUUID: UUID
        if let uuid = UUID(uuidString: messageId) {
            messageUUID = uuid
        } else {
            // Generate deterministic UUID from messageId string using FNV-1a
            messageUUID = UUID.fromString(messageId)
        }

        // Convert base64 publicKey to raw bytes
        guard let publicKeyData = Data(base64Encoded: publicKey),
              publicKeyData.count == EnvelopeHeader.publicKeySize else {
            throw EnvelopeError.invalidPublicKeySize
        }

        // Convert base64 signature to raw bytes
        guard let signatureData = Data(base64Encoded: signature),
              signatureData.count == EnvelopeHeader.signatureSize else {
            throw EnvelopeError.invalidSignatureSize
        }

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: fromPeerId,
            toPeerId: toPeerId,
            channel: channelHash,
            channelString: channel,  // Preserve original channel string for signature verification
            hopCount: UInt8(min(max(hopCount, 0), 255)),
            timestamp: timestamp,
            messageId: messageUUID,
            machineId: machineId,
            publicKey: publicKeyData,
            signature: signatureData
        )

        // Encode payload as JSON
        let payloadData = try JSONCoding.encoder.encode(payload)

        return try BinaryEnvelopeV2.encodeV2(header: header, payload: payloadData, networkKey: networkKey)
    }

    /// Decode envelope from v2 wire format
    /// The original channel string is preserved for signature verification
    public static func decodeV2(_ data: Data, networkKey: Data) throws -> MeshEnvelope {
        let (header, payloadData) = try BinaryEnvelopeV2.decode(data, networkKey: networkKey)
        let payload = try JSONCoding.decoder.decode(MeshMessage.self, from: payloadData)

        // Convert UUID to string
        let messageId = header.messageId.uuidString

        // Convert raw publicKey bytes to base64
        let publicKey = header.publicKey.base64EncodedString()

        // Convert raw signature bytes to base64
        let signature = header.signature.base64EncodedString()

        return MeshEnvelope(
            messageId: messageId,
            fromPeerId: header.fromPeerId,
            publicKey: publicKey,
            machineId: header.machineId,
            toPeerId: header.toPeerId,
            channel: header.channelString,  // Use preserved channel string
            hopCount: Int(header.hopCount),
            timestamp: header.timestamp,
            payload: payload,
            signature: signature
        )
    }

    /// Decode envelope from v2 wire format, returning the raw channel hash
    /// Use this when you need to match against known channel hashes
    public static func decodeV2WithHash(_ data: Data, networkKey: Data) throws -> (envelope: MeshEnvelope, channelHash: UInt16) {
        let (header, payloadData) = try BinaryEnvelopeV2.decode(data, networkKey: networkKey)
        let payload = try JSONCoding.decoder.decode(MeshMessage.self, from: payloadData)

        let messageId = header.messageId.uuidString
        let publicKey = header.publicKey.base64EncodedString()
        let signature = header.signature.base64EncodedString()

        let envelope = MeshEnvelope(
            messageId: messageId,
            fromPeerId: header.fromPeerId,
            publicKey: publicKey,
            machineId: header.machineId,
            toPeerId: header.toPeerId,
            channel: header.channelString,  // Use preserved channel string
            hopCount: Int(header.hopCount),
            timestamp: header.timestamp,
            payload: payload,
            signature: signature
        )

        return (envelope, header.channel)
    }
}

// MARK: - UUID Extension for deterministic generation from string

extension UUID {
    /// Generate a deterministic UUID from a string using FNV-1a hash
    static func fromString(_ string: String) -> UUID {
        // FNV-1a hash to generate 128 bits
        var hash1: UInt64 = 14695981039346656037
        var hash2: UInt64 = 14695981039346656037

        for (i, byte) in string.utf8.enumerated() {
            if i % 2 == 0 {
                hash1 ^= UInt64(byte)
                hash1 &*= 1099511628211
            } else {
                hash2 ^= UInt64(byte)
                hash2 &*= 1099511628211
            }
        }

        // Combine into UUID bytes
        var uuid: uuid_t = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        withUnsafeMutableBytes(of: &uuid) { ptr in
            ptr[0] = UInt8(truncatingIfNeeded: hash1)
            ptr[1] = UInt8(truncatingIfNeeded: hash1 >> 8)
            ptr[2] = UInt8(truncatingIfNeeded: hash1 >> 16)
            ptr[3] = UInt8(truncatingIfNeeded: hash1 >> 24)
            ptr[4] = UInt8(truncatingIfNeeded: hash1 >> 32)
            ptr[5] = UInt8(truncatingIfNeeded: hash1 >> 40)
            ptr[6] = UInt8(truncatingIfNeeded: hash1 >> 48)
            ptr[7] = UInt8(truncatingIfNeeded: hash1 >> 56)
            ptr[8] = UInt8(truncatingIfNeeded: hash2)
            ptr[9] = UInt8(truncatingIfNeeded: hash2 >> 8)
            ptr[10] = UInt8(truncatingIfNeeded: hash2 >> 16)
            ptr[11] = UInt8(truncatingIfNeeded: hash2 >> 24)
            ptr[12] = UInt8(truncatingIfNeeded: hash2 >> 32)
            ptr[13] = UInt8(truncatingIfNeeded: hash2 >> 40)
            ptr[14] = UInt8(truncatingIfNeeded: hash2 >> 48)
            ptr[15] = UInt8(truncatingIfNeeded: hash2 >> 56)
        }

        // Set version (4) and variant (RFC 4122) bits
        uuid.6 = (uuid.6 & 0x0F) | 0x40  // Version 4
        uuid.8 = (uuid.8 & 0x3F) | 0x80  // Variant RFC 4122

        return UUID(uuid: uuid)
    }
}
