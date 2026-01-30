// BinaryEnvelopeV2.swift - Wire Format v3 with split routing/auth/payload encryption
//
// Format structure:
// UNENCRYPTED PREFIX (4 bytes):
//   [3 bytes] magic "OMR"
//   [1 byte]  version 0x03
//
// ROUTING HEADER SECTION:
//   [12 bytes] nonce (base nonce, shared by all sections)
//   [16 bytes] routing_tag (Poly1305)
//   [44 bytes] encrypted routing header (fixed size)
//
// AUTH HEADER SECTION:
//   [16 bytes] auth_tag (Poly1305)
//   [128 bytes] encrypted auth header (fixed size)
//
// PAYLOAD SECTION (chunked encryption for parallel decryption):
//   [4 bytes]  total_payload_length (plaintext size)
//   For each chunk (count and sizes derived from total_payload_length):
//     [N bytes]  encrypted chunk data (512 bytes, last chunk may be smaller)
//     [16 bytes] chunk_tag (Poly1305)
//
// Each chunk uses nonce: base_nonce XOR (0x02 | (chunk_index << 8))
// Chunk size: 512 bytes (last chunk = total_payload_length % 512, or 512 if even)
//
// Fixed header overhead: 4 + 12 + 16 + 44 + 16 + 136 + 4 = 232 bytes
// Per-chunk overhead: 16 (tag) = 16 bytes

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

/// Wire format v3 implementation with split routing/auth/payload encryption
public enum BinaryEnvelopeV2 {
    /// Magic bytes identifying Omerta packets (3 bytes)
    public static let magic = Data("OMR".utf8)

    /// Wire format version
    public static let version: UInt8 = 0x03

    /// Size of the unencrypted prefix (magic + version)
    public static let prefixSize = 4

    /// Size of the nonce
    public static let nonceSize = 12

    /// Size of authentication tags
    public static let tagSize = 16

    /// Chunk size for payload encryption (512 bytes)
    public static let chunkSize = 512

    /// Fixed header overhead (excluding per-chunk overhead)
    public static let headerOverhead = prefixSize + nonceSize + tagSize + RoutingHeader.encodedSize +
                                       tagSize + AuthHeader.encodedSize + 4  // = 232

    /// Per-chunk overhead: 16 bytes tag only (no length field; derived from total payload length)
    public static let perChunkOverhead = tagSize  // = 16

    /// Calculate total overhead for a given payload size
    public static func totalOverhead(payloadSize: Int) -> Int {
        let chunkCount = max(1, (payloadSize + chunkSize - 1) / chunkSize)
        return headerOverhead + chunkCount * perChunkOverhead
    }

    /// HKDF info string for header key derivation
    private static let headerKeyInfo = Data("omerta-header-v3".utf8)

    /// Nonce XOR values for domain separation
    private static let routingNonceXor: UInt8 = 0x00
    private static let authNonceXor: UInt8 = 0x01

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

    /// Derive a nonce by XORing the last byte of the base nonce
    private static func deriveNonce(_ baseNonce: [UInt8], xor: UInt8) throws -> ChaChaPoly.Nonce {
        var derived = baseNonce
        derived[11] ^= xor
        return try ChaChaPoly.Nonce(data: derived)
    }

    /// Derive a chunk nonce: XOR low byte with 0x02, bytes 9-10 with chunk index
    private static func deriveChunkNonce(_ baseNonce: [UInt8], chunkIndex: Int) throws -> ChaChaPoly.Nonce {
        var derived = baseNonce
        derived[11] ^= 0x02
        derived[9] ^= UInt8(truncatingIfNeeded: chunkIndex >> 8)
        derived[10] ^= UInt8(truncatingIfNeeded: chunkIndex)
        return try ChaChaPoly.Nonce(data: derived)
    }

    // MARK: - Encoding

    /// Encode a complete envelope with split routing/auth/payload encryption
    public static func encode(
        header: EnvelopeHeader,
        payload: Data,
        networkKey: Data
    ) throws -> SealedEnvelope {
        // Generate random base nonce
        let baseNonceValue = ChaChaPoly.Nonce()
        let baseNonce = Array(baseNonceValue)

        // Derive keys
        let headerKey = deriveHeaderKey(from: networkKey)
        let payloadKey = SymmetricKey(data: networkKey)

        // Encode headers
        let routingData = try header.encodeRouting()
        let authData = try header.encodeAuth()

        // Encrypt routing header (nonce XOR 0x00 = base nonce)
        let routingNonce = try deriveNonce(baseNonce, xor: routingNonceXor)
        let routingSealedBox = try ChaChaPoly.seal(routingData, using: headerKey, nonce: routingNonce)

        // Encrypt auth header (nonce XOR 0x01)
        let authNonce = try deriveNonce(baseNonce, xor: authNonceXor)
        let authSealedBox = try ChaChaPoly.seal(authData, using: payloadKey, nonce: authNonce)

        // Split payload into chunks and encrypt each
        let chunkPlaintexts: [Data]
        if payload.isEmpty {
            chunkPlaintexts = [Data()]
        } else {
            chunkPlaintexts = stride(from: 0, to: payload.count, by: chunkSize).map { start in
                let end = min(start + chunkSize, payload.count)
                return Data(payload[start..<end])
            }
        }

        var encryptedChunks: [(ciphertext: Data, tag: Data)] = []
        encryptedChunks.reserveCapacity(chunkPlaintexts.count)
        for (i, chunkData) in chunkPlaintexts.enumerated() {
            let chunkNonce = try deriveChunkNonce(baseNonce, chunkIndex: i)
            let sealed = try ChaChaPoly.seal(chunkData, using: payloadKey, nonce: chunkNonce)
            encryptedChunks.append((Data(sealed.ciphertext), Data(sealed.tag)))
        }

        // Build the packet
        let totalSize = headerOverhead + chunkPlaintexts.count * perChunkOverhead + payload.count
        var writer = BinaryWriter(capacity: totalSize)

        // Unencrypted prefix (4 bytes)
        writer.writeBytes(magic)
        writer.writeByte(version)

        // Routing header section
        writer.writeBytes(Data(baseNonce))                      // 12 bytes nonce
        writer.writeBytes(routingSealedBox.tag)                 // 16 bytes tag
        writer.writeBytes(routingSealedBox.ciphertext)          // 44 bytes encrypted routing

        // Auth header section
        writer.writeBytes(authSealedBox.tag)                    // 16 bytes tag
        writer.writeBytes(authSealedBox.ciphertext)             // 136 bytes encrypted auth

        // Payload section (chunked) — chunk count and sizes derived from total length
        writer.writeUInt32(UInt32(payload.count))               // 4 bytes total plaintext length

        for chunk in encryptedChunks {
            writer.writeBytes(chunk.ciphertext)                    // N bytes encrypted data
            writer.writeBytes(chunk.tag)                           // 16 bytes tag
        }

        return SealedEnvelope(data: writer.data)
    }

    // Alias for backward compatibility
    public static func encodeV2(
        header: EnvelopeHeader,
        payload: Data,
        networkKey: Data
    ) throws -> SealedEnvelope {
        try encode(header: header, payload: payload, networkKey: networkKey)
    }

    // MARK: - Fast Path Rejection

    /// Check if data has valid magic and version (O(1) check)
    public static func isValidPrefix(_ data: Data) -> Bool {
        guard data.count >= prefixSize else { return false }
        return data.prefix(3) == magic && data[3] == version
    }

    // MARK: - Routing-Only Decode

    /// Decode only the routing header (for relay routing decisions)
    /// Does not decrypt auth or payload sections.
    public static func decodeRoutingOnly(
        _ data: Data,
        networkKey: Data
    ) throws -> RoutingHeader {
        let minSize = prefixSize + nonceSize + tagSize + RoutingHeader.encodedSize
        guard data.count >= minSize else {
            throw EnvelopeError.truncatedPacket
        }

        // Verify prefix
        guard data.prefix(3) == magic else {
            throw EnvelopeError.invalidMagic
        }
        guard data[3] == version else {
            throw EnvelopeError.unsupportedVersion(data[3])
        }

        // Extract nonce
        let nonceStart = prefixSize
        let baseNonce = Array(data[nonceStart..<(nonceStart + nonceSize)])

        // Extract routing tag + ciphertext
        let routingTagStart = nonceStart + nonceSize
        let routingTag = Data(data[routingTagStart..<(routingTagStart + tagSize)])
        let routingDataStart = routingTagStart + tagSize
        let routingDataEnd = routingDataStart + RoutingHeader.encodedSize
        let encryptedRouting = Data(data[routingDataStart..<routingDataEnd])

        // Decrypt routing header
        let headerKey = deriveHeaderKey(from: networkKey)
        let routingNonce = try deriveNonce(baseNonce, xor: routingNonceXor)
        let routingSealedBox = try ChaChaPoly.SealedBox(
            nonce: routingNonce,
            ciphertext: encryptedRouting,
            tag: routingTag
        )
        let routingData = try ChaChaPoly.open(routingSealedBox, using: headerKey)

        return try RoutingHeader.decode(from: routingData)
    }

    // MARK: - Full Decode

    /// Decode the complete envelope (routing + auth + payload)
    public static func decode(
        _ data: Data,
        networkKey: Data
    ) throws -> (header: EnvelopeHeader, payload: Data) {
        let routingEnd = prefixSize + nonceSize + tagSize + RoutingHeader.encodedSize
        let authEnd = routingEnd + tagSize + AuthHeader.encodedSize
        let minSize = authEnd + 4  // + payload length
        guard data.count >= minSize else {
            throw EnvelopeError.truncatedPacket
        }

        // Verify prefix
        guard data.prefix(3) == magic else {
            throw EnvelopeError.invalidMagic
        }
        guard data[3] == version else {
            throw EnvelopeError.unsupportedVersion(data[3])
        }

        // Extract base nonce
        let nonceStart = prefixSize
        let baseNonce = Array(data[nonceStart..<(nonceStart + nonceSize)])

        // Derive keys
        let headerKey = deriveHeaderKey(from: networkKey)
        let payloadKey = SymmetricKey(data: networkKey)

        // --- Decrypt routing header ---
        let routingTagStart = nonceStart + nonceSize
        let routingTag = Data(data[routingTagStart..<(routingTagStart + tagSize)])
        let routingDataStart = routingTagStart + tagSize
        let routingDataEnd = routingDataStart + RoutingHeader.encodedSize
        let encryptedRouting = Data(data[routingDataStart..<routingDataEnd])

        let routingNonce = try deriveNonce(baseNonce, xor: routingNonceXor)
        let routingSealedBox = try ChaChaPoly.SealedBox(
            nonce: routingNonce,
            ciphertext: encryptedRouting,
            tag: routingTag
        )
        let routingBytes = try ChaChaPoly.open(routingSealedBox, using: headerKey)
        let routingHeader = try RoutingHeader.decode(from: routingBytes)

        // Verify network hash
        let expectedHash = computeNetworkHash(networkKey)
        guard routingHeader.networkHash == expectedHash else {
            throw EnvelopeError.networkMismatch
        }

        // --- Decrypt auth header ---
        let authTagStart = routingDataEnd
        let authTag = Data(data[authTagStart..<(authTagStart + tagSize)])
        let authDataStart = authTagStart + tagSize
        let authDataEnd = authDataStart + AuthHeader.encodedSize
        let encryptedAuth = Data(data[authDataStart..<authDataEnd])

        let authNonce = try deriveNonce(baseNonce, xor: authNonceXor)
        let authSealedBox = try ChaChaPoly.SealedBox(
            nonce: authNonce,
            ciphertext: encryptedAuth,
            tag: authTag
        )
        let authBytes = try ChaChaPoly.open(authSealedBox, using: payloadKey)
        let authHeader = try AuthHeader.decode(from: authBytes)

        // --- Decrypt payload chunks ---
        var reader = BinaryReader(data)
        reader.offset = authDataEnd
        let totalPayloadLength = Int(try reader.readUInt32())

        // Derive chunk count and sizes from total payload length
        let chunkCount: Int
        if totalPayloadLength == 0 {
            chunkCount = 1  // Empty payload still has one zero-length chunk
        } else {
            chunkCount = (totalPayloadLength + chunkSize - 1) / chunkSize
        }

        var payload = Data(capacity: totalPayloadLength)

        for i in 0..<chunkCount {
            // Derive this chunk's plaintext size
            let chunkLen: Int
            if totalPayloadLength == 0 {
                chunkLen = 0
            } else if i < chunkCount - 1 {
                chunkLen = chunkSize  // Full 512-byte chunk
            } else {
                let remainder = totalPayloadLength % chunkSize
                chunkLen = remainder == 0 ? chunkSize : remainder
            }

            let chunkDataStart = reader.offset
            let chunkDataEnd = chunkDataStart + chunkLen
            guard chunkDataEnd + tagSize <= data.count else {
                throw EnvelopeError.truncatedPacket
            }

            let encryptedChunk = Data(data[(data.startIndex + chunkDataStart)..<(data.startIndex + chunkDataEnd)])
            let chunkTag = Data(data[(data.startIndex + chunkDataEnd)..<(data.startIndex + chunkDataEnd + tagSize)])
            reader.offset = chunkDataEnd + tagSize

            let chunkNonce = try deriveChunkNonce(baseNonce, chunkIndex: i)
            let chunkSealedBox = try ChaChaPoly.SealedBox(
                nonce: chunkNonce,
                ciphertext: encryptedChunk,
                tag: chunkTag
            )
            let chunkData = try ChaChaPoly.open(chunkSealedBox, using: payloadKey)
            payload.append(chunkData)
        }

        // Reconstruct combined header
        let machineIdStr = MachineIdCompact.toString(authHeader.machineId)
        // Reconstruct full peer ID from public key (peer ID = hex of first 8 bytes of SHA256(publicKey))
        let fromPeerIdFull = IdentityKeypair.derivePeerId(from: authHeader.publicKey)
        let header = EnvelopeHeader(
            routing: routingHeader,
            auth: authHeader,
            channelString: "",  // Channel string not in wire format; caller must resolve
            fromPeerIdFull: fromPeerIdFull,
            toPeerIdFull: routingHeader.isBroadcast ? nil : routingHeader.toPeerId.map { String(format: "%02x", $0) }.joined(),
            machineIdString: machineIdStr
        )

        return (header, payload)
    }
}

// MARK: - MeshEnvelope Integration

extension MeshEnvelope {
    /// Encode envelope using v3 wire format
    public func encodeV2(networkKey: Data) throws -> SealedEnvelope {
        let networkHash = BinaryEnvelopeV2.computeNetworkHash(networkKey)
        let channelHash = ChannelHash.hash(channel)

        let messageUUID: UUID
        if let uuid = UUID(uuidString: messageId) {
            messageUUID = uuid
        } else {
            messageUUID = UUID.fromString(messageId)
        }

        guard let publicKeyData = Data(base64Encoded: publicKey),
              publicKeyData.count == AuthHeader.publicKeySize else {
            throw EnvelopeError.invalidPublicKeySize
        }

        guard let signatureData = Data(base64Encoded: signature),
              signatureData.count == AuthHeader.signatureSize else {
            throw EnvelopeError.invalidSignatureSize
        }

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: fromPeerId,
            toPeerId: toPeerId,
            channel: channelHash,
            channelString: channel,
            hopCount: UInt8(min(max(hopCount, 0), 255)),
            timestamp: timestamp,
            messageId: messageUUID,
            machineId: machineId,
            publicKey: publicKeyData,
            signature: signatureData
        )

        let payloadData = try JSONCoding.encoder.encode(payload)
        return try BinaryEnvelopeV2.encode(header: header, payload: payloadData, networkKey: networkKey)
    }

    /// Decode envelope from v3 wire format
    public static func decodeV2(_ data: Data, networkKey: Data) throws -> MeshEnvelope {
        let (header, payloadData) = try BinaryEnvelopeV2.decode(data, networkKey: networkKey)
        let payload = try JSONCoding.decoder.decode(MeshMessage.self, from: payloadData)

        let messageId = header.messageId.uuidString
        let publicKey = header.publicKey.base64EncodedString()
        let signature = header.signature.base64EncodedString()

        return MeshEnvelope(
            messageId: messageId,
            fromPeerId: header.fromPeerId,
            publicKey: publicKey,
            machineId: header.machineId,
            toPeerId: header.toPeerId,
            channel: header.channelString,
            hopCount: Int(header.hopCount),
            timestamp: header.timestamp,
            payload: payload,
            signature: signature
        )
    }

    /// Decode envelope from v3 wire format, returning the raw channel hash
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
            channel: header.channelString,
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
