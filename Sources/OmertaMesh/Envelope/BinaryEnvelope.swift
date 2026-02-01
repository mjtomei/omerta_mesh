// BinaryEnvelope.swift - Wire Format v3 with split routing/auth/payload encryption
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
import Crypto  // Still needed for SHA256, HKDF, SymmetricKey

/// Encrypted data ready for network transmission.
/// Can only be constructed by BinaryEnvelope encryption methods.
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
public enum BinaryEnvelope {
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

    /// Maximum envelope payload (post-JSON-encoding) that fits in a single
    /// UDP datagram (65535 bytes).
    /// Derived from: wireSize = headerOverhead + payload + ceil(payload/chunkSize) * perChunkOverhead
    public static let maxPayloadForUDP: Int = {
        let maxWire = 65535
        // Binary search for the largest payload where totalOverhead(payload) + payload <= maxWire
        var lo = 0
        var hi = maxWire
        while lo < hi {
            let mid = (lo + hi + 1) / 2
            let wireSize = mid + totalOverhead(payloadSize: mid)
            if wireSize <= maxWire {
                lo = mid
            } else {
                hi = mid - 1
            }
        }
        return lo
    }()

    /// Maximum application data size for a MeshMessage.data() payload that fits
    /// in a single UDP datagram. Accounts for JSON encoding overhead: base64
    /// expands data by 4/3, plus JSON wrapper bytes for the enum encoding.
    /// Computed empirically from the actual encoder to avoid wrapper size guesses.
    public static let maxApplicationDataForUDP: Int = {
        // Measure JSON overhead by encoding a small known payload
        let probe = Data(repeating: 0, count: 3) // 3 bytes → 4 base64 chars
        let msg = MeshMessage.data(probe)
        let encoded = try! JSONCoding.encoder.encode(msg)
        let jsonOverhead = encoded.count - 4  // subtract the 4 base64 chars for 3 bytes

        // Base64: ceil(n/3) * 4 bytes. Total JSON = jsonOverhead + ceil(n/3)*4
        // Solve: jsonOverhead + ceil(n/3)*4 <= maxPayloadForUDP
        let available = maxPayloadForUDP - jsonOverhead
        // ceil(n/3)*4 <= available → n <= floor(available/4) * 3
        return (available / 4) * 3
    }()

    /// Nonce XOR values for domain separation
    private static let routingNonceXor: UInt8 = 0x00
    private static let authNonceXor: UInt8 = 0x01

    // MARK: - Network Hash

    /// Compute the 8-byte network hash from the network key
    public static func computeNetworkHash(_ networkKey: Data) -> Data {
        let hash = SHA256.hash(data: networkKey)
        return Data(hash.prefix(8))
    }

    // MARK: - Nonce Derivation

    /// Derive a nonce by XORing the last byte of the base nonce
    private static func deriveNonce(_ baseNonce: [UInt8], xor: UInt8) -> [UInt8] {
        var derived = baseNonce
        derived[11] ^= xor
        return derived
    }

    /// Derive a chunk nonce: XOR low byte with 0x02, bytes 9-10 with chunk index
    private static func deriveChunkNonce(_ baseNonce: [UInt8], chunkIndex: Int) -> [UInt8] {
        var derived = baseNonce
        derived[11] ^= 0x02
        derived[9] ^= UInt8(truncatingIfNeeded: chunkIndex >> 8)
        derived[10] ^= UInt8(truncatingIfNeeded: chunkIndex)
        return derived
    }

    // MARK: - Encoding

    /// Encode a complete envelope with split routing/auth/payload encryption
    public static func encode(
        header: EnvelopeHeader,
        payload: Data,
        networkKey: Data
    ) throws -> SealedEnvelope {
        // Create ephemeral AEAD contexts (callers using NetworkKey get precomputed ones)
        let keyBytes = [UInt8](networkKey)
        let headerKeyBytes = NetworkKey.deriveHeaderKeyBytes(from: networkKey)
        let headerCtx = try AEADContext(key: headerKeyBytes)
        let payloadCtx = try AEADContext(key: keyBytes)
        return try encodeWithContexts(header: header, payload: payload,
                                       headerCtx: headerCtx, payloadCtx: payloadCtx)
    }

    /// Encode using precomputed AEAD contexts from NetworkKey
    public static func encode(
        header: EnvelopeHeader,
        payload: Data,
        networkKey: NetworkKey
    ) throws -> SealedEnvelope {
        try encodeWithContexts(header: header, payload: payload,
                                headerCtx: networkKey.headerAeadContext,
                                payloadCtx: networkKey.aeadContext)
    }

    /// Internal encode implementation using AEAD contexts
    private static func encodeWithContexts(
        header: EnvelopeHeader,
        payload: Data,
        headerCtx: AEADContext,
        payloadCtx: AEADContext
    ) throws -> SealedEnvelope {
        // Generate random base nonce
        let baseNonce = DirectCrypto.randomNonce()

        // Encode headers
        let routingData = [UInt8](try header.encodeRouting())
        let authData = [UInt8](try header.encodeAuth())

        // Encrypt routing header (nonce XOR 0x00 = base nonce)
        let routingNonce = deriveNonce(baseNonce, xor: routingNonceXor)
        let (routingCiphertext, routingTag) = try headerCtx.seal(plaintext: routingData, nonce: routingNonce)

        // Encrypt auth header (nonce XOR 0x01)
        let authNonce = deriveNonce(baseNonce, xor: authNonceXor)
        let (authCiphertext, authTag) = try payloadCtx.seal(plaintext: authData, nonce: authNonce)

        // Split payload into chunks and encrypt each
        let payloadBytes = [UInt8](payload)
        let chunkPlaintexts: [[UInt8]]
        if payloadBytes.isEmpty {
            chunkPlaintexts = [[]]
        } else {
            chunkPlaintexts = stride(from: 0, to: payloadBytes.count, by: chunkSize).map { start in
                let end = min(start + chunkSize, payloadBytes.count)
                return Array(payloadBytes[start..<end])
            }
        }

        var encryptedChunks: [(ciphertext: [UInt8], tag: [UInt8])] = []
        encryptedChunks.reserveCapacity(chunkPlaintexts.count)
        for (i, chunkData) in chunkPlaintexts.enumerated() {
            let chunkNonce = deriveChunkNonce(baseNonce, chunkIndex: i)
            let (ct, tag) = try payloadCtx.seal(plaintext: chunkData, nonce: chunkNonce)
            encryptedChunks.append((ct, tag))
        }

        // Build the packet
        let totalSize = headerOverhead + chunkPlaintexts.count * perChunkOverhead + payload.count
        var writer = BinaryWriter(capacity: totalSize)

        // Unencrypted prefix (4 bytes)
        writer.writeBytes(magic)
        writer.writeByte(version)

        // Routing header section
        writer.writeBytes(baseNonce)                            // 12 bytes nonce
        writer.writeBytes(routingTag)                           // 16 bytes tag
        writer.writeBytes(routingCiphertext)                    // 44 bytes encrypted routing

        // Auth header section
        writer.writeBytes(authTag)                              // 16 bytes tag
        writer.writeBytes(authCiphertext)                       // 136 bytes encrypted auth

        // Payload section (chunked) — chunk count and sizes derived from total length
        writer.writeUInt32(UInt32(payload.count))               // 4 bytes total plaintext length

        for chunk in encryptedChunks {
            writer.writeBytes(chunk.ciphertext)                 // N bytes encrypted data
            writer.writeBytes(chunk.tag)                        // 16 bytes tag
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
        let headerKeyBytes = NetworkKey.deriveHeaderKeyBytes(from: networkKey)
        let headerCtx = try AEADContext(key: headerKeyBytes)
        return try decodeRoutingOnlyWithContext(data, headerCtx: headerCtx)
    }

    /// Decode routing header using precomputed context from NetworkKey
    public static func decodeRoutingOnly(
        _ data: Data,
        networkKey: NetworkKey
    ) throws -> RoutingHeader {
        try decodeRoutingOnlyWithContext(data, headerCtx: networkKey.headerAeadContext)
    }

    private static func decodeRoutingOnlyWithContext(
        _ data: Data,
        headerCtx: AEADContext
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
        let baseNonce = [UInt8](data[nonceStart..<(nonceStart + nonceSize)])

        // Extract routing tag + ciphertext
        let routingTagStart = nonceStart + nonceSize
        let routingTag = [UInt8](data[routingTagStart..<(routingTagStart + tagSize)])
        let routingDataStart = routingTagStart + tagSize
        let routingDataEnd = routingDataStart + RoutingHeader.encodedSize
        let encryptedRouting = [UInt8](data[routingDataStart..<routingDataEnd])

        // Decrypt routing header
        let routingNonce = deriveNonce(baseNonce, xor: routingNonceXor)
        let routingBytes = try headerCtx.open(ciphertext: encryptedRouting, tag: routingTag, nonce: routingNonce)

        return try RoutingHeader.decode(from: Data(routingBytes))
    }

    // MARK: - Full Decode

    /// Decode the complete envelope (routing + auth + payload)
    public static func decode(
        _ data: Data,
        networkKey: Data
    ) throws -> (header: EnvelopeHeader, payload: Data) {
        let keyBytes = [UInt8](networkKey)
        let headerKeyBytes = NetworkKey.deriveHeaderKeyBytes(from: networkKey)
        let headerCtx = try AEADContext(key: headerKeyBytes)
        let payloadCtx = try AEADContext(key: keyBytes)
        return try decodeWithContexts(data, networkKey: networkKey,
                                       headerCtx: headerCtx, payloadCtx: payloadCtx)
    }

    /// Decode using precomputed AEAD contexts from NetworkKey
    public static func decode(
        _ data: Data,
        networkKey: NetworkKey
    ) throws -> (header: EnvelopeHeader, payload: Data) {
        try decodeWithContexts(data, networkKey: networkKey.networkKey,
                                headerCtx: networkKey.headerAeadContext,
                                payloadCtx: networkKey.aeadContext)
    }

    private static func decodeWithContexts(
        _ data: Data,
        networkKey: Data,
        headerCtx: AEADContext,
        payloadCtx: AEADContext
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
        let baseNonce = [UInt8](data[nonceStart..<(nonceStart + nonceSize)])

        // --- Decrypt routing header ---
        let routingTagStart = nonceStart + nonceSize
        let routingTag = [UInt8](data[routingTagStart..<(routingTagStart + tagSize)])
        let routingDataStart = routingTagStart + tagSize
        let routingDataEnd = routingDataStart + RoutingHeader.encodedSize
        let encryptedRouting = [UInt8](data[routingDataStart..<routingDataEnd])

        let routingNonce = deriveNonce(baseNonce, xor: routingNonceXor)
        let routingBytes = try headerCtx.open(ciphertext: encryptedRouting, tag: routingTag, nonce: routingNonce)
        let routingHeader = try RoutingHeader.decode(from: Data(routingBytes))

        // Verify network hash
        let expectedHash = computeNetworkHash(networkKey)
        guard routingHeader.networkHash == expectedHash else {
            throw EnvelopeError.networkMismatch
        }

        // --- Decrypt auth header ---
        let authTagStart = routingDataEnd
        let authTag = [UInt8](data[authTagStart..<(authTagStart + tagSize)])
        let authDataStart = authTagStart + tagSize
        let authDataEnd = authDataStart + AuthHeader.encodedSize
        let encryptedAuth = [UInt8](data[authDataStart..<authDataEnd])

        let authNonce = deriveNonce(baseNonce, xor: authNonceXor)
        let authBytes = try payloadCtx.open(ciphertext: encryptedAuth, tag: authTag, nonce: authNonce)
        let authHeader = try AuthHeader.decode(from: Data(authBytes))

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

            let encryptedChunk = [UInt8](data[(data.startIndex + chunkDataStart)..<(data.startIndex + chunkDataEnd)])
            let chunkTag = [UInt8](data[(data.startIndex + chunkDataEnd)..<(data.startIndex + chunkDataEnd + tagSize)])
            reader.offset = chunkDataEnd + tagSize

            let chunkNonce = deriveChunkNonce(baseNonce, chunkIndex: i)
            let chunkBytes = try payloadCtx.open(ciphertext: encryptedChunk, tag: chunkTag, nonce: chunkNonce)
            payload.append(contentsOf: chunkBytes)
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
        let networkHash = BinaryEnvelope.computeNetworkHash(networkKey)
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
        return try BinaryEnvelope.encode(header: header, payload: payloadData, networkKey: networkKey)
    }

    /// Decode envelope from v3 wire format
    public static func decodeV2(_ data: Data, networkKey: Data) throws -> MeshEnvelope {
        let (header, payloadData) = try BinaryEnvelope.decode(data, networkKey: networkKey)
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
        let (header, payloadData) = try BinaryEnvelope.decode(data, networkKey: networkKey)
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
