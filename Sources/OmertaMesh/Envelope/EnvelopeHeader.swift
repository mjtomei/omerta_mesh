// EnvelopeHeader.swift - Header structure for Wire Format v2
//
// The header contains routing information that is encrypted separately from
// the payload to enable efficient routing decisions without full decryption.
//
// All fields are binary-encoded for fast processing without string parsing.

import Foundation

/// Header structure for Wire Format v2 envelopes
/// Contains routing information that can be decrypted independently of payload
/// All fields use fixed-size binary encoding for efficient processing
public struct EnvelopeHeader: Sendable, Equatable {
    /// Network hash (8 bytes) - first 8 bytes of SHA256(networkKey)
    /// Used to verify the message is for this network after header decryption
    public let networkHash: Data

    /// Sender's peer ID (truncated to 16 bytes for compactness)
    public let fromPeerId: PeerId

    /// Recipient's peer ID (nil for broadcast, truncated to 16 bytes)
    public let toPeerId: PeerId?

    /// Channel identifier (UInt16) for O(1) routing lookups
    /// Use ChannelHash.hash() to convert string channel names
    public let channel: UInt16

    /// Original channel string (for signature verification)
    /// This is stored alongside the hash to preserve signature verifiability
    public let channelString: String

    /// Number of hops this message has taken (0-255)
    public let hopCount: UInt8

    /// When the message was created (Unix timestamp, milliseconds)
    public let timestamp: Date

    /// Unique message identifier (16 bytes)
    public let messageId: UUID

    /// Machine ID of the sender (truncated to 16 bytes)
    public let machineId: String

    /// Public key of the sender (32 bytes raw Ed25519)
    public let publicKey: Data

    /// Signature of the envelope (64 bytes Ed25519)
    public let signature: Data

    public init(
        networkHash: Data,
        fromPeerId: PeerId,
        toPeerId: PeerId?,
        channel: UInt16,
        channelString: String = "",
        hopCount: UInt8,
        timestamp: Date,
        messageId: UUID,
        machineId: String,
        publicKey: Data,
        signature: Data
    ) {
        self.networkHash = networkHash
        self.fromPeerId = fromPeerId
        self.toPeerId = toPeerId
        self.channel = channel
        self.channelString = channelString
        self.hopCount = hopCount
        self.timestamp = timestamp
        self.messageId = messageId
        self.machineId = machineId
        self.publicKey = publicKey
        self.signature = signature
    }

    // MARK: - Binary Encoding

    /// Binary header format (fixed size fields for fast parsing):
    /// - [8 bytes]  networkHash
    /// - [1 byte]   flags (bit 0: hasToPeerId)
    /// - [44 bytes] fromPeerId (base64 peer ID, null-padded)
    /// - [44 bytes] toPeerId if present, or skipped if flags.bit0 == 0
    /// - [2 bytes]  channel (UInt16, big-endian)
    /// - [64 bytes] channelString (original channel name, null-padded)
    /// - [1 byte]   hopCount
    /// - [8 bytes]  timestamp (milliseconds since epoch, UInt64 big-endian)
    /// - [16 bytes] messageId (UUID bytes)
    /// - [36 bytes] machineId (UUID string, null-padded)
    /// - [32 bytes] publicKey (raw Ed25519 public key)
    /// - [64 bytes] signature (raw Ed25519 signature)
    ///
    /// Total size: 276 bytes (with toPeerId) or 232 bytes (without)

    public static let peerIdFieldSize = 44      // Base64 peer ID max length
    public static let channelStringFieldSize = 64  // Channel string max length
    public static let machineIdFieldSize = 36   // UUID string length
    public static let publicKeySize = 32        // Ed25519 public key
    public static let signatureSize = 64        // Ed25519 signature

    public func encode() throws -> Data {
        var writer = BinaryWriter(capacity: 280)

        // Network hash (exactly 8 bytes)
        guard networkHash.count == 8 else {
            throw EnvelopeError.invalidNetworkHash
        }
        writer.writeBytes(networkHash)

        // Flags
        let flags: UInt8 = toPeerId != nil ? 0x01 : 0x00
        writer.writeByte(flags)

        // fromPeerId (fixed 44 bytes, null-padded)
        writer.writeFixedString(fromPeerId, size: Self.peerIdFieldSize)

        // toPeerId if present (fixed 44 bytes, null-padded)
        if let to = toPeerId {
            writer.writeFixedString(to, size: Self.peerIdFieldSize)
        }

        // Channel (UInt16)
        writer.writeUInt16(channel)

        // Channel string (fixed 64 bytes, null-padded)
        writer.writeFixedString(channelString, size: Self.channelStringFieldSize)

        // hopCount
        writer.writeByte(hopCount)

        // timestamp (milliseconds since epoch as UInt64)
        let timestampMs = UInt64(timestamp.timeIntervalSince1970 * 1000)
        writer.writeUInt64(timestampMs)

        // messageId (16 bytes UUID)
        writer.writeUUID(messageId)

        // machineId (fixed 36 bytes, null-padded)
        writer.writeFixedString(machineId, size: Self.machineIdFieldSize)

        // publicKey (32 bytes)
        guard publicKey.count == Self.publicKeySize else {
            throw EnvelopeError.invalidPublicKeySize
        }
        writer.writeBytes(publicKey)

        // signature (64 bytes)
        guard signature.count == Self.signatureSize else {
            throw EnvelopeError.invalidSignatureSize
        }
        writer.writeBytes(signature)

        return writer.data
    }

    /// Decode header from binary format
    public static func decode(from data: Data) throws -> EnvelopeHeader {
        var reader = BinaryReader(data)

        // Network hash (8 bytes)
        let networkHash = try reader.readBytes(8)

        // Flags
        let flags = try reader.readByte()
        let hasToPeerId = (flags & 0x01) != 0

        // fromPeerId (fixed 44 bytes)
        let fromPeerId = try reader.readFixedString(size: peerIdFieldSize)

        // toPeerId if present
        let toPeerId: PeerId?
        if hasToPeerId {
            toPeerId = try reader.readFixedString(size: peerIdFieldSize)
        } else {
            toPeerId = nil
        }

        // Channel (UInt16)
        let channel = try reader.readUInt16()

        // Channel string (fixed 64 bytes)
        let channelString = try reader.readFixedString(size: channelStringFieldSize)

        // hopCount
        let hopCount = try reader.readByte()

        // timestamp (UInt64 milliseconds)
        let timestampMs = try reader.readUInt64()
        let timestamp = Date(timeIntervalSince1970: Double(timestampMs) / 1000.0)

        // messageId (16 bytes UUID)
        let messageId = try reader.readUUID()

        // machineId (fixed 36 bytes)
        let machineId = try reader.readFixedString(size: machineIdFieldSize)

        // publicKey (32 bytes)
        let publicKey = try reader.readBytes(publicKeySize)

        // signature (64 bytes)
        let signature = try reader.readBytes(signatureSize)

        return EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: fromPeerId,
            toPeerId: toPeerId,
            channel: channel,
            channelString: channelString,
            hopCount: hopCount,
            timestamp: timestamp,
            messageId: messageId,
            machineId: machineId,
            publicKey: publicKey,
            signature: signature
        )
    }
}

// MARK: - Channel Hash

/// Utility for converting string channel names to UInt16 identifiers
public enum ChannelHash {
    /// Convert a channel name string to a UInt16 hash for binary encoding
    /// Uses FNV-1a hash truncated to 16 bits
    ///
    /// Reserved channels:
    /// - 0: Default/empty channel
    /// - 1-99: Reserved for mesh infrastructure (mesh-*)
    /// - 100+: Application channels
    public static func hash(_ channel: String) -> UInt16 {
        guard !channel.isEmpty else { return 0 }

        // FNV-1a hash
        var hash: UInt64 = 14695981039346656037
        for byte in channel.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1099511628211
        }

        // Mix the bits and truncate to 16 bits
        // XOR-fold the 64-bit hash to 16 bits for better distribution
        let h32 = UInt32(truncatingIfNeeded: hash ^ (hash >> 32))
        let h16 = UInt16(truncatingIfNeeded: h32 ^ (h32 >> 16))

        // Ensure non-zero for non-empty channels (0 is reserved for empty)
        return h16 == 0 ? 1 : h16
    }

    /// Well-known infrastructure channel hashes (precomputed)
    public static let meshPing: UInt16 = hash("mesh-ping")
    public static let meshGossip: UInt16 = hash("mesh-gossip")
    public static let meshRelay: UInt16 = hash("mesh-relay")
    public static let meshHolePunch: UInt16 = hash("mesh-holepunch")
    public static let meshDir: UInt16 = hash("mesh-dir")
    public static let healthRequest: UInt16 = hash("health-request")
    public static let cloisterNegotiate: UInt16 = hash("cloister-negotiate")
    public static let cloisterShare: UInt16 = hash("cloister-share")
}

// MARK: - Binary Writer Extensions

extension BinaryWriter {
    mutating func writeUInt16(_ value: UInt16) {
        var bigEndian = value.bigEndian
        data.append(Data(bytes: &bigEndian, count: 2))
    }

    mutating func writeUInt64(_ value: UInt64) {
        var bigEndian = value.bigEndian
        data.append(Data(bytes: &bigEndian, count: 8))
    }

    mutating func writeUUID(_ uuid: UUID) {
        let bytes = withUnsafeBytes(of: uuid.uuid) { Data($0) }
        data.append(bytes)
    }

    /// Write a string to a fixed-size field, null-padded
    mutating func writeFixedString(_ string: String, size: Int) {
        let utf8 = Data(string.utf8)
        if utf8.count >= size {
            // Truncate if too long
            data.append(utf8.prefix(size))
        } else {
            // Pad with nulls
            data.append(utf8)
            data.append(Data(repeating: 0, count: size - utf8.count))
        }
    }
}

// MARK: - Binary Reader Extensions

extension BinaryReader {
    mutating func readUInt16() throws -> UInt16 {
        guard remaining >= 2 else {
            throw BinaryEnvelopeError.truncatedData
        }
        let startIndex = data.startIndex.advanced(by: offset)
        let b0 = UInt16(data[startIndex])
        let b1 = UInt16(data[startIndex.advanced(by: 1)])
        offset += 2
        return (b0 << 8) | b1
    }

    mutating func readUInt64() throws -> UInt64 {
        guard remaining >= 8 else {
            throw BinaryEnvelopeError.truncatedData
        }
        var value: UInt64 = 0
        for i in 0..<8 {
            let idx = data.startIndex.advanced(by: offset + i)
            value = (value << 8) | UInt64(data[idx])
        }
        offset += 8
        return value
    }

    mutating func readUUID() throws -> UUID {
        guard remaining >= 16 else {
            throw BinaryEnvelopeError.truncatedData
        }
        let startIndex = data.startIndex.advanced(by: offset)
        let bytes = data[startIndex..<startIndex.advanced(by: 16)]
        offset += 16

        var uuid: uuid_t = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
        withUnsafeMutableBytes(of: &uuid) { ptr in
            _ = bytes.copyBytes(to: ptr)
        }
        return UUID(uuid: uuid)
    }

    /// Read a fixed-size null-padded string
    mutating func readFixedString(size: Int) throws -> String {
        guard remaining >= size else {
            throw BinaryEnvelopeError.truncatedData
        }
        let startIndex = data.startIndex.advanced(by: offset)
        let fieldData = data[startIndex..<startIndex.advanced(by: size)]
        offset += size

        // Find null terminator or use full length
        var endIndex = fieldData.endIndex
        for i in fieldData.indices {
            if fieldData[i] == 0 {
                endIndex = i
                break
            }
        }

        let stringData = fieldData[fieldData.startIndex..<endIndex]
        guard let string = String(data: Data(stringData), encoding: .utf8) else {
            throw BinaryEnvelopeError.invalidUTF8(field: "fixed string")
        }
        return string
    }
}

/// Errors specific to envelope operations
public enum EnvelopeError: Error, LocalizedError {
    case invalidMagic
    case unsupportedVersion(UInt8)
    case invalidNetworkHash
    case networkMismatch
    case headerDecryptionFailed
    case headerAuthenticationFailed
    case payloadDecryptionFailed
    case payloadAuthenticationFailed
    case signatureTooLong
    case truncatedPacket
    case invalidPublicKeySize
    case invalidSignatureSize

    public var errorDescription: String? {
        switch self {
        case .invalidMagic:
            return "Invalid magic bytes - not an Omerta packet"
        case .unsupportedVersion(let v):
            return "Unsupported wire format version: \(v)"
        case .invalidNetworkHash:
            return "Network hash must be exactly 8 bytes"
        case .networkMismatch:
            return "Packet is for a different network"
        case .headerDecryptionFailed:
            return "Failed to decrypt header"
        case .headerAuthenticationFailed:
            return "Header authentication tag verification failed"
        case .payloadDecryptionFailed:
            return "Failed to decrypt payload"
        case .payloadAuthenticationFailed:
            return "Payload authentication tag verification failed"
        case .signatureTooLong:
            return "Signature exceeds maximum length"
        case .truncatedPacket:
            return "Packet is too short"
        case .invalidPublicKeySize:
            return "Public key must be exactly 32 bytes"
        case .invalidSignatureSize:
            return "Signature must be exactly 64 bytes"
        }
    }
}
