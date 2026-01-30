// EnvelopeHeader.swift - Split header structure for Wire Format v3
//
// Two separately encrypted header sections:
//   RoutingHeader (44 bytes fixed) - decrypted by relay nodes for routing
//   AuthHeader (128 bytes fixed) - decrypted by recipients for signature verification
//
// Compact field sizes:
//   - PeerId: 16 bytes (truncated raw key instead of 44-byte Base64)
//   - MachineId: 16 bytes (raw UUID instead of 36-byte string)
//   - Channel: UInt16 hash only (no channelString)

import Foundation

// MARK: - Routing Header

/// Routing header for Wire Format v3 envelopes.
/// Contains minimal routing information that relay nodes can decrypt
/// without accessing authentication or payload data.
///
/// Fixed size: 44 bytes, all multi-byte fields 8-byte aligned.
///
/// Layout:
/// - [8 bytes]  networkHash
/// - [16 bytes] fromPeerId (truncated)
/// - [16 bytes] toPeerId (all-zeros = broadcast)
/// - [1 byte]   flags
/// - [1 byte]   hopCount
/// - [2 bytes]  channel (UInt16)
public struct RoutingHeader: Sendable, Equatable {
    /// Total encoded size in bytes (fixed)
    public static let encodedSize = 44

    /// Network hash (8 bytes) - first 8 bytes of SHA256(networkKey)
    public let networkHash: Data

    /// Sender's peer ID (truncated to 16 bytes)
    public let fromPeerId: Data

    /// Recipient's peer ID (16 bytes; all-zeros = broadcast)
    public let toPeerId: Data

    /// Flags byte
    /// - bit 0: reserved
    public let flags: UInt8

    /// Number of hops this message has taken (0-255)
    public let hopCount: UInt8

    /// Channel identifier (UInt16) for O(1) routing lookups
    public let channel: UInt16

    /// All-zero peer ID used for broadcast
    public static let broadcastPeerId = Data(repeating: 0, count: 16)

    /// Whether this is a broadcast message
    public var isBroadcast: Bool {
        toPeerId == Self.broadcastPeerId
    }

    public init(
        networkHash: Data,
        fromPeerId: Data,
        toPeerId: Data,
        flags: UInt8 = 0,
        hopCount: UInt8,
        channel: UInt16
    ) {
        self.networkHash = networkHash
        self.fromPeerId = fromPeerId
        self.toPeerId = toPeerId
        self.flags = flags
        self.hopCount = hopCount
        self.channel = channel
    }

    /// Encode routing header to exactly 44 bytes
    public func encode() throws -> Data {
        guard networkHash.count == 8 else {
            throw EnvelopeError.invalidNetworkHash
        }
        guard fromPeerId.count == 16 else {
            throw EnvelopeError.invalidPeerIdSize
        }
        guard toPeerId.count == 16 else {
            throw EnvelopeError.invalidPeerIdSize
        }

        var writer = BinaryWriter(capacity: Self.encodedSize)
        writer.writeBytes(networkHash)          // 8 bytes  (offset 0)
        writer.writeBytes(fromPeerId)           // 16 bytes (offset 8)
        writer.writeBytes(toPeerId)             // 16 bytes (offset 24)
        writer.writeByte(flags)                 // 1 byte   (offset 40)
        writer.writeByte(hopCount)              // 1 byte   (offset 41)
        writer.writeUInt16(channel)             // 2 bytes  (offset 42)
        return writer.data
    }

    /// Decode routing header from binary
    public static func decode(from data: Data) throws -> RoutingHeader {
        guard data.count >= encodedSize else {
            throw BinaryEnvelopeError.truncatedData
        }
        var reader = BinaryReader(data)
        let networkHash = try reader.readBytes(8)
        let fromPeerId = try reader.readBytes(16)
        let toPeerId = try reader.readBytes(16)
        let flags = try reader.readByte()
        let hopCount = try reader.readByte()
        let channel = try reader.readUInt16()
        return RoutingHeader(
            networkHash: networkHash,
            fromPeerId: fromPeerId,
            toPeerId: toPeerId,
            flags: flags,
            hopCount: hopCount,
            channel: channel
        )
    }
}

// MARK: - Auth Header

/// Authentication header for Wire Format v3 envelopes.
/// Contains signature and identity data for message verification.
/// Recipients decrypt this before the payload to verify signatures
/// without decrypting potentially large payloads.
///
/// Fixed size: 128 bytes, all fields 8-byte aligned.
///
/// Layout:
/// - [8 bytes]  timestamp (UInt64 ms since epoch)
/// - [16 bytes] messageId (UUID)
/// - [16 bytes] machineId (raw UUID)
/// - [32 bytes] publicKey (Ed25519)
/// - [64 bytes] signature (Ed25519)
///
/// Note: The original channel string is stored alongside these headers
/// for signature verification purposes, but it is NOT part of the auth
/// header wire format. It is carried in the EnvelopeHeader wrapper.
public struct AuthHeader: Sendable, Equatable {
    /// Total encoded size in bytes (fixed)
    /// 8 (timestamp) + 16 (messageId) + 16 (machineId) + 32 (publicKey) + 64 (signature) = 136
    public static let encodedSize = 136

    // Field sizes
    public static let publicKeySize = 32
    public static let signatureSize = 64

    /// When the message was created (Unix timestamp, milliseconds)
    public let timestamp: Date

    /// Unique message identifier (16 bytes)
    public let messageId: UUID

    /// Machine ID of the sender (raw 16-byte UUID)
    public let machineId: UUID

    /// Public key of the sender (32 bytes raw Ed25519)
    public let publicKey: Data

    /// Signature of the envelope (64 bytes Ed25519)
    public let signature: Data

    public init(
        timestamp: Date,
        messageId: UUID,
        machineId: UUID,
        publicKey: Data,
        signature: Data
    ) {
        self.timestamp = timestamp
        self.messageId = messageId
        self.machineId = machineId
        self.publicKey = publicKey
        self.signature = signature
    }

    /// Encode auth header to exactly 128 bytes
    public func encode() throws -> Data {
        guard publicKey.count == Self.publicKeySize else {
            throw EnvelopeError.invalidPublicKeySize
        }
        guard signature.count == Self.signatureSize else {
            throw EnvelopeError.invalidSignatureSize
        }

        var writer = BinaryWriter(capacity: Self.encodedSize)
        let timestampMs = UInt64(timestamp.timeIntervalSince1970 * 1000)
        writer.writeUInt64(timestampMs)         // 8 bytes  (offset 0)
        writer.writeUUID(messageId)             // 16 bytes (offset 8)
        writer.writeUUID(machineId)             // 16 bytes (offset 24)
        writer.writeBytes(publicKey)            // 32 bytes (offset 40) -- Note: not on 8-byte boundary
        writer.writeBytes(signature)            // 64 bytes (offset 72) -- Note: on 8-byte boundary
        return writer.data
    }

    /// Decode auth header from binary
    public static func decode(from data: Data) throws -> AuthHeader {
        guard data.count >= encodedSize else {
            throw BinaryEnvelopeError.truncatedData
        }
        var reader = BinaryReader(data)
        let timestampMs = try reader.readUInt64()
        let timestamp = Date(timeIntervalSince1970: Double(timestampMs) / 1000.0)
        let messageId = try reader.readUUID()
        let machineId = try reader.readUUID()
        let publicKey = try reader.readBytes(Self.publicKeySize)
        let signature = try reader.readBytes(Self.signatureSize)
        return AuthHeader(
            timestamp: timestamp,
            messageId: messageId,
            machineId: machineId,
            publicKey: publicKey,
            signature: signature
        )
    }
}

// MARK: - Combined Envelope Header

/// Combined header wrapper that holds both routing and auth headers
/// plus the original channel string (needed for signature verification).
public struct EnvelopeHeader: Sendable, Equatable {
    public let routing: RoutingHeader
    public let auth: AuthHeader

    /// Original channel string for signature verification.
    /// Not part of wire format — carried separately.
    public let channelString: String

    /// Original full peer ID strings for signature verification.
    /// The routing header only carries truncated 16-byte versions.
    public let fromPeerIdFull: PeerId
    public let toPeerIdFull: PeerId?
    public let machineIdString: MachineId

    // Convenience accessors
    public var networkHash: Data { routing.networkHash }
    public var fromPeerId: PeerId { fromPeerIdFull }
    public var toPeerId: PeerId? { toPeerIdFull }
    public var channel: UInt16 { routing.channel }
    public var hopCount: UInt8 { routing.hopCount }
    public var timestamp: Date { auth.timestamp }
    public var messageId: UUID { auth.messageId }
    public var machineId: String { machineIdString }
    public var publicKey: Data { auth.publicKey }
    public var signature: Data { auth.signature }

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
        self.routing = RoutingHeader(
            networkHash: networkHash,
            fromPeerId: PeerIdCompact.truncate(fromPeerId),
            toPeerId: toPeerId.map { PeerIdCompact.truncate($0) } ?? RoutingHeader.broadcastPeerId,
            hopCount: hopCount,
            channel: channel
        )
        self.auth = AuthHeader(
            timestamp: timestamp,
            messageId: messageId,
            machineId: MachineIdCompact.toUUID(machineId) ?? UUID(),
            publicKey: publicKey,
            signature: signature
        )
        self.channelString = channelString
        self.fromPeerIdFull = fromPeerId
        self.toPeerIdFull = toPeerId
        self.machineIdString = machineId
    }

    /// Reconstruct from decoded routing and auth headers
    public init(routing: RoutingHeader, auth: AuthHeader, channelString: String, fromPeerIdFull: PeerId, toPeerIdFull: PeerId?, machineIdString: MachineId) {
        self.routing = routing
        self.auth = auth
        self.channelString = channelString
        self.fromPeerIdFull = fromPeerIdFull
        self.toPeerIdFull = toPeerIdFull
        self.machineIdString = machineIdString
    }

    /// Encode routing header only (for encryption)
    public func encodeRouting() throws -> Data {
        try routing.encode()
    }

    /// Encode auth header only (for encryption)
    public func encodeAuth() throws -> Data {
        try auth.encode()
    }

    // Legacy encode: encode routing header (for backward compatibility in tests)
    public func encode() throws -> Data {
        try routing.encode()
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

// MARK: - PeerId Compact Helpers

/// Utilities for truncating peer IDs to 16 bytes
public enum PeerIdCompact {
    /// Truncate a peer ID string to 16 bytes for the routing header.
    /// Uses the raw bytes of the base64-decoded public key if possible,
    /// otherwise uses SHA256 hash of the string.
    public static func truncate(_ peerId: PeerId) -> Data {
        if let keyData = Data(base64Encoded: peerId), keyData.count >= 16 {
            return Data(keyData.prefix(16))
        }
        // Fallback: hash the string
        let utf8 = Data(peerId.utf8)
        if utf8.count >= 16 {
            return Data(utf8.prefix(16))
        }
        // Pad short strings
        var padded = utf8
        padded.append(Data(repeating: 0, count: 16 - utf8.count))
        return padded
    }

    /// Check if a truncated peer ID matches a full peer ID
    public static func matches(truncated: Data, full: PeerId) -> Bool {
        return truncate(full) == truncated
    }
}

// MARK: - MachineId Compact Helpers

/// Utilities for converting machine IDs to/from raw 16-byte UUIDs
public enum MachineIdCompact {
    /// Convert a machine ID string (UUID format) to a UUID
    public static func toUUID(_ machineId: MachineId) -> UUID? {
        UUID(uuidString: machineId)
    }

    /// Convert a UUID back to a machine ID string
    public static func toString(_ uuid: UUID) -> MachineId {
        uuid.uuidString
    }
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
    case invalidPeerIdSize
    case authDecryptionFailed

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
        case .invalidPeerIdSize:
            return "Peer ID must be exactly 16 bytes (truncated)"
        case .authDecryptionFailed:
            return "Failed to decrypt auth header"
        }
    }
}
