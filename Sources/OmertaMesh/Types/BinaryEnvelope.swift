// BinaryEnvelope.swift - Binary wire format for MeshEnvelope
//
// Binary format provides faster parsing than JSON for high-throughput scenarios.
// Format detection: first byte 0x01 = binary, '{' (0x7B) = JSON

import Foundation

/// Binary format version
public let BinaryEnvelopeVersion: UInt8 = 0x01

/// Errors that can occur during binary envelope encoding/decoding
public enum BinaryEnvelopeError: Error, CustomStringConvertible {
    case invalidVersion(UInt8)
    case truncatedData
    case stringTooLong(field: String, length: Int, max: Int)
    case invalidUTF8(field: String)
    case payloadTooLarge(size: Int)

    public var description: String {
        switch self {
        case .invalidVersion(let v):
            return "Invalid binary envelope version: \(v)"
        case .truncatedData:
            return "Binary envelope data is truncated"
        case .stringTooLong(let field, let length, let max):
            return "Field '\(field)' too long: \(length) > \(max)"
        case .invalidUTF8(let field):
            return "Invalid UTF-8 in field '\(field)'"
        case .payloadTooLarge(let size):
            return "Payload too large: \(size) bytes"
        }
    }
}

// MARK: - Binary Writer

/// Helper for writing binary data
struct BinaryWriter {
    var data: Data

    init(capacity: Int = 1024) {
        data = Data(capacity: capacity)
    }

    mutating func writeByte(_ value: UInt8) {
        data.append(value)
    }

    mutating func writeUInt32(_ value: UInt32) {
        var bigEndian = value.bigEndian
        data.append(Data(bytes: &bigEndian, count: 4))
    }

    mutating func writeInt64(_ value: Int64) {
        var bigEndian = value.bigEndian
        data.append(Data(bytes: &bigEndian, count: 8))
    }

    /// Write a Double (8 bytes, IEEE 754, big-endian bit pattern)
    mutating func writeDouble(_ value: Double) {
        let bits = value.bitPattern
        var bigEndian = bits.bigEndian
        data.append(Data(bytes: &bigEndian, count: 8))
    }

    /// Write a length-prefixed string (1-byte length, max 255 chars)
    mutating func writeString(_ string: String, field: String) throws {
        let utf8 = Data(string.utf8)
        guard utf8.count <= 255 else {
            throw BinaryEnvelopeError.stringTooLong(field: field, length: utf8.count, max: 255)
        }
        writeByte(UInt8(utf8.count))
        data.append(utf8)
    }

    /// Write raw bytes
    mutating func writeBytes(_ bytes: Data) {
        data.append(bytes)
    }
}

// MARK: - Binary Reader

/// Helper for reading binary data
struct BinaryReader {
    let data: Data
    var offset: Int = 0

    init(_ data: Data) {
        self.data = data
    }

    var remaining: Int {
        data.count - offset
    }

    mutating func readByte() throws -> UInt8 {
        guard offset < data.count else {
            throw BinaryEnvelopeError.truncatedData
        }
        let value = data[data.startIndex.advanced(by: offset)]
        offset += 1
        return value
    }

    mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else {
            throw BinaryEnvelopeError.truncatedData
        }
        // Read bytes individually to avoid alignment issues on ARM64
        let startIndex = data.startIndex.advanced(by: offset)
        let b0 = UInt32(data[startIndex])
        let b1 = UInt32(data[startIndex.advanced(by: 1)])
        let b2 = UInt32(data[startIndex.advanced(by: 2)])
        let b3 = UInt32(data[startIndex.advanced(by: 3)])
        offset += 4
        // Big-endian: most significant byte first
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    mutating func readInt64() throws -> Int64 {
        guard remaining >= 8 else {
            throw BinaryEnvelopeError.truncatedData
        }
        // Read bytes individually to avoid alignment issues on ARM64
        let startIndex = data.startIndex.advanced(by: offset)
        let b0 = Int64(data[startIndex])
        let b1 = Int64(data[startIndex.advanced(by: 1)])
        let b2 = Int64(data[startIndex.advanced(by: 2)])
        let b3 = Int64(data[startIndex.advanced(by: 3)])
        let b4 = Int64(data[startIndex.advanced(by: 4)])
        let b5 = Int64(data[startIndex.advanced(by: 5)])
        let b6 = Int64(data[startIndex.advanced(by: 6)])
        let b7 = Int64(data[startIndex.advanced(by: 7)])
        offset += 8
        // Big-endian: most significant byte first
        return (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) |
               (b4 << 24) | (b5 << 16) | (b6 << 8) | b7
    }

    /// Read a Double (8 bytes, IEEE 754, big-endian bit pattern)
    mutating func readDouble() throws -> Double {
        guard remaining >= 8 else {
            throw BinaryEnvelopeError.truncatedData
        }
        // Read bytes individually to avoid alignment issues on ARM64
        let startIndex = data.startIndex.advanced(by: offset)
        let b0 = UInt64(data[startIndex])
        let b1 = UInt64(data[startIndex.advanced(by: 1)])
        let b2 = UInt64(data[startIndex.advanced(by: 2)])
        let b3 = UInt64(data[startIndex.advanced(by: 3)])
        let b4 = UInt64(data[startIndex.advanced(by: 4)])
        let b5 = UInt64(data[startIndex.advanced(by: 5)])
        let b6 = UInt64(data[startIndex.advanced(by: 6)])
        let b7 = UInt64(data[startIndex.advanced(by: 7)])
        offset += 8
        // Big-endian: most significant byte first
        let bits = (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) |
                   (b4 << 24) | (b5 << 16) | (b6 << 8) | b7
        return Double(bitPattern: bits)
    }

    mutating func readString(field: String) throws -> String {
        let length = Int(try readByte())
        guard remaining >= length else {
            throw BinaryEnvelopeError.truncatedData
        }
        let bytes = data[data.startIndex.advanced(by: offset)..<data.startIndex.advanced(by: offset + length)]
        offset += length
        guard let string = String(data: bytes, encoding: .utf8) else {
            throw BinaryEnvelopeError.invalidUTF8(field: field)
        }
        return string
    }

    mutating func readBytes(_ count: Int) throws -> Data {
        guard remaining >= count else {
            throw BinaryEnvelopeError.truncatedData
        }
        let bytes = data[data.startIndex.advanced(by: offset)..<data.startIndex.advanced(by: offset + count)]
        offset += count
        return Data(bytes)
    }
}

// MARK: - MeshEnvelope Binary Extension

extension MeshEnvelope {

    /// Encode envelope to binary format
    /// Format:
    /// - [1 byte] version (0x01)
    /// - [1 byte + N bytes] messageId (length-prefixed UTF-8)
    /// - [1 byte + N bytes] fromPeerId (length-prefixed UTF-8)
    /// - [1 byte + N bytes] publicKey (length-prefixed UTF-8)
    /// - [1 byte + N bytes] machineId (length-prefixed UTF-8)
    /// - [1 byte] flags (bit 0: hasToPeerId)
    /// - [0 or 1 byte + N bytes] toPeerId if present (length-prefixed UTF-8)
    /// - [1 byte + N bytes] channel (length-prefixed UTF-8, max 64)
    /// - [1 byte] hopCount
    /// - [8 bytes] timestamp (Unix seconds, big-endian Int64)
    /// - [4 bytes] payload length (big-endian UInt32)
    /// - [N bytes] payload (JSON-encoded MeshMessage)
    /// - [1 byte + N bytes] signature (length-prefixed base64)
    public func encodeBinary() throws -> Data {
        var writer = BinaryWriter(capacity: 512)

        // Version
        writer.writeByte(BinaryEnvelopeVersion)

        // Header fields
        try writer.writeString(messageId, field: "messageId")
        try writer.writeString(fromPeerId, field: "fromPeerId")
        try writer.writeString(publicKey, field: "publicKey")
        try writer.writeString(machineId, field: "machineId")

        // Flags and optional toPeerId
        let flags: UInt8 = toPeerId != nil ? 0x01 : 0x00
        writer.writeByte(flags)
        if let to = toPeerId {
            try writer.writeString(to, field: "toPeerId")
        }

        // Channel (max 64 chars enforced by ChannelUtils)
        try writer.writeString(channel, field: "channel")

        // HopCount (clamped to 0-255)
        writer.writeByte(UInt8(min(max(hopCount, 0), 255)))

        // Timestamp as timeIntervalSinceReferenceDate (raw Double bits)
        // This matches the default JSON encoding and preserves exact precision for signature verification
        writer.writeDouble(timestamp.timeIntervalSinceReferenceDate)

        // Payload (JSON-encoded MeshMessage)
        let payloadData = try JSONCoding.encoder.encode(payload)
        guard payloadData.count <= UInt32.max else {
            throw BinaryEnvelopeError.payloadTooLarge(size: payloadData.count)
        }
        writer.writeUInt32(UInt32(payloadData.count))
        writer.writeBytes(payloadData)

        // Signature
        try writer.writeString(signature, field: "signature")

        return writer.data
    }

    /// Decode envelope from binary format
    public static func decodeBinary(_ data: Data) throws -> MeshEnvelope {
        var reader = BinaryReader(data)

        // Version check
        let version = try reader.readByte()
        guard version == BinaryEnvelopeVersion else {
            throw BinaryEnvelopeError.invalidVersion(version)
        }

        // Header fields
        let messageId = try reader.readString(field: "messageId")
        let fromPeerId = try reader.readString(field: "fromPeerId")
        let publicKey = try reader.readString(field: "publicKey")
        let machineId = try reader.readString(field: "machineId")

        // Flags and optional toPeerId
        let flags = try reader.readByte()
        let hasToPeerId = (flags & 0x01) != 0
        let toPeerId: PeerId? = hasToPeerId ? try reader.readString(field: "toPeerId") : nil

        // Channel
        let channel = try reader.readString(field: "channel")

        // HopCount
        let hopCount = Int(try reader.readByte())

        // Timestamp (timeIntervalSinceReferenceDate as raw Double)
        let refInterval = try reader.readDouble()
        let timestamp = Date(timeIntervalSinceReferenceDate: refInterval)

        // Payload
        let payloadLength = Int(try reader.readUInt32())
        let payloadData = try reader.readBytes(payloadLength)
        let payload = try JSONCoding.decoder.decode(MeshMessage.self, from: payloadData)

        // Signature
        let signature = try reader.readString(field: "signature")

        return MeshEnvelope(
            messageId: messageId,
            fromPeerId: fromPeerId,
            publicKey: publicKey,
            machineId: machineId,
            toPeerId: toPeerId,
            channel: channel,
            hopCount: hopCount,
            timestamp: timestamp,
            payload: payload,
            signature: signature
        )
    }
}

// MARK: - Format Detection

/// Wire format for mesh messages
public enum EnvelopeWireFormat {
    case json
    case binary

    /// Detect format from first byte of data
    public static func detect(_ data: Data) -> EnvelopeWireFormat {
        guard let firstByte = data.first else {
            return .json  // Default to JSON for empty data
        }

        // Binary format starts with version byte 0x01
        if firstByte == BinaryEnvelopeVersion {
            return .binary
        }

        // JSON starts with '{' (0x7B)
        return .json
    }
}

// MARK: - Unified Encoding/Decoding

extension MeshEnvelope {

    /// Encode envelope using specified wire format
    public func encode(format: EnvelopeWireFormat) throws -> Data {
        switch format {
        case .json:
            return try JSONCoding.encoder.encode(self)
        case .binary:
            return try encodeBinary()
        }
    }

    /// Decode envelope, auto-detecting format from data
    public static func decode(_ data: Data) throws -> MeshEnvelope {
        let format = EnvelopeWireFormat.detect(data)
        switch format {
        case .json:
            return try JSONCoding.decoder.decode(MeshEnvelope.self, from: data)
        case .binary:
            return try decodeBinary(data)
        }
    }
}
