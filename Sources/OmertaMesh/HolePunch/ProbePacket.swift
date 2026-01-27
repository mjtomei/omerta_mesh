// ProbePacket.swift - UDP hole punch probe packet format

import Foundation

/// Magic bytes identifying hole punch probes
public let holePunchProbeMagic: [UInt8] = [0x4F, 0x4D, 0x45, 0x52, 0x54, 0x41, 0x48, 0x50] // "OMERTAHP"

/// A UDP hole punch probe packet
public struct ProbePacket: Sendable {
    /// Sequence number for ordering/deduplication
    public let sequence: UInt32

    /// Timestamp when probe was sent (ms since epoch)
    public let timestamp: UInt64

    /// Sender's peer ID (truncated to 16 bytes)
    public let senderIdPrefix: Data

    /// Whether this is a response probe
    public let isResponse: Bool

    /// Total packet size
    public static let packetSize = 8 + 4 + 8 + 16 + 1  // magic + seq + timestamp + peerId + isResponse

    public init(
        sequence: UInt32,
        timestamp: UInt64 = UInt64(Date().timeIntervalSince1970 * 1000),
        senderId: String,
        isResponse: Bool = false
    ) {
        self.sequence = sequence
        self.timestamp = timestamp
        self.isResponse = isResponse

        // Truncate or pad sender ID to 16 bytes
        var idData = senderId.data(using: .utf8) ?? Data()
        if idData.count > 16 {
            idData = idData.prefix(16)
        } else if idData.count < 16 {
            idData.append(contentsOf: [UInt8](repeating: 0, count: 16 - idData.count))
        }
        self.senderIdPrefix = idData
    }

    /// Serialize probe to Data
    public func serialize() -> Data {
        var data = Data(holePunchProbeMagic)

        // Sequence number (big endian)
        withUnsafeBytes(of: sequence.bigEndian) { data.append(contentsOf: $0) }

        // Timestamp (big endian)
        withUnsafeBytes(of: timestamp.bigEndian) { data.append(contentsOf: $0) }

        // Sender ID prefix
        data.append(senderIdPrefix)

        // Is response flag
        data.append(isResponse ? 1 : 0)

        return data
    }

    /// Parse probe from Data
    public static func parse(_ data: Data) -> ProbePacket? {
        guard data.count >= packetSize else { return nil }

        let bytes = [UInt8](data)

        // Verify magic
        guard Array(bytes.prefix(8)) == holePunchProbeMagic else { return nil }

        // Parse sequence
        let sequence = UInt32(bytes[8]) << 24 | UInt32(bytes[9]) << 16 |
                       UInt32(bytes[10]) << 8 | UInt32(bytes[11])

        // Parse timestamp
        let timestamp = UInt64(bytes[12]) << 56 | UInt64(bytes[13]) << 48 |
                        UInt64(bytes[14]) << 40 | UInt64(bytes[15]) << 32 |
                        UInt64(bytes[16]) << 24 | UInt64(bytes[17]) << 16 |
                        UInt64(bytes[18]) << 8 | UInt64(bytes[19])

        // Parse sender ID
        let senderIdPrefix = Data(bytes[20..<36])

        // Parse isResponse
        let isResponse = bytes[36] != 0

        return ProbePacket(
            sequence: sequence,
            timestamp: timestamp,
            senderId: String(data: senderIdPrefix.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "",
            isResponse: isResponse
        )
    }

    /// Calculate round-trip time from probe timestamp
    public var rtt: TimeInterval {
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        return TimeInterval(now - timestamp) / 1000.0
    }
}

/// Validates if data is a hole punch probe
public func isHolePunchProbe(_ data: Data) -> Bool {
    guard data.count >= 8 else { return false }
    return Array(data.prefix(8)) == holePunchProbeMagic
}
