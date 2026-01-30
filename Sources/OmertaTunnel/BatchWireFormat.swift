// BatchWireFormat.swift - Pack/unpack utilities for batched tunnel packets
//
// First byte tag distinguishes packet types:
//   0x01 = single packet:  [0x01][data...]
//   0x02 = batch:          [0x02][1B reserved][2B count][2B len₁][data₁ padded to even][2B len₂][data₂ padded to even]...
//
// All length and count fields are UInt16 big-endian. Each packet is padded to
// 2-byte alignment (at most 1 byte) so length fields land on even offsets.

import Foundation

public enum BatchWireFormat {

    // MARK: - Tags

    public static let singleTag: UInt8 = 0x01
    public static let batchTag: UInt8 = 0x02

    // MARK: - Packing

    /// Wrap a single packet with the single-packet tag.
    public static func packSingle(_ data: Data) -> Data {
        var out = Data(capacity: 1 + data.count)
        out.append(singleTag)
        out.append(data)
        return out
    }

    /// Pack multiple packets into a batch.
    /// Precondition: each packet.count <= UInt16.max
    public static func packBatch(_ packets: [Data]) -> Data {
        precondition(packets.count <= Int(UInt16.max), "Too many packets for batch")

        // Calculate capacity
        var capacity = 1 + 1 + 2  // tag + reserved + count
        for pkt in packets {
            capacity += 2 + pkt.count + (pkt.count & 1)  // length + data + padding
        }
        var out = Data(capacity: capacity)

        out.append(batchTag)
        out.append(0x00)  // reserved
        appendUInt16(&out, UInt16(packets.count))

        for pkt in packets {
            precondition(pkt.count <= Int(UInt16.max), "Packet too large for batch")
            appendUInt16(&out, UInt16(pkt.count))
            out.append(pkt)
            // Pad to 2-byte alignment
            if pkt.count & 1 != 0 {
                out.append(0x00)
            }
        }

        return out
    }

    // MARK: - Unpacking

    /// Unpack data into one or more packets.
    /// Returns an empty array for empty batch or invalid data.
    public static func unpack(_ data: Data) -> [Data] {
        guard let first = data.first else { return [] }

        switch first {
        case singleTag:
            if data.count <= 1 { return [Data()] }
            return [data.dropFirst().asData]

        case batchTag:
            return unpackBatch(data)

        default:
            // Unknown tag — treat as raw single packet for forward compatibility
            return [data]
        }
    }

    // MARK: - Private

    private static func unpackBatch(_ data: Data) -> [Data] {
        // Minimum: tag(1) + reserved(1) + count(2) = 4 bytes
        guard data.count >= 4 else { return [] }

        let base = data.startIndex
        // skip tag + reserved
        let count = readUInt16(data, at: base + 2)
        guard count > 0 else { return [] }

        var packets: [Data] = []
        packets.reserveCapacity(Int(count))
        var offset = base + 4

        for _ in 0..<count {
            guard offset + 2 <= data.endIndex else { break }
            let len = Int(readUInt16(data, at: offset))
            offset += 2

            guard offset + len <= data.endIndex else { break }
            let pkt = Data(data[offset..<(offset + len)])
            packets.append(pkt)
            offset += len
            // Skip padding byte if odd length
            if len & 1 != 0 {
                offset += 1
            }
        }

        return packets
    }

    private static func appendUInt16(_ data: inout Data, _ value: UInt16) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xFF))
    }

    private static func readUInt16(_ data: Data, at index: Data.Index) -> UInt16 {
        return (UInt16(data[index]) << 8) | UInt16(data[index + 1])
    }
}

// MARK: - Data Extension

private extension Data.SubSequence {
    var asData: Data { Data(self) }
}
