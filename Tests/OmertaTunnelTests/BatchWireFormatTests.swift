import Foundation
import Testing
@testable import OmertaTunnel

@Suite("BatchWireFormat Tests")
struct BatchWireFormatTests {

    // MARK: - Pack Tests

    @Test func testPackSingle() {
        let payload = Data([0xCA, 0xFE, 0xBA, 0xBE])
        let packed = BatchWireFormat.packSingle(payload)

        #expect(packed.count == 1 + payload.count)
        #expect(packed[0] == BatchWireFormat.singleTag)
        #expect(packed.dropFirst() == payload)
    }

    @Test func testPackBatch() {
        let p1 = Data([0x01, 0x02])
        let p2 = Data([0x03, 0x04, 0x05])
        let packed = BatchWireFormat.packBatch([p1, p2])

        #expect(packed[0] == BatchWireFormat.batchTag)
        #expect(packed[1] == 0x00) // reserved byte

        // 2-byte big-endian count == 2
        let count = UInt16(packed[2]) << 8 | UInt16(packed[3])
        #expect(count == 2)

        // First packet: 2B length (2) + 2B data = 4 bytes
        let len1 = UInt16(packed[4]) << 8 | UInt16(packed[5])
        #expect(len1 == UInt16(p1.count))
        #expect(Data(packed[6..<8]) == p1)

        // Second packet: 2B length (3) + 3B data + 1B padding = 6 bytes
        let len2 = UInt16(packed[8]) << 8 | UInt16(packed[9])
        #expect(len2 == UInt16(p2.count))
        #expect(Data(packed[10..<13]) == p2)
    }

    // MARK: - Unpack Tests

    @Test func testUnpackSingle() {
        let payload = Data([0xAA, 0xBB, 0xCC])
        var wire = Data([BatchWireFormat.singleTag])
        wire.append(payload)

        let result = BatchWireFormat.unpack(wire)
        #expect(result.count == 1)
        #expect(result[0] == payload)
    }

    @Test func testUnpackBatch() {
        let p1 = Data([0x10, 0x20])
        let p2 = Data([0x30, 0x40, 0x50])
        let packed = BatchWireFormat.packBatch([p1, p2])

        let result = BatchWireFormat.unpack(packed)
        #expect(result.count == 2)
        #expect(result[0] == p1)
        #expect(result[1] == p2)
    }

    // MARK: - Round-Trip Tests

    @Test func testRoundTripSingle() {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let packed = BatchWireFormat.packSingle(payload)
        let unpacked = BatchWireFormat.unpack(packed)

        #expect(unpacked.count == 1)
        #expect(unpacked[0] == payload)
    }

    @Test func testRoundTripBatch() {
        let packets: [Data] = [
            Data([0x01]),
            Data([0x02, 0x03]),
            Data([0x04, 0x05, 0x06]),
            Data([0x07, 0x08, 0x09, 0x0A]),
        ]
        let packed = BatchWireFormat.packBatch(packets)
        let unpacked = BatchWireFormat.unpack(packed)

        #expect(unpacked.count == packets.count)
        for (original, recovered) in zip(packets, unpacked) {
            #expect(original == recovered)
        }
    }

    // MARK: - Edge Cases

    @Test func testUnpackEmptyBatch() {
        let packed = BatchWireFormat.packBatch([])
        let result = BatchWireFormat.unpack(packed)
        #expect(result.isEmpty)
    }

    @Test func testUnpackLargePayloads() {
        let large1 = Data(repeating: 0xAA, count: 4096)
        let large2 = Data(repeating: 0xBB, count: 8192)
        let large3 = Data(repeating: 0xCC, count: 12345)

        let packed = BatchWireFormat.packBatch([large1, large2, large3])
        let unpacked = BatchWireFormat.unpack(packed)

        #expect(unpacked.count == 3)
        #expect(unpacked[0] == large1)
        #expect(unpacked[1] == large2)
        #expect(unpacked[2] == large3)
    }

    @Test func testUnpackManyPackets() {
        let packets = (0..<1024).map { i in
            Data([UInt8(i & 0xFF), UInt8((i >> 8) & 0xFF)])
        }
        let packed = BatchWireFormat.packBatch(packets)
        let unpacked = BatchWireFormat.unpack(packed)

        #expect(unpacked.count == packets.count)
        for (original, recovered) in zip(packets, unpacked) {
            #expect(original == recovered)
        }
    }

    @Test func testOddLengthPadding() {
        // Odd-length packets should be padded to even boundary in the wire format
        let oddPacket = Data([0x01, 0x02, 0x03]) // 3 bytes — odd
        let packed = BatchWireFormat.packBatch([oddPacket])

        // Header: 1 tag + 1 reserved + 2 count = 4
        // Packet: 2 length + 3 data + 1 padding = 6
        #expect(packed.count == 4 + 6)

        // Round-trip still works
        let unpacked = BatchWireFormat.unpack(packed)
        #expect(unpacked.count == 1)
        #expect(unpacked[0] == oddPacket)
    }

    @Test func testEmptyData() {
        let result = BatchWireFormat.unpack(Data())
        #expect(result.isEmpty)
    }

    @Test func testUnknownTagPassthrough() {
        let raw = Data([0xFF, 0x01, 0x02, 0x03])
        let result = BatchWireFormat.unpack(raw)

        #expect(result.count == 1)
        #expect(result[0] == raw)
    }
}
