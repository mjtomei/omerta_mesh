// FramingTests.swift - Tests for IPC message framing

import XCTest
@testable import OmertaMesh

/// Tests that would have caught the endianness bug where the frame decoder
/// was double-swapping the length prefix bytes.
final class FramingTests: XCTestCase {

    // MARK: - Length Prefix Tests

    func testLengthPrefixIsBigEndian() throws {
        // IPCMessage.encode should write length in big-endian
        let message = "Hello"
        let encoded = try IPCMessage.encode(message)

        // First 4 bytes are length in big-endian
        let lengthBytes = Array(encoded.prefix(4))

        // "Hello" in JSON is "\"Hello\"" which is 7 bytes
        // So the length should be 7, stored as big-endian: [0, 0, 0, 7]
        XCTAssertEqual(lengthBytes[0], 0)
        XCTAssertEqual(lengthBytes[1], 0)
        XCTAssertEqual(lengthBytes[2], 0)
        XCTAssertEqual(lengthBytes[3], 7)
    }

    func testLengthPrefixReadCorrectly() throws {
        // Create a message and verify IPCMessage.readLength works
        let message = "Test message"
        let encoded = try IPCMessage.encode(message)

        let length = IPCMessage.readLength(from: encoded)
        XCTAssertNotNil(length)

        // The JSON payload (minus the 4-byte header) should match the length
        let payloadLength = encoded.count - 4
        XCTAssertEqual(Int(length!), payloadLength)
    }

    func testLengthPrefixForVariousSizes() throws {
        // Test various payload sizes to ensure endianness is correct
        let testCases: [(String, Int)] = [
            ("a", 3),           // "a" in JSON - small
            (String(repeating: "x", count: 100), 102),   // medium
            (String(repeating: "y", count: 1000), 1002), // larger
        ]

        for (input, expectedJsonLength) in testCases {
            let encoded = try IPCMessage.encode(input)

            // Read length manually
            let b0 = UInt32(encoded[0]) << 24
            let b1 = UInt32(encoded[1]) << 16
            let b2 = UInt32(encoded[2]) << 8
            let b3 = UInt32(encoded[3])
            let manualLength = b0 | b1 | b2 | b3

            XCTAssertEqual(Int(manualLength), expectedJsonLength,
                "Length mismatch for input of size \(input.count)")
        }
    }

    func testFrameRoundTrip() throws {
        // Encode a complex object and verify we can decode it
        let original = DaemonStatusData(
            isRunning: true,
            daemonType: "meshd",
            networkId: "test-network-123",
            uptime: 3600.5,
            additionalInfo: [
                "peerId": "abc123def456",
                "peerCount": "42",
                "connectionCount": "10"
            ]
        )

        let encoded = try IPCMessage.encode(original)

        // Verify length prefix
        let length = IPCMessage.readLength(from: encoded)
        XCTAssertNotNil(length)
        XCTAssertEqual(Int(length!) + 4, encoded.count)

        // Decode
        let payload = Data(encoded.dropFirst(4))
        let decoded = try IPCMessage.decode(DaemonStatusData.self, from: payload)

        XCTAssertEqual(original.isRunning, decoded.isRunning)
        XCTAssertEqual(original.networkId, decoded.networkId)
        XCTAssertEqual(original.additionalInfo["peerId"], decoded.additionalInfo["peerId"])
    }

    // MARK: - Edge Cases

    func testEmptyPayload() throws {
        // Empty string encodes to "" in JSON (2 bytes)
        let encoded = try IPCMessage.encode("")

        let length = IPCMessage.readLength(from: encoded)
        XCTAssertEqual(length, 2)  // Just the quotes

        let payload = Data(encoded.dropFirst(4))
        let decoded = try IPCMessage.decode(String.self, from: payload)
        XCTAssertEqual(decoded, "")
    }

    func testLargePayload() throws {
        // Test a payload larger than 255 bytes (requires more than 1 byte in length)
        let largeString = String(repeating: "x", count: 500)
        let encoded = try IPCMessage.encode(largeString)

        let length = IPCMessage.readLength(from: encoded)
        XCTAssertNotNil(length)
        XCTAssertGreaterThan(length!, 255)

        // Verify the first byte is NOT the full length (it's big-endian split)
        XCTAssertEqual(encoded[0], 0)  // 502 < 65536, so first 2 bytes are 0
        XCTAssertEqual(encoded[1], 0)

        let payload = Data(encoded.dropFirst(4))
        let decoded = try IPCMessage.decode(String.self, from: payload)
        XCTAssertEqual(decoded, largeString)
    }

    func testLengthPrefix65536() throws {
        // Test payload exactly at 65536 bytes (0x00010000 in big-endian)
        let largeString = String(repeating: "a", count: 65536 - 2)  // -2 for JSON quotes
        let encoded = try IPCMessage.encode(largeString)

        // Length should be 65536
        XCTAssertEqual(encoded[0], 0x00)
        XCTAssertEqual(encoded[1], 0x01)
        XCTAssertEqual(encoded[2], 0x00)
        XCTAssertEqual(encoded[3], 0x00)
    }

    // MARK: - Malformed Frame Tests

    func testTruncatedLengthPrefix() {
        // Only 2 bytes instead of 4
        let truncated = Data([0x00, 0x00])
        let length = IPCMessage.readLength(from: truncated)
        XCTAssertNil(length)
    }

    func testEmptyData() {
        let empty = Data()
        let length = IPCMessage.readLength(from: empty)
        XCTAssertNil(length)
    }

    // MARK: - Binary Data Tests

    func testBinaryLengthWriting() {
        // Manually construct what we expect
        // For a 256-byte payload, big-endian length is: [0, 0, 1, 0]
        var length = UInt32(256).bigEndian
        let bytes = withUnsafeBytes(of: &length) { Array($0) }

        XCTAssertEqual(bytes[0], 0)
        XCTAssertEqual(bytes[1], 0)
        XCTAssertEqual(bytes[2], 1)
        XCTAssertEqual(bytes[3], 0)
    }

    func testBinaryLengthReading() {
        // Big-endian [0, 0, 1, 0] should be 256
        let bytes: [UInt8] = [0, 0, 1, 0]

        // Construct UInt32 from bytes manually to avoid alignment issues on Linux
        let length = UInt32(bytes[0]) << 24 |
                     UInt32(bytes[1]) << 16 |
                     UInt32(bytes[2]) << 8 |
                     UInt32(bytes[3])

        XCTAssertEqual(length, 256)
    }

    // MARK: - Cross-Platform Consistency

    func testEndiannessConsistency() {
        // This test ensures our encoding matches what we expect regardless of platform
        let testValue: UInt32 = 0x12345678

        // Big-endian representation should be [0x12, 0x34, 0x56, 0x78]
        var bigEndian = testValue.bigEndian
        let bytes = withUnsafeBytes(of: &bigEndian) { Array($0) }

        // On ALL platforms, bigEndian should give us the bytes in network order
        XCTAssertEqual(bytes[0], 0x12)
        XCTAssertEqual(bytes[1], 0x34)
        XCTAssertEqual(bytes[2], 0x56)
        XCTAssertEqual(bytes[3], 0x78)
    }
}
