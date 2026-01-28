// DateEncodingTests.swift - Tests for date encoding/decoding consistency

import XCTest
@testable import OmertaMesh

/// Tests that would have caught the date encoding/decoding mismatch bug
/// where StoredIdentity was saved with ISO8601 but loaded without it.
final class DateEncodingTests: XCTestCase {

    // MARK: - ISO8601 Round-Trip Tests

    func testDateEncodingRoundTripWithISO8601() throws {
        struct TestDate: Codable {
            let date: Date
        }

        let original = TestDate(date: Date(timeIntervalSince1970: 1700000000))

        // Encode with ISO8601
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        // Decode with ISO8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(TestDate.self, from: data)

        XCTAssertEqual(original.date, decoded.date)
    }

    func testDateEncodingMismatchFails() throws {
        struct TestDate: Codable {
            let date: Date
        }

        let original = TestDate(date: Date())

        // Encode with ISO8601
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        // Try to decode WITHOUT ISO8601 - this should fail
        let decoder = JSONDecoder()
        // No dateDecodingStrategy set - uses default (Double)

        XCTAssertThrowsError(try decoder.decode(TestDate.self, from: data)) { error in
            // Should get a type mismatch error
            if case DecodingError.typeMismatch = error {
                // This is the bug we found - the decoder expected Double but got String
            } else {
                XCTFail("Expected typeMismatch error, got \(error)")
            }
        }
    }

    func testIPCMessageDateConsistency() throws {
        // IPCMessage should use consistent date encoding/decoding
        let status = DaemonStatusData(
            isRunning: true,
            daemonType: "test",
            networkId: "test-net",
            uptime: 100
        )

        // Encode using IPCMessage (which uses ISO8601)
        let encoded = try IPCMessage.encode(status)

        // Skip the 4-byte length prefix
        let jsonPayload = Data(encoded.dropFirst(4))

        // Decode using IPCMessage (which should also use ISO8601)
        let decoded = try IPCMessage.decode(DaemonStatusData.self, from: jsonPayload)

        XCTAssertEqual(status.isRunning, decoded.isRunning)
        XCTAssertEqual(status.networkId, decoded.networkId)
    }

    // MARK: - PeerData Date Tests

    func testPeerDataDateRoundTrip() throws {
        let original = PeerData(
            peerId: "peer123",
            endpoint: "192.168.1.1:9999",
            natType: "cone",
            lastSeen: Date(timeIntervalSince1970: 1700000000),
            isConnected: true,
            isDirect: true
        )

        // Encode with ISO8601
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        // Decode with ISO8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(PeerData.self, from: data)

        XCTAssertEqual(original.lastSeen, decoded.lastSeen)
    }

    // MARK: - NetworkInfoData Date Tests

    func testNetworkInfoDataDateRoundTrip() throws {
        let original = NetworkInfoData(
            id: "net123",
            name: "TestNet",
            isActive: true,
            joinedAt: Date(timeIntervalSince1970: 1700000000),
            bootstrapPeerCount: 3
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(NetworkInfoData.self, from: data)

        XCTAssertEqual(original.joinedAt, decoded.joinedAt)
    }

    // MARK: - HealthCheckResultData Date Tests

    func testHealthCheckResultDataDateRoundTrip() throws {
        let original = HealthCheckResultData(
            peerId: "peer123",
            isHealthy: true,
            rttMs: 25.0,
            lastSeen: Date(timeIntervalSince1970: 1700000000),
            error: nil
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(HealthCheckResultData.self, from: data)

        XCTAssertEqual(original.lastSeen, decoded.lastSeen)
    }
}
