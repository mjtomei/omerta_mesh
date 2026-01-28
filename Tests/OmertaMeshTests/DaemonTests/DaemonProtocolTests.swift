// DaemonProtocolTests.swift - Tests for daemon protocol types

import XCTest
@testable import OmertaMesh

final class DaemonProtocolTests: XCTestCase {

    // MARK: - Base Daemon Command Tests

    func testBaseDaemonCommandStatusEncodeDecode() throws {
        let command = BaseDaemonCommand.status

        let encoder = JSONEncoder()
        let data = try encoder.encode(command)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(BaseDaemonCommand.self, from: data)

        switch decoded {
        case .status:
            break // Success
        default:
            XCTFail("Expected .status, got \(decoded)")
        }
    }

    func testBaseDaemonCommandShutdownEncodeDecode() throws {
        let command = BaseDaemonCommand.shutdown(graceful: true, timeoutSeconds: 30)

        let encoder = JSONEncoder()
        let data = try encoder.encode(command)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(BaseDaemonCommand.self, from: data)

        switch decoded {
        case .shutdown(let graceful, let timeout):
            XCTAssertTrue(graceful)
            XCTAssertEqual(timeout, 30)
        default:
            XCTFail("Expected .shutdown, got \(decoded)")
        }
    }

    // MARK: - Base Daemon Response Tests

    func testBaseDaemonResponseStatusEncodeDecode() throws {
        let status = DaemonStatusData(
            isRunning: true,
            daemonType: "meshd",
            networkId: "test-network",
            uptime: 3600.5,
            additionalInfo: ["peerId": "abc123"]
        )
        let response = BaseDaemonResponse.status(status)

        let encoder = JSONEncoder()
        let data = try encoder.encode(response)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(BaseDaemonResponse.self, from: data)

        switch decoded {
        case .status(let decodedStatus):
            XCTAssertTrue(decodedStatus.isRunning)
            XCTAssertEqual(decodedStatus.daemonType, "meshd")
            XCTAssertEqual(decodedStatus.networkId, "test-network")
            XCTAssertEqual(decodedStatus.uptime, 3600.5)
            XCTAssertEqual(decodedStatus.additionalInfo["peerId"], "abc123")
        default:
            XCTFail("Expected .status, got \(decoded)")
        }
    }

    func testBaseDaemonResponseShutdownAckEncodeDecode() throws {
        let ack = ShutdownAckData(accepted: true, reason: nil, estimatedSeconds: 5)
        let response = BaseDaemonResponse.shutdownAck(ack)

        let encoder = JSONEncoder()
        let data = try encoder.encode(response)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(BaseDaemonResponse.self, from: data)

        switch decoded {
        case .shutdownAck(let decodedAck):
            XCTAssertTrue(decodedAck.accepted)
            XCTAssertEqual(decodedAck.estimatedSeconds, 5)
            XCTAssertNil(decodedAck.reason)
        default:
            XCTFail("Expected .shutdownAck, got \(decoded)")
        }
    }

    func testBaseDaemonResponseErrorEncodeDecode() throws {
        let response = BaseDaemonResponse.error("Something went wrong")

        let encoder = JSONEncoder()
        let data = try encoder.encode(response)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(BaseDaemonResponse.self, from: data)

        switch decoded {
        case .error(let message):
            XCTAssertEqual(message, "Something went wrong")
        default:
            XCTFail("Expected .error, got \(decoded)")
        }
    }

    // MARK: - Peer Data Tests

    func testPeerDataEncodeDecode() throws {
        let peer = PeerData(
            peerId: "peer123",
            endpoint: "192.168.1.1:9999",
            natType: "symmetric",
            lastSeen: Date(timeIntervalSince1970: 1700000000),
            isConnected: true,
            isDirect: false
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(peer)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(PeerData.self, from: data)

        XCTAssertEqual(decoded.peerId, "peer123")
        XCTAssertEqual(decoded.endpoint, "192.168.1.1:9999")
        XCTAssertEqual(decoded.natType, "symmetric")
        XCTAssertEqual(decoded.lastSeen, Date(timeIntervalSince1970: 1700000000))
        XCTAssertTrue(decoded.isConnected)
        XCTAssertFalse(decoded.isDirect)
    }

    // MARK: - Ping Result Data Tests

    func testPingResultDataEncodeDecode() throws {
        let result = PingResultData(
            peerId: "peer123",
            rttMs: 42.5,
            endpoint: "192.168.1.1:9999",
            natType: "cone",
            peersDiscovered: 5
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(result)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(PingResultData.self, from: data)

        XCTAssertEqual(decoded.peerId, "peer123")
        XCTAssertEqual(decoded.rttMs, 42.5)
        XCTAssertEqual(decoded.endpoint, "192.168.1.1:9999")
        XCTAssertEqual(decoded.natType, "cone")
        XCTAssertEqual(decoded.peersDiscovered, 5)
    }

    // MARK: - Connect Result Data Tests

    func testConnectResultDataSuccessEncodeDecode() throws {
        let result = ConnectResultData(
            success: true,
            peerId: "peer123",
            endpoint: "192.168.1.1:9999",
            isDirect: true,
            method: "direct",
            rttMs: 15.0,
            error: nil
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(result)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ConnectResultData.self, from: data)

        XCTAssertTrue(decoded.success)
        XCTAssertEqual(decoded.peerId, "peer123")
        XCTAssertEqual(decoded.endpoint, "192.168.1.1:9999")
        XCTAssertTrue(decoded.isDirect)
        XCTAssertEqual(decoded.method, "direct")
        XCTAssertEqual(decoded.rttMs, 15.0)
        XCTAssertNil(decoded.error)
    }

    func testConnectResultDataFailureEncodeDecode() throws {
        let result = ConnectResultData(
            success: false,
            peerId: "peer123",
            error: "Connection timed out"
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(result)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(ConnectResultData.self, from: data)

        XCTAssertFalse(decoded.success)
        XCTAssertEqual(decoded.peerId, "peer123")
        XCTAssertEqual(decoded.error, "Connection timed out")
    }

    // MARK: - Network Info Data Tests

    func testNetworkInfoDataEncodeDecode() throws {
        let info = NetworkInfoData(
            id: "net123",
            name: "TestNetwork",
            isActive: true,
            joinedAt: Date(timeIntervalSince1970: 1700000000),
            bootstrapPeerCount: 3
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(info)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(NetworkInfoData.self, from: data)

        XCTAssertEqual(decoded.id, "net123")
        XCTAssertEqual(decoded.name, "TestNetwork")
        XCTAssertTrue(decoded.isActive)
        XCTAssertEqual(decoded.joinedAt, Date(timeIntervalSince1970: 1700000000))
        XCTAssertEqual(decoded.bootstrapPeerCount, 3)
    }

    // MARK: - IPC Message Tests

    func testIPCMessageEncodeDecodeRoundTrip() throws {
        let status = DaemonStatusData(
            isRunning: true,
            daemonType: "meshd",
            networkId: "test"
        )

        let encoded = try IPCMessage.encode(status)

        // Skip the 4-byte length prefix to get JSON payload
        let jsonPayload = encoded.dropFirst(4)
        let decoded = try IPCMessage.decode(DaemonStatusData.self, from: Data(jsonPayload))

        XCTAssertTrue(decoded.isRunning)
        XCTAssertEqual(decoded.daemonType, "meshd")
        XCTAssertEqual(decoded.networkId, "test")
    }

    func testIPCMessageLengthPrefix() throws {
        let message = "Hello, World!"
        let encoded = try IPCMessage.encode(message)

        // First 4 bytes should be the length in big-endian
        // Construct UInt32 from bytes manually to avoid alignment issues on Linux
        let length = UInt32(encoded[0]) << 24 |
                     UInt32(encoded[1]) << 16 |
                     UInt32(encoded[2]) << 8 |
                     UInt32(encoded[3])

        // The remaining data should be the JSON payload
        XCTAssertEqual(Int(length), encoded.count - 4)
    }

    func testIPCMessageTooLarge() {
        // Create a message larger than the max size
        let largeData = Data(repeating: 0x41, count: IPCMessage.maxMessageSize + 1)
        let largeMessage = largeData.base64EncodedString()

        XCTAssertThrowsError(try IPCMessage.encode(largeMessage)) { error in
            if case IPCError.messageTooLarge(let size) = error {
                XCTAssertGreaterThan(size, IPCMessage.maxMessageSize)
            } else {
                XCTFail("Expected messageTooLarge error")
            }
        }
    }

    // MARK: - Socket Paths Tests

    func testDaemonSocketPathsMeshDaemonControl() {
        let path = DaemonSocketPaths.meshDaemonControl(networkId: "test-network")
        XCTAssertEqual(path, "/tmp/omerta-meshd-test-network.sock")
    }

    func testDaemonSocketPathsMeshDaemonData() {
        let path = DaemonSocketPaths.meshDaemonData(networkId: "test-network")
        XCTAssertEqual(path, "/tmp/omerta-meshd-test-network.data.sock")
    }

    func testDaemonSocketPathsVMDaemonControl() {
        let path = DaemonSocketPaths.vmDaemonControl(networkId: "test-network")
        XCTAssertEqual(path, "/tmp/omertad-test-network.sock")
    }

    func testDaemonSocketPathsSanitizesNetworkId() {
        // Network IDs with special characters should be handled
        let path = DaemonSocketPaths.meshDaemonControl(networkId: "test/network")
        XCTAssertFalse(path.contains("//"))
    }

    // MARK: - IPC Error Tests

    func testIPCErrorDescriptions() {
        let connectionError = IPCError.connectionFailed("test reason")
        XCTAssertTrue(connectionError.description.contains("test reason"))

        let timeoutError = IPCError.timeout
        XCTAssertFalse(timeoutError.description.isEmpty)

        let socketError = IPCError.socketError("socket issue")
        XCTAssertTrue(socketError.description.contains("socket issue"))

        let sizeError = IPCError.messageTooLarge(999999)
        XCTAssertTrue(sizeError.description.contains("999999"))
    }

    // MARK: - Health Check Result Tests

    func testHealthCheckResultDataEncodeDecode() throws {
        let result = HealthCheckResultData(
            peerId: "peer123",
            isHealthy: true,
            rttMs: 25.0,
            lastSeen: Date(timeIntervalSince1970: 1700000000),
            error: nil
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(result)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(HealthCheckResultData.self, from: data)

        XCTAssertEqual(decoded.peerId, "peer123")
        XCTAssertTrue(decoded.isHealthy)
        XCTAssertEqual(decoded.rttMs, 25.0)
        XCTAssertEqual(decoded.lastSeen, Date(timeIntervalSince1970: 1700000000))
        XCTAssertNil(decoded.error)
    }

    // MARK: - Send Message Result Tests

    func testSendMessageResultDataEncodeDecode() throws {
        let result = SendMessageResultData(
            success: true,
            messageId: "msg-123",
            deliveryConfirmed: true,
            error: nil
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(result)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(SendMessageResultData.self, from: data)

        XCTAssertTrue(decoded.success)
        XCTAssertEqual(decoded.messageId, "msg-123")
        XCTAssertTrue(decoded.deliveryConfirmed)
        XCTAssertNil(decoded.error)
    }
}
