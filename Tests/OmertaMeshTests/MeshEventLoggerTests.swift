// MeshEventLoggerTests.swift - Tests for MeshEventLogger

import XCTest
@testable import OmertaMesh

final class MeshEventLoggerTests: XCTestCase {

    var tempDir: String!
    var logger: MeshEventLogger!

    override func setUp() async throws {
        // Create a unique temp directory for each test
        tempDir = NSTemporaryDirectory() + "MeshEventLoggerTests-\(UUID().uuidString)"
        logger = try MeshEventLogger(logDir: tempDir)
    }

    override func tearDown() async throws {
        // Stop the logger and clean up
        await logger?.stop()
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    // MARK: - Initialization Tests

    func testInitializationCreatesDirectory() async throws {
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempDir))
    }

    func testInitializationWithDefaultPath() async throws {
        // This tests that initialization doesn't throw with default path
        let defaultLogger = try MeshEventLogger()
        await defaultLogger.stop()
    }

    // MARK: - Peer Discovery Tests

    func testRecordPeerDiscovery() async throws {
        await logger.recordPeerDiscovery(
            peerId: "test-peer-123",
            machineId: "machine-456",
            method: .bootstrap,
            sourcePeerId: nil,
            endpoint: "192.168.1.1:9999"
        )

        await logger.stop()

        // Verify log file was created and has content
        let logPath = "\(tempDir!)/peer_discovery.jsonl"
        XCTAssertTrue(FileManager.default.fileExists(atPath: logPath))

        let content = try String(contentsOfFile: logPath)
        XCTAssertTrue(content.contains("test-peer-123"))
        XCTAssertTrue(content.contains("machine-456"))
        XCTAssertTrue(content.contains("bootstrap"))
        XCTAssertTrue(content.contains("192.168.1.1:9999"))
    }

    func testRecordPeerDiscoveryWithGossip() async throws {
        await logger.recordPeerDiscovery(
            peerId: "discovered-peer",
            machineId: nil,
            method: .gossip,
            sourcePeerId: "gossip-source",
            endpoint: "10.0.0.1:8888"
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/peer_discovery.jsonl")
        XCTAssertTrue(content.contains("discovered-peer"))
        XCTAssertTrue(content.contains("gossip"))
        XCTAssertTrue(content.contains("gossip-source"))
    }

    // MARK: - Peer Seen Tests

    func testRecordPeerSeenFirstTime() async throws {
        await logger.recordPeerSeen(
            peerId: "new-peer",
            endpoint: "1.2.3.4:5678",
            natType: "full_cone"
        )

        let peers = await logger.getAllPeersSeen()
        XCTAssertEqual(peers.count, 1)
        XCTAssertEqual(peers.first?.peerId, "new-peer")
        XCTAssertEqual(peers.first?.lastEndpoint, "1.2.3.4:5678")
        XCTAssertEqual(peers.first?.lastNATType, "full_cone")
    }

    func testRecordPeerSeenUpdatesExisting() async throws {
        // First sighting
        await logger.recordPeerSeen(
            peerId: "existing-peer",
            endpoint: "1.1.1.1:1111",
            natType: "symmetric"
        )

        // Wait a bit
        try await Task.sleep(for: .milliseconds(10))

        // Second sighting with different endpoint
        await logger.recordPeerSeen(
            peerId: "existing-peer",
            endpoint: "2.2.2.2:2222",
            natType: "restricted"
        )

        let peers = await logger.getAllPeersSeen()
        XCTAssertEqual(peers.count, 1)
        XCTAssertEqual(peers.first?.peerId, "existing-peer")
        XCTAssertEqual(peers.first?.lastEndpoint, "2.2.2.2:2222")
        XCTAssertEqual(peers.first?.lastNATType, "restricted")

        // firstSeen should be before lastSeen
        if let peer = peers.first {
            XCTAssertTrue(peer.firstSeen <= peer.lastSeen)
        }
    }

    // MARK: - Connection Event Tests

    func testRecordConnectionEstablished() async throws {
        await logger.recordConnectionEvent(
            peerId: "connected-peer",
            machineId: "machine-id",
            eventType: .established,
            connectionType: .direct,
            endpoint: "5.5.5.5:5555",
            error: nil,
            durationMs: 150
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/connections.jsonl")
        XCTAssertTrue(content.contains("connected-peer"))
        XCTAssertTrue(content.contains("established"))
        XCTAssertTrue(content.contains("direct"))
        XCTAssertTrue(content.contains("150"))
    }

    func testRecordConnectionFailed() async throws {
        await logger.recordConnectionEvent(
            peerId: "failed-peer",
            machineId: nil,
            eventType: .failed,
            connectionType: nil,
            endpoint: "6.6.6.6:6666",
            error: "Connection refused",
            durationMs: nil
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/connections.jsonl")
        XCTAssertTrue(content.contains("failed-peer"))
        XCTAssertTrue(content.contains("failed"))
        XCTAssertTrue(content.contains("Connection refused"))
    }

    // MARK: - Latency Tracking Tests

    func testRecordLatencySample() async throws {
        await logger.recordLatencySample(peerId: "latency-peer", latencyMs: 50.0)
        await logger.recordLatencySample(peerId: "latency-peer", latencyMs: 60.0)
        await logger.recordLatencySample(peerId: "latency-peer", latencyMs: 70.0)

        // Samples are kept in memory until flushed
        // We can trigger a flush by stopping the logger
        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/latency_stats.jsonl")
        XCTAssertTrue(content.contains("latency-peer"))
        XCTAssertTrue(content.contains("sampleCount"))
        XCTAssertTrue(content.contains("meanMs"))
    }

    func testRecordLatencyLoss() async throws {
        await logger.recordLatencyLoss(peerId: "lossy-peer")
        await logger.recordLatencyLoss(peerId: "lossy-peer")

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/latency_stats.jsonl")
        XCTAssertTrue(content.contains("lossy-peer"))
        XCTAssertTrue(content.contains("\"lossCount\":2"))
    }

    // MARK: - NAT Event Tests

    func testRecordNATTypeChange() async throws {
        await logger.recordNATTypeChange(oldType: "symmetric", newType: "full_cone")

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/nat_events.jsonl")
        XCTAssertTrue(content.contains("type_changed"))
        XCTAssertTrue(content.contains("symmetric"))
        XCTAssertTrue(content.contains("full_cone"))
    }

    func testRecordEndpointChange() async throws {
        await logger.recordEndpointChange(oldEndpoint: "1.1.1.1:1111", newEndpoint: "2.2.2.2:2222")

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/nat_events.jsonl")
        XCTAssertTrue(content.contains("endpoint_changed"))
        XCTAssertTrue(content.contains("1.1.1.1:1111"))
        XCTAssertTrue(content.contains("2.2.2.2:2222"))
    }

    // MARK: - Hole Punch Event Tests

    func testRecordHolePunchStarted() async throws {
        await logger.recordHolePunchEvent(
            peerId: "nat-peer",
            eventType: .started,
            ourNATType: "restricted",
            peerNATType: "symmetric",
            strategy: "simultaneous",
            durationMs: nil,
            error: nil
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/hole_punch.jsonl")
        XCTAssertTrue(content.contains("nat-peer"))
        XCTAssertTrue(content.contains("started"))
        XCTAssertTrue(content.contains("simultaneous"))
    }

    func testRecordHolePunchSucceeded() async throws {
        await logger.recordHolePunchEvent(
            peerId: "nat-peer",
            eventType: .succeeded,
            ourNATType: "restricted",
            peerNATType: "full_cone",
            strategy: "initiator_first",
            durationMs: 250,
            error: nil
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/hole_punch.jsonl")
        XCTAssertTrue(content.contains("succeeded"))
        XCTAssertTrue(content.contains("250"))
    }

    func testRecordHolePunchFailed() async throws {
        await logger.recordHolePunchEvent(
            peerId: "failed-nat-peer",
            eventType: .failed,
            ourNATType: "symmetric",
            peerNATType: "symmetric",
            strategy: "relay_fallback",
            durationMs: 5000,
            error: "Both peers behind symmetric NAT"
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/hole_punch.jsonl")
        XCTAssertTrue(content.contains("failed"))
        XCTAssertTrue(content.contains("Both peers behind symmetric NAT"))
    }

    // MARK: - Relay Event Tests

    func testRecordRelayStarted() async throws {
        await logger.recordRelayEvent(
            peerId: "relayed-peer",
            relayPeerId: "relay-node",
            eventType: .started,
            reason: "NAT traversal failed",
            durationMs: nil,
            bytesRelayed: nil
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/relay.jsonl")
        XCTAssertTrue(content.contains("relayed-peer"))
        XCTAssertTrue(content.contains("relay-node"))
        XCTAssertTrue(content.contains("started"))
    }

    func testRecordRelayClosed() async throws {
        await logger.recordRelayEvent(
            peerId: "relayed-peer",
            relayPeerId: "relay-node",
            eventType: .closed,
            reason: "Session ended",
            durationMs: 60000,
            bytesRelayed: 1024000
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/relay.jsonl")
        XCTAssertTrue(content.contains("closed"))
        XCTAssertTrue(content.contains("60000"))
        XCTAssertTrue(content.contains("1024000"))
    }

    // MARK: - Message Event Tests

    func testRecordMessageSent() async throws {
        await logger.recordMessageEvent(
            peerId: "target-peer",
            direction: .sent,
            messageType: "data",
            sizeBytes: 512,
            success: true,
            error: nil,
            retryCount: 0
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/messages.jsonl")
        XCTAssertTrue(content.contains("target-peer"))
        XCTAssertTrue(content.contains("sent"))
        XCTAssertTrue(content.contains("data"))
        XCTAssertTrue(content.contains("512"))
    }

    func testRecordMessageReceived() async throws {
        await logger.recordMessageEvent(
            peerId: "source-peer",
            direction: .received,
            messageType: "ping",
            sizeBytes: 64,
            success: true,
            error: nil,
            retryCount: nil
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/messages.jsonl")
        XCTAssertTrue(content.contains("received"))
        XCTAssertTrue(content.contains("ping"))
    }

    func testRecordMessageFailed() async throws {
        await logger.recordMessageEvent(
            peerId: "unreachable-peer",
            direction: .sent,
            messageType: "data",
            sizeBytes: 1024,
            success: false,
            error: "Connection timeout",
            retryCount: 3
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/messages.jsonl")
        XCTAssertTrue(content.contains("\"success\":false"))
        XCTAssertTrue(content.contains("Connection timeout"))
        XCTAssertTrue(content.contains("\"retryCount\":3"))
    }

    // MARK: - Error Event Tests

    func testRecordError() async throws {
        await logger.recordError(
            component: "MeshNode",
            operation: "sendMessage",
            errorType: "network",
            errorMessage: "Socket error: connection reset",
            peerId: "problematic-peer",
            context: ["attempt": "3", "retryDelay": "1000ms"]
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/errors.jsonl")
        XCTAssertTrue(content.contains("MeshNode"))
        XCTAssertTrue(content.contains("sendMessage"))
        XCTAssertTrue(content.contains("network"))
        XCTAssertTrue(content.contains("Socket error"))
        XCTAssertTrue(content.contains("problematic-peer"))
    }

    func testGetRecentErrors() async throws {
        // Record some errors
        for i in 1...5 {
            await logger.recordError(
                component: "TestComponent",
                operation: "testOperation\(i)",
                errorType: "test",
                errorMessage: "Test error \(i)",
                peerId: nil,
                context: nil
            )
        }

        await logger.stop()

        // Re-open to read errors
        let newLogger = try MeshEventLogger(logDir: tempDir)
        let errors = try await newLogger.getRecentErrors(limit: 3)
        await newLogger.stop()

        XCTAssertEqual(errors.count, 3)
        // Most recent first
        XCTAssertTrue(errors.first?.operation.contains("5") ?? false)
    }

    // MARK: - Hourly Stats Tests

    func testRecordHourlyStats() async throws {
        await logger.recordHourlyStats(
            activePeers: 10,
            messagesSent: 1000,
            messagesReceived: 950,
            bytesSent: 512000,
            bytesReceived: 480000,
            directConnections: 8,
            relayConnections: 2,
            holePunchAttempts: 15,
            holePunchSuccesses: 12,
            errors: 5
        )

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/hourly_stats.jsonl")
        XCTAssertTrue(content.contains("\"activePeers\":10"))
        XCTAssertTrue(content.contains("\"messagesSent\":1000"))
        XCTAssertTrue(content.contains("\"holePunchSuccesses\":12"))
    }

    // MARK: - Persistence Tests

    func testPeersSeenPersistence() async throws {
        // Record some peers
        await logger.recordPeerSeen(peerId: "peer-A", endpoint: "1.1.1.1:1111", natType: "full_cone")
        await logger.recordPeerSeen(peerId: "peer-B", endpoint: "2.2.2.2:2222", natType: "symmetric")

        // Stop to trigger save
        await logger.stop()

        // Verify file exists
        let peersPath = "\(tempDir!)/peers_seen.json"
        XCTAssertTrue(FileManager.default.fileExists(atPath: peersPath))

        // Create new logger and verify peers are loaded
        let newLogger = try MeshEventLogger(logDir: tempDir)
        let peers = await newLogger.getAllPeersSeen()
        await newLogger.stop()

        XCTAssertEqual(peers.count, 2)
        let peerIds = Set(peers.map { $0.peerId })
        XCTAssertTrue(peerIds.contains("peer-A"))
        XCTAssertTrue(peerIds.contains("peer-B"))
    }

    // MARK: - JSON Format Tests

    func testJSONLinesFormat() async throws {
        // Record multiple events
        await logger.recordPeerDiscovery(peerId: "p1", machineId: nil, method: .direct, sourcePeerId: nil, endpoint: nil)
        await logger.recordPeerDiscovery(peerId: "p2", machineId: nil, method: .cached, sourcePeerId: nil, endpoint: nil)
        await logger.recordPeerDiscovery(peerId: "p3", machineId: nil, method: .gossip, sourcePeerId: nil, endpoint: nil)

        await logger.stop()

        let content = try String(contentsOfFile: "\(tempDir!)/peer_discovery.jsonl")
        let lines = content.split(separator: "\n")

        XCTAssertEqual(lines.count, 3)

        // Each line should be valid JSON
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        for line in lines {
            let data = Data(line.utf8)
            // Should be able to decode as a dictionary at minimum
            XCTAssertNoThrow(try decoder.decode([String: AnyCodable].self, from: data))
        }
    }
}

// Helper for decoding arbitrary JSON
private struct AnyCodable: Codable {
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let string = try? container.decode(String.self) {
            _ = string
        } else if let int = try? container.decode(Int.self) {
            _ = int
        } else if let double = try? container.decode(Double.self) {
            _ = double
        } else if let bool = try? container.decode(Bool.self) {
            _ = bool
        } else if container.decodeNil() {
            // nil value
        } else {
            // array or object - just skip
        }
    }

    func encode(to encoder: Encoder) throws {
        // Not needed for tests
    }
}
