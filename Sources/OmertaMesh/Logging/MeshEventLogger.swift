// MeshEventLogger.swift - JSON Lines-based event logging for OmertaMesh
//
// Uses JSON Lines format (.jsonl) for simple append-only logging.
// Each line is a complete JSON object that can be processed independently.
// This avoids SQLite dependencies while still providing queryable data.

import Foundation
import Logging

/// Actor responsible for logging mesh events to JSON Lines files
public actor MeshEventLogger {
    // MARK: - Properties

    /// Base directory for log files
    private let logDir: String

    /// File handles for each log type
    private var fileHandles: [String: FileHandle] = [:]

    /// Logger
    private let logger: Logger

    /// In-memory latency samples, keyed by peerId
    /// Flushed to latency_stats every 30 minutes
    private var latencySamples: [String: [LatencySample]] = [:]

    /// In-memory peer tracking (lightweight, deduped)
    private var peersSeen: [String: PeerRecord] = [:]

    /// Task for periodic stats flush
    private var flushTask: Task<Void, Never>?

    /// Interval for flushing latency stats (30 minutes)
    private let flushInterval: TimeInterval = 30 * 60

    /// JSON encoder for events
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = []  // No pretty printing, each event is one line
        return encoder
    }()

    // MARK: - Initialization

    /// Initialize the event logger with logs at the specified directory
    /// - Parameter logDir: Directory for log files (default: ~/.omerta/logs/mesh)
    public init(logDir: String? = nil) throws {
        var log = Logger(label: "io.omerta.mesh.eventlogger")
        log.logLevel = .info
        self.logger = log

        let dir = logDir ?? MeshEventLogger.defaultLogDir()
        self.logDir = dir

        // Ensure directory exists
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        // Load existing peers_seen if available (nonisolated context)
        self.peersSeen = MeshEventLogger.loadPeersSeenFromDisk(logDir: dir)

        logger.info("Mesh event logger initialized", metadata: ["path": "\(dir)"])
    }

    /// Start background tasks (call after init)
    public func start() {
        flushTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30 * 60))
                await self?.flushLatencyStats()
                await self?.savePeersSeen()
            }
        }
    }

    /// Stop background tasks and flush pending data
    public func stop() async {
        flushTask?.cancel()
        flushTask = nil
        await flushLatencyStats()
        savePeersSeen()

        // Close all file handles
        for (_, handle) in fileHandles {
            try? handle.synchronize()
            try? handle.close()
        }
        fileHandles.removeAll()
    }

    // MARK: - Default Path

    private static func defaultLogDir() -> String {
        "\(getRealUserHome())/.omerta/logs/mesh"
    }

    // MARK: - File Management

    /// Get or create a file handle for the specified log type
    private func getFileHandle(for logType: String) -> FileHandle? {
        if let handle = fileHandles[logType] {
            return handle
        }

        let path = "\(logDir)/\(logType).jsonl"

        // Create file if it doesn't exist
        if !FileManager.default.fileExists(atPath: path) {
            _ = FileManager.default.createFile(atPath: path, contents: nil)
        }

        guard let handle = FileHandle(forWritingAtPath: path) else {
            logger.warning("Failed to open log file", metadata: ["path": "\(path)"])
            return nil
        }

        // Seek to end for appending
        do {
            try handle.seekToEnd()
        } catch {
            logger.warning("Failed to seek to end of log file", metadata: ["error": "\(error)"])
        }

        fileHandles[logType] = handle
        return handle
    }

    /// Append an event to a log file
    private func appendEvent<T: Encodable>(_ event: T, to logType: String) {
        guard let handle = getFileHandle(for: logType) else { return }

        do {
            var data = try encoder.encode(event)
            data.append(contentsOf: "\n".utf8)
            try handle.write(contentsOf: data)
        } catch {
            logger.warning("Failed to write event", metadata: [
                "logType": "\(logType)",
                "error": "\(error)"
            ])
        }
    }

    // MARK: - Peers Seen (In-Memory + Periodic Save)

    /// Load peers from disk (nonisolated for use in init)
    private static func loadPeersSeenFromDisk(logDir: String) -> [String: PeerRecord] {
        let path = "\(logDir)/peers_seen.json"
        guard FileManager.default.fileExists(atPath: path),
              let data = FileManager.default.contents(atPath: path) else {
            return [:]
        }

        return (try? JSONCoding.iso8601Decoder.decode([String: PeerRecord].self, from: data)) ?? [:]
    }

    private func savePeersSeen() {
        let path = "\(logDir)/peers_seen.json"

        do {
            let data = try JSONCoding.iso8601PrettyEncoder.encode(peersSeen)
            try data.write(to: URL(fileURLWithPath: path))
        } catch {
            logger.warning("Failed to save peers_seen", metadata: ["error": "\(error)"])
        }
    }

    // MARK: - Peer Events

    /// Record that we've seen a peer
    public func recordPeerSeen(
        peerId: String,
        endpoint: String?,
        natType: String?
    ) async {
        let now = Date()

        if var existing = peersSeen[peerId] {
            existing = PeerRecord(
                peerId: peerId,
                firstSeen: existing.firstSeen,
                lastSeen: now,
                lastEndpoint: endpoint ?? existing.lastEndpoint,
                lastNATType: natType ?? existing.lastNATType
            )
            peersSeen[peerId] = existing
        } else {
            peersSeen[peerId] = PeerRecord(
                peerId: peerId,
                firstSeen: now,
                lastSeen: now,
                lastEndpoint: endpoint,
                lastNATType: natType
            )
        }
    }

    /// Record a peer discovery event
    public func recordPeerDiscovery(
        peerId: String,
        machineId: String?,
        method: DiscoveryMethod,
        sourcePeerId: String?,
        endpoint: String?
    ) async {
        let event = PeerDiscoveryEvent(
            timestamp: Date(),
            peerId: peerId,
            machineId: machineId,
            discoveryMethod: method.rawValue,
            sourcePeerId: sourcePeerId,
            endpoint: endpoint
        )
        appendEvent(event, to: "peer_discovery")
    }

    // MARK: - Connection Events

    /// Record a connection event
    public func recordConnectionEvent(
        peerId: String,
        machineId: String?,
        eventType: ConnectionEventType,
        connectionType: ConnectionType?,
        endpoint: String?,
        error: String? = nil,
        durationMs: Int? = nil
    ) async {
        let event = ConnectionEvent(
            timestamp: Date(),
            peerId: peerId,
            machineId: machineId,
            eventType: eventType.rawValue,
            connectionType: connectionType?.rawValue,
            endpoint: endpoint,
            error: error,
            durationMs: durationMs
        )
        appendEvent(event, to: "connections")
    }

    // MARK: - Latency Tracking

    /// Record a latency sample (kept in memory, flushed every 30 min)
    public func recordLatencySample(peerId: String, latencyMs: Double) {
        let sample = LatencySample(timestamp: Date(), latencyMs: latencyMs)

        if latencySamples[peerId] == nil {
            latencySamples[peerId] = []
        }
        latencySamples[peerId]!.append(sample)
    }

    /// Record a failed ping (loss)
    public func recordLatencyLoss(peerId: String) {
        let sample = LatencySample(timestamp: Date(), latencyMs: -1) // -1 indicates loss

        if latencySamples[peerId] == nil {
            latencySamples[peerId] = []
        }
        latencySamples[peerId]!.append(sample)
    }

    /// Flush latency statistics to log file
    private func flushLatencyStats() async {
        let samplesToFlush = latencySamples
        latencySamples = [:]

        guard !samplesToFlush.isEmpty else { return }

        let now = Date()

        for (peerId, samples) in samplesToFlush {
            let validSamples = samples.filter { $0.latencyMs >= 0 }
            let lossCount = samples.count - validSamples.count

            guard !validSamples.isEmpty else {
                // All losses, still record
                let statsEvent = LatencyStatsEvent(
                    timestamp: now,
                    peerId: peerId,
                    sampleCount: 0,
                    lossCount: lossCount,
                    meanMs: 0, medianMs: 0, stddevMs: 0,
                    minMs: 0, maxMs: 0, p75Ms: 0, p95Ms: 0, p99Ms: 0
                )
                appendEvent(statsEvent, to: "latency_stats")
                continue
            }

            let latencies = validSamples.map { $0.latencyMs }.sorted()
            let stats = LatencyStatistics.calculate(from: latencies)

            // Record aggregated stats
            let statsEvent = LatencyStatsEvent(
                timestamp: now,
                peerId: peerId,
                sampleCount: validSamples.count,
                lossCount: lossCount,
                meanMs: stats.mean,
                medianMs: stats.median,
                stddevMs: stats.stddev,
                minMs: stats.min,
                maxMs: stats.max,
                p75Ms: stats.p75,
                p95Ms: stats.p95,
                p99Ms: stats.p99
            )
            appendEvent(statsEvent, to: "latency_stats")

            // Log outliers
            let stddevThreshold = stats.mean + 3 * stats.stddev
            let p95Threshold = 2 * stats.p95

            for sample in validSamples {
                if sample.latencyMs > stddevThreshold && stats.stddev > 0 {
                    let outlier = LatencyOutlierEvent(
                        timestamp: sample.timestamp,
                        peerId: peerId,
                        latencyMs: sample.latencyMs,
                        reason: "high_stddev",
                        thresholdMs: stddevThreshold
                    )
                    appendEvent(outlier, to: "latency_outliers")
                } else if sample.latencyMs > p95Threshold {
                    let outlier = LatencyOutlierEvent(
                        timestamp: sample.timestamp,
                        peerId: peerId,
                        latencyMs: sample.latencyMs,
                        reason: "high_p95",
                        thresholdMs: p95Threshold
                    )
                    appendEvent(outlier, to: "latency_outliers")
                }
            }
        }

        logger.debug("Flushed latency stats", metadata: ["peers": "\(samplesToFlush.count)"])
    }

    // MARK: - NAT Events

    /// Record a NAT type change
    public func recordNATTypeChange(oldType: String?, newType: String) async {
        let event = NATEvent(
            timestamp: Date(),
            eventType: "type_changed",
            oldValue: oldType,
            newValue: newType
        )
        appendEvent(event, to: "nat_events")
    }

    /// Record an endpoint change
    public func recordEndpointChange(oldEndpoint: String?, newEndpoint: String) async {
        let event = NATEvent(
            timestamp: Date(),
            eventType: "endpoint_changed",
            oldValue: oldEndpoint,
            newValue: newEndpoint
        )
        appendEvent(event, to: "nat_events")
    }

    // MARK: - Hole Punch Events

    /// Record a hole punch event
    public func recordHolePunchEvent(
        peerId: String,
        eventType: HolePunchEventType,
        ourNATType: String?,
        peerNATType: String?,
        strategy: String?,
        durationMs: Int? = nil,
        error: String? = nil
    ) async {
        let event = HolePunchEvent(
            timestamp: Date(),
            peerId: peerId,
            eventType: eventType.rawValue,
            ourNatType: ourNATType,
            peerNatType: peerNATType,
            strategy: strategy,
            durationMs: durationMs,
            error: error
        )
        appendEvent(event, to: "hole_punch")
    }

    // MARK: - Relay Events

    /// Record a relay event
    public func recordRelayEvent(
        peerId: String,
        relayPeerId: String,
        eventType: RelayEventType,
        reason: String? = nil,
        durationMs: Int? = nil,
        bytesRelayed: Int? = nil
    ) async {
        let event = RelayEvent(
            timestamp: Date(),
            peerId: peerId,
            relayPeerId: relayPeerId,
            eventType: eventType.rawValue,
            reason: reason,
            durationMs: durationMs,
            bytesRelayed: bytesRelayed
        )
        appendEvent(event, to: "relay")
    }

    // MARK: - Message Events

    /// Record a message event
    public func recordMessageEvent(
        peerId: String,
        direction: MessageDirection,
        messageType: String,
        sizeBytes: Int,
        success: Bool,
        error: String? = nil,
        retryCount: Int? = nil
    ) async {
        let event = MessageEvent(
            timestamp: Date(),
            peerId: peerId,
            direction: direction.rawValue,
            messageType: messageType,
            sizeBytes: sizeBytes,
            success: success,
            error: error,
            retryCount: retryCount
        )
        appendEvent(event, to: "messages")
    }

    // MARK: - Error Events

    /// Record an error event
    public func recordError(
        component: String,
        operation: String,
        errorType: String,
        errorMessage: String,
        peerId: String? = nil,
        context: [String: String]? = nil
    ) async {
        let event = ErrorEvent(
            timestamp: Date(),
            component: component,
            operation: operation,
            errorType: errorType,
            errorMessage: errorMessage,
            peerId: peerId,
            context: context
        )
        appendEvent(event, to: "errors")
    }

    // MARK: - Hourly Stats

    /// Record hourly aggregate statistics
    public func recordHourlyStats(
        activePeers: Int,
        messagesSent: Int,
        messagesReceived: Int,
        bytesSent: Int,
        bytesReceived: Int,
        directConnections: Int,
        relayConnections: Int,
        holePunchAttempts: Int,
        holePunchSuccesses: Int,
        errors: Int
    ) async {
        // Round to hour start
        let calendar = Calendar.current
        let hourStart = calendar.date(from: calendar.dateComponents([.year, .month, .day, .hour], from: Date()))!

        let event = HourlyStatsEvent(
            timestamp: hourStart,
            activePeers: activePeers,
            messagesSent: messagesSent,
            messagesReceived: messagesReceived,
            bytesSent: bytesSent,
            bytesReceived: bytesReceived,
            directConnections: directConnections,
            relayConnections: relayConnections,
            holePunchAttempts: holePunchAttempts,
            holePunchSuccesses: holePunchSuccesses,
            errors: errors
        )
        appendEvent(event, to: "hourly_stats")
    }

    // MARK: - Queries

    /// Get all peers seen
    public func getAllPeersSeen() async -> [PeerRecord] {
        Array(peersSeen.values).sorted { $0.lastSeen > $1.lastSeen }
    }

    /// Get recent errors from log file
    public func getRecentErrors(limit: Int = 100) async throws -> [ErrorRecord] {
        let path = "\(logDir)/errors.jsonl"
        guard FileManager.default.fileExists(atPath: path),
              let data = FileManager.default.contents(atPath: path) else {
            return []
        }

        let lines = String(data: data, encoding: .utf8)?.split(separator: "\n") ?? []
        var records: [ErrorRecord] = []

        for line in lines.suffix(limit) {
            if let lineData = String(line).data(using: .utf8),
               let event = try? JSONCoding.iso8601Decoder.decode(ErrorEvent.self, from: lineData) {
                records.append(ErrorRecord(
                    timestamp: event.timestamp,
                    component: event.component,
                    operation: event.operation,
                    errorType: event.errorType,
                    errorMessage: event.errorMessage,
                    peerId: event.peerId,
                    context: event.context.flatMap { try? String(data: JSONSerialization.data(withJSONObject: $0), encoding: .utf8) }
                ))
            }
        }

        return records.reversed()  // Most recent first
    }

    /// Get latency stats for a peer from log file
    public func getLatencyStats(peerId: String, hours: Int = 24) async throws -> [LatencyStatsRecord] {
        let path = "\(logDir)/latency_stats.jsonl"
        guard FileManager.default.fileExists(atPath: path),
              let data = FileManager.default.contents(atPath: path) else {
            return []
        }

        let since = Date().addingTimeInterval(-Double(hours) * 3600)
        let lines = String(data: data, encoding: .utf8)?.split(separator: "\n") ?? []
        var records: [LatencyStatsRecord] = []

        for line in lines {
            if let lineData = String(line).data(using: .utf8),
               let event = try? JSONCoding.iso8601Decoder.decode(LatencyStatsEvent.self, from: lineData),
               event.peerId == peerId && event.timestamp > since {
                records.append(LatencyStatsRecord(
                    timestamp: event.timestamp,
                    peerId: event.peerId,
                    sampleCount: event.sampleCount,
                    lossCount: event.lossCount,
                    mean: event.meanMs,
                    median: event.medianMs,
                    stddev: event.stddevMs,
                    min: event.minMs,
                    max: event.maxMs,
                    p75: event.p75Ms,
                    p95: event.p95Ms,
                    p99: event.p99Ms
                ))
            }
        }

        return records.sorted { $0.timestamp > $1.timestamp }
    }
}

// MARK: - Internal Event Types

private struct PeerDiscoveryEvent: Codable {
    let timestamp: Date
    let peerId: String
    let machineId: String?
    let discoveryMethod: String
    let sourcePeerId: String?
    let endpoint: String?
}

private struct ConnectionEvent: Codable {
    let timestamp: Date
    let peerId: String
    let machineId: String?
    let eventType: String
    let connectionType: String?
    let endpoint: String?
    let error: String?
    let durationMs: Int?
}

private struct LatencyStatsEvent: Codable {
    let timestamp: Date
    let peerId: String
    let sampleCount: Int
    let lossCount: Int
    let meanMs: Double
    let medianMs: Double
    let stddevMs: Double
    let minMs: Double
    let maxMs: Double
    let p75Ms: Double
    let p95Ms: Double
    let p99Ms: Double
}

private struct LatencyOutlierEvent: Codable {
    let timestamp: Date
    let peerId: String
    let latencyMs: Double
    let reason: String
    let thresholdMs: Double
}

private struct NATEvent: Codable {
    let timestamp: Date
    let eventType: String
    let oldValue: String?
    let newValue: String
}

private struct HolePunchEvent: Codable {
    let timestamp: Date
    let peerId: String
    let eventType: String
    let ourNatType: String?
    let peerNatType: String?
    let strategy: String?
    let durationMs: Int?
    let error: String?
}

private struct RelayEvent: Codable {
    let timestamp: Date
    let peerId: String
    let relayPeerId: String
    let eventType: String
    let reason: String?
    let durationMs: Int?
    let bytesRelayed: Int?
}

private struct MessageEvent: Codable {
    let timestamp: Date
    let peerId: String
    let direction: String
    let messageType: String
    let sizeBytes: Int
    let success: Bool
    let error: String?
    let retryCount: Int?
}

private struct ErrorEvent: Codable {
    let timestamp: Date
    let component: String
    let operation: String
    let errorType: String
    let errorMessage: String
    let peerId: String?
    let context: [String: String]?
}

private struct HourlyStatsEvent: Codable {
    let timestamp: Date
    let activePeers: Int
    let messagesSent: Int
    let messagesReceived: Int
    let bytesSent: Int
    let bytesReceived: Int
    let directConnections: Int
    let relayConnections: Int
    let holePunchAttempts: Int
    let holePunchSuccesses: Int
    let errors: Int
}

// MARK: - Supporting Types

private struct LatencySample {
    let timestamp: Date
    let latencyMs: Double  // -1 indicates loss
}

private struct LatencyStatistics {
    let mean: Double
    let median: Double
    let stddev: Double
    let min: Double
    let max: Double
    let p75: Double
    let p95: Double
    let p99: Double

    static func calculate(from sortedLatencies: [Double]) -> LatencyStatistics {
        guard !sortedLatencies.isEmpty else {
            return LatencyStatistics(mean: 0, median: 0, stddev: 0, min: 0, max: 0, p75: 0, p95: 0, p99: 0)
        }

        let count = sortedLatencies.count
        let sum = sortedLatencies.reduce(0, +)
        let mean = sum / Double(count)

        let variance = sortedLatencies.reduce(0) { $0 + pow($1 - mean, 2) } / Double(count)
        let stddev = sqrt(variance)

        func percentile(_ p: Double) -> Double {
            let index = (p / 100.0) * Double(count - 1)
            let lower = Int(floor(index))
            let upper = Swift.min(lower + 1, count - 1)
            let fraction = index - Double(lower)
            return sortedLatencies[lower] * (1 - fraction) + sortedLatencies[upper] * fraction
        }

        return LatencyStatistics(
            mean: mean,
            median: percentile(50),
            stddev: stddev,
            min: sortedLatencies.first!,
            max: sortedLatencies.last!,
            p75: percentile(75),
            p95: percentile(95),
            p99: percentile(99)
        )
    }
}

// MARK: - Public Record Types

public struct PeerRecord: Codable, Sendable {
    public let peerId: String
    public let firstSeen: Date
    public let lastSeen: Date
    public let lastEndpoint: String?
    public let lastNATType: String?
}

public struct ErrorRecord: Sendable {
    public let timestamp: Date
    public let component: String
    public let operation: String
    public let errorType: String
    public let errorMessage: String
    public let peerId: String?
    public let context: String?
}

public struct LatencyStatsRecord: Sendable {
    public let timestamp: Date
    public let peerId: String
    public let sampleCount: Int
    public let lossCount: Int
    public let mean: Double
    public let median: Double
    public let stddev: Double
    public let min: Double
    public let max: Double
    public let p75: Double
    public let p95: Double
    public let p99: Double
}
