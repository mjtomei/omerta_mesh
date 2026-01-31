// BatchConfig.swift - Configuration for send batching
//
// Batching amortizes per-packet overhead (actor hops, crypto) by accumulating
// multiple small sends into a single wire-level send.

import Foundation

/// Configuration for send batching
public struct BatchConfig: Sendable, Equatable, Codable {
    /// Maximum time to hold buffered data before auto-flushing
    public var maxFlushDelay: Duration

    /// Maximum buffer size in bytes before auto-flushing (0 = no limit)
    public var maxBufferSize: Int

    public static let `default` = BatchConfig(maxFlushDelay: .milliseconds(1), maxBufferSize: 0)

    public init(maxFlushDelay: Duration = .milliseconds(1), maxBufferSize: Int = 0) {
        self.maxFlushDelay = maxFlushDelay
        self.maxBufferSize = maxBufferSize
    }

    // MARK: - Codable (Duration is not Codable by default)

    enum CodingKeys: String, CodingKey {
        case maxFlushDelayMs
        case maxBufferSize
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let ms = try container.decode(Int.self, forKey: .maxFlushDelayMs)
        self.maxFlushDelay = .milliseconds(ms)
        self.maxBufferSize = try container.decode(Int.self, forKey: .maxBufferSize)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let ms = Int(maxFlushDelay.components.seconds * 1000) + Int(maxFlushDelay.components.attoseconds / 1_000_000_000_000_000)
        try container.encode(ms, forKey: .maxFlushDelayMs)
        try container.encode(maxBufferSize, forKey: .maxBufferSize)
    }

    // MARK: - Resolution

    /// Resolve batch config from a priority chain.
    /// Later non-nil values override earlier ones.
    public static func resolve(_ configs: BatchConfig?...) -> BatchConfig {
        var result = BatchConfig.default
        for config in configs {
            if let config {
                result = config
            }
        }
        return result
    }
}

/// Traffic statistics provided to batch monitors
public struct TrafficStats: Sendable {
    public var bytesPerSecond: UInt64
    public var packetsPerSecond: UInt64
    public var activeEndpoints: Int
    public var averageLatencyMicroseconds: Double
    /// Delivered (acknowledged by remote) bytes per second, if available.
    /// When non-nil, this reflects actual throughput as reported by the receiver.
    public var deliveredBytesPerSecond: UInt64?

    public init(
        bytesPerSecond: UInt64 = 0,
        packetsPerSecond: UInt64 = 0,
        activeEndpoints: Int = 0,
        averageLatencyMicroseconds: Double = 0,
        deliveredBytesPerSecond: UInt64? = nil
    ) {
        self.bytesPerSecond = bytesPerSecond
        self.packetsPerSecond = packetsPerSecond
        self.activeEndpoints = activeEndpoints
        self.averageLatencyMicroseconds = averageLatencyMicroseconds
        self.deliveredBytesPerSecond = deliveredBytesPerSecond
    }
}

/// Protocol for dynamic batch parameter adjustment.
///
/// Monitors are consulted when making flush decisions. They can return
/// an updated config to override the static config chain, or nil to
/// keep the current config.
public protocol BatchMonitor: Sendable {
    /// Called periodically or on endpoint changes. Returns updated config, or nil to keep current.
    func recommendedConfig(for endpoint: String, currentTraffic: TrafficStats) async -> BatchConfig?
}
