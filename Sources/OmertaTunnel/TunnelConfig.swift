// TunnelConfig.swift - Configuration and types for tunnel sessions

import Foundation
import OmertaMesh

/// Uniquely identifies a tunnel session by (machineId, channel)
public struct TunnelSessionKey: Hashable, Sendable {
    public let remoteMachineId: MachineId
    public let channel: String

    public init(remoteMachineId: MachineId, channel: String) {
        self.remoteMachineId = remoteMachineId
        self.channel = channel
    }
}

/// Current state of a tunnel session
public enum TunnelState: Sendable, Equatable {
    case connecting
    case active
    case degraded
    case disconnected
    case failed(String)
}

/// Errors from tunnel operations
public enum TunnelError: Error, LocalizedError, Sendable, Equatable {
    case notConnected
    case alreadyConnected
    case machineNotFound(String)
    case timeout
    case sessionRejected

    case sessionLimitReached

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "Session not connected"
        case .alreadyConnected:
            return "Session already connected"
        case .machineNotFound(let machineId):
            return "Machine not found: \(machineId)"
        case .timeout:
            return "Operation timed out"
        case .sessionRejected:
            return "Session rejected by remote machine"
        case .sessionLimitReached:
            return "Session limit reached"
        }
    }
}

/// Configuration for TunnelManager session pool
public struct TunnelManagerConfig: Sendable {
    /// Maximum number of sessions per remote machine
    public var maxSessionsPerMachine: Int = 10
    /// Maximum total sessions across all machines
    public var maxTotalSessions: Int = 1000

    // Health monitoring
    public var healthProbeMinInterval: Duration = .milliseconds(500)
    public var healthProbeMaxInterval: Duration = .seconds(15)
    public var healthDegradedThreshold: Int = 3
    public var healthFailureThreshold: Int = 6
    /// Number of initial probe intervals to skip failure counting (grace period for remote to start probing)
    public var healthGraceIntervals: Int = 3

    /// Batch configuration for tunnel traffic (overrides channel-level config)
    public var batchConfig: BatchConfig?

    public static let `default` = TunnelManagerConfig()

    public init(
        maxSessionsPerMachine: Int = 10,
        maxTotalSessions: Int = 1000,
        healthProbeMinInterval: Duration = .milliseconds(500),
        healthProbeMaxInterval: Duration = .seconds(15),
        healthDegradedThreshold: Int = 3,
        healthFailureThreshold: Int = 6,
        healthGraceIntervals: Int = 3,
        batchConfig: BatchConfig? = nil
    ) {
        self.maxSessionsPerMachine = maxSessionsPerMachine
        self.maxTotalSessions = maxTotalSessions
        self.healthProbeMinInterval = healthProbeMinInterval
        self.healthProbeMaxInterval = healthProbeMaxInterval
        self.healthDegradedThreshold = healthDegradedThreshold
        self.healthFailureThreshold = healthFailureThreshold
        self.healthGraceIntervals = healthGraceIntervals
        self.batchConfig = batchConfig
    }
}
