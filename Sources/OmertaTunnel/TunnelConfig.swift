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
        }
    }
}
