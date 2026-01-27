// RelayConnection.swift - Persistent connection to a relay peer

import Foundation
import Logging

/// State of a relay connection
public enum RelayConnectionState: Sendable, Equatable {
    case disconnected
    case connecting
    case connected
    case failed(String)
}

/// A persistent connection to a relay node
public actor RelayConnection {
    /// The relay's peer ID
    public let relayPeerId: PeerId

    /// The relay's endpoint
    public let relayEndpoint: String

    /// Current connection state
    public private(set) var state: RelayConnectionState = .disconnected

    /// Last successful heartbeat
    public private(set) var lastHeartbeat: Date?

    /// Round-trip time to relay
    public private(set) var rtt: TimeInterval = 0

    /// Number of active sessions through this relay
    public private(set) var activeSessions: Int = 0

    /// Maximum sessions this relay supports
    public let maxSessions: Int

    private let node: MeshNode
    private let logger: Logger
    private var heartbeatTask: Task<Void, Never>?

    /// Heartbeat interval
    private let heartbeatInterval: TimeInterval = 30.0

    /// Connection timeout
    private let connectionTimeout: TimeInterval = 10.0

    public init(
        relayPeerId: PeerId,
        relayEndpoint: String,
        node: MeshNode,
        maxSessions: Int = 100
    ) {
        self.relayPeerId = relayPeerId
        self.relayEndpoint = relayEndpoint
        self.node = node
        self.maxSessions = maxSessions
        self.logger = Logger(label: "io.omerta.mesh.relay.\(relayPeerId.prefix(8))")
    }

    // MARK: - Lifecycle

    /// Connect to the relay
    public func connect() async throws {
        guard state == .disconnected || isFailedState else {
            return
        }

        state = .connecting
        logger.info("Connecting to relay \(relayEndpoint)")

        do {
            // Send ping to verify relay is alive
            let startTime = Date()
            let myNATType = await node.getPredictedNATType().type
            let response = try await node.sendAndReceive(
                .ping(recentPeers: [], myNATType: myNATType),
                to: relayEndpoint,
                timeout: connectionTimeout
            )

            if case .pong(_, _, _) = response {
                rtt = Date().timeIntervalSince(startTime)
                lastHeartbeat = Date()
                state = .connected
                logger.info("Connected to relay, RTT: \(String(format: "%.3f", rtt))s")

                // Start heartbeat
                startHeartbeat()
            } else {
                throw RelayError.unexpectedResponse
            }
        } catch {
            state = .failed(error.localizedDescription)
            logger.error("Failed to connect to relay: \(error)")
            throw error
        }
    }

    /// Disconnect from the relay
    public func disconnect() {
        heartbeatTask?.cancel()
        heartbeatTask = nil
        state = .disconnected
        activeSessions = 0
        logger.info("Disconnected from relay")
    }

    /// Check if the connection is healthy
    public var isHealthy: Bool {
        guard state == .connected,
              let lastHB = lastHeartbeat else {
            return false
        }
        // Consider unhealthy if no heartbeat in 2x interval
        return Date().timeIntervalSince(lastHB) < heartbeatInterval * 2
    }

    /// Check if connection is in a failed state
    private var isFailedState: Bool {
        if case .failed = state { return true }
        return false
    }

    // MARK: - Session Management

    /// Request a new relay session to a target peer
    public func requestSession(targetPeerId: PeerId) async throws -> String {
        guard state == .connected else {
            throw RelayError.notConnected
        }

        guard activeSessions < maxSessions else {
            throw RelayError.atCapacity
        }

        let sessionId = UUID().uuidString

        let response = try await node.sendAndReceive(
            .relayRequest(targetPeerId: targetPeerId, sessionId: sessionId),
            to: relayEndpoint,
            timeout: connectionTimeout
        )

        switch response {
        case .relayAccept(let acceptedSessionId):
            guard acceptedSessionId == sessionId else {
                throw RelayError.sessionIdMismatch
            }
            activeSessions += 1
            logger.info("Relay session established: \(sessionId)")
            return sessionId

        case .relayDeny(_, let reason):
            throw RelayError.denied(reason)

        default:
            throw RelayError.unexpectedResponse
        }
    }

    /// End a relay session
    public func endSession(_ sessionId: String) async {
        guard activeSessions > 0 else { return }

        try? await node.send(.relayEnd(sessionId: sessionId), to: relayEndpoint)
        activeSessions -= 1
        logger.debug("Relay session ended: \(sessionId)")
    }

    /// Send data through a relay session
    public func sendData(_ data: Data, sessionId: String) async throws {
        guard state == .connected else {
            throw RelayError.notConnected
        }

        try await node.send(.relayData(sessionId: sessionId, data: data), to: relayEndpoint)
    }

    // MARK: - Heartbeat

    private func startHeartbeat() {
        heartbeatTask?.cancel()
        heartbeatTask = Task {
            await runHeartbeatLoop()
        }
    }

    private func runHeartbeatLoop() async {
        while !Task.isCancelled && state == .connected {
            do {
                try await Task.sleep(nanoseconds: UInt64(heartbeatInterval * 1_000_000_000))

                // Send heartbeat ping
                let startTime = Date()
                let myNATType = await node.getPredictedNATType().type
                let response = try await node.sendAndReceive(
                    .ping(recentPeers: [], myNATType: myNATType),
                    to: relayEndpoint,
                    timeout: connectionTimeout
                )

                if case .pong(_, _, _) = response {
                    rtt = Date().timeIntervalSince(startTime)
                    lastHeartbeat = Date()
                    logger.debug("Heartbeat OK, RTT: \(String(format: "%.3f", rtt))s")
                }
            } catch {
                logger.warning("Heartbeat failed: \(error)")
                // Try to reconnect
                state = .disconnected
                try? await connect()
            }
        }
    }

    // MARK: - Metrics

    /// Get connection metrics
    public var metrics: RelayConnectionMetrics {
        RelayConnectionMetrics(
            relayPeerId: relayPeerId,
            endpoint: relayEndpoint,
            state: state,
            rtt: rtt,
            activeSessions: activeSessions,
            lastHeartbeat: lastHeartbeat
        )
    }
}

/// Metrics for a relay connection
public struct RelayConnectionMetrics: Sendable {
    public let relayPeerId: PeerId
    public let endpoint: String
    public let state: RelayConnectionState
    public let rtt: TimeInterval
    public let activeSessions: Int
    public let lastHeartbeat: Date?
}

/// Relay connection errors
public enum RelayError: Error, CustomStringConvertible {
    case notConnected
    case unexpectedResponse
    case atCapacity
    case denied(String)
    case sessionIdMismatch
    case sessionNotFound
    case timeout

    public var description: String {
        switch self {
        case .notConnected:
            return "Not connected to relay"
        case .unexpectedResponse:
            return "Unexpected response from relay"
        case .atCapacity:
            return "Relay at capacity"
        case .denied(let reason):
            return "Relay denied request: \(reason)"
        case .sessionIdMismatch:
            return "Session ID mismatch"
        case .sessionNotFound:
            return "Session not found"
        case .timeout:
            return "Relay request timed out"
        }
    }
}
