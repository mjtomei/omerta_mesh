// RelaySession.swift - Bidirectional relay session state

import Foundation
import Logging

/// State of a relay session
public enum RelaySessionState: Sendable, Equatable {
    case pending
    case active
    case closing
    case closed
}

/// A bidirectional relay session between two peers
public actor RelaySession {
    /// Unique session identifier
    public let sessionId: String

    /// Our peer ID
    public let localPeerId: PeerId

    /// Remote peer ID
    public let remotePeerId: PeerId

    /// The relay we're using
    public let relayPeerId: PeerId

    /// Current session state
    public private(set) var state: RelaySessionState = .pending

    /// When the session was created
    public let createdAt: Date

    /// Last activity timestamp
    public private(set) var lastActivity: Date

    /// Bytes sent through this session
    public private(set) var bytesSent: UInt64 = 0

    /// Bytes received through this session
    public private(set) var bytesReceived: UInt64 = 0

    /// Handler for incoming data
    private var dataHandler: ((Data) async -> Void)?

    private let logger: Logger

    /// Session timeout (no activity)
    private let idleTimeout: TimeInterval = 300.0  // 5 minutes

    public init(
        sessionId: String,
        localPeerId: PeerId,
        remotePeerId: PeerId,
        relayPeerId: PeerId
    ) {
        self.sessionId = sessionId
        self.localPeerId = localPeerId
        self.remotePeerId = remotePeerId
        self.relayPeerId = relayPeerId
        self.createdAt = Date()
        self.lastActivity = Date()
        self.logger = Logger(label: "io.omerta.mesh.session.\(sessionId.prefix(8))")
    }

    // MARK: - Lifecycle

    /// Activate the session
    public func activate() {
        state = .active
        lastActivity = Date()
        logger.info("Session activated: \(localPeerId) <-> \(remotePeerId) via \(relayPeerId)")
    }

    /// Close the session
    public func close() {
        state = .closed
        dataHandler = nil
        logger.info("Session closed: \(sessionId)")
    }

    /// Begin closing (graceful shutdown)
    public func beginClosing() {
        state = .closing
        lastActivity = Date()
    }

    // MARK: - Data Transfer

    /// Set handler for incoming data
    public func onData(_ handler: @escaping (Data) async -> Void) {
        self.dataHandler = handler
    }

    /// Handle incoming data from relay
    public func handleIncomingData(_ data: Data) async {
        guard state == .active else {
            logger.warning("Received data on inactive session")
            return
        }

        lastActivity = Date()
        bytesReceived += UInt64(data.count)

        if let handler = dataHandler {
            await handler(data)
        }
    }

    /// Record outgoing data
    public func recordOutgoingData(_ data: Data) {
        lastActivity = Date()
        bytesSent += UInt64(data.count)
    }

    // MARK: - Status

    /// Check if session is idle (no activity for timeout period)
    public var isIdle: Bool {
        Date().timeIntervalSince(lastActivity) > idleTimeout
    }

    /// Check if session is active
    public var isActive: Bool {
        state == .active
    }

    /// Session duration
    public var duration: TimeInterval {
        Date().timeIntervalSince(createdAt)
    }

    /// Get session metrics
    public var metrics: RelaySessionMetrics {
        RelaySessionMetrics(
            sessionId: sessionId,
            localPeerId: localPeerId,
            remotePeerId: remotePeerId,
            relayPeerId: relayPeerId,
            state: state,
            duration: duration,
            bytesSent: bytesSent,
            bytesReceived: bytesReceived,
            lastActivity: lastActivity
        )
    }
}

/// Metrics for a relay session
public struct RelaySessionMetrics: Sendable {
    public let sessionId: String
    public let localPeerId: PeerId
    public let remotePeerId: PeerId
    public let relayPeerId: PeerId
    public let state: RelaySessionState
    public let duration: TimeInterval
    public let bytesSent: UInt64
    public let bytesReceived: UInt64
    public let lastActivity: Date
}

// MARK: - Session Manager

/// Manages multiple relay sessions
public actor RelaySessionManager {
    private var sessions: [String: RelaySession] = [:]
    private let maxSessions: Int
    private let logger: Logger

    public init(maxSessions: Int = 100) {
        self.maxSessions = maxSessions
        self.logger = Logger(label: "io.omerta.mesh.sessions")
    }

    /// Create a new session
    public func createSession(
        sessionId: String,
        localPeerId: PeerId,
        remotePeerId: PeerId,
        relayPeerId: PeerId
    ) throws -> RelaySession {
        guard sessions.count < maxSessions else {
            throw RelayError.atCapacity
        }

        let session = RelaySession(
            sessionId: sessionId,
            localPeerId: localPeerId,
            remotePeerId: remotePeerId,
            relayPeerId: relayPeerId
        )

        sessions[sessionId] = session
        logger.info("Created session \(sessionId)")
        return session
    }

    /// Get an existing session
    public func getSession(_ sessionId: String) -> RelaySession? {
        sessions[sessionId]
    }

    /// Remove a session
    public func removeSession(_ sessionId: String) async {
        if let session = sessions.removeValue(forKey: sessionId) {
            await session.close()
            logger.info("Removed session \(sessionId)")
        }
    }

    /// Get all sessions
    public var allSessions: [RelaySession] {
        Array(sessions.values)
    }

    /// Get sessions for a specific peer
    public func sessions(withPeer peerId: PeerId) -> [RelaySession] {
        sessions.values.filter { session in
            session.localPeerId == peerId || session.remotePeerId == peerId
        }
    }

    /// Get sessions through a specific relay
    public func sessions(viaRelay relayPeerId: PeerId) -> [RelaySession] {
        sessions.values.filter { $0.relayPeerId == relayPeerId }
    }

    /// Clean up idle sessions
    public func cleanupIdleSessions() async {
        var toRemove: [String] = []

        for (sessionId, session) in sessions {
            if await session.isIdle {
                toRemove.append(sessionId)
            }
        }

        for sessionId in toRemove {
            await removeSession(sessionId)
        }

        if !toRemove.isEmpty {
            logger.info("Cleaned up \(toRemove.count) idle sessions")
        }
    }

    /// Number of active sessions
    public var activeCount: Int {
        sessions.count
    }
}
