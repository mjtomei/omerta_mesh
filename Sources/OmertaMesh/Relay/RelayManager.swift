// RelayManager.swift - Manages relay connections and sessions

import Foundation
import Logging

/// Configuration for relay management
public struct RelayManagerConfig: Sendable {
    /// Minimum number of relay connections to maintain
    public let minRelays: Int

    /// Maximum number of relay connections
    public let maxRelays: Int

    /// Interval for health checks
    public let healthCheckInterval: TimeInterval

    /// Maximum sessions across all relays
    public let maxTotalSessions: Int

    /// Selection criteria for relays
    public let selectionCriteria: RelaySelectionCriteria

    public init(
        minRelays: Int = 3,
        maxRelays: Int = 5,
        healthCheckInterval: TimeInterval = 30.0,
        maxTotalSessions: Int = 50,
        selectionCriteria: RelaySelectionCriteria = .default
    ) {
        self.minRelays = minRelays
        self.maxRelays = maxRelays
        self.healthCheckInterval = healthCheckInterval
        self.maxTotalSessions = maxTotalSessions
        self.selectionCriteria = selectionCriteria
    }
}

/// Manages relay connections and session forwarding
public actor RelayManager {
    private let node: MeshNode
    private let selector: RelaySelector
    private let sessionManager: RelaySessionManager
    private let config: RelayManagerConfig
    private let logger: Logger

    /// Event logger for persistent logging (optional)
    private var eventLogger: MeshEventLogger?

    /// Active relay connections
    private var connections: [PeerId: RelayConnection] = [:]

    /// Health check task
    private var healthCheckTask: Task<Void, Never>?

    /// Whether we need relays (NAT type doesn't support hole punching)
    public private(set) var needsRelay: Bool = false

    /// Our announced reachability through relays
    public private(set) var relayPaths: [ReachabilityPath] = []

    public init(
        node: MeshNode,
        peerCache: PeerCache,
        config: RelayManagerConfig = RelayManagerConfig()
    ) {
        self.node = node
        self.selector = RelaySelector(peerCache: peerCache, node: node)
        self.sessionManager = RelaySessionManager(maxSessions: config.maxTotalSessions)
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.relay.manager")
    }

    // MARK: - Lifecycle

    /// Start the relay manager
    public func start(needsRelay: Bool) async throws {
        self.needsRelay = needsRelay

        if needsRelay {
            logger.info("Starting relay manager (NAT requires relays)")
            try await selectAndConnectRelays()
            startHealthCheck()
        } else {
            logger.info("Relay manager started (no relays needed)")
        }
    }

    /// Stop the relay manager
    public func stop() async {
        healthCheckTask?.cancel()
        healthCheckTask = nil

        for (_, connection) in connections {
            await connection.disconnect()
        }
        connections.removeAll()

        logger.info("Relay manager stopped")
    }

    /// Set the event logger for persistent logging
    public func setEventLogger(_ logger: MeshEventLogger?) {
        self.eventLogger = logger
    }

    // MARK: - Relay Connection Management

    /// Select and connect to relays
    private func selectAndConnectRelays() async throws {
        let criteria = RelaySelectionCriteria(
            maxRTT: config.selectionCriteria.maxRTT,
            minCapacity: config.selectionCriteria.minCapacity,
            preferDirect: config.selectionCriteria.preferDirect,
            count: config.minRelays
        )

        let candidates = try await selector.selectRelays(criteria: criteria)

        for candidate in candidates {
            if connections.count >= config.maxRelays {
                break
            }

            do {
                try await connectToRelay(candidate)
            } catch {
                logger.warning("Failed to connect to relay \(candidate.peerId): \(error)")
            }
        }

        // Update reachability paths
        updateRelayPaths()

        logger.info("Connected to \(connections.count) relays")
    }

    /// Connect to a specific relay
    private func connectToRelay(_ candidate: RelayCandidate) async throws {
        guard connections[candidate.peerId] == nil else {
            return  // Already connected
        }

        let connection = RelayConnection(
            relayPeerId: candidate.peerId,
            relayEndpoint: candidate.endpoint,
            node: node
        )

        try await connection.connect()
        connections[candidate.peerId] = connection
    }

    /// Disconnect from a relay
    public func disconnectRelay(_ peerId: PeerId) async {
        if let connection = connections.removeValue(forKey: peerId) {
            await connection.disconnect()

            // End any sessions through this relay
            let sessions = await sessionManager.sessions(viaRelay: peerId)
            for session in sessions {
                await sessionManager.removeSession(session.sessionId)
            }
        }

        updateRelayPaths()
    }

    /// Update our announced relay paths
    private func updateRelayPaths() {
        relayPaths = connections.values.compactMap { connection in
            .relay(relayPeerId: connection.relayPeerId, relayEndpoint: connection.relayEndpoint)
        }
    }

    // MARK: - Session Management

    /// Create a relay session to a target peer
    public func createSession(to targetPeerId: PeerId) async throws -> RelaySession {
        // Select best relay for this target
        let criteria = RelaySelectionCriteria(count: 1)
        let candidates = try await selector.selectRelays(forTarget: targetPeerId, criteria: criteria)

        guard let candidate = candidates.first,
              let connection = connections[candidate.peerId] else {
            // Log relay failure
            await eventLogger?.recordRelayEvent(
                peerId: targetPeerId,
                relayPeerId: "none",
                eventType: .failed,
                reason: "No relay connected"
            )
            throw RelayError.notConnected
        }

        // Request session through relay
        let sessionId = try await connection.requestSession(targetPeerId: targetPeerId)

        // Create local session tracking
        let selfPeerId = await node.peerId
        let session = try await sessionManager.createSession(
            sessionId: sessionId,
            localPeerId: selfPeerId,
            remotePeerId: targetPeerId,
            relayPeerId: candidate.peerId
        )

        await session.activate()

        // Log relay session started
        await eventLogger?.recordRelayEvent(
            peerId: targetPeerId,
            relayPeerId: candidate.peerId,
            eventType: .started,
            reason: "Session created"
        )

        return session
    }

    /// Handle incoming relay session request
    public func handleSessionRequest(
        sessionId: String,
        fromPeerId: PeerId,
        viaRelay relayPeerId: PeerId
    ) async throws -> RelaySession {
        let selfPeerId = await node.peerId
        let session = try await sessionManager.createSession(
            sessionId: sessionId,
            localPeerId: selfPeerId,
            remotePeerId: fromPeerId,
            relayPeerId: relayPeerId
        )

        await session.activate()
        return session
    }

    /// End a relay session
    public func endSession(_ sessionId: String) async {
        if let session = await sessionManager.getSession(sessionId) {
            let relayPeerId = session.relayPeerId
            let remotePeerId = session.remotePeerId
            let metrics = await session.metrics

            if let connection = connections[relayPeerId] {
                await connection.endSession(sessionId)
            }
            await sessionManager.removeSession(sessionId)

            // Log relay session closed
            await eventLogger?.recordRelayEvent(
                peerId: remotePeerId,
                relayPeerId: relayPeerId,
                eventType: .closed,
                reason: "Session ended normally",
                durationMs: Int(metrics.duration * 1000),
                bytesRelayed: Int(metrics.bytesSent + metrics.bytesReceived)
            )
        }
    }

    /// Send data through a relay session
    public func sendData(_ data: Data, sessionId: String) async throws {
        guard let session = await sessionManager.getSession(sessionId) else {
            throw RelayError.sessionNotFound
        }

        guard let connection = connections[session.relayPeerId] else {
            throw RelayError.notConnected
        }

        try await connection.sendData(data, sessionId: sessionId)
        await session.recordOutgoingData(data)
    }

    /// Handle incoming data for a session
    public func handleIncomingData(_ data: Data, sessionId: String) async {
        if let session = await sessionManager.getSession(sessionId) {
            await session.handleIncomingData(data)
        }
    }

    // MARK: - Health Monitoring

    private func startHealthCheck() {
        healthCheckTask?.cancel()
        healthCheckTask = Task {
            await runHealthCheckLoop()
        }
    }

    private func runHealthCheckLoop() async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: UInt64(config.healthCheckInterval * 1_000_000_000))
                await performHealthCheck()
            } catch {
                break
            }
        }
    }

    private func performHealthCheck() async {
        // Check connection health
        var unhealthyRelays: [PeerId] = []

        for (peerId, connection) in connections {
            if await !connection.isHealthy {
                unhealthyRelays.append(peerId)
            }
        }

        // Remove unhealthy connections
        for peerId in unhealthyRelays {
            logger.warning("Relay \(peerId) unhealthy, disconnecting")

            // Log relay failure
            await eventLogger?.recordRelayEvent(
                peerId: "self",
                relayPeerId: peerId,
                eventType: .failed,
                reason: "Health check failed"
            )

            await disconnectRelay(peerId)
        }

        // Add more relays if below minimum
        if connections.count < config.minRelays && needsRelay {
            logger.info("Below minimum relays, selecting more")
            do {
                try await selectAndConnectRelays()
            } catch {
                logger.error("Failed to select additional relays: \(error)")
            }
        }

        // Clean up idle sessions
        await sessionManager.cleanupIdleSessions()
    }

    // MARK: - Status

    /// Get all connection metrics
    public func connectionMetrics() async -> [RelayConnectionMetrics] {
        var metrics: [RelayConnectionMetrics] = []
        for (_, connection) in connections {
            metrics.append(await connection.metrics)
        }
        return metrics
    }

    /// Get all session metrics
    public func sessionMetrics() async -> [RelaySessionMetrics] {
        var metrics: [RelaySessionMetrics] = []
        for session in await sessionManager.allSessions {
            metrics.append(await session.metrics)
        }
        return metrics
    }

    /// Number of active connections
    public var connectionCount: Int {
        connections.count
    }

    /// Number of active sessions
    public var sessionCount: Int {
        get async {
            await sessionManager.activeCount
        }
    }
}
