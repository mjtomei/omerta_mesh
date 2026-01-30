// TunnelManager.swift - Machine session management for mesh networks
//
// This utility manages machine-to-machine sessions over a mesh network.
// It is agnostic to how the network was created (Cloister, manual key, etc.)
// and assumes a simple topology: two endpoints (optionally with relay).

import Foundation
import OmertaMesh
import Logging

/// TunnelManager provides session pool management for machine communication over a mesh.
///
/// Usage:
/// ```swift
/// let mesh = MeshNetwork(config: config)
/// try await mesh.start()
///
/// let manager = TunnelManager(provider: mesh, config: .default)
/// try await manager.start()
///
/// // Get or create a session (keyed by machineId + channel)
/// let session = try await manager.getSession(machineId: remoteMachineId, channel: "data")
///
/// await session.onReceive { data in
///     print("Received \(data.count) bytes")
/// }
///
/// try await session.send(data)
/// ```
public actor TunnelManager {
    private let provider: any ChannelProvider
    private let logger: Logger
    private let config: TunnelManagerConfig

    /// Default channel for sessions
    private let defaultChannel = "data"

    /// Session pool keyed by (machineId, channel)
    private var sessions: [TunnelSessionKey: TunnelSession] = [:]

    /// Session IDs for verifying close handshakes
    private var sessionIds: [TunnelSessionKey: String] = [:]

    /// Per-machine health monitors
    private var healthMonitors: [MachineId: TunnelHealthMonitor] = [:]

    /// Network endpoint change detector
    private let endpointChangeDetector = EndpointChangeDetector()

    /// Wire channels registered for dispatch
    private var registeredWireChannels: Set<String> = []

    /// Pre-session data buffer: holds data that arrives before the session handshake completes.
    /// Flushed to the session once it's created. Max 32 packets per key, 5s TTL.
    private var pendingData: [TunnelSessionKey: [(data: Data, bufferedAt: ContinuousClock.Instant)]] = [:]
    private let pendingDataMaxPerKey = 32
    private let pendingDataTTL: Duration = .seconds(5)

    /// Whether the manager is running
    private var isRunning: Bool = false

    /// Task consuming endpoint change events
    private var endpointChangeTask: Task<Void, Never>?

    /// Callback when remote machine initiates a session
    private var sessionRequestHandler: ((MachineId) async -> Bool)?

    /// Callback when session is established
    private var sessionEstablishedHandler: ((TunnelSession) async -> Void)?

    /// Channel for session handshake
    private let handshakeChannel = "tunnel-handshake"

    /// Channel for health probes (separate from handshake to avoid creating sessions)
    private let healthProbeChannel = "tunnel-health-probe"

    /// Number of active sessions in the pool
    public var sessionCount: Int {
        sessions.count
    }

    /// All active session keys
    public var activeSessionKeys: [TunnelSessionKey] {
        Array(sessions.keys)
    }

    /// Get the health monitor for a specific machine (for test observation)
    public func getHealthMonitor(for machineId: MachineId) -> TunnelHealthMonitor? {
        let result = healthMonitors[machineId]
        if result == nil {
            logger.debug("getHealthMonitor: nil for \(machineId), keys=\(Array(healthMonitors.keys))")
        }
        return result
    }

    /// Initialize the tunnel manager
    /// - Parameters:
    ///   - provider: The channel provider (e.g., MeshNetwork) to use for communication
    ///   - config: Configuration for the session pool
    public init(provider: any ChannelProvider, config: TunnelManagerConfig = .default) {
        self.provider = provider
        self.config = config
        self.logger = Logger(label: "io.omerta.tunnel.manager")
    }

    /// Start the tunnel manager
    public func start() async throws {
        guard !isRunning else { return }

        // Register handshake handler for incoming session requests
        try await provider.onChannel(handshakeChannel) { [weak self] machineId, data in
            await self?.handleHandshake(from: machineId, data: data)
        }

        // Register health probe handler — receiving a probe means remote is alive.
        // Both sides run monitors and send probes independently. No echo response needed.
        try await provider.onChannel(healthProbeChannel) { [weak self] machineId, _ in
            guard let self else { return }
            await self.notifyPacketReceived(from: machineId)
        }

        isRunning = true

        // Start endpoint change detection
        await endpointChangeDetector.start()
        endpointChangeTask = Task { [weak self] in
            guard let self else { return }
            let changes = await self.endpointChangeDetector.changes
            for await _ in changes {
                await self.reprobeAllMachines()
            }
        }

        logger.info("Tunnel manager started")
    }

    /// Stop the tunnel manager and close all sessions
    public func stop() async {
        guard isRunning else { return }

        endpointChangeTask?.cancel()
        endpointChangeTask = nil
        await endpointChangeDetector.stop()

        for (_, monitor) in healthMonitors {
            await monitor.stopMonitoring()
        }
        healthMonitors.removeAll()

        await provider.offChannel(handshakeChannel)
        await provider.offChannel(healthProbeChannel)

        for wireChannel in registeredWireChannels {
            await provider.offChannel(wireChannel)
        }
        registeredWireChannels.removeAll()

        for (_, session) in sessions {
            await session.close()
        }
        sessions.removeAll()
        sessionIds.removeAll()
        pendingData.removeAll()

        isRunning = false
        logger.info("Tunnel manager stopped")
    }

    /// Set handler for incoming session requests
    /// - Parameter handler: Callback that returns true to accept, false to reject (receives machineId)
    public func setSessionRequestHandler(_ handler: @escaping (MachineId) async -> Bool) {
        self.sessionRequestHandler = handler
    }

    /// Set handler called when a session is established
    public func setSessionEstablishedHandler(_ handler: @escaping (TunnelSession) async -> Void) {
        self.sessionEstablishedHandler = handler
    }

    // MARK: - Session Management

    /// Get or create a session with a remote machine on a specific channel.
    /// - Parameters:
    ///   - machineId: The remote machine ID
    ///   - channel: The logical channel name (defaults to "data")
    /// - Returns: The tunnel session (existing or newly created)
    public func getSession(machineId: MachineId, channel: String = "data") async throws -> TunnelSession {
        guard isRunning else {
            throw TunnelError.notConnected
        }

        let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)

        // Return existing session if active
        if let existing = sessions[key] {
            let state = await existing.state
            if state == .active {
                return existing
            }
            // Remove stale session
            sessions.removeValue(forKey: key)
        }

        // Check limits
        try checkSessionLimits(forMachine: machineId)

        logger.info("Creating session", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])

        // Generate session ID for this session
        let sid = UUID().uuidString.prefix(8).lowercased()

        // Send handshake with channel info
        let handshake = SessionHandshake(type: .request, channel: channel, sessionId: String(sid))
        let data = try JSONEncoder().encode(handshake)
        try await provider.sendOnChannel(data, toMachine: machineId, channel: handshakeChannel)

        // Create session
        let newSession = TunnelSession(
            remoteMachineId: machineId,
            channel: channel,
            provider: provider
        )

        await newSession.activate()
        sessions[key] = newSession
        sessionIds[key] = String(sid)
        await ensureWireChannelRegistered(for: channel)

        // Start health monitor for this machine if first session
        if healthMonitors[machineId] == nil {
            logger.info("Creating health monitor for machine \(machineId.prefix(8))...")
            let monitor = TunnelHealthMonitor(
                minProbeInterval: config.healthProbeMinInterval,
                maxProbeInterval: config.healthProbeMaxInterval,
                failureThreshold: config.healthFailureThreshold,
                graceIntervals: config.healthGraceIntervals
            )
            healthMonitors[machineId] = monitor
            await monitor.startMonitoring(
                machineId: machineId,
                sendProbe: { [weak self] id in
                    guard let self else { return }
                    try await self.provider.sendOnChannel(Data([0x01]), toMachine: id, channel: self.healthProbeChannel)
                },
                onFailure: { [weak self] id in
                    guard let self else { return }
                    await self.handleHealthFailure(machineId: id)
                }
            )
        } else {
            logger.debug("Health monitor already exists for \(machineId.prefix(8))...")
        }

        logger.info("Session created", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
        return newSession
    }

    /// Look up an existing session by key (no creation)
    public func getExistingSession(key: TunnelSessionKey) -> TunnelSession? {
        return sessions[key]
    }

    /// Create a session with a remote machine on the default "data" channel.
    /// Convenience wrapper around `getSession(machineId:channel:)`.
    public func createSession(withMachine machine: MachineId) async throws -> TunnelSession {
        return try await getSession(machineId: machine, channel: defaultChannel)
    }

    /// Close a specific session by key
    public func closeSession(key: TunnelSessionKey) async {
        guard let session = sessions.removeValue(forKey: key) else { return }
        let sid = sessionIds.removeValue(forKey: key)

        logger.info("closeSession: sending close handshake", metadata: ["machine": "\(key.remoteMachineId)", "channel": "\(key.channel)"])

        // Notify remote machine
        let handshake = SessionHandshake(type: .close, channel: key.channel, sessionId: sid)
        if let data = try? JSONEncoder().encode(handshake) {
            try? await provider.sendOnChannel(data, toMachine: key.remoteMachineId, channel: handshakeChannel)
        }

        await session.close()
        logger.info("Session closed", metadata: ["machine": "\(key.remoteMachineId)", "channel": "\(key.channel)"])
    }

    /// Close all sessions to a specific machine
    public func closeAllSessions(to machineId: MachineId) async {
        let keysToClose = sessions.keys.filter { $0.remoteMachineId == machineId }
        for key in keysToClose {
            await closeSession(key: key)
        }

        if let monitor = healthMonitors.removeValue(forKey: machineId) {
            await monitor.stopMonitoring()
        }
    }

    /// Close the default "data" channel session (backward compatibility)
    public func closeSession() async {
        // Close all sessions (backward compatible behavior)
        let allKeys = Array(sessions.keys)
        for key in allKeys {
            await closeSession(key: key)
        }
    }

    // MARK: - Private

    /// Notify health monitor that a packet was received from a machine
    public func notifyPacketReceived(from machineId: MachineId) async {
        if let monitor = healthMonitors[machineId] {
            await monitor.onPacketReceived()
        }
    }

    private func handleHealthFailure(machineId: MachineId) async {
        logger.warning("Health check FAILED for machine — closing all sessions", metadata: ["machine": "\(machineId)"])
        await closeAllSessions(to: machineId)
        // Remove dead monitor so new sessions get a fresh one
        healthMonitors.removeValue(forKey: machineId)
    }

    private func reprobeAllMachines() async {
        for (_, monitor) in healthMonitors {
            await monitor.onPacketReceived()
        }
    }

    private func ensureWireChannelRegistered(for channel: String) async {
        let wireChannel = "tunnel-\(channel)"
        guard !registeredWireChannels.contains(wireChannel) else { return }
        do {
            try await provider.onChannel(wireChannel) { [weak self] machineId, data in
                await self?.dispatchToSession(data, from: machineId, channel: channel)
            }
            registeredWireChannels.insert(wireChannel)
        } catch {
            logger.error("Failed to register wire channel", metadata: [
                "wireChannel": "\(wireChannel)",
                "channel": "\(channel)",
                "error": "\(error)"
            ])
        }
    }

    private func dispatchToSession(_ data: Data, from machineId: MachineId, channel: String) async {
        let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)
        if let session = sessions[key] {
            await session.deliverIncoming(data)
        } else {
            // Buffer data that arrives before the session handshake completes
            let now = ContinuousClock.now
            var buffer = pendingData[key] ?? []
            // Evict expired entries
            buffer.removeAll { now - $0.bufferedAt > pendingDataTTL }
            if buffer.count < pendingDataMaxPerKey {
                buffer.append((data: data, bufferedAt: now))
                pendingData[key] = buffer
                logger.debug("Buffered pre-session data", metadata: ["machine": "\(machineId)", "channel": "\(channel)", "buffered": "\(buffer.count)"])
            }
        }
    }

    private func checkSessionLimits(forMachine machineId: MachineId) throws {
        // Check total limit
        if sessions.count >= config.maxTotalSessions {
            throw TunnelError.sessionLimitReached
        }
        // Check per-machine limit
        let machineCount = sessions.keys.filter { $0.remoteMachineId == machineId }.count
        if machineCount >= config.maxSessionsPerMachine {
            throw TunnelError.sessionLimitReached
        }
    }

    private func handleHandshake(from machineId: MachineId, data: Data) async {
        guard let handshake = try? JSONDecoder().decode(SessionHandshake.self, from: data) else {
            logger.warning("Invalid handshake from machine \(machineId.prefix(8))...")
            return
        }

        let channel = handshake.channel ?? defaultChannel

        switch handshake.type {
        case .request:
            // Remote machine wants to start a session
            let accept: Bool
            if let handler = sessionRequestHandler {
                accept = await handler(machineId)
            } else {
                accept = true
            }

            if accept {
                let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)

                // Close existing session on same key if any
                if let existing = sessions[key] {
                    await existing.close()
                }

                // Create new session
                let newSession = TunnelSession(
                    remoteMachineId: machineId,
                    channel: channel,
                    provider: provider
                )
                await newSession.activate()
                sessions[key] = newSession
                sessionIds[key] = handshake.sessionId
                await ensureWireChannelRegistered(for: channel)

                // Flush any data that arrived before the session was created
                if let buffered = pendingData.removeValue(forKey: key) {
                    let now = ContinuousClock.now
                    for entry in buffered where now - entry.bufferedAt <= pendingDataTTL {
                        await newSession.deliverIncoming(entry.data)
                    }
                    if !buffered.isEmpty {
                        logger.info("Flushed \(buffered.count) buffered packet(s)", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
                    }
                }

                // Send ack
                let ack = SessionHandshake(type: .ack, channel: channel, sessionId: handshake.sessionId)
                if let ackData = try? JSONEncoder().encode(ack) {
                    try? await provider.sendOnChannel(ackData, toMachine: machineId, channel: handshakeChannel)
                }

                // Start health monitor for this machine if first session
                if healthMonitors[machineId] == nil {
                    let monitor = TunnelHealthMonitor(
                        minProbeInterval: config.healthProbeMinInterval,
                        maxProbeInterval: config.healthProbeMaxInterval,
                        failureThreshold: config.healthFailureThreshold,
                        graceIntervals: config.healthGraceIntervals
                    )
                    healthMonitors[machineId] = monitor
                    await monitor.startMonitoring(
                        machineId: machineId,
                        sendProbe: { [weak self] id in
                            guard let self else { return }
                            try await self.provider.sendOnChannel(Data([0x01]), toMachine: id, channel: self.healthProbeChannel)
                        },
                        onFailure: { [weak self] id in
                            await self?.handleHealthFailure(machineId: id)
                        }
                    )
                }

                logger.info("Session accepted", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])

                if let handler = sessionEstablishedHandler {
                    await handler(newSession)
                }
            } else {
                let reject = SessionHandshake(type: .reject, channel: channel)
                if let rejectData = try? JSONEncoder().encode(reject) {
                    try? await provider.sendOnChannel(rejectData, toMachine: machineId, channel: handshakeChannel)
                }
                logger.info("Session rejected", metadata: ["machine": "\(machineId)"])
            }

        case .ack:
            logger.debug("Session ack received", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])

        case .reject:
            logger.info("Session rejected by machine", metadata: ["machine": "\(machineId)"])

        case .close:
            let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)
            // Verify sessionId matches to reject stale close from old sessions
            if let currentSid = sessionIds[key] {
                if let closeSid = handshake.sessionId, closeSid != currentSid {
                    logger.info("Ignoring stale close handshake (sid \(closeSid) != \(currentSid))", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
                    return
                }
            }
            if let session = sessions.removeValue(forKey: key) {
                sessionIds.removeValue(forKey: key)
                await session.close()
                logger.info("Session closed by machine", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
            }
        }
    }
}

// MARK: - Internal Types

struct SessionHandshake: Codable, Sendable {
    enum HandshakeType: String, Codable, Sendable {
        case request
        case ack
        case reject
        case close
    }

    let type: HandshakeType
    let channel: String?
    let sessionId: String?

    init(type: HandshakeType, channel: String? = nil, sessionId: String? = nil) {
        self.type = type
        self.channel = channel
        self.sessionId = sessionId
    }
}
