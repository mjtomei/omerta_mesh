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

    /// Whether the manager is running
    private var isRunning: Bool = false

    /// Callback when remote machine initiates a session
    private var sessionRequestHandler: ((MachineId) async -> Bool)?

    /// Callback when session is established
    private var sessionEstablishedHandler: ((TunnelSession) async -> Void)?

    /// Channel for session handshake
    private let handshakeChannel = "tunnel-handshake"

    /// Number of active sessions in the pool
    public var sessionCount: Int {
        sessions.count
    }

    /// All active session keys
    public var activeSessionKeys: [TunnelSessionKey] {
        Array(sessions.keys)
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

        isRunning = true
        logger.info("Tunnel manager started")
    }

    /// Stop the tunnel manager and close all sessions
    public func stop() async {
        guard isRunning else { return }

        await provider.offChannel(handshakeChannel)

        for (_, session) in sessions {
            await session.close()
        }
        sessions.removeAll()

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

        // Send handshake with channel info
        let handshake = SessionHandshake(type: .request, channel: channel)
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

        // Notify remote machine
        let handshake = SessionHandshake(type: .close, channel: key.channel)
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

                // Send ack
                let ack = SessionHandshake(type: .ack, channel: channel)
                if let ackData = try? JSONEncoder().encode(ack) {
                    try? await provider.sendOnChannel(ackData, toMachine: machineId, channel: handshakeChannel)
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
            if let session = sessions.removeValue(forKey: key) {
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

    init(type: HandshakeType, channel: String? = nil) {
        self.type = type
        self.channel = channel
    }
}
