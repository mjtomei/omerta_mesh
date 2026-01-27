// TunnelManager.swift - Machine session management for mesh networks
//
// This utility manages machine-to-machine sessions over a mesh network.
// It is agnostic to how the network was created (Cloister, manual key, etc.)
// and assumes a simple topology: two endpoints (optionally with relay).

import Foundation
import OmertaMesh
import Logging

/// TunnelManager provides session management for machine communication over a mesh.
///
/// Usage:
/// ```swift
/// // Higher level code creates the mesh network (e.g., via Cloister)
/// let mesh = MeshNetwork(config: config)
/// try await mesh.start()
///
/// // Create tunnel manager on that network
/// let manager = TunnelManager(provider: mesh)
/// try await manager.start()
///
/// // Create session with the remote machine
/// let session = try await manager.createSession(withMachine: remoteMachineId)
///
/// // Set up receive handler
/// await session.onReceive { data in
///     print("Received \(data.count) bytes")
/// }
///
/// // Send data
/// try await session.send(data)
/// ```
public actor TunnelManager {
    private let provider: any ChannelProvider
    private let logger: Logger

    /// Default channel for sessions (will be configurable in Phase 2)
    private let defaultChannel = "data"

    /// The current session (only one machine expected - Phase 2 will add session pool)
    private var session: TunnelSession?

    /// Whether the manager is running
    private var isRunning: Bool = false

    /// Callback when remote machine initiates a session
    private var sessionRequestHandler: ((MachineId) async -> Bool)?

    /// Callback when session is established
    private var sessionEstablishedHandler: ((TunnelSession) async -> Void)?

    /// Channel for session handshake
    private let handshakeChannel = "tunnel-handshake"

    /// Initialize the tunnel manager
    /// - Parameter provider: The channel provider (e.g., MeshNetwork) to use for communication
    public init(provider: any ChannelProvider) {
        self.provider = provider
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

    /// Stop the tunnel manager
    public func stop() async {
        guard isRunning else { return }

        await provider.offChannel(handshakeChannel)

        if let session = session {
            await session.close()
            self.session = nil
        }

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

    /// Create a session with a remote machine
    /// - Parameter machine: The machine to create the session with
    /// - Returns: The tunnel session
    public func createSession(withMachine machine: MachineId) async throws -> TunnelSession {
        guard isRunning else {
            throw TunnelError.notConnected
        }

        // Only one session at a time in this simple model (Phase 2 will add session pool)
        if let existing = session {
            await existing.close()
        }

        logger.info("Creating session", metadata: ["machine": "\(machine)"])

        // Send handshake to machine
        let handshake = SessionHandshake(type: .request)
        let data = try JSONEncoder().encode(handshake)
        try await provider.sendOnChannel(data, toMachine: machine, channel: handshakeChannel)

        // Create session (don't wait for ack in simple model)
        let newSession = TunnelSession(
            remoteMachineId: machine,
            channel: defaultChannel,
            provider: provider
        )

        await newSession.activate()
        self.session = newSession

        logger.info("Session created", metadata: ["machine": "\(machine)"])
        return newSession
    }

    /// Get the current session
    public func currentSession() -> TunnelSession? {
        return session
    }

    /// Close the current session
    public func closeSession() async {
        if let session = session {
            // Notify remote machine
            let handshake = SessionHandshake(type: .close)
            if let data = try? JSONEncoder().encode(handshake) {
                let machine = await session.remoteMachineId
                try? await provider.sendOnChannel(data, toMachine: machine, channel: handshakeChannel)
            }

            await session.close()
            self.session = nil
            logger.info("Session closed")
        }
    }

    // MARK: - Private

    private func handleHandshake(from machineId: MachineId, data: Data) async {
        guard let handshake = try? JSONDecoder().decode(SessionHandshake.self, from: data) else {
            logger.warning("Invalid handshake from machine \(machineId.prefix(8))...")
            return
        }

        switch handshake.type {
        case .request:
            // Remote machine wants to start a session
            let accept: Bool
            if let handler = sessionRequestHandler {
                accept = await handler(machineId)
            } else {
                // Accept by default
                accept = true
            }

            if accept {
                // Close existing session if any
                if let existing = session {
                    await existing.close()
                }

                // Create new session
                let newSession = TunnelSession(
                    remoteMachineId: machineId,
                    channel: defaultChannel,
                    provider: provider
                )
                await newSession.activate()
                self.session = newSession

                // Send ack to the machine
                let ack = SessionHandshake(type: .ack)
                if let ackData = try? JSONEncoder().encode(ack) {
                    try? await provider.sendOnChannel(ackData, toMachine: machineId, channel: handshakeChannel)
                }

                logger.info("Session accepted", metadata: ["machine": "\(machineId)"])

                if let handler = sessionEstablishedHandler {
                    await handler(newSession)
                }
            } else {
                // Send reject
                let reject = SessionHandshake(type: .reject)
                if let rejectData = try? JSONEncoder().encode(reject) {
                    try? await provider.sendOnChannel(rejectData, toMachine: machineId, channel: handshakeChannel)
                }
                logger.info("Session rejected", metadata: ["machine": "\(machineId)"])
            }

        case .ack:
            logger.debug("Session ack received", metadata: ["machine": "\(machineId)"])

        case .reject:
            logger.info("Session rejected by machine", metadata: ["machine": "\(machineId)"])

        case .close:
            if let session = session, await session.remoteMachineId == machineId {
                await session.close()
                self.session = nil
                logger.info("Session closed by machine", metadata: ["machine": "\(machineId)"])
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
}
