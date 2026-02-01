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
/// let session = try await manager.getSession(machineId: remoteMachineId, channel: "data") { data in
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

    /// Per-session receive accumulators (bytes and packets since last probe)
    private var receiveAccum: [TunnelSessionKey: (bytes: UInt64, packets: UInt64)] = [:]

    /// Timestamp of last probe sent to each machine (for computing per-second rates)
    private var lastProbeTime: [MachineId: ContinuousClock.Instant] = [:]

    /// Per-machine round-robin offset for probe channel selection
    private var probeRoundRobinOffset: [MachineId: Int] = [:]

    /// Remote-reported delivered stats per session
    private var deliveredStats: [TunnelSessionKey: (bytesPerSecond: UInt64, packetsPerSecond: UInt64)] = [:]

    /// Per-session endpoint sets for multi-endpoint tunnels
    private var endpointSets: [TunnelSessionKey: EndpointSet] = [:]

    /// Auxiliary ports bound by this manager (port → set of session keys using it)
    private var auxiliaryPorts: [UInt16: Set<TunnelSessionKey>] = [:]

    /// Whether the manager is running
    private var isRunning: Bool = false

    /// Task consuming endpoint change events
    private var endpointChangeTask: Task<Void, Never>?

    /// Factory for inbound sessions: called when a remote machine requests a session.
    /// Returns a receive handler to accept (passed to TunnelSession constructor), or nil to reject.
    private var inboundSessionHandler: ((MachineId, String) async -> (@Sendable (Data) async -> Void)?)?

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

    /// Get the endpoint set for a session (for test observation)
    public func getEndpointSet(for key: TunnelSessionKey) -> EndpointSet? {
        endpointSets[key]
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
        // Probes carry per-channel receive stats reported by the remote side.
        try await provider.onChannel(healthProbeChannel) { [weak self] machineId, data in
            guard let self else { return }
            await self.handleHealthProbe(from: machineId, data: data)
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
        receiveAccum.removeAll()
        deliveredStats.removeAll()
        endpointSets.removeAll()
        auxiliaryPorts.removeAll()
        lastProbeTime.removeAll()
        probeRoundRobinOffset.removeAll()

        isRunning = false
        logger.info("Tunnel manager stopped")
    }

    /// Set factory for inbound sessions.
    /// Called when a remote machine requests a session with (machineId, channel).
    /// Return a receive handler to accept, or nil to reject.
    public func setInboundSessionHandler(_ handler: @escaping (MachineId, String) async -> (@Sendable (Data) async -> Void)?) {
        self.inboundSessionHandler = handler
    }

    // MARK: - Session Management

    /// Get or create a session with a remote machine on a specific channel.
    /// - Parameters:
    ///   - machineId: The remote machine ID
    ///   - channel: The logical channel name (defaults to "data")
    /// - Returns: The tunnel session (existing or newly created)
    public func getSession(machineId: MachineId, channel: String = "data", extraEndpoints: Int? = nil, receiveHandler: (@Sendable (Data) async -> Void)? = nil) async throws -> TunnelSession {
        guard isRunning else {
            throw TunnelError.notConnected
        }

        let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)

        // Return existing session if active
        if let existing = sessions[key] {
            let state = await existing.state
            if state == .active || state == .degraded {
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

        // Send handshake with channel info (include extra endpoints request if configured)
        let effectiveExtra = extraEndpoints ?? config.extraEndpoints
        let extraRequested = effectiveExtra > 0 ? effectiveExtra : nil
        let handshake = SessionHandshake(type: .request, channel: channel, sessionId: String(sid),
                                         extraEndpointsRequested: extraRequested)
        let data = try JSONEncoder().encode(handshake)
        try await provider.sendOnChannel(data, toMachine: machineId, channel: handshakeChannel)

        // Create session
        let newSession = TunnelSession(
            remoteMachineId: machineId,
            channel: channel,
            provider: provider,
            receiveHandler: receiveHandler
        )

        await newSession.activate()
        sessions[key] = newSession
        sessionIds[key] = String(sid)
        await ensureWireChannelRegistered(for: channel)

        // Initialize endpoint set (primary endpoint will be added when ack arrives with extras)
        let endpointSet = EndpointSet()
        endpointSets[key] = endpointSet
        await newSession.setEndpointSet(endpointSet)

        // Start health monitor for this machine if first session
        if healthMonitors[machineId] == nil {
            logger.info("Creating health monitor for machine \(machineId.prefix(8))...")
            let monitor = TunnelHealthMonitor(
                minProbeInterval: config.healthProbeMinInterval,
                maxProbeInterval: config.healthProbeMaxInterval,
                degradedThreshold: config.healthDegradedThreshold,
                failureThreshold: config.healthFailureThreshold,
                graceIntervals: config.healthGraceIntervals
            )
            healthMonitors[machineId] = monitor
            await monitor.startMonitoring(
                machineId: machineId,
                sendProbe: { [weak self] id in
                    await self?.sendProbeToAllEndpoints(machineId: id)
                },
                onDegraded: { [weak self] id in
                    await self?.handleHealthDegraded(machineId: id)
                },
                onFailure: { [weak self] id in
                    guard let self else { return }
                    await self.handleHealthFailure(machineId: id)
                },
                onRecovered: { [weak self] id in
                    await self?.handleHealthRecovered(machineId: id)
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
    public func createSession(withMachine machine: MachineId, receiveHandler: (@Sendable (Data) async -> Void)? = nil) async throws -> TunnelSession {
        return try await getSession(machineId: machine, channel: defaultChannel, receiveHandler: receiveHandler)
    }

    /// Close a specific session by key
    public func closeSession(key: TunnelSessionKey) async {
        guard let session = sessions.removeValue(forKey: key) else { return }
        let sid = sessionIds.removeValue(forKey: key)
        receiveAccum.removeValue(forKey: key)
        deliveredStats.removeValue(forKey: key)
        endpointSets.removeValue(forKey: key)

        // Unbind auxiliary ports associated with this session
        if let auxProvider = provider as? AuxiliaryPortProvider {
            var portsToUnbind: [UInt16] = []
            for (port, var keys) in auxiliaryPorts {
                keys.remove(key)
                if keys.isEmpty {
                    portsToUnbind.append(port)
                    auxiliaryPorts.removeValue(forKey: port)
                } else {
                    auxiliaryPorts[port] = keys
                }
            }
            for port in portsToUnbind {
                await auxProvider.unbindAuxiliaryPort(port)
                logger.info("Unbound auxiliary port \(port) for closed session")
            }
        }

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
        lastProbeTime.removeValue(forKey: machineId)
        probeRoundRobinOffset.removeValue(forKey: machineId)
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

    private func handleHealthDegraded(machineId: MachineId) async {
        logger.warning("Health DEGRADED for machine — marking sessions degraded", metadata: ["machine": "\(machineId)"])
        let keys = sessions.keys.filter { $0.remoteMachineId == machineId }
        for key in keys {
            if let session = sessions[key] {
                await session.setDegraded()
            }
        }
    }

    private func handleHealthRecovered(machineId: MachineId) async {
        logger.info("Health RECOVERED for machine — restoring sessions", metadata: ["machine": "\(machineId)"])
        let keys = sessions.keys.filter { $0.remoteMachineId == machineId }
        for key in keys {
            if let session = sessions[key] {
                await session.recover()
            }
        }
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
        await notifyPacketReceived(from: machineId)
        if let session = sessions[key] {
            receiveAccum[key, default: (bytes: 0, packets: 0)].bytes += UInt64(data.count)
            receiveAccum[key, default: (bytes: 0, packets: 0)].packets += 1
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
            // Use inbound session handler to get receive handler (accept) or nil (reject)
            let receiveHandler: (@Sendable (Data) async -> Void)?
            if let handler = inboundSessionHandler {
                receiveHandler = await handler(machineId, channel)
            } else {
                // Default: accept but log discarded data
                receiveHandler = { [logger] data in
                    logger.debug("Received \(data.count) bytes with no inbound handler; discarding",
                                 metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
                }
            }

            if receiveHandler != nil {
                let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)

                // Close existing session on same key if any
                if let existing = sessions[key] {
                    await existing.close()
                }

                // Create new session with receive handler from factory
                let newSession = TunnelSession(
                    remoteMachineId: machineId,
                    channel: channel,
                    provider: provider,
                    receiveHandler: receiveHandler
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

                // Initialize endpoint set for inbound session
                let endpointSet = EndpointSet()
                endpointSets[key] = endpointSet
                await newSession.setEndpointSet(endpointSet)

                // Bind auxiliary ports if requested and provider supports it
                var extraEndpointAddrs: [String]? = nil
                if let requested = handshake.extraEndpointsRequested, requested > 0,
                   let auxProvider = provider as? AuxiliaryPortProvider {
                    let localHost = await auxProvider.localAddressForMachine(machineId)
                    if let host = localHost {
                        var addrs: [String] = []
                        for _ in 0..<requested {
                            do {
                                let auxPort = try await auxProvider.bindAuxiliaryPort()
                                let addr = "\(host):\(auxPort)"
                                addrs.append(addr)
                                await endpointSet.add(address: addr, localPort: auxPort)
                                auxiliaryPorts[auxPort, default: []].insert(key)
                                logger.info("Bound auxiliary port \(auxPort) for inbound session")
                            } catch {
                                logger.warning("Failed to bind auxiliary port: \(error)")
                            }
                        }
                        if !addrs.isEmpty {
                            extraEndpointAddrs = addrs
                        }
                    }
                }

                // Send ack (with extra endpoints if we bound any)
                let ack = SessionHandshake(type: .ack, channel: channel, sessionId: handshake.sessionId,
                                           extraEndpoints: extraEndpointAddrs)
                do {
                    let ackData = try JSONEncoder().encode(ack)
                    try await provider.sendOnChannel(ackData, toMachine: machineId, channel: handshakeChannel)
                    logger.info("Sent ack with \(extraEndpointAddrs?.count ?? 0) extra endpoint(s)", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
                } catch {
                    logger.error("Failed to send ack: \(error)", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
                }

                // Start health monitor for this machine if first session
                if healthMonitors[machineId] == nil {
                    let monitor = TunnelHealthMonitor(
                        minProbeInterval: config.healthProbeMinInterval,
                        maxProbeInterval: config.healthProbeMaxInterval,
                        degradedThreshold: config.healthDegradedThreshold,
                        failureThreshold: config.healthFailureThreshold,
                        graceIntervals: config.healthGraceIntervals
                    )
                    healthMonitors[machineId] = monitor
                    await monitor.startMonitoring(
                        machineId: machineId,
                        sendProbe: { [weak self] id in
                            await self?.sendProbeToAllEndpoints(machineId: id)
                        },
                        onDegraded: { [weak self] id in
                            await self?.handleHealthDegraded(machineId: id)
                        },
                        onFailure: { [weak self] id in
                            await self?.handleHealthFailure(machineId: id)
                        },
                        onRecovered: { [weak self] id in
                            await self?.handleHealthRecovered(machineId: id)
                        }
                    )
                }

                logger.info("Session accepted", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
            } else {
                let reject = SessionHandshake(type: .reject, channel: channel)
                if let rejectData = try? JSONEncoder().encode(reject) {
                    try? await provider.sendOnChannel(rejectData, toMachine: machineId, channel: handshakeChannel)
                }
                logger.info("Session rejected", metadata: ["machine": "\(machineId)"])
            }

        case .ack:
            let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)
            // If ack includes extra endpoints, add them to our EndpointSet
            if let extras = handshake.extraEndpoints, !extras.isEmpty,
               let endpointSet = endpointSets[key] {
                // Add primary endpoint first (localPort nil = primary socket, address "primary" = sentinel)
                await endpointSet.add(address: "primary", localPort: nil)

                for ep in extras {
                    await endpointSet.add(address: ep, localPort: nil)
                }
                let totalCount = await endpointSet.count
                logger.info("Received \(extras.count) extra endpoint(s) from ack, total \(totalCount) endpoints", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])

                // Bind our own auxiliary ports (one per remote extra endpoint)
                // and pair each with a remote endpoint for sending.
                // Also send our aux port addresses back so the remote can send to us.
                if let auxProvider = provider as? AuxiliaryPortProvider {
                    let localHost = await auxProvider.localAddressForMachine(machineId)
                    if let host = localHost {
                        var ourAddrs: [String] = []
                        // Re-add remote extras with paired local aux ports
                        for remoteEp in extras {
                            do {
                                let auxPort = try await auxProvider.bindAuxiliaryPort()
                                let addr = "\(host):\(auxPort)"
                                ourAddrs.append(addr)
                                auxiliaryPorts[auxPort, default: []].insert(key)
                                // Update the endpoint entry with the local port for sending
                                await endpointSet.updateLocalPort(for: remoteEp, localPort: auxPort)
                                logger.info("Bound auxiliary port \(auxPort) → remote \(remoteEp)")
                            } catch {
                                logger.warning("Failed to bind auxiliary port: \(error)")
                            }
                        }
                        if !ourAddrs.isEmpty {
                            let offer = SessionHandshake(type: .endpointOffer, channel: channel,
                                                          sessionId: handshake.sessionId,
                                                          extraEndpoints: ourAddrs)
                            if let offerData = try? JSONEncoder().encode(offer) {
                                try? await provider.sendOnChannel(offerData, toMachine: machineId, channel: handshakeChannel)
                            }
                        }
                    }
                }
            }
            logger.debug("Session ack received", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])

        case .endpointOffer:
            let key = TunnelSessionKey(remoteMachineId: machineId, channel: channel)
            if let extras = handshake.extraEndpoints, !extras.isEmpty,
               let endpointSet = endpointSets[key] {
                // Add primary endpoint first
                await endpointSet.add(address: "primary", localPort: nil)

                // The responder already has its own aux ports bound (from the .request handler).
                // Now pair each remote extra endpoint with one of our local aux ports.
                let ourAuxPorts = auxiliaryPorts.keys.filter { port in
                    auxiliaryPorts[port]?.contains(key) == true
                }.sorted()

                for (i, ep) in extras.enumerated() {
                    let localPort = i < ourAuxPorts.count ? ourAuxPorts[i] : nil
                    await endpointSet.add(address: ep, localPort: localPort)
                }
                let totalCount = await endpointSet.count
                logger.info("Received \(extras.count) extra endpoint(s) from offer, total \(totalCount) endpoints", metadata: ["machine": "\(machineId)", "channel": "\(channel)"])
            }

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
    // MARK: - Delivered Stats

    /// Get delivered traffic stats for a session, as reported by the remote side.
    public func deliveredTrafficStats(for key: TunnelSessionKey) -> (bytesPerSecond: UInt64, packetsPerSecond: UInt64)? {
        deliveredStats[key]
    }

    // MARK: - Probe Encoding/Decoding

    /// Send health probe to all endpoints for a machine (primary + extras from EndpointSets).
    private func sendProbeToAllEndpoints(machineId: MachineId) async {
        let payload = buildProbePayload(for: machineId)

        // Always send on primary channel
        try? await provider.sendOnChannel(payload, toMachine: machineId, channel: healthProbeChannel)

        // Also send on any extra endpoints from this machine's sessions
        let machineKeys = endpointSets.keys.filter { $0.remoteMachineId == machineId }
        var sentAddresses = Set<String>()
        for key in machineKeys {
            guard let endpointSet = endpointSets[key] else { continue }
            let addresses = await endpointSet.activeAddresses
            for addr in addresses {
                guard !sentAddresses.contains(addr) else { continue }
                sentAddresses.insert(addr)
                try? await provider.sendOnChannel(payload, toEndpoint: addr, viaPort: nil,
                                                   toMachine: machineId, channel: healthProbeChannel)
            }
        }
    }

    /// Build a probe payload with per-channel receive stats for the given machine.
    /// Format: [1B channelCount] then per channel: [1B nameLen][name bytes][8B bytesPerSec LE][8B packetsPerSec LE]
    private func buildProbePayload(for machineId: MachineId) -> Data {
        let now = ContinuousClock.now
        let elapsed: Duration
        if let last = lastProbeTime[machineId] {
            elapsed = now - last
        } else {
            elapsed = .zero
        }
        lastProbeTime[machineId] = now

        let elapsedSeconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18

        // Gather channels for this machine, sorted for stability
        let relevantKeys = receiveAccum.keys
            .filter { $0.remoteMachineId == machineId }
            .sorted { $0.channel < $1.channel }

        // Round-robin: pick up to 10
        let maxChannels = 10
        let total = relevantKeys.count
        let selected: [TunnelSessionKey]
        if total <= maxChannels {
            selected = relevantKeys
        } else {
            let offset = probeRoundRobinOffset[machineId, default: 0] % total
            var picks: [TunnelSessionKey] = []
            for i in 0..<maxChannels {
                picks.append(relevantKeys[(offset + i) % total])
            }
            selected = picks
            probeRoundRobinOffset[machineId] = offset + maxChannels
        }

        // Encode
        var payload = Data()
        payload.append(UInt8(selected.count))

        for key in selected {
            let accum = receiveAccum[key] ?? (bytes: 0, packets: 0)
            let bps: UInt64
            let pps: UInt64
            if elapsedSeconds > 0 {
                bps = UInt64(Double(accum.bytes) / elapsedSeconds)
                pps = UInt64(Double(accum.packets) / elapsedSeconds)
            } else {
                bps = 0
                pps = 0
            }

            // Reset accumulator for this channel
            receiveAccum.removeValue(forKey: key)

            let nameBytes = Array(key.channel.utf8)
            payload.append(UInt8(min(nameBytes.count, 255)))
            payload.append(contentsOf: nameBytes.prefix(255))
            var bpsLE = bps.littleEndian
            var ppsLE = pps.littleEndian
            payload.append(Data(bytes: &bpsLE, count: 8))
            payload.append(Data(bytes: &ppsLE, count: 8))
        }

        return payload
    }

    /// Handle an incoming health probe, parsing per-channel stats.
    private func handleHealthProbe(from machineId: MachineId, data: Data) async {
        logger.debug("Health probe received from \(machineId.prefix(8))")

        // Parse stats if payload is present
        if data.count >= 1 {
            parseProbeStats(from: machineId, data: data)
        }

        await notifyPacketReceived(from: machineId)
    }

    /// Parse probe payload and store delivered stats.
    private func parseProbeStats(from machineId: MachineId, data: Data) {
        var offset = 0
        guard offset < data.count else { return }

        let channelCount = Int(data[offset])
        offset += 1

        for _ in 0..<channelCount {
            guard offset < data.count else { return }
            let nameLen = Int(data[offset])
            offset += 1

            guard offset + nameLen + 16 <= data.count else { return }

            let nameBytes = data[offset..<(offset + nameLen)]
            offset += nameLen

            guard let channelName = String(bytes: nameBytes, encoding: .utf8) else {
                offset += 16
                continue
            }

            let bps = data[offset..<(offset + 8)].withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
            offset += 8
            let pps = data[offset..<(offset + 8)].withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
            offset += 8

            let key = TunnelSessionKey(remoteMachineId: machineId, channel: channelName)
            deliveredStats[key] = (bytesPerSecond: UInt64(littleEndian: bps), packetsPerSecond: UInt64(littleEndian: pps))
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
        case endpointOffer
    }

    let type: HandshakeType
    let channel: String?
    let sessionId: String?

    /// Number of extra endpoints the initiator is requesting (request only)
    let extraEndpointsRequested: Int?
    /// Extra endpoints offered by this side ("host:port" strings)
    let extraEndpoints: [String]?

    init(type: HandshakeType, channel: String? = nil, sessionId: String? = nil,
         extraEndpointsRequested: Int? = nil, extraEndpoints: [String]? = nil) {
        self.type = type
        self.channel = channel
        self.sessionId = sessionId
        self.extraEndpointsRequested = extraEndpointsRequested
        self.extraEndpoints = extraEndpoints
    }
}
