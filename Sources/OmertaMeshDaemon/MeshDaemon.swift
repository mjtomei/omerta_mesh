// MeshDaemon.swift - Main mesh daemon actor
//
// The core daemon that owns the MeshNetwork instance and exposes it via IPC.

import Foundation
import OmertaMesh
import Logging

// MARK: - Mesh Daemon

/// Main mesh daemon actor
public actor MeshDaemon {
    /// Daemon state
    public enum State: Sendable {
        case stopped
        case starting
        case running
        case stopping
    }

    private let config: MeshDaemonConfig
    private let logger: Logger
    private var state: State = .stopped
    private var startTime: Date?

    // Core components
    private var meshNetwork: MeshNetwork?
    private var identity: IdentityKeypair?
    private var controlSocket: ControlSocketServer?
    private var dataSocket: DataSocketServer?
    private var channelBridge: ChannelBridge?

    // Network store for persistence
    private var networkStore: NetworkStore?

    /// Create a new mesh daemon
    /// - Parameter config: Daemon configuration
    public init(config: MeshDaemonConfig) {
        self.config = config
        self.logger = Logger(label: "io.omerta.meshd")
    }

    // MARK: - Lifecycle

    /// Start the daemon
    public func start() async throws {
        guard state == .stopped else {
            throw MeshDaemonError.alreadyRunning
        }

        state = .starting
        logger.info("Starting mesh daemon", metadata: ["networkId": "\(config.networkId)"])

        do {
            // Validate configuration
            try config.validate()

            // Load or generate identity
            identity = try loadOrGenerateIdentity()
            logger.info("Loaded identity", metadata: ["peerId": "\(identity!.peerId)"])

            // Load network from store
            networkStore = NetworkStore.defaultStore()
            try await networkStore?.load()

            guard let network = await networkStore?.network(id: config.networkId) else {
                throw MeshDaemonError.networkNotFound(config.networkId)
            }

            // Build mesh config from network key
            var meshConfig = MeshConfig(networkKey: network.key)
            meshConfig.port = config.port
            meshConfig.canRelay = config.canRelay
            meshConfig.canCoordinateHolePunch = config.canCoordinateHolePunch
            meshConfig.enableEventLogging = config.enableEventLogging
            meshConfig.eventLogDir = config.eventLogDir

            // Add configured bootstrap peers (merge with network key bootstrap peers)
            let allBootstrapPeers = Set(config.bootstrapPeers + network.key.bootstrapPeers)

            // Fix bootstrap ports if needed (use our port for self-references)
            let fixedBootstrapPeers = fixBootstrapPorts(
                Array(allBootstrapPeers),
                myPeerId: identity!.peerId,
                port: config.port
            )

            meshConfig = MeshConfig(
                encryptionKey: network.key.networkKey,
                port: config.port,
                canRelay: config.canRelay,
                canCoordinateHolePunch: config.canCoordinateHolePunch,
                bootstrapPeers: fixedBootstrapPeers,
                enableEventLogging: config.enableEventLogging,
                eventLogDir: config.eventLogDir
            )

            // Create mesh network
            let mesh = MeshNetwork(identity: identity!, config: meshConfig, networkStore: networkStore)
            meshNetwork = mesh

            // Create channel bridge
            let bridge = ChannelBridge(meshNetwork: mesh)
            channelBridge = bridge

            // Start mesh network
            try await mesh.start()
            logger.info("Mesh network started")

            // Start control socket
            let controlPath = DaemonSocketPaths.meshDaemonControl(networkId: config.networkId)
            let control = ControlSocketServer(socketPath: controlPath)
            controlSocket = control

            try await control.start { [weak self] (command: MeshDaemonCommand, client: ClientConnection) async -> MeshDaemonResponse in
                guard let self = self else { return .error("Daemon shutting down") }
                return await self.handleCommand(command, from: client)
            }
            logger.info("Control socket started", metadata: ["path": "\(controlPath)"])

            // Start data socket for tunnel packets
            let dataPath = DaemonSocketPaths.meshDaemonData(networkId: config.networkId)
            let data = DataSocketServer(socketPath: dataPath)
            dataSocket = data
            try await data.start()
            logger.info("Data socket started", metadata: ["path": "\(dataPath)"])

            // Write PID file if configured
            if let pidPath = config.pidFile ?? MeshDaemonConfig.defaultPidFilePath(networkId: config.networkId) as String? {
                writePidFile(pidPath)
            }

            startTime = Date()
            state = .running
            logger.info("Mesh daemon started successfully")

        } catch {
            state = .stopped
            await cleanup()
            throw error
        }
    }

    /// Stop the daemon
    public func stop() async {
        guard state == .running else { return }

        state = .stopping
        logger.info("Stopping mesh daemon")

        await cleanup()

        // Remove PID file
        if let pidPath = config.pidFile ?? MeshDaemonConfig.defaultPidFilePath(networkId: config.networkId) as String? {
            try? FileManager.default.removeItem(atPath: pidPath)
        }

        state = .stopped
        startTime = nil
        logger.info("Mesh daemon stopped")
    }

    private func cleanup() async {
        // Stop sockets first
        if let control = controlSocket {
            await control.stop()
            controlSocket = nil
        }

        if let data = dataSocket {
            await data.stop()
            dataSocket = nil
        }

        // Stop mesh network
        if let mesh = meshNetwork {
            await mesh.stop()
            meshNetwork = nil
        }

        channelBridge = nil
    }

    // MARK: - Command Handling

    private func handleCommand(_ command: MeshDaemonCommand, from client: ClientConnection) async -> MeshDaemonResponse {
        switch command {
        case .base(let baseCommand):
            return await handleBaseCommand(baseCommand)

        case .peers:
            return await handlePeers()

        case .ping(let peerId, let timeout, let requestFullList):
            return await handlePing(peerId: peerId, timeout: timeout, requestFullList: requestFullList)

        case .connect(let peerId, let timeout):
            return await handleConnect(peerId: peerId, timeout: timeout)

        case .networkList:
            return await handleNetworkList()

        case .networkShow(let networkId):
            return await handleNetworkShow(networkId: networkId)

        case .sendMessage(let peerId, let content, let requestReceipt, let timeout):
            return await handleSendMessage(peerId: peerId, content: content, requestReceipt: requestReceipt, timeout: timeout)

        case .healthCheck(let peerId, let timeout):
            return await handleHealthCheck(peerId: peerId, timeout: timeout)

        case .negotiateNetwork(let peerId, let networkName, let timeout):
            return await handleNegotiateNetwork(peerId: peerId, networkName: networkName, timeout: timeout)

        case .shareInvite(let peerId, let networkKey, let networkName, let timeout):
            return await handleShareInvite(peerId: peerId, networkKey: networkKey, networkName: networkName, timeout: timeout)

        case .registerChannel(let channel, let clientId):
            return await handleRegisterChannel(channel: channel, clientId: clientId, client: client)

        case .unregisterChannel(let channel, let clientId):
            return await handleUnregisterChannel(channel: channel, clientId: clientId)

        case .sendOnChannel(let channel, let peerId, let data):
            return await handleSendOnChannel(channel: channel, peerId: peerId, data: data)

        case .sendOnChannelToMachine(let channel, let machineId, let data):
            return await handleSendOnChannelToMachine(channel: channel, machineId: machineId, data: data)

        case .createTunnel(let peerId, let tunnelId):
            return await handleCreateTunnel(peerId: peerId, tunnelId: tunnelId)

        case .closeTunnel(let tunnelId):
            return await handleCloseTunnel(tunnelId: tunnelId)

        case .natInfo:
            return await handleNatInfo()
        }
    }

    // MARK: - Base Command Handlers

    private func handleBaseCommand(_ command: BaseDaemonCommand) async -> MeshDaemonResponse {
        switch command {
        case .status:
            return await handleStatus()

        case .shutdown(let graceful, let timeoutSeconds):
            return await handleShutdown(graceful: graceful, timeout: timeoutSeconds)
        }
    }

    private func handleStatus() async -> MeshDaemonResponse {
        guard let mesh = meshNetwork else {
            return .base(.status(DaemonStatusData(
                isRunning: false,
                daemonType: "meshd",
                networkId: config.networkId
            )))
        }

        let stats = await mesh.statistics()
        let uptime = startTime.map { Date().timeIntervalSince($0) }

        let status = DaemonStatusData(
            isRunning: state == .running,
            daemonType: "meshd",
            networkId: config.networkId,
            uptime: uptime,
            additionalInfo: [
                "peerId": await mesh.peerId,
                "natType": stats.natType.rawValue,
                "publicEndpoint": stats.publicEndpoint ?? "",
                "peerCount": "\(stats.peerCount)",
                "connectionCount": "\(stats.connectionCount)",
                "directConnectionCount": "\(stats.directConnectionCount)",
                "relayCount": "\(stats.relayCount)"
            ]
        )

        return .base(.status(status))
    }

    private func handleShutdown(graceful: Bool, timeout: Int) async -> MeshDaemonResponse {
        logger.info("Shutdown requested", metadata: ["graceful": "\(graceful)", "timeout": "\(timeout)"])

        // Schedule shutdown in background
        Task {
            if graceful {
                // Give connections time to close gracefully
                try? await Task.sleep(nanoseconds: UInt64(timeout) * 1_000_000_000)
            }
            await self.stop()
            // Exit the process after shutdown completes
            exit(0)
        }

        return .base(.shutdownAck(ShutdownAckData(
            accepted: true,
            estimatedSeconds: graceful ? timeout : 1
        )))
    }

    // MARK: - Peer Command Handlers

    private func handlePeers() async -> MeshDaemonResponse {
        guard let mesh = meshNetwork else {
            return .error("Mesh network not running")
        }

        let peers = await mesh.knownPeersWithInfo()
        let connections = await mesh.activeConnections()
        let connectionMap = Dictionary(uniqueKeysWithValues: connections.map { ($0.peerId, $0) })

        let peerData = peers.map { info in
            let connection = connectionMap[info.peerId]
            return PeerData(
                peerId: info.peerId,
                endpoint: info.endpoint,
                natType: info.natType.rawValue,
                lastSeen: info.lastSeen,
                isConnected: connection != nil,
                isDirect: connection?.isDirect ?? false
            )
        }

        return .peers(peerData)
    }

    private func handlePing(peerId: String, timeout: Int, requestFullList: Bool) async -> MeshDaemonResponse {
        guard let mesh = meshNetwork else {
            return .error("Mesh network not running")
        }

        let result = await mesh.ping(peerId, timeout: TimeInterval(timeout), requestFullList: requestFullList)

        if let result = result {
            return .pingResult(PingResultData(
                peerId: peerId,
                rttMs: Double(result.latencyMs),
                endpoint: result.endpoint,
                natType: nil,  // NAT type not available in ping result
                peersDiscovered: result.receivedPeers.count
            ))
        } else {
            return .pingResult(nil)
        }
    }

    private func handleConnect(peerId: String, timeout: Int) async -> MeshDaemonResponse {
        guard let mesh = meshNetwork else {
            return .error("Mesh network not running")
        }

        do {
            let connection = try await mesh.connect(to: peerId)
            return .connectResult(ConnectResultData(
                success: true,
                peerId: peerId,
                endpoint: connection.endpoint,
                isDirect: connection.isDirect,
                method: connection.method.rawValue,
                rttMs: connection.rttMs
            ))
        } catch {
            return .connectResult(ConnectResultData(
                success: false,
                peerId: peerId,
                error: error.localizedDescription
            ))
        }
    }

    // MARK: - Network Command Handlers

    private func handleNetworkList() async -> MeshDaemonResponse {
        guard let store = networkStore else {
            return .networkList([])
        }

        let networks = await store.allNetworks()
        let networkData = networks.map { network in
            NetworkInfoData(
                id: network.id,
                name: network.name,
                isActive: network.isActive,
                joinedAt: network.joinedAt,
                bootstrapPeerCount: network.key.bootstrapPeers.count
            )
        }

        return .networkList(networkData)
    }

    private func handleNetworkShow(networkId: String) async -> MeshDaemonResponse {
        guard let store = networkStore else {
            return .networkShow(nil)
        }

        guard let network = await store.network(id: networkId) else {
            return .networkShow(nil)
        }

        var peerCount = 0
        var connectedPeerCount = 0

        if let mesh = meshNetwork {
            peerCount = await mesh.peerCount()
            connectedPeerCount = await mesh.connectionCount()
        }

        let inviteLink: String
        do {
            inviteLink = try network.key.encode()
        } catch {
            return .error("Failed to encode invite link: \(error)")
        }

        let detail = NetworkDetailData(
            id: network.id,
            name: network.name,
            isActive: network.isActive,
            joinedAt: network.joinedAt,
            bootstrapPeers: network.key.bootstrapPeers,
            inviteLink: inviteLink,
            peerCount: peerCount,
            connectedPeerCount: connectedPeerCount
        )

        return .networkShow(detail)
    }

    // MARK: - Service Command Handlers

    private func handleSendMessage(peerId: String, content: Data, requestReceipt: Bool, timeout: Int) async -> MeshDaemonResponse {
        guard let mesh = meshNetwork else {
            return .error("Mesh network not running")
        }

        do {
            try await mesh.sendOnChannel(content, to: peerId, channel: "message")
            return .sendMessageResult(SendMessageResultData(
                success: true,
                messageId: UUID().uuidString,
                deliveryConfirmed: false  // Fire and forget for now
            ))
        } catch {
            return .sendMessageResult(SendMessageResultData(
                success: false,
                error: error.localizedDescription
            ))
        }
    }

    private func handleHealthCheck(peerId: String, timeout: Int) async -> MeshDaemonResponse {
        guard let mesh = meshNetwork else {
            return .error("Mesh network not running")
        }

        let result = await mesh.ping(peerId, timeout: TimeInterval(timeout))

        if let result = result {
            return .healthCheckResult(HealthCheckResultData(
                peerId: peerId,
                isHealthy: true,
                rttMs: Double(result.latencyMs),
                lastSeen: Date()
            ))
        } else {
            return .healthCheckResult(HealthCheckResultData(
                peerId: peerId,
                isHealthy: false,
                error: "Ping failed"
            ))
        }
    }

    private func handleNegotiateNetwork(peerId: String, networkName: String, timeout: Int) async -> MeshDaemonResponse {
        // TODO: Implement cloister-based network negotiation
        return .negotiateResult(NegotiateResultData(
            success: false,
            error: "Network negotiation not yet implemented"
        ))
    }

    private func handleShareInvite(peerId: String, networkKey: Data, networkName: String?, timeout: Int) async -> MeshDaemonResponse {
        // TODO: Implement invite sharing via cloister
        return .shareInviteResult(ShareInviteResultData(
            success: false,
            error: "Invite sharing not yet implemented"
        ))
    }

    // MARK: - Channel Command Handlers

    private func handleRegisterChannel(channel: String, clientId: String, client: ClientConnection) async -> MeshDaemonResponse {
        guard let bridge = channelBridge else {
            return .channelRegistered(success: false, error: "Channel bridge not available")
        }

        do {
            try await bridge.register(channel: channel, clientId: clientId, connection: client)
            return .channelRegistered(success: true, error: nil)
        } catch {
            return .channelRegistered(success: false, error: error.localizedDescription)
        }
    }

    private func handleUnregisterChannel(channel: String, clientId: String) async -> MeshDaemonResponse {
        guard let bridge = channelBridge else {
            return .channelUnregistered(success: false)
        }

        await bridge.unregister(channel: channel, clientId: clientId)
        return .channelUnregistered(success: true)
    }

    private func handleSendOnChannel(channel: String, peerId: String, data: Data) async -> MeshDaemonResponse {
        guard let bridge = channelBridge else {
            return .channelSendResult(success: false, error: "Channel bridge not available")
        }

        do {
            try await bridge.sendOnChannel(data, to: peerId, channel: channel)
            return .channelSendResult(success: true, error: nil)
        } catch {
            return .channelSendResult(success: false, error: error.localizedDescription)
        }
    }

    private func handleSendOnChannelToMachine(channel: String, machineId: String, data: Data) async -> MeshDaemonResponse {
        guard let bridge = channelBridge else {
            return .channelSendResult(success: false, error: "Channel bridge not available")
        }

        do {
            try await bridge.sendOnChannelToMachine(data, to: machineId, channel: channel)
            return .channelSendResult(success: true, error: nil)
        } catch {
            return .channelSendResult(success: false, error: error.localizedDescription)
        }
    }

    // MARK: - Tunnel Command Handlers

    private func handleCreateTunnel(peerId: String, tunnelId: String) async -> MeshDaemonResponse {
        guard let dataSocket = dataSocket else {
            return .tunnelCreated(tunnelId: tunnelId, success: false, error: "Data socket not available")
        }

        guard let uuid = UUID(uuidString: tunnelId) else {
            return .tunnelCreated(tunnelId: tunnelId, success: false, error: "Invalid tunnel ID format")
        }

        // Register tunnel handler
        await dataSocket.registerTunnel(uuid) { [weak self] tunnelId, packet in
            // Forward packet to peer via mesh network
            guard let self = self, let mesh = await self.meshNetwork else { return }
            // TODO: Implement proper tunnel forwarding
            try? await mesh.sendOnChannel(packet, to: peerId, channel: "tunnel-\(tunnelId)")
        }

        return .tunnelCreated(tunnelId: tunnelId, success: true, error: nil)
    }

    private func handleCloseTunnel(tunnelId: String) async -> MeshDaemonResponse {
        guard let dataSocket = dataSocket else {
            return .tunnelClosed(tunnelId: tunnelId, success: false)
        }

        guard let uuid = UUID(uuidString: tunnelId) else {
            return .tunnelClosed(tunnelId: tunnelId, success: false)
        }

        await dataSocket.unregisterTunnel(uuid)
        return .tunnelClosed(tunnelId: tunnelId, success: true)
    }

    // MARK: - NAT Command Handlers

    private func handleNatInfo() async -> MeshDaemonResponse {
        guard let mesh = meshNetwork else {
            return .error("Mesh network not running")
        }

        let stats = await mesh.statistics()

        return .natInfo(NATInfoData(
            natType: stats.natType.rawValue,
            publicEndpoint: stats.publicEndpoint,
            localPort: nil,
            isHolePunchable: stats.natType.isHolePunchable,
            canRelay: stats.natType.canRelay
        ))
    }

    // MARK: - Helper Methods

    /// Load or generate identity
    private func loadOrGenerateIdentity() throws -> IdentityKeypair {
        let identityPath = config.identityPath ?? MeshDaemonConfig.defaultIdentityPath

        let identityURL = URL(fileURLWithPath: identityPath)

        // Try to load existing identity
        if FileManager.default.fileExists(atPath: identityPath) {
            let data = try Data(contentsOf: identityURL)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let stored = try decoder.decode(StoredIdentity.self, from: data)
            return try IdentityKeypair(privateKeyBase64: stored.privateKey)
        }

        // Generate new identity
        let identity = IdentityKeypair()

        // Save it
        let stored = StoredIdentity(
            privateKey: identity.privateKeyBase64,
            createdAt: Date()
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(stored)

        // Create directory if needed
        try FileManager.default.createDirectory(
            at: identityURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        try data.write(to: identityURL)

        return identity
    }

    /// Fix bootstrap peer ports for self-references
    private func fixBootstrapPorts(_ peers: [String], myPeerId: String, port: Int) -> [String] {
        peers.map { peer in
            let parts = peer.split(separator: "@", maxSplits: 1)
            guard parts.count == 2 else { return peer }

            let peerId = String(parts[0])
            let endpoint = String(parts[1])

            // If this is our own peer ID, update the port
            if peerId == myPeerId && port > 0 {
                let endpointParts = endpoint.split(separator: ":")
                if endpointParts.count >= 1 {
                    let host = endpointParts.dropLast().joined(separator: ":")
                    return "\(peerId)@\(host):\(port)"
                }
            }

            return peer
        }
    }

    /// Write PID file
    private func writePidFile(_ path: String) {
        let pid = ProcessInfo.processInfo.processIdentifier
        try? String(pid).write(toFile: path, atomically: true, encoding: .utf8)
    }

    // MARK: - Status

    /// Current daemon state
    public var currentState: State {
        state
    }

    /// Uptime in seconds
    public var uptime: TimeInterval? {
        startTime.map { Date().timeIntervalSince($0) }
    }
}

// MARK: - Stored Identity

/// Stored identity format
private struct StoredIdentity: Codable {
    let privateKey: String  // Base64-encoded private key
    let createdAt: Date
}

// MARK: - Errors

/// Mesh daemon errors
public enum MeshDaemonError: Error, CustomStringConvertible {
    case alreadyRunning
    case notRunning
    case networkNotFound(String)
    case identityLoadFailed(String)
    case startupFailed(String)

    public var description: String {
        switch self {
        case .alreadyRunning:
            return "Daemon is already running"
        case .notRunning:
            return "Daemon is not running"
        case .networkNotFound(let id):
            return "Network not found: \(id)"
        case .identityLoadFailed(let reason):
            return "Failed to load identity: \(reason)"
        case .startupFailed(let reason):
            return "Startup failed: \(reason)"
        }
    }
}
