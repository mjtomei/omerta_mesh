// MeshNetwork.swift - Main entry point for the mesh network

import Foundation
import Logging
import NIOCore
import NIOPosix

/// The main entry point for the mesh network
/// This actor wraps all internal components and provides a clean public API
public actor MeshNetwork: ChannelProvider {
    // MARK: - Properties

    /// Our cryptographic identity
    public let identity: IdentityKeypair

    /// Our peer ID (derived from identity public key)
    public var peerId: PeerId {
        identity.peerId
    }

    /// Our machine ID (identifies this physical machine)
    public var machineId: MachineId {
        get async {
            await meshNode?.machineId ?? ""
        }
    }

    /// Configuration
    public let config: MeshConfig

    /// Current state
    public private(set) var state: MeshNetworkState = .stopped

    /// Event publisher for subscribers
    private let eventPublisher = MeshEventPublisher()

    /// Connection tracker
    private let connectionTracker: DirectConnectionTracker

    /// Network store for persistence
    private let networkStore: NetworkStore

    /// Internal mesh node
    private var meshNode: MeshNode?

    /// Event logger for persistent event storage
    private var eventLogger: MeshEventLogger?

    /// Detected NAT type
    private var natType: NATType = .unknown

    /// Public endpoint from STUN
    private var publicEndpoint: Endpoint?

    /// Logger
    private let logger: Logger

    /// Event loop group
    private var eventLoopGroup: EventLoopGroup?
    private var ownsEventLoopGroup: Bool = false

    /// Retry configuration for network operations
    public var retryConfig: RetryConfig = .network

    /// Optional crypto process pool for offloading ChaCha20-Poly1305 operations
    private var cryptoPool: CryptoProcessPool?

    /// Optional signature process pool for offloading Ed25519 verification
    private var signaturePool: SignatureProcessPool?

    // MARK: - Initialization

    /// Create a new mesh network with a cryptographic identity
    /// - Parameters:
    ///   - identity: Our cryptographic identity (keypair)
    ///   - config: Network configuration (must include encryption key)
    ///   - networkStore: Store for network memberships (defaults to standard location)
    public init(identity: IdentityKeypair, config: MeshConfig, networkStore: NetworkStore? = nil) {
        self.identity = identity
        self.config = config
        self.connectionTracker = DirectConnectionTracker(staleThreshold: config.recentContactMaxAge)
        self.networkStore = networkStore ?? NetworkStore.defaultStore()
        self.logger = Logger(label: "io.omerta.mesh.network")
    }

    /// Create a new mesh network with auto-generated identity
    /// - Parameter config: Network configuration (must include encryption key)
    /// - Parameter networkStore: Store for network memberships (defaults to standard location)
    public init(config: MeshConfig, networkStore: NetworkStore? = nil) {
        self.identity = IdentityKeypair()
        self.config = config
        self.connectionTracker = DirectConnectionTracker(staleThreshold: config.recentContactMaxAge)
        self.networkStore = networkStore ?? NetworkStore.defaultStore()
        self.logger = Logger(label: "io.omerta.mesh.network")
    }

    // MARK: - Process Pools

    /// Enable crypto process pool for offloading ChaCha20-Poly1305 chunk operations.
    /// Must be called before start(). Only functional on Linux.
    /// - Parameter workerCount: Number of worker processes (default: processor count)
    public func enableCryptoPool(workerCount: Int = ProcessInfo.processInfo.processorCount) throws {
        guard state == .stopped else { return }
        self.cryptoPool = try CryptoProcessPool(workerCount: workerCount)
    }

    /// Enable signature process pool for offloading Ed25519 verification.
    /// Must be called before start(). Only functional on Linux.
    /// - Parameter workerCount: Number of worker processes (default: 2)
    public func enableSignaturePool(workerCount: Int = 2) throws {
        guard state == .stopped else { return }
        self.signaturePool = try SignatureProcessPool(workerCount: workerCount)
    }

    // MARK: - Lifecycle

    /// Start the mesh network
    public func start() async throws {
        guard state == .stopped else {
            throw MeshError.alreadyStarted
        }

        state = .starting
        logger.info("Starting mesh network", metadata: ["peerId": "\(peerId.prefix(16))..."])

        do {
            // Validate configuration
            try config.validate()

            // Create event loop group
            let elg = MultiThreadedEventLoopGroup(numberOfThreads: 2)
            self.eventLoopGroup = elg
            self.ownsEventLoopGroup = true

            // NAT type will be detected from peer observations after connecting to bootstrap peers
            state = .detectingNAT
            self.natType = .unknown

            // Create internal mesh node
            let nodeConfig = MeshNode.Config(
                encryptionKey: config.encryptionKey,
                port: UInt16(config.port),
                targetRelays: config.targetRelayCount,
                maxRelays: config.maxRelayCount,
                canRelay: config.canRelay,
                canCoordinateHolePunch: config.canCoordinateHolePunch,
                keepaliveInterval: config.keepaliveInterval,
                connectionTimeout: config.connectionTimeout,
                maxCachedPeers: config.maxCachedPeers,
                peerCacheTTL: config.peerCacheTTL,
                cacheCleanupInterval: config.cacheCleanupInterval,
                recentContactMaxAge: config.recentContactMaxAge,
                freshnessQueryInterval: config.freshnessQueryInterval,
                holePunchTimeout: config.holePunchTimeout,
                holePunchProbeCount: config.holePunchProbeCount,
                holePunchProbeInterval: config.holePunchProbeInterval,
                endpointValidationMode: config.allowLocalhost ? .allowAll : .permissive,
                forceRelayOnly: config.forceRelayOnly
            )

            // Create event logger if enabled
            if config.enableEventLogging {
                self.eventLogger = try? MeshEventLogger(logDir: config.eventLogDir)
            }

            let node = try MeshNode(identity: identity, config: nodeConfig, eventLogger: eventLogger, cryptoPool: cryptoPool, signaturePool: signaturePool)
            self.meshNode = node

            // Start the node
            try await node.start(natType: natType)

            // Apply pending channel handlers
            await applyPendingChannelHandlers(to: node)

            // Connect to bootstrap peers
            state = .bootstrapping
            await connectToBootstrapPeers()

            // Wait for bootstrap pong responses (up to 2 seconds, or until we have 2 observations)
            let observationCount = await meshNode?.waitForBootstrapObservations(minimum: 2, timeout: 2.0) ?? 0
            logger.debug("Received \(observationCount) endpoint observations from bootstrap peers")

            // Detect NAT type from peer observations (after bootstrap pongs)
            await detectNATFromPeers()

            state = .running
            await eventPublisher.publish(.started(localPeerId: peerId))
            await eventPublisher.publish(.natDetected(type: natType, publicEndpoint: publicEndpoint))

            logger.info("Mesh network started", metadata: [
                "natType": "\(natType.rawValue)",
                "publicEndpoint": "\(publicEndpoint ?? "none")"
            ])

        } catch {
            state = .stopped
            await cleanup()
            throw error
        }
    }

    /// Stop the mesh network
    public func stop() async {
        guard state != .stopped else { return }

        logger.info("Stopping mesh network")
        state = .stopping

        await cleanup()

        state = .stopped
        await eventPublisher.publish(.stopped)
        await eventPublisher.finish()

        logger.info("Mesh network stopped")
    }

    private func cleanup() async {
        if let node = meshNode {
            await node.stop()
            meshNode = nil
        }

        cryptoPool?.shutdown()
        cryptoPool = nil
        signaturePool?.shutdown()
        signaturePool = nil

        if ownsEventLoopGroup, let elg = eventLoopGroup {
            try? await elg.shutdownGracefully()
            eventLoopGroup = nil
            ownsEventLoopGroup = false
        }
    }

    // MARK: - Event Subscription

    /// Subscribe to mesh events
    public func events() async -> MeshEventStream {
        await eventPublisher.subscribe()
    }

    // MARK: - Peer Operations

    /// Connect to a peer
    /// - Parameter peerId: The peer's ID
    /// - Returns: The established connection
    public func connect(to targetPeerId: PeerId) async throws -> DirectConnection {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }

        // Check if we already have a connection
        if let existing = await connectionTracker.getConnection(for: targetPeerId) {
            return existing
        }

        // Try to get peer info from cache
        guard let peerInfo = await node.getCachedPeer(targetPeerId) else {
            throw MeshError.peerNotFound(peerId: targetPeerId)
        }

        // Determine connection method based on NAT types
        let targetNATType = peerInfo.natType

        // When forceRelayOnly is enabled, skip direct and hole punch attempts
        if config.forceRelayOnly {
            logger.info("forceRelayOnly: Skipping direct/holepunch for \(targetPeerId.prefix(16))..., using relay")

            if let relayId = await node.getConnectedRelays().first {
                let connection = DirectConnection(
                    peerId: targetPeerId,
                    endpoint: peerInfo.endpoint,
                    isDirect: false,
                    relayPeerId: relayId,
                    natType: targetNATType,
                    method: .relay
                )
                await connectionTracker.setConnection(connection)
                await eventPublisher.publish(.peerConnected(peerId: targetPeerId, endpoint: peerInfo.endpoint, isDirect: false))
                return connection
            }

            throw MeshError.noRelaysAvailable
        }

        // Normal flow: If we have an endpoint (e.g., from bootstrap), try direct connection first
        // This works for LAN connections even when NAT type is unknown
        if !peerInfo.endpoint.isEmpty {
            logger.debug("Trying direct connection to \(targetPeerId) at \(peerInfo.endpoint)")

            // Send a ping to verify the connection works
            let pingSuccess = await node.sendPing(to: targetPeerId)
            if pingSuccess {
                let connection = DirectConnection(
                    peerId: targetPeerId,
                    endpoint: peerInfo.endpoint,
                    isDirect: true,
                    natType: targetNATType,
                    method: .discovery
                )
                await connectionTracker.setConnection(connection)
                await eventPublisher.publish(.directConnectionEstablished(peerId: targetPeerId, endpoint: peerInfo.endpoint))
                return connection
            }
            logger.debug("Direct ping to \(targetPeerId) failed, trying hole punch")
        }

        // Try hole punching if direct failed or NAT types suggest we need it
        let holePunchResult = await node.establishDirectConnection(to: targetPeerId)
        if case .success(let endpoint, let rtt) = holePunchResult {
            let rttMs = rtt * 1000.0
            let connection = DirectConnection(
                peerId: targetPeerId,
                endpoint: endpoint,
                isDirect: true,
                natType: targetNATType,
                rttMs: rttMs,
                method: .holePunch
            )
            await connectionTracker.setConnection(connection)
            await eventPublisher.publish(.holePunchSucceeded(peerId: targetPeerId, endpoint: endpoint, rttMs: rttMs))
            return connection
        }

        // Fall back to relay
        if let relayId = await node.getConnectedRelays().first {
            let connection = DirectConnection(
                peerId: targetPeerId,
                endpoint: peerInfo.endpoint,
                isDirect: false,
                relayPeerId: relayId,
                natType: targetNATType,
                method: .relay
            )
            await connectionTracker.setConnection(connection)
            await eventPublisher.publish(.peerConnected(peerId: targetPeerId, endpoint: peerInfo.endpoint, isDirect: false))
            return connection
        }

        throw MeshError.peerUnreachable(peerId: targetPeerId)
    }

    /// Disconnect from a peer
    public func disconnect(from peerId: PeerId) async {
        await connectionTracker.removeConnection(for: peerId)
        await eventPublisher.publish(.peerDisconnected(peerId: peerId, reason: .peerClosed))
    }

    /// Get connection to a peer
    public func connection(to peerId: PeerId) async -> DirectConnection? {
        await connectionTracker.getConnection(for: peerId)
    }

    /// Get all active connections
    public func activeConnections() async -> [DirectConnection] {
        await connectionTracker.activeConnections
    }

    // MARK: - Messaging

    /// Ping a peer and get detailed gossip results
    /// - Parameters:
    ///   - targetPeerId: The peer to ping
    ///   - timeout: Timeout in seconds
    ///   - requestFullList: If true, request the peer's full peer list (for bootstrap/reconnection)
    /// - Returns: PingResult with latency and gossip info, or nil if failed
    public func ping(_ targetPeerId: PeerId, timeout: TimeInterval = 3.0, requestFullList: Bool = false) async -> MeshNode.PingResult? {
        guard state == .running, let node = meshNode else {
            return nil
        }
        return await node.sendPingWithDetails(to: targetPeerId, timeout: timeout, requestFullList: requestFullList)
    }

    /// Ping a specific machine by MachineId. Use this when the peer has multiple machines
    /// (e.g. same user on laptop + desktop).
    /// - Parameters:
    ///   - machineId: The machine to ping
    ///   - timeout: Timeout in seconds
    ///   - requestFullList: If true, request the peer's full peer list (for bootstrap/reconnection)
    /// - Returns: PingResult with latency and gossip info, or nil if failed
    public func ping(machineId: MachineId, timeout: TimeInterval = 3.0, requestFullList: Bool = false) async -> MeshNode.PingResult? {
        guard state == .running, let node = meshNode else {
            return nil
        }
        return await node.sendPingWithDetails(toMachine: machineId, timeout: timeout, requestFullList: requestFullList)
    }

    // MARK: - Channel-based Messaging

    /// Pending channel handlers (registered before node is started)
    private var pendingChannelHandlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]

    /// Register a handler for a channel
    /// Messages arriving before handler registration are queued and delivered when handler is registered
    /// - Parameters:
    ///   - channel: Channel name (max 64 chars, alphanumeric/-/_ only)
    ///   - handler: Async handler that receives (fromMachineId, data). Use machinePeerRegistry to look up peerId if needed.
    /// - Throws: MeshError if channel name is invalid
    public func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        // Validate channel name
        guard ChannelUtils.isValid(channel) else {
            throw MeshError.sendFailed(reason: "Invalid channel '\(channel)': must be max 64 chars, alphanumeric/-/_ only")
        }

        if let node = meshNode {
            // Node is running - register directly
            try await node.onChannel(channel, handler: handler)
        } else {
            // Node not started - save for later
            pendingChannelHandlers[channel] = handler
        }
    }

    /// Unregister a handler for a channel
    /// - Parameter channel: Channel name to stop listening on
    public func offChannel(_ channel: String) async {
        pendingChannelHandlers.removeValue(forKey: channel)
        if let node = meshNode {
            await node.offChannel(channel)
        }
    }

    /// Send data on a channel to a peer
    /// Uses automatic NAT-aware routing (IPv6 > direct > relay fallback)
    /// When a peer has multiple machines, this sends to all of them.
    /// - Parameters:
    ///   - data: Data to send
    ///   - peerId: Target peer ID
    ///   - channel: Channel name
    /// - Throws: MeshError if not started, channel invalid, or send fails
    public func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }
        try await node.sendOnChannel(data, to: peerId, channel: channel)
    }

    /// Send data on a channel to a specific machine
    /// Use this when you need to target a specific machine (e.g., responding to a request).
    /// - Parameters:
    ///   - data: Data to send
    ///   - machineId: Target machine ID
    ///   - channel: Channel name
    /// - Throws: MeshError if not started, channel invalid, or send fails
    public func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }
        try await node.sendOnChannel(data, toMachine: machineId, channel: channel)
    }

    // MARK: - Buffered Channel Send

    /// Buffer data for batched sending on a channel to a peer.
    public func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }
        try await node.sendOnChannelBuffered(data, to: peerId, channel: channel)
    }

    /// Buffer data for batched sending on a channel to a specific machine.
    public func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }
        try await node.sendOnChannelBuffered(data, toMachine: machineId, channel: channel)
    }

    /// Flush all buffered data for a channel.
    public func flushChannel(_ channel: String) async throws {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }
        try await node.flushChannel(channel)
    }

    /// Register a handler with a batch config override.
    public func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        guard ChannelUtils.isValid(channel) else {
            throw MeshError.sendFailed(reason: "Invalid channel '\(channel)': must be max 64 chars, alphanumeric/-/_ only")
        }

        if let node = meshNode {
            try await node.onChannel(channel, batchConfig: batchConfig, handler: handler)
        } else {
            pendingChannelHandlers[channel] = handler
        }
    }

    // MARK: - Batch Monitors

    /// Registered batch monitors
    private var batchMonitors: [any BatchMonitor] = []

    /// Register a batch monitor for dynamic parameter adjustment.
    public func registerBatchMonitor(_ monitor: any BatchMonitor) async {
        batchMonitors.append(monitor)
        await meshNode?.registerBatchMonitor(monitor)
    }

    /// Unregister a batch monitor.
    public func unregisterBatchMonitor(_ monitor: any BatchMonitor) async {
        batchMonitors.removeAll { ($0 as AnyObject) === (monitor as AnyObject) }
        await meshNode?.unregisterBatchMonitor(monitor)
    }

    /// Access the machine-peer registry for looking up peer identities from machine IDs
    /// Returns nil if the network is not started.
    public var machinePeerRegistry: MachinePeerRegistry? {
        get async {
            meshNode?.machinePeerRegistry
        }
    }

    /// Apply pending channel handlers when node starts
    private func applyPendingChannelHandlers(to node: MeshNode) async {
        for (channel, handler) in pendingChannelHandlers {
            try? await node.onChannel(channel, handler: handler)
        }
    }

    // MARK: - Peer Discovery

    /// Discover peers from bootstrap nodes
    public func discoverPeers() async throws {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }

        await node.requestPeers()
    }

    /// Add a peer endpoint manually
    public func addPeer(_ peerId: PeerId, endpoint: Endpoint) async {
        guard let node = meshNode else { return }

        await node.updatePeerEndpoint(peerId, endpoint: endpoint)
        await eventPublisher.publish(.peerDiscovered(peerId: peerId, endpoint: endpoint, viaBootstrap: false))
    }

    /// Get known peers
    public func knownPeers() async -> [PeerId] {
        guard let node = meshNode else { return [] }
        return await node.getCachedPeerIds()
    }

    /// Get known peers with full info (including endpoints)
    public func knownPeersWithInfo() async -> [MeshNode.CachedPeerInfo] {
        guard let node = meshNode else { return [] }
        let peerIds = await node.getCachedPeerIds()
        var peers: [MeshNode.CachedPeerInfo] = []
        for peerId in peerIds {
            if let info = await node.getCachedPeer(peerId) {
                peers.append(info)
            }
        }
        return peers
    }

    // MARK: - Relay Operations

    /// Get connected relays
    public func connectedRelays() async -> [PeerId] {
        guard let node = meshNode else { return [] }
        return await node.getConnectedRelays()
    }

    /// Request relay services from a peer
    public func requestRelay(from relayId: PeerId, forTarget targetPeerId: PeerId) async throws {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }

        let sessionId = UUID().uuidString
        try await node.sendToPeer(MeshMessage.relayRequest(targetPeerId: targetPeerId, sessionId: sessionId), peerId: relayId)
    }

    // MARK: - Hole Punching

    /// Attempt to establish a direct connection via hole punching
    public func holePunch(to targetPeerId: PeerId) async throws -> DirectConnection {
        guard state == .running, let node = meshNode else {
            throw MeshError.notStarted
        }

        await eventPublisher.publish(.holePunchStarted(peerId: targetPeerId))

        let result = await node.establishDirectConnection(to: targetPeerId)

        switch result {
        case .success(let endpoint, let rtt):
            let rttMs = rtt * 1000.0
            let connection = DirectConnection(
                peerId: targetPeerId,
                endpoint: endpoint,
                isDirect: true,
                natType: .unknown,
                rttMs: rttMs,
                method: .holePunch
            )

            await connectionTracker.setConnection(connection)
            await eventPublisher.publish(.holePunchSucceeded(peerId: targetPeerId, endpoint: endpoint, rttMs: rttMs))
            await eventPublisher.publish(.directConnectionEstablished(peerId: targetPeerId, endpoint: endpoint))

            return connection

        case .failed(let reason):
            await eventPublisher.publish(.holePunchFailed(peerId: targetPeerId, reason: reason))
            throw reason.asMeshError(for: targetPeerId)
        }
    }

    // MARK: - Status

    /// Current NAT type
    public var currentNATType: NATType {
        natType
    }

    /// Current public endpoint
    public var currentPublicEndpoint: Endpoint? {
        publicEndpoint
    }

    /// Number of known peers
    public func peerCount() async -> Int {
        guard let node = meshNode else { return 0 }
        return await node.getCachedPeerIds().count
    }

    /// Number of active connections
    public func connectionCount() async -> Int {
        await connectionTracker.count
    }

    /// Number of direct connections
    public func directConnectionCount() async -> Int {
        await connectionTracker.directCount
    }

    /// Network statistics
    public func statistics() async -> MeshStatistics {
        guard let node = meshNode else {
            return MeshStatistics()
        }

        return MeshStatistics(
            peerCount: await node.getCachedPeerIds().count,
            connectionCount: await connectionTracker.count,
            directConnectionCount: await connectionTracker.directCount,
            relayCount: await node.getConnectedRelays().count,
            natType: natType,
            publicEndpoint: publicEndpoint,
            uptime: state == .running ? Date().timeIntervalSince(Date()) : 0
        )
    }

    // MARK: - Network Management

    /// Join a network using an invite link
    /// - Parameters:
    ///   - inviteLink: The invite link (omerta://join/...)
    ///   - name: Optional custom name for the network
    /// - Returns: The joined network
    public func joinNetwork(inviteLink: String, name: String? = nil) async throws -> Network {
        let networkKey = try NetworkKey.decode(from: inviteLink)
        return try await joinNetwork(key: networkKey, name: name)
    }

    /// Join a network using a NetworkKey
    /// - Parameters:
    ///   - key: The network key
    ///   - name: Optional custom name for the network
    /// - Returns: The joined network
    public func joinNetwork(key: NetworkKey, name: String? = nil) async throws -> Network {
        // Load existing networks first
        try await networkStore.load()

        // Join the network
        let network = try await networkStore.join(key, name: name)

        logger.info("Joined network: \(network.name)", metadata: ["networkId": "\(network.id)"])

        // Add bootstrap peers from the network key and announce to them
        for peer in key.bootstrapPeers {
            let parts = peer.split(separator: "@", maxSplits: 1)
            if parts.count == 2 {
                let bootstrapPeerId = String(parts[0])
                let endpoint = String(parts[1])
                await meshNode?.updatePeerEndpoint(bootstrapPeerId, endpoint: endpoint)
                await eventPublisher.publish(.peerDiscovered(peerId: bootstrapPeerId, endpoint: endpoint, viaBootstrap: true))

                // Send announcement to introduce ourselves
                await meshNode?.announceTo(endpoint: endpoint)
            }
        }

        // Brief delay to allow announcements to be processed
        try? await Task.sleep(nanoseconds: 100_000_000)  // 100ms

        // Request peers from bootstrap nodes (now accepted since we're announced)
        await meshNode?.requestPeers()

        await eventPublisher.publish(.networkJoined(network: network))

        return network
    }

    /// Leave a network
    /// - Parameter networkId: The network ID to leave
    public func leaveNetwork(id networkId: String) async throws {
        try await networkStore.load()
        try await networkStore.leave(networkId)

        logger.info("Left network", metadata: ["networkId": "\(networkId)"])
        await eventPublisher.publish(.networkLeft(networkId: networkId))
    }

    /// Get all joined networks
    public func networks() async -> [Network] {
        try? await networkStore.load()
        return await networkStore.allNetworks()
    }

    /// Get a specific network by ID
    public func network(id: String) async -> Network? {
        try? await networkStore.load()
        return await networkStore.network(id: id)
    }

    /// Create a new network
    /// - Parameters:
    ///   - name: Name for the network
    ///   - bootstrapEndpoint: Optional endpoint for this node as bootstrap
    /// - Returns: The network key for sharing with others
    public func createNetwork(name: String, bootstrapEndpoint: String? = nil) async throws -> NetworkKey {
        var bootstrapPeers: [String] = []

        // Add ourselves as a bootstrap peer if endpoint provided
        if let endpoint = bootstrapEndpoint {
            bootstrapPeers.append("\(peerId)@\(endpoint)")
        } else if let publicEp = publicEndpoint {
            bootstrapPeers.append("\(peerId)@\(publicEp)")
        }

        // Generate network key
        let key = NetworkKey.generate(networkName: name, bootstrapPeers: bootstrapPeers)

        // Auto-join the network we created
        _ = try await joinNetwork(key: key, name: name)

        logger.info("Created network: \(name)", metadata: ["networkId": "\(key.deriveNetworkId())"])

        return key
    }

    // MARK: - Retry-Enabled Operations

    /// Connect to a peer with automatic retry
    /// - Parameters:
    ///   - peerId: The peer's ID
    ///   - retryConfig: Optional custom retry configuration
    /// - Returns: The established connection
    public func connectWithRetry(to targetPeerId: PeerId, retryConfig: RetryConfig? = nil) async throws -> DirectConnection {
        try await withRetry(
            config: retryConfig ?? self.retryConfig,
            operation: "connect to \(targetPeerId.prefix(8))...",
            shouldRetry: { error in
                guard let meshError = error as? MeshError else { return false }
                return meshError.shouldRetry
            }
        ) {
            try await self.connect(to: targetPeerId)
        }
    }

    /// Attempt hole punch with automatic retry
    /// - Parameters:
    ///   - peerId: Target peer ID
    ///   - retryConfig: Optional custom retry configuration
    /// - Returns: The established direct connection
    public func holePunchWithRetry(to targetPeerId: PeerId, retryConfig: RetryConfig? = nil) async throws -> DirectConnection {
        try await withRetry(
            config: retryConfig ?? .persistent,  // Hole punching benefits from more attempts
            operation: "hole punch to \(targetPeerId.prefix(8))...",
            shouldRetry: { error in
                guard let meshError = error as? MeshError else { return false }
                // Retry hole punch failures except for impossible cases
                switch meshError {
                case .holePunchFailed:
                    return true
                case .holePunchImpossible:
                    return false  // Both symmetric NAT, no point retrying
                default:
                    return meshError.shouldRetry
                }
            }
        ) {
            try await self.holePunch(to: targetPeerId)
        }
    }

    // MARK: - Private Methods

    /// Detect NAT type from peer endpoint observations
    private func detectNATFromPeers() async {
        guard let node = meshNode else { return }

        // Get prediction from the node's NATPredictor (populated by pong responses)
        let prediction = await node.getPredictedNATType()

        if prediction.type != .unknown {
            self.natType = prediction.type
            self.publicEndpoint = prediction.publicEndpoint

            logger.info("NAT prediction complete", metadata: [
                "type": "\(prediction.type.rawValue)",
                "endpoint": "\(prediction.publicEndpoint ?? "none")",
                "confidence": "\(prediction.confidence)"
            ])
        } else {
            logger.debug("NAT type not yet determined (confidence: \(prediction.confidence))")
            // Keep unknown type - will be updated as more observations come in
        }
    }

    /// Refresh NAT prediction from current observations
    public func refreshNATPrediction() async -> (type: NATType, publicEndpoint: String?, confidence: Int) {
        guard let node = meshNode else {
            return (type: .unknown, publicEndpoint: nil, confidence: 0)
        }

        let prediction = await node.getPredictedNATType()

        if prediction.type != .unknown {
            self.natType = prediction.type
            self.publicEndpoint = prediction.publicEndpoint
            await eventPublisher.publish(.natDetected(type: prediction.type, publicEndpoint: prediction.publicEndpoint))
        }

        return prediction
    }

    private func connectToBootstrapPeers() async {
        guard !config.bootstrapPeers.isEmpty else {
            logger.debug("No bootstrap peers configured")
            return
        }

        logger.info("Connecting to \(config.bootstrapPeers.count) bootstrap peer(s): \(config.bootstrapPeers)")

        // First, add all bootstrap peer endpoints
        var bootstrapPeerIds: [PeerId] = []
        for peer in config.bootstrapPeers {
            // Parse peer as "peerId@endpoint" or just "endpoint"
            let parts = peer.split(separator: "@", maxSplits: 1)
            if parts.count == 2 {
                let bootstrapPeerId = String(parts[0])
                let endpoint = String(parts[1])

                logger.info("Bootstrap: connecting to \(bootstrapPeerId) at \(endpoint)")

                await meshNode?.updatePeerEndpoint(bootstrapPeerId, endpoint: endpoint)
                await eventPublisher.publish(.peerDiscovered(
                    peerId: bootstrapPeerId,
                    endpoint: endpoint,
                    viaBootstrap: true
                ))
                bootstrapPeerIds.append(bootstrapPeerId)
            } else {
                logger.warning("Bootstrap: invalid peer format '\(peer)' - expected peerId@endpoint")
            }
        }

        // Send ping to each bootstrap peer using sendPing which establishes keepalive
        // This is done in parallel since sendPing handles its own timeout
        for peerId in bootstrapPeerIds {
            logger.info("Bootstrap: sending ping to \(peerId.prefix(16))...")
            // sendPing uses sendPingWithDetails which adds to keepalive monitoring on success
            _ = await meshNode?.sendPing(to: peerId)
        }
    }
}

// MARK: - State

/// State of the mesh network
public enum MeshNetworkState: String, Sendable, Equatable {
    case stopped
    case starting
    case detectingNAT
    case bootstrapping
    case running
    case stopping

    public var isActive: Bool {
        self == .running
    }
}

// MARK: - Statistics

/// Network statistics
public struct MeshStatistics: Sendable {
    public let peerCount: Int
    public let connectionCount: Int
    public let directConnectionCount: Int
    public let relayCount: Int
    public let natType: NATType
    public let publicEndpoint: Endpoint?
    public let uptime: TimeInterval

    public init(
        peerCount: Int = 0,
        connectionCount: Int = 0,
        directConnectionCount: Int = 0,
        relayCount: Int = 0,
        natType: NATType = .unknown,
        publicEndpoint: Endpoint? = nil,
        uptime: TimeInterval = 0
    ) {
        self.peerCount = peerCount
        self.connectionCount = connectionCount
        self.directConnectionCount = directConnectionCount
        self.relayCount = relayCount
        self.natType = natType
        self.publicEndpoint = publicEndpoint
        self.uptime = uptime
    }
}

// MARK: - Convenience Extensions

extension MeshNetwork {
    /// Create a mesh network with a randomly generated identity
    public static func create(config: MeshConfig) -> MeshNetwork {
        MeshNetwork(config: config)
    }

    /// Create a mesh network for a relay node
    public static func createRelay(
        identity: IdentityKeypair,
        encryptionKey: Data,
        bootstrapPeers: [String] = [],
        port: Int = 0
    ) -> MeshNetwork {
        var config = MeshConfig.relayNode(encryptionKey: encryptionKey, bootstrapPeers: bootstrapPeers)
        config.port = port
        return MeshNetwork(identity: identity, config: config)
    }

    /// Create a mesh network for a server
    public static func createServer(
        identity: IdentityKeypair,
        encryptionKey: Data,
        bootstrapPeers: [String] = [],
        port: Int = 0
    ) -> MeshNetwork {
        var config = MeshConfig.server(encryptionKey: encryptionKey, bootstrapPeers: bootstrapPeers)
        config.port = port
        return MeshNetwork(identity: identity, config: config)
    }
}
