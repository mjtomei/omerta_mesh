// MeshNode.swift - Main mesh network node actor

import Foundation
import NIOCore
import NIOPosix
import Crypto
import Logging

/// A node in the mesh network
public actor MeshNode {
    // MARK: - Configuration

    /// Configuration for MeshNode
    public struct Config: Sendable {
        /// 256-bit symmetric key for message encryption (required)
        public let encryptionKey: Data

        /// Network ID derived from encryption key (used for storage scoping)
        /// This ensures each network has isolated persistent storage
        public var networkId: String {
            // Hash the encryption key and take first 16 hex chars for a readable ID
            let hash = SHA256.hash(data: encryptionKey)
            return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
        }

        public let port: UInt16
        public let targetRelays: Int
        public let maxRelays: Int
        public let canRelay: Bool
        public let canCoordinateHolePunch: Bool
        public let keepaliveInterval: TimeInterval
        public let connectionTimeout: TimeInterval
        public let maxCachedPeers: Int
        public let peerCacheTTL: TimeInterval
        public let cacheCleanupInterval: TimeInterval
        public let recentContactMaxAge: TimeInterval
        public let freshnessQueryInterval: TimeInterval
        public let holePunchTimeout: TimeInterval
        public let holePunchProbeCount: Int
        public let holePunchProbeInterval: TimeInterval

        /// Endpoint validation mode (default: strict for production)
        /// Use .permissive for LAN testing, .allowAll for localhost testing
        public let endpointValidationMode: EndpointValidator.ValidationMode

        /// Force all communication through relays (skip direct and hole punch)
        /// Useful for testing relay code paths even when direct connectivity is available
        public let forceRelayOnly: Bool

        public init(
            encryptionKey: Data,
            port: UInt16 = 0,
            targetRelays: Int = 3,
            maxRelays: Int = 5,
            canRelay: Bool = false,
            canCoordinateHolePunch: Bool = false,
            keepaliveInterval: TimeInterval = 15,
            connectionTimeout: TimeInterval = 10,
            maxCachedPeers: Int = 500,
            peerCacheTTL: TimeInterval = 3600,
            cacheCleanupInterval: TimeInterval = 60,
            recentContactMaxAge: TimeInterval = 300,
            freshnessQueryInterval: TimeInterval = 30,
            holePunchTimeout: TimeInterval = 10,
            holePunchProbeCount: Int = 5,
            holePunchProbeInterval: TimeInterval = 0.2,
            endpointValidationMode: EndpointValidator.ValidationMode = .permissive,
            forceRelayOnly: Bool = false
        ) {
            self.encryptionKey = encryptionKey
            self.port = port
            self.targetRelays = targetRelays
            self.maxRelays = maxRelays
            self.canRelay = canRelay
            self.canCoordinateHolePunch = canCoordinateHolePunch
            self.keepaliveInterval = keepaliveInterval
            self.connectionTimeout = connectionTimeout
            self.maxCachedPeers = maxCachedPeers
            self.peerCacheTTL = peerCacheTTL
            self.cacheCleanupInterval = cacheCleanupInterval
            self.recentContactMaxAge = recentContactMaxAge
            self.freshnessQueryInterval = freshnessQueryInterval
            self.holePunchTimeout = holePunchTimeout
            self.holePunchProbeCount = holePunchProbeCount
            self.holePunchProbeInterval = holePunchProbeInterval
            self.endpointValidationMode = endpointValidationMode
            self.forceRelayOnly = forceRelayOnly
        }
    }

    /// Cached peer information
    public struct CachedPeerInfo: Sendable {
        public let peerId: PeerId
        public let endpoint: Endpoint
        public let natType: NATType
        public let lastSeen: Date

        public init(peerId: PeerId, endpoint: Endpoint, natType: NATType = .unknown, lastSeen: Date = Date()) {
            self.peerId = peerId
            self.endpoint = endpoint
            self.natType = natType
            self.lastSeen = lastSeen
        }
    }

    /// Result of a ping with gossip details
    public struct PingResult: Sendable {
        /// Peer ID we pinged
        public let peerId: PeerId
        /// Endpoint we pinged
        public let endpoint: String
        /// Round-trip latency in milliseconds
        public let latencyMs: Int
        /// Peers we shared (includes machineId for proper tracking)
        public let sentPeers: [PeerEndpointInfo]
        /// Peers they shared (includes machineId for proper tracking)
        public let receivedPeers: [PeerEndpointInfo]
        /// Peers that were new to us (includes machineId)
        public let newPeers: [PeerEndpointInfo]
    }

    // MARK: - Properties

    /// This node's identity keypair
    public let identity: IdentityKeypair

    /// This node's peer ID (derived from identity public key)
    public var peerId: PeerId {
        identity.peerId
    }

    /// This node's machine ID (identifies this physical machine)
    public let machineId: MachineId

    /// Node configuration
    public let config: Config

    /// Endpoint manager for multi-endpoint tracking by (peerId, machineId)
    public let endpointManager: PeerEndpointManager

    /// Socket type alias for subsystem access
    public typealias Socket = UDPSocket

    /// Connected relay peer IDs
    private var connectedRelays: Set<PeerId> = []

    /// Application message handler
    private var applicationMessageHandler: ((MeshMessage, PeerId) async -> Void)?

    /// The UDP socket for network communication
    private let socket: UDPSocket

    /// Event loop group for NIO
    private let eventLoopGroup: EventLoopGroup

    /// Known peer connections
    private var peers: [PeerId: PeerConnection] = [:]

    /// Known contact information for reaching machines
    public struct KnownContact: Sendable {
        public let contactMachineId: MachineId
        public let contactPeerId: PeerId
        public let lastSeen: Date
        public let isFirstHand: Bool
    }

    /// Known contacts for all peers (not just symmetric NAT)
    /// Maps target machineId -> list of contacts who can reach that machine
    private var knownContacts: [MachineId: [KnownContact]] = [:]
    private let maxContactsPerMachine = 10

    /// Legacy: Potential relays for symmetric NAT peers (kept for backward compatibility)
    /// Maps symmetric NAT peer ID -> list of potential relays (most recent first)
    private var potentialRelays: [PeerId: [(relayPeerId: PeerId, lastSeen: Date)]] = [:]
    private let maxRelaysPerPeer = 10

    /// Machines we've received messages directly from (not via gossip)
    /// Used to set isFirstHand flag in gossip messages
    private var directContacts: Set<MachineId> = []

    /// Message IDs we've seen (for deduplication)
    private var seenMessageIds: Set<String> = []
    private let maxSeenMessages = 10000

    /// Gossip propagation queue - peer info to forward to other peers
    /// Each item has a count that decrements on each forward, removed when exhausted
    /// Internal for testing
    var peerPropagationQueue: [PeerId: (info: PeerEndpointInfo, count: Int)] = [:]
    let gossipFanout = 5  // Number of peers to forward each new peer info to

    /// Our observed public IPv4 endpoint as reported by peers (no STUN needed)
    private var observedPublicEndpoint: String?

    /// Our observed public IPv6 endpoint as reported by peers
    private var observedIPv6Endpoint: String?

    /// Task for periodic IPv6 address detection
    private var ipv6DetectionTask: Task<Void, Never>?

    /// Callback when our observed public endpoint changes
    private var endpointChangeHandler: ((String, String?) async -> Void)?

    /// Handler for incoming messages (legacy, for internal mesh messages)
    private var messageHandler: ((MeshMessage, PeerId) async -> MeshMessage?)?

    /// Pending responses for request/response pattern
    private var pendingResponses: [String: (continuation: CheckedContinuation<MeshMessage, Error>, timer: Task<Void, Never>)] = [:]

    // MARK: - Channel System

    /// Registered channel handlers
    /// Key is channel hash (UInt16) for O(1) lookup matching wire format, value is (channelName, handler)
    /// Handler receives (fromMachineId, data). Use machinePeerRegistry to look up peerId if needed.
    private var channelHandlers: [UInt16: (name: String, handler: @Sendable (MachineId, Data) async -> Void)] = [:]

    /// Queued messages for channels without handlers
    /// Key is channel hash (UInt16) for consistent lookup with wire format
    /// Messages are queued until a handler registers, then delivered immediately
    private var channelQueues: [UInt16: [(from: MachineId, data: Data, channelHash: UInt16, timestamp: Date)]] = [:]

    /// Registry tracking machine-to-peer mappings with recency
    public let machinePeerRegistry: MachinePeerRegistry

    /// Maximum messages to queue per channel (prevents memory exhaustion)
    private let maxQueuedMessagesPerChannel = 100

    /// Maximum age of queued messages before they're dropped (60 seconds)
    private let queuedMessageMaxAge: TimeInterval = 60.0

    // MARK: - Channel Batching

    /// Per-channel batch configuration overrides
    private var channelBatchConfigs: [UInt16: BatchConfig] = [:]

    /// Per-channel send buffers keyed by "channelHash:destination"
    private var channelSendBuffers: [String: (packets: [Data], totalSize: Int)] = [:]

    /// Auto-flush timer tasks per buffer key
    private var channelFlushTasks: [String: Task<Void, Never>] = [:]

    /// Registered batch monitors
    private var batchMonitors: [any BatchMonitor] = []

    /// Whether the node is running
    private var isRunning = false

    /// Logger
    private let logger: Logger

    /// Event logger for persistent event storage (optional)
    private let eventLogger: MeshEventLogger?

    /// Freshness manager for tracking recent contacts and handling stale info
    public let freshnessManager: FreshnessManager

    /// Hole punch manager for NAT traversal
    public let holePunchManager: HolePunchManager

    /// Connection keepalive manager for maintaining NAT mappings
    public let connectionKeepalive: ConnectionKeepalive

    /// NAT type predictor using peer-reported endpoint observations
    private let natPredictor: NATPredictor

    /// Set of known bootstrap peer IDs (for weighted NAT predictions)
    private var bootstrapPeers: Set<PeerId> = []

    /// The port we're listening on
    public var port: Int? {
        get async {
            await socket.port
        }
    }

    // MARK: - Initialization

    /// Create a new mesh node with a cryptographic identity and config
    /// - Parameters:
    ///   - identity: The cryptographic identity (peer ID is derived from this)
    ///   - config: Node configuration (must include encryption key)
    ///   - eventLogger: Optional event logger for persistent storage
    public init(identity: IdentityKeypair, config: Config, eventLogger: MeshEventLogger? = nil) throws {
        self.identity = identity
        self.machineId = try getOrCreateMachineId()
        self.config = config
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.socket = UDPSocket(eventLoopGroup: self.eventLoopGroup)
        self.logger = Logger(label: "io.omerta.mesh.node.\(identity.peerId.prefix(8))")
        self.eventLogger = eventLogger
        self.endpointManager = PeerEndpointManager(
            networkId: config.networkId,
            validationMode: config.endpointValidationMode,
            logger: Logger(label: "io.omerta.mesh.endpoints")
        )
        self.freshnessManager = FreshnessManager()
        self.holePunchManager = HolePunchManager(
            peerId: identity.peerId,
            config: HolePunchManager.Config(
                holePunchConfig: HolePunchConfig(
                    probeCount: config.holePunchProbeCount,
                    probeInterval: config.holePunchProbeInterval,
                    timeout: config.holePunchTimeout
                ),
                canCoordinate: config.canCoordinateHolePunch
            )
        )
        self.connectionKeepalive = ConnectionKeepalive(
            config: ConnectionKeepalive.Config(interval: config.keepaliveInterval)
        )
        self.natPredictor = NATPredictor()
        self.machinePeerRegistry = MachinePeerRegistry()
    }

    /// Set up the hole punch manager callbacks
    private func setupHolePunchManager() async {
        // Use the new unified services approach
        await holePunchManager.setServices(self)
    }

    /// Set up the freshness manager callbacks
    private func setupFreshnessManager() async {
        // Use the new unified services approach
        await freshnessManager.setServices(self)
    }

    /// Set up the connection keepalive callbacks
    private func setupConnectionKeepalive() async {
        // Use the new unified services approach
        await connectionKeepalive.setServices(self)
    }

    /// Send a ping to a specific endpoint (for keepalive)
    private func sendPingToEndpoint(peerId: PeerId, endpoint: String, timeout: TimeInterval) async -> Bool {
        // Build our recentPeers to send (with machineId and NAT type)
        // Pass currentEndpoint to advertise IPv6 if we're on IPv4
        let peerInfoList = await buildPeerEndpointInfoList(currentEndpoint: endpoint)
        let sentPeers = Array(peerInfoList.prefix(5))
        let myNATType = await getPredictedNATType().type
        let ping = MeshMessage.ping(recentPeers: sentPeers, myNATType: myNATType)

        do {
            let _ = try await sendAndReceive(ping, to: endpoint, timeout: timeout)
            return true
        } catch {
            return false
        }
    }

    /// Handle a keepalive failure for a machine (internal implementation)
    private func handleKeepaliveConnectionFailure(peerId: PeerId, machineId: MachineId, endpoint: String) async {
        // Log the failure - endpointManager handles endpoint lifecycle via activity tracking
        logger.info("Keepalive failure for \(peerId.prefix(8))...:\(machineId.prefix(8))... at \(endpoint)")

        // Notify freshness manager about the failure
        let _ = await freshnessManager.pathFailureReporter.reportFailure(
            peerId: peerId,
            path: .direct(endpoint: endpoint)
        )
    }

    /// Get endpoint for a peer (returns best endpoint from any machine) - internal use
    private func getEndpointForPeer(_ peerId: PeerId) async -> String? {
        await endpointManager.getAllEndpoints(peerId: peerId).first
    }

    /// Broadcast a message to all known peers with hop count tracking
    public func broadcast(_ message: MeshMessage, maxHops: Int) async {
        // Get all known peer IDs and their best endpoints
        for peerId in await endpointManager.allPeerIds {
            guard peerId != self.peerId else { continue }

            guard let endpoint = await endpointManager.getAllEndpoints(peerId: peerId).first else {
                continue
            }

            do {
                let envelope = try MeshEnvelope.signed(
                    from: identity,
                    machineId: machineId,
                    to: nil,
                    payload: message
                )

                let sealed = try envelope.encodeV2(networkKey: config.encryptionKey)
                try await socket.send(sealed, to: endpoint)
            } catch {
                logger.debug("Failed to broadcast to \(peerId): \(error)")
            }
        }
    }

    /// Set up the receive handler for incoming datagrams
    private func setupReceiveHandler() async {
        await socket.onReceive { [weak self] data, address in
            guard let self = self else { return }
            await self.handleIncomingData(data, from: address)
        }
    }

    // MARK: - Lifecycle

    /// Start the node
    public func start(natType: NATType = .unknown) async throws {
        guard !isRunning else { return }

        // Bind socket if not already bound
        let currentPort = await socket.port
        logger.debug("MeshNode.start() - current socket port: \(currentPort?.description ?? "nil"), config.port: \(config.port)")

        if currentPort == nil {
            // Determine bind address based on mode
            let bindHost: String
            if config.endpointValidationMode == .allowAll {
                // Testing mode (allowLocalhost) - use IPv4 to avoid routing issues
                // with IPv4-mapped IPv6 addresses on loopback
                bindHost = "0.0.0.0"
            } else {
                // Production mode - detect best local IPv6 address to bind to
                // This is important on systems with IPv6 privacy extensions (macOS)
                // where binding to "::" causes outbound to use temporary addresses
                // instead of the stable address we advertise to peers
                bindHost = EndpointUtils.getBestLocalIPv6Address() ?? "::"
            }
            logger.debug("MeshNode.start() - binding socket to \(bindHost):\(config.port)")
            try await socket.bind(host: bindHost, port: Int(config.port))
            logger.debug("MeshNode.start() - socket bound successfully")
            await setupReceiveHandler()
            await setupFreshnessManager()
            await setupHolePunchManager()
            await setupConnectionKeepalive()
        } else {
            logger.debug("MeshNode.start() - socket already bound to port \(currentPort!)")
        }

        isRunning = true

        // Start event logger if provided
        await eventLogger?.start()

        // Start endpoint manager for persistence and cleanup
        await endpointManager.start()

        // Start freshness manager
        await freshnessManager.start()

        // Start hole punch manager
        let boundPort = await socket.port ?? 0
        logger.debug("MeshNode.start() - boundPort after start: \(boundPort)")
        await holePunchManager.start(natType: natType, localPort: UInt16(boundPort))

        // Start connection keepalive
        await connectionKeepalive.start()

        // Start IPv6 address detection (checks immediately and every 5 minutes)
        startIPv6DetectionTask()

        // Note: Cache cleanup is now handled by endpointManager

        logger.info("Mesh node started on port \(boundPort)")
    }

    /// Stop the node
    public func stop() async {
        guard isRunning else { return }
        isRunning = false

        // Stop event logger
        await eventLogger?.stop()

        // Stop endpoint manager (saves to disk)
        await endpointManager.stop()

        // Stop freshness manager
        await freshnessManager.stop()

        // Stop hole punch manager
        await holePunchManager.stop()

        // Stop connection keepalive
        await connectionKeepalive.stop()

        // Stop IPv6 detection task
        ipv6DetectionTask?.cancel()
        ipv6DetectionTask = nil

        // Note: Cache cleanup is now handled by endpointManager (stopped above)

        // Cancel all pending responses
        for (_, pending) in pendingResponses {
            pending.timer.cancel()
            pending.continuation.resume(throwing: MeshNodeError.stopped)
        }
        pendingResponses.removeAll()

        await socket.close()
        logger.info("Mesh node stopped")
    }

    // MARK: - Message Handling

    /// Register a handler for incoming messages
    public func onMessage(_ handler: @escaping (MeshMessage, PeerId) async -> MeshMessage?) {
        self.messageHandler = handler
    }

    /// Handle incoming UDP data
    private func handleIncomingData(_ data: Data, from address: NIOCore.SocketAddress) async {
        logger.info("Received \(data.count) bytes from \(address)")

        // Try v2 wire format first (fast path rejection for non-Omerta packets)
        if BinaryEnvelopeV2.isValidPrefix(data) {
            do {
                // Use decodeV2WithHash to get the raw channel hash for routing
                let (envelope, channelHash) = try MeshEnvelope.decodeV2WithHash(data, networkKey: config.encryptionKey)
                await processEnvelope(envelope, from: address, channelHash: channelHash)
                return
            } catch EnvelopeError.networkMismatch {
                logger.debug("Packet for different network from \(address)")
                return
            } catch {
                logger.warning("Failed to decode v2 envelope from \(address): \(error)")
                return
            }
        }

        // Fall back to v1 format for backward compatibility during migration
        guard let decryptedData = try? MessageEncryption.decrypt(data, key: config.encryptionKey) else {
            logger.warning("Failed to decrypt message from \(address) (\(data.count) bytes)")
            return
        }

        guard let envelope = try? MeshEnvelope.decode(decryptedData) else {
            logger.debug("Failed to decode message from \(address)")
            return
        }

        await processEnvelope(envelope, from: address, channelHash: nil)
    }

    /// Process a decoded envelope
    /// - Parameters:
    ///   - envelope: The decoded envelope
    ///   - address: Source address
    ///   - channelHash: Raw channel hash from v2 format (nil for v1 format, uses string-based lookup)
    private func processEnvelope(_ envelope: MeshEnvelope, from address: NIOCore.SocketAddress, channelHash: UInt16? = nil) async {

        // Check for duplicates
        if seenMessageIds.contains(envelope.messageId) {
            logger.debug("Ignoring duplicate message \(envelope.messageId)")
            return
        }
        markMessageSeen(envelope.messageId)

        // Verify signature using embedded public key (also verifies peer ID derivation)
        guard envelope.verifySignature() else {
            logger.warning("Rejecting message with invalid signature",
                          metadata: ["from": "\(envelope.fromPeerId.prefix(8))..."])

            // Log signature error
            await eventLogger?.recordError(
                component: MeshComponent.meshNode.rawValue,
                operation: "verifySignature",
                errorType: MeshErrorCategory.signature.rawValue,
                errorMessage: "Invalid signature on incoming message",
                peerId: envelope.fromPeerId
            )

            return
        }

        // Update peer info and track endpoint
        let endpointString = formatEndpoint(address)
        await updatePeerConnectionFromMessage(peerId: envelope.fromPeerId, endpoint: endpointString)

        // Record in endpoint manager for multi-endpoint tracking
        logger.info("Recording endpoint for peer \(envelope.fromPeerId.prefix(16))... machine \(envelope.machineId.prefix(16))... at \(endpointString)")
        await endpointManager.recordMessageReceived(
            from: envelope.fromPeerId,
            machineId: envelope.machineId,
            endpoint: endpointString
        )

        // Record machine-peer association in registry
        await machinePeerRegistry.setMachine(envelope.machineId, peer: envelope.fromPeerId)

        // Record direct contact for first-hand tracking
        // This machine has sent us a message directly, so we have first-hand knowledge of it
        directContacts.insert(envelope.machineId)

        // Log peer seen event
        await eventLogger?.recordPeerSeen(
            peerId: envelope.fromPeerId,
            endpoint: endpointString,
            natType: nil
        )

        // Check if this is a response to a pending request
        if case .pong(_, _, _) = envelope.payload {
            // Add/update machine in keepalive monitoring
            // This happens before resuming the continuation so sendPingWithDetails sees updated state
            await connectionKeepalive.addMachine(peerId: envelope.fromPeerId, machineId: envelope.machineId)
            await connectionKeepalive.recordSuccessfulCommunication(peerId: envelope.fromPeerId, machineId: envelope.machineId)

            // Find any pending ping request
            for (requestId, pending) in pendingResponses {
                if requestId.hasPrefix("ping-") {
                    pendingResponses.removeValue(forKey: requestId)
                    pending.timer.cancel()
                    pending.continuation.resume(returning: envelope.payload)
                    return
                }
            }
        }

        if case .response(let requestId, _) = envelope.payload {
            if let pending = pendingResponses.removeValue(forKey: requestId) {
                pending.timer.cancel()
                pending.continuation.resume(returning: envelope.payload)
                return
            }
        }

        // Handle through message handler or default
        if let handler = messageHandler {
            if let response = await handler(envelope.payload, envelope.fromPeerId) {
                try? await send(response, to: endpointString)
            }
        } else {
            await handleDefaultMessage(envelope.payload, from: envelope.fromPeerId, machineId: envelope.machineId, endpoint: endpointString, channel: envelope.channel, channelHash: channelHash, hopCount: envelope.hopCount)
        }

        // Check if we should attempt direct connection (Phase 8: Direct connection on relayed message)
        // If the message came via relay (source endpoint doesn't match known endpoints for sender)
        // and sender's NAT type allows direct connection, try to establish direct path
        await attemptDirectConnectionIfNeeded(
            fromPeerId: envelope.fromPeerId,
            sourceEndpoint: endpointString
        )
    }

    /// Default message handling for basic protocol
    /// - Parameters:
    ///   - message: The message payload
    ///   - peerId: Sender's peer ID
    ///   - machineId: Sender's machine ID
    ///   - endpoint: Sender's endpoint
    ///   - channel: Channel string (original name for v1, hash string for v2)
    ///   - channelHash: Raw channel hash from v2 format (nil for v1, uses string-based lookup)
    ///   - hopCount: Current hop count
    private func handleDefaultMessage(_ message: MeshMessage, from peerId: PeerId, machineId: MachineId, endpoint: String, channel: String = "", channelHash: UInt16? = nil, hopCount: Int = 0) async {
        switch message {
        case .ping(let recentPeers, let theirNATType, let requestFullList):
            // Check if this is a NEW or RECONNECTING peer BEFORE recording
            // A peer is considered "reconnecting" if we haven't heard from them in 10+ minutes
            // (updated from 60s to 600s for more efficient gossip)
            let hasEndpoints = !(await endpointManager.getAllEndpoints(peerId: peerId).isEmpty)
            let hasRecentContact = await freshnessManager.hasRecentContact(peerId, maxAgeSeconds: 600)
            let isNewOrReconnecting = !hasEndpoints || !hasRecentContact

            // Track sender's NAT type
            await endpointManager.updateNATType(peerId: peerId, natType: theirNATType)

            // Record this contact first so we're included in the response
            await freshnessManager.recordContact(
                peerId: peerId,
                reachability: .direct(endpoint: endpoint),
                latencyMs: 0,
                connectionType: .inboundDirect
            )

            // Build response - if requestFullList, NEW or RECONNECTING peer, send ALL known peers; otherwise send delta
            let myPeers: [PeerEndpointInfo]
            if requestFullList || isNewOrReconnecting {
                // Explicit request or new/reconnecting peer gets full peer list to bootstrap their view of the network
                myPeers = await buildPeerEndpointInfoList(currentEndpoint: endpoint)
                if requestFullList {
                    logger.info("Peer \(peerId.prefix(8))... requested full list - sending \(myPeers.count) known peers")
                } else if hasEndpoints {
                    logger.info("Reconnecting peer \(peerId.prefix(8))... - sending \(myPeers.count) known peers")
                } else {
                    logger.info("New peer \(peerId.prefix(8))... contacted us - sending \(myPeers.count) known peers")
                }
            } else {
                // Known peer gets recent peers + propagation queue items (delta gossip)
                myPeers = await buildPeerEndpointInfoListWithPropagation(excluding: peerId, currentEndpoint: endpoint)
            }

            // Get our predicted NAT type (unknown until integrated with NATPredictor in Phase 2)
            let myNATType = await getPredictedNATType().type
            try? await send(.pong(recentPeers: myPeers, yourEndpoint: endpoint, myNATType: myNATType), to: endpoint)

            // Learn about new peers from the ping WITH machineId and NAT type
            // Get sender's machine ID for contact tracking
            let senderMachines = await endpointManager.getAllMachines(peerId: peerId)
            let senderMachineId = senderMachines.first(where: { $0.bestEndpoint == endpoint })?.machineId ?? "unknown-\(peerId.prefix(8))"

            for peerInfo in recentPeers where peerInfo.peerId != self.peerId {
                // Check if we already know about this peer's endpoint
                let existingEndpoints = await endpointManager.getAllEndpoints(peerId: peerInfo.peerId)
                let isNewlyLearnedPeer = existingEndpoints.isEmpty

                if !existingEndpoints.contains(peerInfo.endpoint) {
                    logger.info("Learned about peer \(peerInfo.peerId.prefix(16))... at \(peerInfo.endpoint) from gossip")
                }

                // Record in endpointManager (handles deduplication and priority)
                await endpointManager.recordMessageReceived(
                    from: peerInfo.peerId,
                    machineId: peerInfo.machineId,
                    endpoint: peerInfo.endpoint
                )

                // Track peer's NAT type from gossip
                await endpointManager.updateNATType(peerId: peerInfo.peerId, natType: peerInfo.natType)

                // CONTACT TRACKING: Record the sender as a known contact for ALL peers (not just symmetric)
                // This helps us route messages to peers we can't reach directly
                recordKnownContact(
                    for: peerInfo.machineId,
                    targetPeerId: peerInfo.peerId,
                    via: senderMachineId,
                    contactPeerId: peerId,
                    isFirstHand: peerInfo.isFirstHand
                )

                // LEGACY: Still record potential relay for symmetric NAT peers
                if peerInfo.natType == .symmetric {
                    recordPotentialRelay(for: peerInfo.peerId, via: peerId)
                }

                // GOSSIP: Propagate if new peer OR endpoint has changed
                let endpointChanged = !isNewlyLearnedPeer && !existingEndpoints.contains(peerInfo.endpoint)
                if isNewlyLearnedPeer || endpointChanged {
                    addToPropagationQueue(peerInfo)
                }
            }

            // GOSSIP: If the sender is a new or reconnecting peer, add them to propagation queue
            if isNewOrReconnecting {
                // Get the sender's machineId from endpointManager (was just recorded in handleIncomingData)
                let senderMachines = await endpointManager.getAllMachines(peerId: peerId)
                if let senderMachine = senderMachines.first(where: { $0.bestEndpoint == endpoint }) {
                    let senderInfo = PeerEndpointInfo(
                        peerId: peerId,
                        machineId: senderMachine.machineId,
                        endpoint: endpoint,
                        natType: theirNATType
                    )
                    addToPropagationQueue(senderInfo)
                }
            }

        case .pong(let recentPeers, let yourEndpoint, let theirNATType):
            // Pong sender is already recorded in handleIncomingData via endpointManager.recordMessageReceived
            logger.info("Received pong from: \(peerId.prefix(8))... at \(endpoint) with \(recentPeers.count) peers")

            // Notify hole punch manager in case this pong completes a hole punch
            await holePunchManager.holePuncher.handlePongReceived(from: endpoint, peerId: peerId)

            // Track sender's NAT type
            await endpointManager.updateNATType(peerId: peerId, natType: theirNATType)

            // Update our observed public endpoint based on what the peer sees
            await updateObservedEndpoint(yourEndpoint, reportedBy: peerId)

            // Learn about new peers from the pong WITH machineId and NAT type
            // Get sender's machine ID for contact tracking
            let senderMachinesPong = await endpointManager.getAllMachines(peerId: peerId)
            let senderMachineIdPong = senderMachinesPong.first(where: { $0.bestEndpoint == endpoint })?.machineId ?? "unknown-\(peerId.prefix(8))"

            for peerInfo in recentPeers where peerInfo.peerId != self.peerId {
                // Check if we already know about this peer's endpoint
                let existingEndpoints = await endpointManager.getAllEndpoints(peerId: peerInfo.peerId)
                let isNewlyLearnedPeer = existingEndpoints.isEmpty

                if isNewlyLearnedPeer {
                    logger.info("Learned NEW peer \(peerInfo.peerId.prefix(16))... at \(peerInfo.endpoint) from pong")
                } else if !existingEndpoints.contains(peerInfo.endpoint) {
                    logger.info("Learned NEW endpoint for \(peerInfo.peerId.prefix(16))...: \(peerInfo.endpoint) (had: \(existingEndpoints.first ?? "none"))")
                } else {
                    logger.debug("Refreshed endpoint for \(peerInfo.peerId.prefix(16))...: \(peerInfo.endpoint)")
                }

                // Record in endpointManager (handles deduplication and priority)
                await endpointManager.recordMessageReceived(
                    from: peerInfo.peerId,
                    machineId: peerInfo.machineId,
                    endpoint: peerInfo.endpoint
                )

                // Track peer's NAT type from gossip
                await endpointManager.updateNATType(peerId: peerInfo.peerId, natType: peerInfo.natType)

                // CONTACT TRACKING: Record the sender as a known contact for ALL peers (not just symmetric)
                // This helps us route messages to peers we can't reach directly
                recordKnownContact(
                    for: peerInfo.machineId,
                    targetPeerId: peerInfo.peerId,
                    via: senderMachineIdPong,
                    contactPeerId: peerId,
                    isFirstHand: peerInfo.isFirstHand
                )

                // LEGACY: Still record potential relay for symmetric NAT peers
                if peerInfo.natType == .symmetric {
                    recordPotentialRelay(for: peerInfo.peerId, via: peerId)
                }

                // GOSSIP: Propagate if new peer OR endpoint has changed
                let endpointChanged = !isNewlyLearnedPeer && !existingEndpoints.contains(peerInfo.endpoint)
                if isNewlyLearnedPeer || endpointChanged {
                    addToPropagationQueue(peerInfo)
                }
            }

            // Record this as a recent contact
            await freshnessManager.recordContact(
                peerId: peerId,
                reachability: .direct(endpoint: endpoint),
                latencyMs: 0,
                connectionType: .direct
            )

            // Update keepalive monitoring - pong means connection is healthy
            if await connectionKeepalive.isMonitoring(peerId: peerId) {
                await connectionKeepalive.recordSuccessfulCommunication(peerId: peerId)
            }

            // In forceRelayOnly mode, add any responsive peer as a potential relay
            // This enables testing relay code paths on LAN where direct connectivity exists
            if config.forceRelayOnly && !connectedRelays.contains(peerId) {
                connectedRelays.insert(peerId)
                logger.info("forceRelayOnly: Added \(peerId.prefix(16))... as connected relay")
            }

        case .whoHasRecent, .iHaveRecent, .pathFailed:
            // Handle freshness messages
            let (response, shouldForward) = await freshnessManager.handleMessage(
                message,
                from: peerId,
                hopCount: hopCount
            )

            // Send response if any
            if let response = response {
                try? await send(response, to: endpoint)
            }

            // Forward if needed
            if shouldForward {
                await forwardMessage(message, from: peerId, hopCount: hopCount + 1)
            }

        case .holePunchRequest, .holePunchInvite, .holePunchExecute, .holePunchResult:
            // Handle hole punch messages
            if let response = await holePunchManager.handleMessage(message, from: peerId) {
                try? await send(response, to: endpoint)
            }

        case .data(let payload):
            // Route based on channel
            if let hash = channelHash, hash != 0 {
                // v2 format: use channel hash directly for O(1) routing
                logger.info("Routing .data(\(payload.count) bytes) to channel hash \(hash) from machine \(machineId.prefix(16))...")
                await handleChannelMessageByHash(from: machineId, channelHash: hash, data: payload)
            } else if !channel.isEmpty {
                // v1 format: compute hash from channel string
                logger.info("Routing .data(\(payload.count) bytes) to channel '\(channel)' from machine \(machineId.prefix(16))...")
                await handleChannelMessage(from: machineId, channel: channel, data: payload)
            } else if let handler = applicationMessageHandler {
                // Legacy application handler (for internal mesh messages)
                logger.info("Passing .data(\(payload.count) bytes) to application handler from \(peerId.prefix(16))...")
                await handler(.data(payload), peerId)
            } else {
                logger.warning("No handler for .data message from \(peerId.prefix(16))... (channel: empty, no applicationMessageHandler)")
            }

        case .peerInfo:
            // Record this contact when receiving a peer announcement
            await freshnessManager.recordContact(
                peerId: peerId,
                reachability: .direct(endpoint: endpoint),
                latencyMs: 0,
                connectionType: .inboundDirect
            )
            // Note: endpoint is already recorded in handleIncomingData via endpointManager.recordMessageReceived
            logger.info("Received peer announcement: \(peerId.prefix(8))... at \(endpoint)")

        case .relayForward(let targetPeerId, let payload):
            // Handle relay forward request - forward the payload to the target peer
            logger.info("Relay forward request from \(peerId.prefix(8))... to \(targetPeerId.prefix(8))...")
            await handleRelayForward(targetPeerId: targetPeerId, payload: payload, from: peerId, senderEndpoint: endpoint)

        case .relayForwardResult(let targetPeerId, let success):
            // Log relay forward result (the continuation mechanism handles response matching)
            if success {
                logger.debug("Relay forward to \(targetPeerId.prefix(8))... succeeded")
            } else {
                logger.warning("Relay forward to \(targetPeerId.prefix(8))... failed")
            }

        default:
            break
        }
    }

    /// Forward a message to other peers (for gossip propagation)
    private func forwardMessage(_ message: MeshMessage, from originalSender: PeerId, hopCount: Int) async {
        for peerId in await endpointManager.allPeerIds {
            // Don't forward back to sender or to ourselves
            guard peerId != originalSender && peerId != self.peerId else { continue }

            guard let endpoint = await endpointManager.getAllEndpoints(peerId: peerId).first else {
                continue
            }

            // Use the standard send method which handles v2 encryption
            try? await send(message, to: endpoint)
        }
    }

    // MARK: - Sending Messages

    /// Send a message to an endpoint
    /// - Parameters:
    ///   - message: Message to send
    ///   - endpoint: Target endpoint
    ///   - channel: Channel for routing (default: empty for internal mesh messages)
    /// - Throws: If message encoding or socket send fails
    public func send(_ message: MeshMessage, to endpoint: String, channel: String = "") async throws {
        // Create signed envelope with embedded public key
        let envelope = try MeshEnvelope.signed(
            from: identity,
            machineId: machineId,
            to: nil,
            channel: channel,
            payload: message
        )

        // Encode using v2 wire format with layered encryption
        let encryptedData = try envelope.encodeV2(networkKey: config.encryptionKey)
        logger.info("Sending \(encryptedData.data.count) bytes to \(endpoint)")
        try await socket.send(encryptedData, to: endpoint)

        logger.info("Sent \(type(of: message)) (\(encryptedData.data.count) bytes) to \(endpoint) [channel: \(channel.isEmpty ? "<mesh>" : channel)]")
    }

    /// Send a message and wait for a response
    public func sendAndReceive(
        _ message: MeshMessage,
        to endpoint: String,
        timeout: TimeInterval = 5.0
    ) async throws -> MeshMessage {
        let requestId: String

        switch message {
        case .ping:
            requestId = "ping-\(UUID().uuidString)"
        case .request(let rid, _):
            requestId = rid
        default:
            requestId = UUID().uuidString
        }

        return try await withCheckedThrowingContinuation { continuation in
            // Create timeout task
            let timeoutTask = Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                if let pending = self.pendingResponses.removeValue(forKey: requestId) {
                    pending.continuation.resume(throwing: MeshNodeError.timeout)
                }
            }

            // Store continuation
            self.pendingResponses[requestId] = (continuation, timeoutTask)

            // Send the message
            Task {
                do {
                    try await self.send(message, to: endpoint)
                } catch {
                    // Send failed - resume continuation with error
                    if let pending = self.pendingResponses.removeValue(forKey: requestId) {
                        pending.timer.cancel()
                        pending.continuation.resume(throwing: error)
                    }
                }
            }
        }
    }

    // MARK: - Peer Management

    /// Update a peer's endpoint from incoming message
    /// Note: endpointManager is updated separately in handleIncomingData
    private func updatePeerConnectionFromMessage(peerId: PeerId, endpoint: String) async {
        // Update PeerConnection if we have one
        if let peer = peers[peerId] {
            await peer.setActiveEndpoint(endpoint)
            await peer.updateLastSeen()
        }
    }

    /// Add a peer with known public key
    public func addPeer(publicKeyBase64: String) throws {
        let connection = try PeerConnection(publicKeyBase64: publicKeyBase64)
        peers[connection.peerId] = connection
    }

    /// Get known peer IDs
    public var knownPeerIds: [PeerId] {
        Array(peers.keys)
    }


    // MARK: - MeshNetwork API Methods

    /// Get cached peer info
    public func getCachedPeer(_ peerId: PeerId) async -> CachedPeerInfo? {
        // Build CachedPeerInfo from endpointManager
        guard let endpoint = await endpointManager.getAllEndpoints(peerId: peerId).first else {
            return nil
        }
        // Get last seen from the machine endpoints
        let machines = await endpointManager.getAllMachines(peerId: peerId)
        let lastSeen = machines.map { $0.lastActivity }.max() ?? Date()
        return CachedPeerInfo(peerId: peerId, endpoint: endpoint, natType: .unknown, lastSeen: lastSeen)
    }

    /// Get list of cached peer IDs
    public func getCachedPeerIds() async -> [PeerId] {
        await endpointManager.allPeerIds
    }

    /// Get connected relay peer IDs
    public func getConnectedRelays() async -> [PeerId] {
        Array(connectedRelays)
    }

    /// Update a peer's endpoint (public API for MeshNetwork)
    /// Note: Uses a generated machineId since we don't know the actual machineId yet
    public func updatePeerEndpoint(_ peerId: PeerId, endpoint: Endpoint) async {
        // Don't add ourselves as a peer
        guard peerId != self.peerId else { return }
        // Use a placeholder machineId - will be updated when we receive a message from them
        let placeholderMachineId = "bootstrap-\(peerId.prefix(16))"
        await endpointManager.recordMessageReceived(from: peerId, machineId: placeholderMachineId, endpoint: endpoint)
    }

    /// Request peer list from known peers
    public func requestPeers() async {
        let myNATType = await getPredictedNATType().type

        // Send ping to all known peers
        for peerId in await endpointManager.allPeerIds {
            guard peerId != self.peerId else { continue }
            guard let endpoint = await endpointManager.getAllEndpoints(peerId: peerId).first else {
                continue
            }
            // Build peer list with currentEndpoint to conditionally advertise IPv6
            let myPeers = await buildPeerEndpointInfoList(currentEndpoint: endpoint)
            try? await send(.ping(recentPeers: myPeers, myNATType: myNATType), to: endpoint)
        }
    }

    // MARK: - Observed Endpoint (Peer-Reported)

    /// Get our observed public endpoint as reported by peers
    /// This is determined from pong messages without requiring STUN
    public var getObservedEndpoint: String? {
        observedPublicEndpoint
    }

    /// Set callback for when our observed public endpoint changes
    public func setEndpointChangeHandler(_ handler: @escaping (String, String?) async -> Void) {
        endpointChangeHandler = handler
    }

    /// Update our observed public endpoint based on peer reports
    /// Called when we receive a pong message that tells us our endpoint
    /// Tracks IPv4 and IPv6 endpoints separately
    private func updateObservedEndpoint(_ newEndpoint: String, reportedBy peerId: PeerId) async {
        // Determine if this is IPv4 or IPv6
        let isIPv6 = EndpointUtils.isIPv6(newEndpoint)

        // Record observation for NAT prediction
        let isBootstrap = bootstrapPeers.contains(peerId)
        await natPredictor.recordObservation(endpoint: newEndpoint, from: peerId, isBootstrap: isBootstrap)

        if isIPv6 {
            // Update IPv6 endpoint
            if observedIPv6Endpoint != newEndpoint {
                if let old = observedIPv6Endpoint {
                    logger.info("Observed IPv6 endpoint changed from \(old) to \(newEndpoint) (reported by \(peerId.prefix(8))...)")
                } else {
                    logger.info("Observed IPv6 endpoint set to \(newEndpoint) (reported by \(peerId.prefix(8))...)")
                }
                observedIPv6Endpoint = newEndpoint
            }
        } else {
            // Update IPv4 endpoint
            let oldEndpoint = observedPublicEndpoint
            if oldEndpoint != newEndpoint {
                if let old = oldEndpoint {
                    logger.info("Observed endpoint changed from \(old) to \(newEndpoint) (reported by \(peerId.prefix(8))...)")
                } else {
                    logger.info("Observed endpoint set to \(newEndpoint) (reported by \(peerId.prefix(8))...)")
                }

                observedPublicEndpoint = newEndpoint

                // Notify handler if set
                if let handler = endpointChangeHandler {
                    await handler(newEndpoint, oldEndpoint)
                }
            }
        }
    }

    /// Check for local IPv6 addresses and update our endpoint if found
    /// This allows advertising IPv6 without waiting for a peer to report it
    private func detectLocalIPv6Endpoint() async {
        // Skip IPv6 detection in test mode (using IPv4-only socket)
        guard config.endpointValidationMode != .allowAll else {
            return
        }

        guard let ipv6Address = EndpointUtils.getBestLocalIPv6Address() else {
            return
        }

        // Get our bound port
        guard let boundPort = await socket.port else {
            return
        }

        // Construct the endpoint in bracket notation for IPv6
        let endpoint = "[\(ipv6Address)]:\(boundPort)"

        // Only update if we don't already have an observed IPv6 endpoint
        // (peer-reported endpoint is more accurate than local detection)
        if observedIPv6Endpoint == nil {
            logger.info("Detected local IPv6 address: \(endpoint)")
            observedIPv6Endpoint = endpoint
        }
    }

    /// Start periodic IPv6 address detection
    private func startIPv6DetectionTask() {
        ipv6DetectionTask = Task {
            // Check immediately on start
            await detectLocalIPv6Endpoint()

            // Then check every 5 minutes
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(300))
                await detectLocalIPv6Endpoint()
            }
        }
    }

    // MARK: - NAT Prediction

    /// Get our predicted NAT type based on peer observations
    /// Returns (type, publicEndpoint, confidence) where confidence is number of observations
    public func getPredictedNATType() async -> (type: NATType, publicEndpoint: String?, confidence: Int) {
        await natPredictor.predictNATType()
    }

    /// Get the NAT type of a specific peer
    public func getNATType(for peerId: PeerId) async -> NATType? {
        await endpointManager.getNATType(peerId: peerId)
    }

    /// Register a peer as a bootstrap node (for weighted NAT predictions)
    public func registerBootstrapPeer(_ peerId: PeerId) {
        bootstrapPeers.insert(peerId)
    }

    /// Reset NAT prediction (e.g., after network change)
    public func resetNATPrediction() async {
        await natPredictor.reset()
    }

    /// Wait for endpoint observations from bootstrap peers
    /// - Parameters:
    ///   - minimumObservations: Minimum number of observations to wait for (default: 2)
    ///   - timeout: Maximum time to wait in seconds (default: 2.0)
    /// - Returns: Number of observations received before timeout
    public func waitForBootstrapObservations(minimum: Int = 2, timeout: TimeInterval = 2.0) async -> Int {
        let startTime = Date()
        let pollInterval: UInt64 = 50_000_000 // 50ms

        while Date().timeIntervalSince(startTime) < timeout {
            let count = await natPredictor.observationCount
            if count >= minimum {
                logger.debug("Received \(count) bootstrap observations")
                return count
            }
            try? await Task.sleep(nanoseconds: pollInterval)
        }

        let finalCount = await natPredictor.observationCount
        logger.debug("Bootstrap observation wait timed out with \(finalCount) observations")
        return finalCount
    }

    // MARK: - Relay Discovery

    /// Record a potential relay for a symmetric NAT peer
    /// Called when we receive gossip about a symmetric NAT peer - the sender becomes a potential relay
    public func recordPotentialRelay(for symmetricPeerId: PeerId, via relayPeerId: PeerId) {
        // Don't record ourselves as a relay
        guard relayPeerId != peerId else { return }
        // Don't record the symmetric peer as its own relay
        guard relayPeerId != symmetricPeerId else { return }

        var relays = potentialRelays[symmetricPeerId] ?? []

        // Remove existing entry for this relay (to move to front)
        relays.removeAll { $0.relayPeerId == relayPeerId }

        // Add at front (most recent)
        relays.insert((relayPeerId: relayPeerId, lastSeen: Date()), at: 0)

        // Keep only max relays
        potentialRelays[symmetricPeerId] = Array(relays.prefix(maxRelaysPerPeer))

        logger.debug("Recorded potential relay \(relayPeerId.prefix(8))... for symmetric peer \(symmetricPeerId.prefix(8))...")
    }

    /// Get potential relays for a symmetric NAT peer
    /// Returns relays ordered by most recent contact
    public func getPotentialRelays(for symmetricPeerId: PeerId) -> [(relayPeerId: PeerId, lastSeen: Date)] {
        potentialRelays[symmetricPeerId] ?? []
    }

    /// Clear potential relays for a peer (e.g., when direct connection established)
    public func clearPotentialRelays(for peerId: PeerId) {
        potentialRelays.removeValue(forKey: peerId)
    }

    // MARK: - Known Contacts (All NAT Types)

    /// Record a known contact for any machine (not just symmetric NAT)
    /// Called when we receive gossip about a peer - the sender becomes a potential contact path
    public func recordKnownContact(
        for targetMachineId: MachineId,
        targetPeerId: PeerId,
        via contactMachineId: MachineId,
        contactPeerId: PeerId,
        isFirstHand: Bool
    ) {
        // Don't record ourselves as a contact
        guard contactPeerId != peerId else { return }
        // Don't record the target as its own contact
        guard contactMachineId != targetMachineId else { return }

        var contacts = knownContacts[targetMachineId] ?? []

        // Remove existing entry for this contact (to update position)
        contacts.removeAll { $0.contactMachineId == contactMachineId }

        // Add at front (most recent)
        contacts.insert(KnownContact(
            contactMachineId: contactMachineId,
            contactPeerId: contactPeerId,
            lastSeen: Date(),
            isFirstHand: isFirstHand
        ), at: 0)

        // Keep only max contacts
        knownContacts[targetMachineId] = Array(contacts.prefix(maxContactsPerMachine))

        logger.debug("Recorded contact \(contactPeerId.prefix(8))... for machine \(targetMachineId.prefix(8))... (firstHand: \(isFirstHand))")
    }

    /// Get contacts for a machine with priority sorting
    /// Priority: first-hand Public/Shared > first-hand Per-Peer > second-hand Public/Shared > second-hand Per-Peer
    public func getContactsForMachine(_ machineId: MachineId) async -> [KnownContact] {
        guard let contacts = knownContacts[machineId] else { return [] }

        // Pre-fetch NAT types for all contacts
        var natTypes: [PeerId: NATType] = [:]
        for contact in contacts {
            natTypes[contact.contactPeerId] = await endpointManager.getNATType(peerId: contact.contactPeerId) ?? .unknown
        }

        return contacts.sorted { a, b in
            let aNatType = natTypes[a.contactPeerId] ?? .unknown
            let bNatType = natTypes[b.contactPeerId] ?? .unknown
            let aIsRestricted = aNatType == .symmetric || aNatType == .portRestrictedCone
            let bIsRestricted = bNatType == .symmetric || bNatType == .portRestrictedCone

            // First-hand before second-hand
            if a.isFirstHand != b.isFirstHand { return a.isFirstHand }
            // Public/Shared before Per-Peer (restricted)
            if aIsRestricted != bIsRestricted { return !aIsRestricted }
            // Most recent
            return a.lastSeen > b.lastSeen
        }
    }

    /// Clear known contacts for a machine (e.g., when direct connection established)
    public func clearKnownContacts(for machineId: MachineId) {
        knownContacts.removeValue(forKey: machineId)
    }

    // MARK: - Relay Forwarding

    /// Handle a relay forward request - forward payload to target peer
    private func handleRelayForward(targetPeerId: PeerId, payload: Data, from senderPeerId: PeerId, senderEndpoint: String) async {
        // Check if we know an endpoint for the target
        guard let targetEndpoint = await endpointManager.getAllEndpoints(peerId: targetPeerId).first else {
            logger.warning("Relay forward failed: no endpoint for target \(targetPeerId.prefix(8))...")
            try? await send(.relayForwardResult(targetPeerId: targetPeerId, success: false), to: senderEndpoint)
            return
        }

        // Forward the raw payload directly to the target
        // The payload is already an encrypted MeshEnvelope from the original sender
        do {
            try await socket.send(SealedEnvelope(trustedData: payload), to: targetEndpoint)
            logger.info("Relayed \(payload.count) bytes to \(targetPeerId.prefix(8))... at \(targetEndpoint)")
            try? await send(.relayForwardResult(targetPeerId: targetPeerId, success: true), to: senderEndpoint)
        } catch {
            logger.error("Relay forward to \(targetPeerId.prefix(8))... failed: \(error)")
            try? await send(.relayForwardResult(targetPeerId: targetPeerId, success: false), to: senderEndpoint)
        }
    }

    /// Attempt direct connection to a peer if message appears to have been relayed
    /// Called after receiving any message to establish direct bidirectional paths
    private func attemptDirectConnectionIfNeeded(fromPeerId: PeerId, sourceEndpoint: String) async {
        // Don't try to connect to ourselves
        guard fromPeerId != peerId else { return }

        // Get sender's known NAT type
        let senderNATType = await endpointManager.getNATType(peerId: fromPeerId) ?? .unknown

        // Only attempt direct connection if sender is NOT behind symmetric NAT
        // Symmetric NAT requires relay because their port mapping changes per destination
        if senderNATType == .symmetric {
            logger.debug("Not attempting direct connection to \(fromPeerId.prefix(8))... - symmetric NAT")
            return
        }

        // Get sender's known endpoints
        let knownEndpoints = await endpointManager.getAllEndpoints(peerId: fromPeerId)

        // If the source endpoint is NOT in our known endpoints for this peer,
        // the message likely came via relay. Try to establish direct connection.
        if !knownEndpoints.contains(sourceEndpoint) && !knownEndpoints.isEmpty {
            // We have a different endpoint for this peer - message was relayed
            // Try pinging their known endpoint to establish direct path
            if let directEndpoint = knownEndpoints.first {
                logger.info("Relayed message detected from \(fromPeerId.prefix(8))... - attempting direct connection to \(directEndpoint)")

                // Send ping to establish direct bidirectional communication
                // Use a background task to avoid blocking message processing
                Task {
                    let _ = await self.sendPing(to: fromPeerId, timeout: 5.0)
                }
            }
        }

        // If we received directly (sourceEndpoint IS in knownEndpoints), no action needed
        // The direct path is already working
    }

    /// Send a message via relay to a peer behind symmetric NAT
    /// Uses the most recently contacted relay that knows the target peer
    /// - Parameters:
    ///   - message: Message to send
    ///   - targetPeerId: Target peer ID
    ///   - channel: Channel for routing (default: empty for internal mesh messages)
    public func sendViaRelay(_ message: MeshMessage, to targetPeerId: PeerId, channel: String = "") async throws {
        // Get potential relays for this symmetric NAT peer
        let relays = getPotentialRelays(for: targetPeerId)
        guard !relays.isEmpty else {
            logger.warning("sendViaRelay: No potential relays for \(targetPeerId.prefix(8))...")
            throw MeshNodeError.noRelayAvailable
        }

        // Create the envelope we want to send to the target
        let envelope = try MeshEnvelope.signed(
            from: identity,
            machineId: machineId,
            to: targetPeerId,
            channel: channel,
            payload: message
        )

        // Encode using v2 wire format (inner payload for relay)
        let encryptedPayload = try envelope.encodeV2(networkKey: config.encryptionKey)

        // Try relays in order (most recent first)
        for relay in relays {
            guard let relayEndpoint = await endpointManager.getAllEndpoints(peerId: relay.relayPeerId).first else {
                continue
            }

            logger.info("Sending via relay \(relay.relayPeerId.prefix(8))... to \(targetPeerId.prefix(8))... [channel: \(channel.isEmpty ? "<mesh>" : channel)]")
            try await send(.relayForward(targetPeerId: targetPeerId, payload: encryptedPayload.data), to: relayEndpoint)
            return // Successfully sent to relay
        }

        throw MeshNodeError.noRelayAvailable
    }

    /// Send a self-announcement to a specific endpoint
    /// This is used during bootstrap to introduce ourselves before sending pings
    /// The announcement is self-authenticating (contains our public key)
    public func announceTo(endpoint: Endpoint) async {
        // Determine our reachability
        var reachability: [ReachabilityPath] = []
        if let boundPort = await socket.port {
            // We don't know our public IP, but we can be reached on our bound port
            // The receiver will use the source address of the UDP packet
            reachability.append(.direct(endpoint: "0.0.0.0:\(boundPort)"))
        }

        // Create signed announcement
        do {
            var capabilities: [String] = []
            if config.canRelay { capabilities.append("relay") }
            if config.canCoordinateHolePunch { capabilities.append("holePunchCoordinator") }
            let announcement = try Gossip.createAnnouncement(
                identity: identity,
                reachability: reachability,
                capabilities: capabilities
            )

            // Send as peerInfo message (self-authenticating)
            try await send(.peerInfo(announcement), to: endpoint)
            logger.info("Sent announcement to \(endpoint) (peerId=\(identity.peerId))")
        } catch {
            logger.error("Failed to send announcement: \(error)")
        }
    }

    /// Announce to all known peers (bootstrap introduction)
    public func announceToAllPeers() async {
        for peerId in await endpointManager.allPeerIds {
            guard peerId != self.peerId else { continue }
            guard let endpoint = await endpointManager.getAllEndpoints(peerId: peerId).first else {
                continue
            }
            await announceTo(endpoint: endpoint)
        }
    }

    /// Send a message to a peer by ID (NAT-aware routing)
    /// Automatically routes via relay for symmetric NAT peers, direct otherwise
    public func sendToPeer(_ message: MeshMessage, peerId: PeerId) async throws {
        // Check peer's NAT type for routing decision
        let peerNATType = await endpointManager.getNATType(peerId: peerId) ?? .unknown

        // Symmetric NAT peers require relay (their port mapping changes per destination)
        if peerNATType == .symmetric {
            let relays = getPotentialRelays(for: peerId)
            if !relays.isEmpty {
                logger.info("sendToPeer: Routing to symmetric NAT peer \(peerId.prefix(16))... via relay")
                try await sendViaRelay(message, to: peerId)
                return
            }
            // Fall through to try direct if no relays available
            logger.warning("sendToPeer: Symmetric NAT peer \(peerId.prefix(16))... but no relays, trying direct")
        }

        // Direct send for non-symmetric NAT peers (or fallback for symmetric)
        let endpoints = await endpointManager.getAllEndpoints(peerId: peerId)
        guard !endpoints.isEmpty else {
            logger.warning("sendToPeer: No endpoints found for peer \(peerId.prefix(16))...")
            throw MeshNodeError.peerNotFound
        }

        logger.info("sendToPeer: Sending to \(peerId.prefix(16))... via \(endpoints[0])")
        // For fire-and-forget sends, try the best endpoint only
        // Use sendToPeerWithFallback for request-response patterns
        try await send(message, to: endpoints[0])
    }

    /// Send to peer with fallback through multiple endpoints
    ///
    /// Tries endpoints in priority order (best first) until one succeeds.
    /// On success, promotes the working endpoint to highest priority.
    ///
    /// - Parameters:
    ///   - message: The message to send
    ///   - peerId: Target peer ID
    ///   - machineId: Target machine ID
    ///   - timeout: Timeout per endpoint attempt
    /// - Returns: The response message
    /// - Throws: MeshNodeError.peerNotFound if no endpoints, last error if all fail
    public func sendToPeerWithFallback(
        _ message: MeshMessage,
        peerId: PeerId,
        machineId: MachineId,
        timeout: TimeInterval = 5.0
    ) async throws -> MeshMessage {
        let endpoints = await endpointManager.getEndpoints(peerId: peerId, machineId: machineId)
        guard !endpoints.isEmpty else {
            throw MeshNodeError.peerNotFound
        }

        var lastError: Error = MeshNodeError.peerNotFound

        for endpoint in endpoints {
            do {
                let response = try await sendAndReceive(message, to: endpoint, timeout: timeout)
                // Success - promote this endpoint to highest priority
                await endpointManager.recordSendSuccess(to: peerId, machineId: machineId, endpoint: endpoint)
                return response
            } catch {
                lastError = error
                logger.debug("Send to \(endpoint) failed, trying next: \(error)")
            }
        }

        throw lastError
    }

    /// Set the application message handler
    public func setMessageHandler(_ handler: @escaping (MeshMessage, PeerId) async -> Void) async {
        self.applicationMessageHandler = handler
    }

    // MARK: - Freshness Operations

    /// Query the network for fresh information about a peer
    public func findFreshPeerInfo(_ peerId: PeerId) async -> FreshnessQueryResult {
        await freshnessManager.queryFreshInfo(for: peerId)
    }

    /// Report a connection failure for a peer
    public func reportConnectionFailure(
        to peerId: PeerId,
        via path: ReachabilityPath
    ) async {
        await freshnessManager.reportConnectionFailure(peerId: peerId, path: path)
    }

    /// Check if a path is known to have failed
    public func isPathFailed(_ peerId: PeerId, path: ReachabilityPath) async -> Bool {
        await freshnessManager.isPathFailed(peerId: peerId, path: path)
    }

    /// Get recent contacts
    public var recentContacts: [PeerId: RecentContact] {
        get async {
            var result: [PeerId: RecentContact] = [:]
            for contact in await freshnessManager.recentContacts.allContacts {
                result[contact.peerId] = contact
            }
            return result
        }
    }

    // MARK: - Hole Punch Operations

    /// Establish a direct connection to a peer via hole punching
    public func establishDirectConnection(to targetPeerId: PeerId) async -> HolePunchResult {
        await holePunchManager.establishDirectConnection(to: targetPeerId)
    }

    /// Update our known NAT type
    public func updateNATType(_ natType: NATType) async {
        await holePunchManager.updateNATType(natType)
    }

    /// Send a ping to a peer and wait for pong response
    /// Returns true if pong received, false if timeout or error
    public func sendPing(to targetPeerId: PeerId, timeout: TimeInterval = 3.0, requestFullList: Bool = false) async -> Bool {
        let result = await sendPingWithDetails(to: targetPeerId, timeout: timeout, requestFullList: requestFullList)
        return result != nil
    }

    /// Send a ping to a peer and return detailed results including gossip info
    /// - Parameters:
    ///   - targetPeerId: The peer to ping
    ///   - timeout: Timeout in seconds
    ///   - requestFullList: If true, request the peer's full peer list (for bootstrap/reconnection)
    /// - Returns: PingResult with latency and gossip info, or nil if failed
    public func sendPingWithDetails(to targetPeerId: PeerId, timeout: TimeInterval = 3.0, requestFullList: Bool = false) async -> PingResult? {
        // Get the endpoint for this peer
        let allEndpoints = await endpointManager.getAllEndpoints(peerId: targetPeerId)
        guard let endpoint = allEndpoints.first else {
            logger.debug("sendPing: No endpoint for peer \(targetPeerId)")
            return nil
        }

        // Log endpoint selection for debugging (helps diagnose IPv4/IPv6 mismatch issues)
        if allEndpoints.count > 1 {
            logger.debug("sendPing: Selected endpoint \(endpoint) from \(allEndpoints.count) available for \(targetPeerId.prefix(8))...")
        }

        // Build our recentPeers to send (with machineId and NAT type)
        // Pass currentEndpoint to advertise IPv6 if we're on IPv4
        let peerInfoList = await buildPeerEndpointInfoList(currentEndpoint: endpoint)
        let sentPeers = Array(peerInfoList.prefix(5))
        let myNATType = await getPredictedNATType().type
        let ping = MeshMessage.ping(recentPeers: sentPeers, myNATType: myNATType, requestFullList: requestFullList)

        let startTime = Date()
        do {
            let response = try await sendAndReceive(ping, to: endpoint, timeout: timeout)
            if case .pong(let receivedPeers, let yourEndpoint, let theirNATType) = response {
                let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)
                logger.info("Received pong from \(targetPeerId.prefix(8))... with \(receivedPeers.count) peers, ourEndpoint=\(yourEndpoint)")

                // Update our observed endpoint for NAT prediction
                await updateObservedEndpoint(yourEndpoint, reportedBy: targetPeerId)

                // Track sender's NAT type
                await endpointManager.updateNATType(peerId: targetPeerId, natType: theirNATType)

                // Learn new peers from gossip
                var newPeers: [PeerEndpointInfo] = []
                for peerInfo in receivedPeers where peerInfo.peerId != identity.peerId {
                    let existingEndpoints = await endpointManager.getAllEndpoints(peerId: peerInfo.peerId)
                    let isNewlyLearnedPeer = existingEndpoints.isEmpty

                    // Record this peer's endpoint
                    await endpointManager.recordMessageReceived(
                        from: peerInfo.peerId,
                        machineId: peerInfo.machineId,
                        endpoint: peerInfo.endpoint
                    )

                    // Track their NAT type from gossip
                    await endpointManager.updateNATType(peerId: peerInfo.peerId, natType: peerInfo.natType)

                    if isNewlyLearnedPeer {
                        logger.info("Learned NEW peer \(peerInfo.peerId.prefix(16))... at \(peerInfo.endpoint) from pong")
                        newPeers.append(peerInfo)
                    } else if !existingEndpoints.contains(peerInfo.endpoint) {
                        logger.info("Learned NEW endpoint for \(peerInfo.peerId.prefix(16))...: \(peerInfo.endpoint) (had: \(existingEndpoints.first ?? "none"))")
                        newPeers.append(peerInfo)
                    }
                }

                // Record this as a recent contact
                await freshnessManager.recordContact(
                    peerId: targetPeerId,
                    reachability: .direct(endpoint: endpoint),
                    latencyMs: latencyMs,
                    connectionType: .direct
                )

                // In forceRelayOnly mode, add any responsive peer as a potential relay
                // This enables testing relay code paths on LAN where direct connectivity exists
                if config.forceRelayOnly && !connectedRelays.contains(targetPeerId) {
                    connectedRelays.insert(targetPeerId)
                    logger.info("forceRelayOnly: Added \(targetPeerId.prefix(16))... as connected relay")
                }

                // Log latency sample
                await eventLogger?.recordLatencySample(peerId: targetPeerId, latencyMs: Double(latencyMs))

                // Note: Keepalive monitoring is handled in handleIncomingData when pong is received
                // This ensures we have the machineId from the response envelope

                return PingResult(
                    peerId: targetPeerId,
                    endpoint: endpoint,
                    latencyMs: latencyMs,
                    sentPeers: sentPeers,
                    receivedPeers: receivedPeers,
                    newPeers: newPeers
                )
            }
            return nil
        } catch {
            logger.warning("sendPing: Failed to ping \(targetPeerId.prefix(8))... at \(endpoint): \(error)")

            // Log latency loss
            await eventLogger?.recordLatencyLoss(peerId: targetPeerId)

            return nil
        }
    }

    /// Ping a specific machine by MachineId. Used when multiple machines share a PeerId.
    /// - Parameters:
    ///   - machineId: The machine to ping
    ///   - timeout: Timeout in seconds
    ///   - requestFullList: If true, request the peer's full peer list (for bootstrap/reconnection)
    /// - Returns: PingResult with latency and gossip info, or nil if failed
    public func sendPingWithDetails(toMachine machineId: MachineId, timeout: TimeInterval = 3.0, requestFullList: Bool = false) async -> PingResult? {
        // Look up peerId from registry
        guard let peerId = await machinePeerRegistry.getMostRecentPeer(for: machineId) else {
            logger.debug("sendPing: No peer found for machine \(machineId)")
            return nil
        }

        // Get endpoints for this specific machine (not all machines for the peer)
        let endpoints = await endpointManager.getEndpoints(peerId: peerId, machineId: machineId)
        guard let endpoint = EndpointUtils.preferredEndpoint(from: endpoints) else {
            logger.debug("sendPing: No endpoint for machine \(machineId) (peer \(peerId))")
            return nil
        }

        // Log endpoint selection for debugging
        if endpoints.count > 1 {
            logger.debug("sendPing: Selected endpoint \(endpoint) from \(endpoints.count) available for machine \(machineId)")
        }

        // Build our recentPeers to send (with machineId and NAT type)
        let peerInfoList = await buildPeerEndpointInfoList(currentEndpoint: endpoint)
        let sentPeers = Array(peerInfoList.prefix(5))
        let myNATType = await getPredictedNATType().type
        let ping = MeshMessage.ping(recentPeers: sentPeers, myNATType: myNATType, requestFullList: requestFullList)

        let startTime = Date()
        do {
            let response = try await sendAndReceive(ping, to: endpoint, timeout: timeout)
            if case .pong(let receivedPeers, let yourEndpoint, let theirNATType) = response {
                let latencyMs = Int(Date().timeIntervalSince(startTime) * 1000)
                logger.info("Received pong from machine \(machineId) (peer \(peerId.prefix(8))...) with \(receivedPeers.count) peers, ourEndpoint=\(yourEndpoint)")

                // Update our observed endpoint for NAT prediction
                await updateObservedEndpoint(yourEndpoint, reportedBy: peerId)

                // Track sender's NAT type
                await endpointManager.updateNATType(peerId: peerId, natType: theirNATType)

                // Learn new peers from gossip
                var newPeers: [PeerEndpointInfo] = []
                for peerInfo in receivedPeers where peerInfo.peerId != identity.peerId {
                    let existingEndpoints = await endpointManager.getAllEndpoints(peerId: peerInfo.peerId)
                    let isNewlyLearnedPeer = existingEndpoints.isEmpty

                    await endpointManager.recordMessageReceived(
                        from: peerInfo.peerId,
                        machineId: peerInfo.machineId,
                        endpoint: peerInfo.endpoint
                    )

                    await endpointManager.updateNATType(peerId: peerInfo.peerId, natType: peerInfo.natType)

                    if isNewlyLearnedPeer {
                        logger.info("Learned NEW peer \(peerInfo.peerId.prefix(16))... at \(peerInfo.endpoint) from pong")
                        newPeers.append(peerInfo)
                    } else if !existingEndpoints.contains(peerInfo.endpoint) {
                        logger.info("Learned NEW endpoint for \(peerInfo.peerId.prefix(16))...: \(peerInfo.endpoint) (had: \(existingEndpoints.first ?? "none"))")
                        newPeers.append(peerInfo)
                    }
                }

                // Record this as a recent contact
                await freshnessManager.recordContact(
                    peerId: peerId,
                    reachability: .direct(endpoint: endpoint),
                    latencyMs: latencyMs,
                    connectionType: .direct
                )

                // In forceRelayOnly mode, add any responsive peer as a potential relay
                if config.forceRelayOnly && !connectedRelays.contains(peerId) {
                    connectedRelays.insert(peerId)
                    logger.info("forceRelayOnly: Added \(peerId.prefix(16))... as connected relay")
                }

                // Log latency sample
                await eventLogger?.recordLatencySample(peerId: peerId, latencyMs: Double(latencyMs))

                return PingResult(
                    peerId: peerId,
                    endpoint: endpoint,
                    latencyMs: latencyMs,
                    sentPeers: sentPeers,
                    receivedPeers: receivedPeers,
                    newPeers: newPeers
                )
            }
            return nil
        } catch {
            logger.warning("sendPing: Failed to ping machine \(machineId) (peer \(peerId.prefix(8))...) at \(endpoint): \(error)")
            await eventLogger?.recordLatencyLoss(peerId: peerId)
            return nil
        }
    }

    // MARK: - Keepalive Management

    /// Add a direct connection to keepalive monitoring
    public func addToKeepalive(peerId: PeerId, endpoint: String) async {
        await connectionKeepalive.addConnection(peerId: peerId, endpoint: endpoint)
    }

    /// Remove a connection from keepalive monitoring
    public func removeFromKeepalive(peerId: PeerId) async {
        await connectionKeepalive.removeConnection(peerId: peerId)
    }

    /// Check if a peer is being monitored for keepalive
    public func isMonitoringKeepalive(peerId: PeerId) async -> Bool {
        await connectionKeepalive.isMonitoring(peerId: peerId)
    }

    /// Get keepalive statistics
    public func keepaliveStatistics() async -> ConnectionKeepalive.Statistics {
        await connectionKeepalive.statistics
    }

    /// Get all connections being monitored for keepalive
    public func monitoredConnections() async -> [ConnectionKeepalive.ConnectionState] {
        await connectionKeepalive.monitoredConnections
    }

    // MARK: - Helpers

    /// Check if we have direct contact with a machine (first-hand knowledge)
    public func hasDirectContact(with machineId: MachineId) -> Bool {
        directContacts.contains(machineId)
    }

    /// Build a list of peer endpoint info for gossip (includes machineId, natType, and isFirstHand)
    /// - Parameter currentEndpoint: The endpoint we're currently communicating over (to check if IPv6 upgrade should be advertised)
    /// If we have an IPv6 endpoint AND are currently communicating over IPv4, includes ourselves to enable upgrade
    func buildPeerEndpointInfoList(currentEndpoint: String? = nil) async -> [PeerEndpointInfo] {
        var result: [PeerEndpointInfo] = []

        // Include ourselves with IPv6 endpoint for upgrade path
        // Only if we're currently on IPv4 (otherwise they already have our IPv6)
        let isCurrentlyIPv4 = currentEndpoint.map { !EndpointUtils.isIPv6($0) } ?? true
        if isCurrentlyIPv4, let ipv6Endpoint = observedIPv6Endpoint {
            let myNATType = await getPredictedNATType().type
            result.append(PeerEndpointInfo(
                peerId: peerId,
                machineId: machineId,
                endpoint: ipv6Endpoint,
                natType: myNATType,
                isFirstHand: true  // We know ourselves first-hand!
            ))
        }

        for peerId in await endpointManager.allPeerIds {
            guard peerId != self.peerId else { continue }
            let natType = await endpointManager.getNATType(peerId: peerId) ?? .unknown
            for machine in await endpointManager.getAllMachines(peerId: peerId) {
                if let endpoint = machine.bestEndpoint {
                    // Set isFirstHand based on whether we have direct contact with this machine
                    let isFirstHand = directContacts.contains(machine.machineId)
                    result.append(PeerEndpointInfo(
                        peerId: machine.peerId,
                        machineId: machine.machineId,
                        endpoint: endpoint,
                        natType: natType,
                        isFirstHand: isFirstHand
                    ))
                }
            }
            if result.count >= 10 { break }
        }
        return result
    }

    /// Build peer list including propagation queue items, decrementing their counts
    /// Used for regular keepalive responses to existing peers (delta gossip)
    /// - Parameters:
    ///   - excludePeerId: Peer ID to exclude from the list
    ///   - currentEndpoint: The endpoint we're currently communicating over
    /// If we have an IPv6 endpoint AND are currently on IPv4, includes ourselves for upgrade
    func buildPeerEndpointInfoListWithPropagation(excluding excludePeerId: PeerId, currentEndpoint: String? = nil) async -> [PeerEndpointInfo] {
        var result: [PeerEndpointInfo] = []

        // Include ourselves with IPv6 endpoint for upgrade path
        // Only if we're currently on IPv4
        let isCurrentlyIPv4 = currentEndpoint.map { !EndpointUtils.isIPv6($0) } ?? true
        if isCurrentlyIPv4, let ipv6Endpoint = observedIPv6Endpoint {
            let myNATType = await getPredictedNATType().type
            result.append(PeerEndpointInfo(
                peerId: peerId,
                machineId: machineId,
                endpoint: ipv6Endpoint,
                natType: myNATType,
                isFirstHand: true
            ))
        }

        // Add known peers (up to 5)
        for peerId in await endpointManager.allPeerIds {
            guard peerId != self.peerId else { continue }
            let natType = await endpointManager.getNATType(peerId: peerId) ?? .unknown
            for machine in await endpointManager.getAllMachines(peerId: peerId) {
                if let endpoint = machine.bestEndpoint {
                    // Set isFirstHand based on whether we have direct contact with this machine
                    let isFirstHand = directContacts.contains(machine.machineId)
                    result.append(PeerEndpointInfo(
                        peerId: machine.peerId,
                        machineId: machine.machineId,
                        endpoint: endpoint,
                        natType: natType,
                        isFirstHand: isFirstHand
                    ))
                }
            }
            if result.count >= 5 { break }
        }

        // Add propagation queue items (gossip) - don't include the peer we're sending to
        var keysToRemove: [PeerId] = []
        for (key, var item) in peerPropagationQueue {
            guard item.info.peerId != excludePeerId else { continue }

            // Add to result if not already present
            if !result.contains(where: { $0.peerId == item.info.peerId }) {
                result.append(item.info)
                logger.debug("Gossiping peer \(item.info.peerId.prefix(8))... (count: \(item.count - 1) remaining)")
            }

            // Decrement count
            item.count -= 1
            if item.count <= 0 {
                keysToRemove.append(key)
            } else {
                peerPropagationQueue[key] = item
            }
        }

        // Remove exhausted items
        for key in keysToRemove {
            peerPropagationQueue.removeValue(forKey: key)
        }

        return result
    }

    /// Add peer info to the gossip propagation queue
    func addToPropagationQueue(_ peerInfo: PeerEndpointInfo) {
        // Don't add ourselves
        guard peerInfo.peerId != self.peerId else { return }

        // Don't add if already in queue (but could update endpoint)
        if peerPropagationQueue[peerInfo.peerId] != nil {
            // Update with fresh info but keep existing count
            let existingCount = peerPropagationQueue[peerInfo.peerId]!.count
            peerPropagationQueue[peerInfo.peerId] = (info: peerInfo, count: existingCount)
            return
        }

        peerPropagationQueue[peerInfo.peerId] = (info: peerInfo, count: gossipFanout)
        logger.info("Added peer \(peerInfo.peerId.prefix(8))... to gossip queue (fanout: \(gossipFanout))")
    }

    /// Set propagation count for a peer (internal for testing)
    func setPropagationCount(for peerId: PeerId, count: Int) {
        guard var item = peerPropagationQueue[peerId] else { return }
        item.count = count
        peerPropagationQueue[peerId] = item
    }

    /// Get propagation count for a peer (internal for testing)
    func getPropagationCount(for peerId: PeerId) -> Int? {
        peerPropagationQueue[peerId]?.count
    }

    /// Get propagation info for a peer (internal for testing)
    func getPropagationInfo(for peerId: PeerId) -> PeerEndpointInfo? {
        peerPropagationQueue[peerId]?.info
    }

    /// Get propagation queue size (internal for testing)
    var propagationQueueCount: Int {
        peerPropagationQueue.count
    }

    // MARK: - Message Deduplication

    /// Mark a message ID as seen
    private func markMessageSeen(_ messageId: String) {
        seenMessageIds.insert(messageId)

        // Prune if too large
        if seenMessageIds.count > maxSeenMessages {
            let toRemove = seenMessageIds.prefix(maxSeenMessages / 2)
            for id in toRemove {
                seenMessageIds.remove(id)
            }
        }
    }

    /// Check if a message has been seen
    public func hasSeenMessage(_ messageId: String) -> Bool {
        seenMessageIds.contains(messageId)
    }

    /// Register a peer's public key (for testing and bootstrap)
    /// Receive an envelope directly (for testing)
    /// Verifies signature using embedded public key
    public func receiveEnvelope(_ envelope: MeshEnvelope) async -> Bool {
        // Verify signature using embedded public key (also verifies peer ID derivation)
        guard envelope.verifySignature() else {
            logger.warning("Rejected message with invalid signature from \(envelope.fromPeerId.prefix(8))...")
            return false
        }

        // Check for duplicates
        if seenMessageIds.contains(envelope.messageId) {
            return false
        }
        markMessageSeen(envelope.messageId)

        return true
    }

    // MARK: - Utilities

    /// Format a SocketAddress as "host:port" string
    private nonisolated func formatEndpoint(_ address: NIOCore.SocketAddress) -> String {
        guard let port = address.port else {
            return "\(address)"
        }
        switch address {
        case .v4(let addr):
            return "\(addr.host):\(port)"
        case .v6(let addr):
            return "[\(addr.host)]:\(port)"
        case .unixDomainSocket:
            return "unix:\(address)"
        }
    }
}

/// Errors from MeshNode operations
public enum MeshNodeError: Error, CustomStringConvertible {
    case stopped
    case timeout
    case peerNotFound
    case sendFailed(Error)
    case noRelayAvailable
    case invalidChannel(String)

    public var description: String {
        switch self {
        case .stopped:
            return "Node has stopped"
        case .timeout:
            return "Request timed out"
        case .peerNotFound:
            return "Peer not found"
        case .sendFailed(let error):
            return "Send failed: \(error)"
        case .noRelayAvailable:
            return "No relay available for symmetric NAT peer"
        case .invalidChannel(let channel):
            return "Invalid channel '\(channel)': must be max 64 chars, alphanumeric/-/_ only"
        }
    }
}

// MARK: - MeshNodeServices Conformance

extension MeshNode: MeshNodeServices {
    public func send(_ message: MeshMessage, to peerId: PeerId, strategy: RoutingStrategy) async throws {
        switch strategy {
        case .direct(let endpoint):
            try await send(message, to: endpoint)
        case .auto:
            try await sendWithAutoRouting(message, to: peerId)
        case .relay(let relayPeerId):
            try await sendViaSpecificRelay(message, to: peerId, via: relayPeerId)
        }
    }

    public func getEndpoint(for peerId: PeerId) async -> Endpoint? {
        // Get all endpoints and prefer IPv6 using EndpointUtils
        EndpointUtils.preferredEndpoint(from: await endpointManager.getAllEndpoints(peerId: peerId))
    }

    public func getEndpoint(peerId: PeerId, machineId: MachineId) async -> Endpoint? {
        await endpointManager.getBestEndpoint(peerId: peerId, machineId: machineId)
    }

    // getNATType(for:) is already declared in MeshNode, so we don't need to redeclare it

    public var allPeerIds: [PeerId] {
        get async { await endpointManager.allPeerIds }
    }

    public func getCoordinatorPeerId() async -> PeerId? {
        // Return first connected relay as coordinator (they have public IPs)
        if let relay = await getConnectedRelays().first {
            return relay
        }
        // Fall back to first known peer with reachable NAT type
        for peerId in await endpointManager.allPeerIds {
            if let natType = await endpointManager.getNATType(peerId: peerId),
               natType.isDirectlyReachable {
                return peerId
            }
        }
        return await endpointManager.allPeerIds.first
    }

    public func invalidateCache(peerId: PeerId, path: ReachabilityPath) async {
        // Log the cache invalidation request
        logger.debug("Cache invalidation requested for \(peerId) via \(path)")
    }

    public func sendPing(peerId: PeerId, machineId: MachineId, endpoint: Endpoint) async -> Bool {
        await sendPingToEndpoint(peerId: peerId, endpoint: endpoint, timeout: 5.0)
    }

    public func handleKeepaliveFailure(peerId: PeerId, machineId: MachineId, endpoint: Endpoint) async {
        await handleKeepaliveConnectionFailure(peerId: peerId, machineId: machineId, endpoint: endpoint)
    }

    // MARK: - Auto-routing

    /// Send a message with automatic routing strategy
    /// Priority: IPv6 > direct (if reachable) > relay
    /// When forceRelayOnly is enabled, skips direct attempts and always uses relay
    /// - Parameters:
    ///   - message: Message to send
    ///   - peerId: Target peer ID
    ///   - channel: Channel for routing (default: empty for internal mesh messages)
    private func sendWithAutoRouting(_ message: MeshMessage, to peerId: PeerId, channel: String = "") async throws {
        // Helper to get best endpoint for peer (across all machines)
        func getBestPeerEndpoint() async -> Endpoint? {
            EndpointUtils.preferredEndpoint(from: await endpointManager.getAllEndpoints(peerId: peerId))
        }

        // When forceRelayOnly is enabled, skip all direct attempts and use relay
        if config.forceRelayOnly {
            logger.debug("forceRelayOnly: Skipping direct send, using relay for \(peerId.prefix(16))...")

            // Try potential relays first
            let potentialRelays = getPotentialRelays(for: peerId)
            if !potentialRelays.isEmpty {
                try await sendViaRelay(message, to: peerId, channel: channel)
                return
            }

            // Try connected relays
            if let relay = connectedRelays.first {
                try await sendViaSpecificRelay(message, to: peerId, via: relay, channel: channel)
                return
            }

            // No relays available
            logger.warning("forceRelayOnly: No relays available for \(peerId.prefix(16))...")
            throw MeshNodeError.noRelayAvailable
        }

        // Normal routing: 1. Try IPv6 first (always works, no NAT)
        if let endpoint = await getBestPeerEndpoint(),
           EndpointUtils.isIPv6(endpoint) {
            try await send(message, to: endpoint, channel: channel)
            return
        }

        // 2. Try direct if peer is reachable
        let peerNATType = await endpointManager.getNATType(peerId: peerId) ?? .unknown
        if peerNATType.isDirectlyReachable,
           let endpoint = await getBestPeerEndpoint() {
            try await send(message, to: endpoint, channel: channel)
            return
        }

        // 3. Fall back to relay (uses existing sendViaRelay which finds best relay)
        let potentialRelays = getPotentialRelays(for: peerId)
        if !potentialRelays.isEmpty {
            try await sendViaRelay(message, to: peerId, channel: channel)
            return
        }

        // 4. Try connected relays
        if let relay = connectedRelays.first {
            try await sendViaSpecificRelay(message, to: peerId, via: relay, channel: channel)
            return
        }

        // 5. Last resort: try direct anyway
        if let endpoint = await getBestPeerEndpoint() {
            try await send(message, to: endpoint, channel: channel)
            return
        }

        throw MeshNodeError.peerNotFound
    }

    /// Send via a specific relay peer (for MeshNodeServices.send with .relay strategy)
    /// - Parameters:
    ///   - message: Message to send
    ///   - targetPeerId: Target peer ID
    ///   - relayPeerId: Relay peer to route through
    ///   - channel: Channel for routing (default: empty for internal mesh messages)
    private func sendViaSpecificRelay(_ message: MeshMessage, to targetPeerId: PeerId, via relayPeerId: PeerId, channel: String = "") async throws {
        guard let relayEndpoint = await endpointManager.getAllEndpoints(peerId: relayPeerId).first else {
            throw MeshNodeError.noRelayAvailable
        }

        // Create the envelope we want to send to the target
        let envelope = try MeshEnvelope.signed(
            from: identity,
            machineId: machineId,
            to: targetPeerId,
            channel: channel,
            payload: message
        )

        // Encode using v2 wire format (inner payload for relay)
        let encryptedPayload = try envelope.encodeV2(networkKey: config.encryptionKey)

        logger.info("Sending via relay \(relayPeerId.prefix(8))... to \(targetPeerId.prefix(8))... [channel: \(channel.isEmpty ? "<mesh>" : channel)]")
        try await send(.relayForward(targetPeerId: targetPeerId, payload: encryptedPayload.data), to: relayEndpoint)
    }

    // MARK: - Channel System

    /// Register a handler for a channel
    /// Any queued messages for this channel will be delivered immediately
    /// - Parameters:
    ///   - channel: Channel name to listen on (max 64 chars, alphanumeric/-/_)
    ///   - handler: Async handler that receives (fromMachineId, data). Use machinePeerRegistry to look up peerId if needed.
    /// - Throws: MeshNodeError.invalidChannel if channel name is invalid or hash collides with existing channel
    public func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        guard ChannelUtils.isValid(channel) else {
            throw MeshNodeError.invalidChannel(channel)
        }

        let hash = ChannelHash.hash(channel)

        // Check for hash collision with existing handler
        if let existing = channelHandlers[hash], existing.name != channel {
            logger.error("Channel hash collision: '\(channel)' collides with existing '\(existing.name)'")
            throw MeshNodeError.invalidChannel("\(channel) (hash collision with '\(existing.name)')")
        }

        channelHandlers[hash] = (name: channel, handler: handler)

        // Deliver any queued messages for this channel
        if var queue = channelQueues.removeValue(forKey: hash) {
            // Filter out expired messages (v2 wire format uses hash-only matching)
            let now = Date()
            queue = queue.filter {
                now.timeIntervalSince($0.timestamp) < queuedMessageMaxAge
            }

            if !queue.isEmpty {
                logger.debug("Delivering \(queue.count) queued message(s) for channel '\(channel)'")

                for message in queue {
                    await handler(message.from, message.data)
                }
            }
        }
    }

    /// Unregister a handler for a channel
    /// - Parameter channel: Channel name to stop listening on
    public func offChannel(_ channel: String) {
        let hash = ChannelHash.hash(channel)
        channelHandlers.removeValue(forKey: hash)
        // Also clear the queue for this channel
        channelQueues.removeValue(forKey: hash)
    }

    /// Send data on a channel to a peer
    /// Uses auto-routing (IPv6 > direct > relay fallback)
    /// When a peer has multiple machines, this sends to all of them.
    /// - Parameters:
    ///   - data: Data to send
    ///   - peerId: Target peer ID
    ///   - channel: Channel name
    /// - Throws: MeshNodeError.invalidChannel if channel name is invalid
    public func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        guard ChannelUtils.isValid(channel) else {
            throw MeshNodeError.invalidChannel(channel)
        }
        let message = MeshMessage.data(data)
        try await sendWithAutoRouting(message, to: peerId, channel: channel)
    }

    /// Send data on a channel to a specific machine
    /// Uses the endpoints known for that specific machine.
    /// - Parameters:
    ///   - data: Data to send
    ///   - machineId: Target machine ID
    ///   - channel: Channel name
    /// - Throws: MeshNodeError.invalidChannel if channel name is invalid, MeshNodeError.peerNotFound if no endpoints known
    public func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        guard ChannelUtils.isValid(channel) else {
            throw MeshNodeError.invalidChannel(channel)
        }

        // Look up the peer for this machine
        guard let peerId = await machinePeerRegistry.getMostRecentPeer(for: machineId) else {
            throw MeshNodeError.peerNotFound
        }

        // Get endpoints specifically for this machine
        let endpoints = await endpointManager.getEndpoints(peerId: peerId, machineId: machineId)
        guard let endpoint = EndpointUtils.preferredEndpoint(from: endpoints) else {
            throw MeshNodeError.peerNotFound
        }

        let message = MeshMessage.data(data)
        try await send(message, to: endpoint, channel: channel)
    }

    /// Handle incoming message on a channel (string-based, for v1 compatibility)
    /// Called by handleIncomingData when a message arrives with a non-empty channel
    /// Uses hash-based lookup for O(1) routing with collision verification
    internal func handleChannelMessage(from machineId: MachineId, channel: String, data: Data) async {
        let hash = ChannelHash.hash(channel)
        await handleChannelMessageByHash(from: machineId, channelHash: hash, data: data)
    }

    /// Handle incoming message on a channel by hash (for v2 wire format)
    /// Used directly when decoding v2 envelopes which only contain the hash
    internal func handleChannelMessageByHash(from machineId: MachineId, channelHash: UInt16, data: Data) async {
        if let entry = channelHandlers[channelHash] {
            // Handler registered - deliver immediately
            await entry.handler(machineId, data)
        } else {
            // No handler - queue the message
            queueChannelMessage(from: machineId, channelHash: channelHash, data: data)
        }
    }

    /// Queue a message for a channel that doesn't have a handler registered yet
    private func queueChannelMessage(from machineId: MachineId, channelHash: UInt16, data: Data) {
        var queue = channelQueues[channelHash] ?? []

        // Enforce queue size limit
        if queue.count >= maxQueuedMessagesPerChannel {
            // Drop oldest message
            queue.removeFirst()
            logger.warning("Channel queue overflow for hash \(channelHash), dropping oldest message")
        }

        queue.append((from: machineId, data: data, channelHash: channelHash, timestamp: Date()))
        channelQueues[channelHash] = queue

        logger.debug("Queued message for channel hash \(channelHash) (queue size: \(queue.count))")
    }

    // MARK: - Buffered Channel Send

    /// Register a handler with a per-channel batch config override
    public func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        try await onChannel(channel, handler: handler)
        if let config = batchConfig {
            let hash = ChannelHash.hash(channel)
            channelBatchConfigs[hash] = config
        }
    }

    /// Buffer data for batched sending on a channel to a peer
    public func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws {
        guard ChannelUtils.isValid(channel) else {
            throw MeshNodeError.invalidChannel(channel)
        }
        let bufferKey = "\(ChannelHash.hash(channel)):peer:\(peerId)"
        appendToBuffer(bufferKey, data: data, channel: channel)
    }

    /// Buffer data for batched sending on a channel to a specific machine
    public func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        guard ChannelUtils.isValid(channel) else {
            throw MeshNodeError.invalidChannel(channel)
        }
        let bufferKey = "\(ChannelHash.hash(channel)):machine:\(machineId)"
        appendToBuffer(bufferKey, data: data, channel: channel)
    }

    /// Flush all buffered data for a channel
    public func flushChannel(_ channel: String) async throws {
        let hash = ChannelHash.hash(channel)
        let prefix = "\(hash):"
        let keysToFlush = channelSendBuffers.keys.filter { $0.hasPrefix(prefix) }

        for key in keysToFlush {
            try await flushBuffer(key, channel: channel)
        }
    }

    /// Register a batch monitor
    public func registerBatchMonitor(_ monitor: any BatchMonitor) {
        batchMonitors.append(monitor)
    }

    /// Unregister a batch monitor
    public func unregisterBatchMonitor(_ monitor: any BatchMonitor) {
        batchMonitors.removeAll { ($0 as AnyObject) === (monitor as AnyObject) }
    }

    private func appendToBuffer(_ key: String, data: Data, channel: String) {
        var entry = channelSendBuffers[key] ?? (packets: [], totalSize: 0)
        entry.packets.append(data)
        entry.totalSize += data.count
        channelSendBuffers[key] = entry

        // Check buffer size threshold
        let hash = ChannelHash.hash(channel)
        let config = resolvedBatchConfig(channelHash: hash)
        if config.maxBufferSize > 0 && entry.totalSize >= config.maxBufferSize {
            let ch = channel
            Task { try? await self.flushBuffer(key, channel: ch) }
            return
        }

        // Start auto-flush timer if not running
        if channelFlushTasks[key] == nil {
            let delay = config.maxFlushDelay
            let ch = channel
            channelFlushTasks[key] = Task {
                try? await Task.sleep(for: delay)
                guard !Task.isCancelled else { return }
                try? await self.flushBuffer(key, channel: ch)
            }
        }
    }

    private func flushBuffer(_ key: String, channel: String) async throws {
        // Cancel timer
        channelFlushTasks[key]?.cancel()
        channelFlushTasks.removeValue(forKey: key)

        guard let entry = channelSendBuffers.removeValue(forKey: key), !entry.packets.isEmpty else {
            return
        }

        // Pack into batch
        let batchData: Data
        if entry.packets.count == 1 {
            // Single packet — just send the raw data directly
            batchData = entry.packets[0]
        } else {
            // Multiple packets — length-prefix each
            var packed = Data()
            for pkt in entry.packets {
                var len = UInt16(min(pkt.count, Int(UInt16.max))).bigEndian
                packed.append(Data(bytes: &len, count: 2))
                packed.append(pkt)
            }
            batchData = packed
        }

        // Parse key to determine destination type
        let parts = key.split(separator: ":", maxSplits: 2)
        if parts.count >= 3 {
            let destType = String(parts[1])
            let destId = String(parts[2])
            if destType == "peer" {
                try await sendOnChannel(batchData, to: destId, channel: channel)
            } else {
                try await sendOnChannel(batchData, toMachine: destId, channel: channel)
            }
        }
    }

    private func resolvedBatchConfig(channelHash: UInt16) -> BatchConfig {
        // Priority: monitor → channel override → default
        if let channelConfig = channelBatchConfigs[channelHash] {
            return channelConfig
        }
        return .default
    }

    /// Clear expired messages from all channel queues
    /// Called periodically to prevent memory leaks
    internal func cleanupChannelQueues() {
        let now = Date()
        for (hash, queue) in channelQueues {
            let filtered = queue.filter { now.timeIntervalSince($0.timestamp) < queuedMessageMaxAge }
            if filtered.isEmpty {
                channelQueues.removeValue(forKey: hash)
            } else if filtered.count != queue.count {
                channelQueues[hash] = filtered
                logger.debug("Cleaned up \(queue.count - filtered.count) expired message(s) from channel hash \(hash)")
            }
        }
    }
}
