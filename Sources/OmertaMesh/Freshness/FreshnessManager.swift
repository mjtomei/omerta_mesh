// FreshnessManager.swift - Coordinates freshness queries and path failure handling

import Foundation
import Logging

/// Manages peer freshness tracking, queries, and path failure reporting
public actor FreshnessManager {
    /// Configuration for the freshness manager
    public struct Config: Sendable {
        public let recentContactConfig: RecentContactTracker.Config
        public let freshnessQueryConfig: FreshnessQuery.Config
        public let pathFailureConfig: PathFailureReporter.Config

        public init(
            recentContactConfig: RecentContactTracker.Config = .init(),
            freshnessQueryConfig: FreshnessQuery.Config = .init(),
            pathFailureConfig: PathFailureReporter.Config = .init()
        ) {
            self.recentContactConfig = recentContactConfig
            self.freshnessQueryConfig = freshnessQueryConfig
            self.pathFailureConfig = pathFailureConfig
        }

        public static let `default` = Config()
    }

    /// The recent contact tracker
    public let recentContacts: RecentContactTracker

    /// The freshness query handler
    public let freshnessQuery: FreshnessQuery

    /// The path failure reporter
    public let pathFailureReporter: PathFailureReporter

    private let logger: Logger
    private let config: Config

    /// Callback to send messages (deprecated - use setServices)
    private var sendMessage: ((MeshMessage, PeerId?) async -> Void)?

    /// Callback to broadcast messages (deprecated - use setServices)
    private var broadcastMessage: ((MeshMessage, Int) async -> Void)?

    /// Callback to invalidate cache entries (deprecated - use setServices)
    private var invalidateCache: ((PeerId, ReachabilityPath) async -> Void)?

    /// Unified services reference (preferred over individual callbacks)
    private weak var services: (any MeshNodeServices)?

    public init(config: Config = .default) {
        self.config = config
        self.recentContacts = RecentContactTracker(config: config.recentContactConfig)
        self.freshnessQuery = FreshnessQuery(
            recentContacts: recentContacts,
            config: config.freshnessQueryConfig
        )
        self.pathFailureReporter = PathFailureReporter(config: config.pathFailureConfig)
        self.logger = Logger(label: "io.omerta.mesh.freshness.manager")
    }

    // MARK: - Lifecycle

    /// Start the freshness manager
    public func start() async {
        await recentContacts.start()

        // Run cleanup immediately on start (for short-lived daemon sessions)
        await cleanup()

        // Set up path failure handler to invalidate cache
        await pathFailureReporter.onFailure { [weak self] failure in
            await self?.handlePathFailure(failure)
        }

        logger.info("Freshness manager started")
    }

    /// Stop the freshness manager
    public func stop() async {
        await recentContacts.stop()
        logger.info("Freshness manager stopped")
    }

    // MARK: - Configuration

    /// Set callbacks for network operations (deprecated - use setServices)
    public func setCallbacks(
        sendMessage: @escaping (MeshMessage, PeerId?) async -> Void,
        broadcastMessage: @escaping (MeshMessage, Int) async -> Void,
        invalidateCache: @escaping (PeerId, ReachabilityPath) async -> Void
    ) {
        self.sendMessage = sendMessage
        self.broadcastMessage = broadcastMessage
        self.invalidateCache = invalidateCache
    }

    /// Set the unified services reference (preferred over individual callbacks)
    public func setServices(_ services: any MeshNodeServices) {
        self.services = services
    }

    // MARK: - Recording Contacts

    /// Record a successful communication with a peer
    public func recordContact(
        peerId: PeerId,
        reachability: ReachabilityPath,
        latencyMs: Int,
        connectionType: ConnectionType
    ) async {
        await recentContacts.recordContact(
            peerId: peerId,
            reachability: reachability,
            latencyMs: latencyMs,
            connectionType: connectionType
        )
    }

    /// Update last seen time for a peer
    public func touchContact(_ peerId: PeerId) async {
        await recentContacts.touch(peerId)
    }

    // MARK: - Freshness Queries

    /// Query the network for fresh information about a peer
    public func queryFreshInfo(for peerId: PeerId) async -> FreshnessQueryResult {
        // Use services if available, fall back to legacy callback
        if let services = services {
            return await freshnessQuery.query(peerId: peerId) { message, maxHops in
                await services.broadcast(message, maxHops: maxHops)
            }
        }

        guard let broadcast = broadcastMessage else {
            logger.warning("Cannot query: no broadcast callback set")
            return .notFound(peerId)
        }

        return await freshnessQuery.query(peerId: peerId) { message, maxHops in
            await broadcast(message, maxHops)
        }
    }

    /// Check if we have recent contact info for a peer
    public func hasRecentContact(_ peerId: PeerId, maxAgeSeconds: Int = 300) async -> Bool {
        await recentContacts.hasRecentContact(peerId, maxAgeSeconds: maxAgeSeconds)
    }

    /// Get recent contact info for a peer
    public func getRecentContact(_ peerId: PeerId) async -> RecentContact? {
        await recentContacts.getContact(peerId)
    }

    // MARK: - Path Failure Reporting

    /// Report a connection failure to a peer
    /// Note: Path failures are tracked locally only, not broadcast to network
    public func reportConnectionFailure(
        peerId: PeerId,
        path: ReachabilityPath
    ) async {
        // Report locally (returns message but we no longer broadcast it)
        _ = await pathFailureReporter.reportFailure(peerId: peerId, path: path)

        // Invalidate local cache (prefer services)
        if let services = services {
            await services.invalidateCache(peerId: peerId, path: path)
        } else {
            await invalidateCache?(peerId, path)
        }

        // Remove from recent contacts
        await recentContacts.removeContact(peerId)
    }

    /// Check if a path is known to have failed
    public func isPathFailed(peerId: PeerId, path: ReachabilityPath) async -> Bool {
        await pathFailureReporter.isPathFailed(peerId: peerId, path: path)
    }

    /// Get paths that are known to have failed for a peer
    public func failedPaths(for peerId: PeerId) async -> [ReachabilityPath] {
        await pathFailureReporter.failedPaths(for: peerId)
    }

    // MARK: - Message Handling

    /// Handle an incoming freshness-related message
    /// Returns a response message if one should be sent, plus whether to forward
    public func handleMessage(
        _ message: MeshMessage,
        from peerId: PeerId,
        hopCount: Int
    ) async -> (response: MeshMessage?, shouldForward: Bool) {
        switch message {
        case .whoHasRecent(let targetPeerId, let maxAgeSeconds):
            return await handleWhoHasRecent(
                targetPeerId: targetPeerId,
                maxAgeSeconds: maxAgeSeconds,
                hopCount: hopCount
            )

        case .iHaveRecent(let targetPeerId, let lastSeenSecondsAgo, let reachability):
            await handleIHaveRecent(
                targetPeerId: targetPeerId,
                lastSeenSecondsAgo: lastSeenSecondsAgo,
                reachability: reachability,
                fromPeerId: peerId
            )
            return (nil, false)

        case .pathFailed(let targetPeerId, let path, let failedAt):
            return await handlePathFailed(
                targetPeerId: targetPeerId,
                path: path,
                failedAt: failedAt,
                fromPeerId: peerId,
                hopCount: hopCount
            )

        default:
            return (nil, false)
        }
    }

    // MARK: - Private Message Handlers

    private func handleWhoHasRecent(
        targetPeerId: PeerId,
        maxAgeSeconds: Int,
        hopCount: Int
    ) async -> (response: MeshMessage?, shouldForward: Bool) {
        // Check if we have recent contact
        let response = await freshnessQuery.handleQuery(
            peerId: targetPeerId,
            maxAgeSeconds: maxAgeSeconds
        )

        // Determine if we should forward
        let shouldForward = freshnessQuery.shouldForward(hopCount: hopCount)

        return (response, shouldForward)
    }

    private func handleIHaveRecent(
        targetPeerId: PeerId,
        lastSeenSecondsAgo: Int,
        reachability: ReachabilityPath,
        fromPeerId: PeerId
    ) async {
        await freshnessQuery.handleResponse(
            peerId: targetPeerId,
            lastSeenSecondsAgo: lastSeenSecondsAgo,
            reachability: reachability,
            fromPeerId: fromPeerId
        )
    }

    private func handlePathFailed(
        targetPeerId: PeerId,
        path: ReachabilityPath,
        failedAt: Date,
        fromPeerId: PeerId,
        hopCount: Int
    ) async -> (response: MeshMessage?, shouldForward: Bool) {
        await pathFailureReporter.handleFailure(
            peerId: targetPeerId,
            path: path,
            failedAt: failedAt,
            reportedBy: fromPeerId
        )

        // Determine if we should propagate
        let shouldForward = pathFailureReporter.shouldPropagate(hopCount: hopCount)

        return (nil, shouldForward)
    }

    private func handlePathFailure(_ failure: PathFailure) async {
        // Invalidate cache for this path (prefer services)
        if let services = services {
            await services.invalidateCache(peerId: failure.peerId, path: failure.path)
        } else {
            await invalidateCache?(failure.peerId, failure.path)
        }

        // Remove from recent contacts if the path matches
        if let contact = await recentContacts.getContact(failure.peerId),
           contact.reachability == failure.path {
            await recentContacts.removeContact(failure.peerId)
        }
    }

    // MARK: - Cleanup

    /// Perform periodic cleanup
    public func cleanup() async {
        await freshnessQuery.cleanup()
        await pathFailureReporter.cleanup()
    }

    // MARK: - Statistics

    /// Get the number of tracked recent contacts
    public var recentContactCount: Int {
        get async {
            await recentContacts.count
        }
    }

    /// Get recent peer IDs for ping messages
    public var recentPeerIds: [PeerId] {
        get async {
            await recentContacts.recentPeerIds
        }
    }
}
