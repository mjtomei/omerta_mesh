// FreshnessQuery.swift - Query network for fresh peer information

import Foundation
import Logging

/// Result of a freshness query
public struct FreshnessQueryResult: Sendable {
    /// The peer we queried for
    public let peerId: PeerId

    /// Fresh reachability path (if found)
    public let reachability: ReachabilityPath?

    /// How recently the responder contacted the peer
    public let lastSeenSecondsAgo: Int?

    /// The peer that provided the fresh info
    public let responderId: PeerId?

    /// Whether the query succeeded
    public var success: Bool {
        reachability != nil
    }

    public static func notFound(_ peerId: PeerId) -> FreshnessQueryResult {
        FreshnessQueryResult(
            peerId: peerId,
            reachability: nil,
            lastSeenSecondsAgo: nil,
            responderId: nil
        )
    }
}

/// Handles freshness queries to recover from stale peer information
public actor FreshnessQuery {
    /// Configuration for freshness queries
    public struct Config: Sendable {
        /// Maximum hops for query propagation
        public let maxHops: Int

        /// Timeout for waiting for responses
        public let queryTimeout: TimeInterval

        /// Minimum interval between queries for the same peer (rate limiting)
        public let queryInterval: TimeInterval

        /// Maximum age to accept for a "recent" contact
        public let maxAcceptableAge: Int

        /// Maximum concurrent queries
        public let maxConcurrentQueries: Int

        public init(
            maxHops: Int = 3,
            queryTimeout: TimeInterval = 5.0,
            queryInterval: TimeInterval = 30.0,
            maxAcceptableAge: Int = 300,  // 5 minutes
            maxConcurrentQueries: Int = 10
        ) {
            self.maxHops = maxHops
            self.queryTimeout = queryTimeout
            self.queryInterval = queryInterval
            self.maxAcceptableAge = maxAcceptableAge
            self.maxConcurrentQueries = maxConcurrentQueries
        }
    }

    private let config: Config
    private let recentContacts: RecentContactTracker
    private let logger: Logger

    /// Last query time per peer (for rate limiting)
    private var lastQueryTime: [PeerId: Date] = [:]

    /// Active queries (to prevent duplicates)
    private var activeQueries: Set<PeerId> = []

    /// Pending query continuations
    private var pendingQueries: [PeerId: [CheckedContinuation<FreshnessQueryResult, Never>]] = [:]

    /// Best response received so far per query
    private var bestResponses: [PeerId: (reachability: ReachabilityPath, age: Int, responder: PeerId)] = [:]

    public init(
        recentContacts: RecentContactTracker,
        config: Config = Config()
    ) {
        self.recentContacts = recentContacts
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.freshness")
    }

    // MARK: - Query Initiation

    /// Query the network for fresh information about a peer
    /// Returns the best result found within the timeout
    public func query(
        peerId: PeerId,
        sendQuery: @escaping (MeshMessage, Int) async -> Void
    ) async -> FreshnessQueryResult {
        // Check rate limiting
        if let lastQuery = lastQueryTime[peerId] {
            let elapsed = Date().timeIntervalSince(lastQuery)
            if elapsed < config.queryInterval {
                logger.debug("Rate limited query for \(peerId), last query \(elapsed)s ago")
                // Return cached best response if available
                if let best = bestResponses[peerId] {
                    return FreshnessQueryResult(
                        peerId: peerId,
                        reachability: best.reachability,
                        lastSeenSecondsAgo: best.age,
                        responderId: best.responder
                    )
                }
                return .notFound(peerId)
            }
        }

        // Check if we already have fresh local contact
        if let contact = await recentContacts.getContact(peerId),
           contact.ageSeconds <= config.maxAcceptableAge {
            logger.debug("Have fresh local contact for \(peerId)")
            return FreshnessQueryResult(
                peerId: peerId,
                reachability: contact.reachability,
                lastSeenSecondsAgo: contact.ageSeconds,
                responderId: nil
            )
        }

        // Check concurrent query limit
        if activeQueries.count >= config.maxConcurrentQueries {
            logger.warning("Max concurrent queries reached, rejecting query for \(peerId)")
            return .notFound(peerId)
        }

        // Check if query already active - join it
        if activeQueries.contains(peerId) {
            return await withCheckedContinuation { continuation in
                pendingQueries[peerId, default: []].append(continuation)
            }
        }

        // Start new query
        activeQueries.insert(peerId)
        lastQueryTime[peerId] = Date()
        bestResponses.removeValue(forKey: peerId)

        // Send the query
        let message = MeshMessage.whoHasRecent(peerId: peerId, maxAgeSeconds: config.maxAcceptableAge)
        await sendQuery(message, config.maxHops)

        logger.debug("Sent freshness query for \(peerId)")

        // Wait for responses with timeout
        let result = await withTaskGroup(of: FreshnessQueryResult.self) { group in
            group.addTask {
                // Timeout task
                try? await Task.sleep(nanoseconds: UInt64(self.config.queryTimeout * 1_000_000_000))
                return await self.finishQuery(peerId)
            }

            // Return first result (the timeout)
            return await group.next() ?? .notFound(peerId)
        }

        return result
    }

    /// Check if a query can be initiated (rate limiting check)
    public func canQuery(_ peerId: PeerId) -> Bool {
        if let lastQuery = lastQueryTime[peerId] {
            return Date().timeIntervalSince(lastQuery) >= config.queryInterval
        }
        return true
    }

    // MARK: - Response Handling

    /// Handle an incoming iHaveRecent response
    public func handleResponse(
        peerId: PeerId,
        lastSeenSecondsAgo: Int,
        reachability: ReachabilityPath,
        fromPeerId: PeerId
    ) {
        // Ignore if no active query
        guard activeQueries.contains(peerId) else {
            logger.debug("Ignoring response for inactive query: \(peerId)")
            return
        }

        // Ignore if too old
        guard lastSeenSecondsAgo <= config.maxAcceptableAge else {
            logger.debug("Ignoring stale response for \(peerId): \(lastSeenSecondsAgo)s old")
            return
        }

        // Check if better than current best
        if let current = bestResponses[peerId] {
            if lastSeenSecondsAgo >= current.age {
                // Current is fresher or equal, ignore
                return
            }
        }

        // Update best response
        bestResponses[peerId] = (reachability, lastSeenSecondsAgo, fromPeerId)
        logger.debug("Got fresher info for \(peerId) from \(fromPeerId): \(lastSeenSecondsAgo)s ago")
    }

    /// Finish a query and return the best result
    private func finishQuery(_ peerId: PeerId) -> FreshnessQueryResult {
        activeQueries.remove(peerId)

        let result: FreshnessQueryResult
        if let best = bestResponses[peerId] {
            result = FreshnessQueryResult(
                peerId: peerId,
                reachability: best.reachability,
                lastSeenSecondsAgo: best.age,
                responderId: best.responder
            )
        } else {
            result = .notFound(peerId)
        }

        // Resume any waiting queries
        if let continuations = pendingQueries.removeValue(forKey: peerId) {
            for continuation in continuations {
                continuation.resume(returning: result)
            }
        }

        return result
    }

    // MARK: - Incoming Query Handling

    /// Handle an incoming whoHasRecent query
    /// Returns a response if we have recent contact, nil otherwise
    public func handleQuery(
        peerId: PeerId,
        maxAgeSeconds: Int
    ) async -> MeshMessage? {
        guard let contact = await recentContacts.getContact(peerId) else {
            return nil
        }

        // Check if our contact is fresh enough
        guard contact.ageSeconds <= maxAgeSeconds else {
            return nil
        }

        return .iHaveRecent(
            peerId: peerId,
            lastSeenSecondsAgo: contact.ageSeconds,
            reachability: contact.reachability
        )
    }

    /// Determine if we should forward a query (hop count check)
    public nonisolated func shouldForward(hopCount: Int) -> Bool {
        hopCount < config.maxHops
    }

    // MARK: - Cleanup

    /// Clean up stale rate limiting entries
    public func cleanup() {
        let cutoff = Date().addingTimeInterval(-config.queryInterval * 2)
        lastQueryTime = lastQueryTime.filter { $0.value > cutoff }
        bestResponses = bestResponses.filter { peerId, _ in
            lastQueryTime[peerId] != nil
        }
    }
}
