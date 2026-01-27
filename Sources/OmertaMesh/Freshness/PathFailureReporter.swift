// PathFailureReporter.swift - Reports and handles path failures

import Foundation
import Logging

/// A reported path failure
public struct PathFailure: Sendable, Equatable {
    /// The peer that became unreachable
    public let peerId: PeerId

    /// The path that failed
    public let path: ReachabilityPath

    /// When the failure occurred
    public let failedAt: Date

    /// Who reported the failure
    public let reportedBy: PeerId?

    public init(
        peerId: PeerId,
        path: ReachabilityPath,
        failedAt: Date = Date(),
        reportedBy: PeerId? = nil
    ) {
        self.peerId = peerId
        self.path = path
        self.failedAt = failedAt
        self.reportedBy = reportedBy
    }
}

/// Reports path failures and propagates them through the network
public actor PathFailureReporter {
    /// Configuration for path failure reporting
    public struct Config: Sendable {
        /// Minimum interval between reports for the same path
        public let reportInterval: TimeInterval

        /// How long to remember a failure
        public let failureMemory: TimeInterval

        /// Maximum failures to track
        public let maxFailures: Int

        /// Maximum hops to propagate failures
        public let maxPropagationHops: Int

        public init(
            reportInterval: TimeInterval = 60.0,
            failureMemory: TimeInterval = 300.0,  // 5 minutes
            maxFailures: Int = 200,
            maxPropagationHops: Int = 2
        ) {
            self.reportInterval = reportInterval
            self.failureMemory = failureMemory
            self.maxFailures = maxFailures
            self.maxPropagationHops = maxPropagationHops
        }
    }

    private let config: Config
    private let logger: Logger

    /// Recent failures we've reported (to avoid duplicates)
    private var reportedFailures: [PathFailureKey: Date] = [:]

    /// Recent failures we've received (for cache invalidation)
    private var knownFailures: [PathFailure] = []

    /// Handlers to call when a path failure is received
    private var failureHandlers: [(PathFailure) async -> Void] = []

    /// Key for deduplicating failure reports
    private struct PathFailureKey: Hashable {
        let peerId: PeerId
        let pathHash: Int

        init(peerId: PeerId, path: ReachabilityPath) {
            self.peerId = peerId
            // Simple hash of the path for deduplication
            switch path {
            case .direct(let endpoint):
                self.pathHash = "direct:\(endpoint)".hashValue
            case .relay(let relayPeerId, let relayEndpoint):
                self.pathHash = "relay:\(relayPeerId):\(relayEndpoint)".hashValue
            case .holePunch(let publicIP, let localPort):
                self.pathHash = "holepunch:\(publicIP):\(localPort)".hashValue
            }
        }
    }

    public init(config: Config = Config()) {
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.pathfailure")
    }

    // MARK: - Reporting Failures

    /// Report a path failure (will broadcast to network if not recently reported)
    /// Returns the message to broadcast, or nil if rate limited
    public func reportFailure(
        peerId: PeerId,
        path: ReachabilityPath
    ) -> MeshMessage? {
        let key = PathFailureKey(peerId: peerId, path: path)
        let now = Date()

        // Check rate limiting
        if let lastReport = reportedFailures[key] {
            if now.timeIntervalSince(lastReport) < config.reportInterval {
                logger.debug("Rate limited failure report for \(peerId)")
                return nil
            }
        }

        // Record the report
        reportedFailures[key] = now

        // Create failure record
        let failure = PathFailure(
            peerId: peerId,
            path: path,
            failedAt: now,
            reportedBy: nil
        )
        addKnownFailure(failure)

        logger.info("Reporting path failure for \(peerId)")

        return .pathFailed(peerId: peerId, path: path, failedAt: now)
    }

    /// Check if we should report a failure (rate limiting)
    public func shouldReport(peerId: PeerId, path: ReachabilityPath) -> Bool {
        let key = PathFailureKey(peerId: peerId, path: path)

        if let lastReport = reportedFailures[key] {
            return Date().timeIntervalSince(lastReport) >= config.reportInterval
        }
        return true
    }

    // MARK: - Receiving Failures

    /// Handle an incoming path failure report
    public func handleFailure(
        peerId: PeerId,
        path: ReachabilityPath,
        failedAt: Date,
        reportedBy: PeerId
    ) async {
        // Ignore very old failure reports
        if Date().timeIntervalSince(failedAt) > config.failureMemory {
            logger.debug("Ignoring old failure report for \(peerId)")
            return
        }

        let failure = PathFailure(
            peerId: peerId,
            path: path,
            failedAt: failedAt,
            reportedBy: reportedBy
        )

        // Check if we already know about this
        if knownFailures.contains(where: { $0.peerId == peerId && $0.path == path && $0.failedAt == failedAt }) {
            logger.debug("Already know about failure for \(peerId)")
            return
        }

        addKnownFailure(failure)
        logger.debug("Received path failure for \(peerId) from \(reportedBy)")

        // Notify handlers
        for handler in failureHandlers {
            await handler(failure)
        }
    }

    /// Determine if we should propagate a failure (hop count check)
    public nonisolated func shouldPropagate(hopCount: Int) -> Bool {
        hopCount < config.maxPropagationHops
    }

    // MARK: - Failure Queries

    /// Check if a path is known to have failed recently
    public func isPathFailed(peerId: PeerId, path: ReachabilityPath) -> Bool {
        let cutoff = Date().addingTimeInterval(-config.failureMemory)
        return knownFailures.contains { failure in
            failure.peerId == peerId &&
            failure.path == path &&
            failure.failedAt > cutoff
        }
    }

    /// Get all recent failures for a peer
    public func failures(for peerId: PeerId) -> [PathFailure] {
        let cutoff = Date().addingTimeInterval(-config.failureMemory)
        return knownFailures.filter { $0.peerId == peerId && $0.failedAt > cutoff }
    }

    /// Get all known failed paths for a peer
    public func failedPaths(for peerId: PeerId) -> [ReachabilityPath] {
        failures(for: peerId).map { $0.path }
    }

    // MARK: - Event Handling

    /// Register a handler for path failures
    public func onFailure(_ handler: @escaping (PathFailure) async -> Void) {
        failureHandlers.append(handler)
    }

    // MARK: - Cleanup

    /// Clean up old failure records
    public func cleanup() {
        let cutoff = Date().addingTimeInterval(-config.failureMemory)

        // Clean up known failures
        knownFailures.removeAll { $0.failedAt < cutoff }

        // Clean up report tracking
        reportedFailures = reportedFailures.filter { $0.value > cutoff }
    }

    // MARK: - Private Helpers

    private func addKnownFailure(_ failure: PathFailure) {
        knownFailures.append(failure)

        // Limit size
        if knownFailures.count > config.maxFailures {
            knownFailures.removeFirst(knownFailures.count - config.maxFailures)
        }
    }
}
