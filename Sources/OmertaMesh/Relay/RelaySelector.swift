// RelaySelector.swift - Relay selection algorithm

import Foundation
import Logging

/// Criteria for selecting relays
public struct RelaySelectionCriteria: Sendable {
    /// Maximum acceptable RTT
    public let maxRTT: TimeInterval

    /// Minimum available capacity
    public let minCapacity: Int

    /// Prefer relays with direct connectivity
    public let preferDirect: Bool

    /// Number of relays to select
    public let count: Int

    public init(
        maxRTT: TimeInterval = 0.5,
        minCapacity: Int = 10,
        preferDirect: Bool = true,
        count: Int = 3
    ) {
        self.maxRTT = maxRTT
        self.minCapacity = minCapacity
        self.preferDirect = preferDirect
        self.count = count
    }

    public static let `default` = RelaySelectionCriteria()
}

/// Information about a potential relay
public struct RelayCandidate: Sendable {
    public let peerId: PeerId
    public let endpoint: String
    public let rtt: TimeInterval
    public let availableCapacity: Int
    public let isDirect: Bool
    public let natType: NATType

    public init(
        peerId: PeerId,
        endpoint: String,
        rtt: TimeInterval,
        availableCapacity: Int,
        isDirect: Bool,
        natType: NATType
    ) {
        self.peerId = peerId
        self.endpoint = endpoint
        self.rtt = rtt
        self.availableCapacity = availableCapacity
        self.isDirect = isDirect
        self.natType = natType
    }

    /// Score for this relay (higher is better)
    public var score: Double {
        var score = 100.0

        // Penalize high RTT
        score -= rtt * 100.0

        // Reward capacity
        score += Double(min(availableCapacity, 100)) * 0.5

        // Prefer direct connectivity
        if isDirect {
            score += 20.0
        }

        // Prefer public or full cone NAT
        switch natType {
        case .public:
            score += 30.0
        case .fullCone:
            score += 20.0
        case .restrictedCone, .portRestrictedCone:
            score += 10.0
        case .symmetric, .unknown:
            break
        }

        return max(0, score)
    }
}

/// Selects optimal relays based on criteria
public actor RelaySelector {
    private let peerCache: PeerCache
    private let node: MeshNode
    private let logger: Logger

    /// Cache of relay candidates with their measured RTT
    private var candidateCache: [PeerId: RelayCandidate] = [:]

    /// Cache expiration time
    private let cacheExpiration: TimeInterval = 60.0

    /// When the cache was last updated
    private var cacheUpdatedAt: Date?

    public init(peerCache: PeerCache, node: MeshNode) {
        self.peerCache = peerCache
        self.node = node
        self.logger = Logger(label: "io.omerta.mesh.relay.selector")
    }

    // MARK: - Selection

    /// Select relays based on criteria
    public func selectRelays(
        criteria: RelaySelectionCriteria = .default
    ) async throws -> [RelayCandidate] {
        // Refresh candidate cache if stale
        if shouldRefreshCache {
            await refreshCandidates()
        }

        // Filter candidates by criteria
        var filtered = candidateCache.values.filter { candidate in
            candidate.rtt <= criteria.maxRTT &&
            candidate.availableCapacity >= criteria.minCapacity
        }

        // Sort by score (highest first)
        filtered.sort { $0.score > $1.score }

        // If preferring direct, separate and prioritize
        if criteria.preferDirect {
            let direct = filtered.filter { $0.isDirect }
            let indirect = filtered.filter { !$0.isDirect }
            filtered = direct + indirect
        }

        let selected = Array(filtered.prefix(criteria.count))

        logger.info("Selected \(selected.count) relays from \(candidateCache.count) candidates")

        return selected
    }

    /// Select a single best relay
    public func selectBestRelay() async throws -> RelayCandidate? {
        let relays = try await selectRelays(criteria: RelaySelectionCriteria(count: 1))
        return relays.first
    }

    /// Select relays for a specific target peer
    public func selectRelays(
        forTarget targetPeerId: PeerId,
        criteria: RelaySelectionCriteria = .default
    ) async throws -> [RelayCandidate] {
        // Get target peer's announcement
        guard let targetAnnouncement = await peerCache.get(targetPeerId) else {
            // Just use general selection
            return try await selectRelays(criteria: criteria)
        }

        // Find relays that the target might also be able to reach
        var candidates = try await selectRelays(criteria: criteria)

        // Prefer relays that target lists in their reachability
        let targetRelays = Set(targetAnnouncement.reachability.compactMap { path -> PeerId? in
            if case .relay(let relayId, _) = path {
                return relayId
            }
            return nil
        })

        // Boost score of shared relays
        candidates.sort { a, b in
            let aShared = targetRelays.contains(a.peerId)
            let bShared = targetRelays.contains(b.peerId)
            if aShared != bShared {
                return aShared
            }
            return a.score > b.score
        }

        return Array(candidates.prefix(criteria.count))
    }

    // MARK: - Cache Management

    private var shouldRefreshCache: Bool {
        guard let updatedAt = cacheUpdatedAt else {
            return true
        }
        return Date().timeIntervalSince(updatedAt) > cacheExpiration
    }

    private func refreshCandidates() async {
        logger.debug("Refreshing relay candidates")

        // Get all relay-capable peers
        let relayPeers = await peerCache.relayCapablePeers

        // Probe each relay
        for peer in relayPeers {
            // Get endpoint
            guard let endpoint = peer.reachability.first.flatMap({ path -> String? in
                switch path {
                case .direct(let ep): return ep
                case .relay(_, let ep): return ep
                case .holePunch: return nil
                }
            }) else { continue }

            // Measure RTT
            do {
                let startTime = Date()
                let myNATType = await node.getPredictedNATType().type
                let response = try await node.sendAndReceive(
                    .ping(recentPeers: [], myNATType: myNATType),
                    to: endpoint,
                    timeout: 5.0
                )

                if case .pong(_, _, _) = response {
                    let rtt = Date().timeIntervalSince(startTime)

                    // Extract capacity from announcement (default to 50)
                    let capacity = 50  // Would come from relayCapacity message

                    let isDirect = peer.reachability.contains { path in
                        if case .direct = path { return true }
                        return false
                    }

                    // Determine NAT type (would come from announcement in full implementation)
                    let natType = isDirect ? NATType.public : NATType.unknown

                    let candidate = RelayCandidate(
                        peerId: peer.peerId,
                        endpoint: endpoint,
                        rtt: rtt,
                        availableCapacity: capacity,
                        isDirect: isDirect,
                        natType: natType
                    )

                    candidateCache[peer.peerId] = candidate
                }
            } catch {
                // Remove from cache if unreachable
                candidateCache.removeValue(forKey: peer.peerId)
            }
        }

        cacheUpdatedAt = Date()
        logger.info("Relay candidate cache refreshed: \(candidateCache.count) relays")
    }

    /// Force a cache refresh
    public func refreshNow() async {
        cacheUpdatedAt = nil
        await refreshCandidates()
    }

    /// Get current candidates (without refreshing)
    public var currentCandidates: [RelayCandidate] {
        Array(candidateCache.values)
    }
}
