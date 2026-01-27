// Gossip.swift - Peer announcement gossip broadcast

import Foundation
import Logging

/// Configuration for gossip protocol
public struct GossipConfig: Sendable {
    /// Number of peers to gossip to
    public let fanout: Int

    /// Interval between gossip rounds
    public let interval: TimeInterval

    /// TTL for gossip messages (hop count)
    public let maxHops: Int

    /// Maximum announcements per gossip message
    public let maxAnnouncementsPerMessage: Int

    public init(
        fanout: Int = 6,
        interval: TimeInterval = 30.0,
        maxHops: Int = 3,
        maxAnnouncementsPerMessage: Int = 10
    ) {
        self.fanout = fanout
        self.interval = interval
        self.maxHops = maxHops
        self.maxAnnouncementsPerMessage = maxAnnouncementsPerMessage
    }
}

/// Gossip protocol for peer announcement propagation
public actor Gossip {
    private let node: MeshNode
    private let peerCache: PeerCache
    private let config: GossipConfig
    private let logger: Logger

    /// Recently gossiped announcement IDs (to avoid loops)
    private var recentGossip: Set<String> = []
    private let maxRecentGossip = 1000

    /// Task for periodic gossip
    private var gossipTask: Task<Void, Never>?

    /// Our own announcement (to broadcast)
    private var selfAnnouncement: PeerAnnouncement?

    public init(
        node: MeshNode,
        peerCache: PeerCache,
        config: GossipConfig = GossipConfig()
    ) {
        self.node = node
        self.peerCache = peerCache
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.gossip")
    }

    // MARK: - Lifecycle

    /// Start the gossip protocol
    public func start(selfAnnouncement: PeerAnnouncement) {
        self.selfAnnouncement = selfAnnouncement
        gossipTask = Task {
            await runGossipLoop()
        }
        logger.info("Gossip protocol started")
    }

    /// Stop the gossip protocol
    public func stop() {
        gossipTask?.cancel()
        gossipTask = nil
        logger.info("Gossip protocol stopped")
    }

    // MARK: - Gossip Operations

    /// Broadcast our own announcement
    public func announceself() async {
        guard let announcement = selfAnnouncement else { return }
        await broadcast(announcement)
    }

    /// Broadcast a peer announcement
    public func broadcast(_ announcement: PeerAnnouncement) async {
        // Generate unique ID for this gossip
        let gossipId = "\(announcement.peerId):\(announcement.timestamp.timeIntervalSince1970)"

        // Skip if recently gossiped
        guard !recentGossip.contains(gossipId) else {
            return
        }
        markGossiped(gossipId)

        // Select random peers to gossip to
        let peers = await selectGossipTargets()

        for peer in peers {
            await sendAnnouncement(announcement, to: peer)
        }

        logger.debug("Broadcast announcement for \(announcement.peerId) to \(peers.count) peers")
    }

    /// Handle incoming announcement (and potentially re-gossip)
    public func handleAnnouncement(_ announcement: PeerAnnouncement, hopCount: Int) async {
        // Validate announcement
        guard !announcement.isExpired else {
            logger.debug("Ignoring expired announcement from \(announcement.peerId)")
            return
        }

        // Add to cache
        await peerCache.insert(announcement)

        // Re-gossip if not at max hops
        if hopCount < config.maxHops {
            await broadcast(announcement)
        }
    }

    // MARK: - Private Methods

    private func runGossipLoop() async {
        while !Task.isCancelled {
            do {
                // Wait for interval
                try await Task.sleep(nanoseconds: UInt64(config.interval * 1_000_000_000))

                // Gossip our own announcement
                await announceself()

                // Gossip some cached peers (helps propagate knowledge)
                let cachedPeers = await peerCache.allAnnouncements
                for announcement in cachedPeers.shuffled().prefix(3) {
                    await broadcast(announcement)
                }
            } catch {
                // Task cancelled
                break
            }
        }
    }

    private func selectGossipTargets() async -> [PeerAnnouncement] {
        let allPeers = await peerCache.allAnnouncements

        // Don't gossip to ourselves
        let selfId = await node.peerId
        let others = allPeers.filter { $0.peerId != selfId }

        // Random selection
        return Array(others.shuffled().prefix(config.fanout))
    }

    private func sendAnnouncement(_ announcement: PeerAnnouncement, to peer: PeerAnnouncement) async {
        guard let endpoint = peer.reachability.first.flatMap({ path -> String? in
            switch path {
            case .direct(let ep): return ep
            case .relay(_, let ep): return ep
            case .holePunch: return nil
            }
        }) else { return }

        try? await node.send(.announce(announcement), to: endpoint)
    }

    private func markGossiped(_ id: String) {
        recentGossip.insert(id)

        // Prune if too large
        if recentGossip.count > maxRecentGossip {
            // Remove oldest half (simple approach)
            let toRemove = recentGossip.prefix(maxRecentGossip / 2)
            for item in toRemove {
                recentGossip.remove(item)
            }
        }
    }
}

// MARK: - Announcement Creation

extension Gossip {
    /// Create a signed announcement for this node
    public static func createAnnouncement(
        identity: IdentityKeypair,
        reachability: [ReachabilityPath],
        capabilities: [String],
        ttlSeconds: Int = 3600
    ) throws -> PeerAnnouncement {
        // Create unsigned announcement
        var announcement = PeerAnnouncement(
            peerId: identity.peerId,
            publicKey: identity.publicKeyBase64,
            reachability: reachability,
            capabilities: capabilities,
            ttlSeconds: ttlSeconds
        )

        // Sign it
        let dataToSign = try signatureData(for: announcement)
        let signature = try identity.sign(dataToSign)
        announcement = PeerAnnouncement(
            peerId: announcement.peerId,
            publicKey: announcement.publicKey,
            reachability: announcement.reachability,
            capabilities: announcement.capabilities,
            timestamp: announcement.timestamp,
            ttlSeconds: announcement.ttlSeconds,
            signature: signature.base64
        )

        return announcement
    }

    private static func signatureData(for announcement: PeerAnnouncement) throws -> Data {
        // Create a signable version without signature
        let signable = SignablePeerAnnouncement(
            peerId: announcement.peerId,
            publicKey: announcement.publicKey,
            reachability: announcement.reachability,
            capabilities: announcement.capabilities,
            timestamp: announcement.timestamp,
            ttlSeconds: announcement.ttlSeconds
        )

        return try JSONCoding.signatureEncoder.encode(signable)
    }
}

/// Internal struct for signing
private struct SignablePeerAnnouncement: Codable {
    let peerId: PeerId
    let publicKey: String
    let reachability: [ReachabilityPath]
    let capabilities: [String]
    let timestamp: Date
    let ttlSeconds: Int
}

// MARK: - Announcement Verification

extension PeerAnnouncement {
    /// Verify the announcement signature
    public func verifySignature() -> Bool {
        guard !signature.isEmpty,
              let sigData = Data(base64Encoded: signature) else {
            return false
        }

        // Create signable version
        let signable = SignablePeerAnnouncement(
            peerId: peerId,
            publicKey: publicKey,
            reachability: reachability,
            capabilities: capabilities,
            timestamp: timestamp,
            ttlSeconds: ttlSeconds
        )

        guard let data = try? JSONCoding.signatureEncoder.encode(signable) else {
            return false
        }

        let sig = Signature(data: sigData)
        return sig.verify(data, publicKeyBase64: publicKey)
    }
}
