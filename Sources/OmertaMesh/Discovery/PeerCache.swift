// PeerCache.swift - LRU cache with TTL for peer announcements

import Foundation

/// LRU cache for peer announcements with TTL expiration
public actor PeerCache {
    /// Cached peer entry
    private struct CacheEntry {
        let announcement: PeerAnnouncement
        let insertedAt: Date
        var lastAccessedAt: Date

        var isExpired: Bool {
            announcement.isExpired
        }
    }

    /// Maximum number of entries
    private let maxEntries: Int

    /// Cache storage
    private var cache: [PeerId: CacheEntry] = [:]

    /// Access order for LRU eviction (most recent at end)
    private var accessOrder: [PeerId] = []

    /// Create a peer cache with specified capacity
    public init(maxEntries: Int = 1000) {
        self.maxEntries = maxEntries
    }

    // MARK: - Public API

    /// Insert or update a peer announcement
    public func insert(_ announcement: PeerAnnouncement) {
        let peerId = announcement.peerId

        // Remove from access order if exists
        if let index = accessOrder.firstIndex(of: peerId) {
            accessOrder.remove(at: index)
        }

        // Insert or update
        cache[peerId] = CacheEntry(
            announcement: announcement,
            insertedAt: Date(),
            lastAccessedAt: Date()
        )

        // Add to end of access order (most recent)
        accessOrder.append(peerId)

        // Evict if over capacity
        evictIfNeeded()
    }

    /// Get a peer announcement by ID
    public func get(_ peerId: PeerId) -> PeerAnnouncement? {
        guard var entry = cache[peerId] else {
            return nil
        }

        // Check if expired
        if entry.isExpired {
            remove(peerId)
            return nil
        }

        // Update access time
        entry.lastAccessedAt = Date()
        cache[peerId] = entry

        // Move to end of access order
        if let index = accessOrder.firstIndex(of: peerId) {
            accessOrder.remove(at: index)
            accessOrder.append(peerId)
        }

        return entry.announcement
    }

    /// Remove a peer from cache
    public func remove(_ peerId: PeerId) {
        cache.removeValue(forKey: peerId)
        if let index = accessOrder.firstIndex(of: peerId) {
            accessOrder.remove(at: index)
        }
    }

    /// Get all cached peer IDs
    public var peerIds: [PeerId] {
        Array(cache.keys)
    }

    /// Get all non-expired announcements
    public var allAnnouncements: [PeerAnnouncement] {
        cache.values
            .filter { !$0.isExpired }
            .map { $0.announcement }
    }

    /// Get peers with specific capability
    public func peers(withCapability capability: String) -> [PeerAnnouncement] {
        cache.values
            .filter { !$0.isExpired && $0.announcement.capabilities.contains(capability) }
            .map { $0.announcement }
    }

    /// Get peers that can relay
    public var relayCapablePeers: [PeerAnnouncement] {
        peers(withCapability: "relay")
    }

    /// Number of cached peers
    public var count: Int {
        cache.count
    }

    /// Remove all expired entries
    public func pruneExpired() {
        let expiredIds = cache.filter { $0.value.isExpired }.map { $0.key }
        for peerId in expiredIds {
            remove(peerId)
        }
    }

    /// Clear all entries
    public func clear() {
        cache.removeAll()
        accessOrder.removeAll()
    }

    // MARK: - Lookup by Reachability

    /// Find peers with direct reachability
    public var directlyReachablePeers: [PeerAnnouncement] {
        allAnnouncements.filter { announcement in
            announcement.reachability.contains { path in
                if case .direct = path { return true }
                return false
            }
        }
    }

    /// Find peers reachable via a specific relay
    public func peersViaRelay(_ relayPeerId: PeerId) -> [PeerAnnouncement] {
        allAnnouncements.filter { announcement in
            announcement.reachability.contains { path in
                if case .relay(let relay, _) = path {
                    return relay == relayPeerId
                }
                return false
            }
        }
    }

    // MARK: - Private Methods

    private func evictIfNeeded() {
        while cache.count > maxEntries && !accessOrder.isEmpty {
            let lruPeerId = accessOrder.removeFirst()
            cache.removeValue(forKey: lruPeerId)
        }
    }
}

// MARK: - Peer Finder

extension PeerCache {
    /// Find the best path to reach a peer
    public func bestPath(to peerId: PeerId) -> ReachabilityPath? {
        guard let announcement = get(peerId) else {
            return nil
        }

        // Prefer direct, then relay, then hole punch
        for path in announcement.reachability {
            if case .direct = path {
                return path
            }
        }

        for path in announcement.reachability {
            if case .relay = path {
                return path
            }
        }

        return announcement.reachability.first
    }

    /// Find peers closest to a target ID (for Kademlia-style routing)
    public func closestPeers(to targetId: PeerId, count: Int = 20) -> [PeerAnnouncement] {
        // XOR distance (simplified - compare as bytes)
        let sorted = allAnnouncements.sorted { a, b in
            compareXorDistance(a.peerId, b.peerId, to: targetId)
        }
        return Array(sorted.prefix(count))
    }

    private func compareXorDistance(_ a: PeerId, _ b: PeerId, to target: PeerId) -> Bool {
        let distA = xorDistance(a, target)
        let distB = xorDistance(b, target)

        // Compare byte by byte
        for i in 0..<min(distA.count, distB.count) {
            if distA[i] != distB[i] {
                return distA[i] < distB[i]
            }
        }
        return distA.count < distB.count
    }

    private func xorDistance(_ a: PeerId, _ b: PeerId) -> [UInt8] {
        guard let aData = Data(base64Encoded: a),
              let bData = Data(base64Encoded: b) else {
            return []
        }

        let length = min(aData.count, bData.count)
        var result = [UInt8](repeating: 0, count: length)
        for i in 0..<length {
            result[i] = aData[i] ^ bData[i]
        }
        return result
    }
}
