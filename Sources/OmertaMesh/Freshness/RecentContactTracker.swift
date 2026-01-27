// RecentContactTracker.swift - Tracks recent peer communications

import Foundation

/// Information about a recent contact with a peer
public struct RecentContact: Sendable {
    /// The peer we contacted
    public let peerId: PeerId

    /// When we last communicated
    public let lastSeen: Date

    /// How we reached them
    public let reachability: ReachabilityPath

    /// Round-trip latency in milliseconds
    public let latencyMs: Int

    /// How the connection was established
    public let connectionType: ConnectionType

    /// How old this contact is
    public var age: TimeInterval {
        Date().timeIntervalSince(lastSeen)
    }

    /// Age in seconds as an integer
    public var ageSeconds: Int {
        Int(age)
    }

    public init(
        peerId: PeerId,
        lastSeen: Date = Date(),
        reachability: ReachabilityPath,
        latencyMs: Int,
        connectionType: ConnectionType
    ) {
        self.peerId = peerId
        self.lastSeen = lastSeen
        self.reachability = reachability
        self.latencyMs = latencyMs
        self.connectionType = connectionType
    }
}

/// How a connection was established
public enum ConnectionType: String, Codable, Sendable {
    /// We initiated a direct connection
    case direct

    /// They connected to us directly
    case inboundDirect

    /// Connection through a relay
    case viaRelay

    /// Connection established via hole punching
    case holePunched
}

/// Tracks recent peer communications for freshness queries
public actor RecentContactTracker {
    /// Configuration for the tracker
    public struct Config: Sendable {
        /// Maximum age before a contact is considered stale
        public let maxAge: TimeInterval

        /// Maximum number of contacts to track
        public let maxContacts: Int

        /// Cleanup interval
        public let cleanupInterval: TimeInterval

        public init(
            maxAge: TimeInterval = 300,  // 5 minutes
            maxContacts: Int = 500,
            cleanupInterval: TimeInterval = 60
        ) {
            self.maxAge = maxAge
            self.maxContacts = maxContacts
            self.cleanupInterval = cleanupInterval
        }
    }

    private let config: Config

    /// Recent contacts indexed by peer ID
    private var contacts: [PeerId: RecentContact] = [:]

    /// Access order for LRU eviction (most recent at end)
    private var accessOrder: [PeerId] = []

    /// Cleanup task
    private var cleanupTask: Task<Void, Never>?

    public init(config: Config = Config()) {
        self.config = config
    }

    // MARK: - Lifecycle

    /// Start the tracker with periodic cleanup
    public func start() {
        cleanupTask?.cancel()
        cleanupTask = Task {
            await runCleanupLoop()
        }
    }

    /// Stop the tracker
    public func stop() {
        cleanupTask?.cancel()
        cleanupTask = nil
    }

    private func runCleanupLoop() async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: UInt64(config.cleanupInterval * 1_000_000_000))
                pruneStale()
            } catch {
                break
            }
        }
    }

    // MARK: - Recording Contacts

    /// Record a successful communication with a peer
    public func recordContact(
        peerId: PeerId,
        reachability: ReachabilityPath,
        latencyMs: Int,
        connectionType: ConnectionType
    ) {
        let contact = RecentContact(
            peerId: peerId,
            lastSeen: Date(),
            reachability: reachability,
            latencyMs: latencyMs,
            connectionType: connectionType
        )

        // Remove from access order if exists
        if let index = accessOrder.firstIndex(of: peerId) {
            accessOrder.remove(at: index)
        }

        // Insert or update
        contacts[peerId] = contact
        accessOrder.append(peerId)

        // Evict if over capacity
        evictIfNeeded()
    }

    /// Update last seen time for an existing contact
    public func touch(_ peerId: PeerId) {
        guard var contact = contacts[peerId] else { return }

        // Create updated contact with new timestamp
        contact = RecentContact(
            peerId: contact.peerId,
            lastSeen: Date(),
            reachability: contact.reachability,
            latencyMs: contact.latencyMs,
            connectionType: contact.connectionType
        )
        contacts[peerId] = contact

        // Move to end of access order
        if let index = accessOrder.firstIndex(of: peerId) {
            accessOrder.remove(at: index)
            accessOrder.append(peerId)
        }
    }

    // MARK: - Querying Contacts

    /// Get a recent contact by peer ID
    public func getContact(_ peerId: PeerId) -> RecentContact? {
        guard let contact = contacts[peerId] else { return nil }

        // Check if stale
        if contact.age > config.maxAge {
            removeContact(peerId)
            return nil
        }

        return contact
    }

    /// Check if we have recent contact with a peer
    public func hasRecentContact(_ peerId: PeerId, maxAgeSeconds: Int) -> Bool {
        guard let contact = contacts[peerId] else { return false }
        return contact.ageSeconds <= maxAgeSeconds
    }

    /// Get contacts within a maximum age
    public func contactsWithin(maxAgeSeconds: Int) -> [RecentContact] {
        contacts.values.filter { $0.ageSeconds <= maxAgeSeconds }
    }

    /// Get all non-stale contacts
    public var allContacts: [RecentContact] {
        contacts.values.filter { $0.age <= config.maxAge }
    }

    /// Get peer IDs of all recent contacts
    public var recentPeerIds: [PeerId] {
        allContacts.map { $0.peerId }
    }

    /// Number of tracked contacts
    public var count: Int {
        contacts.count
    }

    // MARK: - Removal

    /// Remove a contact
    public func removeContact(_ peerId: PeerId) {
        contacts.removeValue(forKey: peerId)
        if let index = accessOrder.firstIndex(of: peerId) {
            accessOrder.remove(at: index)
        }
    }

    /// Remove contacts that used a specific path (for path failure handling)
    public func removeContactsUsingPath(_ path: ReachabilityPath) {
        let toRemove = contacts.filter { $0.value.reachability == path }.map { $0.key }
        for peerId in toRemove {
            removeContact(peerId)
        }
    }

    /// Remove all contacts
    public func clear() {
        contacts.removeAll()
        accessOrder.removeAll()
    }

    // MARK: - Private Helpers

    /// Remove stale contacts
    private func pruneStale() {
        let staleIds = contacts.filter { $0.value.age > config.maxAge }.map { $0.key }
        for peerId in staleIds {
            removeContact(peerId)
        }
    }

    /// Evict oldest contacts if over capacity
    private func evictIfNeeded() {
        while contacts.count > config.maxContacts && !accessOrder.isEmpty {
            let lruPeerId = accessOrder.removeFirst()
            contacts.removeValue(forKey: lruPeerId)
        }
    }
}
