// PeerStore.swift - Peer persistence across restarts (network-scoped)

import Foundation
import Logging

/// Persistence format for peer store (version 3: network-scoped)
private struct PeerStoreFile: Codable {
    let version: Int
    let savedAt: Date
    let networkId: String                   // Network this data belongs to
    let peers: [PeerId: StoredPeer]

    static let currentVersion = 3

    /// Stored peer with metadata
    struct StoredPeer: Codable {
        let announcement: PeerAnnouncement
        let lastSeenAt: Date
        let successfulContacts: Int
        let failedContacts: Int

        var reliability: Double {
            let total = successfulContacts + failedContacts
            guard total > 0 else { return 0.5 }
            return Double(successfulContacts) / Double(total)
        }
    }
}

/// Persists peer announcements to disk for recovery after restart
/// Scoped by network ID to prevent cross-network data leakage
public actor PeerStore {
    private let storePath: URL
    private let logger: Logger
    private let maxStoredPeers: Int

    /// Network ID this store is scoped to
    private let networkId: String

    /// Endpoint validation mode
    private let validationMode: EndpointValidator.ValidationMode

    /// Stored peer with metadata (internal alias)
    private typealias StoredPeer = PeerStoreFile.StoredPeer

    private var peers: [PeerId: StoredPeer] = [:]

    /// Initialize with network scoping
    /// - Parameters:
    ///   - networkId: Network ID to scope storage to
    ///   - validationMode: Endpoint validation strictness
    ///   - storePath: Override storage path (for testing)
    ///   - maxStoredPeers: Maximum number of peers to store
    public init(
        networkId: String,
        validationMode: EndpointValidator.ValidationMode = .permissive,
        storePath: URL? = nil,
        maxStoredPeers: Int = 500
    ) {
        self.networkId = networkId
        self.validationMode = validationMode
        self.storePath = storePath ?? URL(fileURLWithPath: getRealUserHome())
            .appendingPathComponent(".omerta/mesh/networks/\(networkId)/peers.json")
        self.maxStoredPeers = maxStoredPeers
        self.logger = Logger(label: "io.omerta.mesh.peerstore")

        // Clean up legacy global files (one-time migration)
        Self.cleanupLegacyFiles(logger: self.logger)
    }

    /// Legacy init without networkId - for backwards compatibility during transition
    @available(*, deprecated, message: "Use init(networkId:) instead")
    public init(storePath: URL, maxStoredPeers: Int = 500) {
        self.networkId = "legacy-\(UUID().uuidString.prefix(8))"
        self.validationMode = .permissive
        self.storePath = storePath
        self.maxStoredPeers = maxStoredPeers
        self.logger = Logger(label: "io.omerta.mesh.peerstore")
    }

    /// Clean up legacy global files from pre-network-scoped versions
    private static func cleanupLegacyFiles(logger: Logger) {
        let meshDir = URL(fileURLWithPath: getRealUserHome())
            .appendingPathComponent(".omerta/mesh")

        // Old global file (pre-network-scoping)
        let legacyPath = meshDir.appendingPathComponent("peers.json")

        if FileManager.default.fileExists(atPath: legacyPath.path) {
            do {
                try FileManager.default.removeItem(at: legacyPath)
                logger.info("Removed legacy file", metadata: ["path": "\(legacyPath.lastPathComponent)"])
            } catch {
                logger.warning("Failed to remove legacy file", metadata: [
                    "path": "\(legacyPath.lastPathComponent)",
                    "error": "\(error)"
                ])
            }
        }
    }

    // MARK: - Public API

    /// Load peers from disk
    public func load() async throws {
        guard FileManager.default.fileExists(atPath: storePath.path) else {
            logger.info("No peer store found", metadata: ["networkId": "\(networkId)"])
            return
        }

        let data = try Data(contentsOf: storePath)

        // Try to decode - handle version mismatches gracefully
        do {
            let file = try JSONCoding.decoder.decode(PeerStoreFile.self, from: data)

            // Version check
            guard file.version == PeerStoreFile.currentVersion else {
                logger.info("Old version \(file.version), starting fresh", metadata: [
                    "expected": "\(PeerStoreFile.currentVersion)"
                ])
                return
            }

            // Network ID check
            guard file.networkId == networkId else {
                logger.info("Different network, starting fresh", metadata: [
                    "stored": "\(file.networkId)",
                    "current": "\(networkId)"
                ])
                return
            }

            peers = file.peers

            // Remove expired peers and filter invalid endpoints
            cleanup()

            logger.info("Loaded \(peers.count) peers from store", metadata: [
                "networkId": "\(networkId)"
            ])
        } catch {
            // Decoding failed (old format or corrupt) - start fresh
            logger.warning("Failed to decode peer store, starting fresh", metadata: [
                "error": "\(error)"
            ])
        }
    }

    /// Save peers to disk
    public func save() async throws {
        let file = PeerStoreFile(
            version: PeerStoreFile.currentVersion,
            savedAt: Date(),
            networkId: networkId,
            peers: peers
        )

        let data = try JSONCoding.prettyEncoder.encode(file)

        // Ensure directory exists
        try FileManager.default.createDirectory(
            at: storePath.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        try data.write(to: storePath)
        logger.debug("Saved \(peers.count) peers to store", metadata: [
            "networkId": "\(networkId)"
        ])
    }

    /// Update or insert a peer
    /// Filters out invalid endpoints from the announcement before storing
    public func update(_ announcement: PeerAnnouncement, contactSuccessful: Bool = true) {
        // Filter invalid endpoints from the announcement
        let filteredAnnouncement = filterAnnouncement(announcement)

        // Skip if no valid reachability paths remain
        guard !filteredAnnouncement.reachability.isEmpty else {
            logger.debug("Rejecting announcement with no valid endpoints", metadata: [
                "peerId": "\(announcement.peerId)"
            ])
            return
        }

        let peerId = filteredAnnouncement.peerId

        if var existing = peers[peerId] {
            // Update existing
            if contactSuccessful {
                existing = StoredPeer(
                    announcement: filteredAnnouncement,
                    lastSeenAt: Date(),
                    successfulContacts: existing.successfulContacts + 1,
                    failedContacts: existing.failedContacts
                )
            } else {
                existing = StoredPeer(
                    announcement: existing.announcement,
                    lastSeenAt: existing.lastSeenAt,
                    successfulContacts: existing.successfulContacts,
                    failedContacts: existing.failedContacts + 1
                )
            }
            peers[peerId] = existing
        } else {
            // Insert new
            peers[peerId] = StoredPeer(
                announcement: filteredAnnouncement,
                lastSeenAt: Date(),
                successfulContacts: contactSuccessful ? 1 : 0,
                failedContacts: contactSuccessful ? 0 : 1
            )
        }

        // Evict if over capacity
        evictIfNeeded()
    }

    /// Mark a peer contact as failed
    public func markFailed(_ peerId: PeerId) {
        guard var existing = peers[peerId] else { return }
        existing = StoredPeer(
            announcement: existing.announcement,
            lastSeenAt: existing.lastSeenAt,
            successfulContacts: existing.successfulContacts,
            failedContacts: existing.failedContacts + 1
        )
        peers[peerId] = existing
    }

    /// Get all stored peers, sorted by reliability
    /// Filters out invalid endpoints (defense in depth)
    public func allPeers() -> [PeerAnnouncement] {
        peers.values
            .filter { !$0.announcement.isExpired }
            .sorted { $0.reliability > $1.reliability }
            .map { filterAnnouncement($0.announcement) }
            .filter { !$0.reachability.isEmpty }  // Only return peers with valid endpoints
    }

    /// Get peers with specific capability
    /// Filters out invalid endpoints (defense in depth)
    public func peers(withCapability capability: String) -> [PeerAnnouncement] {
        allPeers().filter { $0.capabilities.contains(capability) }
    }

    /// Get relay-capable peers
    /// Filters out invalid endpoints (defense in depth)
    public var relayPeers: [PeerAnnouncement] {
        peers(withCapability: "relay")
    }

    /// Remove a peer
    public func remove(_ peerId: PeerId) {
        peers.removeValue(forKey: peerId)
    }

    /// Number of stored peers
    public var count: Int {
        peers.count
    }

    // MARK: - Private Methods

    private func evictIfNeeded() {
        guard peers.count > maxStoredPeers else { return }

        // Sort by reliability and last seen
        let sorted = peers.sorted { a, b in
            // Prioritize reliability
            if abs(a.value.reliability - b.value.reliability) > 0.1 {
                return a.value.reliability > b.value.reliability
            }
            // Then by last seen
            return a.value.lastSeenAt > b.value.lastSeenAt
        }

        // Keep only top peers
        peers = [:]
        for (key, value) in sorted.prefix(maxStoredPeers) {
            peers[key] = value
        }
    }

    // MARK: - Endpoint Validation

    /// Filter invalid endpoints from a PeerAnnouncement
    /// Returns a new announcement with only valid reachability paths
    private func filterAnnouncement(_ announcement: PeerAnnouncement) -> PeerAnnouncement {
        let validPaths = announcement.reachability.filter { path in
            switch path {
            case .direct(let endpoint):
                let result = EndpointValidator.validate(endpoint, mode: validationMode)
                if !result.isValid {
                    logger.debug("Filtering invalid direct endpoint", metadata: [
                        "endpoint": "\(endpoint)",
                        "reason": "\(result.reason ?? "unknown")"
                    ])
                }
                return result.isValid

            case .relay(_, let relayEndpoint):
                let result = EndpointValidator.validate(relayEndpoint, mode: validationMode)
                if !result.isValid {
                    logger.debug("Filtering invalid relay endpoint", metadata: [
                        "endpoint": "\(relayEndpoint)",
                        "reason": "\(result.reason ?? "unknown")"
                    ])
                }
                return result.isValid

            case .holePunch:
                // Hole punch doesn't have a full endpoint to validate
                return true
            }
        }

        return PeerAnnouncement(
            peerId: announcement.peerId,
            publicKey: announcement.publicKey,
            reachability: validPaths,
            capabilities: announcement.capabilities,
            timestamp: announcement.timestamp,
            ttlSeconds: announcement.ttlSeconds,
            signature: announcement.signature
        )
    }

    // MARK: - Cleanup

    /// Remove expired peers and re-filter endpoints
    /// Called on load and can be called periodically
    private func cleanup() {
        let originalCount = peers.count

        // Remove expired peers
        peers = peers.filter { !$0.value.announcement.isExpired }

        // Re-filter endpoints in remaining peers and remove those with no valid paths
        var cleanedPeers: [PeerId: StoredPeer] = [:]
        for (peerId, stored) in peers {
            let filtered = filterAnnouncement(stored.announcement)
            if !filtered.reachability.isEmpty {
                cleanedPeers[peerId] = StoredPeer(
                    announcement: filtered,
                    lastSeenAt: stored.lastSeenAt,
                    successfulContacts: stored.successfulContacts,
                    failedContacts: stored.failedContacts
                )
            }
        }
        peers = cleanedPeers

        let removedCount = originalCount - peers.count
        if removedCount > 0 {
            logger.info("Cleaned up peer store", metadata: [
                "removed": "\(removedCount)",
                "remaining": "\(peers.count)"
            ])
        }
    }
}

// MARK: - Convenience Factory

extension PeerStore {
    /// Create a peer store in the default location for a network
    /// Uses getRealUserHome() to handle sudo correctly
    /// - Parameters:
    ///   - networkId: Network ID to scope storage to
    ///   - validationMode: Endpoint validation strictness
    public static func defaultStore(
        networkId: String,
        validationMode: EndpointValidator.ValidationMode = .strict
    ) -> PeerStore {
        return PeerStore(
            networkId: networkId,
            validationMode: validationMode
        )
    }
}

