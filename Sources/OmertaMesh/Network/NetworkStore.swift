// NetworkStore.swift - Network membership persistence

import Foundation
import Logging

/// Persists network memberships to disk for recovery after restart
public actor NetworkStore {
    private let storePath: URL
    private let logger: Logger
    private var networks: [String: Network] = [:]  // networkId -> Network

    public init(storePath: URL) {
        self.storePath = storePath
        self.logger = Logger(label: "io.omerta.mesh.networkstore")
    }

    // MARK: - Network Management

    /// Join a network using a NetworkKey
    public func join(_ key: NetworkKey, name: String? = nil) async throws -> Network {
        let networkId = key.deriveNetworkId()

        // Check if already joined
        if networks[networkId] != nil {
            logger.warning("Already joined network: \(networkId)")
            throw NetworkStoreError.alreadyJoined
        }

        // Create network membership
        let network = Network(key: key, name: name)
        networks[networkId] = network

        logger.info("Joined network: \(network.name) (\(networkId))")

        // Save to disk immediately (don't fire-and-forget)
        try await save()

        return network
    }

    /// Leave a network
    public func leave(_ networkId: String) async throws {
        guard networks.removeValue(forKey: networkId) != nil else {
            throw NetworkStoreError.notFound
        }

        logger.info("Left network: \(networkId)")

        // Save to disk
        try await save()
    }

    /// Get all joined networks
    public func allNetworks() -> [Network] {
        Array(networks.values)
    }

    /// Get a specific network by ID
    public func network(id: String) -> Network? {
        networks[id]
    }

    /// Get active networks only
    public func activeNetworks() -> [Network] {
        networks.values.filter { $0.isActive }
    }

    /// Get the most recently joined network
    public func mostRecentNetwork() -> Network? {
        networks.values.max { $0.joinedAt < $1.joinedAt }
    }

    /// Set network active/inactive
    public func setActive(_ networkId: String, active: Bool) async throws {
        guard var network = networks[networkId] else {
            throw NetworkStoreError.notFound
        }

        network.isActive = active
        networks[networkId] = network

        logger.info("Network \(networkId) \(active ? "activated" : "deactivated")")

        try await save()
    }

    /// Check if a network exists
    public func contains(_ networkId: String) -> Bool {
        networks[networkId] != nil
    }

    /// Number of joined networks
    public var count: Int {
        networks.count
    }

    // MARK: - Bootstrap Peer Management

    /// Get bootstrap peers for a network
    public func bootstrapPeers(forNetwork networkId: String) -> [String]? {
        networks[networkId]?.key.bootstrapPeers
    }

    /// Update bootstrap peers for a network
    public func updateBootstrapPeers(_ networkId: String, peers: [String]) async throws {
        guard var network = networks[networkId] else {
            throw NetworkStoreError.notFound
        }

        network.key = network.key.withBootstrapPeers(peers)
        networks[networkId] = network

        logger.info("Updated bootstrap peers for network \(networkId): \(peers.count) peer(s)")

        try await save()
    }

    /// Add a bootstrap peer to a network
    public func addBootstrapPeer(_ networkId: String, peer: String) async throws {
        guard var network = networks[networkId] else {
            throw NetworkStoreError.notFound
        }

        let oldCount = network.key.bootstrapPeers.count
        network.key = network.key.addingBootstrapPeer(peer)
        networks[networkId] = network

        if network.key.bootstrapPeers.count > oldCount {
            logger.info("Added bootstrap peer to network \(networkId): \(peer)")
            try await save()
        } else {
            logger.debug("Bootstrap peer already exists in network \(networkId): \(peer)")
        }
    }

    /// Remove a bootstrap peer from a network
    public func removeBootstrapPeer(_ networkId: String, peer: String) async throws {
        guard var network = networks[networkId] else {
            throw NetworkStoreError.notFound
        }

        let oldCount = network.key.bootstrapPeers.count
        network.key = network.key.removingBootstrapPeer(peer)
        networks[networkId] = network

        if network.key.bootstrapPeers.count < oldCount {
            logger.info("Removed bootstrap peer from network \(networkId): \(peer)")
            try await save()
        } else {
            logger.debug("Bootstrap peer not found in network \(networkId): \(peer)")
        }
    }

    // MARK: - Persistence

    /// Load networks from disk
    public func load() async throws {
        guard FileManager.default.fileExists(atPath: storePath.path) else {
            logger.info("No network store found at \(storePath.path)")
            return
        }

        let data = try Data(contentsOf: storePath)

        // Handle empty file
        guard !data.isEmpty else {
            logger.debug("Network store file is empty")
            return
        }

        let stored = try JSONCoding.iso8601Decoder.decode([String: Network].self, from: data)
        networks = stored

        logger.info("Loaded \(networks.count) networks from store")
    }

    /// Save networks to disk
    public func save() async throws {
        let data = try JSONCoding.iso8601PrettyEncoder.encode(networks)

        // Ensure directory exists
        try FileManager.default.createDirectory(
            at: storePath.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        try data.write(to: storePath)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: storePath.path
        )
        logger.debug("Saved \(networks.count) networks to store")
    }
}

// MARK: - Convenience Factory

extension NetworkStore {
    /// Create a network store in the default location
    /// Uses getRealUserHome() to handle sudo correctly
    public static func defaultStore() -> NetworkStore {
        let homeDir = getRealUserHome()
        let storePath = URL(fileURLWithPath: homeDir)
            .appendingPathComponent(".omerta/mesh/networks.json")

        return NetworkStore(storePath: storePath)
    }
}

// MARK: - Errors

public enum NetworkStoreError: Error, LocalizedError {
    case alreadyJoined
    case notFound
    case persistenceFailed(String)

    public var errorDescription: String? {
        switch self {
        case .alreadyJoined:
            return "Already joined this network"
        case .notFound:
            return "Network not found"
        case .persistenceFailed(let details):
            return "Failed to save/load networks: \(details)"
        }
    }
}
