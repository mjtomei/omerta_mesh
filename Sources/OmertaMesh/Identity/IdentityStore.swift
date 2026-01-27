// IdentityStore.swift - Persistent identity storage

import Foundation
import Logging

/// Persists mesh node identities to disk
/// Each network can have its own identity, or a default identity can be used
public actor IdentityStore {
    private let storePath: URL
    private let logger: Logger
    private var identities: [String: StoredIdentity] = [:]  // networkId or "default" -> identity

    /// Stored identity data
    private struct StoredIdentity: Codable {
        let privateKeyBase64: String
        let createdAt: Date
    }

    public init(storePath: URL) {
        self.storePath = storePath
        self.logger = Logger(label: "io.omerta.mesh.identitystore")
    }

    // MARK: - Identity Management

    /// Get or create identity for a network
    /// If no identity exists for this network, creates a new one
    public func getOrCreateIdentity(forNetwork networkId: String) async throws -> IdentityKeypair {
        // Try to load existing identity
        if let stored = identities[networkId] {
            return try IdentityKeypair(privateKeyBase64: stored.privateKeyBase64)
        }

        // Create new identity
        let identity = IdentityKeypair()
        let stored = StoredIdentity(
            privateKeyBase64: identity.privateKeyBase64,
            createdAt: Date()
        )
        identities[networkId] = stored

        // Save to disk
        try await save()

        logger.info("Created new identity for network \(networkId)", metadata: [
            "peerId": "\(identity.peerId)"
        ])

        return identity
    }

    /// Get identity for a network (returns nil if none exists)
    public func getIdentity(forNetwork networkId: String) throws -> IdentityKeypair? {
        guard let stored = identities[networkId] else {
            return nil
        }
        return try IdentityKeypair(privateKeyBase64: stored.privateKeyBase64)
    }

    /// Get the default identity (used when no network-specific identity exists)
    public func getOrCreateDefaultIdentity() async throws -> IdentityKeypair {
        return try await getOrCreateIdentity(forNetwork: "default")
    }

    /// Delete identity for a network
    public func deleteIdentity(forNetwork networkId: String) async throws {
        guard identities.removeValue(forKey: networkId) != nil else {
            return  // No identity to delete
        }
        try await save()
        logger.info("Deleted identity for network \(networkId)")
    }

    /// Check if identity exists for a network
    public func hasIdentity(forNetwork networkId: String) -> Bool {
        identities[networkId] != nil
    }

    // MARK: - Persistence

    /// Load identities from disk
    public func load() async throws {
        guard FileManager.default.fileExists(atPath: storePath.path) else {
            logger.debug("No identity store found at \(storePath.path)")
            return
        }

        let data = try Data(contentsOf: storePath)
        identities = try JSONCoding.iso8601Decoder.decode([String: StoredIdentity].self, from: data)

        logger.info("Loaded \(identities.count) identities from store")
    }

    /// Save identities to disk
    public func save() async throws {
        let data = try JSONCoding.iso8601PrettyEncoder.encode(identities)

        // Ensure directory exists
        try FileManager.default.createDirectory(
            at: storePath.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        try data.write(to: storePath)
        logger.debug("Saved \(identities.count) identities to store")
    }
}

// MARK: - Convenience Factory

extension IdentityStore {
    /// Create an identity store in the default location
    /// Uses getRealUserHome() to handle sudo correctly
    public static func defaultStore() -> IdentityStore {
        let homeDir = getRealUserHome()
        let storePath = URL(fileURLWithPath: homeDir)
            .appendingPathComponent(".omerta/mesh/identities.json")

        return IdentityStore(storePath: storePath)
    }
}
