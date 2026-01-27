// Network.swift - Network membership model

import Foundation

/// Represents a network membership
public struct Network: Identifiable, Sendable, Codable {
    public let id: String  // Derived from network key hash
    public let name: String
    public var key: NetworkKey  // Mutable to allow bootstrap peer updates
    public let joinedAt: Date
    public var isActive: Bool

    public init(
        id: String,
        name: String,
        key: NetworkKey,
        joinedAt: Date = Date(),
        isActive: Bool = true
    ) {
        self.id = id
        self.name = name
        self.key = key
        self.joinedAt = joinedAt
        self.isActive = isActive
    }

    /// Create a network from a NetworkKey
    public init(key: NetworkKey, name: String? = nil) {
        self.id = key.deriveNetworkId()
        self.name = name ?? key.networkName
        self.key = key
        self.joinedAt = Date()
        self.isActive = true
    }
}
