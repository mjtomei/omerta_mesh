// MeshConfig.swift - Configuration for the mesh network

import Foundation
import Crypto

/// Configuration for a mesh network node
public struct MeshConfig: Sendable {
    // MARK: - Security Settings

    /// 256-bit symmetric key for message encryption (ChaCha20-Poly1305)
    /// All mesh messages are encrypted with this key
    public let encryptionKey: Data

    /// Network ID derived from encryption key (used for storage scoping)
    /// This ensures each network has isolated persistent storage
    public var networkId: String {
        // Hash the encryption key and take first 16 hex chars for a readable ID
        let hash = SHA256.hash(data: encryptionKey)
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Storage Settings

    /// Directory for persistent storage (peers, networks)
    /// Defaults to ~/.omerta/mesh/
    public var storageDirectory: URL?

    // MARK: - Network Settings

    /// Port to bind to (0 for automatic)
    public var port: Int

    /// Whether this node can act as a relay for other peers
    public var canRelay: Bool

    /// Whether this node can coordinate hole punches for other peers
    public var canCoordinateHolePunch: Bool

    // MARK: - Relay Settings

    /// Target number of relay connections to maintain
    public var targetRelayCount: Int

    /// Maximum number of relay connections
    public var maxRelayCount: Int

    /// Maximum sessions to relay for other peers (if canRelay is true)
    public var maxRelaySessions: Int

    // MARK: - Timing Settings

    /// Interval between keepalive messages (seconds)
    public var keepaliveInterval: TimeInterval

    /// Timeout for connection attempts (seconds)
    public var connectionTimeout: TimeInterval

    /// Interval between peer cache cleanup (seconds)
    public var cacheCleanupInterval: TimeInterval

    // MARK: - Discovery Settings

    /// Bootstrap peers for initial discovery
    public var bootstrapPeers: [String]

    /// Maximum peers to track in cache
    public var maxCachedPeers: Int

    /// Time-to-live for cached peer info (seconds)
    public var peerCacheTTL: TimeInterval

    // MARK: - Hole Punch Settings

    /// Number of probe packets to send during hole punch
    public var holePunchProbeCount: Int

    /// Interval between hole punch probes (seconds)
    public var holePunchProbeInterval: TimeInterval

    /// Timeout for hole punch attempts (seconds)
    public var holePunchTimeout: TimeInterval

    // MARK: - Freshness Settings

    /// Maximum age for "recent" contact info (seconds)
    public var recentContactMaxAge: TimeInterval

    /// Interval between freshness queries for the same peer (seconds)
    public var freshnessQueryInterval: TimeInterval

    // MARK: - Logging Settings

    /// Whether to enable persistent event logging (default: false)
    public var enableEventLogging: Bool

    /// Custom directory for event logs (default: ~/.omerta/logs/mesh)
    public var eventLogDir: String?

    // MARK: - Debug Settings

    /// Force all communication through relays (skip direct and hole punch)
    /// Useful for testing relay code paths even when direct connectivity is available
    public var forceRelayOnly: Bool

    /// Allow localhost endpoints (127.0.0.1, ::1) for testing
    /// Default is false - localhost is rejected in production
    public var allowLocalhost: Bool

    // MARK: - Initialization

    public init(
        encryptionKey: Data,
        storageDirectory: URL? = nil,
        port: Int = 0,
        canRelay: Bool = false,
        canCoordinateHolePunch: Bool = false,
        targetRelayCount: Int = 3,
        maxRelayCount: Int = 5,
        maxRelaySessions: Int = 50,
        keepaliveInterval: TimeInterval = 15,
        connectionTimeout: TimeInterval = 10,
        cacheCleanupInterval: TimeInterval = 60,
        bootstrapPeers: [String] = [],
        maxCachedPeers: Int = 500,
        peerCacheTTL: TimeInterval = 3600,
        holePunchProbeCount: Int = 5,
        holePunchProbeInterval: TimeInterval = 0.2,
        holePunchTimeout: TimeInterval = 10,
        recentContactMaxAge: TimeInterval = 300,
        freshnessQueryInterval: TimeInterval = 30,
        enableEventLogging: Bool = false,
        eventLogDir: String? = nil,
        forceRelayOnly: Bool = false,
        allowLocalhost: Bool = false
    ) {
        self.encryptionKey = encryptionKey
        self.storageDirectory = storageDirectory
        self.port = port
        self.canRelay = canRelay
        self.canCoordinateHolePunch = canCoordinateHolePunch
        self.targetRelayCount = targetRelayCount
        self.maxRelayCount = maxRelayCount
        self.maxRelaySessions = maxRelaySessions
        self.keepaliveInterval = keepaliveInterval
        self.connectionTimeout = connectionTimeout
        self.cacheCleanupInterval = cacheCleanupInterval
        self.bootstrapPeers = bootstrapPeers
        self.maxCachedPeers = maxCachedPeers
        self.peerCacheTTL = peerCacheTTL
        self.holePunchProbeCount = holePunchProbeCount
        self.holePunchProbeInterval = holePunchProbeInterval
        self.holePunchTimeout = holePunchTimeout
        self.recentContactMaxAge = recentContactMaxAge
        self.freshnessQueryInterval = freshnessQueryInterval
        self.enableEventLogging = enableEventLogging
        self.eventLogDir = eventLogDir
        self.forceRelayOnly = forceRelayOnly
        self.allowLocalhost = allowLocalhost
    }

    /// Create a config from a NetworkKey
    public init(
        networkKey: NetworkKey,
        storageDirectory: URL? = nil,
        port: Int = 0,
        canRelay: Bool = false,
        canCoordinateHolePunch: Bool = false,
        enableEventLogging: Bool = false,
        eventLogDir: String? = nil,
        forceRelayOnly: Bool = false,
        allowLocalhost: Bool = false
    ) {
        self.encryptionKey = networkKey.networkKey
        self.storageDirectory = storageDirectory
        self.port = port
        self.canRelay = canRelay
        self.canCoordinateHolePunch = canCoordinateHolePunch
        self.targetRelayCount = 3
        self.maxRelayCount = 5
        self.maxRelaySessions = 50
        self.keepaliveInterval = 15
        self.connectionTimeout = 10
        self.cacheCleanupInterval = 60
        self.bootstrapPeers = networkKey.bootstrapPeers
        self.maxCachedPeers = 500
        self.peerCacheTTL = 3600
        self.holePunchProbeCount = 5
        self.holePunchProbeInterval = 0.2
        self.holePunchTimeout = 10
        self.recentContactMaxAge = 300
        self.freshnessQueryInterval = 30
        self.enableEventLogging = enableEventLogging
        self.eventLogDir = eventLogDir
        self.forceRelayOnly = forceRelayOnly
        self.allowLocalhost = allowLocalhost
    }

    // MARK: - Preset Configurations

    /// Configuration for a public relay node
    public static func relayNode(encryptionKey: Data, bootstrapPeers: [String] = []) -> MeshConfig {
        MeshConfig(
            encryptionKey: encryptionKey,
            canRelay: true,
            canCoordinateHolePunch: true,
            targetRelayCount: 0,  // Relay nodes don't need relays themselves
            maxRelayCount: 0,
            maxRelaySessions: 100,
            keepaliveInterval: 10,
            bootstrapPeers: bootstrapPeers
        )
    }

    /// Configuration for a server/always-on device
    public static func server(encryptionKey: Data, bootstrapPeers: [String] = []) -> MeshConfig {
        MeshConfig(
            encryptionKey: encryptionKey,
            canRelay: true,
            canCoordinateHolePunch: true,
            targetRelayCount: 5,
            maxRelayCount: 10,
            maxRelaySessions: 200,
            keepaliveInterval: 10,
            bootstrapPeers: bootstrapPeers,
            maxCachedPeers: 1000,
            peerCacheTTL: 7200  // 2 hour TTL
        )
    }

    // MARK: - Validation

    /// Validate the configuration
    public func validate() throws {
        if encryptionKey.count != 32 {
            throw MeshError.invalidConfiguration(reason: "Encryption key must be 32 bytes (256 bits)")
        }
        if port < 0 || port > 65535 {
            throw MeshError.invalidConfiguration(reason: "Port must be 0-65535")
        }
        if targetRelayCount < 0 {
            throw MeshError.invalidConfiguration(reason: "Target relay count must be non-negative")
        }
        if maxRelayCount < targetRelayCount {
            throw MeshError.invalidConfiguration(reason: "Max relay count must be >= target relay count")
        }
        if keepaliveInterval <= 0 {
            throw MeshError.invalidConfiguration(reason: "Keepalive interval must be positive")
        }
        if connectionTimeout <= 0 {
            throw MeshError.invalidConfiguration(reason: "Connection timeout must be positive")
        }
    }
}

// MARK: - Builder Pattern

extension MeshConfig {
    /// Create a builder for customizing configuration
    public static func builder(encryptionKey: Data) -> MeshConfigBuilder {
        MeshConfigBuilder(encryptionKey: encryptionKey)
    }

    /// Create a builder from a NetworkKey
    public static func builder(networkKey: NetworkKey) -> MeshConfigBuilder {
        MeshConfigBuilder(encryptionKey: networkKey.networkKey)
            .bootstrapPeers(networkKey.bootstrapPeers)
    }
}

/// Builder for MeshConfig
public class MeshConfigBuilder {
    private var encryptionKey: Data
    private var storageDirectory: URL?
    private var port: Int = 0
    private var canRelay: Bool = false
    private var canCoordinateHolePunch: Bool = false
    private var targetRelayCount: Int = 3
    private var maxRelayCount: Int = 5
    private var maxRelaySessions: Int = 50
    private var keepaliveInterval: TimeInterval = 15
    private var connectionTimeout: TimeInterval = 10
    private var cacheCleanupInterval: TimeInterval = 60
    private var bootstrapPeers: [String] = []
    private var maxCachedPeers: Int = 500
    private var peerCacheTTL: TimeInterval = 3600
    private var holePunchProbeCount: Int = 5
    private var holePunchProbeInterval: TimeInterval = 0.2
    private var holePunchTimeout: TimeInterval = 10
    private var recentContactMaxAge: TimeInterval = 300
    private var freshnessQueryInterval: TimeInterval = 30
    private var enableEventLogging: Bool = false
    private var eventLogDir: String?
    private var forceRelayOnly: Bool = false
    private var allowLocalhost: Bool = false

    public init(encryptionKey: Data) {
        self.encryptionKey = encryptionKey
    }

    @discardableResult
    public func storageDirectory(_ dir: URL?) -> Self {
        storageDirectory = dir
        return self
    }

    @discardableResult
    public func port(_ port: Int) -> Self {
        self.port = port
        return self
    }

    @discardableResult
    public func canRelay(_ canRelay: Bool) -> Self {
        self.canRelay = canRelay
        return self
    }

    @discardableResult
    public func canCoordinateHolePunch(_ can: Bool) -> Self {
        self.canCoordinateHolePunch = can
        return self
    }

    @discardableResult
    public func targetRelayCount(_ count: Int) -> Self {
        self.targetRelayCount = count
        return self
    }

    @discardableResult
    public func maxRelayCount(_ count: Int) -> Self {
        self.maxRelayCount = count
        return self
    }

    @discardableResult
    public func keepaliveInterval(_ interval: TimeInterval) -> Self {
        self.keepaliveInterval = interval
        return self
    }

    @discardableResult
    public func connectionTimeout(_ timeout: TimeInterval) -> Self {
        self.connectionTimeout = timeout
        return self
    }

    @discardableResult
    public func bootstrapPeers(_ peers: [String]) -> Self {
        self.bootstrapPeers = peers
        return self
    }

    @discardableResult
    public func addBootstrapPeer(_ peer: String) -> Self {
        self.bootstrapPeers.append(peer)
        return self
    }

    @discardableResult
    public func enableEventLogging(_ enabled: Bool) -> Self {
        self.enableEventLogging = enabled
        return self
    }

    @discardableResult
    public func eventLogDir(_ dir: String?) -> Self {
        self.eventLogDir = dir
        return self
    }

    @discardableResult
    public func forceRelayOnly(_ force: Bool) -> Self {
        self.forceRelayOnly = force
        return self
    }

    @discardableResult
    public func allowLocalhost(_ allow: Bool) -> Self {
        self.allowLocalhost = allow
        return self
    }

    public func build() throws -> MeshConfig {
        let config = MeshConfig(
            encryptionKey: encryptionKey,
            storageDirectory: storageDirectory,
            port: port,
            canRelay: canRelay,
            canCoordinateHolePunch: canCoordinateHolePunch,
            targetRelayCount: targetRelayCount,
            maxRelayCount: maxRelayCount,
            maxRelaySessions: maxRelaySessions,
            keepaliveInterval: keepaliveInterval,
            connectionTimeout: connectionTimeout,
            cacheCleanupInterval: cacheCleanupInterval,
            bootstrapPeers: bootstrapPeers,
            maxCachedPeers: maxCachedPeers,
            peerCacheTTL: peerCacheTTL,
            holePunchProbeCount: holePunchProbeCount,
            holePunchProbeInterval: holePunchProbeInterval,
            holePunchTimeout: holePunchTimeout,
            recentContactMaxAge: recentContactMaxAge,
            freshnessQueryInterval: freshnessQueryInterval,
            enableEventLogging: enableEventLogging,
            eventLogDir: eventLogDir,
            forceRelayOnly: forceRelayOnly,
            allowLocalhost: allowLocalhost
        )
        try config.validate()
        return config
    }

    public func buildUnchecked() -> MeshConfig {
        MeshConfig(
            encryptionKey: encryptionKey,
            storageDirectory: storageDirectory,
            port: port,
            canRelay: canRelay,
            canCoordinateHolePunch: canCoordinateHolePunch,
            targetRelayCount: targetRelayCount,
            maxRelayCount: maxRelayCount,
            maxRelaySessions: maxRelaySessions,
            keepaliveInterval: keepaliveInterval,
            connectionTimeout: connectionTimeout,
            cacheCleanupInterval: cacheCleanupInterval,
            bootstrapPeers: bootstrapPeers,
            maxCachedPeers: maxCachedPeers,
            peerCacheTTL: peerCacheTTL,
            holePunchProbeCount: holePunchProbeCount,
            holePunchProbeInterval: holePunchProbeInterval,
            holePunchTimeout: holePunchTimeout,
            recentContactMaxAge: recentContactMaxAge,
            freshnessQueryInterval: freshnessQueryInterval,
            enableEventLogging: enableEventLogging,
            eventLogDir: eventLogDir,
            forceRelayOnly: forceRelayOnly,
            allowLocalhost: allowLocalhost
        )
    }
}
