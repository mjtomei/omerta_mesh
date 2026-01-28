// MeshDaemonConfig.swift - Configuration for the mesh daemon
//
// Parses configuration from ~/.omerta/meshd.conf or command-line arguments.

import Foundation
import OmertaMesh

// MARK: - Mesh Daemon Configuration

/// Configuration for the mesh daemon
public struct MeshDaemonConfig: Codable, Sendable {
    /// Network ID to operate on
    public var networkId: String

    /// Port to bind for mesh network
    public var port: Int

    /// Whether this node can act as a relay
    public var canRelay: Bool

    /// Whether this node can coordinate hole punches
    public var canCoordinateHolePunch: Bool

    /// Bootstrap peers (format: peerId@host:port)
    public var bootstrapPeers: [String]

    /// Log level (trace, debug, info, warning, error)
    public var logLevel: String

    /// Whether to enable event logging
    public var enableEventLogging: Bool

    /// Event log directory (optional)
    public var eventLogDir: String?

    /// Path to identity file
    public var identityPath: String?

    /// Run in foreground (don't daemonize)
    public var foreground: Bool

    /// PID file path
    public var pidFile: String?

    /// LAN mode - bind to IPv4 (0.0.0.0) instead of specific IPv6 for cross-machine LAN testing
    public var lanMode: Bool

    /// Default configuration
    public static var `default`: MeshDaemonConfig {
        MeshDaemonConfig(
            networkId: "",
            port: 0,
            canRelay: false,
            canCoordinateHolePunch: false,
            bootstrapPeers: [],
            logLevel: "info",
            enableEventLogging: false,
            eventLogDir: nil,
            identityPath: nil,
            foreground: true,
            pidFile: nil,
            lanMode: false
        )
    }

    public init(
        networkId: String,
        port: Int = 0,
        canRelay: Bool = false,
        canCoordinateHolePunch: Bool = false,
        bootstrapPeers: [String] = [],
        logLevel: String = "info",
        enableEventLogging: Bool = false,
        eventLogDir: String? = nil,
        identityPath: String? = nil,
        foreground: Bool = true,
        pidFile: String? = nil,
        lanMode: Bool = false
    ) {
        self.networkId = networkId
        self.port = port
        self.canRelay = canRelay
        self.canCoordinateHolePunch = canCoordinateHolePunch
        self.bootstrapPeers = bootstrapPeers
        self.logLevel = logLevel
        self.enableEventLogging = enableEventLogging
        self.eventLogDir = eventLogDir
        self.identityPath = identityPath
        self.foreground = foreground
        self.pidFile = pidFile
        self.lanMode = lanMode
    }
}

// MARK: - Configuration Loading

extension MeshDaemonConfig {
    /// Load configuration from file
    /// - Parameter path: Path to configuration file (JSON format)
    /// - Returns: Loaded configuration
    public static func load(from path: String) throws -> MeshDaemonConfig {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)

        let decoder = JSONDecoder()
        return try decoder.decode(MeshDaemonConfig.self, from: data)
    }

    /// Load configuration from default location
    /// - Returns: Loaded configuration, or default if file doesn't exist
    public static func loadDefault() -> MeshDaemonConfig {
        let homeDir = getRealUserHome()
        let configPath = URL(fileURLWithPath: homeDir)
            .appendingPathComponent(".omerta/meshd.conf")
            .path

        if FileManager.default.fileExists(atPath: configPath) {
            do {
                return try load(from: configPath)
            } catch {
                // Fall through to default
            }
        }

        return .default
    }

    /// Save configuration to file
    /// - Parameter path: Path to save configuration to
    public func save(to path: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)

        let url = URL(fileURLWithPath: path)

        // Create directory if needed
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        try data.write(to: url)
    }

    /// Get default identity path
    public static var defaultIdentityPath: String {
        let homeDir = getRealUserHome()
        return URL(fileURLWithPath: homeDir)
            .appendingPathComponent(".omerta/mesh/identity.json")
            .path
    }

    /// Get default config path
    public static var defaultConfigPath: String {
        let homeDir = getRealUserHome()
        return URL(fileURLWithPath: homeDir)
            .appendingPathComponent(".omerta/meshd.conf")
            .path
    }

    /// Get default PID file path for a network
    public static func defaultPidFilePath(networkId: String) -> String {
        "/tmp/omerta-meshd-\(networkId).pid"
    }
}

// MARK: - Validation

extension MeshDaemonConfig {
    /// Validate the configuration
    public func validate() throws {
        if networkId.isEmpty {
            throw ConfigError.missingNetworkId
        }

        if port < 0 || port > 65535 {
            throw ConfigError.invalidPort(port)
        }

        // Validate bootstrap peer format
        for peer in bootstrapPeers {
            let parts = peer.split(separator: "@", maxSplits: 1)
            if parts.count != 2 {
                throw ConfigError.invalidBootstrapPeer(peer)
            }
        }
    }

    /// Configuration validation errors
    public enum ConfigError: Error, CustomStringConvertible {
        case missingNetworkId
        case invalidPort(Int)
        case invalidBootstrapPeer(String)
        case fileNotFound(String)

        public var description: String {
            switch self {
            case .missingNetworkId:
                return "Network ID is required"
            case .invalidPort(let port):
                return "Invalid port: \(port)"
            case .invalidBootstrapPeer(let peer):
                return "Invalid bootstrap peer format: '\(peer)' (expected: peerId@host:port)"
            case .fileNotFound(let path):
                return "Configuration file not found: \(path)"
            }
        }
    }
}

// MARK: - Helper

/// Get the real user's home directory (handles sudo correctly)
public func getRealUserHome() -> String {
    // Check for SUDO_USER first
    if let sudoUser = ProcessInfo.processInfo.environment["SUDO_USER"] {
        // Get home directory for the sudo user
        #if os(macOS)
        return "/Users/\(sudoUser)"
        #else
        return "/home/\(sudoUser)"
        #endif
    }

    // Fall back to current user's home
    return FileManager.default.homeDirectoryForCurrentUser.path
}
