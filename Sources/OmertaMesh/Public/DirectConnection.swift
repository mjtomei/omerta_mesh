// DirectConnection.swift - Represents a direct connection for WireGuard integration

import Foundation

/// Represents a direct connection to a peer, suitable for WireGuard configuration
public struct DirectConnection: Sendable, Equatable {
    /// The peer's ID (typically their public key)
    public let peerId: PeerId

    /// The peer's current endpoint (host:port)
    public let endpoint: Endpoint

    /// Whether this is a truly direct connection (vs relayed)
    public let isDirect: Bool

    /// The relay peer ID if this connection goes through a relay
    public let relayPeerId: PeerId?

    /// The peer's NAT type
    public let natType: NATType

    /// When this connection was established
    public let establishedAt: Date

    /// Last successful communication time
    public var lastCommunication: Date

    /// Round-trip time in milliseconds (if measured)
    public let rttMs: Double?

    /// How the connection was established
    public let method: ConnectionMethod

    public init(
        peerId: PeerId,
        endpoint: Endpoint,
        isDirect: Bool,
        relayPeerId: PeerId? = nil,
        natType: NATType = .unknown,
        establishedAt: Date = Date(),
        lastCommunication: Date = Date(),
        rttMs: Double? = nil,
        method: ConnectionMethod = .bootstrap
    ) {
        self.peerId = peerId
        self.endpoint = endpoint
        self.isDirect = isDirect
        self.relayPeerId = relayPeerId
        self.natType = natType
        self.establishedAt = establishedAt
        self.lastCommunication = lastCommunication
        self.rttMs = rttMs
        self.method = method
    }

    /// Age of the connection in seconds
    public var age: TimeInterval {
        Date().timeIntervalSince(establishedAt)
    }

    /// Time since last communication in seconds
    public var timeSinceLastCommunication: TimeInterval {
        Date().timeIntervalSince(lastCommunication)
    }

    /// Whether the connection is considered stale
    public func isStale(threshold: TimeInterval = 300) -> Bool {
        timeSinceLastCommunication > threshold
    }
}

/// How a connection was established
public enum ConnectionMethod: String, Sendable, Equatable, CaseIterable {
    /// Connected via bootstrap peer announcement
    case bootstrap

    /// Connected via peer discovery/announcement
    case discovery

    /// Connected via hole punching
    case holePunch

    /// Connected via relay
    case relay

    /// Manually specified endpoint
    case manual
}

// MARK: - Connection Quality

extension DirectConnection {
    /// Connection quality based on RTT and stability
    public var quality: ConnectionQuality {
        guard isDirect else {
            return .relayed
        }

        guard let rtt = rttMs else {
            return .unknown
        }

        if rtt < 50 {
            return .excellent
        } else if rtt < 100 {
            return .good
        } else if rtt < 200 {
            return .fair
        } else {
            return .poor
        }
    }
}

/// Quality of a connection
public enum ConnectionQuality: String, Sendable, Equatable, Comparable {
    case excellent
    case good
    case fair
    case poor
    case relayed
    case unknown

    public static func < (lhs: ConnectionQuality, rhs: ConnectionQuality) -> Bool {
        let order: [ConnectionQuality] = [.unknown, .relayed, .poor, .fair, .good, .excellent]
        guard let lhsIndex = order.firstIndex(of: lhs),
              let rhsIndex = order.firstIndex(of: rhs) else {
            return false
        }
        return lhsIndex < rhsIndex
    }
}

// MARK: - WireGuard Configuration

extension DirectConnection {
    /// Generate WireGuard peer configuration string
    public func wireGuardPeerConfig(allowedIPs: [String] = ["0.0.0.0/0", "::/0"]) -> String {
        var config = """
        [Peer]
        PublicKey = \(peerId)
        Endpoint = \(endpoint)
        AllowedIPs = \(allowedIPs.joined(separator: ", "))
        """

        if !isDirect, let relay = relayPeerId {
            config += "\n# Via relay: \(relay)"
        }

        return config
    }

    /// Host part of the endpoint
    public var host: String {
        if let colonIndex = endpoint.lastIndex(of: ":") {
            return String(endpoint[..<colonIndex])
        }
        return endpoint
    }

    /// Port part of the endpoint
    public var port: UInt16? {
        if let colonIndex = endpoint.lastIndex(of: ":") {
            let portString = String(endpoint[endpoint.index(after: colonIndex)...])
            return UInt16(portString)
        }
        return nil
    }
}

// MARK: - Connection State

/// State of a direct connection
public enum DirectConnectionState: Sendable, Equatable {
    /// Attempting to establish connection
    case connecting

    /// Connection is active
    case connected

    /// Connection is degraded (high latency or packet loss)
    case degraded

    /// Connection was lost, attempting to reconnect
    case reconnecting

    /// Connection failed
    case failed(reason: String)

    /// Connection was closed
    case closed

    public var isActive: Bool {
        switch self {
        case .connected, .degraded:
            return true
        default:
            return false
        }
    }
}

// MARK: - Connection Tracker

/// Tracks and manages direct connections
public actor DirectConnectionTracker {
    private var connections: [PeerId: DirectConnection] = [:]
    private var connectionStates: [PeerId: DirectConnectionState] = [:]
    private let staleThreshold: TimeInterval

    public init(staleThreshold: TimeInterval = 300) {
        self.staleThreshold = staleThreshold
    }

    /// Add or update a connection
    public func setConnection(_ connection: DirectConnection) {
        connections[connection.peerId] = connection
        if connectionStates[connection.peerId] == nil {
            connectionStates[connection.peerId] = .connected
        }
    }

    /// Get a connection
    public func getConnection(for peerId: PeerId) -> DirectConnection? {
        connections[peerId]
    }

    /// Remove a connection
    public func removeConnection(for peerId: PeerId) {
        connections.removeValue(forKey: peerId)
        connectionStates.removeValue(forKey: peerId)
    }

    /// Update connection state
    public func setState(_ state: DirectConnectionState, for peerId: PeerId) {
        connectionStates[peerId] = state
    }

    /// Get connection state
    public func getState(for peerId: PeerId) -> DirectConnectionState? {
        connectionStates[peerId]
    }

    /// Update last communication time
    public func updateLastCommunication(for peerId: PeerId) {
        if var connection = connections[peerId] {
            connection.lastCommunication = Date()
            connections[peerId] = connection
        }
    }

    /// Get all active connections
    public var activeConnections: [DirectConnection] {
        connections.values.filter { connection in
            guard let state = connectionStates[connection.peerId] else {
                return false
            }
            return state.isActive
        }
    }

    /// Get all direct (non-relayed) connections
    public var directConnections: [DirectConnection] {
        connections.values.filter { $0.isDirect }
    }

    /// Get all relayed connections
    public var relayedConnections: [DirectConnection] {
        connections.values.filter { !$0.isDirect }
    }

    /// Get stale connections
    public var staleConnections: [DirectConnection] {
        connections.values.filter { $0.isStale(threshold: staleThreshold) }
    }

    /// Get best connection to a peer (direct preferred, lowest RTT)
    public func bestConnection(to peerId: PeerId) -> DirectConnection? {
        connections[peerId]
    }

    /// Find connections via a specific relay
    public func connections(viaRelay relayId: PeerId) -> [DirectConnection] {
        connections.values.filter { $0.relayPeerId == relayId }
    }

    /// Number of connections
    public var count: Int {
        connections.count
    }

    /// Number of direct connections
    public var directCount: Int {
        directConnections.count
    }
}

// MARK: - Description

extension DirectConnection: CustomStringConvertible {
    public var description: String {
        var parts = ["DirectConnection(\(peerId.prefix(8))... @ \(endpoint)"]

        if isDirect {
            parts.append("direct")
        } else if let relay = relayPeerId {
            parts.append("via \(relay.prefix(8))...")
        }

        if let rtt = rttMs {
            parts.append("RTT: \(Int(rtt))ms")
        }

        parts.append("method: \(method.rawValue)")

        return parts.joined(separator: ", ") + ")"
    }
}
