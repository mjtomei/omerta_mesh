// MeshEventTypes.swift - Type-safe event types for mesh logging

import Foundation

// MARK: - Discovery Method

/// How a peer was discovered
public enum DiscoveryMethod: String, Sendable, Codable {
    case bootstrap = "bootstrap"     // From bootstrap server
    case gossip = "gossip"           // Via gossip from another peer
    case direct = "direct"           // Direct connection attempt
    case cached = "cached"           // Loaded from peer cache
}

// MARK: - Connection Events

/// Types of connection events
public enum ConnectionEventType: String, Sendable, Codable {
    case established = "established"  // Connection successfully established
    case failed = "failed"            // Connection attempt failed
    case closed = "closed"            // Connection closed normally
    case timeout = "timeout"          // Connection timed out
    case rejected = "rejected"        // Connection rejected by peer
}

// Note: ConnectionType is defined in RecentContactTracker.swift
// Use that ConnectionType for connection logging

// MARK: - Hole Punch Events

/// Types of hole punch events
public enum HolePunchEventType: String, Sendable, Codable {
    case started = "started"          // Hole punch attempt started
    case succeeded = "succeeded"      // Hole punch succeeded
    case failed = "failed"            // Hole punch failed
    case abandoned = "abandoned"      // Hole punch abandoned (e.g., direct connection established first)
}

// Note: HolePunchStrategy is defined in MeshMessage.swift
// Use HolePunchStrategy.rawValue when logging

// MARK: - Relay Events

/// Types of relay events
public enum RelayEventType: String, Sendable, Codable {
    case started = "started"          // Started using relay
    case closed = "closed"            // Stopped using relay (normal)
    case failed = "failed"            // Relay connection failed
    case upgraded = "upgraded"        // Upgraded from relay to direct
}

// MARK: - Message Events

/// Direction of message
public enum MessageDirection: String, Sendable, Codable {
    case sent = "sent"
    case received = "received"
}

/// Types of mesh messages
public enum MeshMessageType: String, Sendable, Codable {
    case data = "data"                // Application data
    case ping = "ping"                // Keepalive ping
    case pong = "pong"                // Keepalive pong
    case gossip = "gossip"            // Peer gossip
    case holePunchInit = "hole_punch_init"    // Hole punch initiation
    case holePunchProbe = "hole_punch_probe"  // Hole punch probe packet
    case relayRequest = "relay_request"       // Request to relay
    case relayData = "relay_data"             // Relayed data
    case freshnessQuery = "freshness_query"   // Freshness query
    case freshnessResponse = "freshness_response"  // Freshness response
    case unknown = "unknown"          // Unknown message type
}

// MARK: - NAT Events

/// Types of NAT events
public enum NATEventType: String, Sendable, Codable {
    case typeChanged = "type_changed"         // NAT type changed
    case endpointChanged = "endpoint_changed" // Public endpoint changed
    case detected = "detected"                // Initial NAT detection
}

// MARK: - Error Categories

/// Categories of mesh errors for logging
public enum MeshErrorCategory: String, Sendable, Codable {
    case network = "network"                  // Network-level errors
    case connection = "connection"            // Connection errors
    case encryption = "encryption"            // Encryption/decryption errors
    case signature = "signature"              // Signature verification errors
    case protocol_ = "protocol"               // Protocol errors
    case timeout = "timeout"                  // Timeout errors
    case resource = "resource"                // Resource exhaustion
    case configuration = "configuration"      // Configuration errors
    case internal_ = "internal"               // Internal errors
}

// MARK: - Component Names

/// Mesh components for error attribution
public enum MeshComponent: String, Sendable, Codable {
    case meshNode = "MeshNode"
    case peerEndpointManager = "PeerEndpointManager"
    case holePunchManager = "HolePunchManager"
    case holePunchCoordinator = "HolePunchCoordinator"
    case relayManager = "RelayManager"
    case relaySession = "RelaySession"
    case natDetector = "NATDetector"
    case stunClient = "STUNClient"
    case gossip = "Gossip"
    case peerCache = "PeerCache"
    case freshnessManager = "FreshnessManager"
    case connectionKeepalive = "ConnectionKeepalive"
    case udpSocket = "UDPSocket"
    case messageEncryption = "MessageEncryption"
}
