// MeshNodeServices.swift - Unified service protocol for mesh subsystems

import Foundation

/// Routing strategy for outbound messages
public enum RoutingStrategy: Sendable {
    /// Send directly to endpoint, bypassing routing logic
    case direct(endpoint: Endpoint)
    /// Automatic: IPv6 preferred > direct if reachable > relay
    case auto
    /// Force relay routing through a specific peer
    case relay(via: PeerId)
}

/// Protocol providing network services to mesh subsystems
/// Replaces individual callback registrations with a single unified interface
public protocol MeshNodeServices: AnyObject, Sendable {
    // MARK: - Message Sending

    /// Send a message to a peer with the specified routing strategy
    func send(_ message: MeshMessage, to peerId: PeerId, strategy: RoutingStrategy) async throws

    /// Broadcast a message to all known peers
    func broadcast(_ message: MeshMessage, maxHops: Int) async

    // MARK: - Peer Information

    /// Get the best available endpoint for a peer
    func getEndpoint(for peerId: PeerId) async -> Endpoint?

    /// Get endpoint for a specific machine
    func getEndpoint(peerId: PeerId, machineId: MachineId) async -> Endpoint?

    /// Get the NAT type for a peer
    func getNATType(for peerId: PeerId) async -> NATType?

    /// Get all known peer IDs
    var allPeerIds: [PeerId] { get async }

    // MARK: - Coordination

    /// Get a peer that can serve as coordinator (for hole punching)
    func getCoordinatorPeerId() async -> PeerId?

    // MARK: - Cache Operations

    /// Invalidate cached information for a peer's path
    func invalidateCache(peerId: PeerId, path: ReachabilityPath) async

    // MARK: - Keepalive

    /// Send a ping to a specific endpoint and return whether it succeeded
    func sendPing(peerId: PeerId, machineId: MachineId, endpoint: Endpoint) async -> Bool

    /// Handle a keepalive failure for a machine
    func handleKeepaliveFailure(peerId: PeerId, machineId: MachineId, endpoint: Endpoint) async
}
