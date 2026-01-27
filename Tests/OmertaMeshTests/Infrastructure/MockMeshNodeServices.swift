// MockMeshNodeServices.swift - Mock implementation for testing

import Foundation
@testable import OmertaMesh

/// Mock implementation of MeshNodeServices for testing
public actor MockMeshNodeServices: MeshNodeServices {
    /// Sent messages for verification
    public var sentMessages: [(message: MeshMessage, peerId: PeerId, strategy: RoutingStrategy)] = []

    /// Broadcast messages for verification
    public var broadcasts: [(message: MeshMessage, maxHops: Int)] = []

    /// Configurable endpoints by peer
    public var endpointsByPeer: [PeerId: Endpoint] = [:]

    /// Configurable endpoints by (peerId, machineId)
    public var endpointsByMachine: [String: Endpoint] = [:]

    /// Configurable NAT types by peer
    public var natTypesByPeer: [PeerId: NATType] = [:]

    /// The coordinator peer ID to return
    public var coordinatorPeerId: PeerId? = nil

    /// Ping results by endpoint
    public var pingResults: [String: Bool] = [:]

    /// Cache invalidations for verification
    public var cacheInvalidations: [(peerId: PeerId, path: ReachabilityPath)] = []

    /// Keepalive failures for verification
    public var keepaliveFailures: [(peerId: PeerId, machineId: MachineId, endpoint: Endpoint)] = []

    /// All peer IDs
    public var peerIds: [PeerId] = []

    public init() {}

    // MARK: - MeshNodeServices Implementation

    public func send(_ message: MeshMessage, to peerId: PeerId, strategy: RoutingStrategy) async throws {
        sentMessages.append((message, peerId, strategy))
    }

    public func broadcast(_ message: MeshMessage, maxHops: Int) async {
        broadcasts.append((message, maxHops))
    }

    public func getEndpoint(for peerId: PeerId) async -> Endpoint? {
        endpointsByPeer[peerId]
    }

    public func getEndpoint(peerId: PeerId, machineId: MachineId) async -> Endpoint? {
        let key = "\(peerId):\(machineId)"
        if let endpoint = endpointsByMachine[key] {
            return endpoint
        }
        return endpointsByPeer[peerId]
    }

    public func getNATType(for peerId: PeerId) async -> NATType? {
        natTypesByPeer[peerId]
    }

    public var allPeerIds: [PeerId] {
        get async { peerIds.isEmpty ? Array(endpointsByPeer.keys) : peerIds }
    }

    public func getCoordinatorPeerId() async -> PeerId? {
        coordinatorPeerId
    }

    public func invalidateCache(peerId: PeerId, path: ReachabilityPath) async {
        cacheInvalidations.append((peerId, path))
    }

    public func sendPing(peerId: PeerId, machineId: MachineId, endpoint: Endpoint) async -> Bool {
        pingResults[endpoint] ?? true
    }

    public func handleKeepaliveFailure(peerId: PeerId, machineId: MachineId, endpoint: Endpoint) async {
        keepaliveFailures.append((peerId, machineId, endpoint))
    }

    // MARK: - Test Helpers

    /// Reset all recorded data
    public func reset() {
        sentMessages.removeAll()
        broadcasts.removeAll()
        cacheInvalidations.removeAll()
        keepaliveFailures.removeAll()
    }

    /// Configure endpoint for a peer
    public func setEndpoint(_ endpoint: Endpoint, for peerId: PeerId) {
        endpointsByPeer[peerId] = endpoint
    }

    /// Configure endpoint for a specific machine
    public func setEndpoint(_ endpoint: Endpoint, peerId: PeerId, machineId: MachineId) {
        let key = "\(peerId):\(machineId)"
        endpointsByMachine[key] = endpoint
    }

    /// Configure NAT type for a peer
    public func setNATType(_ natType: NATType, for peerId: PeerId) {
        natTypesByPeer[peerId] = natType
    }

    /// Configure ping result for an endpoint
    public func setPingResult(_ result: Bool, for endpoint: Endpoint) {
        pingResults[endpoint] = result
    }
}
