// MachinePeerRegistry.swift - Bidirectional mapping between machines and peers with recency tracking

import Foundation

/// Error thrown when a required association is not found
public enum RegistryError: Error, LocalizedError {
    case machineNotFound(peerId: PeerId)
    case peerNotFound(machineId: MachineId)

    public var errorDescription: String? {
        switch self {
        case .machineNotFound(let peerId):
            return "No machine found for peer \(peerId.prefix(16))... - have you received a message from this peer?"
        case .peerNotFound(let machineId):
            return "No peer found for machine \(machineId.prefix(16))... - have you received a message from this machine?"
        }
    }
}

/// Tracks the bidirectional mapping between machines and peers.
///
/// ## Key Concepts
/// - **Machine**: A physical/logical endpoint identified by a persistent UUID. Messages are *routed* to machines.
/// - **Peer**: A cryptographic identity (public key hash). Peers *authenticate* messages and represent users.
///
/// ## Important Usage Notes
///
/// ### When routing responses, use machineId (not peerId)
/// When you receive a message and need to respond, use the sender's machineId from the handler:
/// ```swift
/// // CORRECT: Route response to the machine that sent the request
/// try await provider.sendOnChannel(response, toMachine: senderMachineId, channel: "response")
///
/// // INCORRECT: Looking up machineId from peerId loses routing precision
/// let machineId = await registry.getMostRecentMachine(for: peerId)  // May get wrong machine!
/// ```
///
/// ### When identifying "who" sent a message, use peerId
/// If you need to know the identity (e.g., for authorization or VM ownership):
/// ```swift
/// let peerId = await registry.getMostRecentPeer(for: senderMachineId)
/// ```
///
/// ### Multiple associations are normal
/// - A machine can have multiple peers over time (user switched identity)
/// - A peer can have multiple machines (same user on laptop + desktop)
/// - Always use "most recent" methods, which return the latest association
///
/// A machine can be associated with multiple peers over time (e.g., if identity changes).
/// A peer can have multiple machines (same identity on different physical machines).
/// All associations track recency for ordering.
public actor MachinePeerRegistry {
    /// Association between a machine and peer with timestamp
    public struct Association: Sendable, Equatable {
        public let peerId: PeerId
        public let machineId: MachineId
        public var lastSeen: Date

        public init(peerId: PeerId, machineId: MachineId, lastSeen: Date = Date()) {
            self.peerId = peerId
            self.machineId = machineId
            self.lastSeen = lastSeen
        }
    }

    /// Machine → list of peer associations, ordered by most recent first
    private var machineToPeers: [MachineId: [Association]] = [:]

    /// Peer → list of machine associations, ordered by most recent first
    private var peerToMachines: [PeerId: [Association]] = [:]

    public init() {}

    // MARK: - Recording Associations

    /// Record an association between a machine and peer.
    /// This is called automatically when using subscript assignment.
    /// Updates recency if association already exists, or creates new one.
    private func record(machineId: MachineId, peerId: PeerId) {
        let now = Date()
        let association = Association(peerId: peerId, machineId: machineId, lastSeen: now)

        // Update machine → peers mapping
        var peers = machineToPeers[machineId] ?? []
        if let idx = peers.firstIndex(where: { $0.peerId == peerId }) {
            // Update existing and move to front
            peers.remove(at: idx)
        }
        peers.insert(association, at: 0)
        machineToPeers[machineId] = peers

        // Update peer → machines mapping
        var machines = peerToMachines[peerId] ?? []
        if let idx = machines.firstIndex(where: { $0.machineId == machineId }) {
            // Update existing and move to front
            machines.remove(at: idx)
        }
        machines.insert(association, at: 0)
        peerToMachines[peerId] = machines
    }

    // MARK: - Subscript Access (Machine → Peer)

    /// Get the most recent peer for a machine, or set/update the association.
    /// Setting automatically records with current timestamp.
    public subscript(machine machineId: MachineId) -> PeerId? {
        get {
            machineToPeers[machineId]?.first?.peerId
        }
    }

    /// Set/update the peer association for a machine.
    /// This records the association with current timestamp.
    public func setMachine(_ machineId: MachineId, peer peerId: PeerId) {
        record(machineId: machineId, peerId: peerId)
    }

    // MARK: - Queries

    /// Get all peers ever associated with a machine, ordered by most recent first
    public func getAllPeers(for machineId: MachineId) -> [Association] {
        machineToPeers[machineId] ?? []
    }

    /// Get the most recent peer for a machine.
    /// Use this when you need to identify who sent a message.
    public func getMostRecentPeer(for machineId: MachineId) -> PeerId? {
        machineToPeers[machineId]?.first?.peerId
    }

    /// Get the most recent peer for a machine, throwing if unknown.
    /// Use this when you *require* knowing the peer identity.
    public func requirePeer(for machineId: MachineId) throws -> PeerId {
        guard let peerId = machineToPeers[machineId]?.first?.peerId else {
            throw RegistryError.peerNotFound(machineId: machineId)
        }
        return peerId
    }

    /// Get all machines for a peer, ordered by most recent first
    public func getAllMachines(for peerId: PeerId) -> [Association] {
        peerToMachines[peerId] ?? []
    }

    /// Get the most recent machine for a peer.
    ///
    /// - Warning: Prefer using the machineId from the handler when routing responses.
    ///   Only use this when you truly need to initiate a connection to a peer
    ///   (e.g., the peer has multiple machines and you want to reach any of them).
    ///
    /// - Returns: The most recently seen machine for this peer, or nil if unknown.
    public func getMostRecentMachine(for peerId: PeerId) -> MachineId? {
        peerToMachines[peerId]?.first?.machineId
    }

    /// Get the most recent machine for a peer, throwing if unknown.
    ///
    /// - Warning: Prefer using the machineId from the handler when routing responses.
    ///   Only use this when you truly need to initiate a connection to a peer.
    ///
    /// - Throws: `RegistryError.machineNotFound` if no machine is known for this peer.
    /// - Returns: The most recently seen machine for this peer.
    public func requireMachine(for peerId: PeerId) throws -> MachineId {
        guard let machineId = peerToMachines[peerId]?.first?.machineId else {
            throw RegistryError.machineNotFound(peerId: peerId)
        }
        return machineId
    }

    /// Get full association details for a machine-peer pair
    public func getAssociation(machineId: MachineId, peerId: PeerId) -> Association? {
        machineToPeers[machineId]?.first { $0.peerId == peerId }
    }

    /// Check if a machine has any known peer association
    public func hasPeer(for machineId: MachineId) -> Bool {
        machineToPeers[machineId]?.isEmpty == false
    }

    /// Check if a peer has any known machine association
    public func hasMachine(for peerId: PeerId) -> Bool {
        peerToMachines[peerId]?.isEmpty == false
    }

    // MARK: - Statistics

    /// Total number of unique machines tracked
    public var machineCount: Int {
        machineToPeers.count
    }

    /// Total number of unique peers tracked
    public var peerCount: Int {
        peerToMachines.count
    }

    // MARK: - Cleanup

    /// Remove associations older than the given age
    public func removeStale(olderThan maxAge: TimeInterval) {
        let cutoff = Date().addingTimeInterval(-maxAge)

        for (machineId, associations) in machineToPeers {
            let filtered = associations.filter { $0.lastSeen > cutoff }
            if filtered.isEmpty {
                machineToPeers.removeValue(forKey: machineId)
            } else {
                machineToPeers[machineId] = filtered
            }
        }

        for (peerId, associations) in peerToMachines {
            let filtered = associations.filter { $0.lastSeen > cutoff }
            if filtered.isEmpty {
                peerToMachines.removeValue(forKey: peerId)
            } else {
                peerToMachines[peerId] = filtered
            }
        }
    }
}
