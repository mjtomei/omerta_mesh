// PeerEndpointManager.swift - Multi-endpoint tracking by (peerId, machineId)

import Foundation
import Logging

/// Endpoints tracked for a specific machine
public struct MachineEndpoints: Codable, Sendable {
    public let peerId: PeerId
    public let machineId: MachineId
    public var endpoints: [String]       // Ordered list - front is best
    public var lastActivity: Date

    public init(peerId: PeerId, machineId: MachineId, endpoints: [String] = [], lastActivity: Date = Date()) {
        self.peerId = peerId
        self.machineId = machineId
        self.endpoints = endpoints
        self.lastActivity = lastActivity
    }

    /// Best endpoint - prefers IPv6 if available, otherwise first available
    public var bestEndpoint: String? {
        EndpointUtils.preferredEndpoint(from: endpoints)
    }

    public var isStale: Bool {
        Date().timeIntervalSince(lastActivity) > 86400  // 24 hours
    }

    /// Move endpoint to front (on receive or send success)
    public mutating func promoteEndpoint(_ endpoint: String) {
        endpoints.removeAll { $0 == endpoint }
        endpoints.insert(endpoint, at: 0)
        lastActivity = Date()
    }
}

/// Persistence format for peer endpoints (version 3: network-scoped)
private struct PeerEndpointsFile: Codable {
    let version: Int
    let savedAt: Date
    let networkId: String                     // Network this data belongs to
    let machines: [String: MachineEndpoints]  // key = "peerId:machineId"

    static let currentVersion = 3
}

/// Manages endpoint tracking for peers by (peerId, machineId)
/// Scoped by network ID to prevent cross-network data leakage
public actor PeerEndpointManager {
    private var machines: [String: MachineEndpoints] = [:]  // key = "peerId:machineId"
    private var natTypes: [PeerId: NATType] = [:]           // NAT type per peer
    private var isDirty = false
    private var cleanupTask: Task<Void, Never>?
    private var saveTask: Task<Void, Never>?
    private let logger: Logger
    private let maxEndpointsPerMachine = 1000

    /// Network ID this manager is scoped to
    private let networkId: String

    /// Endpoint validation mode
    private let validationMode: EndpointValidator.ValidationMode

    /// Storage path for peer endpoints
    private let storagePath: URL

    /// Initialize with network scoping
    /// - Parameters:
    ///   - networkId: Network ID to scope storage to
    ///   - validationMode: Endpoint validation strictness
    ///   - storagePath: Override storage path (for testing)
    ///   - logger: Override logger
    public init(
        networkId: String,
        validationMode: EndpointValidator.ValidationMode = .permissive,
        storagePath: URL? = nil,
        logger: Logger? = nil
    ) {
        self.networkId = networkId
        self.validationMode = validationMode
        self.storagePath = storagePath ?? URL(fileURLWithPath: getRealUserHome())
            .appendingPathComponent(".omerta/mesh/networks/\(networkId)/peer_endpoints.json")
        self.logger = logger ?? Logger(label: "io.omerta.mesh.endpoints")

        // Clean up legacy global files (one-time migration)
        Self.cleanupLegacyFiles(logger: self.logger)
    }

    /// Legacy init without networkId - for backwards compatibility during transition
    /// Generates a placeholder network ID from the storage path
    @available(*, deprecated, message: "Use init(networkId:) instead")
    public init(storagePath: URL? = nil, logger: Logger? = nil) {
        // Use a placeholder network ID derived from path or random
        self.networkId = "legacy-\(UUID().uuidString.prefix(8))"
        self.validationMode = .permissive
        self.storagePath = storagePath ?? URL(fileURLWithPath: getRealUserHome())
            .appendingPathComponent(".omerta/mesh/peer_endpoints.json")
        self.logger = logger ?? Logger(label: "io.omerta.mesh.endpoints")
    }

    /// Clean up legacy global files from pre-network-scoped versions
    private static func cleanupLegacyFiles(logger: Logger) {
        let meshDir = URL(fileURLWithPath: getRealUserHome())
            .appendingPathComponent(".omerta/mesh")

        // Old global files (pre-network-scoping)
        let legacyPaths = [
            meshDir.appendingPathComponent("peers.json"),
            meshDir.appendingPathComponent("peer_endpoints.json")
        ]

        for path in legacyPaths {
            if FileManager.default.fileExists(atPath: path.path) {
                do {
                    try FileManager.default.removeItem(at: path)
                    logger.info("Removed legacy file", metadata: ["path": "\(path.lastPathComponent)"])
                } catch {
                    logger.warning("Failed to remove legacy file", metadata: [
                        "path": "\(path.lastPathComponent)",
                        "error": "\(error)"
                    ])
                }
            }
        }
    }

    /// Start background tasks for cleanup and persistence
    public func start() async {
        // Load from disk
        do {
            try await load()
        } catch {
            logger.warning("Failed to load peer endpoints: \(error)")
        }

        // Run cleanup immediately on start (for short-lived daemon sessions)
        cleanup()

        // Start hourly cleanup task
        cleanupTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(3600))
                cleanup()
            }
        }

        // Start periodic save task (every 5 minutes if dirty)
        saveTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(300))
                if isDirty {
                    do {
                        try await save()
                    } catch {
                        logger.warning("Failed to save peer endpoints: \(error)")
                    }
                }
            }
        }
    }

    /// Stop background tasks and save
    public func stop() async {
        cleanupTask?.cancel()
        saveTask?.cancel()

        if isDirty {
            try? await save()
        }
    }

    // MARK: - Recording

    /// Record that we received a message from this endpoint
    /// Moves the endpoint to front of the list (highest priority)
    public func recordMessageReceived(from peerId: PeerId, machineId: MachineId, endpoint: String) {
        // Validate endpoint before storing
        let validation = EndpointValidator.validate(endpoint, mode: validationMode)
        guard validation.isValid else {
            logger.debug("Rejecting invalid endpoint on receive", metadata: [
                "endpoint": "\(endpoint)",
                "reason": "\(validation.reason ?? "unknown")"
            ])
            return
        }

        let key = makeKey(peerId: peerId, machineId: machineId)

        if var machine = machines[key] {
            machine.promoteEndpoint(endpoint)
            // Trim to max endpoints
            if machine.endpoints.count > maxEndpointsPerMachine {
                machine.endpoints = Array(machine.endpoints.prefix(maxEndpointsPerMachine))
            }
            machines[key] = machine
        } else {
            machines[key] = MachineEndpoints(
                peerId: peerId,
                machineId: machineId,
                endpoints: [endpoint],
                lastActivity: Date()
            )
        }

        isDirty = true
    }

    /// Record that we successfully sent to this endpoint
    /// Moves the endpoint to front of the list (highest priority)
    public func recordSendSuccess(to peerId: PeerId, machineId: MachineId, endpoint: String) {
        // Validate endpoint before storing
        let validation = EndpointValidator.validate(endpoint, mode: validationMode)
        guard validation.isValid else {
            logger.debug("Rejecting invalid endpoint on send", metadata: [
                "endpoint": "\(endpoint)",
                "reason": "\(validation.reason ?? "unknown")"
            ])
            return
        }

        let key = makeKey(peerId: peerId, machineId: machineId)

        if var machine = machines[key] {
            machine.promoteEndpoint(endpoint)
            machines[key] = machine
            isDirty = true
        }
    }

    // MARK: - Queries

    /// Get endpoints for a specific machine, ordered by priority (best first)
    /// Filters out invalid endpoints (defense in depth)
    public func getEndpoints(peerId: PeerId, machineId: MachineId) -> [String] {
        let key = makeKey(peerId: peerId, machineId: machineId)
        let endpoints = machines[key]?.endpoints ?? []
        // Filter on read (defense in depth)
        return EndpointValidator.filterValid(endpoints, mode: validationMode)
    }

    /// Get the best endpoint for a specific machine
    /// Returns nil if no valid endpoints. Prefers IPv6 if available.
    public func getBestEndpoint(peerId: PeerId, machineId: MachineId) -> String? {
        EndpointUtils.preferredEndpoint(from: getEndpoints(peerId: peerId, machineId: machineId))
    }

    /// Get all endpoints for all machines with this peerId (for broadcast)
    /// Filters out invalid endpoints. IPv6 first, then preserves recency order within each type.
    public func getAllEndpoints(peerId: PeerId) -> [String] {
        var endpoints: [String] = []
        for (key, machine) in machines {
            if key.hasPrefix("\(peerId):") {
                endpoints.append(contentsOf: machine.endpoints)
            }
        }
        // Filter on read (defense in depth)
        let validEndpoints = EndpointValidator.filterValid(endpoints, mode: validationMode)
        // Deduplicate while preserving order (most recently seen first within each machine)
        var seen = Set<String>()
        let deduped = validEndpoints.filter { seen.insert($0).inserted }
        // Partition into IPv6 and IPv4, preserving recency order within each
        // (don't alphabetically sort - that loses recency information)
        let ipv6 = deduped.filter { EndpointUtils.isIPv6($0) }
        let ipv4 = deduped.filter { !EndpointUtils.isIPv6($0) }
        return ipv6 + ipv4
    }

    /// Get all machines with this peerId
    public func getAllMachines(peerId: PeerId) -> [MachineEndpoints] {
        machines.values.filter { $0.peerId == peerId }
    }

    /// Get all known peer IDs, ordered by most recent activity first
    /// This ensures gossip prioritizes recently active peers
    public var allPeerIds: [PeerId] {
        // Group machines by peerId and get max lastActivity for each
        var peerActivity: [PeerId: Date] = [:]
        for machine in machines.values {
            if let existing = peerActivity[machine.peerId] {
                if machine.lastActivity > existing {
                    peerActivity[machine.peerId] = machine.lastActivity
                }
            } else {
                peerActivity[machine.peerId] = machine.lastActivity
            }
        }
        // Sort by most recent activity first
        return peerActivity.sorted { $0.value > $1.value }.map { $0.key }
    }

    /// Check if we have any endpoints for a peer
    public func hasEndpoints(for peerId: PeerId) -> Bool {
        machines.values.contains { $0.peerId == peerId && !$0.endpoints.isEmpty }
    }

    // MARK: - NAT Type Tracking

    /// Update the NAT type for a peer
    /// Called when we receive NAT type info from gossip or direct messages
    public func updateNATType(peerId: PeerId, natType: NATType) {
        // Only update if it's a meaningful value
        guard natType != .unknown else { return }

        let oldType = natTypes[peerId]
        if oldType != natType {
            natTypes[peerId] = natType
            isDirty = true
            if let old = oldType {
                logger.debug("NAT type updated for peer", metadata: [
                    "peerId": "\(peerId.prefix(8))",
                    "oldType": "\(old.rawValue)",
                    "newType": "\(natType.rawValue)"
                ])
            } else {
                logger.debug("NAT type recorded for peer", metadata: [
                    "peerId": "\(peerId.prefix(8))",
                    "type": "\(natType.rawValue)"
                ])
            }
        }
    }

    /// Get the NAT type for a peer
    public func getNATType(peerId: PeerId) -> NATType? {
        natTypes[peerId]
    }

    // MARK: - Persistence

    /// Load peer endpoints from disk
    public func load() async throws {
        guard FileManager.default.fileExists(atPath: storagePath.path) else {
            return
        }

        let data = try Data(contentsOf: storagePath)

        // Try to decode - handle version mismatches gracefully
        do {
            let file = try JSONCoding.decoder.decode(PeerEndpointsFile.self, from: data)

            // Version check
            guard file.version == PeerEndpointsFile.currentVersion else {
                logger.info("Old version \(file.version), starting fresh", metadata: [
                    "expected": "\(PeerEndpointsFile.currentVersion)"
                ])
                return
            }

            // Network ID check
            guard file.networkId == networkId else {
                logger.info("Different network, starting fresh", metadata: [
                    "stored": "\(file.networkId)",
                    "current": "\(networkId)"
                ])
                return
            }

            machines = file.machines
            logger.info("Loaded \(machines.count) machine endpoint records", metadata: [
                "networkId": "\(networkId)"
            ])
        } catch {
            // Decoding failed (old format or corrupt) - start fresh
            logger.warning("Failed to decode peer endpoints, starting fresh", metadata: [
                "error": "\(error)"
            ])
        }
    }

    /// Save peer endpoints to disk
    public func save() async throws {
        let file = PeerEndpointsFile(
            version: PeerEndpointsFile.currentVersion,
            savedAt: Date(),
            networkId: networkId,
            machines: machines
        )

        let data = try JSONCoding.prettyEncoder.encode(file)

        // Ensure directory exists
        let dir = storagePath.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        try data.write(to: storagePath)
        isDirty = false

        logger.debug("Saved \(machines.count) machine endpoint records", metadata: [
            "networkId": "\(networkId)"
        ])
    }

    // MARK: - Cleanup

    /// Remove stale endpoints (not seen in 24 hours)
    private func cleanup() {
        let staleKeys = machines.filter { $0.value.isStale }.map { $0.key }

        if !staleKeys.isEmpty {
            for key in staleKeys {
                machines.removeValue(forKey: key)
            }
            isDirty = true
            logger.info("Removed \(staleKeys.count) stale machine endpoint records")
        }
    }

    // MARK: - Helpers

    private func makeKey(peerId: PeerId, machineId: MachineId) -> String {
        "\(peerId):\(machineId)"
    }
}
