// ConnectionKeepalive.swift - Maintains NAT mappings for direct connections
// Tracks by machine (peerId:machineId) with budget-based weighted sampling

import Foundation
import Logging

/// Manages keepalive pings to maintain NAT mappings for direct connections
/// Tracks machines (not just peers) and uses weighted random sampling to manage ping budget
public actor ConnectionKeepalive {
    /// Configuration for keepalive behavior
    public struct Config: Sendable {
        /// Interval between keepalive cycles (seconds)
        public let interval: TimeInterval

        /// Number of missed keepalives before marking connection as failed
        public let missedThreshold: Int

        /// Timeout for waiting for a pong response (seconds)
        public let responseTimeout: TimeInterval

        /// Maximum machines to ping per cycle (budget)
        public let maxMachinesPerCycle: Int

        /// Half-life for sampling weight decay (seconds)
        /// Machines contacted this long ago have 50% the weight of just-contacted machines
        public let samplingHalfLife: TimeInterval

        /// Minimum sampling weight (floor for very stale machines)
        /// Ensures stale machines still get occasional pings
        public let minSamplingWeight: Double

        public init(
            interval: TimeInterval = 15,
            missedThreshold: Int = 3,
            responseTimeout: TimeInterval = 5,
            maxMachinesPerCycle: Int = 30,
            samplingHalfLife: TimeInterval = 300,  // 5 minutes
            minSamplingWeight: Double = 0.05       // 5% floor
        ) {
            self.interval = interval
            self.missedThreshold = missedThreshold
            self.responseTimeout = responseTimeout
            self.maxMachinesPerCycle = maxMachinesPerCycle
            self.samplingHalfLife = samplingHalfLife
            self.minSamplingWeight = minSamplingWeight
        }

        public static let `default` = Config()
    }

    /// State of a tracked machine connection
    public struct MachineState: Sendable {
        public let peerId: PeerId
        public let machineId: MachineId
        public var lastKnownEndpoint: String?  // Last endpoint used for this machine
        public var lastSuccessfulPing: Date
        public var missedPings: Int

        public var isHealthy: Bool { missedPings < 3 }

        /// Backward compatibility: alias for lastKnownEndpoint
        public var endpoint: String { lastKnownEndpoint ?? "" }

        public init(peerId: PeerId, machineId: MachineId, endpoint: String? = nil) {
            self.peerId = peerId
            self.machineId = machineId
            self.lastKnownEndpoint = endpoint
            self.lastSuccessfulPing = Date()
            self.missedPings = 0
        }

        /// Key for this machine: "peerId:machineId"
        public var key: String { "\(peerId):\(machineId)" }
    }

    /// Callback type for getting best endpoint for a machine
    public typealias EndpointProvider = (PeerId, MachineId) async -> String?

    /// Callback type for sending pings (returns true if pong received)
    public typealias PingSender = (PeerId, MachineId, String) async -> Bool

    /// Callback type for reporting failed connections
    public typealias FailureHandler = (PeerId, MachineId, String) async -> Void

    // MARK: - Properties

    private let config: Config
    private let logger: Logger

    /// Active machines being monitored, keyed by "peerId:machineId"
    private var machines: [String: MachineState] = [:]

    /// Background task for keepalive loop
    private var keepaliveTask: Task<Void, Never>?

    /// Callback to get best endpoint for a machine (deprecated - use setServices)
    private var endpointProvider: EndpointProvider?

    /// Callback to send ping to a machine (deprecated - use setServices)
    private var pingSender: PingSender?

    /// Callback when a connection fails (deprecated - use setServices)
    private var failureHandler: FailureHandler?

    /// Unified services reference (preferred over individual callbacks)
    private weak var services: (any MeshNodeServices)?

    // MARK: - Initialization

    public init(config: Config = .default) {
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.keepalive")
    }

    // MARK: - Configuration

    /// Set the endpoint provider callback
    public func setEndpointProvider(_ provider: @escaping EndpointProvider) {
        self.endpointProvider = provider
    }

    /// Set the ping sender callback
    public func setPingSender(_ sender: @escaping PingSender) {
        self.pingSender = sender
    }

    /// Set the failure handler callback
    public func setFailureHandler(_ handler: @escaping FailureHandler) {
        self.failureHandler = handler
    }

    /// Set the unified services reference (preferred over individual callbacks)
    public func setServices(_ services: any MeshNodeServices) {
        self.services = services
    }

    // MARK: - Lifecycle

    /// Start the keepalive manager
    public func start() {
        guard keepaliveTask == nil else { return }

        keepaliveTask = Task {
            await runKeepaliveLoop()
        }

        logger.info("Connection keepalive started with interval \(config.interval)s")
    }

    /// Stop the keepalive manager
    public func stop() {
        keepaliveTask?.cancel()
        keepaliveTask = nil
        logger.info("Connection keepalive stopped")
    }

    /// Stop and clear all machines
    public func stopAndClear() {
        stop()
        machines.removeAll()
    }

    // MARK: - Machine Management

    /// Add a machine to monitor
    public func addMachine(peerId: PeerId, machineId: MachineId) {
        let key = "\(peerId):\(machineId)"
        if machines[key] == nil {
            machines[key] = MachineState(peerId: peerId, machineId: machineId)
            logger.debug("Added machine to monitor: \(peerId.prefix(8))...:\(machineId.prefix(8))...")
        }
    }

    /// Remove a machine from monitoring
    public func removeMachine(peerId: PeerId, machineId: MachineId) {
        let key = "\(peerId):\(machineId)"
        machines.removeValue(forKey: key)
        logger.debug("Removed machine from monitoring: \(peerId.prefix(8))...:\(machineId.prefix(8))...")
    }

    /// Record a successful communication (resets missed count)
    public func recordSuccessfulCommunication(peerId: PeerId, machineId: MachineId) {
        let key = "\(peerId):\(machineId)"
        if var state = machines[key] {
            state.lastSuccessfulPing = Date()
            state.missedPings = 0
            machines[key] = state
        }
    }

    /// Check if a machine is being monitored
    public func isMonitoring(peerId: PeerId, machineId: MachineId) -> Bool {
        let key = "\(peerId):\(machineId)"
        return machines[key] != nil
    }

    /// Get the state of a machine
    public func getMachineState(peerId: PeerId, machineId: MachineId) -> MachineState? {
        let key = "\(peerId):\(machineId)"
        return machines[key]
    }

    /// Get all monitored machines
    public var monitoredMachines: [MachineState] {
        Array(machines.values)
    }

    /// Get count of healthy machines
    public var healthyMachineCount: Int {
        machines.values.filter { $0.isHealthy }.count
    }

    /// Get total monitored machine count
    public var totalMachineCount: Int {
        machines.count
    }

    // MARK: - Backward Compatibility (PeerId-based API)
    // These methods maintain compatibility but internally use machine tracking

    /// Legacy connection state type (alias to MachineState)
    public typealias ConnectionState = MachineState

    /// Add a connection to monitor (legacy API - uses placeholder machineId)
    public func addConnection(peerId: PeerId, endpoint: String) {
        // Use endpoint hash as placeholder machineId for backward compatibility
        let placeholderMachineId = "legacy-\(endpoint.hashValue)"
        addMachine(peerId: peerId, machineId: placeholderMachineId)
    }

    /// Remove a connection from monitoring (legacy API)
    public func removeConnection(peerId: PeerId) {
        // Remove all machines for this peer
        let keysToRemove = machines.filter { $0.value.peerId == peerId }.map { $0.key }
        for key in keysToRemove {
            machines.removeValue(forKey: key)
        }
        logger.debug("Removed all machines for peer from monitoring: \(peerId.prefix(8))...")
    }

    /// Check if monitoring a peer (legacy API)
    public func isMonitoring(peerId: PeerId) -> Bool {
        machines.values.contains { $0.peerId == peerId }
    }

    /// Record successful communication for a peer (legacy API)
    public func recordSuccessfulCommunication(peerId: PeerId) {
        // Update all machines for this peer
        for (key, var state) in machines where state.peerId == peerId {
            state.lastSuccessfulPing = Date()
            state.missedPings = 0
            machines[key] = state
        }
    }

    /// Get all monitored connections (legacy API - returns machine states)
    public var monitoredConnections: [MachineState] {
        Array(machines.values)
    }

    // MARK: - Private Methods

    private func runKeepaliveLoop() async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: UInt64(config.interval * 1_000_000_000))
                await sendKeepalives()
            } catch {
                // Task cancelled
                break
            }
        }
    }

    private func sendKeepalives() async {
        // Prefer services if available, fall back to legacy callbacks
        let useServices = services != nil

        if !useServices {
            guard pingSender != nil else {
                logger.warning("No ping sender configured for keepalive")
                return
            }
            guard endpointProvider != nil else {
                logger.warning("No endpoint provider configured for keepalive")
                return
            }
        }

        // Select machines to ping this cycle using weighted sampling
        let selectedKeys = selectMachinesToPing()

        if !selectedKeys.isEmpty {
            logger.info("Sending keepalive pings to \(selectedKeys.count)/\(machines.count) machine(s)")
        }

        for key in selectedKeys {
            guard let state = machines[key] else { continue }

            // Get current best endpoint for this machine
            let endpoint: String?
            if let services = services {
                endpoint = await services.getEndpoint(peerId: state.peerId, machineId: state.machineId)
            } else {
                endpoint = await endpointProvider?(state.peerId, state.machineId)
            }

            guard let endpoint = endpoint else {
                logger.debug("No endpoint for machine \(state.peerId.prefix(8))...:\(state.machineId.prefix(8))...")
                continue
            }

            // Send ping
            let success: Bool
            if let services = services {
                success = await services.sendPing(peerId: state.peerId, machineId: state.machineId, endpoint: endpoint)
            } else {
                success = await pingSender?(state.peerId, state.machineId, endpoint) ?? false
            }

            if success {
                // Reset missed count on success and record endpoint
                if var updatedState = machines[key] {
                    updatedState.lastSuccessfulPing = Date()
                    updatedState.missedPings = 0
                    updatedState.lastKnownEndpoint = endpoint
                    machines[key] = updatedState
                    logger.info("Keepalive OK", metadata: [
                        "peer": "\(state.peerId.prefix(8))...",
                        "machine": "\(state.machineId.prefix(8))...",
                        "endpoint": "\(endpoint)"
                    ])
                }
            } else {
                // Increment missed count
                if var updatedState = machines[key] {
                    updatedState.missedPings += 1
                    machines[key] = updatedState

                    logger.warning("Keepalive missed", metadata: [
                        "peer": "\(state.peerId.prefix(8))...",
                        "machine": "\(state.machineId.prefix(8))...",
                        "missed": "\(updatedState.missedPings)/\(config.missedThreshold)"
                    ])

                    // Check if connection should be marked as failed
                    if updatedState.missedPings >= config.missedThreshold {
                        logger.warning("Connection to machine \(state.peerId.prefix(8))...:\(state.machineId.prefix(8))... failed")

                        // Remove from monitoring
                        machines.removeValue(forKey: key)

                        // Notify failure handler
                        if let services = services {
                            await services.handleKeepaliveFailure(peerId: state.peerId, machineId: state.machineId, endpoint: endpoint)
                        } else if let handler = failureHandler {
                            await handler(state.peerId, state.machineId, endpoint)
                        }
                    }
                }
            }
        }
    }

    /// Select machines to ping using weighted random sampling
    /// Recent machines have higher probability, stale machines still get occasional pings
    private func selectMachinesToPing() -> [String] {
        guard !machines.isEmpty else { return [] }

        let now = Date()

        // Calculate weights for all machines
        var weightedMachines: [(key: String, weight: Double)] = []
        for (key, state) in machines {
            let age = now.timeIntervalSince(state.lastSuccessfulPing)
            // Exponential decay: weight = 2^(-age/halfLife)
            // With floor to ensure stale machines still get some probability
            let decayWeight = pow(0.5, age / config.samplingHalfLife)
            let weight = max(config.minSamplingWeight, decayWeight)
            weightedMachines.append((key, weight))
        }

        // If we have fewer machines than budget, ping all of them
        if machines.count <= config.maxMachinesPerCycle {
            return Array(machines.keys)
        }

        // Weighted random sampling without replacement
        return weightedSampleWithoutReplacement(weightedMachines, count: config.maxMachinesPerCycle)
    }

    /// Weighted random sampling without replacement
    private func weightedSampleWithoutReplacement(_ items: [(key: String, weight: Double)], count: Int) -> [String] {
        var remaining = items
        var selected: [String] = []

        for _ in 0..<min(count, items.count) {
            guard !remaining.isEmpty else { break }

            // Calculate total weight
            let totalWeight = remaining.reduce(0.0) { $0 + $1.weight }
            guard totalWeight > 0 else { break }

            // Random selection weighted by probability
            let rand = Double.random(in: 0..<totalWeight)
            var cumulative = 0.0
            var selectedIndex = 0

            for (index, item) in remaining.enumerated() {
                cumulative += item.weight
                if rand < cumulative {
                    selectedIndex = index
                    break
                }
            }

            // Add selected item and remove from remaining
            selected.append(remaining[selectedIndex].key)
            remaining.remove(at: selectedIndex)
        }

        return selected
    }
}

// MARK: - Statistics

extension ConnectionKeepalive {
    /// Statistics about keepalive state
    public struct Statistics: Sendable {
        public let totalMachines: Int
        public let healthyMachines: Int
        public let unhealthyMachines: Int
        public let budgetPerCycle: Int

        public var healthPercentage: Double {
            guard totalMachines > 0 else { return 100.0 }
            return Double(healthyMachines) / Double(totalMachines) * 100.0
        }
    }

    /// Get current statistics
    public var statistics: Statistics {
        let healthy = machines.values.filter { $0.isHealthy }.count
        let unhealthy = machines.count - healthy
        return Statistics(
            totalMachines: machines.count,
            healthyMachines: healthy,
            unhealthyMachines: unhealthy,
            budgetPerCycle: config.maxMachinesPerCycle
        )
    }
}
