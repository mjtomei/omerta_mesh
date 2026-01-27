// VirtualNetwork.swift - In-process packet routing for testing

import Foundation
@testable import OmertaMesh

/// A virtual network that routes packets between TestNodes without real UDP
public actor VirtualNetwork {
    /// All nodes in the network, keyed by their ID
    private var nodes: [String: TestNode] = [:]

    /// Links between nodes (bidirectional)
    /// Key is "nodeA:nodeB" (sorted alphabetically)
    private var links: [String: LinkConfig] = [:]

    /// Partitioned groups (nodes in different groups can't communicate)
    private var partitionGroups: [[String]]? = nil

    /// Packets in flight (for simulating latency)
    private var pendingPackets: [PendingPacket] = []

    /// Whether the network is running
    private var isRunning = false

    /// Configuration for a link between two nodes
    public struct LinkConfig: Sendable {
        public var latencyMs: Int
        public var packetLossPercent: Double
        public var isEnabled: Bool

        public init(latencyMs: Int = 0, packetLossPercent: Double = 0, isEnabled: Bool = true) {
            self.latencyMs = latencyMs
            self.packetLossPercent = packetLossPercent
            self.isEnabled = isEnabled
        }
    }

    /// A packet waiting to be delivered
    private struct PendingPacket {
        let from: String
        let to: String
        let data: Data
        let deliverAt: Date
    }

    public init() {}

    // MARK: - Node Management

    /// Register a node with the network
    public func registerNode(_ node: TestNode) {
        nodes[node.id] = node
    }

    /// Get a node by ID
    public func node(_ id: String) -> TestNode? {
        nodes[id]
    }

    /// Get all node IDs
    public var nodeIds: [String] {
        Array(nodes.keys)
    }

    /// Remove a node (simulates node failure)
    public func removeNode(_ id: String) {
        nodes.removeValue(forKey: id)
    }

    // MARK: - Link Management

    /// Create or update a link between two nodes
    public func setLink(from: String, to: String, config: LinkConfig) {
        let key = linkKey(from, to)
        links[key] = config
    }

    /// Get link configuration
    public func getLink(from: String, to: String) -> LinkConfig? {
        links[linkKey(from, to)]
    }

    /// Disable a link (simulates network failure)
    public func disableLink(from: String, to: String) {
        let key = linkKey(from, to)
        links[key]?.isEnabled = false
    }

    /// Enable a link
    public func enableLink(from: String, to: String) {
        let key = linkKey(from, to)
        links[key]?.isEnabled = true
    }

    /// Set latency on a link
    public func setLatency(from: String, to: String, ms: Int) {
        let key = linkKey(from, to)
        links[key]?.latencyMs = ms
    }

    /// Set packet loss on a link
    public func setPacketLoss(from: String, to: String, percent: Double) {
        let key = linkKey(from, to)
        links[key]?.packetLossPercent = percent
    }

    private func linkKey(_ a: String, _ b: String) -> String {
        // Sort to make bidirectional lookup work
        a < b ? "\(a):\(b)" : "\(b):\(a)"
    }

    // MARK: - Partitioning

    /// Create a network partition
    public func partition(groups: [[String]]) {
        partitionGroups = groups
    }

    /// Heal all partitions
    public func healPartition() {
        partitionGroups = nil
    }

    /// Check if two nodes can communicate (not partitioned)
    private func canCommunicate(_ a: String, _ b: String) -> Bool {
        guard let groups = partitionGroups else { return true }

        // Find which groups a and b are in
        var aGroup: Int? = nil
        var bGroup: Int? = nil

        for (index, group) in groups.enumerated() {
            if group.contains(a) { aGroup = index }
            if group.contains(b) { bGroup = index }
        }

        // If either is not in a group, they can communicate
        guard let ag = aGroup, let bg = bGroup else { return true }

        // Can only communicate if in same group
        return ag == bg
    }

    // MARK: - Packet Routing

    /// Send a packet from one node to another
    public func send(from: String, to: String, data: Data) async {
        // Check if link exists and is enabled
        guard let link = links[linkKey(from, to)], link.isEnabled else {
            return // Packet dropped - no link
        }

        // Check partition
        guard canCommunicate(from, to) else {
            return // Packet dropped - partitioned
        }

        // Check packet loss
        if link.packetLossPercent > 0 {
            let random = Double.random(in: 0..<100)
            if random < link.packetLossPercent {
                return // Packet dropped - simulated loss
            }
        }

        // Calculate delivery time
        let deliverAt: Date
        if link.latencyMs > 0 {
            deliverAt = Date().addingTimeInterval(TimeInterval(link.latencyMs) / 1000.0)
        } else {
            deliverAt = Date()
        }

        // If no latency, deliver immediately
        if link.latencyMs == 0 {
            await deliverPacket(from: from, to: to, data: data)
        } else {
            // Queue for delayed delivery
            let packet = PendingPacket(from: from, to: to, data: data, deliverAt: deliverAt)
            pendingPackets.append(packet)

            // Schedule delivery
            Task {
                try? await Task.sleep(nanoseconds: UInt64(link.latencyMs) * 1_000_000)
                await self.deliverPendingPackets()
            }
        }
    }

    /// Deliver a packet to destination node
    private func deliverPacket(from: String, to: String, data: Data) async {
        guard let targetNode = nodes[to] else { return }
        await targetNode.receive(data: data, from: from)
    }

    /// Deliver any pending packets that are ready
    private func deliverPendingPackets() async {
        let now = Date()
        var delivered: [Int] = []

        for (index, packet) in pendingPackets.enumerated() {
            if packet.deliverAt <= now {
                await deliverPacket(from: packet.from, to: packet.to, data: packet.data)
                delivered.append(index)
            }
        }

        // Remove delivered packets (in reverse order to preserve indices)
        for index in delivered.reversed() {
            pendingPackets.remove(at: index)
        }
    }

    // MARK: - Lifecycle

    /// Start the virtual network
    public func start() {
        isRunning = true
    }

    /// Stop the virtual network
    public func stop() {
        isRunning = false
        pendingPackets.removeAll()
    }

    /// Shutdown and cleanup
    public func shutdown() async {
        stop()
        for node in nodes.values {
            await node.stop()
        }
        nodes.removeAll()
        links.removeAll()
    }
}
