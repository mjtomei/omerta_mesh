// TestNetworkBuilder.swift - DSL for creating test network topologies

import Foundation
@testable import OmertaMesh

/// Builder for creating test network topologies
public class TestNetworkBuilder {
    /// Nodes to be created
    private var nodeConfigs: [NodeConfig] = []

    /// Links between nodes
    private var linkConfigs: [LinkConfig] = []

    /// Configuration for a node
    private struct NodeConfig {
        let id: String
        let natType: NATType
        let portAllocation: SimulatedNAT.PortAllocationStrategy
    }

    /// Configuration for a link
    private struct LinkConfig {
        let from: String
        let to: String
        let latencyMs: Int
        let packetLossPercent: Double
    }

    public init() {}

    // MARK: - Adding Nodes

    /// Add a public node (no NAT)
    @discardableResult
    public func addPublicNode(id: String) -> Self {
        nodeConfigs.append(NodeConfig(
            id: id,
            natType: .public,
            portAllocation: .sequential
        ))
        return self
    }

    /// Add a node (shorthand for public node)
    @discardableResult
    public func addNode(id: String) -> Self {
        addPublicNode(id: id)
    }

    /// Add a node behind NAT
    @discardableResult
    public func addNATNode(
        id: String,
        natType: NATType,
        portAllocation: SimulatedNAT.PortAllocationStrategy = .sequential
    ) -> Self {
        nodeConfigs.append(NodeConfig(
            id: id,
            natType: natType,
            portAllocation: portAllocation
        ))
        return self
    }

    /// Add a STUN server node (just a public node with a special role)
    @discardableResult
    public func addSTUNServer(id: String) -> Self {
        addPublicNode(id: id)
    }

    // MARK: - Adding Links

    /// Add a bidirectional link between two nodes
    @discardableResult
    public func link(
        _ from: String,
        _ to: String,
        latencyMs: Int = 0,
        packetLossPercent: Double = 0
    ) -> Self {
        linkConfigs.append(LinkConfig(
            from: from,
            to: to,
            latencyMs: latencyMs,
            packetLossPercent: packetLossPercent
        ))
        return self
    }

    // MARK: - Topology Helpers

    /// Create a linear topology: A-B-C-D-...
    @discardableResult
    public func addLinearTopology(count: Int, prefix: String = "node") -> Self {
        for i in 0..<count {
            addPublicNode(id: "\(prefix)\(i)")
        }
        for i in 0..<(count - 1) {
            link("\(prefix)\(i)", "\(prefix)\(i + 1)")
        }
        return self
    }

    /// Create a ring topology: A-B-C-D-A
    @discardableResult
    public func addRingTopology(count: Int, prefix: String = "node") -> Self {
        for i in 0..<count {
            addPublicNode(id: "\(prefix)\(i)")
        }
        for i in 0..<count {
            link("\(prefix)\(i)", "\(prefix)((i + 1) % count)")
        }
        return self
    }

    /// Create a star topology: center connected to all others
    @discardableResult
    public func addStarTopology(centerID: String, leafCount: Int, leafPrefix: String = "leaf") -> Self {
        addPublicNode(id: centerID)
        for i in 0..<leafCount {
            addPublicNode(id: "\(leafPrefix)\(i)")
            link(centerID, "\(leafPrefix)\(i)")
        }
        return self
    }

    /// Create a fully connected mesh
    @discardableResult
    public func addFullMesh(nodeIds: [String]) -> Self {
        for id in nodeIds {
            addPublicNode(id: id)
        }
        for i in 0..<nodeIds.count {
            for j in (i + 1)..<nodeIds.count {
                link(nodeIds[i], nodeIds[j])
            }
        }
        return self
    }

    // MARK: - Building

    /// Build the test network
    public func build() async throws -> TestNetwork {
        let virtualNetwork = VirtualNetwork()
        var nodes: [String: TestNode] = [:]
        var nats: [String: SimulatedNAT] = [:]

        // Create nodes
        for config in nodeConfigs {
            let nat: SimulatedNAT?
            if config.natType != .public {
                let simNAT = SimulatedNAT(
                    type: config.natType,
                    publicIP: "10.0.\(nodes.count / 256).\(nodes.count % 256)",
                    portAllocation: config.portAllocation
                )
                nat = simNAT
                nats[config.id] = simNAT
            } else {
                nat = nil
            }

            let node = TestNode(
                id: config.id,
                natType: config.natType,
                nat: nat
            )
            await node.setNetwork(virtualNetwork)
            await virtualNetwork.registerNode(node)
            nodes[config.id] = node
        }

        // Create links
        for linkConfig in linkConfigs {
            await virtualNetwork.setLink(
                from: linkConfig.from,
                to: linkConfig.to,
                config: VirtualNetwork.LinkConfig(
                    latencyMs: linkConfig.latencyMs,
                    packetLossPercent: linkConfig.packetLossPercent,
                    isEnabled: true
                )
            )
        }

        // Start the network
        await virtualNetwork.start()

        return TestNetwork(
            virtualNetwork: virtualNetwork,
            nodes: nodes,
            nats: nats
        )
    }
}

/// A built test network ready for use
public class TestNetwork {
    /// The underlying virtual network
    public let virtualNetwork: VirtualNetwork

    /// All nodes in the network
    private let nodes: [String: TestNode]

    /// All NATs in the network
    private let nats: [String: SimulatedNAT]

    public init(
        virtualNetwork: VirtualNetwork,
        nodes: [String: TestNode],
        nats: [String: SimulatedNAT]
    ) {
        self.virtualNetwork = virtualNetwork
        self.nodes = nodes
        self.nats = nats
    }

    /// Get a node by ID
    public func node(_ id: String) -> TestNode {
        guard let node = nodes[id] else {
            fatalError("Node '\(id)' not found in test network")
        }
        return node
    }

    /// Get a NAT by node ID
    public func nat(for nodeId: String) -> SimulatedNAT? {
        nats[nodeId]
    }

    /// Get all node IDs
    public var nodeIds: [String] {
        Array(nodes.keys)
    }

    /// Get all nodes
    public var allNodes: [TestNode] {
        Array(nodes.values)
    }

    // MARK: - Network Manipulation

    /// Kill a node (remove from network)
    public func killNode(_ id: String) async {
        if let node = nodes[id] {
            await node.stop()
        }
        await virtualNetwork.removeNode(id)
    }

    /// Create a network partition
    public func partition(group1: [String], group2: [String]) async {
        await virtualNetwork.partition(groups: [group1, group2])
    }

    /// Heal all partitions
    public func healPartition() async {
        await virtualNetwork.healPartition()
    }

    /// Add latency to a node
    public func addLatency(to nodeId: String, ms: Int) async {
        for otherId in nodeIds where otherId != nodeId {
            await virtualNetwork.setLatency(from: nodeId, to: otherId, ms: ms)
        }
    }

    /// Remove latency from a node
    public func removeLatency(from nodeId: String) async {
        for otherId in nodeIds where otherId != nodeId {
            await virtualNetwork.setLatency(from: nodeId, to: otherId, ms: 0)
        }
    }

    /// Set packet loss for a node
    public func setPacketLoss(for nodeId: String, percent: Double) async {
        for otherId in nodeIds where otherId != nodeId {
            await virtualNetwork.setPacketLoss(from: nodeId, to: otherId, percent: percent)
        }
    }

    /// Change a node's endpoint (simulates NAT rebinding)
    public func changeEndpoint(for nodeId: String, to newEndpoint: String) async {
        // This would update the node's advertised endpoint
        // For now this is a placeholder - full implementation in later phases
    }

    // MARK: - Lifecycle

    /// Shutdown the entire network
    public func shutdown() async {
        await virtualNetwork.shutdown()
    }
}
