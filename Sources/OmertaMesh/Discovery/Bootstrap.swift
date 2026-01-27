// Bootstrap.swift - Network bootstrap implementation

import Foundation
import Logging

/// Configuration for bootstrap process
public struct BootstrapConfig: Sendable {
    /// Hardcoded bootstrap node addresses
    public let bootstrapNodes: [String]

    /// Maximum peers to request from each bootstrap node
    public let maxPeersPerNode: Int

    /// Timeout for bootstrap requests
    public let timeout: TimeInterval

    /// Number of concurrent bootstrap attempts
    public let concurrency: Int

    public init(
        bootstrapNodes: [String] = [],
        maxPeersPerNode: Int = 50,
        timeout: TimeInterval = 10.0,
        concurrency: Int = 3
    ) {
        self.bootstrapNodes = bootstrapNodes
        self.maxPeersPerNode = maxPeersPerNode
        self.timeout = timeout
        self.concurrency = concurrency
    }

    /// Default bootstrap config with public nodes
    public static let `default` = BootstrapConfig(
        bootstrapNodes: [
            // These would be real bootstrap nodes in production
            "bootstrap1.omerta.network:5000",
            "bootstrap2.omerta.network:5000",
            "bootstrap3.omerta.network:5000"
        ]
    )
}

/// Result of bootstrap process
public struct BootstrapResult: Sendable {
    /// Number of peers discovered
    public let peersDiscovered: Int

    /// Number of bootstrap nodes contacted
    public let nodesContacted: Int

    /// Endpoints that failed
    public let failedEndpoints: [String]

    /// Our detected NAT type (if available)
    public let natType: NATType?

    /// Our public endpoint (if available)
    public let publicEndpoint: String?

    /// Whether bootstrap was successful
    public var isSuccessful: Bool {
        peersDiscovered > 0
    }
}

/// Bootstrap process for joining the mesh network
public actor Bootstrap {
    private let node: MeshNode
    private let config: BootstrapConfig
    private let peerCache: PeerCache
    private let logger: Logger

    public init(
        node: MeshNode,
        config: BootstrapConfig = .default,
        peerCache: PeerCache
    ) {
        self.node = node
        self.config = config
        self.peerCache = peerCache
        self.logger = Logger(label: "io.omerta.mesh.bootstrap")
    }

    /// Execute the bootstrap process
    public func bootstrap() async throws -> BootstrapResult {
        logger.info("Starting bootstrap process with \(config.bootstrapNodes.count) nodes")

        var peersDiscovered = 0
        var nodesContacted = 0
        var failedEndpoints: [String] = []

        // Try each bootstrap node
        for endpoint in config.bootstrapNodes {
            do {
                let peers = try await bootstrapFromNode(endpoint)
                nodesContacted += 1
                peersDiscovered += peers.count

                // Add discovered peers to cache
                for peer in peers {
                    await peerCache.insert(peer)
                }

                logger.info("Discovered \(peers.count) peers from \(endpoint)")

                // If we have enough peers, we can stop
                if peersDiscovered >= config.maxPeersPerNode {
                    break
                }
            } catch {
                logger.warning("Failed to bootstrap from \(endpoint): \(error)")
                failedEndpoints.append(endpoint)
            }
        }

        // NAT type is now detected automatically via peer pong responses
        // The NATPredictor in MeshNode will determine the NAT type from observations

        let result = BootstrapResult(
            peersDiscovered: peersDiscovered,
            nodesContacted: nodesContacted,
            failedEndpoints: failedEndpoints,
            natType: nil,
            publicEndpoint: nil
        )

        if result.isSuccessful {
            logger.info("Bootstrap successful: \(peersDiscovered) peers from \(nodesContacted) nodes")
        } else {
            logger.error("Bootstrap failed: no peers discovered")
        }

        return result
    }

    /// Bootstrap from a single node
    private func bootstrapFromNode(_ endpoint: String) async throws -> [PeerAnnouncement] {
        // Send ping to discover the node
        let myNATType = await node.getPredictedNATType().type
        let response = try await node.sendAndReceive(
            .ping(recentPeers: [], myNATType: myNATType),
            to: endpoint,
            timeout: config.timeout
        )

        // Request peer list
        let peerListResponse = try await node.sendAndReceive(
            .peerList([]),  // Empty list means "send me peers"
            to: endpoint,
            timeout: config.timeout
        )

        if case .peerList(let peers) = peerListResponse {
            return peers
        }

        // If we got a pong, at least we know the node is alive
        if case .pong(let recentPeers, _, _) = response {
            logger.debug("Bootstrap node \(endpoint) knows about \(recentPeers.count) peers")
        }

        return []
    }

    /// Try to find a specific peer
    public func findPeer(_ peerId: PeerId) async throws -> PeerAnnouncement? {
        // First check local cache
        if let cached = await peerCache.get(peerId) {
            return cached
        }

        // Ask known peers
        let knownPeers = await peerCache.allAnnouncements

        for peer in knownPeers.prefix(10) {
            guard let endpoint = peer.reachability.first.flatMap({ path -> String? in
                switch path {
                case .direct(let ep): return ep
                case .relay(_, let ep): return ep
                case .holePunch: return nil
                }
            }) else { continue }

            do {
                let response = try await node.sendAndReceive(
                    .findPeer(peerId: peerId),
                    to: endpoint,
                    timeout: 5.0
                )

                if case .peerInfo(let announcement) = response {
                    await peerCache.insert(announcement)
                    return announcement
                }
            } catch {
                logger.debug("Peer lookup failed from \(peer.peerId): \(error)")
            }
        }

        return nil
    }
}

// MARK: - Bootstrap from Peer Store

extension Bootstrap {
    /// Bootstrap using persisted peers from previous session
    public func bootstrapFromPersistedPeers(_ persistedPeers: [PeerAnnouncement]) async throws -> BootstrapResult {
        logger.info("Bootstrapping from \(persistedPeers.count) persisted peers")

        var peersDiscovered = 0
        var nodesContacted = 0
        var failedEndpoints: [String] = []

        for peer in persistedPeers {
            // Skip expired announcements
            if peer.isExpired {
                continue
            }

            // Try to contact the peer
            guard let endpoint = peer.reachability.first.flatMap({ path -> String? in
                switch path {
                case .direct(let ep): return ep
                case .relay(_, let ep): return ep
                case .holePunch: return nil
                }
            }) else { continue }

            do {
                let myNATType = await node.getPredictedNATType().type
                let response = try await node.sendAndReceive(
                    .ping(recentPeers: [], myNATType: myNATType),
                    to: endpoint,
                    timeout: 5.0
                )

                if case .pong(_, _, _) = response {
                    nodesContacted += 1
                    await peerCache.insert(peer)
                    peersDiscovered += 1

                    // Get more peers from this node
                    if let morePeers = try? await bootstrapFromNode(endpoint) {
                        peersDiscovered += morePeers.count
                        for p in morePeers {
                            await peerCache.insert(p)
                        }
                    }
                }
            } catch {
                failedEndpoints.append(endpoint)
            }
        }

        // If persisted peers failed, fall back to hardcoded bootstrap
        if peersDiscovered == 0 && !config.bootstrapNodes.isEmpty {
            logger.info("Persisted peers failed, falling back to bootstrap nodes")
            return try await bootstrap()
        }

        return BootstrapResult(
            peersDiscovered: peersDiscovered,
            nodesContacted: nodesContacted,
            failedEndpoints: failedEndpoints,
            natType: nil,
            publicEndpoint: nil
        )
    }
}
