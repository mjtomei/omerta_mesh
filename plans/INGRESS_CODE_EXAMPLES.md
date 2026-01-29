# Ingress NAT Traversal - Code Examples

This file contains implementation code examples for the ingress NAT traversal feature.
See [INGRESS_NAT_TRAVERSAL.md](./INGRESS_NAT_TRAVERSAL.md) for the design overview.

---

## Part 1: API Types

### 1.1 New Types in MeshNodeServices.swift

```swift
// MARK: - Ingress Endpoint Negotiation

/// Method used to obtain an ingress endpoint
public enum IngressMethod: String, Codable, Sendable {
    case direct         // Same LAN - use local IP directly
    case publicIP       // We have a public IP
    case holePunched    // NAT mapping created via hole punch
    case relayAllocated // Relay allocated a public port for us
}

/// Result of ingress endpoint negotiation
public struct IngressEndpoint: Codable, Sendable, Equatable {
    /// The publicly-reachable endpoint to advertise (host:port)
    public let endpoint: String

    /// How this endpoint was obtained
    public let method: IngressMethod

    /// For relay tunnels: the tunnel ID for forwarding and cleanup
    public let tunnelId: UUID?

    /// The relay peer ID (if using relay)
    public let relayPeerId: PeerId?

    /// TTL in seconds - endpoint should be re-negotiated after this time
    public let ttlSeconds: Int

    /// When this endpoint was negotiated
    public let negotiatedAt: Date

    public init(
        endpoint: String,
        method: IngressMethod,
        tunnelId: UUID? = nil,
        relayPeerId: PeerId? = nil,
        ttlSeconds: Int = 300
    ) {
        self.endpoint = endpoint
        self.method = method
        self.tunnelId = tunnelId
        self.relayPeerId = relayPeerId
        self.ttlSeconds = ttlSeconds
        self.negotiatedAt = Date()
    }

    /// Check if this endpoint has expired
    public var isExpired: Bool {
        Date().timeIntervalSince(negotiatedAt) > TimeInterval(ttlSeconds)
    }
}

/// Delegate for receiving endpoint change notifications
public protocol IngressEndpointDelegate: AnyObject, Sendable {
    /// Called when the ingress endpoint changes (e.g., NAT mapping expired, relay changed)
    func ingressEndpointDidChange(
        tunnelId: UUID,
        oldEndpoint: IngressEndpoint,
        newEndpoint: IngressEndpoint
    ) async

    /// Called when the ingress endpoint becomes unavailable
    func ingressEndpointDidFail(tunnelId: UUID, error: Error) async
}
```

### 1.2 Protocol Extension in MeshNodeServices.swift

```swift
extension MeshNodeServices {
    // MARK: - Ingress Endpoint Negotiation

    /// Negotiate a publicly-reachable inbound endpoint for receiving traffic from a peer.
    /// This answers "how can targetPeer reach ME?"
    ///
    /// Strategy (in order):
    /// 1. Direct - if same LAN, use local IP
    /// 2. Public IP - if we have one, use it
    /// 3. Hole punch - create NAT mapping with target peer
    /// 4. Relay - allocate public port on a relay node
    ///
    /// - Parameters:
    ///   - targetPeer: The peer that needs to send traffic to us
    ///   - localPort: Our local port that should receive the traffic
    ///   - timeout: Max time for negotiation (default 10s)
    /// - Returns: IngressEndpoint with publicly-reachable address
    /// - Throws: MeshError.noIngressAvailable if all methods fail
    func negotiateIngressEndpoint(
        for targetPeer: PeerId,
        localPort: UInt16,
        timeout: TimeInterval
    ) async throws -> IngressEndpoint

    /// Release an ingress endpoint and clean up resources
    /// - Parameter endpoint: The endpoint to release
    func releaseIngressEndpoint(_ endpoint: IngressEndpoint) async

    /// Subscribe to endpoint changes for automatic migration
    /// - Parameters:
    ///   - endpoint: The current endpoint to monitor
    ///   - delegate: Delegate to receive change notifications
    /// - Returns: Subscription ID for later cancellation
    func subscribeToEndpointChanges(
        for endpoint: IngressEndpoint,
        delegate: IngressEndpointDelegate
    ) async -> UUID

    /// Cancel endpoint change subscription
    func cancelEndpointSubscription(_ subscriptionId: UUID) async

    /// Refresh an existing endpoint (e.g., before TTL expires)
    /// May return same endpoint or a new one if conditions changed
    func refreshIngressEndpoint(
        _ endpoint: IngressEndpoint,
        for targetPeer: PeerId,
        localPort: UInt16
    ) async throws -> IngressEndpoint
}
```

### 1.3 New Message Types in MeshMessage.swift

```swift
// MARK: - Ingress Relay Messages

/// Request to allocate an ingress port on a relay
public struct IngressRequest: Codable, Sendable {
    public let tunnelId: UUID
    public let requesterId: PeerId
    public let requesterMachineId: MachineId

    public init(tunnelId: UUID, requesterId: PeerId, requesterMachineId: MachineId) {
        self.tunnelId = tunnelId
        self.requesterId = requesterId
        self.requesterMachineId = requesterMachineId
    }
}

/// Response with allocated ingress port
public struct IngressAllocated: Codable, Sendable {
    public let tunnelId: UUID
    public let publicEndpoint: String  // "relay.ip:54321"
    public let ttlSeconds: Int

    public init(tunnelId: UUID, publicEndpoint: String, ttlSeconds: Int = 600) {
        self.tunnelId = tunnelId
        self.publicEndpoint = publicEndpoint
        self.ttlSeconds = ttlSeconds
    }
}

/// Forwarded data through ingress tunnel
public struct IngressData: Codable, Sendable {
    public let tunnelId: UUID
    public let data: Data
    public let sourceEndpoint: String?  // Original sender (for responses)

    public init(tunnelId: UUID, data: Data, sourceEndpoint: String? = nil) {
        self.tunnelId = tunnelId
        self.data = data
        self.sourceEndpoint = sourceEndpoint
    }
}

/// Release an ingress tunnel
public struct IngressRelease: Codable, Sendable {
    public let tunnelId: UUID

    public init(tunnelId: UUID) {
        self.tunnelId = tunnelId
    }
}

/// Keepalive for ingress tunnel (prevents idle timeout)
public struct IngressKeepalive: Codable, Sendable {
    public let tunnelId: UUID

    public init(tunnelId: UUID) {
        self.tunnelId = tunnelId
    }
}

// Add to MeshMessage enum:
case ingressRequest(IngressRequest)
case ingressAllocated(IngressAllocated)
case ingressData(IngressData)
case ingressRelease(IngressRelease)
case ingressKeepalive(IngressKeepalive)
```

### 1.4 Configuration in MeshConfig.swift

```swift
// MARK: - Ingress Relay Configuration

public extension MeshConfig {
    /// Enable ingress relay capability on this node (requires public IP)
    var canRelayIngress: Bool {
        get { getBool("canRelayIngress") ?? false }
        set { set("canRelayIngress", value: newValue) }
    }

    /// Port range for ingress relay allocation
    var ingressPortRange: ClosedRange<UInt16> {
        get {
            let start = getUInt16("ingressPortRangeStart") ?? 54000
            let end = getUInt16("ingressPortRangeEnd") ?? 54999
            return start...end
        }
        set {
            set("ingressPortRangeStart", value: newValue.lowerBound)
            set("ingressPortRangeEnd", value: newValue.upperBound)
        }
    }

    /// Maximum concurrent ingress tunnels this node will relay
    var maxIngressTunnels: Int {
        get { getInt("maxIngressTunnels") ?? 50 }
        set { set("maxIngressTunnels", value: newValue) }
    }

    /// Idle timeout for ingress tunnels (seconds)
    var ingressIdleTimeout: TimeInterval {
        get { getDouble("ingressIdleTimeout") ?? 300 }
        set { set("ingressIdleTimeout", value: newValue) }
    }

    /// Keepalive interval for ingress tunnels (seconds)
    var ingressKeepaliveInterval: TimeInterval {
        get { getDouble("ingressKeepaliveInterval") ?? 60 }
        set { set("ingressKeepaliveInterval", value: newValue) }
    }
}
```

---

## Part 2: New Files

### 2.1 Sources/OmertaMesh/Relay/IngressRelay.swift

```swift
// IngressRelay.swift - UDP port allocation and forwarding for ingress traffic

import Foundation
import NIOCore
import Logging

/// Manages ingress relay functionality on public nodes
/// Allocates UDP ports and forwards traffic to consumers via mesh
public actor IngressRelay {
    private let node: MeshNode
    private let config: MeshConfig
    private let logger: Logger

    // Active tunnels by ID
    private var tunnels: [UUID: IngressTunnel] = [:]

    // Port to tunnel mapping for incoming UDP
    private var portToTunnel: [UInt16: UUID] = [:]

    // UDP channels for allocated ports
    private var udpChannels: [UInt16: Channel] = [:]

    // Next port to try allocating
    private var nextPort: UInt16

    // Cleanup task
    private var cleanupTask: Task<Void, Never>?

    /// State of an ingress tunnel
    struct IngressTunnel {
        let tunnelId: UUID
        let consumerPeerId: PeerId
        let consumerMachineId: MachineId
        let allocatedPort: UInt16
        let createdAt: Date
        var lastActivity: Date
        var sourceEndpoint: SocketAddress?  // Learned from first incoming packet
        var bytesForwarded: UInt64 = 0
    }

    public init(node: MeshNode, config: MeshConfig, logger: Logger? = nil) {
        self.node = node
        self.config = config
        self.logger = logger ?? Logger(label: "io.omerta.mesh.ingress-relay")
        self.nextPort = config.ingressPortRange.lowerBound
    }

    // MARK: - Lifecycle

    public func start() async {
        // Start cleanup loop
        cleanupTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                await cleanupIdleTunnels()
            }
        }
        logger.info("Ingress relay started", metadata: [
            "portRange": "\(config.ingressPortRange)"
        ])
    }

    public func stop() async {
        cleanupTask?.cancel()

        // Close all UDP channels
        for (port, channel) in udpChannels {
            try? await channel.close()
            logger.debug("Closed UDP channel", metadata: ["port": "\(port)"])
        }
        udpChannels.removeAll()
        tunnels.removeAll()
        portToTunnel.removeAll()

        logger.info("Ingress relay stopped")
    }

    // MARK: - Tunnel Management

    /// Allocate a port for a consumer
    public func allocate(
        tunnelId: UUID,
        for consumerPeerId: PeerId,
        machineId: MachineId
    ) async throws -> (port: UInt16, endpoint: String) {
        // Check capacity
        guard tunnels.count < config.maxIngressTunnels else {
            throw MeshError.relayAtCapacity
        }

        // Find available port
        let port = try await findAvailablePort()

        // Create UDP listener on this port
        try await createUDPListener(port: port)

        // Track tunnel
        let tunnel = IngressTunnel(
            tunnelId: tunnelId,
            consumerPeerId: consumerPeerId,
            consumerMachineId: machineId,
            allocatedPort: port,
            createdAt: Date(),
            lastActivity: Date()
        )
        tunnels[tunnelId] = tunnel
        portToTunnel[port] = tunnelId

        // Get our public endpoint
        let publicIP = await node.getPublicIP() ?? "0.0.0.0"
        let endpoint = "\(publicIP):\(port)"

        logger.info("Allocated ingress port", metadata: [
            "tunnelId": "\(tunnelId)",
            "consumer": "\(consumerPeerId.prefix(8))",
            "port": "\(port)",
            "endpoint": "\(endpoint)"
        ])

        return (port, endpoint)
    }

    /// Release a tunnel
    public func release(_ tunnelId: UUID) async {
        guard let tunnel = tunnels.removeValue(forKey: tunnelId) else {
            return
        }

        portToTunnel.removeValue(forKey: tunnel.allocatedPort)

        // Close UDP channel
        if let channel = udpChannels.removeValue(forKey: tunnel.allocatedPort) {
            try? await channel.close()
        }

        logger.info("Released ingress tunnel", metadata: [
            "tunnelId": "\(tunnelId)",
            "port": "\(tunnel.allocatedPort)",
            "bytesForwarded": "\(tunnel.bytesForwarded)"
        ])
    }

    /// Handle keepalive
    public func handleKeepalive(_ tunnelId: UUID) async {
        if var tunnel = tunnels[tunnelId] {
            tunnel.lastActivity = Date()
            tunnels[tunnelId] = tunnel
        }
    }

    // MARK: - Data Forwarding

    /// Handle incoming UDP from internet (VM's packets)
    public func handleIncomingUDP(_ data: Data, from source: SocketAddress, port: UInt16) async {
        guard let tunnelId = portToTunnel[port],
              var tunnel = tunnels[tunnelId] else {
            logger.debug("Dropping packet for unknown port", metadata: ["port": "\(port)"])
            return
        }

        // Learn source endpoint on first packet
        if tunnel.sourceEndpoint == nil {
            tunnel.sourceEndpoint = source
            tunnels[tunnelId] = tunnel
            logger.debug("Learned source endpoint", metadata: [
                "tunnelId": "\(tunnelId)",
                "source": "\(source)"
            ])
        }

        // Update activity
        tunnel.lastActivity = Date()
        tunnel.bytesForwarded += UInt64(data.count)
        tunnels[tunnelId] = tunnel

        // Forward to consumer via mesh
        let ingressData = IngressData(
            tunnelId: tunnelId,
            data: data,
            sourceEndpoint: source.description
        )

        do {
            try await node.send(
                .ingressData(ingressData),
                to: tunnel.consumerPeerId,
                strategy: .auto
            )
        } catch {
            logger.warning("Failed to forward ingress data", metadata: [
                "tunnelId": "\(tunnelId)",
                "error": "\(error)"
            ])
        }
    }

    /// Handle outgoing data from consumer (responses to VM)
    public func handleMeshData(_ ingressData: IngressData) async {
        guard let tunnel = tunnels[ingressData.tunnelId] else {
            logger.debug("Dropping data for unknown tunnel", metadata: [
                "tunnelId": "\(ingressData.tunnelId)"
            ])
            return
        }

        guard let sourceEndpoint = tunnel.sourceEndpoint else {
            logger.warning("Cannot send response - no source endpoint learned", metadata: [
                "tunnelId": "\(ingressData.tunnelId)"
            ])
            return
        }

        // Update activity
        if var t = tunnels[ingressData.tunnelId] {
            t.lastActivity = Date()
            t.bytesForwarded += UInt64(ingressData.data.count)
            tunnels[ingressData.tunnelId] = t
        }

        // Send via UDP to learned source
        if let channel = udpChannels[tunnel.allocatedPort] {
            let envelope = AddressedEnvelope(
                remoteAddress: sourceEndpoint,
                data: ByteBuffer(data: ingressData.data)
            )
            do {
                try await channel.writeAndFlush(envelope)
            } catch {
                logger.warning("Failed to send UDP response", metadata: [
                    "tunnelId": "\(ingressData.tunnelId)",
                    "error": "\(error)"
                ])
            }
        }
    }

    // MARK: - Helpers

    private func findAvailablePort() async throws -> UInt16 {
        let range = config.ingressPortRange
        var attempts = 0
        let maxAttempts = Int(range.upperBound - range.lowerBound)

        while attempts < maxAttempts {
            let port = nextPort
            nextPort = port >= range.upperBound ? range.lowerBound : port + 1

            if portToTunnel[port] == nil {
                return port
            }
            attempts += 1
        }

        throw MeshError.noPortsAvailable
    }

    private func createUDPListener(port: UInt16) async throws {
        // Create UDP bootstrap and bind to port
        // Implementation depends on NIO setup
        // This creates a DatagramChannel that calls handleIncomingUDP
    }

    private func cleanupIdleTunnels() async {
        let now = Date()
        let timeout = config.ingressIdleTimeout

        var toRemove: [UUID] = []
        for (id, tunnel) in tunnels {
            if now.timeIntervalSince(tunnel.lastActivity) > timeout {
                toRemove.append(id)
            }
        }

        for id in toRemove {
            await release(id)
            logger.info("Cleaned up idle tunnel", metadata: ["tunnelId": "\(id)"])
        }
    }

    // MARK: - Stats

    public var activeTunnelCount: Int {
        tunnels.count
    }

    public var allocatedPorts: [UInt16] {
        Array(portToTunnel.keys)
    }
}
```

### 2.2 Sources/OmertaMesh/Ingress/IngressManager.swift

```swift
// IngressManager.swift - Client-side ingress endpoint management

import Foundation
import Logging

/// Manages ingress endpoints for receiving inbound traffic
/// Handles negotiation, refresh, and automatic migration
public actor IngressManager {
    private let node: MeshNode
    private let logger: Logger

    // Active ingress endpoints
    private var activeEndpoints: [UUID: ManagedIngress] = [:]

    // Subscriptions for endpoint change notifications
    private var subscriptions: [UUID: IngressSubscription] = [:]

    // Refresh task
    private var refreshTask: Task<Void, Never>?

    /// Managed ingress endpoint with metadata
    struct ManagedIngress {
        var endpoint: IngressEndpoint
        let targetPeer: PeerId
        let localPort: UInt16
        var subscriptionIds: Set<UUID>
    }

    /// Subscription for endpoint changes
    struct IngressSubscription {
        let ingressId: UUID
        weak var delegate: IngressEndpointDelegate?
    }

    public init(node: MeshNode, logger: Logger? = nil) {
        self.node = node
        self.logger = logger ?? Logger(label: "io.omerta.mesh.ingress-manager")
    }

    // MARK: - Lifecycle

    public func start() async {
        // Start refresh loop
        refreshTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                await refreshExpiringEndpoints()
            }
        }
        logger.info("Ingress manager started")
    }

    public func stop() async {
        refreshTask?.cancel()

        // Release all endpoints
        for (_, managed) in activeEndpoints {
            await releaseEndpointInternal(managed.endpoint)
        }
        activeEndpoints.removeAll()
        subscriptions.removeAll()

        logger.info("Ingress manager stopped")
    }

    // MARK: - Endpoint Negotiation

    /// Negotiate an ingress endpoint
    public func negotiate(
        for targetPeer: PeerId,
        localPort: UInt16,
        timeout: TimeInterval = 10
    ) async throws -> IngressEndpoint {

        // 1. Check if same LAN
        if let directEndpoint = await tryDirectEndpoint(targetPeer: targetPeer, localPort: localPort) {
            return track(directEndpoint, for: targetPeer, localPort: localPort)
        }

        // 2. Check if we have a public IP
        if let publicEndpoint = await tryPublicIP(localPort: localPort) {
            return track(publicEndpoint, for: targetPeer, localPort: localPort)
        }

        // 3. Try hole punch
        let holePunchTimeout = timeout / 2
        if let punchedEndpoint = await tryHolePunch(
            targetPeer: targetPeer,
            localPort: localPort,
            timeout: holePunchTimeout
        ) {
            return track(punchedEndpoint, for: targetPeer, localPort: localPort)
        }

        // 4. Fall back to relay
        let relayEndpoint = try await allocateRelay(localPort: localPort)
        return track(relayEndpoint, for: targetPeer, localPort: localPort)
    }

    /// Release an endpoint
    public func release(_ endpoint: IngressEndpoint) async {
        await releaseEndpointInternal(endpoint)

        // Remove from tracking
        if let tunnelId = endpoint.tunnelId {
            activeEndpoints.removeValue(forKey: tunnelId)
        }
    }

    /// Refresh an endpoint (before TTL expires)
    public func refresh(
        _ endpoint: IngressEndpoint,
        for targetPeer: PeerId,
        localPort: UInt16
    ) async throws -> IngressEndpoint {

        // For relay endpoints, send keepalive
        if endpoint.method == .relayAllocated, let tunnelId = endpoint.tunnelId {
            if let relayPeer = endpoint.relayPeerId {
                try await node.send(
                    .ingressKeepalive(IngressKeepalive(tunnelId: tunnelId)),
                    to: relayPeer,
                    strategy: .auto
                )
            }

            // Return same endpoint with updated timestamp
            return IngressEndpoint(
                endpoint: endpoint.endpoint,
                method: endpoint.method,
                tunnelId: endpoint.tunnelId,
                relayPeerId: endpoint.relayPeerId,
                ttlSeconds: endpoint.ttlSeconds
            )
        }

        // For hole-punched endpoints, verify still valid
        if endpoint.method == .holePunched {
            // Check if NAT mapping still exists by attempting ping
            let stillValid = await node.sendPing(to: targetPeer)
            if stillValid {
                return endpoint
            }

            // Re-negotiate
            return try await negotiate(for: targetPeer, localPort: localPort)
        }

        // Direct and public IP endpoints don't need refresh
        return endpoint
    }

    // MARK: - Subscriptions

    /// Subscribe to endpoint changes
    public func subscribe(
        to endpoint: IngressEndpoint,
        delegate: IngressEndpointDelegate
    ) -> UUID {
        let subscriptionId = UUID()
        let ingressId = endpoint.tunnelId ?? UUID()

        subscriptions[subscriptionId] = IngressSubscription(
            ingressId: ingressId,
            delegate: delegate
        )

        // Track subscription on the managed endpoint
        if var managed = activeEndpoints[ingressId] {
            managed.subscriptionIds.insert(subscriptionId)
            activeEndpoints[ingressId] = managed
        }

        return subscriptionId
    }

    /// Cancel subscription
    public func cancelSubscription(_ subscriptionId: UUID) {
        if let sub = subscriptions.removeValue(forKey: subscriptionId) {
            if var managed = activeEndpoints[sub.ingressId] {
                managed.subscriptionIds.remove(subscriptionId)
                activeEndpoints[sub.ingressId] = managed
            }
        }
    }

    // MARK: - Incoming Data Handling

    /// Handle incoming ingress data from relay
    public func handleIngressData(_ data: IngressData) async {
        guard let managed = activeEndpoints[data.tunnelId] else {
            logger.debug("Received data for unknown tunnel", metadata: [
                "tunnelId": "\(data.tunnelId)"
            ])
            return
        }

        // Forward to local port
        await forwardToLocalPort(data.data, port: managed.localPort)
    }

    // MARK: - Private Helpers

    private func track(
        _ endpoint: IngressEndpoint,
        for targetPeer: PeerId,
        localPort: UInt16
    ) -> IngressEndpoint {
        let ingressId = endpoint.tunnelId ?? UUID()
        activeEndpoints[ingressId] = ManagedIngress(
            endpoint: endpoint,
            targetPeer: targetPeer,
            localPort: localPort,
            subscriptionIds: []
        )
        return endpoint
    }

    private func tryDirectEndpoint(targetPeer: PeerId, localPort: UInt16) async -> IngressEndpoint? {
        guard let targetEndpoint = await node.endpointManager.getBestEndpoint(
            peerId: targetPeer,
            machineId: await node.machineId
        ) else {
            return nil
        }

        // Check if on same LAN
        guard isOnSameLAN(targetEndpoint) else {
            return nil
        }

        // Get our local IP for this LAN
        guard let localIP = await getLocalIPForLAN(targetEndpoint) else {
            return nil
        }

        logger.debug("Using direct endpoint", metadata: [
            "endpoint": "\(localIP):\(localPort)"
        ])

        return IngressEndpoint(
            endpoint: "\(localIP):\(localPort)",
            method: .direct,
            ttlSeconds: 3600
        )
    }

    private func tryPublicIP(localPort: UInt16) async -> IngressEndpoint? {
        guard let publicIP = await node.detectPublicIP() else {
            return nil
        }

        logger.debug("Using public IP endpoint", metadata: [
            "endpoint": "\(publicIP):\(localPort)"
        ])

        return IngressEndpoint(
            endpoint: "\(publicIP):\(localPort)",
            method: .publicIP,
            ttlSeconds: 3600
        )
    }

    private func tryHolePunch(
        targetPeer: PeerId,
        localPort: UInt16,
        timeout: TimeInterval
    ) async -> IngressEndpoint? {
        // Check NAT compatibility
        let myNAT = await node.currentNATType
        let theirNAT = await node.getNATType(for: targetPeer) ?? .unknown

        let compatibility = HolePunchCompatibility.check(initiator: myNAT, responder: theirNAT)
        guard compatibility.canHolePunch else {
            logger.debug("Hole punch not viable", metadata: [
                "myNAT": "\(myNAT)",
                "theirNAT": "\(theirNAT)"
            ])
            return nil
        }

        // Attempt hole punch
        let result = await node.holePunchManager?.establishDirectConnection(
            to: targetPeer,
            timeout: timeout
        )

        guard case .success(let endpoint, _) = result else {
            logger.debug("Hole punch failed")
            return nil
        }

        // The endpoint is theirs, but hole punch creates bidirectional NAT mapping
        // We need to determine OUR mapped endpoint
        // This comes from the pong response which includes yourEndpoint
        guard let ourMappedEndpoint = await node.getObservedEndpoint(from: targetPeer) else {
            logger.warning("Hole punch succeeded but couldn't determine our mapped endpoint")
            return nil
        }

        logger.debug("Using hole-punched endpoint", metadata: [
            "endpoint": "\(ourMappedEndpoint)"
        ])

        return IngressEndpoint(
            endpoint: ourMappedEndpoint,
            method: .holePunched,
            ttlSeconds: 300  // NAT mappings expire
        )
    }

    private func allocateRelay(localPort: UInt16) async throws -> IngressEndpoint {
        // Select best relay
        guard let relay = await node.relayManager?.selectRelayForIngress() else {
            throw MeshError.noRelayAvailable
        }

        let tunnelId = UUID()

        // Send allocation request
        let request = IngressRequest(
            tunnelId: tunnelId,
            requesterId: await node.peerId,
            requesterMachineId: await node.machineId
        )

        // Send and wait for response
        let response = try await node.sendAndWaitForResponse(
            .ingressRequest(request),
            to: relay.peerId,
            timeout: 5
        )

        guard case .ingressAllocated(let allocated) = response,
              allocated.tunnelId == tunnelId else {
            throw MeshError.relayAllocationFailed
        }

        logger.info("Allocated relay endpoint", metadata: [
            "tunnelId": "\(tunnelId)",
            "endpoint": "\(allocated.publicEndpoint)",
            "relay": "\(relay.peerId.prefix(8))"
        ])

        // Start keepalive task
        startKeepalive(tunnelId: tunnelId, relayPeer: relay.peerId)

        return IngressEndpoint(
            endpoint: allocated.publicEndpoint,
            method: .relayAllocated,
            tunnelId: tunnelId,
            relayPeerId: relay.peerId,
            ttlSeconds: allocated.ttlSeconds
        )
    }

    private func releaseEndpointInternal(_ endpoint: IngressEndpoint) async {
        guard endpoint.method == .relayAllocated,
              let tunnelId = endpoint.tunnelId,
              let relayPeer = endpoint.relayPeerId else {
            return
        }

        // Send release to relay
        try? await node.send(
            .ingressRelease(IngressRelease(tunnelId: tunnelId)),
            to: relayPeer,
            strategy: .auto
        )

        logger.debug("Released relay endpoint", metadata: [
            "tunnelId": "\(tunnelId)"
        ])
    }

    private func refreshExpiringEndpoints() async {
        let now = Date()
        let refreshThreshold: TimeInterval = 60  // Refresh 60s before expiry

        for (ingressId, managed) in activeEndpoints {
            let endpoint = managed.endpoint
            let expiresAt = endpoint.negotiatedAt.addingTimeInterval(TimeInterval(endpoint.ttlSeconds))
            let timeToExpiry = expiresAt.timeIntervalSince(now)

            if timeToExpiry < refreshThreshold {
                do {
                    let newEndpoint = try await refresh(
                        endpoint,
                        for: managed.targetPeer,
                        localPort: managed.localPort
                    )

                    // Notify subscribers if endpoint changed
                    if newEndpoint.endpoint != endpoint.endpoint {
                        await notifyEndpointChange(
                            ingressId: ingressId,
                            oldEndpoint: endpoint,
                            newEndpoint: newEndpoint
                        )
                    }

                    // Update tracked endpoint
                    if var m = activeEndpoints[ingressId] {
                        m.endpoint = newEndpoint
                        activeEndpoints[ingressId] = m
                    }
                } catch {
                    logger.warning("Failed to refresh endpoint", metadata: [
                        "ingressId": "\(ingressId)",
                        "error": "\(error)"
                    ])
                    await notifyEndpointFailed(ingressId: ingressId, error: error)
                }
            }
        }
    }

    private func notifyEndpointChange(
        ingressId: UUID,
        oldEndpoint: IngressEndpoint,
        newEndpoint: IngressEndpoint
    ) async {
        guard let managed = activeEndpoints[ingressId] else { return }

        for subId in managed.subscriptionIds {
            if let sub = subscriptions[subId], let delegate = sub.delegate {
                await delegate.ingressEndpointDidChange(
                    tunnelId: ingressId,
                    oldEndpoint: oldEndpoint,
                    newEndpoint: newEndpoint
                )
            }
        }
    }

    private func notifyEndpointFailed(ingressId: UUID, error: Error) async {
        guard let managed = activeEndpoints[ingressId] else { return }

        for subId in managed.subscriptionIds {
            if let sub = subscriptions[subId], let delegate = sub.delegate {
                await delegate.ingressEndpointDidFail(tunnelId: ingressId, error: error)
            }
        }
    }

    private func startKeepalive(tunnelId: UUID, relayPeer: PeerId) {
        Task {
            while activeEndpoints[tunnelId] != nil {
                try? await Task.sleep(for: .seconds(node.config.ingressKeepaliveInterval))

                guard activeEndpoints[tunnelId] != nil else { break }

                try? await node.send(
                    .ingressKeepalive(IngressKeepalive(tunnelId: tunnelId)),
                    to: relayPeer,
                    strategy: .auto
                )
            }
        }
    }

    private func forwardToLocalPort(_ data: Data, port: UInt16) async {
        // Send data to localhost:port via UDP
        // Implementation depends on NIO setup
    }

    private func isOnSameLAN(_ endpoint: String) -> Bool {
        // Check if endpoint is on same LAN as us
        guard let host = endpoint.split(separator: ":").first else { return false }
        let ip = String(host).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))

        // Check private IP ranges
        return ip.hasPrefix("192.168.") ||
               ip.hasPrefix("10.") ||
               ip.hasPrefix("172.16.") ||
               ip.hasPrefix("172.17.") ||
               ip.hasPrefix("172.18.") ||
               ip.hasPrefix("172.19.") ||
               ip.hasPrefix("172.2") ||
               ip.hasPrefix("172.30.") ||
               ip.hasPrefix("172.31.")
    }

    private func getLocalIPForLAN(_ targetEndpoint: String) async -> String? {
        // Get our local IP that can reach the target endpoint
        // Use routing table or interface enumeration
        return nil  // Implementation needed
    }
}
```

---

## Part 3: File Modifications

### 3.1 MeshNode.swift - Message Handlers

```swift
// MARK: - Ingress Management

/// Ingress manager for inbound endpoint negotiation
public private(set) var ingressManager: IngressManager?

// In init or start:
self.ingressManager = IngressManager(node: self, logger: logger)
await ingressManager?.start()

// In stop:
await ingressManager?.stop()

// Add message handlers in handleMessage:
case .ingressRequest(let request):
    await handleIngressRequest(request, from: senderId)
case .ingressAllocated(let allocated):
    await handleIngressAllocated(allocated)
case .ingressData(let data):
    await handleIngressData(data)
case .ingressRelease(let release):
    await handleIngressRelease(release)
case .ingressKeepalive(let keepalive):
    await handleIngressKeepalive(keepalive)

// Handler implementations:
private func handleIngressRequest(_ request: IngressRequest, from senderId: PeerId) async {
    guard config.canRelayIngress, let relay = ingressRelay else {
        logger.debug("Ignoring ingress request - not a relay")
        return
    }

    do {
        let (port, endpoint) = try await relay.allocate(
            tunnelId: request.tunnelId,
            for: request.requesterId,
            machineId: request.requesterMachineId
        )

        let response = IngressAllocated(
            tunnelId: request.tunnelId,
            publicEndpoint: endpoint,
            ttlSeconds: Int(config.ingressIdleTimeout)
        )

        try await send(.ingressAllocated(response), to: senderId, strategy: .auto)
    } catch {
        logger.warning("Failed to allocate ingress", metadata: ["error": "\(error)"])
    }
}

private func handleIngressData(_ data: IngressData) async {
    // If we're the consumer, forward to local port
    if let manager = ingressManager {
        await manager.handleIngressData(data)
    }

    // If we're the relay, forward to consumer
    if let relay = ingressRelay {
        await relay.handleMeshData(data)
    }
}
```

### 3.2 RelayManager.swift - Ingress Relay Selection

```swift
// MARK: - Ingress Relay Selection

/// Select a relay suitable for ingress (public IP, low latency, available capacity)
public func selectRelayForIngress() async -> RelayCandidate? {
    let candidates = await getRelayCapablePeers()
        .filter { $0.capabilities.contains("ingress-relay") }
        .filter { $0.natType == .public || $0.natType == .fullCone }

    // Score and select best
    var best: (peer: RelayCandidate, score: Double)?
    for candidate in candidates {
        let score = await scoreRelayForIngress(candidate)
        if best == nil || score > best!.score {
            best = (candidate, score)
        }
    }

    return best?.peer
}

private func scoreRelayForIngress(_ candidate: RelayCandidate) async -> Double {
    var score: Double = 100

    // Penalize by RTT
    if let rtt = candidate.rtt {
        score -= rtt * 100  // 100ms = -10 points
    }

    // Reward available capacity
    let capacity = candidate.availableIngressSlots ?? 0
    score += Double(min(capacity, 20))  // Up to +20 for capacity

    // Reward low load
    if let load = candidate.currentLoad {
        score -= load * 50  // High load = penalty
    }

    return score
}
```

### 3.3 EphemeralVPN.swift - Ingress Integration

```swift
// Add property for mesh network reference
private var meshNetwork: MeshNetwork?
private var activeIngressEndpoints: [UUID: IngressEndpoint] = [:]
private var endpointSubscriptions: [UUID: UUID] = [:]  // jobId -> subscriptionId

/// Create VPN for job with automatic endpoint negotiation
public func createVPNForJob(
    _ jobId: UUID,
    providerPeerId: PeerId,
    meshNetwork: MeshNetwork
) async throws -> VPNConfiguration {
    self.meshNetwork = meshNetwork

    // ... existing key generation, port allocation, subnet allocation ...

    // Negotiate inbound endpoint using mesh
    let ingressEndpoint = try await meshNetwork.ingressManager?.negotiate(
        for: providerPeerId,
        localPort: port,
        timeout: 10
    ) ?? throw VPNError.ingressNegotiationFailed

    logger.info("WireGuard endpoint negotiated", metadata: [
        "endpoint": "\(ingressEndpoint.endpoint)",
        "method": "\(ingressEndpoint.method.rawValue)",
        "ttl": "\(ingressEndpoint.ttlSeconds)"
    ])

    // Track for cleanup and migration
    activeIngressEndpoints[jobId] = ingressEndpoint

    // Subscribe to endpoint changes for automatic migration
    if let manager = meshNetwork.ingressManager {
        let subscriptionId = await manager.subscribe(to: ingressEndpoint, delegate: self)
        endpointSubscriptions[jobId] = subscriptionId
    }

    // ... rest of existing VPN setup ...

    return VPNConfiguration(
        consumerPublicKey: serverPublicKey,
        consumerEndpoint: ingressEndpoint.endpoint,
        consumerVPNIP: consumerVPNIP,
        vmVPNIP: vmVPNIP,
        vpnSubnet: vpnSubnet
    )
}

/// Release VPN resources
public func releaseVPN(_ jobId: UUID) async {
    // Cancel endpoint subscription
    if let subId = endpointSubscriptions.removeValue(forKey: jobId) {
        await meshNetwork?.ingressManager?.cancelSubscription(subId)
    }

    // Release ingress endpoint
    if let endpoint = activeIngressEndpoints.removeValue(forKey: jobId) {
        await meshNetwork?.ingressManager?.release(endpoint)
    }

    // ... existing cleanup ...
}
```

### 3.4 EphemeralVPN+IngressEndpointDelegate

```swift
extension EphemeralVPN: IngressEndpointDelegate {
    public func ingressEndpointDidChange(
        tunnelId: UUID,
        oldEndpoint: IngressEndpoint,
        newEndpoint: IngressEndpoint
    ) async {
        logger.info("Ingress endpoint changed, migrating WireGuard", metadata: [
            "old": "\(oldEndpoint.endpoint)",
            "new": "\(newEndpoint.endpoint)"
        ])

        // Find the job using this tunnel
        guard let (jobId, _) = activeIngressEndpoints.first(where: {
            $0.value.tunnelId == tunnelId
        }) else {
            return
        }

        // Update tracked endpoint
        activeIngressEndpoints[jobId] = newEndpoint

        // Notify provider of endpoint change (they need to update VM config)
        await notifyProviderOfEndpointChange(jobId: jobId, newEndpoint: newEndpoint)
    }

    public func ingressEndpointDidFail(tunnelId: UUID, error: Error) async {
        logger.error("Ingress endpoint failed", metadata: [
            "tunnelId": "\(tunnelId)",
            "error": "\(error)"
        ])

        // Attempt re-negotiation
        guard let (jobId, endpoint) = activeIngressEndpoints.first(where: {
            $0.value.tunnelId == tunnelId
        }) else {
            return
        }

        // Try to negotiate a new endpoint
        do {
            // We need the original parameters - would need to track these
            logger.info("Attempting endpoint re-negotiation", metadata: ["jobId": "\(jobId)"])
        } catch {
            logger.error("Re-negotiation failed", metadata: ["error": "\(error)"])
        }
    }

    private func notifyProviderOfEndpointChange(jobId: UUID, newEndpoint: IngressEndpoint) async {
        // Send endpoint update message to provider
        // Provider will update VM's WireGuard config
    }
}
```

### 3.5 VMProtocolMessages.swift - Endpoint Update Messages

```swift
/// Notify provider of consumer endpoint change
public struct EndpointUpdateNotification: Codable, Sendable {
    public let vmId: UUID
    public let newEndpoint: String
    public let reason: String  // "refresh", "migration", "failover"

    public init(vmId: UUID, newEndpoint: String, reason: String) {
        self.vmId = vmId
        self.newEndpoint = newEndpoint
        self.reason = reason
    }
}

/// Provider acknowledgment of endpoint update
public struct EndpointUpdateAck: Codable, Sendable {
    public let vmId: UUID
    public let success: Bool
    public let error: String?

    public init(vmId: UUID, success: Bool, error: String? = nil) {
        self.vmId = vmId
        self.success = success
        self.error = error
    }
}
```

### 3.6 MeshProviderDaemon.swift - Handle Endpoint Updates

```swift
// Handle endpoint update from consumer
private func handleEndpointUpdate(_ update: EndpointUpdateNotification, from consumer: PeerId) async {
    guard let vm = activeVMs[update.vmId] else {
        logger.warning("Endpoint update for unknown VM", metadata: ["vmId": "\(update.vmId)"])
        return
    }

    // Verify this is the actual consumer
    guard vm.consumerPeerId == consumer else {
        logger.warning("Endpoint update from wrong consumer")
        return
    }

    logger.info("Updating VM endpoint", metadata: [
        "vmId": "\(update.vmId)",
        "newEndpoint": "\(update.newEndpoint)",
        "reason": "\(update.reason)"
    ])

    // Update VM's WireGuard peer config
    do {
        try await vmManager.updatePeerEndpoint(
            vmId: update.vmId,
            newEndpoint: update.newEndpoint
        )

        // Send ack
        try await mesh.send(
            .endpointUpdateAck(EndpointUpdateAck(vmId: update.vmId, success: true)),
            to: consumer
        )
    } catch {
        logger.error("Failed to update endpoint", metadata: ["error": "\(error)"])
        try? await mesh.send(
            .endpointUpdateAck(EndpointUpdateAck(vmId: update.vmId, success: false, error: error.localizedDescription)),
            to: consumer
        )
    }
}
```

---

## Part 4: Unit Tests

### 4.1 IngressEndpointTests.swift

```swift
import XCTest
@testable import OmertaMesh

final class IngressEndpointTests: XCTestCase {

    func testIngressEndpointCreation() {
        let endpoint = IngressEndpoint(
            endpoint: "203.0.113.50:54321",
            method: .relayAllocated,
            tunnelId: UUID(),
            relayPeerId: "relay-peer-id",
            ttlSeconds: 300
        )

        XCTAssertEqual(endpoint.endpoint, "203.0.113.50:54321")
        XCTAssertEqual(endpoint.method, .relayAllocated)
        XCTAssertNotNil(endpoint.tunnelId)
        XCTAssertEqual(endpoint.ttlSeconds, 300)
        XCTAssertFalse(endpoint.isExpired)
    }

    func testIngressEndpointExpiry() {
        let endpoint = IngressEndpoint(
            endpoint: "192.0.2.100:51900",
            method: .direct,
            ttlSeconds: 0
        )
        XCTAssertTrue(endpoint.isExpired)
    }

    func testIngressMethodRawValues() {
        XCTAssertEqual(IngressMethod.direct.rawValue, "direct")
        XCTAssertEqual(IngressMethod.publicIP.rawValue, "publicIP")
        XCTAssertEqual(IngressMethod.holePunched.rawValue, "holePunched")
        XCTAssertEqual(IngressMethod.relayAllocated.rawValue, "relayAllocated")
    }

    func testIngressEndpointCodable() throws {
        let original = IngressEndpoint(
            endpoint: "10.0.0.1:9000",
            method: .holePunched,
            tunnelId: UUID(),
            ttlSeconds: 600
        )

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IngressEndpoint.self, from: encoded)

        XCTAssertEqual(decoded.endpoint, original.endpoint)
        XCTAssertEqual(decoded.method, original.method)
        XCTAssertEqual(decoded.tunnelId, original.tunnelId)
        XCTAssertEqual(decoded.ttlSeconds, original.ttlSeconds)
    }
}
```

### 4.2 IngressRelayTests.swift

```swift
import XCTest
@testable import OmertaMesh

final class IngressRelayTests: XCTestCase {
    var mockNode: MockMeshNode!
    var config: MeshConfig!
    var relay: IngressRelay!

    override func setUp() async throws {
        mockNode = MockMeshNode()
        config = MeshConfig()
        config.canRelayIngress = true
        config.ingressPortRange = 54000...54100
        config.maxIngressTunnels = 10
        config.ingressIdleTimeout = 60

        relay = IngressRelay(node: mockNode, config: config)
        await relay.start()
    }

    override func tearDown() async throws {
        await relay.stop()
    }

    func testAllocatePort() async throws {
        let tunnelId = UUID()
        let (port, endpoint) = try await relay.allocate(
            tunnelId: tunnelId,
            for: "consumer-peer-id",
            machineId: "machine-1"
        )

        XCTAssertTrue((54000...54100).contains(port))
        XCTAssertTrue(endpoint.contains(":\(port)"))
        XCTAssertEqual(relay.activeTunnelCount, 1)
    }

    func testAllocateMultiplePorts() async throws {
        var ports: [UInt16] = []

        for i in 0..<5 {
            let tunnelId = UUID()
            let (port, _) = try await relay.allocate(
                tunnelId: tunnelId,
                for: "consumer-\(i)",
                machineId: "machine-\(i)"
            )
            ports.append(port)
        }

        XCTAssertEqual(Set(ports).count, 5)
        XCTAssertEqual(relay.activeTunnelCount, 5)
    }

    func testCapacityLimit() async throws {
        for i in 0..<10 {
            let tunnelId = UUID()
            _ = try await relay.allocate(
                tunnelId: tunnelId,
                for: "consumer-\(i)",
                machineId: "machine-\(i)"
            )
        }

        XCTAssertEqual(relay.activeTunnelCount, 10)

        do {
            _ = try await relay.allocate(
                tunnelId: UUID(),
                for: "overflow-consumer",
                machineId: "machine-x"
            )
            XCTFail("Expected capacity error")
        } catch MeshError.relayAtCapacity {
            // Expected
        }
    }

    func testReleaseTunnel() async throws {
        let tunnelId = UUID()
        _ = try await relay.allocate(
            tunnelId: tunnelId,
            for: "consumer",
            machineId: "machine"
        )

        XCTAssertEqual(relay.activeTunnelCount, 1)
        await relay.release(tunnelId)
        XCTAssertEqual(relay.activeTunnelCount, 0)
    }
}
```

### 4.3 IngressManagerTests.swift

```swift
import XCTest
@testable import OmertaMesh

final class IngressManagerTests: XCTestCase {
    var mockNode: MockMeshNode!
    var manager: IngressManager!

    override func setUp() async throws {
        mockNode = MockMeshNode()
        manager = IngressManager(node: mockNode)
        await manager.start()
    }

    override func tearDown() async throws {
        await manager.stop()
    }

    func testNegotiateSameLAN() async throws {
        mockNode.mockBestEndpoint = "192.0.2.50:8001"
        mockNode.mockLocalIP = "192.0.2.100"

        let endpoint = try await manager.negotiate(
            for: "target-peer",
            localPort: 51900,
            timeout: 5
        )

        XCTAssertEqual(endpoint.method, .direct)
        XCTAssertEqual(endpoint.endpoint, "192.0.2.100:51900")
        XCTAssertNil(endpoint.tunnelId)
    }

    func testNegotiatePublicIP() async throws {
        mockNode.mockBestEndpoint = "203.0.113.50:8001"
        mockNode.mockPublicIP = "198.51.100.10"

        let endpoint = try await manager.negotiate(
            for: "target-peer",
            localPort: 51900,
            timeout: 5
        )

        XCTAssertEqual(endpoint.method, .publicIP)
        XCTAssertEqual(endpoint.endpoint, "198.51.100.10:51900")
    }

    func testNegotiateRelayFallback() async throws {
        mockNode.mockBestEndpoint = "203.0.113.50:8001"
        mockNode.mockPublicIP = nil
        mockNode.mockNATType = .symmetric
        mockNode.mockTargetNATType = .symmetric
        mockNode.mockRelayEndpoint = "relay.example.com:54321"
        mockNode.mockRelayPeerId = "relay-peer"

        let endpoint = try await manager.negotiate(
            for: "target-peer",
            localPort: 51900,
            timeout: 5
        )

        XCTAssertEqual(endpoint.method, .relayAllocated)
        XCTAssertTrue(endpoint.endpoint.contains("54321"))
        XCTAssertNotNil(endpoint.tunnelId)
        XCTAssertEqual(endpoint.relayPeerId, "relay-peer")
    }
}

// MARK: - Mock Types

class MockIngressDelegate: IngressEndpointDelegate {
    var changedEndpoints: [(old: IngressEndpoint, new: IngressEndpoint)] = []
    var failedTunnels: [(id: UUID, error: Error)] = []

    func ingressEndpointDidChange(
        tunnelId: UUID,
        oldEndpoint: IngressEndpoint,
        newEndpoint: IngressEndpoint
    ) async {
        changedEndpoints.append((oldEndpoint, newEndpoint))
    }

    func ingressEndpointDidFail(tunnelId: UUID, error: Error) async {
        failedTunnels.append((tunnelId, error))
    }
}
```

### 4.4 IngressMessageTests.swift

```swift
import XCTest
@testable import OmertaMesh

final class IngressMessageTests: XCTestCase {

    func testIngressRequestCodable() throws {
        let original = IngressRequest(
            tunnelId: UUID(),
            requesterId: "requester-peer-id",
            requesterMachineId: "machine-123"
        )

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IngressRequest.self, from: encoded)

        XCTAssertEqual(decoded.tunnelId, original.tunnelId)
        XCTAssertEqual(decoded.requesterId, original.requesterId)
        XCTAssertEqual(decoded.requesterMachineId, original.requesterMachineId)
    }

    func testIngressAllocatedCodable() throws {
        let original = IngressAllocated(
            tunnelId: UUID(),
            publicEndpoint: "203.0.113.50:54321",
            ttlSeconds: 600
        )

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IngressAllocated.self, from: encoded)

        XCTAssertEqual(decoded.tunnelId, original.tunnelId)
        XCTAssertEqual(decoded.publicEndpoint, original.publicEndpoint)
        XCTAssertEqual(decoded.ttlSeconds, original.ttlSeconds)
    }

    func testIngressDataCodable() throws {
        let original = IngressData(
            tunnelId: UUID(),
            data: Data([0x01, 0x02, 0x03, 0x04]),
            sourceEndpoint: "10.0.0.5:12345"
        )

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IngressData.self, from: encoded)

        XCTAssertEqual(decoded.tunnelId, original.tunnelId)
        XCTAssertEqual(decoded.data, original.data)
        XCTAssertEqual(decoded.sourceEndpoint, original.sourceEndpoint)
    }

    func testIngressReleaseCodable() throws {
        let tunnelId = UUID()
        let original = IngressRelease(tunnelId: tunnelId)

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IngressRelease.self, from: encoded)

        XCTAssertEqual(decoded.tunnelId, tunnelId)
    }

    func testIngressKeepaliveCodable() throws {
        let tunnelId = UUID()
        let original = IngressKeepalive(tunnelId: tunnelId)

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IngressKeepalive.self, from: encoded)

        XCTAssertEqual(decoded.tunnelId, tunnelId)
    }
}
```
