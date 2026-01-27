// TestNode.swift - Test wrapper for mesh nodes

import Foundation
@testable import OmertaMesh

/// A test node that participates in a virtual network
public actor TestNode {
    /// Unique identifier for this node
    public let id: String

    /// Identity keypair for signing messages
    public let identity: IdentityKeypair

    /// The NAT type this node is behind (nil = public)
    public let natType: NATType

    /// The simulated NAT (if behind NAT)
    public let nat: SimulatedNAT?

    /// Reference to the virtual network
    private weak var network: VirtualNetwork?

    /// Internal endpoint (behind NAT)
    public let internalEndpoint: String

    /// Public endpoint (as seen by others)
    public var publicEndpoint: String {
        get async {
            if let nat = nat {
                return await nat.getExternalEndpoint(for: internalEndpoint) ?? internalEndpoint
            }
            return internalEndpoint
        }
    }

    /// Handler for incoming messages
    private var messageHandler: ((MeshMessage, String) async -> MeshMessage?)?

    /// Handler for raw data
    private var dataHandler: ((Data, String) async -> Void)?

    /// Received messages (for inspection in tests)
    private var receivedMessages: [(message: MeshMessage, from: String)] = []

    /// Sent messages (for inspection in tests)
    private var sentMessages: [(message: MeshMessage, to: String)] = []

    /// Cache of known peers
    public private(set) var peerCache: [PeerId: PeerAnnouncement] = [:]

    /// Recent contacts
    public private(set) var recentContacts: [PeerId: RecentContact] = [:]

    /// Relay connections (for NAT nodes)
    public private(set) var relayConnections: [RelayConnection] = []

    /// Whether the node is running
    private var _isRunning = false

    /// Public getter for running state
    public var isRunning: Bool { _isRunning }

    /// Pending responses for request/response pattern
    private var pendingResponses: [String: CheckedContinuation<MeshMessage, Error>] = [:]

    /// Recent contact info
    public struct RecentContact: Sendable {
        public let peerId: PeerId
        public let lastSeen: Date
        public let reachability: ReachabilityPath

        public var age: TimeInterval {
            Date().timeIntervalSince(lastSeen)
        }
    }

    /// Relay connection info
    public struct RelayConnection: Sendable {
        public let relayPeerId: PeerId
        public let relayEndpoint: String
        public let connectedAt: Date
        public var lastHeartbeat: Date

        public var isHealthy: Bool {
            Date().timeIntervalSince(lastHeartbeat) < 30
        }
    }

    public init(
        id: String,
        natType: NATType = .public,
        nat: SimulatedNAT? = nil,
        internalEndpoint: String? = nil
    ) {
        self.id = id
        self.identity = IdentityKeypair()
        self.natType = natType
        self.nat = nat
        self.internalEndpoint = internalEndpoint ?? "192.168.1.\(id.hashValue % 255):\(5000 + (id.hashValue % 1000))"
    }

    // MARK: - Lifecycle

    /// Set the virtual network this node belongs to
    public func setNetwork(_ network: VirtualNetwork) {
        self.network = network
    }

    /// Start the node
    public func start() async throws {
        _isRunning = true
    }

    /// Stop the node
    public func stop() async {
        _isRunning = false
        // Cancel all pending responses
        for (_, continuation) in pendingResponses {
            continuation.resume(throwing: TestNodeError.stopped)
        }
        pendingResponses.removeAll()
    }

    // MARK: - Message Handling

    /// Register a handler for incoming messages
    public func onMessage(_ handler: @escaping (MeshMessage, String) async -> MeshMessage?) {
        messageHandler = handler
    }

    /// Register a handler for raw data
    public func onData(_ handler: @escaping (Data, String) async -> Void) {
        dataHandler = handler
    }

    /// Receive data from the network
    public func receive(data: Data, from senderId: String) async {
        // Decode the message
        guard let envelope = try? JSONDecoder().decode(MeshEnvelope.self, from: data) else {
            // Raw data handler
            await dataHandler?(data, senderId)
            return
        }

        // Record received message
        receivedMessages.append((envelope.payload, senderId))

        // Update recent contacts
        recentContacts[senderId] = RecentContact(
            peerId: senderId,
            lastSeen: Date(),
            reachability: .direct(endpoint: senderId)
        )

        // Check if this is a response to a pending request
        if case .response(let requestId, _) = envelope.payload {
            if let continuation = pendingResponses.removeValue(forKey: requestId) {
                continuation.resume(returning: envelope.payload)
                return
            }
        }

        // Handle pong as response to ping
        if case .pong = envelope.payload {
            // Check for any pending ping
            for (requestId, continuation) in pendingResponses {
                if requestId.hasPrefix("ping-") {
                    pendingResponses.removeValue(forKey: requestId)
                    continuation.resume(returning: envelope.payload)
                    return
                }
            }
        }

        // Handle through message handler
        if let handler = messageHandler {
            if let response = await handler(envelope.payload, senderId) {
                // Send response back
                await send(response, to: senderId)
            }
        } else {
            // Default handling for basic messages
            await handleDefaultMessage(envelope.payload, from: senderId)
        }
    }

    /// Default message handling
    private func handleDefaultMessage(_ message: MeshMessage, from senderId: String) async {
        switch message {
        case .ping(_, _, _):
            // Respond with pong including recent peers with endpoints
            var peerEndpointInfoList: [PeerEndpointInfo] = []
            for (peerId, contact) in recentContacts {
                if case .direct(let endpoint) = contact.reachability {
                    // Use peerId as machineId placeholder in tests
                    peerEndpointInfoList.append(PeerEndpointInfo(
                        peerId: peerId,
                        machineId: "test-machine-\(peerId.prefix(8))",
                        endpoint: endpoint,
                        natType: .unknown
                    ))
                }
            }
            // Use senderId as yourEndpoint (in real network this would be the observed UDP source)
            await send(.pong(recentPeers: peerEndpointInfoList, yourEndpoint: senderId, myNATType: .unknown), to: senderId)

        case .findPeer(let peerId):
            // Check cache and respond
            if let announcement = peerCache[peerId] {
                await send(.peerInfo(announcement), to: senderId)
            } else {
                await send(.peerNotFound(peerId: peerId), to: senderId)
            }

        case .announce(let announcement):
            // Store in cache
            peerCache[announcement.peerId] = announcement

        default:
            break
        }
    }

    // MARK: - Sending Messages

    /// Send a message to another node
    public func send(_ message: MeshMessage, to targetId: String) async {
        guard let network = network else { return }

        guard let envelope = try? MeshEnvelope.signed(
            from: identity,
            machineId: "test-machine-\(id)",
            to: targetId,
            payload: message
        ) else { return }

        guard let data = try? JSONEncoder().encode(envelope) else { return }

        // Record sent message
        sentMessages.append((message, targetId))

        // Send through virtual network
        await network.send(from: id, to: targetId, data: data)
    }

    /// Send a message and wait for a response
    public func sendAndReceive(
        _ message: MeshMessage,
        to targetId: String,
        timeout: TimeInterval = 5.0
    ) async throws -> MeshMessage {
        let requestId: String
        let messageToSend: MeshMessage

        // For request/response pattern
        if case .request = message {
            messageToSend = message
            if case .request(let rid, _) = message {
                requestId = rid
            } else {
                requestId = UUID().uuidString
            }
        } else if case .ping = message {
            requestId = "ping-\(UUID().uuidString)"
            messageToSend = message
        } else {
            // Wrap in request
            requestId = UUID().uuidString
            if case .data(let payload) = message {
                messageToSend = .request(requestId: requestId, data: payload)
            } else {
                messageToSend = message
                // Use message description as pseudo-request ID for simple cases
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            Task {
                // Store continuation
                self.storeContinuation(requestId: requestId, continuation: continuation)

                // Send the message
                await self.send(messageToSend, to: targetId)

                // Set up timeout
                Task {
                    try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                    self.timeoutRequest(requestId: requestId)
                }
            }
        }
    }

    private func storeContinuation(requestId: String, continuation: CheckedContinuation<MeshMessage, Error>) {
        pendingResponses[requestId] = continuation
    }

    private func timeoutRequest(requestId: String) {
        if let continuation = pendingResponses.removeValue(forKey: requestId) {
            continuation.resume(throwing: TestNodeError.timeout)
        }
    }

    // MARK: - Peer Cache

    /// Add an announcement to the peer cache
    public func addToCache(_ announcement: PeerAnnouncement) {
        peerCache[announcement.peerId] = announcement
    }

    /// Add multiple announcements to the peer cache
    public func addToCache(_ announcements: PeerAnnouncement...) {
        for announcement in announcements {
            peerCache[announcement.peerId] = announcement
        }
    }

    /// Clear the peer cache
    public func clearCache() {
        peerCache.removeAll()
    }

    // MARK: - Relay Connections

    /// Add a relay connection
    public func addRelayConnection(_ relay: RelayConnection) {
        relayConnections.append(relay)
    }

    /// Remove a relay connection
    public func removeRelayConnection(relayPeerId: PeerId) {
        relayConnections.removeAll { $0.relayPeerId == relayPeerId }
    }

    // MARK: - Inspection (for tests)

    /// Get all received messages
    public func getReceivedMessages() -> [(message: MeshMessage, from: String)] {
        receivedMessages
    }

    /// Get all sent messages
    public func getSentMessages() -> [(message: MeshMessage, to: String)] {
        sentMessages
    }

    /// Clear message history
    public func clearMessageHistory() {
        receivedMessages.removeAll()
        sentMessages.removeAll()
    }

    /// Check if a specific message was received
    public func didReceive(_ check: (MeshMessage) -> Bool) -> Bool {
        receivedMessages.contains { check($0.message) }
    }

    /// Count messages of a specific type
    public func countReceived(_ check: (MeshMessage) -> Bool) -> Int {
        receivedMessages.filter { check($0.message) }.count
    }
}

/// Errors that can occur in TestNode
public enum TestNodeError: Error {
    case timeout
    case stopped
    case notConnected
    case encodingError
}
