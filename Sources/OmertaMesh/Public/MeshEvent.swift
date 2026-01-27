// MeshEvent.swift - Events emitted by the mesh network

import Foundation

/// Events emitted by the mesh network
public enum MeshEvent: Sendable {
    // MARK: - Lifecycle Events

    /// The mesh network has started
    case started(localPeerId: PeerId)

    /// The mesh network has stopped
    case stopped

    // MARK: - NAT Events

    /// NAT detection completed
    case natDetected(type: NATType, publicEndpoint: Endpoint?)

    /// NAT type changed (e.g., from unknown to detected)
    case natTypeChanged(from: NATType, to: NATType)

    // MARK: - Peer Events

    /// A new peer was discovered
    case peerDiscovered(peerId: PeerId, endpoint: Endpoint, viaBootstrap: Bool)

    /// A peer connected to us
    case peerConnected(peerId: PeerId, endpoint: Endpoint, isDirect: Bool)

    /// A peer disconnected
    case peerDisconnected(peerId: PeerId, reason: DisconnectReason)

    /// A peer became unreachable (all paths failed)
    case peerUnreachable(peerId: PeerId)

    /// Fresh info received for a peer we were looking for
    case peerInfoRefreshed(peerId: PeerId, newEndpoint: Endpoint)

    // MARK: - Relay Events

    /// Connected to a relay
    case relayConnected(peerId: PeerId, endpoint: Endpoint)

    /// Disconnected from a relay
    case relayDisconnected(peerId: PeerId)

    /// Started relaying for another peer
    case relayingStarted(forPeerId: PeerId)

    /// Stopped relaying for another peer
    case relayingStopped(forPeerId: PeerId)

    // MARK: - Hole Punch Events

    /// Hole punch attempt started
    case holePunchStarted(peerId: PeerId)

    /// Hole punch succeeded - direct connection established
    case holePunchSucceeded(peerId: PeerId, endpoint: Endpoint, rttMs: Double)

    /// Hole punch failed
    case holePunchFailed(peerId: PeerId, reason: HolePunchFailure)

    // MARK: - Message Events

    /// Received an application message from a peer
    case messageReceived(from: PeerId, data: Data, isDirect: Bool)

    /// Message send failed
    case messageSendFailed(to: PeerId, reason: String)

    // MARK: - Connection Events

    /// Direct connection established (may be via hole punch)
    case directConnectionEstablished(peerId: PeerId, endpoint: Endpoint)

    /// Direct connection lost, falling back to relay
    case directConnectionLost(peerId: PeerId, fallbackRelay: PeerId?)

    // MARK: - Network Membership Events

    /// Joined a network
    case networkJoined(network: Network)

    /// Left a network
    case networkLeft(networkId: String)

    // MARK: - Error Events

    /// A recoverable error occurred
    case error(MeshError)

    /// A warning (non-fatal issue)
    case warning(message: String)
}

/// Reason for peer disconnection
public enum DisconnectReason: Sendable, Equatable, CustomStringConvertible {
    /// Peer explicitly disconnected
    case peerClosed

    /// Connection timed out (no keepalive)
    case timeout

    /// Network error
    case networkError(String)

    /// Local node is stopping
    case localShutdown

    /// Peer was evicted from cache
    case evicted

    public var description: String {
        switch self {
        case .peerClosed:
            return "Peer closed connection"
        case .timeout:
            return "Connection timed out"
        case .networkError(let msg):
            return "Network error: \(msg)"
        case .localShutdown:
            return "Local shutdown"
        case .evicted:
            return "Evicted from cache"
        }
    }
}

// MARK: - Event Stream

/// An async stream of mesh events
public typealias MeshEventStream = AsyncStream<MeshEvent>

/// A continuation for sending mesh events
public typealias MeshEventContinuation = AsyncStream<MeshEvent>.Continuation

// MARK: - Event Publisher

/// Publishes events to multiple subscribers
public actor MeshEventPublisher {
    private var continuations: [UUID: MeshEventContinuation] = [:]

    public init() {}

    /// Subscribe to events
    public func subscribe() -> MeshEventStream {
        let id = UUID()
        let (stream, continuation) = AsyncStream<MeshEvent>.makeStream()

        continuation.onTermination = { [weak self] _ in
            Task { [weak self] in
                await self?.unsubscribe(id: id)
            }
        }

        continuations[id] = continuation
        return stream
    }

    /// Unsubscribe from events
    private func unsubscribe(id: UUID) {
        continuations.removeValue(forKey: id)
    }

    /// Publish an event to all subscribers
    public func publish(_ event: MeshEvent) {
        for continuation in continuations.values {
            continuation.yield(event)
        }
    }

    /// Finish all streams (call when shutting down)
    public func finish() {
        for continuation in continuations.values {
            continuation.finish()
        }
        continuations.removeAll()
    }

    /// Number of active subscribers
    public var subscriberCount: Int {
        continuations.count
    }
}

// MARK: - Event Filtering

extension MeshEventStream {
    /// Filter to only lifecycle events
    public func lifecycleEvents() -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .started, .stopped:
                return true
            default:
                return false
            }
        }
    }

    /// Filter to only peer events
    public func peerEvents() -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .peerDiscovered, .peerConnected, .peerDisconnected,
                 .peerUnreachable, .peerInfoRefreshed:
                return true
            default:
                return false
            }
        }
    }

    /// Filter to only connection events
    public func connectionEvents() -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .peerConnected, .peerDisconnected, .relayConnected,
                 .relayDisconnected, .directConnectionEstablished,
                 .directConnectionLost, .holePunchSucceeded:
                return true
            default:
                return false
            }
        }
    }

    /// Filter to only hole punch events
    public func holePunchEvents() -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .holePunchStarted, .holePunchSucceeded, .holePunchFailed:
                return true
            default:
                return false
            }
        }
    }

    /// Filter to only message events
    public func messageEvents() -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .messageReceived, .messageSendFailed:
                return true
            default:
                return false
            }
        }
    }

    /// Filter to only error/warning events
    public func errorEvents() -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .error, .warning:
                return true
            default:
                return false
            }
        }
    }

    /// Filter to only network membership events
    public func networkEvents() -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .networkJoined, .networkLeft:
                return true
            default:
                return false
            }
        }
    }

    /// Filter events for a specific peer
    public func events(forPeer peerId: PeerId) -> AsyncFilterSequence<MeshEventStream> {
        filter { event in
            switch event {
            case .peerDiscovered(let id, _, _),
                 .peerConnected(let id, _, _),
                 .peerDisconnected(let id, _),
                 .peerUnreachable(let id),
                 .peerInfoRefreshed(let id, _),
                 .relayConnected(let id, _),
                 .relayDisconnected(let id),
                 .relayingStarted(let id),
                 .relayingStopped(let id),
                 .holePunchStarted(let id),
                 .holePunchSucceeded(let id, _, _),
                 .holePunchFailed(let id, _),
                 .messageReceived(let id, _, _),
                 .messageSendFailed(let id, _),
                 .directConnectionEstablished(let id, _),
                 .directConnectionLost(let id, _):
                return id == peerId
            default:
                return false
            }
        }
    }
}

// MARK: - Event Description

extension MeshEvent: CustomStringConvertible {
    public var description: String {
        switch self {
        case .started(let peerId):
            return "Mesh started with peer ID: \(peerId)"
        case .stopped:
            return "Mesh stopped"
        case .natDetected(let type, let endpoint):
            return "NAT detected: \(type.rawValue), public endpoint: \(endpoint ?? "none")"
        case .natTypeChanged(let from, let to):
            return "NAT type changed: \(from.rawValue) -> \(to.rawValue)"
        case .peerDiscovered(let peerId, let endpoint, let viaBootstrap):
            return "Peer discovered: \(peerId) at \(endpoint) (bootstrap: \(viaBootstrap))"
        case .peerConnected(let peerId, let endpoint, let isDirect):
            return "Peer connected: \(peerId) at \(endpoint) (direct: \(isDirect))"
        case .peerDisconnected(let peerId, let reason):
            return "Peer disconnected: \(peerId) - \(reason)"
        case .peerUnreachable(let peerId):
            return "Peer unreachable: \(peerId)"
        case .peerInfoRefreshed(let peerId, let endpoint):
            return "Peer info refreshed: \(peerId) at \(endpoint)"
        case .relayConnected(let peerId, let endpoint):
            return "Relay connected: \(peerId) at \(endpoint)"
        case .relayDisconnected(let peerId):
            return "Relay disconnected: \(peerId)"
        case .relayingStarted(let peerId):
            return "Started relaying for: \(peerId)"
        case .relayingStopped(let peerId):
            return "Stopped relaying for: \(peerId)"
        case .holePunchStarted(let peerId):
            return "Hole punch started to: \(peerId)"
        case .holePunchSucceeded(let peerId, let endpoint, let rtt):
            return "Hole punch succeeded to \(peerId) at \(endpoint) (RTT: \(rtt)ms)"
        case .holePunchFailed(let peerId, let reason):
            return "Hole punch failed to \(peerId): \(reason)"
        case .messageReceived(let from, let data, let isDirect):
            return "Message received from \(from): \(data.count) bytes (direct: \(isDirect))"
        case .messageSendFailed(let to, let reason):
            return "Message send failed to \(to): \(reason)"
        case .directConnectionEstablished(let peerId, let endpoint):
            return "Direct connection established to \(peerId) at \(endpoint)"
        case .directConnectionLost(let peerId, let fallback):
            return "Direct connection lost to \(peerId), fallback: \(fallback ?? "none")"
        case .networkJoined(let network):
            return "Joined network: \(network.name) (\(network.id))"
        case .networkLeft(let networkId):
            return "Left network: \(networkId)"
        case .error(let error):
            return "Error: \(error)"
        case .warning(let message):
            return "Warning: \(message)"
        }
    }
}
