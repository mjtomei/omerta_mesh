// HolePuncher.swift - UDP hole punch execution using encrypted pings

import Foundation
import Logging

/// Result of a hole punch attempt
public enum HolePunchResult: Sendable, Equatable {
    /// Hole punch succeeded
    case success(endpoint: String, rtt: TimeInterval)

    /// Hole punch failed
    case failed(reason: HolePunchFailure)

    public var succeeded: Bool {
        if case .success = self { return true }
        return false
    }

    public var endpoint: String? {
        if case .success(let ep, _) = self { return ep }
        return nil
    }

    public var failureReason: HolePunchFailure? {
        if case .failed(let reason) = self { return reason }
        return nil
    }
}

/// Reasons for hole punch failure
public enum HolePunchFailure: Error, Sendable, Equatable, CustomStringConvertible {
    case timeout
    case bothSymmetric
    case bindFailed
    case invalidEndpoint(String)
    case cancelled
    case socketError(String)
    case noServices

    public var description: String {
        switch self {
        case .timeout:
            return "Hole punch timed out"
        case .bothSymmetric:
            return "Both peers have symmetric NAT - hole punching impossible"
        case .bindFailed:
            return "Failed to bind UDP socket"
        case .invalidEndpoint(let ep):
            return "Invalid endpoint: \(ep)"
        case .cancelled:
            return "Hole punch was cancelled"
        case .socketError(let msg):
            return "Socket error: \(msg)"
        case .noServices:
            return "No mesh services available for sending pings"
        }
    }
}

/// Configuration for hole punching
public struct HolePunchConfig: Sendable {
    /// Number of ping packets to send during hole punch
    public let probeCount: Int

    /// Interval between pings
    public let probeInterval: TimeInterval

    /// Timeout for hole punch attempt
    public let timeout: TimeInterval

    /// Whether to send response pings when receiving
    public let sendResponseProbes: Bool

    /// Number of response pings to send
    public let responseProbeCount: Int

    public init(
        probeCount: Int = 5,
        probeInterval: TimeInterval = 0.2,
        timeout: TimeInterval = 10.0,
        sendResponseProbes: Bool = true,
        responseProbeCount: Int = 3
    ) {
        self.probeCount = probeCount
        self.probeInterval = probeInterval
        self.timeout = timeout
        self.sendResponseProbes = sendResponseProbes
        self.responseProbeCount = responseProbeCount
    }

    public static let `default` = HolePunchConfig()
}

/// UDP hole puncher for establishing direct connections through NAT.
///
/// Uses encrypted mesh pings (via BinaryEnvelopeV2) instead of raw UDP probes.
/// All packets go through the standard encryption layer.
public actor HolePuncher {
    private let peerId: String
    private let config: HolePunchConfig
    private let logger: Logger

    /// Active hole punch sessions
    private var activeSessions: [String: HolePunchSession] = [:]

    /// Mesh services for sending encrypted pings
    private weak var services: (any MeshNodeServices)?

    public init(peerId: String, config: HolePunchConfig = .default) {
        self.peerId = peerId
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.holepunch")
    }

    /// Set mesh services for encrypted communication
    public func setServices(_ services: any MeshNodeServices) {
        self.services = services
    }

    // MARK: - Public API

    /// Execute hole punch based on strategy
    public func execute(
        targetPeerId: String,
        targetEndpoint: String,
        strategy: HolePunchStrategy,
        localPort: UInt16
    ) async -> HolePunchResult {
        // Check for impossible strategy
        if strategy == .impossible {
            return .failed(reason: .bothSymmetric)
        }

        guard let services = services else {
            return .failed(reason: .noServices)
        }

        logger.info("Starting hole punch", metadata: [
            "target": "\(targetPeerId)",
            "endpoint": "\(targetEndpoint)",
            "strategy": "\(strategy.rawValue)"
        ])

        // Create session
        let sessionId = "\(peerId)-\(targetPeerId)-\(UUID().uuidString.prefix(8))"
        let session = HolePunchSession(
            sessionId: sessionId,
            localPeerId: peerId,
            remotePeerId: targetPeerId,
            targetEndpoint: targetEndpoint,
            strategy: strategy,
            config: config,
            services: services
        )
        activeSessions[sessionId] = session

        defer {
            activeSessions.removeValue(forKey: sessionId)
        }

        // Execute based on strategy
        let result: HolePunchResult
        switch strategy {
        case .simultaneous:
            result = await session.executeSimultaneous()

        case .initiatorFirst:
            result = await session.executeInitiatorFirst()

        case .responderFirst:
            result = await session.executeResponderFirst()

        case .impossible:
            result = .failed(reason: .bothSymmetric)
        }

        if result.succeeded {
            logger.info("Hole punch succeeded", metadata: [
                "target": "\(targetPeerId)",
                "endpoint": "\(result.endpoint ?? "unknown")"
            ])
        } else {
            logger.warning("Hole punch failed", metadata: [
                "target": "\(targetPeerId)",
                "reason": "\(result)"
            ])
        }

        return result
    }

    /// Cancel an active hole punch
    public func cancel(targetPeerId: String) {
        for (sessionId, session) in activeSessions {
            if session.remotePeerId == targetPeerId {
                Task { await session.cancel() }
                activeSessions.removeValue(forKey: sessionId)
            }
        }
    }

    /// Notify that a pong was received from an endpoint (called by MeshNode on pong receipt)
    public func handlePongReceived(from endpoint: String, peerId: PeerId) async {
        for (_, session) in activeSessions {
            if session.remotePeerId == peerId || session.targetEndpoint == endpoint {
                await session.handlePongReceived(from: endpoint)
                return
            }
        }
    }

    /// Get active session count
    public var activeSessionCount: Int {
        activeSessions.count
    }
}

// MARK: - HolePunchSession

/// A single hole punch attempt session.
///
/// Instead of creating a raw UDP socket and sending unencrypted probe packets,
/// this sends encrypted pings through the mesh node's standard send path
/// (BinaryEnvelopeV2 with ChaCha20-Poly1305).
actor HolePunchSession {
    let sessionId: String
    let localPeerId: String
    let remotePeerId: String
    let targetEndpoint: String
    let strategy: HolePunchStrategy
    let config: HolePunchConfig

    private var receivedPong: String?  // endpoint from which pong was received
    private var pongContinuation: CheckedContinuation<String?, Never>?
    private var isCancelled = false
    private let services: any MeshNodeServices
    private let logger: Logger

    init(
        sessionId: String,
        localPeerId: String,
        remotePeerId: String,
        targetEndpoint: String,
        strategy: HolePunchStrategy,
        config: HolePunchConfig,
        services: any MeshNodeServices
    ) {
        self.sessionId = sessionId
        self.localPeerId = localPeerId
        self.remotePeerId = remotePeerId
        self.targetEndpoint = targetEndpoint
        self.strategy = strategy
        self.config = config
        self.services = services
        self.logger = Logger(label: "io.omerta.mesh.holepunch.session.\(sessionId.prefix(8))")
    }

    /// Execute simultaneous hole punch strategy
    func executeSimultaneous() async -> HolePunchResult {
        guard !isCancelled else { return .failed(reason: .cancelled) }

        let startTime = Date()

        // Send pings to target endpoint
        await sendPings(to: targetEndpoint)

        // Wait for pong response
        guard let endpoint = await waitForPong(timeout: config.timeout) else {
            return .failed(reason: .timeout)
        }

        let rtt = Date().timeIntervalSince(startTime)
        return .success(endpoint: endpoint, rtt: rtt)
    }

    /// Execute initiator-first strategy (we send first to create NAT mapping)
    func executeInitiatorFirst() async -> HolePunchResult {
        guard !isCancelled else { return .failed(reason: .cancelled) }

        let startTime = Date()

        // Send pings first to create NAT mapping
        await sendPings(to: targetEndpoint)

        // Wait for pong with longer timeout
        guard let endpoint = await waitForPong(timeout: config.timeout * 1.5) else {
            return .failed(reason: .timeout)
        }

        let rtt = Date().timeIntervalSince(startTime)
        return .success(endpoint: endpoint, rtt: rtt)
    }

    /// Execute responder-first strategy (we wait, then respond)
    func executeResponderFirst() async -> HolePunchResult {
        guard !isCancelled else { return .failed(reason: .cancelled) }

        let startTime = Date()

        // Wait for incoming pong first (the other side is sending pings)
        guard let endpoint = await waitForPong(timeout: config.timeout) else {
            return .failed(reason: .timeout)
        }

        // Send response pings to complete the hole
        await sendPings(to: endpoint)

        let rtt = Date().timeIntervalSince(startTime)
        return .success(endpoint: endpoint, rtt: rtt)
    }

    /// Handle a pong received from the target
    func handlePongReceived(from endpoint: String) {
        receivedPong = endpoint

        if let continuation = pongContinuation {
            pongContinuation = nil
            continuation.resume(returning: endpoint)
        }
    }

    /// Cancel the session
    func cancel() {
        isCancelled = true
        if let continuation = pongContinuation {
            pongContinuation = nil
            continuation.resume(returning: nil)
        }
    }

    // MARK: - Private Methods

    /// Send encrypted pings to the target endpoint to punch through NAT.
    /// Uses the standard mesh send path (BinaryEnvelopeV2 encryption).
    private func sendPings(to endpoint: String) async {
        let natType = await services.getNATType(for: localPeerId) ?? .unknown

        for i in 0..<config.probeCount {
            guard !isCancelled else { break }

            do {
                let ping = MeshMessage.ping(recentPeers: [], myNATType: natType, requestFullList: false)
                try await services.send(ping, to: remotePeerId, strategy: .direct(endpoint: endpoint))
                logger.debug("Sent hole punch ping \(i) to \(endpoint)")

                if i < config.probeCount - 1 {
                    try await Task.sleep(nanoseconds: UInt64(config.probeInterval * 1_000_000_000))
                }
            } catch {
                logger.debug("Failed to send hole punch ping: \(error)")
            }
        }
    }

    private func waitForPong(timeout: TimeInterval) async -> String? {
        // Check if we already received a pong
        if let received = receivedPong {
            return received
        }

        return await withCheckedContinuation { continuation in
            pongContinuation = continuation

            // Set up timeout
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                if let cont = self.pongContinuation {
                    self.pongContinuation = nil
                    cont.resume(returning: nil)
                }
            }
        }
    }
}
