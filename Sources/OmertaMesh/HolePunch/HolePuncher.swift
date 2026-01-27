// HolePuncher.swift - UDP hole punch execution

import Foundation
import NIOCore
import NIOPosix
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
        }
    }
}

/// Configuration for hole punching
public struct HolePunchConfig: Sendable {
    /// Number of probe packets to send
    public let probeCount: Int

    /// Interval between probes
    public let probeInterval: TimeInterval

    /// Timeout for hole punch attempt
    public let timeout: TimeInterval

    /// Whether to send response probes when receiving
    public let sendResponseProbes: Bool

    /// Number of response probes to send
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

/// UDP hole puncher for establishing direct connections through NAT
public actor HolePuncher {
    private let peerId: String
    private let config: HolePunchConfig
    private let logger: Logger

    /// Active hole punch sessions
    private var activeSessions: [String: HolePunchSession] = [:]

    public init(peerId: String, config: HolePunchConfig = .default) {
        self.peerId = peerId
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.holepunch")
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
            config: config
        )
        activeSessions[sessionId] = session

        defer {
            activeSessions.removeValue(forKey: sessionId)
        }

        // Execute based on strategy
        let result: HolePunchResult
        switch strategy {
        case .simultaneous:
            result = await session.executeSimultaneous(localPort: localPort)

        case .initiatorFirst:
            result = await session.executeInitiatorFirst(localPort: localPort)

        case .responderFirst:
            result = await session.executeResponderFirst(localPort: localPort)

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

    /// Handle incoming probe (called when we receive a probe from another peer)
    public func handleIncomingProbe(
        from endpoint: String,
        probe: ProbePacket,
        respondWith socket: UDPSocket?
    ) async {
        // Find matching session
        let senderId = String(data: probe.senderIdPrefix.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""

        for (_, session) in activeSessions {
            if session.remotePeerId == senderId || session.targetEndpoint == endpoint {
                await session.handleProbe(from: endpoint, probe: probe)

                // Send response probes if configured and this isn't already a response
                if config.sendResponseProbes && !probe.isResponse, let socket = socket {
                    await sendResponseProbes(to: endpoint, socket: socket)
                }
                return
            }
        }

        // No matching session - might be unsolicited probe
        logger.debug("Received probe with no matching session", metadata: [
            "from": "\(endpoint)",
            "sender": "\(senderId)"
        ])
    }

    /// Send response probes to an endpoint
    private func sendResponseProbes(to endpoint: String, socket: UDPSocket) async {
        for i in 0..<config.responseProbeCount {
            let probe = ProbePacket(
                sequence: UInt32(100 + i),
                senderId: peerId,
                isResponse: true
            )
            do {
                try await socket.send(probe.serialize(), to: endpoint)
                if i < config.responseProbeCount - 1 {
                    try await Task.sleep(nanoseconds: 50_000_000)  // 50ms
                }
            } catch {
                logger.debug("Failed to send response probe: \(error)")
            }
        }
    }

    /// Get active session count
    public var activeSessionCount: Int {
        activeSessions.count
    }
}

// MARK: - HolePunchSession

/// A single hole punch attempt session
actor HolePunchSession {
    let sessionId: String
    let localPeerId: String
    let remotePeerId: String
    let targetEndpoint: String
    let strategy: HolePunchStrategy
    let config: HolePunchConfig

    private var receivedProbe: (endpoint: String, probe: ProbePacket)?
    private var probeContinuation: CheckedContinuation<(String, ProbePacket)?, Never>?
    private var isCancelled = false
    private var socket: UDPSocket?
    private let logger: Logger

    init(
        sessionId: String,
        localPeerId: String,
        remotePeerId: String,
        targetEndpoint: String,
        strategy: HolePunchStrategy,
        config: HolePunchConfig
    ) {
        self.sessionId = sessionId
        self.localPeerId = localPeerId
        self.remotePeerId = remotePeerId
        self.targetEndpoint = targetEndpoint
        self.strategy = strategy
        self.config = config
        self.logger = Logger(label: "io.omerta.mesh.holepunch.session.\(sessionId.prefix(8))")
    }

    /// Execute simultaneous hole punch strategy
    func executeSimultaneous(localPort: UInt16) async -> HolePunchResult {
        guard !isCancelled else { return .failed(reason: .cancelled) }

        do {
            let socket = try await createSocket(port: localPort)
            self.socket = socket
            defer { cleanup() }

            let startTime = Date()

            // Send probes
            await sendProbes(to: targetEndpoint, socket: socket)

            // Wait for response
            guard let (endpoint, probe) = await waitForProbe(timeout: config.timeout) else {
                return .failed(reason: .timeout)
            }

            let rtt = Date().timeIntervalSince(startTime)
            return .success(endpoint: endpoint, rtt: rtt)

        } catch let error as HolePunchFailure {
            return .failed(reason: error)
        } catch {
            return .failed(reason: .socketError(error.localizedDescription))
        }
    }

    /// Execute initiator-first strategy (we're symmetric, send first)
    func executeInitiatorFirst(localPort: UInt16) async -> HolePunchResult {
        guard !isCancelled else { return .failed(reason: .cancelled) }

        do {
            let socket = try await createSocket(port: localPort)
            self.socket = socket
            defer { cleanup() }

            let startTime = Date()

            // Send probes first to create NAT mapping
            await sendProbes(to: targetEndpoint, socket: socket)

            // Wait for response with longer timeout
            guard let (endpoint, _) = await waitForProbe(timeout: config.timeout * 1.5) else {
                return .failed(reason: .timeout)
            }

            let rtt = Date().timeIntervalSince(startTime)
            return .success(endpoint: endpoint, rtt: rtt)

        } catch let error as HolePunchFailure {
            return .failed(reason: error)
        } catch {
            return .failed(reason: .socketError(error.localizedDescription))
        }
    }

    /// Execute responder-first strategy (we wait, then respond)
    func executeResponderFirst(localPort: UInt16) async -> HolePunchResult {
        guard !isCancelled else { return .failed(reason: .cancelled) }

        do {
            let socket = try await createSocket(port: localPort)
            self.socket = socket
            defer { cleanup() }

            let startTime = Date()

            // Wait for incoming probe first
            guard let (endpoint, _) = await waitForProbe(timeout: config.timeout) else {
                return .failed(reason: .timeout)
            }

            // Send response probes to complete the hole
            await sendProbes(to: endpoint, socket: socket, isResponse: true)

            let rtt = Date().timeIntervalSince(startTime)
            return .success(endpoint: endpoint, rtt: rtt)

        } catch let error as HolePunchFailure {
            return .failed(reason: error)
        } catch {
            return .failed(reason: .socketError(error.localizedDescription))
        }
    }

    /// Handle an incoming probe
    func handleProbe(from endpoint: String, probe: ProbePacket) {
        receivedProbe = (endpoint, probe)

        if let continuation = probeContinuation {
            probeContinuation = nil
            continuation.resume(returning: (endpoint, probe))
        }
    }

    /// Cancel the session
    func cancel() {
        isCancelled = true
        if let continuation = probeContinuation {
            probeContinuation = nil
            continuation.resume(returning: nil)
        }
        cleanup()
    }

    // MARK: - Private Methods

    private func createSocket(port: UInt16) async throws -> UDPSocket {
        let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let socket = UDPSocket(eventLoopGroup: eventLoopGroup)

        do {
            try await socket.bind(port: Int(port))
        } catch {
            try? await eventLoopGroup.shutdownGracefully()
            throw HolePunchFailure.bindFailed
        }

        // Set up probe handler
        await socket.onReceive { [weak self] data, address in
            guard let self = self else { return }
            if let probe = ProbePacket.parse(data) {
                let endpoint = self.formatEndpoint(address)
                await self.handleProbe(from: endpoint, probe: probe)
            }
        }

        return socket
    }

    private func sendProbes(to endpoint: String, socket: UDPSocket, isResponse: Bool = false) async {
        for i in 0..<config.probeCount {
            guard !isCancelled else { break }

            let probe = ProbePacket(
                sequence: UInt32(i),
                senderId: localPeerId,
                isResponse: isResponse
            )

            do {
                try await socket.send(probe.serialize(), to: endpoint)
                logger.debug("Sent probe \(i) to \(endpoint)")

                if i < config.probeCount - 1 {
                    try await Task.sleep(nanoseconds: UInt64(config.probeInterval * 1_000_000_000))
                }
            } catch {
                logger.debug("Failed to send probe: \(error)")
            }
        }
    }

    private func waitForProbe(timeout: TimeInterval) async -> (String, ProbePacket)? {
        // Check if we already received a probe
        if let received = receivedProbe {
            return received
        }

        return await withCheckedContinuation { continuation in
            probeContinuation = continuation

            // Set up timeout
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                if let cont = self.probeContinuation {
                    self.probeContinuation = nil
                    cont.resume(returning: nil)
                }
            }
        }
    }

    private func cleanup() {
        if let socket = socket {
            Task { await socket.close() }
        }
        socket = nil
    }

    private nonisolated func formatEndpoint(_ address: NIOCore.SocketAddress) -> String {
        guard let port = address.port else {
            return address.description
        }

        switch address {
        case .v4(let addr):
            return "\(addr.host):\(port)"
        case .v6(let addr):
            return "[\(addr.host)]:\(port)"
        default:
            return address.description
        }
    }
}
