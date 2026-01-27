// HealthHandler.swift - Handler for incoming health check requests
//
// Listens for health check requests and responds with local health status.

import Foundation
import Logging

/// Handler for incoming health check requests
public actor HealthHandler {
    /// The channel provider for receiving requests and sending responses
    private let provider: any ChannelProvider

    /// Custom metrics provider (optional)
    private var metricsProvider: (@Sendable () async -> HealthMetrics)?

    /// Logger
    private let logger = Logger(label: "io.omerta.mesh.services.health.handler")

    /// Whether the handler is running
    private var isRunning: Bool = false

    /// Start time for uptime calculation
    private var startTime: Date = Date()

    /// Initialize with a channel provider
    public init(provider: any ChannelProvider) {
        self.provider = provider
    }

    // MARK: - Lifecycle

    /// Start listening for health check requests
    public func start() async throws {
        guard !isRunning else {
            throw ServiceError.alreadyRunning
        }

        startTime = Date()

        do {
            try await provider.onChannel(HealthChannels.request) { [weak self] fromMachineId, data in
                await self?.handleRequest(data, from: fromMachineId)
            }
            isRunning = true
            logger.info("Health handler started")
        } catch {
            throw ServiceError.channelRegistrationFailed(HealthChannels.request)
        }
    }

    /// Stop listening for health check requests
    public func stop() async {
        await provider.offChannel(HealthChannels.request)
        isRunning = false
        logger.info("Health handler stopped")
    }

    // MARK: - Configuration

    /// Set a custom metrics provider
    /// - Parameter provider: Async closure that returns current health metrics
    public func setMetricsProvider(_ provider: @escaping @Sendable () async -> HealthMetrics) {
        metricsProvider = provider
    }

    // MARK: - Internal

    private func handleRequest(_ data: Data, from machineId: MachineId) async {
        guard let request = try? JSONCoding.decoder.decode(HealthRequest.self, from: data) else {
            logger.warning("Failed to decode health request from machine \(machineId.prefix(8))...")
            return
        }

        logger.debug("Received health request from machine \(machineId.prefix(8))..., includeMetrics: \(request.includeMetrics)")

        // Build response
        let response: HealthResponse
        if request.includeMetrics, let provider = metricsProvider {
            let metrics = await provider()
            response = HealthResponse(
                requestId: request.requestId,
                status: determineStatus(from: metrics),
                metrics: metrics
            )
        } else {
            // Default metrics if no provider set
            response = HealthResponse(
                requestId: request.requestId,
                status: .healthy,
                metrics: request.includeMetrics ? defaultMetrics() : nil
            )
        }

        // Send response directly to the requesting machine
        do {
            let responseData = try JSONCoding.encoder.encode(response)
            let myPeerId = await provider.peerId
            let responseChannel = HealthChannels.response(for: myPeerId)
            try await provider.sendOnChannel(responseData, toMachine: machineId, channel: responseChannel)
            logger.debug("Sent health response to machine \(machineId.prefix(8))... on \(responseChannel)")
        } catch {
            logger.error("Failed to send health response to machine \(machineId.prefix(8))...: \(error)")
        }
    }

    private func determineStatus(from metrics: HealthMetrics) -> HealthStatus {
        // Simple status determination based on metrics
        if metrics.peerCount == 0 && metrics.directConnectionCount == 0 {
            return .unhealthy
        } else if metrics.directConnectionCount == 0 && metrics.relayCount > 0 {
            return .degraded
        } else if metrics.natType == .symmetric && metrics.relayCount == 0 {
            return .degraded
        }
        return .healthy
    }

    private func defaultMetrics() -> HealthMetrics {
        HealthMetrics(
            peerCount: 0,
            directConnectionCount: 0,
            relayCount: 0,
            natType: .unknown,
            publicEndpoint: nil,
            uptimeSeconds: Date().timeIntervalSince(startTime),
            averageLatencyMs: nil
        )
    }
}
