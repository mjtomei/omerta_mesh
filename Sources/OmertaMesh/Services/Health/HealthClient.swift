// HealthClient.swift - Client for health check requests
//
// Sends health check requests to local or remote peers and awaits responses.

import Foundation
import Logging

/// Client for performing health checks on peers
public actor HealthClient {
    /// The channel provider for sending requests
    private let provider: any ChannelProvider

    /// Pending requests waiting for responses
    private var pendingRequests: [UUID: CheckedContinuation<HealthResponse, Error>] = [:]

    /// Timeout cleanup tasks
    private var timeoutTasks: [UUID: Task<Void, Never>] = [:]

    /// Logger
    private let logger = Logger(label: "io.omerta.mesh.services.health.client")

    /// Whether the response handler is registered
    private var isRegistered: Bool = false

    /// Initialize with a channel provider
    public init(provider: any ChannelProvider) {
        self.provider = provider
    }

    // MARK: - Public API

    /// Perform a health check on a peer
    /// - Parameters:
    ///   - peerId: The peer to check (or nil for local health)
    ///   - includeMetrics: Whether to include detailed metrics
    ///   - timeout: How long to wait for a response
    /// - Returns: The health response
    public func check(
        peer peerId: PeerId,
        includeMetrics: Bool = true,
        timeout: TimeInterval = 5.0
    ) async throws -> HealthResponse {
        // Ensure response channel is registered
        if !isRegistered {
            try await registerResponseHandler()
        }

        let request = HealthRequest(includeMetrics: includeMetrics)

        // Encode the request
        let requestData: Data
        do {
            requestData = try JSONCoding.encoder.encode(request)
        } catch {
            throw ServiceError.encodingFailed("Failed to encode health request: \(error)")
        }

        // Send request and wait for response
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                // Store continuation
                await self.storeContinuation(request.requestId, continuation)

                // Set up timeout
                await self.setupTimeout(request.requestId, timeout: timeout)

                // Send request
                do {
                    try await self.provider.sendOnChannel(requestData, to: peerId, channel: HealthChannels.request)
                } catch {
                    // Remove continuation and cancel timeout
                    await self.removeContinuation(request.requestId)
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Internal

    private func storeContinuation(_ requestId: UUID, _ continuation: CheckedContinuation<HealthResponse, Error>) {
        pendingRequests[requestId] = continuation
    }

    private func removeContinuation(_ requestId: UUID) {
        pendingRequests.removeValue(forKey: requestId)
        timeoutTasks[requestId]?.cancel()
        timeoutTasks.removeValue(forKey: requestId)
    }

    private func setupTimeout(_ requestId: UUID, timeout: TimeInterval) {
        let task = Task {
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            if let continuation = self.pendingRequests.removeValue(forKey: requestId) {
                continuation.resume(throwing: ServiceError.timeout)
            }
            self.timeoutTasks.removeValue(forKey: requestId)
        }
        timeoutTasks[requestId] = task
    }

    private func registerResponseHandler() async throws {
        let myPeerId = await provider.peerId
        let responseChannel = HealthChannels.response(for: myPeerId)

        do {
            try await provider.onChannel(responseChannel) { [weak self] fromMachineId, data in
                await self?.handleResponse(data, from: fromMachineId)
            }
            isRegistered = true
            logger.debug("Registered health response handler on \(responseChannel)")
        } catch {
            throw ServiceError.channelRegistrationFailed(responseChannel)
        }
    }

    private func handleResponse(_ data: Data, from machineId: MachineId) async {
        guard let response = try? JSONCoding.decoder.decode(HealthResponse.self, from: data) else {
            logger.warning("Failed to decode health response from machine \(machineId.prefix(8))...")
            return
        }

        if let continuation = pendingRequests.removeValue(forKey: response.requestId) {
            timeoutTasks[response.requestId]?.cancel()
            timeoutTasks.removeValue(forKey: response.requestId)
            continuation.resume(returning: response)
        } else {
            logger.debug("Received health response for unknown request: \(response.requestId)")
        }
    }

    /// Unregister the response handler
    public func stop() async {
        let myPeerId = await provider.peerId
        await provider.offChannel(HealthChannels.response(for: myPeerId))
        isRegistered = false

        // Cancel all pending requests
        for (requestId, continuation) in pendingRequests {
            continuation.resume(throwing: ServiceError.notStarted)
            timeoutTasks[requestId]?.cancel()
        }
        pendingRequests.removeAll()
        timeoutTasks.removeAll()
    }
}
