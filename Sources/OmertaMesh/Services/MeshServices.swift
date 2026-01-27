// MeshServices.swift - Coordinator for utility services
//
// Provides access to Health, Message, and Cloister services.
// Manages handler lifecycle and provides client factories.

import Foundation
import Logging

/// Coordinator for mesh utility services
public actor MeshServices {
    /// The channel provider for sending/receiving messages
    private let provider: any ChannelProvider

    /// Health service handler
    private var healthHandler: HealthHandler?

    /// Message service handler
    private var messageHandler: MessageHandler?

    /// Cloister service handler
    private var cloisterHandler: CloisterHandler?

    /// Logger for service coordination
    private let logger = Logger(label: "io.omerta.mesh.services")

    /// Whether services have been started
    private var started: Bool = false

    /// Initialize with a channel provider
    /// - Parameter provider: The channel provider to use for messaging
    public init(provider: any ChannelProvider) {
        self.provider = provider
    }

    // MARK: - Lifecycle

    /// Start all service handlers
    /// This registers channel handlers for incoming requests
    public func startAllHandlers() async throws {
        guard !started else {
            throw ServiceError.alreadyRunning
        }

        logger.info("Starting mesh services")

        // Start health handler
        healthHandler = HealthHandler(provider: provider)
        try await healthHandler?.start()

        // Start message handler
        messageHandler = MessageHandler(provider: provider)
        try await messageHandler?.start()

        // Start cloister handler
        cloisterHandler = CloisterHandler(provider: provider)
        try await cloisterHandler?.start()

        started = true
        logger.info("Mesh services started")
    }

    /// Stop all service handlers
    /// This unregisters channel handlers
    public func stopAllHandlers() async {
        logger.info("Stopping mesh services")

        await healthHandler?.stop()
        healthHandler = nil

        await messageHandler?.stop()
        messageHandler = nil

        await cloisterHandler?.stop()
        cloisterHandler = nil

        started = false
        logger.info("Mesh services stopped")
    }

    /// Start the health service handler individually
    public func startHealthHandler() async throws {
        guard healthHandler == nil else {
            throw ServiceError.alreadyRunning
        }
        healthHandler = HealthHandler(provider: provider)
        try await healthHandler?.start()
    }

    /// Start the message service handler individually
    public func startMessageHandler() async throws {
        guard messageHandler == nil else {
            throw ServiceError.alreadyRunning
        }
        messageHandler = MessageHandler(provider: provider)
        try await messageHandler?.start()
    }

    /// Start the cloister service handler individually
    public func startCloisterHandler() async throws {
        guard cloisterHandler == nil else {
            throw ServiceError.alreadyRunning
        }
        cloisterHandler = CloisterHandler(provider: provider)
        try await cloisterHandler?.start()
    }

    // MARK: - Client Factories

    /// Get a health client for checking peer health
    /// - Returns: A configured HealthClient
    public func healthClient() async throws -> HealthClient {
        HealthClient(provider: provider)
    }

    /// Get a message client for peer-to-peer messaging
    /// - Returns: A configured MessageClient
    public func messageClient() async throws -> MessageClient {
        MessageClient(provider: provider)
    }

    /// Get a cloister client for private network negotiation
    /// - Returns: A configured CloisterClient
    public func cloisterClient() async throws -> CloisterClient {
        CloisterClient(provider: provider)
    }

    // MARK: - Handler Configuration

    /// Set a custom health metrics provider
    /// - Parameter metricsProvider: Async closure that returns current health metrics
    public func setHealthMetricsProvider(_ metricsProvider: @escaping @Sendable () async -> HealthMetrics) async {
        await healthHandler?.setMetricsProvider(metricsProvider)
    }

    /// Set a message received handler
    /// - Parameter handler: Async closure called when messages are received
    public func setMessageHandler(_ handler: @escaping @Sendable (PeerId, PeerMessage) async -> Void) async {
        await messageHandler?.setMessageHandler(handler)
    }

    /// Set a cloister negotiation request handler
    /// - Parameter handler: Async closure that decides whether to accept negotiation requests
    ///   Parameters: (fromPeerId, networkName) -> accept?
    public func setCloisterRequestHandler(_ handler: @escaping @Sendable (PeerId, String) async -> Bool) async {
        await cloisterHandler?.setRequestHandler(handler)
    }

    /// Set an invite share handler
    /// - Parameter handler: Async closure that decides whether to accept shared invites
    ///   Parameters: (fromPeerId, networkNameHint) -> accept?
    public func setInviteShareHandler(_ handler: @escaping @Sendable (PeerId, String?) async -> Bool) async {
        await cloisterHandler?.setInviteHandler(handler)
    }

    // MARK: - Status

    /// Check if services are running
    public var isRunning: Bool {
        started
    }

    /// Get the peer ID of this node
    public var peerId: PeerId {
        get async {
            await provider.peerId
        }
    }
}
