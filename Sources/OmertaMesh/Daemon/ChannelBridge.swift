// ChannelBridge.swift - Bridge between mesh channels and IPC clients
//
// Routes incoming channel messages from the mesh network to registered IPC clients.
// Implements exclusive registration (one client per channel).

import Foundation
import Logging

// MARK: - Channel Bridge

/// Bridges mesh channels to IPC clients with exclusive registration
public actor ChannelBridge {
    /// Handler for incoming channel messages
    public typealias ChannelMessageHandler = @Sendable (String, String, String, Data) async -> Void
    // Parameters: (channel, fromPeerId, fromMachineId, data)

    /// Registered channel
    private struct Registration: Sendable {
        let clientId: String
        let connection: ClientConnection
        let registeredAt: Date
    }

    private let logger: Logger
    private var registrations: [String: Registration] = [:]  // channel -> registration

    /// Reference to the mesh network for registering handlers
    private weak var meshNetwork: MeshNetwork?

    public init(meshNetwork: MeshNetwork? = nil) {
        self.logger = Logger(label: "io.omerta.mesh.channelbridge")
        self.meshNetwork = meshNetwork
    }

    /// Set the mesh network reference
    public func setMeshNetwork(_ network: MeshNetwork) {
        self.meshNetwork = network
    }

    // MARK: - Channel Registration

    /// Register a client for a channel
    /// - Parameters:
    ///   - channel: Channel name
    ///   - clientId: Client identifier
    ///   - connection: Client connection for sending messages
    /// - Throws: ChannelBridgeError if channel is already registered
    public func register(
        channel: String,
        clientId: String,
        connection: ClientConnection
    ) async throws {
        // Check if channel is already registered
        if let existing = registrations[channel] {
            logger.warning("Channel already registered",
                metadata: ["channel": "\(channel)", "existingClient": "\(existing.clientId)"])
            throw ChannelBridgeError.channelAlreadyRegistered(channel)
        }

        // Register the channel
        let registration = Registration(
            clientId: clientId,
            connection: connection,
            registeredAt: Date()
        )
        registrations[channel] = registration

        logger.info("Channel registered",
            metadata: ["channel": "\(channel)", "clientId": "\(clientId)"])

        // Register handler with mesh network
        if let mesh = meshNetwork {
            try await mesh.onChannel(channel) { [weak self] machineId, data in
                await self?.routeIncoming(channel: channel, fromMachineId: machineId, data: data)
            }
        }
    }

    /// Unregister a client from a channel
    /// - Parameters:
    ///   - channel: Channel name
    ///   - clientId: Client identifier (must match registration)
    public func unregister(channel: String, clientId: String) async {
        guard let registration = registrations[channel] else {
            logger.debug("Channel not registered for unregister",
                metadata: ["channel": "\(channel)"])
            return
        }

        // Verify client ID matches
        guard registration.clientId == clientId else {
            logger.warning("Unregister client ID mismatch",
                metadata: ["channel": "\(channel)",
                          "registered": "\(registration.clientId)",
                          "attempted": "\(clientId)"])
            return
        }

        registrations.removeValue(forKey: channel)

        logger.info("Channel unregistered",
            metadata: ["channel": "\(channel)", "clientId": "\(clientId)"])

        // Unregister handler from mesh network
        if let mesh = meshNetwork {
            await mesh.offChannel(channel)
        }
    }

    /// Unregister all channels for a client (e.g., when client disconnects)
    public func unregisterAll(clientId: String) async {
        let channelsToRemove = registrations.filter { $0.value.clientId == clientId }.map { $0.key }

        for channel in channelsToRemove {
            registrations.removeValue(forKey: channel)
            if let mesh = meshNetwork {
                await mesh.offChannel(channel)
            }
        }

        if !channelsToRemove.isEmpty {
            logger.info("Unregistered all channels for client",
                metadata: ["clientId": "\(clientId)", "count": "\(channelsToRemove.count)"])
        }
    }

    // MARK: - Message Routing

    /// Route an incoming message from the mesh to the registered client
    private func routeIncoming(channel: String, fromMachineId: MachineId, data: Data) async {
        guard let registration = registrations[channel] else {
            logger.debug("No client registered for channel, dropping message",
                metadata: ["channel": "\(channel)"])
            return
        }

        // Look up the peerId for this machineId
        var fromPeerId = "unknown"
        if let mesh = meshNetwork,
           let registry = await mesh.machinePeerRegistry {
            if let peerId = await registry.getMostRecentPeer(for: fromMachineId) {
                fromPeerId = peerId
            }
        }

        // Create channel message response and send to client
        let response = ChannelMessageNotification(
            channel: channel,
            fromPeerId: fromPeerId,
            fromMachineId: fromMachineId,
            data: data
        )

        do {
            try await registration.connection.send(response)
            logger.debug("Routed message to client",
                metadata: ["channel": "\(channel)",
                          "from": "\(fromPeerId.prefix(16))",
                          "size": "\(data.count)"])
        } catch {
            logger.error("Failed to route message to client: \(error)",
                metadata: ["channel": "\(channel)", "clientId": "\(registration.clientId)"])
        }
    }

    // MARK: - Outgoing Messages

    /// Send a message on a channel to a peer
    public func sendOnChannel(
        _ data: Data,
        to peerId: PeerId,
        channel: String
    ) async throws {
        guard let mesh = meshNetwork else {
            throw ChannelBridgeError.meshNetworkNotAvailable
        }

        try await mesh.sendOnChannel(data, to: peerId, channel: channel)
    }

    /// Send a message on a channel to a specific machine
    public func sendOnChannelToMachine(
        _ data: Data,
        to machineId: MachineId,
        channel: String
    ) async throws {
        guard let mesh = meshNetwork else {
            throw ChannelBridgeError.meshNetworkNotAvailable
        }

        try await mesh.sendOnChannel(data, toMachine: machineId, channel: channel)
    }

    // MARK: - Status

    /// Check if a channel is registered
    public func isRegistered(channel: String) -> Bool {
        registrations[channel] != nil
    }

    /// Get the client ID registered for a channel
    public func registeredClient(for channel: String) -> String? {
        registrations[channel]?.clientId
    }

    /// Get all registered channels
    public var registeredChannels: [String] {
        Array(registrations.keys)
    }

    /// Number of registered channels
    public var registrationCount: Int {
        registrations.count
    }
}

// MARK: - Channel Message Notification

/// Notification sent to clients when a channel message arrives
public struct ChannelMessageNotification: Codable, Sendable {
    public let type: String = "channelMessage"
    public let channel: String
    public let fromPeerId: String
    public let fromMachineId: String
    public let data: Data

    public init(channel: String, fromPeerId: String, fromMachineId: String, data: Data) {
        self.channel = channel
        self.fromPeerId = fromPeerId
        self.fromMachineId = fromMachineId
        self.data = data
    }
}

// MARK: - Errors

/// Errors from channel bridge operations
public enum ChannelBridgeError: Error, Sendable, CustomStringConvertible {
    case channelAlreadyRegistered(String)
    case channelNotRegistered(String)
    case clientIdMismatch
    case meshNetworkNotAvailable
    case sendFailed(String)

    public var description: String {
        switch self {
        case .channelAlreadyRegistered(let channel):
            return "Channel '\(channel)' is already registered by another client"
        case .channelNotRegistered(let channel):
            return "Channel '\(channel)' is not registered"
        case .clientIdMismatch:
            return "Client ID does not match registration"
        case .meshNetworkNotAvailable:
            return "Mesh network is not available"
        case .sendFailed(let reason):
            return "Failed to send message: \(reason)"
        }
    }
}
