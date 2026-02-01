// ChannelProvider.swift - Standardized interface for channel-based messaging

import Foundation

/// Protocol for types that can send messages on channels.
///
/// ## Choosing the Right Send Method
///
/// Use `sendOnChannel(_:toMachine:channel:)` when:
/// - Responding to a request (use the machineId from your handler)
/// - You have a specific machine you need to reach
/// - You're continuing an existing session
///
/// Use `sendOnChannel(_:to:channel:)` when:
/// - Broadcasting to a peer (any of their machines)
/// - Initiating a new request where you don't know which machine will respond
/// - The peer has multiple machines and you want to reach all of them
///
public protocol ChannelSender: Sendable {
    /// Send data to a peer on a specific channel (broadcast to peer's machines).
    ///
    /// Use this for initiating requests when you don't know/care which machine responds.
    /// When a peer has multiple machines, this sends to all of them.
    ///
    /// - Important: When *responding* to a request, prefer `sendOnChannel(_:toMachine:channel:)`
    ///   using the machineId from your handler. This ensures the response goes to the
    ///   correct machine, especially when a peer has multiple machines.
    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws

    /// Send data to a specific machine on a specific channel (targeted send).
    ///
    /// **Preferred method for responses.** Use this when:
    /// - Responding to a request (use machineId from your handler)
    /// - You need to target a specific machine
    /// - Continuing a session with a known machine
    ///
    /// Example:
    /// ```swift
    /// try await provider.onChannel("my-request") { fromMachineId, data in
    ///     let response = processRequest(data)
    ///     // CORRECT: Respond to the specific machine that sent the request
    ///     try await provider.sendOnChannel(response, toMachine: fromMachineId, channel: "my-response")
    /// }
    /// ```
    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws

    // MARK: - Buffered Send

    /// Buffer data for batched sending on a channel to a peer.
    /// Data is accumulated and sent as a single batch on flush or auto-flush timer.
    func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws

    /// Buffer data for batched sending on a channel to a specific machine.
    func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws

    /// Flush all buffered data for a channel, sending it as a single batch.
    func flushChannel(_ channel: String) async throws

    /// Send data to a specific endpoint address, optionally via an auxiliary port.
    /// Used by multi-endpoint tunnels to target specific remote endpoints.
    /// Default implementation delegates to `sendOnChannel(_:toMachine:channel:)`.
    func sendOnChannel(_ data: Data, toEndpoint endpoint: String, viaPort localPort: UInt16?, toMachine machineId: MachineId, channel: String) async throws
}

/// Protocol for types that provide channel-based messaging.
///
/// This is the standardized interface for registering handlers and sending messages on channels.
/// Both `MeshNetwork` and wrapper types like `MeshProviderDaemon` conform to this protocol.
///
/// ## Handler Pattern
///
/// Handlers receive a `MachineId` (not `PeerId`) because:
/// - You need the machineId to send targeted responses
/// - A peer's identity can be looked up from the registry if needed
/// - This ensures responses go to the correct machine
///
/// ```swift
/// try await provider.onChannel("request") { machineId, data in
///     // machineId identifies the sender's machine - use it for responses
///     let response = handleRequest(data)
///     try await provider.sendOnChannel(response, toMachine: machineId, channel: "response")
///
///     // If you need the peer identity (e.g., for authorization):
///     if let registry = await mesh.machinePeerRegistry {
///         let peerId = await registry.getMostRecentPeer(for: machineId)
///     }
/// }
/// ```
public protocol ChannelProvider: ChannelSender {
    /// The peer ID of this node
    var peerId: PeerId { get async }

    /// Register a handler for messages on a specific channel.
    ///
    /// - Parameters:
    ///   - channel: Channel name (max 64 chars, alphanumeric/-/_ only)
    ///   - handler: Async handler called when messages arrive on this channel.
    ///              Receives `(fromMachineId, data)`. Use `sendOnChannel(_:toMachine:channel:)`
    ///              with the received machineId to send responses.
    /// - Throws: Error if channel name is invalid or registration fails
    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws

    /// Register a handler for messages on a specific channel with a batch config override.
    func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws

    /// Unregister a handler for a channel.
    /// - Parameter channel: Channel name to stop listening on
    func offChannel(_ channel: String) async
}

// MARK: - Default Implementations

public extension ChannelSender {
    /// Default: ignores endpoint/port and falls back to machine-targeted send.
    func sendOnChannel(_ data: Data, toEndpoint endpoint: String, viaPort localPort: UInt16?, toMachine machineId: MachineId, channel: String) async throws {
        try await sendOnChannel(data, toMachine: machineId, channel: channel)
    }
}

// MARK: - Auxiliary Port Provider

/// Protocol for providers that can bind auxiliary UDP ports for multi-endpoint tunnels.
/// Conforming types can create extra sockets on OS-assigned ports and send envelope-wrapped
/// data through them.
public protocol AuxiliaryPortProvider: AnyObject, Sendable {
    /// Bind an auxiliary UDP socket on an OS-assigned port.
    /// Returns the bound port number.
    func bindAuxiliaryPort() async throws -> UInt16

    /// Close and remove an auxiliary socket.
    func unbindAuxiliaryPort(_ port: UInt16) async

    /// Get the local address (host) that a given remote machine can reach us on.
    /// Returns "host:primaryPort" or just "host", depending on implementation.
    func localAddressForMachine(_ machineId: MachineId) async -> String?
}
