// TunnelSession.swift - Machine-to-machine session over mesh network
//
// A simple bidirectional packet channel between two machines on a specific channel.
// Sessions are identified by (remoteMachineId, channel).

import Foundation
import OmertaMesh
import Logging

/// A session with a remote machine over the mesh network.
/// Provides bidirectional packet communication on a specific channel.
public actor TunnelSession {
    /// Session key (remoteMachineId, channel)
    public let key: TunnelSessionKey

    /// Current state
    public private(set) var state: TunnelState = .connecting

    // Convenience accessors
    public var remoteMachineId: MachineId { key.remoteMachineId }
    public var channel: String { key.channel }

    // Internal components
    private let provider: any ChannelProvider
    private let logger: Logger

    // Receive callback (like ChannelProvider.onChannel pattern)
    private var receiveHandler: (@Sendable (Data) async -> Void)?

    // Wire channel name for mesh transport
    private var wireChannel: String {
        "tunnel-\(channel)"
    }

    /// Session statistics
    public struct Stats: Sendable {
        public var packetsSent: UInt64 = 0
        public var packetsReceived: UInt64 = 0
        public var bytesSent: UInt64 = 0
        public var bytesReceived: UInt64 = 0
        public var lastActivity: Date = Date()

        public init() {}
    }
    public private(set) var stats = Stats()

    /// Initialize a new tunnel session
    /// - Parameters:
    ///   - remoteMachineId: The machine to communicate with
    ///   - channel: The logical channel name for this session
    ///   - provider: The channel provider (mesh network) for transport
    public init(remoteMachineId: MachineId, channel: String, provider: any ChannelProvider) {
        self.key = TunnelSessionKey(remoteMachineId: remoteMachineId, channel: channel)
        self.provider = provider
        self.logger = Logger(label: "io.omerta.tunnel.session")
    }

    // MARK: - Receive Handler

    /// Set handler for incoming packets (like ChannelProvider.onChannel pattern)
    /// - Parameter handler: Callback invoked when packets arrive from the remote machine
    public func onReceive(_ handler: @escaping @Sendable (Data) async -> Void) {
        self.receiveHandler = handler
    }

    // MARK: - Sending

    /// Send a packet to the remote machine
    /// - Parameter data: The packet data to send
    /// - Throws: TunnelError.notConnected if session is not active
    public func send(_ data: Data) async throws {
        guard state == .active else {
            throw TunnelError.notConnected
        }

        try await provider.sendOnChannel(data, toMachine: remoteMachineId, channel: wireChannel)

        stats.packetsSent += 1
        stats.bytesSent += UInt64(data.count)
        stats.lastActivity = Date()

        logger.trace("Sent packet", metadata: [
            "size": "\(data.count)",
            "channel": "\(channel)",
            "to": "\(remoteMachineId.prefix(16))..."
        ])
    }

    // MARK: - Lifecycle

    /// Activate the session (called after handshake)
    func activate() async {
        state = .active
        logger.info("Session activated", metadata: [
            "machine": "\(remoteMachineId.prefix(16))...",
            "channel": "\(channel)"
        ])
    }

    /// Close the session and clean up resources
    public func close() async {
        state = .disconnected
        receiveHandler = nil

        logger.info("Session closed", metadata: [
            "machine": "\(remoteMachineId.prefix(16))...",
            "channel": "\(channel)"
        ])
    }

    // MARK: - Incoming Data

    /// Deliver incoming data to this session (called by TunnelManager dispatch)
    public func deliverIncoming(_ data: Data) async {
        stats.packetsReceived += 1
        stats.bytesReceived += UInt64(data.count)
        stats.lastActivity = Date()
        await receiveHandler?(data)
    }
}
