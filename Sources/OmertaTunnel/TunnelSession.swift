// TunnelSession.swift - Machine-to-machine session over mesh network
//
// A simple bidirectional packet channel between two machines on a specific channel.
// Sessions are identified by (remoteMachineId, channel).
//
// Supports batched sending: send() buffers, flush() sends batch, sendAndFlush() is immediate.

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

    // MARK: - Batching

    /// Batch configuration for this session
    public var batchConfig: BatchConfig

    /// Update batch configuration
    public func setBatchConfig(_ config: BatchConfig) {
        batchConfig = config
    }

    /// Send buffer for batching
    private var sendBuffer: [Data] = []
    private var sendBufferSize: Int = 0

    /// Auto-flush timer task
    private var autoFlushTask: Task<Void, Never>?

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
    ///   - batchConfig: Batch configuration (defaults to .default)
    public init(remoteMachineId: MachineId, channel: String, provider: any ChannelProvider, batchConfig: BatchConfig = .default) {
        self.key = TunnelSessionKey(remoteMachineId: remoteMachineId, channel: channel)
        self.provider = provider
        self.batchConfig = batchConfig
        self.logger = Logger(label: "io.omerta.tunnel.session")
    }

    // MARK: - Receive Handler

    /// Set handler for incoming packets (like ChannelProvider.onChannel pattern)
    /// - Parameter handler: Callback invoked when packets arrive from the remote machine
    public func onReceive(_ handler: @escaping @Sendable (Data) async -> Void) {
        self.receiveHandler = handler
    }

    // MARK: - Sending

    /// Maximum batch payload size to stay within the 65535-byte UDP datagram limit.
    /// Accounts for v3 envelope overhead and JSON/base64 encoding of MeshMessage.data().
    static let maxDatagramPayload = BinaryEnvelope.maxApplicationDataForUDP

    /// Buffer a packet for batched sending. Starts auto-flush timer if needed.
    /// - Parameter data: The packet data to buffer
    /// - Throws: TunnelError.notConnected if session is not active
    public func send(_ data: Data) async throws {
        guard state == .active else {
            throw TunnelError.notConnected
        }

        sendBuffer.append(data)
        sendBufferSize += data.count

        // Flush if we hit the user-configured threshold or the hard UDP ceiling
        let effectiveLimit = batchConfig.maxBufferSize > 0
            ? min(batchConfig.maxBufferSize, Self.maxDatagramPayload)
            : Self.maxDatagramPayload
        if sendBufferSize >= effectiveLimit {
            try await flush()
            return
        }

        // Start auto-flush timer if not already running
        if autoFlushTask == nil {
            let delay = batchConfig.maxFlushDelay
            autoFlushTask = Task { [weak self] in
                try? await Task.sleep(for: delay)
                guard !Task.isCancelled else { return }
                try? await self?.flush()
            }
        }
    }

    /// Flush all buffered packets, sending them as a single batch.
    /// - Throws: TunnelError.notConnected if session is not active
    public func flush() async throws {
        guard state == .active else {
            throw TunnelError.notConnected
        }

        // Cancel pending auto-flush
        autoFlushTask?.cancel()
        autoFlushTask = nil

        guard !sendBuffer.isEmpty else { return }

        // Take the buffer
        let packets = sendBuffer
        let totalBytes = sendBufferSize
        sendBuffer = []
        sendBufferSize = 0

        // Pack into batch wire format
        let batchData: Data
        if packets.count == 1 {
            batchData = BatchWireFormat.packSingle(packets[0])
        } else {
            batchData = BatchWireFormat.packBatch(packets)
        }

        // Send directly (not buffered) since tunnel already batched
        try await provider.sendOnChannel(batchData, toMachine: remoteMachineId, channel: wireChannel)

        stats.packetsSent += UInt64(packets.count)
        stats.bytesSent += UInt64(totalBytes)
        stats.lastActivity = Date()

        logger.trace("Flushed batch", metadata: [
            "packets": "\(packets.count)",
            "bytes": "\(totalBytes)",
            "channel": "\(channel)",
            "to": "\(remoteMachineId.prefix(16))..."
        ])
    }

    /// Send a single packet immediately without buffering.
    /// This is the old send() behavior — wraps in single-packet wire format and sends.
    /// - Parameter data: The packet data to send
    /// - Throws: TunnelError.notConnected if session is not active
    public func sendAndFlush(_ data: Data) async throws {
        guard state == .active else {
            throw TunnelError.notConnected
        }

        let wireData = BatchWireFormat.packSingle(data)
        try await provider.sendOnChannel(wireData, toMachine: remoteMachineId, channel: wireChannel)

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
        // Flush any remaining buffered data before closing
        if state == .active && !sendBuffer.isEmpty {
            try? await flush()
        }

        autoFlushTask?.cancel()
        autoFlushTask = nil
        state = .disconnected
        receiveHandler = nil
        sendBuffer = []
        sendBufferSize = 0

        logger.info("Session closed", metadata: [
            "machine": "\(remoteMachineId.prefix(16))...",
            "channel": "\(channel)"
        ])
    }

    // MARK: - Incoming Data

    /// Deliver incoming data to this session (called by TunnelManager dispatch).
    /// Automatically unpacks batch wire format.
    public func deliverIncoming(_ data: Data) async {
        let packets = BatchWireFormat.unpack(data)

        for packet in packets {
            stats.packetsReceived += 1
            stats.bytesReceived += UInt64(packet.count)
            stats.lastActivity = Date()
            await receiveHandler?(packet)
        }
    }
}
