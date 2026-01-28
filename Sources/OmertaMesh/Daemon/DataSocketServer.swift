// DataSocketServer.swift - High-performance binary socket for tunnel packets
//
// Uses minimal framing for low-latency packet forwarding:
// Frame: [tunnelId (16 bytes UUID)] [length (2 bytes BE)] [packet data]

import Foundation
import NIOCore
import NIOPosix
import Logging

// MARK: - Data Socket Server

/// Unix domain socket server for high-performance tunnel packet forwarding
public actor DataSocketServer {
    /// Server state
    public enum State: Sendable {
        case stopped
        case starting
        case running
        case stopping
    }

    /// Handler for incoming tunnel packets
    public typealias PacketHandler = @Sendable (UUID, Data) async -> Void

    private let socketPath: String
    private let logger: Logger
    private var state: State = .stopped
    private var eventLoopGroup: EventLoopGroup?
    private var serverChannel: Channel?
    private var tunnelHandlers: [UUID: PacketHandler] = [:]
    private var connections: [ObjectIdentifier: DataConnection] = [:]
    private var ownsEventLoopGroup: Bool = false

    /// Maximum packet size (65535 bytes, max for 2-byte length field)
    public static let maxPacketSize: Int = 65535

    /// Create a new data socket server
    /// - Parameters:
    ///   - socketPath: Path to the Unix domain socket
    ///   - eventLoopGroup: Optional event loop group (creates own if nil)
    public init(socketPath: String, eventLoopGroup: EventLoopGroup? = nil) {
        self.socketPath = socketPath
        self.logger = Logger(label: "io.omerta.mesh.datasocket.server")
        self.eventLoopGroup = eventLoopGroup
    }

    /// Start the server
    public func start() async throws {
        guard state == .stopped else {
            throw IPCError.socketError("Server already running")
        }

        state = .starting

        // Clean up existing socket file
        try? DaemonSocketPaths.removeSocket(socketPath)

        // Create event loop group if needed
        if eventLoopGroup == nil {
            eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            ownsEventLoopGroup = true
        }

        guard let elg = eventLoopGroup else {
            state = .stopped
            throw IPCError.socketError("No event loop group available")
        }

        do {
            let server = self
            let bootstrap = ServerBootstrap(group: elg)
                .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { channel in
                    channel.pipeline.addHandlers([
                        ByteToMessageHandler(TunnelPacketDecoder()),
                        MessageToByteHandler(TunnelPacketEncoder()),
                        DataSocketHandler(server: server)
                    ])
                }
                .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
                .childChannelOption(.socketOption(.so_keepalive), value: 1)

            let channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()

            serverChannel = channel
            state = .running

            // Set socket permissions: owner + omerta group (0o660), fallback to owner-only (0o600)
            var attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o600]
            if let group = getgrnam("omerta") {
                let groupId = group.pointee.gr_gid
                attrs[.groupOwnerAccountID] = NSNumber(value: groupId)
                attrs[.posixPermissions] = 0o660
            }
            try? FileManager.default.setAttributes(attrs, ofItemAtPath: socketPath)

            logger.info("Data socket server started", metadata: ["path": "\(socketPath)"])

        } catch {
            state = .stopped
            if ownsEventLoopGroup {
                try? await eventLoopGroup?.shutdownGracefully()
                eventLoopGroup = nil
                ownsEventLoopGroup = false
            }
            throw IPCError.socketError("Failed to bind: \(error)")
        }
    }

    /// Stop the server
    public func stop() async {
        guard state == .running else { return }

        state = .stopping
        logger.info("Stopping data socket server")

        // Close all connections
        for connection in connections.values {
            await connection.close()
        }
        connections.removeAll()

        // Clear handlers
        tunnelHandlers.removeAll()

        // Close server channel
        if let channel = serverChannel {
            try? await channel.close()
            serverChannel = nil
        }

        // Shutdown event loop group if we own it
        if ownsEventLoopGroup, let elg = eventLoopGroup {
            try? await elg.shutdownGracefully()
            eventLoopGroup = nil
            ownsEventLoopGroup = false
        }

        // Clean up socket file
        try? DaemonSocketPaths.removeSocket(socketPath)

        state = .stopped
        logger.info("Data socket server stopped")
    }

    // MARK: - Tunnel Registration

    /// Register a handler for a tunnel
    /// - Parameters:
    ///   - tunnelId: The tunnel UUID
    ///   - handler: Handler called when packets arrive for this tunnel
    public func registerTunnel(_ tunnelId: UUID, handler: @escaping PacketHandler) {
        tunnelHandlers[tunnelId] = handler
        logger.debug("Tunnel registered", metadata: ["tunnelId": "\(tunnelId)"])
    }

    /// Unregister a tunnel handler
    public func unregisterTunnel(_ tunnelId: UUID) {
        tunnelHandlers.removeValue(forKey: tunnelId)
        logger.debug("Tunnel unregistered", metadata: ["tunnelId": "\(tunnelId)"])
    }

    /// Check if a tunnel is registered
    public func isTunnelRegistered(_ tunnelId: UUID) -> Bool {
        tunnelHandlers[tunnelId] != nil
    }

    // MARK: - Packet Sending

    /// Send a packet on a tunnel to all connected clients
    public func sendPacket(_ tunnelId: UUID, packet: Data) async throws {
        guard packet.count <= Self.maxPacketSize else {
            throw IPCError.messageTooLarge(packet.count)
        }

        let frame = TunnelPacket(tunnelId: tunnelId, data: packet)

        for connection in connections.values {
            try? await connection.send(frame)
        }
    }

    // MARK: - Internal

    /// Handle incoming packet
    func handlePacket(_ packet: TunnelPacket) async {
        guard let handler = tunnelHandlers[packet.tunnelId] else {
            logger.debug("No handler for tunnel, dropping packet",
                metadata: ["tunnelId": "\(packet.tunnelId)"])
            return
        }

        await handler(packet.tunnelId, packet.data)
    }

    /// Register a connection
    func registerConnection(_ connection: DataConnection) {
        let id = ObjectIdentifier(connection)
        connections[id] = connection
        logger.debug("Data connection registered", metadata: ["connectionId": "\(id)"])
    }

    /// Unregister a connection
    func unregisterConnection(_ connection: DataConnection) {
        let id = ObjectIdentifier(connection)
        connections.removeValue(forKey: id)
        logger.debug("Data connection unregistered", metadata: ["connectionId": "\(id)"])
    }

    /// Current server state
    public var currentState: State {
        state
    }

    /// Number of active connections
    public var connectionCount: Int {
        connections.count
    }

    /// Number of registered tunnels
    public var tunnelCount: Int {
        tunnelHandlers.count
    }
}

// MARK: - Data Connection

/// Represents a connected data client
public final class DataConnection: @unchecked Sendable {
    private let channel: Channel

    init(channel: Channel) {
        self.channel = channel
    }

    /// Send a tunnel packet
    func send(_ packet: TunnelPacket) async throws {
        var buffer = channel.allocator.buffer(capacity: 18 + packet.data.count)

        // Write tunnel ID (16 bytes)
        let uuidBytes = withUnsafeBytes(of: packet.tunnelId.uuid) { Data($0) }
        buffer.writeBytes(uuidBytes)

        // Write length (2 bytes, big-endian)
        buffer.writeInteger(UInt16(packet.data.count).bigEndian)

        // Write packet data
        buffer.writeBytes(packet.data)

        try await channel.writeAndFlush(buffer)
    }

    /// Close the connection
    func close() async {
        try? await channel.close()
    }

    /// Whether the connection is active
    var isActive: Bool {
        channel.isActive
    }
}

// MARK: - Tunnel Packet

/// A tunnel packet with UUID and data
public struct TunnelPacket: Sendable {
    public let tunnelId: UUID
    public let data: Data

    public init(tunnelId: UUID, data: Data) {
        self.tunnelId = tunnelId
        self.data = data
    }
}

// MARK: - NIO Handler

/// NIO channel handler for data socket communication
private final class DataSocketHandler: ChannelInboundHandler {
    typealias InboundIn = TunnelPacket
    typealias OutboundOut = ByteBuffer

    private let server: DataSocketServer
    private let logger: Logger
    private var connection: DataConnection?

    init(server: DataSocketServer) {
        self.server = server
        self.logger = Logger(label: "io.omerta.mesh.datasocket.handler")
    }

    func channelActive(context: ChannelHandlerContext) {
        let connection = DataConnection(channel: context.channel)
        self.connection = connection

        Task {
            await server.registerConnection(connection)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let connection = connection {
            Task {
                await server.unregisterConnection(connection)
            }
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let packet = unwrapInboundIn(data)

        Task { [weak self] in
            guard let self = self else { return }
            await self.server.handlePacket(packet)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Data channel error: \(error)")
        context.close(promise: nil)
    }
}

// MARK: - Frame Codec

/// Decoder for tunnel packet frames
/// Frame: [tunnelId (16 bytes)] [length (2 bytes BE)] [data]
private final class TunnelPacketDecoder: ByteToMessageDecoder {
    typealias InboundOut = TunnelPacket

    private enum State {
        case waitingForHeader
        case waitingForData(UUID, Int)
    }

    private var state: State = .waitingForHeader

    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        switch state {
        case .waitingForHeader:
            // Need 18 bytes: 16 for UUID + 2 for length
            guard buffer.readableBytes >= 18 else {
                return .needMoreData
            }

            // Read tunnel ID (16 bytes)
            guard let uuidBytes = buffer.readBytes(length: 16) else {
                return .needMoreData
            }

            let uuid = uuidBytes.withUnsafeBufferPointer { ptr -> UUID? in
                guard let base = ptr.baseAddress else { return nil }
                return base.withMemoryRebound(to: uuid_t.self, capacity: 1) { uuidPtr in
                    UUID(uuid: uuidPtr.pointee)
                }
            }
            guard let uuid else {
                throw IPCError.invalidMessage("Invalid tunnel UUID in frame header")
            }

            // Read length (2 bytes, big-endian)
            guard let lengthBE = buffer.readInteger(as: UInt16.self) else {
                return .needMoreData
            }
            let length = Int(lengthBE.bigEndian)

            guard length <= DataSocketServer.maxPacketSize else {
                throw IPCError.messageTooLarge(length)
            }

            state = .waitingForData(uuid, length)
            return .continue

        case .waitingForData(let tunnelId, let length):
            guard buffer.readableBytes >= length else {
                return .needMoreData
            }

            guard let bytes = buffer.readBytes(length: length) else {
                return .needMoreData
            }

            let packet = TunnelPacket(tunnelId: tunnelId, data: Data(bytes))
            state = .waitingForHeader
            context.fireChannelRead(wrapInboundOut(packet))
            return .continue
        }
    }
}

/// Encoder for tunnel packet frames
private final class TunnelPacketEncoder: MessageToByteEncoder {
    typealias OutboundIn = ByteBuffer

    func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        var mutableData = data
        out.writeBuffer(&mutableData)
    }
}
