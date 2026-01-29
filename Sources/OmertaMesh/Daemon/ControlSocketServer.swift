// ControlSocketServer.swift - Unix domain socket server for daemon IPC
//
// Provides a NIO-based server for receiving commands and sending responses
// using length-prefixed JSON framing.

import Foundation
import NIOCore
import NIOPosix
import Logging

// MARK: - Control Socket Server

/// Unix domain socket server for daemon control communication
public actor ControlSocketServer {
    /// Server state
    public enum State: Sendable {
        case stopped
        case starting
        case running
        case stopping
    }

    /// Handler for incoming commands
    public typealias CommandHandler<Command: Decodable & Sendable, Response: Encodable & Sendable> =
        @Sendable (Command, ClientConnection) async -> Response

    private let socketPath: String
    private let logger: Logger
    private var state: State = .stopped
    private var eventLoopGroup: EventLoopGroup?
    private var serverChannel: Channel?
    private var clients: [ObjectIdentifier: ClientConnection] = [:]
    private var ownsEventLoopGroup: Bool = false

    /// Create a new control socket server
    /// - Parameters:
    ///   - socketPath: Path to the Unix domain socket
    ///   - eventLoopGroup: Optional event loop group (creates own if nil)
    public init(socketPath: String, eventLoopGroup: EventLoopGroup? = nil) {
        self.socketPath = socketPath
        self.logger = Logger(label: "io.omerta.mesh.controlsocket.server")
        self.eventLoopGroup = eventLoopGroup
    }

    /// Start the server
    /// - Parameter handler: Handler for incoming commands
    public func start<Command: Decodable & Sendable, Response: Encodable & Sendable>(
        handler: @escaping CommandHandler<Command, Response>
    ) async throws {
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
                        ByteToMessageHandler(LengthPrefixedFrameDecoder()),
                        MessageToByteHandler(LengthPrefixedFrameEncoder()),
                        ControlSocketHandler<Command, Response>(server: server, handler: handler)
                    ])
                }
                .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

            let channel = try await bootstrap.bind(unixDomainSocketPath: socketPath).get()

            serverChannel = channel
            state = .running

            // Set socket permissions: owner + omerta group (0o660), fallback to owner-only (0o600)
            var attrs: [FileAttributeKey: Any] = [.posixPermissions: 0o600]
            if let group = getgrnam("omerta") {
                let groupId = group.pointee.gr_gid
                attrs[.groupOwnerAccountID] = NSNumber(value: groupId)
                attrs[.posixPermissions] = 0o660
                logger.info("Control socket using 'omerta' group (gid: \(groupId))")
            } else {
                logger.notice("'omerta' group not found, control socket restricted to owner only")
            }
            try? FileManager.default.setAttributes(attrs, ofItemAtPath: socketPath)

            logger.info("Control socket server started", metadata: ["path": "\(socketPath)"])

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
        logger.info("Stopping control socket server")

        // Close all client connections
        for client in clients.values {
            await client.close()
        }
        clients.removeAll()

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
        logger.info("Control socket server stopped")
    }

    /// Register a client connection
    func registerClient(_ client: ClientConnection) {
        let id = ObjectIdentifier(client)
        clients[id] = client
        logger.debug("Client connected", metadata: ["clientId": "\(id)"])
    }

    /// Unregister a client connection
    func unregisterClient(_ client: ClientConnection) {
        let id = ObjectIdentifier(client)
        clients.removeValue(forKey: id)
        logger.debug("Client disconnected", metadata: ["clientId": "\(id)"])
    }

    /// Get all connected clients
    public var connectedClients: [ClientConnection] {
        Array(clients.values)
    }

    /// Number of connected clients
    public var clientCount: Int {
        clients.count
    }

    /// Current server state
    public var currentState: State {
        state
    }
}

// MARK: - Client Connection

/// Represents a connected client
public final class ClientConnection: @unchecked Sendable {
    private let channel: Channel
    private let logger: Logger
    public let clientId: String

    init(channel: Channel) {
        self.channel = channel
        self.clientId = UUID().uuidString
        self.logger = Logger(label: "io.omerta.mesh.controlsocket.client.\(clientId.prefix(8))")
    }

    /// Send a response to this client
    public func send<Response: Encodable>(_ response: Response) async throws {
        let data = try IPCMessage.encode(response)
        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        try await channel.writeAndFlush(buffer)
    }

    /// Close the connection
    public func close() async {
        try? await channel.close()
    }

    /// Whether the connection is still active
    public var isActive: Bool {
        channel.isActive
    }
}

// MARK: - NIO Handler

/// NIO channel handler for control socket communication
private final class ControlSocketHandler<Command: Decodable & Sendable, Response: Encodable & Sendable>: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let server: ControlSocketServer
    private let handler: ControlSocketServer.CommandHandler<Command, Response>
    private let logger: Logger
    private var client: ClientConnection?

    init(server: ControlSocketServer, handler: @escaping ControlSocketServer.CommandHandler<Command, Response>) {
        self.server = server
        self.handler = handler
        self.logger = Logger(label: "io.omerta.mesh.controlsocket.handler")
    }

    func channelActive(context: ChannelHandlerContext) {
        let client = ClientConnection(channel: context.channel)
        self.client = client

        Task {
            await server.registerClient(client)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if let client = client {
            Task {
                await server.unregisterClient(client)
            }
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)

        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            logger.warning("Failed to read bytes from buffer")
            return
        }

        let data = Data(bytes)

        Task { [weak self] in
            guard let self = self, let client = self.client else { return }

            do {
                let command = try IPCMessage.decode(Command.self, from: data)
                let response = await self.handler(command, client)
                try await client.send(response)
            } catch {
                self.logger.error("Error handling command: \(error)")
                // Try to send error response if we can
                // This is a best-effort attempt
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Channel error: \(error)")
        context.close(promise: nil)
    }
}

// MARK: - Frame Codec

/// Decoder for length-prefixed frames
private final class LengthPrefixedFrameDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer

    private enum State {
        case waitingForLength
        case waitingForPayload(Int)
    }

    private var state: State = .waitingForLength

    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        switch state {
        case .waitingForLength:
            guard buffer.readableBytes >= 4 else {
                return .needMoreData
            }

            // NIO's readInteger defaults to big-endian, matching our wire format
            let length = buffer.readInteger(endianness: .big, as: UInt32.self)!
            let payloadLength = Int(length)

            guard payloadLength <= IPCMessage.maxMessageSize else {
                throw IPCError.messageTooLarge(payloadLength)
            }

            state = .waitingForPayload(payloadLength)
            return .continue

        case .waitingForPayload(let length):
            guard buffer.readableBytes >= length else {
                return .needMoreData
            }

            let payload = buffer.readSlice(length: length)!
            state = .waitingForLength
            context.fireChannelRead(wrapInboundOut(payload))
            return .continue
        }
    }
}

/// Encoder for length-prefixed frames
private final class LengthPrefixedFrameEncoder: MessageToByteEncoder {
    typealias OutboundIn = ByteBuffer

    func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
        // Data already includes length prefix from IPCMessage.encode
        var mutableData = data
        out.writeBuffer(&mutableData)
    }
}
