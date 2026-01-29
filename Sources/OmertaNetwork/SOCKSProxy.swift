import Foundation
import NIOCore
import NIOPosix
import Logging

/// SOCKS5 proxy (RFC 1928) that tunnels TCP connections through a NetworkInterface.
public actor SOCKSProxy {
    private let port: UInt16
    private let networkInterface: any NetworkInterface
    private let logger = Logger(label: "omerta.socks-proxy")
    private var serverChannel: Channel?
    private var eventLoopGroup: EventLoopGroup?

    /// The actual port the server bound to (useful when `port` is 0).
    public private(set) var actualPort: UInt16 = 0

    public init(port: UInt16, interface: any NetworkInterface) {
        self.port = port
        self.networkInterface = interface
    }

    public func start() async throws {
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.eventLoopGroup = elg

        let netIface = self.networkInterface
        let log = self.logger

        let bootstrap = ServerBootstrap(group: elg)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(SOCKSHandler(networkInterface: netIface, logger: log))
            }

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: Int(port)).get()
        self.serverChannel = channel

        if let addr = channel.localAddress, let p = addr.port {
            self.actualPort = UInt16(p)
            logger.info("SOCKS5 proxy listening on 127.0.0.1:\(p)")
        }
    }

    public func stop() async {
        try? serverChannel?.close().wait()
        serverChannel = nil
        try? eventLoopGroup?.syncShutdownGracefully()
        eventLoopGroup = nil
        logger.info("SOCKS5 proxy stopped")
    }
}

// MARK: - SOCKS5 Channel Handler

private enum SOCKSState {
    case waitingGreeting
    case waitingConnect
    case relaying
}

private final class SOCKSHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let networkInterface: any NetworkInterface
    private let logger: Logger
    private var state: SOCKSState = .waitingGreeting
    private var buffer = ByteBuffer()
    private var connection: TCPConnection?
    private var relayTask: Task<Void, Never>?

    init(networkInterface: any NetworkInterface, logger: Logger) {
        self.networkInterface = networkInterface
        self.logger = logger
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        buffer.writeBuffer(&incoming)

        switch state {
        case .waitingGreeting:
            handleGreeting(context: context)
        case .waitingConnect:
            handleConnect(context: context)
        case .relaying:
            handleRelay(context: context)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        relayTask?.cancel()
        relayTask = nil
        if let conn = connection {
            Task { await conn.close() }
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("SOCKS handler error: \(error)")
        context.close(promise: nil)
    }

    // MARK: - Greeting

    private func handleGreeting(context: ChannelHandlerContext) {
        // Need at least 2 bytes: version + nMethods
        guard buffer.readableBytes >= 2 else { return }

        let readerIndex = buffer.readerIndex
        guard let version = buffer.getInteger(at: readerIndex, as: UInt8.self),
              let nMethods = buffer.getInteger(at: readerIndex + 1, as: UInt8.self) else { return }

        let totalLen = 2 + Int(nMethods)
        guard buffer.readableBytes >= totalLen else { return }

        guard version == 0x05 else {
            context.close(promise: nil)
            return
        }

        // Read methods
        buffer.moveReaderIndex(forwardBy: 2)
        var methods: [UInt8] = []
        for _ in 0..<nMethods {
            if let m = buffer.readInteger(as: UInt8.self) {
                methods.append(m)
            }
        }

        if methods.contains(0x00) {
            // No auth required - accepted
            var reply = context.channel.allocator.buffer(capacity: 2)
            reply.writeBytes([0x05, 0x00])
            context.writeAndFlush(wrapOutboundOut(reply), promise: nil)
            state = .waitingConnect
        } else {
            // No acceptable method
            var reply = context.channel.allocator.buffer(capacity: 2)
            reply.writeBytes([0x05, 0xFF])
            context.writeAndFlush(wrapOutboundOut(reply), promise: nil)
            context.close(promise: nil)
        }
    }

    // MARK: - Connect

    private func handleConnect(context: ChannelHandlerContext) {
        // Minimum: ver(1) + cmd(1) + rsv(1) + atyp(1) + addr(variable) + port(2)
        guard buffer.readableBytes >= 7 else { return }

        let readerIndex = buffer.readerIndex
        guard let version = buffer.getInteger(at: readerIndex, as: UInt8.self),
              let cmd = buffer.getInteger(at: readerIndex + 1, as: UInt8.self),
              let addrType = buffer.getInteger(at: readerIndex + 3, as: UInt8.self) else { return }

        guard version == 0x05, cmd == 0x01 else {
            sendConnectReply(context: context, rep: 0x07) // Command not supported
            context.close(promise: nil)
            return
        }

        var host: String?
        var consumed = 4 // ver + cmd + rsv + atyp

        switch addrType {
        case 0x01: // IPv4
            guard buffer.readableBytes >= consumed + 4 + 2 else { return }
            let a = buffer.getInteger(at: readerIndex + consumed, as: UInt8.self)!
            let b = buffer.getInteger(at: readerIndex + consumed + 1, as: UInt8.self)!
            let c = buffer.getInteger(at: readerIndex + consumed + 2, as: UInt8.self)!
            let d = buffer.getInteger(at: readerIndex + consumed + 3, as: UInt8.self)!
            host = "\(a).\(b).\(c).\(d)"
            consumed += 4

        case 0x03: // Domain name
            guard buffer.readableBytes >= consumed + 1 else { return }
            let domainLen = Int(buffer.getInteger(at: readerIndex + consumed, as: UInt8.self)!)
            consumed += 1
            guard buffer.readableBytes >= consumed + domainLen + 2 else { return }
            if let domainBytes = buffer.getBytes(at: readerIndex + consumed, length: domainLen) {
                host = String(bytes: domainBytes, encoding: .utf8)
            }
            consumed += domainLen

        default:
            sendConnectReply(context: context, rep: 0x08) // Address type not supported
            context.close(promise: nil)
            return
        }

        // Read port (big-endian UInt16)
        guard buffer.readableBytes >= consumed + 2 else { return }
        let portHi = UInt16(buffer.getInteger(at: readerIndex + consumed, as: UInt8.self)!)
        let portLo = UInt16(buffer.getInteger(at: readerIndex + consumed + 1, as: UInt8.self)!)
        let remotePort = (portHi << 8) | portLo
        consumed += 2

        buffer.moveReaderIndex(forwardBy: consumed)

        guard let targetHost = host else {
            sendConnectReply(context: context, rep: 0x01) // General failure
            context.close(promise: nil)
            return
        }

        let netIface = self.networkInterface
        let channel = context.channel

        Task { [weak self] in
            do {
                guard let conn = try await netIface.dialTCP(host: targetHost, port: remotePort) else {
                    try? await channel.eventLoop.submit {
                        self?.sendConnectReply(context: context, rep: 0x05) // Connection refused
                        context.close(promise: nil)
                    }.get()
                    return
                }

                try? await channel.eventLoop.submit {
                    self?.connection = conn
                    self?.sendConnectReply(context: context, rep: 0x00)
                    self?.state = .relaying
                    self?.startRemoteRelay(context: context, connection: conn)

                    // Relay any leftover buffered data
                    if let selfRef = self, selfRef.buffer.readableBytes > 0 {
                        selfRef.handleRelay(context: context)
                    }
                }.get()
            } catch {
                try? await channel.eventLoop.submit {
                    self?.sendConnectReply(context: context, rep: 0x01)
                    context.close(promise: nil)
                }.get()
            }
        }
    }

    private func sendConnectReply(context: ChannelHandlerContext, rep: UInt8) {
        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        var reply = context.channel.allocator.buffer(capacity: 10)
        reply.writeBytes([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        context.writeAndFlush(wrapOutboundOut(reply), promise: nil)
    }

    // MARK: - Relay

    private func handleRelay(context: ChannelHandlerContext) {
        guard let conn = connection, buffer.readableBytes > 0 else { return }
        let bytes = buffer.readBytes(length: buffer.readableBytes)!
        let data = Data(bytes)
        Task {
            try? await conn.write(data)
        }
    }

    private func startRemoteRelay(context: ChannelHandlerContext, connection: TCPConnection) {
        let channel = context.channel
        relayTask = Task { [weak self] in
            do {
                while !Task.isCancelled {
                    let data = try await connection.read()
                    guard !data.isEmpty else {
                        try? await channel.eventLoop.submit {
                            channel.close(promise: nil)
                        }.get()
                        return
                    }
                    try await channel.eventLoop.submit {
                        var buf = channel.allocator.buffer(capacity: data.count)
                        buf.writeBytes(data)
                        channel.writeAndFlush(buf, promise: nil)
                    }.get()
                }
            } catch {
                if !Task.isCancelled {
                    try? await channel.eventLoop.submit {
                        _ = self
                        channel.close(promise: nil)
                    }.get()
                }
            }
        }
    }
}
