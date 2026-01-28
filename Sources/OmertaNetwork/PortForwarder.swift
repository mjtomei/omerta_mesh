import Foundation
import NIOCore
import NIOPosix
import Logging

/// Forwards a local TCP port to a fixed remote mesh host:port via a NetworkInterface.
public actor PortForwarder {
    private let localPort: UInt16
    private let remoteHost: String
    private let remotePort: UInt16
    private let networkInterface: any NetworkInterface
    private let logger = Logger(label: "omerta.port-forwarder")
    private var serverChannel: Channel?
    private var eventLoopGroup: EventLoopGroup?
    private var _activeConnections: Int = 0

    /// The actual port the server bound to (useful when `localPort` is 0).
    public private(set) var actualPort: UInt16 = 0

    /// Number of currently active relay connections.
    public var activeConnections: Int { _activeConnections }

    public init(localPort: UInt16, remoteHost: String, remotePort: UInt16, interface: any NetworkInterface) {
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.networkInterface = interface
    }

    public func start() async throws {
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.eventLoopGroup = elg

        let netIface = self.networkInterface
        let rHost = self.remoteHost
        let rPort = self.remotePort
        let log = self.logger

        // We need a reference back to the actor for connection counting.
        // Use a simple Sendable counter.
        let counter = ConnectionCounter()

        let bootstrap = ServerBootstrap(group: elg)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(
                    PortForwardHandler(
                        networkInterface: netIface,
                        remoteHost: rHost,
                        remotePort: rPort,
                        logger: log,
                        counter: counter
                    )
                )
            }

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: Int(localPort)).get()
        self.serverChannel = channel

        if let addr = channel.localAddress, let p = addr.port {
            self.actualPort = UInt16(p)
            logger.info("Port forwarder listening on 127.0.0.1:\(p) -> \(rHost):\(rPort)")
        }

        // Store counter so we can read it
        self._counter = counter
    }

    private var _counter: ConnectionCounter?

    /// Refreshes and returns the active connection count from the shared counter.
    public func refreshActiveConnections() -> Int {
        _activeConnections = _counter?.count ?? 0
        return _activeConnections
    }

    public func stop() async {
        try? serverChannel?.close().wait()
        serverChannel = nil
        try? eventLoopGroup?.syncShutdownGracefully()
        eventLoopGroup = nil
        logger.info("Port forwarder stopped")
    }
}

/// Thread-safe connection counter.
final class ConnectionCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var _count: Int = 0

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return _count
    }

    func increment() {
        lock.lock()
        _count += 1
        lock.unlock()
    }

    func decrement() {
        lock.lock()
        _count -= 1
        lock.unlock()
    }
}

// MARK: - Port Forward Handler

private final class PortForwardHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let networkInterface: any NetworkInterface
    private let remoteHost: String
    private let remotePort: UInt16
    private let logger: Logger
    private let counter: ConnectionCounter
    private var connection: TCPConnection?
    private var relayTask: Task<Void, Never>?
    private var pendingData: [ByteBuffer] = []
    private var connected = false

    init(networkInterface: any NetworkInterface, remoteHost: String, remotePort: UInt16, logger: Logger, counter: ConnectionCounter) {
        self.networkInterface = networkInterface
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.logger = logger
        self.counter = counter
    }

    func channelActive(context: ChannelHandlerContext) {
        counter.increment()
        let netIface = self.networkInterface
        let rHost = self.remoteHost
        let rPort = self.remotePort
        let channel = context.channel

        Task { [weak self] in
            do {
                guard let conn = try await netIface.dialTCP(host: rHost, port: rPort) else {
                    try? await channel.eventLoop.submit {
                        channel.close(promise: nil)
                    }.get()
                    return
                }

                try? await channel.eventLoop.submit {
                    self?.connection = conn
                    self?.connected = true
                    self?.startRemoteRelay(context: context, connection: conn)
                    // Flush any pending data
                    if let selfRef = self {
                        for var buf in selfRef.pendingData {
                            if let bytes = buf.readBytes(length: buf.readableBytes) {
                                let data = Data(bytes)
                                Task { try? await conn.write(data) }
                            }
                        }
                        selfRef.pendingData.removeAll()
                    }
                }.get()
            } catch {
                try? await channel.eventLoop.submit {
                    channel.close(promise: nil)
                }.get()
            }
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        if connected, let conn = connection {
            if let bytes = buf.readBytes(length: buf.readableBytes) {
                let data = Data(bytes)
                Task { try? await conn.write(data) }
            }
        } else {
            pendingData.append(buf)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        counter.decrement()
        relayTask?.cancel()
        relayTask = nil
        if let conn = connection {
            Task { await conn.close() }
        }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Port forward error: \(error)")
        context.close(promise: nil)
    }

    private func startRemoteRelay(context: ChannelHandlerContext, connection: TCPConnection) {
        let channel = context.channel
        relayTask = Task {
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
                        channel.close(promise: nil)
                    }.get()
                }
            }
        }
    }
}
