// ProxyIntegrationTests.swift - End-to-end integration tests for SOCKS5 proxy and port forwarder
//
// Uses a LoopbackBridge that implements dialTCP with real TCP sockets,
// connecting to a local echo server. This tests the full data path:
//   App → NIO proxy → NetworkInterface.dialTCP() → real TCP → echo server → back

import XCTest
import Foundation
import NIOCore
import NIOPosix
@testable import OmertaNetwork

// MARK: - Loopback TCP Infrastructure

/// A real TCP connection backed by a POSIX socket.
private final class LoopbackTCPConnection: TCPConnection, @unchecked Sendable {
    let remoteHost: String
    let remotePort: UInt16
    private let fd: Int32
    private var isClosed = false

    init(fd: Int32, host: String, port: UInt16) {
        self.fd = fd
        self.remoteHost = host
        self.remotePort = port
    }

    func read() async throws -> Data {
        guard !isClosed else { throw InterfaceError.closed }
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global().async { [fd] in
                var buf = [UInt8](repeating: 0, count: 4096)
                let n = recv(fd, &buf, buf.count, 0)
                if n > 0 {
                    continuation.resume(returning: Data(buf[0..<n]))
                } else if n == 0 {
                    continuation.resume(returning: Data())
                } else {
                    continuation.resume(throwing: InterfaceError.readFailed("recv: \(errno)"))
                }
            }
        }
    }

    func write(_ data: Data) async throws {
        guard !isClosed else { throw InterfaceError.closed }
        let bytes = Array(data)
        let n = send(fd, bytes, bytes.count, 0)
        guard n == bytes.count else {
            throw InterfaceError.writeFailed("send: \(errno)")
        }
    }

    func close() async {
        guard !isClosed else { return }
        isClosed = true
        Foundation.close(fd)
    }

    deinit {
        if !isClosed { Foundation.close(fd) }
    }
}

/// A NetstackBridgeProtocol that implements dialTCP using real POSIX sockets.
/// Packet-level methods are stubs — this bridge is only used for TCP dial.
private actor LoopbackBridge: NetstackBridgeProtocol {
    private var isRunning = false

    func start() async throws { isRunning = true }
    func stop() async { isRunning = false }

    func injectPacket(_ packet: Data) async throws {
        throw InterfaceError.notSupported
    }

    func setReturnCallback(_ callback: @escaping @Sendable (Data) -> Void) async {}

    func dialTCP(host: String, port: UInt16) async throws -> TCPConnection {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw InterfaceError.dialFailed("socket: \(errno)") }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr(host)

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Foundation.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            Foundation.close(fd)
            throw InterfaceError.dialFailed("connect to \(host):\(port): \(errno)")
        }

        return LoopbackTCPConnection(fd: fd, host: host, port: port)
    }
}

// MARK: - Echo Server

/// Simple TCP echo server that sends back whatever it receives.
private final class EchoServer: @unchecked Sendable {
    private var serverChannel: Channel?
    private let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private(set) var port: UInt16 = 0

    func start() throws {
        let bootstrap = ServerBootstrap(group: elg)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(EchoHandler())
            }
        let channel = try bootstrap.bind(host: "127.0.0.1", port: 0).wait()
        self.serverChannel = channel
        self.port = UInt16(channel.localAddress!.port!)
    }

    func stop() {
        try? serverChannel?.close().wait()
        try? elg.syncShutdownGracefully()
    }
}

private final class EchoHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // Echo back exactly what was received
        context.writeAndFlush(data, promise: nil)
    }
}

/// A TCP server that prefixes each received message with a fixed tag before echoing.
private final class TaggingServer: @unchecked Sendable {
    private var serverChannel: Channel?
    private let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private(set) var port: UInt16 = 0
    private let tag: String

    init(tag: String) { self.tag = tag }

    func start() throws {
        let tag = self.tag
        let bootstrap = ServerBootstrap(group: elg)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(TaggingHandler(tag: tag))
            }
        let channel = try bootstrap.bind(host: "127.0.0.1", port: 0).wait()
        self.serverChannel = channel
        self.port = UInt16(channel.localAddress!.port!)
    }

    func stop() {
        try? serverChannel?.close().wait()
        try? elg.syncShutdownGracefully()
    }
}

private final class TaggingHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    let tag: String
    init(tag: String) { self.tag = tag }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        let incoming = buf.readBytes(length: buf.readableBytes) ?? []
        var out = context.channel.allocator.buffer(capacity: tag.utf8.count + incoming.count)
        out.writeString(tag)
        out.writeBytes(incoming)
        context.writeAndFlush(wrapOutboundOut(out), promise: nil)
    }
}

/// A TCP server that closes the connection immediately after receiving data.
private final class CloseAfterReadServer: @unchecked Sendable {
    private var serverChannel: Channel?
    private let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private(set) var port: UInt16 = 0

    func start() throws {
        let bootstrap = ServerBootstrap(group: elg)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(CloseAfterReadHandler())
            }
        let channel = try bootstrap.bind(host: "127.0.0.1", port: 0).wait()
        self.serverChannel = channel
        self.port = UInt16(channel.localAddress!.port!)
    }

    func stop() {
        try? serverChannel?.close().wait()
        try? elg.syncShutdownGracefully()
    }
}

private final class CloseAfterReadHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.close(promise: nil)
    }
}

// MARK: - Socket Helper

private class TestSocket {
    let fd: Int32

    init(connectingTo port: UInt16) throws {
        fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard fd >= 0 else { throw InterfaceError.dialFailed("socket: \(errno)") }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Foundation.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            Foundation.close(fd)
            throw InterfaceError.dialFailed("connect: \(errno)")
        }
    }

    func send(_ bytes: [UInt8]) {
        bytes.withUnsafeBufferPointer { ptr in
            _ = Foundation.send(fd, ptr.baseAddress!, ptr.count, 0)
        }
    }

    func sendData(_ data: Data) {
        send(Array(data))
    }

    func recv(count: Int, timeout: TimeInterval) throws -> Data {
        var pollFd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        var collected = Data()
        let deadline = Date().addingTimeInterval(timeout)

        while collected.count < count {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else {
                if collected.isEmpty {
                    throw NSError(domain: "ProxyIntegrationTest", code: -1,
                                  userInfo: [NSLocalizedDescriptionKey: "recv timeout"])
                }
                return collected
            }
            let ret = poll(&pollFd, 1, Int32(remaining * 1000))
            guard ret > 0 else { continue }
            var buf = [UInt8](repeating: 0, count: count - collected.count)
            let n = Foundation.recv(fd, &buf, buf.count, 0)
            if n <= 0 { break }
            collected.append(contentsOf: buf[0..<n])
        }
        return collected
    }

    func close() {
        Foundation.close(fd)
    }

    deinit { Foundation.close(fd) }
}

// MARK: - SOCKS5 Helpers

private func socksGreeting(_ sock: TestSocket) throws -> Data {
    sock.send([0x05, 0x01, 0x00])
    return try sock.recv(count: 2, timeout: 2.0)
}

private func socksConnectIPv4(_ sock: TestSocket, host: String, port: UInt16) throws -> Data {
    let parts = host.split(separator: ".").compactMap { UInt8($0) }
    precondition(parts.count == 4)
    var req: [UInt8] = [0x05, 0x01, 0x00, 0x01]
    req.append(contentsOf: parts)
    req.append(UInt8(port >> 8))
    req.append(UInt8(port & 0xFF))
    sock.send(req)
    return try sock.recv(count: 10, timeout: 2.0)
}

// MARK: - Integration Tests: SOCKS5

final class SOCKSProxyIntegrationTests: XCTestCase {

    private var echoServer: EchoServer!
    private var bridge: LoopbackBridge!
    private var netInterface: NetstackInterface!
    private var proxy: SOCKSProxy!

    override func setUp() async throws {
        echoServer = EchoServer()
        try echoServer.start()

        bridge = LoopbackBridge()
        netInterface = NetstackInterface(localIP: "10.0.0.1", bridge: bridge)
        try await netInterface.start()

        proxy = SOCKSProxy(port: 0, interface: netInterface)
        try await proxy.start()
    }

    override func tearDown() async throws {
        await proxy.stop()
        await netInterface.stop()
        echoServer.stop()
    }

    /// Full round trip: client → SOCKS5 proxy → echo server → client
    func testSOCKS5EchoRoundTrip() async throws {
        let proxyPort = await proxy.actualPort
        let sock = try TestSocket(connectingTo: proxyPort)
        defer { sock.close() }

        let greeting = try socksGreeting(sock)
        XCTAssertEqual(greeting, Data([0x05, 0x00]))

        let connectReply = try socksConnectIPv4(sock, host: "127.0.0.1", port: echoServer.port)
        XCTAssertEqual(connectReply[1], 0x00, "SOCKS connect should succeed")

        // Send data through proxy to echo server
        let message = Data("Hello from integration test!".utf8)
        sock.sendData(message)

        let echoed = try sock.recv(count: message.count, timeout: 3.0)
        XCTAssertEqual(echoed, message, "Data should round-trip through proxy and echo server")
    }

    /// Multiple sequential messages in a single SOCKS session
    func testSOCKS5MultipleMessages() async throws {
        let proxyPort = await proxy.actualPort
        let sock = try TestSocket(connectingTo: proxyPort)
        defer { sock.close() }

        _ = try socksGreeting(sock)
        let reply = try socksConnectIPv4(sock, host: "127.0.0.1", port: echoServer.port)
        XCTAssertEqual(reply[1], 0x00)

        for i in 0..<5 {
            let msg = Data("message-\(i)".utf8)
            sock.sendData(msg)
            let echoed = try sock.recv(count: msg.count, timeout: 2.0)
            XCTAssertEqual(echoed, msg, "Message \(i) should echo correctly")
        }
    }

    /// Large payload transfer through the proxy
    func testSOCKS5LargePayload() async throws {
        let proxyPort = await proxy.actualPort
        let sock = try TestSocket(connectingTo: proxyPort)
        defer { sock.close() }

        _ = try socksGreeting(sock)
        let reply = try socksConnectIPv4(sock, host: "127.0.0.1", port: echoServer.port)
        XCTAssertEqual(reply[1], 0x00)

        // 64KB payload
        let payload = Data((0..<65536).map { UInt8($0 & 0xFF) })
        sock.sendData(payload)

        let echoed = try sock.recv(count: payload.count, timeout: 5.0)
        XCTAssertEqual(echoed.count, payload.count)
        XCTAssertEqual(echoed, payload)
    }

    /// Connect to a server that closes after first read — proxy should handle gracefully
    func testSOCKS5RemoteCloses() async throws {
        let closeServer = CloseAfterReadServer()
        try closeServer.start()
        defer { closeServer.stop() }

        let proxyPort = await proxy.actualPort
        let sock = try TestSocket(connectingTo: proxyPort)
        defer { sock.close() }

        _ = try socksGreeting(sock)
        let reply = try socksConnectIPv4(sock, host: "127.0.0.1", port: closeServer.port)
        XCTAssertEqual(reply[1], 0x00)

        sock.sendData(Data("trigger close".utf8))

        // Should see the connection close (recv returns 0 or error)
        try await Task.sleep(for: .milliseconds(300))
        var buf = [UInt8](repeating: 0, count: 1)
        let n = Foundation.recv(sock.fd, &buf, 1, Int32(MSG_DONTWAIT))
        XCTAssertLessThanOrEqual(n, 0, "Local socket should be closed after remote closes")
    }

    /// SOCKS5 connect to unreachable port should return failure reply
    func testSOCKS5ConnectRefused() async throws {
        let proxyPort = await proxy.actualPort
        let sock = try TestSocket(connectingTo: proxyPort)
        defer { sock.close() }

        _ = try socksGreeting(sock)

        // Connect to a port that nobody is listening on
        let reply = try socksConnectIPv4(sock, host: "127.0.0.1", port: 1)
        XCTAssertNotEqual(reply[1], 0x00, "Connect to closed port should fail")
    }

    /// Multiple concurrent SOCKS sessions through the same proxy
    func testSOCKS5ConcurrentSessions() async throws {
        let proxyPort = await proxy.actualPort

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<5 {
                group.addTask {
                    let sock = try TestSocket(connectingTo: proxyPort)
                    defer { sock.close() }

                    _ = try socksGreeting(sock)
                    let reply = try socksConnectIPv4(sock, host: "127.0.0.1", port: self.echoServer.port)
                    XCTAssertEqual(reply[1], 0x00)

                    let msg = Data("concurrent-\(i)".utf8)
                    sock.sendData(msg)
                    let echoed = try sock.recv(count: msg.count, timeout: 3.0)
                    XCTAssertEqual(echoed, msg)
                }
            }
            try await group.waitForAll()
        }
    }
}

// MARK: - Integration Tests: Port Forwarder

final class PortForwarderIntegrationTests: XCTestCase {

    private var echoServer: EchoServer!
    private var bridge: LoopbackBridge!
    private var netInterface: NetstackInterface!
    private var forwarder: PortForwarder!

    override func setUp() async throws {
        echoServer = EchoServer()
        try echoServer.start()

        bridge = LoopbackBridge()
        netInterface = NetstackInterface(localIP: "10.0.0.1", bridge: bridge)
        try await netInterface.start()

        forwarder = PortForwarder(
            localPort: 0,
            remoteHost: "127.0.0.1",
            remotePort: echoServer.port,
            interface: netInterface
        )
        try await forwarder.start()
    }

    override func tearDown() async throws {
        await forwarder.stop()
        await netInterface.stop()
        echoServer.stop()
    }

    /// Full round trip through port forwarder to echo server
    func testPortForwardEchoRoundTrip() async throws {
        let fwdPort = await forwarder.actualPort
        let sock = try TestSocket(connectingTo: fwdPort)
        defer { sock.close() }

        // Wait for dial to complete
        try await Task.sleep(for: .milliseconds(200))

        let message = Data("Hello via port forward!".utf8)
        sock.sendData(message)

        let echoed = try sock.recv(count: message.count, timeout: 3.0)
        XCTAssertEqual(echoed, message)
    }

    /// Multiple messages through a single port-forwarded connection
    func testPortForwardMultipleMessages() async throws {
        let fwdPort = await forwarder.actualPort
        let sock = try TestSocket(connectingTo: fwdPort)
        defer { sock.close() }

        try await Task.sleep(for: .milliseconds(200))

        for i in 0..<10 {
            let msg = Data("msg-\(i)".utf8)
            sock.sendData(msg)
            let echoed = try sock.recv(count: msg.count, timeout: 2.0)
            XCTAssertEqual(echoed, msg, "Message \(i) should echo correctly")
        }
    }

    /// Large payload through port forwarder
    func testPortForwardLargePayload() async throws {
        let fwdPort = await forwarder.actualPort
        let sock = try TestSocket(connectingTo: fwdPort)
        defer { sock.close() }

        try await Task.sleep(for: .milliseconds(200))

        let payload = Data((0..<65536).map { UInt8($0 & 0xFF) })
        sock.sendData(payload)

        let echoed = try sock.recv(count: payload.count, timeout: 5.0)
        XCTAssertEqual(echoed.count, payload.count)
        XCTAssertEqual(echoed, payload)
    }

    /// Multiple concurrent clients through the port forwarder
    func testPortForwardConcurrentClients() async throws {
        let fwdPort = await forwarder.actualPort

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<5 {
                group.addTask {
                    let sock = try TestSocket(connectingTo: fwdPort)
                    defer { sock.close() }

                    try await Task.sleep(for: .milliseconds(200))

                    let msg = Data("client-\(i)".utf8)
                    sock.sendData(msg)
                    let echoed = try sock.recv(count: msg.count, timeout: 3.0)
                    XCTAssertEqual(echoed, msg)
                }
            }
            try await group.waitForAll()
        }

        let count = await forwarder.refreshActiveConnections()
        // Connections may or may not have closed by now, but should not crash
        XCTAssertGreaterThanOrEqual(count, 0)
    }

    /// Remote server closes — local connection should close too
    func testPortForwardRemoteCloses() async throws {
        let closeServer = CloseAfterReadServer()
        try closeServer.start()
        defer { closeServer.stop() }

        let fwd = PortForwarder(
            localPort: 0,
            remoteHost: "127.0.0.1",
            remotePort: closeServer.port,
            interface: netInterface
        )
        try await fwd.start()
        defer { Task { await fwd.stop() } }

        let fwdPort = await fwd.actualPort
        let sock = try TestSocket(connectingTo: fwdPort)
        defer { sock.close() }

        try await Task.sleep(for: .milliseconds(200))

        sock.sendData(Data("trigger".utf8))

        try await Task.sleep(for: .milliseconds(500))

        var buf = [UInt8](repeating: 0, count: 1)
        let n = Foundation.recv(sock.fd, &buf, 1, Int32(MSG_DONTWAIT))
        XCTAssertLessThanOrEqual(n, 0, "Should be closed after remote closes")
    }

    /// Port forwarder to a different backend (tagging server) to prove routing is correct
    func testPortForwardRoutesToConfiguredTarget() async throws {
        let tagging = TaggingServer(tag: "[TAGGED]")
        try tagging.start()
        defer { tagging.stop() }

        let fwd = PortForwarder(
            localPort: 0,
            remoteHost: "127.0.0.1",
            remotePort: tagging.port,
            interface: netInterface
        )
        try await fwd.start()
        defer { Task { await fwd.stop() } }

        let fwdPort = await fwd.actualPort
        let sock = try TestSocket(connectingTo: fwdPort)
        defer { sock.close() }

        try await Task.sleep(for: .milliseconds(200))

        let msg = Data("hello".utf8)
        sock.sendData(msg)

        let expected = Data("[TAGGED]hello".utf8)
        let response = try sock.recv(count: expected.count, timeout: 3.0)
        XCTAssertEqual(response, expected, "Should reach the tagging server, not the echo server")
    }
}
