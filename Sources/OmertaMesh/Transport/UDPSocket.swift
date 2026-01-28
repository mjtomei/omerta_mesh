// UDPSocket.swift - Async/await UDP socket wrapper using SwiftNIO
// Supports both IPv4 and IPv6 with dual-stack socket

import Foundation
import NIOCore
import NIOPosix
import Logging

/// Async/await wrapper for UDP sockets using SwiftNIO
/// Uses dual-stack IPv6 socket to support both IPv4 and IPv6
public actor UDPSocket {
    /// The NIO event loop group
    private let group: EventLoopGroup

    /// The bound channel (IPv6 dual-stack preferred, IPv4 fallback)
    private var channel: Channel?

    /// Whether we're using an IPv6 socket (for address conversion)
    private var isIPv6Socket = false

    /// The local address we're bound to
    public private(set) var localAddress: SocketAddress?

    /// Handler for incoming datagrams
    private var incomingHandler: ((Data, SocketAddress) async -> Void)?

    /// Whether the socket is running
    private var isRunning = false

    /// Logger
    private let logger = Logger(label: "io.omerta.mesh.udp")

    /// Bootstrap for creating datagram channels
    private func makeBootstrap() -> DatagramBootstrap {
        DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandler(UDPInboundHandler(socket: self))
            }
    }

    public init(eventLoopGroup: EventLoopGroup? = nil) {
        self.group = eventLoopGroup ?? MultiThreadedEventLoopGroup(numberOfThreads: 1)
    }

    // MARK: - Lifecycle

    /// Bind to a specific port with dual-stack IPv6 support
    /// Uses IPv6 dual-stack socket (accepts both IPv4 and IPv6) with IPv4 fallback
    public func bind(host: String = "::", port: Int) async throws {
        guard !isRunning else {
            throw UDPSocketError.alreadyRunning
        }

        // Try IPv6 dual-stack first (works with both IPv4 and IPv6)
        // Fall back to IPv4-only if IPv6 fails
        let (boundChannel, usingIPv6) = try await bindDualStack(port: port, preferredHost: host)

        self.channel = boundChannel
        self.isIPv6Socket = usingIPv6
        self.localAddress = boundChannel.localAddress
        self.isRunning = true

        let socketType = usingIPv6 ? "IPv6 dual-stack" : "IPv4"
        logger.info("UDP socket bound to \(boundChannel.localAddress?.description ?? "unknown") (\(socketType))")
    }

    /// Attempt to bind with dual-stack support
    /// - Parameters:
    ///   - port: The port to bind to
    ///   - preferredHost: The host to bind to. If a specific IPv6 address is provided,
    ///     it will be used instead of the dual-stack `::` address. This is important
    ///     on systems with IPv6 privacy extensions (e.g., macOS) where binding to `::`
    ///     causes outbound packets to use a temporary address instead of the stable
    ///     "secured" address that we advertise to peers.
    private func bindDualStack(port: Int, preferredHost: String) async throws -> (Channel, Bool) {
        // If explicitly requesting IPv4, use it
        if preferredHost == "0.0.0.0" {
            let channel = try await makeBootstrap().bind(host: "0.0.0.0", port: port).get()
            return (channel, false)
        }

        // If a specific IPv6 address is provided (not ::), bind to it directly
        // This ensures outbound packets use the same source address we advertise
        if preferredHost != "::" && isIPv6Address(preferredHost) {
            do {
                logger.info("Binding to specific IPv6 address: \(preferredHost)")
                let channel = try await makeBootstrap().bind(host: preferredHost, port: port).get()
                return (channel, true)
            } catch {
                logger.warning("Bind to specific IPv6 \(preferredHost) failed: \(error), falling back to dual-stack")
                // Fall through to dual-stack
            }
        }

        // Try IPv6 dual-stack (accepts both IPv4 and IPv6)
        do {
            let channel = try await makeBootstrap().bind(host: "::", port: port).get()
            return (channel, true)
        } catch {
            logger.info("IPv6 bind failed, falling back to IPv4: \(error)")
            // Fall back to IPv4
            let channel = try await makeBootstrap().bind(host: "0.0.0.0", port: port).get()
            return (channel, false)
        }
    }

    /// Close the socket
    public func close() async {
        guard isRunning else { return }

        isRunning = false
        try? await channel?.close()
        channel = nil
        localAddress = nil

        logger.info("UDP socket closed")
    }

    // MARK: - Sending

    /// Send data to a specific address
    /// Retries on transient errors like "host unreachable" which can occur on macOS
    /// due to stale ICMP error caching
    public func send(_ data: Data, to address: SocketAddress) async throws {
        guard let channel = channel, isRunning else {
            logger.warning("UDP send failed: socket not running")
            throw UDPSocketError.notRunning
        }

        // Convert address if needed for socket type compatibility
        let sendAddress = try convertAddressForSocket(address)

        let buffer = channel.allocator.buffer(bytes: data)
        let envelope = AddressedEnvelope(remoteAddress: sendAddress, data: buffer)

        logger.info("UDP sending \(data.count) bytes to \(sendAddress)")
        do {
            try await channel.writeAndFlush(envelope)
            logger.info("UDP sent \(data.count) bytes to \(sendAddress)")
        } catch {
            let errorString = "\(error)"

            // Check if this is a known transient/spurious error
            // On macOS, stale ICMP errors can be reported on UDP sends even when the
            // network is fine. The packet may still have been sent. Log and continue
            // rather than failing - let higher-level timeouts handle true failures.
            let isSpuriousError = errorString.lowercased().contains("unreachable") ||
                                  errorString.lowercased().contains("connection refused")

            if isSpuriousError {
                logger.warning("UDP send reported spurious error (packet may have been sent): \(error)")
                // Don't throw - let higher-level timeout mechanisms handle actual failures
                return
            }

            logger.error("UDP send failed to \(sendAddress): \(error)")
            throw UDPSocketError.sendFailed(destination: "\(sendAddress)", byteCount: data.count, underlying: error)
        }
    }

    /// Send data to a host:port string
    public func send(_ data: Data, to endpoint: String) async throws {
        let address = try parseEndpoint(endpoint)
        try await send(data, to: address)
    }

    /// Convert address to be compatible with current socket type
    private func convertAddressForSocket(_ address: SocketAddress) throws -> SocketAddress {
        guard isIPv6Socket else {
            // IPv4 socket - can only send to IPv4
            // If we get an IPv6 address, this is an error
            if case .v6 = address {
                throw UDPSocketError.addressMismatch("Cannot send IPv6 address on IPv4 socket")
            }
            return address
        }

        // IPv6 socket - convert IPv4 to IPv4-mapped IPv6
        if case .v4 = address {
            // Create IPv4-mapped IPv6 address (::ffff:w.x.y.z)
            guard let port = address.port,
                  let ipString = address.ipAddress else {
                throw UDPSocketError.invalidEndpoint("Cannot extract IP/port from address")
            }
            let mappedAddress = "::ffff:\(ipString)"
            return try SocketAddress(ipAddress: mappedAddress, port: port)
        }

        return address
    }

    // MARK: - Receiving

    /// Set a handler for incoming datagrams
    public func onReceive(_ handler: @escaping (Data, SocketAddress) async -> Void) {
        self.incomingHandler = handler
    }

    /// Called by the inbound handler when data arrives
    fileprivate func handleIncoming(data: Data, from address: SocketAddress) async {
        await incomingHandler?(data, address)
    }

    // MARK: - Utilities

    /// Parse an endpoint string into a SocketAddress
    /// Supports:
    /// - IPv4: "192.168.1.1:5000"
    /// - IPv6: "[::1]:5000" or "::1:5000" (if unambiguous)
    /// - Hostname: "example.com:5000"
    private func parseEndpoint(_ endpoint: String) throws -> SocketAddress {
        // Handle IPv6 bracket notation: [::1]:5000
        if endpoint.hasPrefix("[") {
            guard let closeBracket = endpoint.firstIndex(of: "]"),
                  endpoint[endpoint.index(after: closeBracket)] == ":",
                  let port = Int(endpoint[endpoint.index(after: endpoint.index(after: closeBracket))...]) else {
                throw UDPSocketError.invalidEndpoint(endpoint)
            }
            let host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<closeBracket])
            return try SocketAddress(ipAddress: host, port: port)
        }

        // Standard host:port format
        let parts = endpoint.split(separator: ":")
        guard parts.count >= 2,
              let port = Int(parts.last!) else {
            throw UDPSocketError.invalidEndpoint(endpoint)
        }

        // For IPv6 without brackets (multiple colons), rejoin all but last part
        let host: String
        if parts.count > 2 {
            // This looks like IPv6 - everything except the last part is the address
            host = parts.dropLast().joined(separator: ":")
        } else {
            host = String(parts[0])
        }

        // Check if this is already an IP address - if so, create address directly
        // without DNS resolution (avoids DNS64 synthesizing addresses on NAT64 networks)
        if isIPv4Address(host) || isIPv6Address(host) {
            return try SocketAddress(ipAddress: host, port: port)
        }

        // For hostnames, use DNS resolution
        return try SocketAddress.makeAddressResolvingHost(host, port: port)
    }

    /// Check if a string is a valid IPv4 address
    private func isIPv4Address(_ string: String) -> Bool {
        var addr = in_addr()
        return inet_pton(AF_INET, string, &addr) == 1
    }

    /// Check if a string is a valid IPv6 address
    private func isIPv6Address(_ string: String) -> Bool {
        var addr = in6_addr()
        return inet_pton(AF_INET6, string, &addr) == 1
    }

    /// Get the port we're bound to
    public var port: Int? {
        localAddress?.port
    }
}

/// Errors from UDPSocket
public enum UDPSocketError: Error, CustomStringConvertible {
    case alreadyRunning
    case notRunning
    case invalidEndpoint(String)
    case sendFailed(destination: String, byteCount: Int, underlying: Error)
    case addressMismatch(String)

    public var description: String {
        switch self {
        case .alreadyRunning:
            return "UDP socket is already running"
        case .notRunning:
            return "UDP socket is not running"
        case .invalidEndpoint(let endpoint):
            return "Invalid endpoint: \(endpoint)"
        case .sendFailed(let destination, let byteCount, let underlying):
            return "Send failed to \(destination) (\(byteCount) bytes): \(underlying)"
        case .addressMismatch(let reason):
            return "Address mismatch: \(reason)"
        }
    }
}

/// NIO channel handler for incoming UDP datagrams
private final class UDPInboundHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let socket: UDPSocket

    init(socket: UDPSocket) {
        self.socket = socket
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        var buffer = envelope.data

        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            print("[UDP] channelRead: Failed to read bytes from buffer")
            return
        }

        let data = Data(bytes)
        let address = envelope.remoteAddress

        print("[UDP] channelRead: Received \(data.count) bytes from \(address)")

        // Handle on a Task to allow async processing
        Task {
            await socket.handleIncoming(data: data, from: address)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Log but don't close - UDP is connectionless
        print("UDP error: \(error)")
    }
}
