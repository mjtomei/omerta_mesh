// NetstackInterface.swift - Userspace network stack interface
//
// Uses a network stack (like gVisor's netstack) to provide packet I/O
// without requiring root privileges or a TUN device.
//
// Note: The actual NetstackBridge implementation will be provided separately
// and may use gVisor netstack, lwIP, or another userspace TCP/IP stack.

import Foundation

/// Configuration for the netstack bridge
public struct NetstackBridgeConfig: Sendable {
    /// The gateway IP address for the netstack
    public let gatewayIP: String

    /// Maximum transmission unit
    public let mtu: Int

    public init(gatewayIP: String, mtu: Int = 1400) {
        self.gatewayIP = gatewayIP
        self.mtu = mtu
    }
}

/// Protocol for netstack bridge implementations
/// This allows plugging in different userspace TCP/IP stacks
public protocol NetstackBridgeProtocol: Sendable {
    /// Start the network stack
    func start() async throws

    /// Stop the network stack
    func stop() async

    /// Inject a packet into the stack (inbound)
    func injectPacket(_ packet: Data) async throws

    /// Set callback for outbound packets
    func setReturnCallback(_ callback: @escaping @Sendable (Data) -> Void) async

    /// Dial a TCP connection through the stack
    func dialTCP(host: String, port: UInt16) async throws -> TCPConnection
}

/// Userspace network interface using a netstack bridge
public actor NetstackInterface: NetworkInterface {
    public let localIP: String
    private let bridge: any NetstackBridgeProtocol
    private var outboundStream: AsyncStream<Data>!
    private var outboundContinuation: AsyncStream<Data>.Continuation!
    private var isRunning = false

    /// Initialize with a netstack bridge
    /// - Parameters:
    ///   - localIP: The local IP address for this interface
    ///   - bridge: The netstack bridge implementation
    public init(localIP: String, bridge: any NetstackBridgeProtocol) {
        self.localIP = localIP
        self.bridge = bridge

        let (stream, continuation) = AsyncStream<Data>.makeStream()
        self.outboundStream = stream
        self.outboundContinuation = continuation
    }

    public func start() async throws {
        guard !isRunning else {
            throw InterfaceError.alreadyStarted
        }

        // Capture the continuation for the callback
        let continuation = self.outboundContinuation!

        // Wire netstack outbound packets to our stream
        await bridge.setReturnCallback { packet in
            continuation.yield(packet)
        }

        try await bridge.start()
        isRunning = true
    }

    public func stop() async {
        guard isRunning else { return }
        isRunning = false
        await bridge.stop()
        outboundContinuation.finish()
    }

    public func readPacket() async throws -> Data {
        guard isRunning else {
            throw InterfaceError.notStarted
        }

        for await packet in outboundStream {
            return packet
        }
        throw InterfaceError.closed
    }

    public func writePacket(_ packet: Data) async throws {
        guard isRunning else {
            throw InterfaceError.notStarted
        }
        try await bridge.injectPacket(packet)
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        guard isRunning else {
            throw InterfaceError.notStarted
        }
        return try await bridge.dialTCP(host: host, port: port)
    }
}

/// A stub netstack bridge for testing without a real implementation
/// This can be replaced with a real gVisor/lwIP bridge later
public actor StubNetstackBridge: NetstackBridgeProtocol {
    private var returnCallback: (@Sendable (Data) -> Void)?
    private var injectedPackets: [Data] = []
    private var isRunning = false

    public init() {}

    public func start() async throws {
        isRunning = true
    }

    public func stop() async {
        isRunning = false
    }

    public func injectPacket(_ packet: Data) async throws {
        guard isRunning else {
            throw InterfaceError.notStarted
        }
        injectedPackets.append(packet)
    }

    public func setReturnCallback(_ callback: @escaping @Sendable (Data) -> Void) async {
        returnCallback = callback
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection {
        throw InterfaceError.notSupported
    }

    // Test helpers
    public func getInjectedPackets() -> [Data] {
        let packets = injectedPackets
        injectedPackets = []
        return packets
    }

    public func simulateOutbound(_ packet: Data) {
        returnCallback?(packet)
    }
}
