// NetstackBridge.swift - Swift wrapper for Go netstack
//
// This provides a Swift-friendly interface to the Go netstack library,
// which is compiled as a C archive (libnetstack.a).

import Foundation
import CNetstack
import Logging

/// Errors from netstack operations
public enum NetstackError: Error, LocalizedError {
    case initializationFailed
    case notStarted
    case injectionFailed
    case invalidPacket

    public var errorDescription: String? {
        switch self {
        case .initializationFailed:
            return "Failed to initialize netstack"
        case .notStarted:
            return "Netstack not started"
        case .injectionFailed:
            return "Failed to inject packet"
        case .invalidPacket:
            return "Invalid packet data"
        }
    }
}

/// Statistics from netstack
public struct NetstackStats: Sendable {
    public let tcpConnections: UInt32
    public let udpConnections: UInt32
}

/// A TCP connection through netstack
public final class NetstackTCPConnection: @unchecked Sendable {
    private var handle: UInt64
    private let lock = NSLock()
    private var isClosed = false
    private let logger = Logger(label: "io.omerta.tunnel.netstack.tcp")

    init(handle: UInt64) {
        self.handle = handle
    }

    deinit {
        close()
    }

    /// Read data from the connection
    /// Returns the data read, or nil on EOF/error
    public func read(maxLength: Int = 4096) throws -> Data? {
        lock.lock()
        let h = handle
        let closed = isClosed
        lock.unlock()

        guard !closed, h != 0 else {
            throw NetstackError.notStarted
        }

        var buffer = [UInt8](repeating: 0, count: maxLength)
        let result = NetstackConnRead(h, &buffer, maxLength)

        if result < 0 {
            return nil  // Error or EOF
        }

        if result == 0 {
            return Data()  // No data available
        }

        return Data(buffer.prefix(Int(result)))
    }

    /// Write data to the connection
    /// Returns the number of bytes written
    @discardableResult
    public func write(_ data: Data) throws -> Int {
        lock.lock()
        let h = handle
        let closed = isClosed
        lock.unlock()

        guard !closed, h != 0 else {
            throw NetstackError.notStarted
        }

        let result = data.withUnsafeBytes { buffer -> Int32 in
            guard let baseAddress = buffer.baseAddress else { return -1 }
            let mutablePtr = UnsafeMutablePointer(mutating: baseAddress.assumingMemoryBound(to: UInt8.self))
            return NetstackConnWrite(h, mutablePtr, buffer.count)
        }

        if result < 0 {
            throw NetstackError.injectionFailed
        }

        return Int(result)
    }

    /// Set read deadline in milliseconds from now. Use 0 to clear.
    public func setReadDeadline(milliseconds: Int64) {
        lock.lock()
        let h = handle
        lock.unlock()

        guard h != 0 else { return }
        _ = NetstackConnSetReadDeadline(h, milliseconds)
    }

    /// Set write deadline in milliseconds from now. Use 0 to clear.
    public func setWriteDeadline(milliseconds: Int64) {
        lock.lock()
        let h = handle
        lock.unlock()

        guard h != 0 else { return }
        _ = NetstackConnSetWriteDeadline(h, milliseconds)
    }

    /// Close the connection
    public func close() {
        lock.lock()
        let h = handle
        let alreadyClosed = isClosed
        isClosed = true
        handle = 0
        lock.unlock()

        guard !alreadyClosed, h != 0 else { return }
        NetstackConnClose(h)
        logger.debug("TCP connection closed", metadata: ["handle": "\(h)"])
    }
}

/// Swift wrapper for the Go netstack userspace TCP/IP stack
public final class NetstackBridge: @unchecked Sendable {
    /// Handle to the Go netstack instance
    private var handle: UInt64 = 0

    /// Whether the stack is running
    private var isRunning: Bool = false

    /// Callback for returned packets
    private var returnCallback: ((Data) -> Void)?

    /// Lock for thread safety
    private let lock = NSLock()

    /// Logger
    private let logger = Logger(label: "io.omerta.tunnel.netstack")

    /// Configuration for the netstack
    public struct Config {
        /// Gateway IP address (the stack's address)
        public let gatewayIP: String

        /// MTU (default: 1500)
        public let mtu: UInt32

        public init(gatewayIP: String, mtu: UInt32 = 1500) {
            self.gatewayIP = gatewayIP
            self.mtu = mtu
        }
    }

    /// Initialize with configuration
    public init(config: Config) throws {
        let cGatewayIP = config.gatewayIP.withCString { strdup($0) }
        defer { free(cGatewayIP) }

        handle = NetstackCreate(cGatewayIP, config.mtu)
        if handle == 0 {
            throw NetstackError.initializationFailed
        }

        logger.info("Netstack initialized", metadata: [
            "gatewayIP": "\(config.gatewayIP)",
            "mtu": "\(config.mtu)"
        ])
    }

    deinit {
        stop()
    }

    /// Set the callback for returned packets (responses from internet)
    public func setReturnCallback(_ callback: @escaping (Data) -> Void) {
        lock.lock()
        returnCallback = callback
        lock.unlock()

        // Set up the C callback
        let context = Unmanaged.passUnretained(self).toOpaque()
        NetstackSetCallback(handle, netstackReturnPacketCallback, context)
    }

    /// Start processing packets
    public func start() throws {
        lock.lock()
        defer { lock.unlock() }

        guard !isRunning else { return }

        let result = NetstackStart(handle)
        if result != 0 {
            throw NetstackError.initializationFailed
        }

        isRunning = true
        logger.info("Netstack started")
    }

    /// Stop processing and clean up
    public func stop() {
        lock.lock()
        defer { lock.unlock() }

        guard handle != 0 else { return }

        NetstackStop(handle)
        handle = 0
        isRunning = false
        returnCallback = nil

        logger.info("Netstack stopped")
    }

    /// Inject a raw IP packet for processing
    public func injectPacket(_ packet: Data) throws {
        lock.lock()
        let running = isRunning
        let h = handle
        lock.unlock()

        guard running, h != 0 else {
            throw NetstackError.notStarted
        }

        guard !packet.isEmpty else {
            throw NetstackError.invalidPacket
        }

        let result = packet.withUnsafeBytes { buffer -> Int32 in
            guard let baseAddress = buffer.baseAddress else { return -1 }
            // Cast to mutable pointer - the C function doesn't actually modify the data
            let mutablePtr = UnsafeMutablePointer(mutating: baseAddress.assumingMemoryBound(to: UInt8.self))
            return NetstackInjectPacket(h, mutablePtr, buffer.count)
        }

        if result != 0 {
            throw NetstackError.injectionFailed
        }
    }

    /// Get current statistics
    public func getStats() -> NetstackStats? {
        lock.lock()
        let h = handle
        lock.unlock()

        guard h != 0 else { return nil }

        var tcpConns: UInt32 = 0
        var udpConns: UInt32 = 0

        let result = NetstackGetStats(h, &tcpConns, &udpConns)
        if result != 0 {
            return nil
        }

        return NetstackStats(tcpConnections: tcpConns, udpConnections: udpConns)
    }

    /// Dial a TCP connection to the specified host and port through the stack.
    /// The packets flow through the netstack and out via the return packet callback.
    public func dialTCP(host: String, port: UInt16) throws -> NetstackTCPConnection {
        lock.lock()
        let h = handle
        let running = isRunning
        lock.unlock()

        guard running, h != 0 else {
            throw NetstackError.notStarted
        }

        let cHost = host.withCString { strdup($0) }
        defer { free(cHost) }

        let connHandle = NetstackDialTCP(h, cHost, port)
        if connHandle == 0 {
            throw NetstackError.initializationFailed
        }

        logger.info("TCP connection established", metadata: [
            "host": "\(host)",
            "port": "\(port)",
            "handle": "\(connHandle)"
        ])

        return NetstackTCPConnection(handle: connHandle)
    }

    /// Called from C when a packet is returned
    fileprivate func handleReturnPacket(_ data: Data) {
        lock.lock()
        let callback = returnCallback
        lock.unlock()

        callback?(data)
    }
}

/// C callback function for returned packets
private func netstackReturnPacketCallback(
    context: UnsafeMutableRawPointer?,
    data: UnsafePointer<UInt8>?,
    length: Int
) {
    guard let context = context,
          let data = data,
          length > 0 else {
        return
    }

    let bridge = Unmanaged<NetstackBridge>.fromOpaque(context).takeUnretainedValue()
    let packetData = Data(bytes: data, count: length)
    bridge.handleReturnPacket(packetData)
}
