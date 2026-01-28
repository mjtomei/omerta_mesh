// ControlSocketClient.swift - Unix domain socket client for daemon IPC
//
// Provides a client for sending commands and receiving responses
// using length-prefixed JSON framing via POSIX sockets.

import Foundation
import Logging

#if canImport(Glibc)
import Glibc
private let systemClose = Glibc.close
private let systemSocket = Glibc.socket
private let systemConnect = Glibc.connect
private let systemSend = Glibc.send
private let systemRecv = Glibc.recv
private let systemSetsockopt = Glibc.setsockopt
private let SOCK_STREAM_VALUE = Int32(SOCK_STREAM.rawValue)
#elseif canImport(Darwin)
import Darwin
private let systemClose = Darwin.close
private let systemSocket = Darwin.socket
private let systemConnect = Darwin.connect
private let systemSend = Darwin.send
private let systemRecv = Darwin.recv
private let systemSetsockopt = Darwin.setsockopt
private let SOCK_STREAM_VALUE = SOCK_STREAM
#endif

// MARK: - Control Socket Client

/// Unix domain socket client for daemon control communication
public actor ControlSocketClient {
    /// Client state
    public enum State: Sendable {
        case disconnected
        case connecting
        case connected
    }

    private let socketPath: String
    private let logger: Logger
    private var state: State = .disconnected
    private var socketFd: Int32 = -1
    private let timeout: TimeInterval

    /// Create a new control socket client
    /// - Parameters:
    ///   - socketPath: Path to the Unix domain socket
    ///   - timeout: Timeout for operations in seconds (default: 30)
    public init(socketPath: String, timeout: TimeInterval = 30) {
        self.socketPath = socketPath
        self.timeout = timeout
        self.logger = Logger(label: "io.omerta.mesh.controlsocket.client")
    }

    /// Connect to the daemon socket
    public func connect() async throws {
        guard state == .disconnected else {
            if state == .connected {
                return  // Already connected
            }
            throw IPCError.socketError("Connection in progress")
        }

        state = .connecting

        // Check if socket exists
        guard DaemonSocketPaths.socketExists(socketPath) else {
            state = .disconnected
            throw IPCError.connectionFailed("Socket not found: \(socketPath)")
        }

        // Create socket
        let fd = systemSocket(AF_UNIX, SOCK_STREAM_VALUE, 0)
        guard fd >= 0 else {
            state = .disconnected
            throw IPCError.socketError("Failed to create socket: \(String(cString: strerror(errno)))")
        }

        // Set up socket address
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            systemClose(fd)
            state = .disconnected
            throw IPCError.socketError("Socket path too long")
        }

        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dest in
                pathBytes.withUnsafeBufferPointer { src in
                    _ = memcpy(dest, src.baseAddress!, pathBytes.count)
                }
            }
        }

        // Connect
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                systemConnect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard connectResult == 0 else {
            systemClose(fd)
            state = .disconnected
            throw IPCError.connectionFailed("Connect failed: \(String(cString: strerror(errno)))")
        }

        // Set socket timeout
        var tv = timeval()
        tv.tv_sec = Int(timeout)
        #if os(Linux)
        tv.tv_usec = Int((timeout.truncatingRemainder(dividingBy: 1)) * 1_000_000)
        #else
        tv.tv_usec = Int32((timeout.truncatingRemainder(dividingBy: 1)) * 1_000_000)
        #endif

        _ = systemSetsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        _ = systemSetsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        socketFd = fd
        state = .connected

        logger.debug("Connected to daemon socket", metadata: ["path": "\(socketPath)"])
    }

    /// Disconnect from the daemon socket
    public func disconnect() {
        guard state == .connected else { return }

        if socketFd >= 0 {
            systemClose(socketFd)
            socketFd = -1
        }

        state = .disconnected
        logger.debug("Disconnected from daemon socket")
    }

    /// Send a command and receive a response
    /// - Parameter command: The command to send
    /// - Returns: The response from the daemon
    public func send<Command: Encodable, Response: Decodable>(
        _ command: Command
    ) async throws -> Response {
        // Auto-connect if not connected
        if state != .connected {
            try await connect()
        }

        guard state == .connected, socketFd >= 0 else {
            throw IPCError.connectionFailed("Not connected")
        }

        // Encode command
        let requestData = try IPCMessage.encode(command)

        // Send request
        let sentBytes = requestData.withUnsafeBytes { ptr in
            systemSend(socketFd, ptr.baseAddress, ptr.count, 0)
        }

        guard sentBytes == requestData.count else {
            disconnect()
            throw IPCError.socketError("Send failed: \(String(cString: strerror(errno)))")
        }

        // Receive response length
        var lengthBuffer = [UInt8](repeating: 0, count: 4)
        var totalReceived = 0

        while totalReceived < 4 {
            let received = systemRecv(socketFd, &lengthBuffer[totalReceived], 4 - totalReceived, 0)
            if received <= 0 {
                disconnect()
                if received == 0 {
                    throw IPCError.connectionClosed
                }
                throw IPCError.socketError("Receive failed: \(String(cString: strerror(errno)))")
            }
            totalReceived += received
        }

        // Construct UInt32 from bytes manually to avoid alignment issues on Linux
        let length = UInt32(lengthBuffer[0]) << 24 |
                     UInt32(lengthBuffer[1]) << 16 |
                     UInt32(lengthBuffer[2]) << 8 |
                     UInt32(lengthBuffer[3])

        guard length <= IPCMessage.maxMessageSize else {
            disconnect()
            throw IPCError.messageTooLarge(Int(length))
        }

        // Receive response payload
        var payloadBuffer = [UInt8](repeating: 0, count: Int(length))
        totalReceived = 0

        while totalReceived < Int(length) {
            let received = systemRecv(socketFd, &payloadBuffer[totalReceived], Int(length) - totalReceived, 0)
            if received <= 0 {
                disconnect()
                if received == 0 {
                    throw IPCError.connectionClosed
                }
                throw IPCError.socketError("Receive failed: \(String(cString: strerror(errno)))")
            }
            totalReceived += received
        }

        // Decode response
        let responseData = Data(payloadBuffer)
        do {
            return try IPCMessage.decode(Response.self, from: responseData)
        } catch {
            throw IPCError.decodingFailed("Failed to decode response: \(error)")
        }
    }

    /// Current client state
    public var currentState: State {
        state
    }

    /// Whether the client is connected
    public var isConnected: Bool {
        state == .connected && socketFd >= 0
    }

    deinit {
        if socketFd >= 0 {
            systemClose(socketFd)
        }
    }
}

// MARK: - Convenience Factory

extension ControlSocketClient {
    /// Create a client for the mesh daemon
    /// - Parameter networkId: The network ID
    /// - Returns: A client configured for the mesh daemon
    public static func meshDaemon(networkId: String, timeout: TimeInterval = 30) -> ControlSocketClient {
        ControlSocketClient(
            socketPath: DaemonSocketPaths.meshDaemonControl(networkId: networkId),
            timeout: timeout
        )
    }

    /// Create a client for the VM daemon
    /// - Parameter networkId: The network ID
    /// - Returns: A client configured for the VM daemon
    public static func vmDaemon(networkId: String, timeout: TimeInterval = 30) -> ControlSocketClient {
        ControlSocketClient(
            socketPath: DaemonSocketPaths.vmDaemonControl(networkId: networkId),
            timeout: timeout
        )
    }
}

// MARK: - One-shot Request

extension ControlSocketClient {
    /// Send a command and receive a response, then disconnect
    /// - Parameter command: The command to send
    /// - Returns: The response from the daemon
    public func request<Command: Encodable, Response: Decodable>(
        _ command: Command
    ) async throws -> Response {
        defer { disconnect() }
        return try await send(command)
    }
}
