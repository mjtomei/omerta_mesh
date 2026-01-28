// DataSocketClient.swift - High-performance binary socket client for tunnel packets
//
// Uses minimal framing for low-latency packet forwarding:
// Frame: [tunnelId (16 bytes UUID)] [length (2 bytes BE)] [packet data]

import Foundation
import Logging

#if canImport(Glibc)
import Glibc
private let systemClose = Glibc.close
private let systemSocket = Glibc.socket
private let systemConnect = Glibc.connect
private let systemSend = Glibc.send
private let systemRecv = Glibc.recv
private let SOCK_STREAM_VALUE = Int32(SOCK_STREAM.rawValue)
#elseif canImport(Darwin)
import Darwin
private let systemClose = Darwin.close
private let systemSocket = Darwin.socket
private let systemConnect = Darwin.connect
private let systemSend = Darwin.send
private let systemRecv = Darwin.recv
private let SOCK_STREAM_VALUE = SOCK_STREAM
#endif

// MARK: - Data Socket Client

/// Unix domain socket client for high-performance tunnel packet forwarding
public actor DataSocketClient {
    /// Client state
    public enum State: Sendable {
        case disconnected
        case connecting
        case connected
    }

    /// Handler for incoming tunnel packets
    public typealias PacketHandler = @Sendable (UUID, Data) async -> Void

    private let socketPath: String
    private let logger: Logger
    private var state: State = .disconnected
    private var socketFd: Int32 = -1
    private var packetHandler: PacketHandler?
    private var receiveTask: Task<Void, Never>?

    /// Create a new data socket client
    /// - Parameter socketPath: Path to the Unix domain socket
    public init(socketPath: String) {
        self.socketPath = socketPath
        self.logger = Logger(label: "io.omerta.mesh.datasocket.client")
    }

    /// Connect to the data socket
    /// - Parameter handler: Handler for incoming packets
    public func connect(handler: @escaping PacketHandler) async throws {
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

        socketFd = fd
        packetHandler = handler
        state = .connected

        // Start receive loop
        startReceiveLoop()

        logger.debug("Connected to data socket", metadata: ["path": "\(socketPath)"])
    }

    /// Disconnect from the data socket
    public func disconnect() {
        guard state == .connected else { return }

        // Cancel receive task
        receiveTask?.cancel()
        receiveTask = nil

        if socketFd >= 0 {
            systemClose(socketFd)
            socketFd = -1
        }

        packetHandler = nil
        state = .disconnected
        logger.debug("Disconnected from data socket")
    }

    /// Send a tunnel packet
    /// - Parameters:
    ///   - tunnelId: The tunnel UUID
    ///   - packet: The packet data
    public func sendPacket(tunnelId: UUID, packet: Data) async throws {
        guard state == .connected, socketFd >= 0 else {
            throw IPCError.connectionFailed("Not connected")
        }

        guard packet.count <= DataSocketServer.maxPacketSize else {
            throw IPCError.messageTooLarge(packet.count)
        }

        // Build frame: [tunnelId (16)] [length (2)] [data]
        var frame = Data(capacity: 18 + packet.count)

        // Add tunnel ID (16 bytes)
        let uuidBytes = withUnsafeBytes(of: tunnelId.uuid) { Data($0) }
        frame.append(uuidBytes)

        // Add length (2 bytes, big-endian)
        var length = UInt16(packet.count).bigEndian
        frame.append(Data(bytes: &length, count: 2))

        // Add packet data
        frame.append(packet)

        // Send frame
        let sentBytes = frame.withUnsafeBytes { ptr in
            systemSend(socketFd, ptr.baseAddress, ptr.count, 0)
        }

        guard sentBytes == frame.count else {
            throw IPCError.socketError("Send failed: \(String(cString: strerror(errno)))")
        }
    }

    // MARK: - Receive Loop

    private func startReceiveLoop() {
        let fd = socketFd
        let handler = packetHandler

        receiveTask = Task { [weak self] in
            var headerBuffer = [UInt8](repeating: 0, count: 18)

            while !Task.isCancelled {
                guard let self = self else { break }

                // Read header (18 bytes: 16 UUID + 2 length)
                var headerReceived = 0
                while headerReceived < 18 {
                    let received = systemRecv(fd, &headerBuffer[headerReceived], 18 - headerReceived, 0)
                    if received <= 0 {
                        if received == 0 || errno == EINTR {
                            continue
                        }
                        await self.handleReceiveError()
                        return
                    }
                    headerReceived += received
                }

                // Parse tunnel ID
                let uuidData = Data(headerBuffer[0..<16])
                let tunnelId = uuidData.withUnsafeBytes { ptr -> UUID in
                    ptr.baseAddress!.assumingMemoryBound(to: uuid_t.self).withMemoryRebound(to: uuid_t.self, capacity: 1) { uuidPtr in
                        UUID(uuid: uuidPtr.pointee)
                    }
                }

                // Parse length - construct UInt16 manually to avoid alignment issues on Linux
                let length = Int(UInt16(headerBuffer[16]) << 8 | UInt16(headerBuffer[17]))

                guard length <= DataSocketServer.maxPacketSize else {
                    await self.handleReceiveError()
                    return
                }

                // Read packet data
                var packetBuffer = [UInt8](repeating: 0, count: length)
                var packetReceived = 0
                while packetReceived < length {
                    let received = systemRecv(fd, &packetBuffer[packetReceived], length - packetReceived, 0)
                    if received <= 0 {
                        if received == 0 || errno == EINTR {
                            continue
                        }
                        await self.handleReceiveError()
                        return
                    }
                    packetReceived += received
                }

                let packetData = Data(packetBuffer)

                // Call handler
                if let handler = handler {
                    await handler(tunnelId, packetData)
                }
            }
        }
    }

    private func handleReceiveError() {
        logger.warning("Receive error, disconnecting")
        if socketFd >= 0 {
            systemClose(socketFd)
            socketFd = -1
        }
        packetHandler = nil
        state = .disconnected
    }

    /// Set packet handler (can be changed after connection)
    public func setPacketHandler(_ handler: @escaping PacketHandler) {
        packetHandler = handler
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
        receiveTask?.cancel()
        if socketFd >= 0 {
            systemClose(socketFd)
        }
    }
}

// MARK: - Convenience Factory

extension DataSocketClient {
    /// Create a client for the mesh daemon data socket
    /// - Parameter networkId: The network ID
    /// - Returns: A client configured for the mesh daemon data socket
    public static func meshDaemon(networkId: String) -> DataSocketClient {
        DataSocketClient(socketPath: DaemonSocketPaths.meshDaemonData(networkId: networkId))
    }
}
