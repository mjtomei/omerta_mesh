// TUNInterface.swift - Linux TUN device implementation of NetworkInterface
//
// Uses DispatchSource for event-driven I/O: the TUN fd is set non-blocking and
// a DispatchSource fires when readable. Supports two delivery paths:
//   - Pull: AsyncStream for readPacket() (node mode)
//   - Push: direct onPacket callback (bridge mode via TUNBridgeAdapter)

#if os(Linux)
import Foundation
import Glibc
import Logging

// Linux TUN constants not exposed by Glibc module
private let TUNSETIFF: UInt = 0x400454ca
private let IFF_TUN: Int16 = 0x0001
private let IFF_NO_PI: Int16 = 0x1000

public actor TUNInterface: NetworkInterface {
    public let localIP: String
    private let name: String
    private let subnetBits: Int
    private let mtu: Int
    private var fd: Int32 = -1
    private var started = false

    // Event-driven read via DispatchSource
    private var readSource: DispatchSourceRead?
    private let readQueue = DispatchQueue(label: "omerta.tun.read")

    // Push path: direct callback for bridge mode.
    // Uses a class box so the DispatchSource closure can read the latest value
    // without re-capturing (callback may be set after start()).
    private let callbackBox = CallbackBox()

    private final class CallbackBox: @unchecked Sendable {
        var onPacket: (@Sendable (Data) -> Void)?
    }

    // Pull path: AsyncStream for readPacket() in node mode
    private var packetStream: AsyncStream<Data>?
    private var streamContinuation: AsyncStream<Data>.Continuation?

    private let logger = Logger(label: "io.omerta.network.tun")

    public init(name: String, ip: String, subnetBits: Int = 16, mtu: Int = 1400) {
        self.name = name
        self.localIP = ip
        self.subnetBits = subnetBits
        self.mtu = mtu
    }

    public func start() async throws {
        guard !started else { throw InterfaceError.alreadyStarted }

        fd = open("/dev/net/tun", O_RDWR)
        guard fd >= 0 else {
            throw InterfaceError.readFailed("Failed to open /dev/net/tun: errno \(errno)")
        }

        // Configure TUN device
        var ifr = ifreq()
        withUnsafeMutableBytes(of: &ifr.ifr_ifrn.ifrn_name) { ptr in
            _ = name.utf8CString.withUnsafeBufferPointer { src in
                let count = min(ptr.count - 1, src.count)
                memcpy(ptr.baseAddress!, src.baseAddress!, count)
            }
        }

        withUnsafeMutableBytes(of: &ifr.ifr_ifru) { ptr in
            ptr.storeBytes(of: IFF_TUN | IFF_NO_PI, toByteOffset: 0, as: Int16.self)
        }

        guard Glibc.ioctl(fd, TUNSETIFF, &ifr) >= 0 else {
            let err = errno
            Glibc.close(fd)
            fd = -1
            throw InterfaceError.readFailed("ioctl TUNSETIFF failed: errno \(err)")
        }

        // Configure IP address and bring interface up
        try configureIP()

        // Set non-blocking
        let flags = fcntl(fd, F_GETFL)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        // Set up AsyncStream for pull-based readPacket()
        let (stream, continuation) = AsyncStream<Data>.makeStream()
        self.packetStream = stream
        self.streamContinuation = continuation

        let tunFd = fd
        let bufSize = mtu + 64 // headroom
        let box = callbackBox
        let cont = continuation

        let source = DispatchSource.makeReadSource(fileDescriptor: tunFd, queue: readQueue)
        source.setEventHandler {
            var buf = [UInt8](repeating: 0, count: bufSize)
            while true {
                let n = Glibc.read(tunFd, &buf, buf.count)
                guard n > 0 else { break }
                let packet = Data(buf[..<n])
                if let cb = box.onPacket {
                    cb(packet)
                } else {
                    cont.yield(packet)
                }
            }
        }
        source.resume()
        self.readSource = source
        started = true

        logger.info("TUN interface started", metadata: [
            "name": "\(name)", "ip": "\(localIP)/\(subnetBits)", "fd": "\(fd)"
        ])
    }

    public func stop() async {
        guard started else { return }

        readSource?.cancel()
        readSource = nil
        streamContinuation?.finish()
        streamContinuation = nil
        packetStream = nil

        if fd >= 0 {
            Glibc.close(fd)
            fd = -1
        }

        // Try to delete the interface
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/ip")
        proc.arguments = ["link", "delete", name]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()

        started = false
        logger.info("TUN interface stopped", metadata: ["name": "\(name)"])
    }

    public func readPacket() async throws -> Data {
        guard started, let stream = packetStream else {
            throw InterfaceError.notStarted
        }
        for await packet in stream {
            return packet
        }
        throw InterfaceError.closed
    }

    public func writePacket(_ packet: Data) async throws {
        guard started, fd >= 0 else { throw InterfaceError.notStarted }
        try packet.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { throw InterfaceError.writeFailed("empty") }
            let n = Glibc.write(fd, base, packet.count)
            guard n == packet.count else {
                throw InterfaceError.writeFailed("write returned \(n), errno \(errno)")
            }
        }
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        nil // TUN mode — apps use kernel sockets directly
    }

    /// Set a direct packet callback for bridge mode.
    /// When set, packets go to this callback instead of the AsyncStream.
    /// Must be called before start().
    public func setPacketCallback(_ callback: @escaping @Sendable (Data) -> Void) {
        callbackBox.onPacket = callback
    }

    private func configureIP() throws {
        func run(_ args: [String]) throws {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/sbin/ip")
            proc.arguments = args
            let errPipe = Pipe()
            proc.standardError = errPipe
            proc.standardOutput = FileHandle.nullDevice
            try proc.run()
            proc.waitUntilExit()
            guard proc.terminationStatus == 0 else {
                let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                let errStr = String(data: errData, encoding: .utf8) ?? ""
                throw InterfaceError.readFailed("ip command failed: \(errStr)")
            }
        }

        try run(["addr", "add", "\(localIP)/\(subnetBits)", "dev", name])
        try run(["link", "set", name, "up"])
        try run(["link", "set", name, "mtu", "\(mtu)"])
    }
}
#endif
