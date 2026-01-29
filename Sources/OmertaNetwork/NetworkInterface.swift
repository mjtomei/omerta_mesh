// NetworkInterface.swift - Protocol abstracting TUN vs userspace packet I/O
//
// This abstraction allows the rest of the system to work identically whether
// using a kernel TUN interface or a userspace network stack (gVisor netstack).

import Foundation

/// Errors from network interface operations
public enum InterfaceError: Error, Sendable {
    case closed
    case notStarted
    case alreadyStarted
    case readFailed(String)
    case writeFailed(String)
    case dialFailed(String)
    case notSupported
    case preflightFailed(String)
}

/// A TCP connection abstraction
public protocol TCPConnection: Sendable {
    var remoteHost: String { get }
    var remotePort: UInt16 { get }

    /// Read data from the connection
    func read() async throws -> Data

    /// Write data to the connection
    func write(_ data: Data) async throws

    /// Close the connection
    func close() async
}

/// Protocol abstracting network interface for packet I/O
///
/// Two implementations exist:
/// - TUNInterface: Kernel mode using /dev/net/tun (requires root)
/// - NetstackInterface: Userspace mode using gVisor netstack
public protocol NetworkInterface: Sendable {
    /// The local IP address assigned to this interface
    var localIP: String { get async }

    /// Read a packet from the interface (outbound from apps)
    /// For TUN: packets written by apps via kernel
    /// For netstack: packets from the userspace TCP/IP stack
    func readPacket() async throws -> Data

    /// Write a packet to the interface (inbound to apps)
    /// For TUN: packets delivered to apps via kernel
    /// For netstack: packets injected into the userspace stack
    func writePacket(_ packet: Data) async throws

    /// Dial a TCP connection through this interface
    /// - Parameters:
    ///   - host: The destination host (IP or hostname)
    ///   - port: The destination port
    /// - Returns: A TCP connection, or nil if not supported (TUN mode)
    ///
    /// TUN mode returns nil because apps use standard sockets directly.
    /// Netstack mode creates a connection through the userspace stack.
    func dialTCP(host: String, port: UInt16) async throws -> TCPConnection?

    /// Start the interface
    func start() async throws

    /// Stop the interface and release resources
    func stop() async
}

/// Configuration for network interfaces
public struct NetworkInterfaceConfig: Sendable {
    /// The IP address to assign to the interface
    public let localIP: String

    /// The subnet mask
    public let netmask: String

    /// Maximum transmission unit (bytes)
    public let mtu: Int

    /// Interface name (for TUN mode)
    public let interfaceName: String

    public init(
        localIP: String,
        netmask: String = "255.255.0.0",
        mtu: Int = 1400,
        interfaceName: String = "omerta0"
    ) {
        self.localIP = localIP
        self.netmask = netmask
        self.mtu = mtu
        self.interfaceName = interfaceName
    }
}
