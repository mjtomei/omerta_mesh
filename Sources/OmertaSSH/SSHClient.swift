// SSHClient.swift - SSH client over mesh tunnel
//
// Provides SSH connectivity through the mesh tunnel.
// Phase 1: Uses system SSH with a ProxyCommand approach
// Phase 2+: Will add native SSH with Citadel

import Foundation
import OmertaTunnel
import Logging

/// Errors from SSH client operations
public enum SSHClientError: Error, LocalizedError {
    case notConnected
    case authenticationFailed
    case channelCreationFailed
    case shellCreationFailed
    case connectionClosed
    case tunnelNotActive
    case dialFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "Not connected to SSH server"
        case .authenticationFailed:
            return "SSH authentication failed"
        case .channelCreationFailed:
            return "Failed to create SSH channel"
        case .shellCreationFailed:
            return "Failed to create shell"
        case .connectionClosed:
            return "SSH connection closed"
        case .tunnelNotActive:
            return "Tunnel session is not active"
        case .dialFailed(let reason):
            return "Failed to dial: \(reason)"
        }
    }
}

/// SSH proxy that bridges stdin/stdout to a netstack TCP connection.
/// This allows the system `ssh` command to work through the mesh tunnel.
///
/// Usage: `ssh -o ProxyCommand='omerta tunnel proxy %h %p' user@vmip`
public final class SSHProxy: @unchecked Sendable {
    private let connection: NetstackTCPConnection
    private let logger = Logger(label: "io.omerta.ssh.proxy")
    private var isRunning = true

    private init(connection: NetstackTCPConnection) {
        self.connection = connection
    }

    /// Create a proxy connected to the specified host:port through netstack
    public static func connect(
        via netstack: NetstackBridge,
        host: String,
        port: UInt16
    ) throws -> SSHProxy {
        let connection = try netstack.dialTCP(host: host, port: port)
        return SSHProxy(connection: connection)
    }

    /// Run the proxy, bridging stdin/stdout to the TCP connection.
    /// This method blocks until the connection closes.
    public func run() throws {
        logger.info("SSH proxy starting")

        // Set stdin to non-blocking
        let stdinFd = FileHandle.standardInput.fileDescriptor
        let stdoutFd = FileHandle.standardOutput.fileDescriptor

        // Create tasks for bidirectional forwarding
        let readGroup = DispatchGroup()
        let writeGroup = DispatchGroup()

        // Forward stdin -> TCP connection
        readGroup.enter()
        DispatchQueue.global().async { [self] in
            defer { readGroup.leave() }

            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
            defer { buffer.deallocate() }

            while self.isRunning {
                let bytesRead = read(stdinFd, buffer, 4096)
                if bytesRead <= 0 {
                    // EOF or error
                    break
                }

                let data = Data(bytes: buffer, count: bytesRead)
                do {
                    try self.connection.write(data)
                } catch {
                    self.logger.error("Write to connection failed: \(error)")
                    break
                }
            }

            self.isRunning = false
        }

        // Forward TCP connection -> stdout
        writeGroup.enter()
        DispatchQueue.global().async { [self] in
            defer { writeGroup.leave() }

            while self.isRunning {
                do {
                    guard let data = try self.connection.read(maxLength: 4096) else {
                        // Connection closed
                        break
                    }

                    if !data.isEmpty {
                        _ = data.withUnsafeBytes { buffer in
                            write(stdoutFd, buffer.baseAddress, buffer.count)
                        }
                    }
                } catch {
                    self.logger.error("Read from connection failed: \(error)")
                    break
                }
            }

            self.isRunning = false
        }

        // Wait for either direction to finish
        readGroup.wait()
        writeGroup.wait()

        connection.close()
        logger.info("SSH proxy stopped")
    }

    /// Stop the proxy
    public func stop() {
        isRunning = false
        connection.close()
    }
}

/// SSH client that uses the system ssh command with ProxyCommand
public struct SSHLauncher {
    private let logger = Logger(label: "io.omerta.ssh.launcher")

    public init() {}

    /// Launch system SSH connecting through the mesh tunnel.
    /// This replaces the current process with ssh.
    public func exec(
        host: String,
        user: String,
        keyPath: String,
        knownHostsPath: String,
        proxyCommand: String
    ) throws -> Never {
        // Build SSH arguments
        let args = [
            "ssh",
            "-o", "ProxyCommand=\(proxyCommand)",
            "-o", "UserKnownHostsFile=\(knownHostsPath)",
            "-o", "StrictHostKeyChecking=accept-new",
            "-i", keyPath,
            "\(user)@\(host)"
        ]

        logger.info("Launching SSH", metadata: [
            "host": "\(host)",
            "user": "\(user)"
        ])

        // Convert to C strings for execvp
        let cArgs = args.map { strdup($0) } + [nil]
        execvp("/usr/bin/ssh", cArgs)

        // If we get here, exec failed
        perror("exec ssh")
        exit(1)
    }
}
