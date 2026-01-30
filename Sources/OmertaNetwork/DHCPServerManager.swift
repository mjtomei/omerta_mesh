// DHCPServerManager.swift - Manages the dnsmasq DHCP server process
//
// Starts dnsmasq bound to the virtual network interface and manages its lifecycle.
// Reads leases from the dnsmasq lease file for address tracking.

import Foundation
import Logging

/// Represents a DHCP lease from dnsmasq
public struct DHCPLease: Sendable, Equatable {
    /// When the lease expires
    public let expiresAt: Date

    /// MAC address of the client
    public let macAddress: String

    /// IP address assigned to the client
    public let ip: String

    /// Hostname of the client (may be "*" if unknown)
    public let hostname: String

    /// Client ID if provided
    public let clientId: String?

    public init(expiresAt: Date, macAddress: String, ip: String, hostname: String, clientId: String? = nil) {
        self.expiresAt = expiresAt
        self.macAddress = macAddress
        self.ip = ip
        self.hostname = hostname
        self.clientId = clientId
    }

    /// Check if the lease is currently valid
    public var isValid: Bool {
        expiresAt > Date()
    }
}

/// Error types for DHCP server operations
public enum DHCPServerError: Error, Sendable {
    case dnsmasqNotFound
    case configWriteFailed(String)
    case startFailed(String)
    case alreadyRunning
    case notRunning
    case leaseFileReadFailed(String)
}

/// Manages the dnsmasq DHCP server process
public actor DHCPServerManager {
    private var process: Process?
    private let config: DHCPServerConfig
    private let configFilePath: String
    private let logger: Logger

    /// Whether the server is currently running
    public var isRunning: Bool {
        process?.isRunning ?? false
    }

    /// Initialize the DHCP server manager
    /// - Parameter config: The DHCP server configuration
    public init(config: DHCPServerConfig) {
        self.config = config
        let tmpDir = ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp"
        self.configFilePath = "\(tmpDir)/omerta-dnsmasq-\(UUID().uuidString).conf"
        self.logger = Logger(label: "io.omerta.dhcp.server")
    }

    /// Initialize with a custom config file path (for testing)
    /// - Parameters:
    ///   - config: The DHCP server configuration
    ///   - configFilePath: Custom path for the config file
    public init(config: DHCPServerConfig, configFilePath: String) {
        self.config = config
        self.configFilePath = configFilePath
        self.logger = Logger(label: "io.omerta.dhcp.server")
    }

    /// Start dnsmasq bound to the network interface
    /// - Parameter interfaceName: The interface to bind to (e.g., "omerta0")
    /// - Throws: DHCPServerError if start fails
    public func start(interfaceName: String) throws {
        guard process == nil else {
            throw DHCPServerError.alreadyRunning
        }

        // Check if dnsmasq exists
        let dnsmasqPath = findDnsmasq()
        guard let dnsmasqPath else {
            throw DHCPServerError.dnsmasqNotFound
        }

        // Ensure lease directory exists
        let leaseDir = (config.leaseFilePath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: leaseDir, withIntermediateDirectories: true)

        // Write configuration file
        let confContent = config.generateDnsmasqConfig(interfaceName: interfaceName)
        do {
            try confContent.write(toFile: configFilePath, atomically: true, encoding: .utf8)
        } catch {
            throw DHCPServerError.configWriteFailed(error.localizedDescription)
        }

        logger.info("Starting dnsmasq", metadata: [
            "interface": "\(interfaceName)",
            "config": "\(configFilePath)",
            "leaseFile": "\(config.leaseFilePath)"
        ])

        // Start dnsmasq process
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: dnsmasqPath)
        proc.arguments = ["--conf-file=\(configFilePath)"]

        // Capture output for logging
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        proc.standardOutput = outputPipe
        proc.standardError = errorPipe

        do {
            try proc.run()
            process = proc

            logger.info("dnsmasq started", metadata: [
                "pid": "\(proc.processIdentifier)"
            ])
        } catch {
            throw DHCPServerError.startFailed(error.localizedDescription)
        }
    }

    /// Stop dnsmasq and clean up
    public func stop() {
        guard let proc = process else {
            return
        }

        logger.info("Stopping dnsmasq", metadata: [
            "pid": "\(proc.processIdentifier)"
        ])

        proc.terminate()
        proc.waitUntilExit()
        process = nil

        // Clean up config file
        try? FileManager.default.removeItem(atPath: configFilePath)

        logger.info("dnsmasq stopped")
    }

    /// Read current leases from dnsmasq lease file
    /// - Returns: Array of current leases
    /// - Throws: DHCPServerError if lease file cannot be read
    public func readLeases() throws -> [DHCPLease] {
        let content: String
        do {
            content = try String(contentsOfFile: config.leaseFilePath, encoding: .utf8)
        } catch {
            // File may not exist yet if no leases have been issued
            if (error as NSError).domain == NSCocoaErrorDomain &&
               (error as NSError).code == NSFileReadNoSuchFileError {
                return []
            }
            throw DHCPServerError.leaseFileReadFailed(error.localizedDescription)
        }

        return parseLeasesFile(content)
    }

    /// Read only valid (non-expired) leases
    /// - Returns: Array of valid leases
    public func readValidLeases() throws -> [DHCPLease] {
        try readLeases().filter { $0.isValid }
    }

    // MARK: - Private

    private func findDnsmasq() -> String? {
        // Common locations for dnsmasq
        let paths = [
            "/usr/sbin/dnsmasq",
            "/usr/bin/dnsmasq",
            "/usr/local/sbin/dnsmasq",
            "/usr/local/bin/dnsmasq",
            "/opt/homebrew/sbin/dnsmasq",
            "/opt/homebrew/bin/dnsmasq"
        ]

        for path in paths {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }

        return nil
    }

    /// Parse dnsmasq lease file format
    /// Format: <expiry_timestamp> <mac> <ip> <hostname> [client_id]
    private func parseLeasesFile(_ content: String) -> [DHCPLease] {
        content.split(separator: "\n").compactMap { line -> DHCPLease? in
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 4 else { return nil }

            guard let timestamp = Double(parts[0]) else { return nil }

            let clientId = parts.count >= 5 ? String(parts[4]) : nil

            return DHCPLease(
                expiresAt: Date(timeIntervalSince1970: timestamp),
                macAddress: String(parts[1]),
                ip: String(parts[2]),
                hostname: String(parts[3]),
                clientId: clientId
            )
        }
    }
}
