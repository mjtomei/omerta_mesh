// main.swift - Entry point for omerta-meshd daemon
//
// Usage:
//   omerta-meshd start <network-id> [options]
//   omerta-meshd stop <network-id>
//   omerta-meshd status <network-id>
//   omerta-meshd config

import Foundation
import ArgumentParser
import OmertaMesh
import Logging

// MARK: - Main Command

@main
struct MeshDaemonCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "omerta-meshd",
        abstract: "Mesh network daemon",
        discussion: """
            The omerta-meshd daemon manages mesh network connections and exposes them via IPC.

            Other applications (like omertad) communicate with meshd through Unix domain
            sockets to access mesh network functionality.

            Socket paths:
              Control: /tmp/omerta-meshd-{network-id}.sock
              Data:    /tmp/omerta-meshd-{network-id}.data.sock
            """,
        subcommands: [Start.self, Stop.self, Status.self, Config.self],
        defaultSubcommand: nil
    )
}

// MARK: - Start Command

struct Start: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "start",
        abstract: "Start the mesh daemon"
    )

    @Argument(help: "Network ID to connect to")
    var networkId: String

    @Option(name: .shortAndLong, help: "Port to bind (0 = auto)")
    var port: Int = 0

    @Option(name: .long, help: "Bootstrap peer (format: peerId@host:port)")
    var bootstrap: [String] = []

    @Flag(name: .long, help: "Act as a relay node")
    var relay: Bool = false

    @Flag(name: .long, help: "Run in foreground (don't daemonize)")
    var foreground: Bool = false

    @Option(name: .shortAndLong, help: "Log level (trace, debug, info, warning, error)")
    var logLevel: String = "info"

    @Option(name: .long, help: "Path to identity file")
    var identity: String?

    @Option(name: .long, help: "Configuration file path")
    var config: String?

    @Flag(name: .long, help: "LAN mode - bind to IPv4 for cross-machine LAN testing")
    var lan: Bool = false

    mutating func run() async throws {
        // Configure logging
        let level = parseLogLevel(logLevel)
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = level
            return handler
        }

        let logger = Logger(label: "io.omerta.meshd.cli")

        // Load base config from file if provided
        var daemonConfig: MeshDaemonConfig
        if let configPath = config {
            daemonConfig = try MeshDaemonConfig.load(from: configPath)
        } else {
            daemonConfig = MeshDaemonConfig.loadDefault()
        }

        // Override with command-line arguments
        daemonConfig.networkId = networkId
        if port != 0 {
            daemonConfig.port = port
        }
        if !bootstrap.isEmpty {
            daemonConfig.bootstrapPeers = bootstrap
        }
        if relay {
            daemonConfig.canRelay = true
            daemonConfig.canCoordinateHolePunch = true
        }
        daemonConfig.foreground = foreground
        daemonConfig.logLevel = logLevel
        if let identityPath = identity {
            daemonConfig.identityPath = identityPath
        }
        if lan {
            daemonConfig.lanMode = true
        }

        // Check if already running
        let controlPath = DaemonSocketPaths.meshDaemonControl(networkId: networkId)
        if DaemonSocketPaths.socketExists(controlPath) {
            print("Error: Daemon appears to be already running (socket exists: \(controlPath))")
            print("Use 'omerta-meshd stop \(networkId)' to stop it first.")
            throw ExitCode.failure
        }

        print("Starting omerta-meshd for network: \(networkId)")
        print("  Port: \(daemonConfig.port == 0 ? "auto" : String(daemonConfig.port))")
        print("  Relay: \(daemonConfig.canRelay)")
        print("  LAN mode: \(daemonConfig.lanMode)")
        print("  Foreground: \(foreground)")
        if !daemonConfig.bootstrapPeers.isEmpty {
            print("  Bootstrap peers: \(daemonConfig.bootstrapPeers.count)")
        }
        print("")

        // Create and start daemon
        let daemon = MeshDaemon(config: daemonConfig)

        do {
            try await daemon.start()
            print("Daemon started successfully")
            print("Control socket: \(controlPath)")

            // Wait for shutdown signal
            await waitForShutdown()

            print("\nShutting down...")
            await daemon.stop()
            print("Daemon stopped")

        } catch {
            logger.error("Failed to start daemon: \(error)")
            print("Error: \(error)")
            throw ExitCode.failure
        }
    }

    private func parseLogLevel(_ level: String) -> Logger.Level {
        switch level.lowercased() {
        case "trace": return .trace
        case "debug": return .debug
        case "info": return .info
        case "warning", "warn": return .warning
        case "error": return .error
        case "critical": return .critical
        default: return .info
        }
    }

    private func waitForShutdown() async {
        let signalSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        signal(SIGINT, SIG_IGN)

        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        signal(SIGTERM, SIG_IGN)

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            signalSource.setEventHandler {
                signalSource.cancel()
                termSource.cancel()
                continuation.resume()
            }
            termSource.setEventHandler {
                signalSource.cancel()
                termSource.cancel()
                continuation.resume()
            }
            signalSource.resume()
            termSource.resume()
        }
    }
}

// MARK: - Stop Command

struct Stop: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "stop",
        abstract: "Stop the mesh daemon"
    )

    @Argument(help: "Network ID of the daemon to stop")
    var networkId: String

    @Flag(name: .long, help: "Force immediate shutdown")
    var force: Bool = false

    @Option(name: .long, help: "Graceful shutdown timeout in seconds")
    var timeout: Int = 5

    mutating func run() async throws {
        let controlPath = DaemonSocketPaths.meshDaemonControl(networkId: networkId)

        guard DaemonSocketPaths.socketExists(controlPath) else {
            print("Daemon is not running (socket not found: \(controlPath))")
            return
        }

        print("Stopping omerta-meshd for network: \(networkId)...")

        let client = ControlSocketClient(socketPath: controlPath)

        do {
            try await client.connect()

            let command = MeshDaemonCommand.base(.shutdown(graceful: !force, timeoutSeconds: timeout))
            let response: MeshDaemonResponse = try await client.send(command)

            switch response {
            case .base(.shutdownAck(let ack)):
                if ack.accepted {
                    print("Shutdown accepted")
                    if let seconds = ack.estimatedSeconds {
                        print("Estimated time: \(seconds) seconds")
                    }
                } else {
                    print("Shutdown rejected: \(ack.reason ?? "unknown")")
                }

            case .error(let message):
                print("Error: \(message)")

            default:
                print("Unexpected response")
            }

            await client.disconnect()

        } catch {
            print("Failed to connect to daemon: \(error)")
            print("You may need to manually remove the socket: \(controlPath)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Status Command

struct Status: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Get daemon status"
    )

    @Argument(help: "Network ID of the daemon to check")
    var networkId: String

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        let controlPath = DaemonSocketPaths.meshDaemonControl(networkId: networkId)

        guard DaemonSocketPaths.socketExists(controlPath) else {
            if json {
                print("{\"running\": false, \"networkId\": \"\(networkId)\"}")
            } else {
                print("Daemon is not running (socket not found)")
            }
            return
        }

        let client = ControlSocketClient(socketPath: controlPath)

        do {
            try await client.connect()

            let command = MeshDaemonCommand.base(.status)
            let response: MeshDaemonResponse = try await client.send(command)

            switch response {
            case .base(.status(let status)):
                if json {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                    let data = try encoder.encode(status)
                    print(String(data: data, encoding: .utf8)!)
                } else {
                    print("Mesh Daemon Status")
                    print("==================")
                    print("Running:    \(status.isRunning ? "yes" : "no")")
                    print("Network:    \(status.networkId)")
                    if let uptime = status.uptime {
                        print("Uptime:     \(formatUptime(uptime))")
                    }
                    print("Protocol:   v\(status.protocolVersion)")

                    if !status.additionalInfo.isEmpty {
                        print("")
                        print("Mesh Status")
                        print("-----------")
                        for (key, value) in status.additionalInfo.sorted(by: { $0.key < $1.key }) {
                            print("\(key): \(value)")
                        }
                    }
                }

            case .error(let message):
                print("Error: \(message)")

            default:
                print("Unexpected response")
            }

            await client.disconnect()

        } catch {
            print("Failed to connect to daemon: \(error)")
            throw ExitCode.failure
        }
    }

    private func formatUptime(_ seconds: TimeInterval) -> String {
        let hours = Int(seconds) / 3600
        let minutes = (Int(seconds) % 3600) / 60
        let secs = Int(seconds) % 60

        if hours > 0 {
            return "\(hours)h \(minutes)m \(secs)s"
        } else if minutes > 0 {
            return "\(minutes)m \(secs)s"
        } else {
            return "\(secs)s"
        }
    }
}

// MARK: - Config Command

struct Config: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "config",
        abstract: "Manage daemon configuration"
    )

    @Flag(name: .long, help: "Show default configuration")
    var showDefault: Bool = false

    @Option(name: .long, help: "Generate configuration for network")
    var generate: String?

    @Option(name: .long, help: "Output path for generated config")
    var output: String?

    mutating func run() throws {
        if showDefault {
            let config = MeshDaemonConfig.default
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(config)
            print(String(data: data, encoding: .utf8)!)
            return
        }

        if let networkId = generate {
            var config = MeshDaemonConfig.default
            config.networkId = networkId

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(config)

            if let outputPath = output {
                try data.write(to: URL(fileURLWithPath: outputPath))
                print("Configuration written to: \(outputPath)")
            } else {
                print(String(data: data, encoding: .utf8)!)
            }
            return
        }

        // Show current config paths
        print("Configuration Paths")
        print("===================")
        print("Default config:  \(MeshDaemonConfig.defaultConfigPath)")
        print("Default identity: \(MeshDaemonConfig.defaultIdentityPath)")
        print("")
        print("Use --show-default to see default configuration")
        print("Use --generate <network-id> to generate a configuration file")
    }
}
