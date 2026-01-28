// OmertaMeshCLI - Mesh network CLI tool
//
// Commands for managing mesh networks, peers, and services.
// This CLI communicates with omerta-meshd for operations requiring a running daemon.

import Foundation
import ArgumentParser
import OmertaMesh
import Logging

// MARK: - Main Command

@main
struct MeshCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "omerta-mesh",
        abstract: "Mesh network management CLI",
        discussion: """
            The omerta-mesh CLI provides commands for managing mesh networks.

            Network management commands (create, join, list) work directly with
            the local network store. Peer and service commands require a running
            omerta-meshd daemon.

            Quick start:
              1. Create a network:  omerta-mesh network create --name mynet
              2. Start the daemon:  omerta-meshd start <network-id>
              3. Check status:      omerta-mesh status <network-id>
              4. List peers:        omerta-mesh peers <network-id>
            """,
        version: "1.0.0",
        subcommands: [
            // Network management
            NetworkCmd.self,
            NetworksCmd.self,

            // Peer operations (require daemon)
            PeersCmd.self,
            PingCmd.self,
            ConnectCmd.self,

            // Services (require daemon)
            SendCmd.self,
            HealthCmd.self,

            // Status (require daemon)
            StatusCmd.self,
            NATCmd.self,

            // Identity management
            IdentityCmd.self,
        ]
    )
}

// MARK: - Shared Helpers

/// Load or generate identity keypair
func loadOrGenerateIdentity() throws -> IdentityKeypair {
    let homeDir = FileManager.default.homeDirectoryForCurrentUser
    let identityDir = homeDir.appendingPathComponent(".omerta/mesh")
    let identityFile = identityDir.appendingPathComponent("identity.json")

    // Try to load existing identity
    if FileManager.default.fileExists(atPath: identityFile.path) {
        let data = try Data(contentsOf: identityFile)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let stored = try decoder.decode(StoredIdentity.self, from: data)
        return try IdentityKeypair(privateKeyBase64: stored.privateKey)
    }

    // Generate new identity
    let identity = IdentityKeypair()

    // Save it
    let stored = StoredIdentity(
        privateKey: identity.privateKeyBase64,
        createdAt: Date()
    )

    try FileManager.default.createDirectory(at: identityDir, withIntermediateDirectories: true)

    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = .prettyPrinted
    let data = try encoder.encode(stored)

    try data.write(to: identityFile)

    return identity
}

/// Stored identity format
struct StoredIdentity: Codable {
    let privateKey: String
    let createdAt: Date
}

/// Format time ago from date
func formatTimeAgo(_ date: Date) -> String {
    let seconds = Int(Date().timeIntervalSince(date))
    if seconds < 60 {
        return "\(seconds)s ago"
    } else if seconds < 3600 {
        return "\(seconds / 60)m ago"
    } else if seconds < 86400 {
        return "\(seconds / 3600)h ago"
    } else {
        return "\(seconds / 86400)d ago"
    }
}

/// Format uptime
func formatUptime(_ seconds: TimeInterval) -> String {
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

/// Format date
func formatDate(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.dateStyle = .medium
    formatter.timeStyle = .short
    return formatter.string(from: date)
}

// MARK: - Daemon Protocol Types

// Re-use the protocol types from OmertaMeshDaemon
// These are duplicated here since OmertaMeshCLI doesn't depend on OmertaMeshDaemon directly

/// Mesh daemon command enum for CLI use
enum MeshDaemonCommand: Codable, Sendable {
    case base(BaseDaemonCommand)
    case peers
    case ping(peerId: String, timeout: Int, requestFullList: Bool)
    case connect(peerId: String, timeout: Int)
    case networkList
    case networkShow(networkId: String)
    case sendMessage(peerId: String, content: Data, requestReceipt: Bool, timeout: Int)
    case healthCheck(peerId: String, timeout: Int)
    case negotiateNetwork(peerId: String, networkName: String, timeout: Int)
    case shareInvite(peerId: String, networkKey: Data, networkName: String?, timeout: Int)
    case registerChannel(channel: String, clientId: String)
    case unregisterChannel(channel: String, clientId: String)
    case sendOnChannel(channel: String, peerId: String, data: Data)
    case sendOnChannelToMachine(channel: String, machineId: String, data: Data)
    case createTunnel(peerId: String, tunnelId: String)
    case closeTunnel(tunnelId: String)
    case natInfo
}

/// Mesh daemon response enum for CLI use
enum MeshDaemonResponse: Codable, Sendable {
    case base(BaseDaemonResponse)
    case peers([PeerData])
    case pingResult(CLIPingResultData?)
    case connectResult(CLIConnectResultData)
    case networkList([CLINetworkInfoData])
    case networkShow(CLINetworkDetailData?)
    case sendMessageResult(CLISendMessageResultData)
    case healthCheckResult(CLIHealthCheckResultData?)
    case negotiateResult(CLINegotiateResultData)
    case shareInviteResult(CLIShareInviteResultData)
    case channelRegistered(success: Bool, error: String?)
    case channelUnregistered(success: Bool)
    case channelSendResult(success: Bool, error: String?)
    case tunnelCreated(tunnelId: String, success: Bool, error: String?)
    case tunnelClosed(tunnelId: String, success: Bool)
    case natInfo(CLINATInfoData)
    case ok
    case error(String)
}

// CLI-specific data types for responses (prefixed with CLI to avoid conflicts)
struct CLIPingResultData: Codable, Sendable {
    let peerId: String
    let rttMs: Double
    let endpoint: String?
    let natType: String?
    let peersDiscovered: Int
}

struct CLIConnectResultData: Codable, Sendable {
    let success: Bool
    let peerId: String
    let endpoint: String?
    let isDirect: Bool
    let method: String
    let rttMs: Double?
    let error: String?
}

struct CLINetworkInfoData: Codable, Sendable {
    let id: String
    let name: String
    let isActive: Bool
    let joinedAt: Date
    let bootstrapPeerCount: Int
}

struct CLINetworkDetailData: Codable, Sendable {
    let id: String
    let name: String
    let isActive: Bool
    let joinedAt: Date
    let bootstrapPeers: [String]
    let inviteLink: String?
    let peerCount: Int
    let connectedPeerCount: Int
}

struct CLISendMessageResultData: Codable, Sendable {
    let success: Bool
    let messageId: String?
    let deliveryConfirmed: Bool
    let error: String?
}

struct CLIHealthCheckResultData: Codable, Sendable {
    let peerId: String
    let isHealthy: Bool
    let rttMs: Double?
    let lastSeen: Date?
    let error: String?
}

struct CLINegotiateResultData: Codable, Sendable {
    let success: Bool
    let networkId: String?
    let networkName: String?
    let error: String?
}

struct CLIShareInviteResultData: Codable, Sendable {
    let success: Bool
    let inviteAccepted: Bool
    let error: String?
}

struct CLINATInfoData: Codable, Sendable {
    let natType: String
    let publicEndpoint: String?
    let localPort: Int?
    let isHolePunchable: Bool
    let canRelay: Bool
}

// MARK: - Network Commands

struct NetworkCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "network",
        abstract: "Manage mesh networks",
        subcommands: [
            NetworkCreate.self,
            NetworkJoin.self,
            NetworkLeave.self,
            NetworkListCmd.self,
            NetworkShowCmd.self,
            NetworkBootstrap.self,
            NetworkInvite.self,
        ]
    )
}

struct NetworkCreate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "create",
        abstract: "Create a new network"
    )

    @Option(name: .shortAndLong, help: "Name for the network")
    var name: String

    @Option(name: .long, help: "Your public endpoint (host:port) for bootstrap")
    var endpoint: String?

    mutating func run() async throws {
        print("Creating network: \(name)")

        let identity = try loadOrGenerateIdentity()
        let tempKey = Data(repeating: 0, count: 32)
        let config = MeshConfig(encryptionKey: tempKey)
        let mesh = MeshNetwork(identity: identity, config: config)

        let networkKey = try await mesh.createNetwork(name: name, bootstrapEndpoint: endpoint)

        print("")
        print("Network created successfully!")
        print("")
        print("Network ID: \(networkKey.deriveNetworkId())")
        print("Name: \(name)")
        print("")
        print("Invite link (share with others to join):")
        print("")
        print("  \(try networkKey.encode())")
        print("")
        print("To start the daemon for this network:")
        print("  omerta-meshd start \(networkKey.deriveNetworkId())")
    }
}

struct NetworkJoin: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "join",
        abstract: "Join a network using an invite link"
    )

    @Argument(help: "Invite link (omerta://join/...)")
    var inviteLink: String

    @Option(name: .shortAndLong, help: "Custom name for the network")
    var name: String?

    mutating func run() async throws {
        let networkKey: NetworkKey
        do {
            networkKey = try NetworkKey.decode(from: inviteLink)
        } catch {
            print("Error: Invalid invite link")
            print("Expected format: omerta://join/<base64-data>")
            throw ExitCode.failure
        }

        let networkId = networkKey.deriveNetworkId()
        let displayName = name ?? networkKey.networkName

        print("Joining network: \(displayName)")
        print("Network ID: \(networkId)")

        let store = NetworkStore.defaultStore()
        try await store.load()

        do {
            let network = try await store.join(networkKey, name: name)
            print("")
            print("Successfully joined network!")
            print("")
            print("Network ID: \(network.id)")
            print("Name: \(network.name)")
            print("Bootstrap peers: \(networkKey.bootstrapPeers.count)")
            print("")
            print("To start the daemon for this network:")
            print("  omerta-meshd start \(network.id)")
        } catch NetworkStoreError.alreadyJoined {
            print("")
            print("Already joined this network.")
        }
    }
}

struct NetworkLeave: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "leave",
        abstract: "Leave a network"
    )

    @Argument(help: "Network ID to leave")
    var networkId: String

    @Flag(name: .long, help: "Force leave without confirmation")
    var force: Bool = false

    mutating func run() async throws {
        let store = NetworkStore.defaultStore()
        try await store.load()

        guard let network = await store.network(id: networkId) else {
            print("Error: Network not found: \(networkId)")
            throw ExitCode.failure
        }

        if !force {
            print("Leave network '\(network.name)' (\(networkId))?")
            print("This will remove all stored configuration for this network.")
            print("")
            print("Type 'yes' to confirm: ", terminator: "")

            guard let input = readLine(), input.lowercased() == "yes" else {
                print("Cancelled")
                return
            }
        }

        try await store.leave(networkId)
        print("Left network: \(network.name)")
    }
}

struct NetworkListCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List joined networks"
    )

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        let store = NetworkStore.defaultStore()
        try await store.load()

        let networks = await store.allNetworks()

        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted]
            encoder.dateEncodingStrategy = .iso8601
            let summaries = networks.map { NetworkSummary(from: $0) }
            let data = try encoder.encode(summaries)
            print(String(data: data, encoding: .utf8)!)
        } else {
            if networks.isEmpty {
                print("No networks joined.")
                print("")
                print("To create a network: omerta-mesh network create --name <name>")
                print("To join a network:   omerta-mesh network join <invite-link>")
            } else {
                print("Joined Networks")
                print("===============")
                print("")
                for network in networks.sorted(by: { $0.joinedAt > $1.joinedAt }) {
                    let status = network.isActive ? "" : " (inactive)"
                    print("\(network.name)\(status)")
                    print("  ID: \(network.id)")
                    print("  Joined: \(formatDate(network.joinedAt))")
                    print("  Bootstrap peers: \(network.key.bootstrapPeers.count)")
                    print("")
                }
            }
        }
    }
}

private struct NetworkSummary: Codable {
    let id: String
    let name: String
    let isActive: Bool
    let joinedAt: Date
    let bootstrapPeerCount: Int

    init(from network: Network) {
        self.id = network.id
        self.name = network.name
        self.isActive = network.isActive
        self.joinedAt = network.joinedAt
        self.bootstrapPeerCount = network.key.bootstrapPeers.count
    }
}

struct NetworkShowCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Show network details"
    )

    @Argument(help: "Network ID to show")
    var networkId: String

    @Flag(name: .long, help: "Show invite link")
    var invite: Bool = false

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        let store = NetworkStore.defaultStore()
        try await store.load()

        guard let network = await store.network(id: networkId) else {
            print("Error: Network not found: \(networkId)")
            throw ExitCode.failure
        }

        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(network)
            print(String(data: data, encoding: .utf8)!)
        } else {
            print("Network: \(network.name)")
            print("==========\(String(repeating: "=", count: network.name.count))")
            print("")
            print("ID:       \(network.id)")
            print("Active:   \(network.isActive ? "yes" : "no")")
            print("Joined:   \(formatDate(network.joinedAt))")
            print("")

            if !network.key.bootstrapPeers.isEmpty {
                print("Bootstrap Peers (\(network.key.bootstrapPeers.count)):")
                for peer in network.key.bootstrapPeers {
                    print("  \(peer)")
                }
                print("")
            }

            if invite {
                print("Invite Link:")
                print("  \(try network.key.encode())")
                print("")
            }
        }
    }
}

struct NetworkBootstrap: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "bootstrap",
        abstract: "Manage bootstrap peers",
        subcommands: [
            BootstrapList.self,
            BootstrapAdd.self,
            BootstrapRemove.self,
        ]
    )
}

struct BootstrapList: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List bootstrap peers for a network"
    )

    @Argument(help: "Network ID")
    var networkId: String

    mutating func run() async throws {
        let store = NetworkStore.defaultStore()
        try await store.load()

        guard let peers = await store.bootstrapPeers(forNetwork: networkId) else {
            print("Error: Network not found: \(networkId)")
            throw ExitCode.failure
        }

        if peers.isEmpty {
            print("No bootstrap peers configured.")
        } else {
            print("Bootstrap Peers for \(networkId):")
            print("")
            for peer in peers {
                print("  \(peer)")
            }
        }
    }
}

struct BootstrapAdd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Add a bootstrap peer"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Argument(help: "Peer (format: peerId@host:port)")
    var peer: String

    mutating func run() async throws {
        let parts = peer.split(separator: "@", maxSplits: 1)
        guard parts.count == 2 else {
            print("Error: Invalid peer format. Expected: peerId@host:port")
            throw ExitCode.failure
        }

        let store = NetworkStore.defaultStore()
        try await store.load()

        try await store.addBootstrapPeer(networkId, peer: peer)
        print("Added bootstrap peer: \(peer)")
    }
}

struct BootstrapRemove: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: "Remove a bootstrap peer"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Argument(help: "Peer to remove (format: peerId@host:port)")
    var peer: String

    mutating func run() async throws {
        let store = NetworkStore.defaultStore()
        try await store.load()

        try await store.removeBootstrapPeer(networkId, peer: peer)
        print("Removed bootstrap peer: \(peer)")
    }
}

struct NetworkInvite: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "invite",
        abstract: "Generate an invite link for a network"
    )

    @Argument(help: "Network ID")
    var networkId: String

    mutating func run() async throws {
        let store = NetworkStore.defaultStore()
        try await store.load()

        guard let network = await store.network(id: networkId) else {
            print("Error: Network not found: \(networkId)")
            throw ExitCode.failure
        }

        print("Invite link for '\(network.name)':")
        print("")
        print("  \(try network.key.encode())")
        print("")
        print("Share this link with others to let them join the network.")
    }
}

// MARK: - Peer Commands

struct PeersCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "peers",
        abstract: "List known peers"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        let client = ControlSocketClient.meshDaemon(networkId: networkId)

        do {
            try await client.connect()

            let command = MeshDaemonCommand.peers
            let response: MeshDaemonResponse = try await client.send(command)

            switch response {
            case .peers(let peers):
                if json {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted]
                    encoder.dateEncodingStrategy = .iso8601
                    let data = try encoder.encode(peers)
                    print(String(data: data, encoding: .utf8)!)
                } else {
                    if peers.isEmpty {
                        print("No peers discovered yet.")
                    } else {
                        print("Known Peers (\(peers.count))")
                        print("=================")
                        print("")
                        for peer in peers {
                            let status = peer.isConnected ? (peer.isDirect ? "[direct]" : "[relay]") : "[offline]"
                            print("\(peer.peerId.prefix(16))... \(status)")
                            print("  Endpoint: \(peer.endpoint)")
                            print("  NAT: \(peer.natType)")
                            if let rtt = peer.rttMs {
                                print("  RTT: \(String(format: "%.1f", rtt))ms")
                            }
                            if let lastSeen = peer.lastSeen {
                                print("  Last seen: \(formatTimeAgo(lastSeen))")
                            }
                            print("")
                        }
                    }
                }

            case .error(let message):
                print("Error: \(message)")
                throw ExitCode.failure

            default:
                print("Unexpected response")
                throw ExitCode.failure
            }

            await client.disconnect()

        } catch let error as IPCError {
            print("Failed to connect to daemon: \(error)")
            print("")
            print("Make sure the daemon is running:")
            print("  omerta-meshd start \(networkId)")
            throw ExitCode.failure
        }
    }
}

struct PingCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ping",
        abstract: "Ping a peer"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Argument(help: "Peer ID to ping")
    var peerId: String

    @Option(name: .shortAndLong, help: "Timeout in seconds")
    var timeout: Int = 5

    @Option(name: .shortAndLong, help: "Number of pings to send")
    var count: Int = 1

    @Flag(name: .long, help: "Request full peer list")
    var fullList: Bool = false

    mutating func run() async throws {
        let client = ControlSocketClient.meshDaemon(networkId: networkId)

        do {
            try await client.connect()

            for i in 1...count {
                let startTime = Date()

                let command = MeshDaemonCommand.ping(
                    peerId: peerId,
                    timeout: timeout,
                    requestFullList: fullList
                )
                let response: MeshDaemonResponse = try await client.send(command)

                switch response {
                case .pingResult(let resultOpt):
                    if let result = resultOpt {
                        if count > 1 {
                            print("[\(i)/\(count)] Reply from \(peerId.prefix(16))...: RTT=\(String(format: "%.1f", result.rttMs))ms")
                        } else {
                            print("PING \(peerId.prefix(16))...")
                            print("Reply received")
                            print("  RTT: \(String(format: "%.1f", result.rttMs))ms")
                            if let endpoint = result.endpoint {
                                print("  Endpoint: \(endpoint)")
                            }
                            if let natType = result.natType {
                                print("  NAT: \(natType)")
                            }
                            if result.peersDiscovered > 0 {
                                print("  Peers discovered: \(result.peersDiscovered)")
                            }
                        }
                    } else {
                        let elapsed = Date().timeIntervalSince(startTime) * 1000
                        if count > 1 {
                            print("[\(i)/\(count)] Request timeout after \(String(format: "%.0f", elapsed))ms")
                        } else {
                            print("PING \(peerId.prefix(16))...")
                            print("Request timeout after \(String(format: "%.0f", elapsed))ms")
                        }
                    }

                case .error(let message):
                    print("Error: \(message)")
                    throw ExitCode.failure

                default:
                    print("Unexpected response")
                    throw ExitCode.failure
                }

                if i < count {
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                }
            }

            await client.disconnect()

        } catch let error as IPCError {
            print("Failed to connect to daemon: \(error)")
            throw ExitCode.failure
        }
    }
}

struct ConnectCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "connect",
        abstract: "Connect to a peer"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Argument(help: "Peer ID to connect to")
    var peerId: String

    @Option(name: .shortAndLong, help: "Connection timeout in seconds")
    var timeout: Int = 30

    mutating func run() async throws {
        print("Connecting to \(peerId.prefix(16))...")

        let client = ControlSocketClient.meshDaemon(networkId: networkId)

        do {
            try await client.connect()

            let command = MeshDaemonCommand.connect(peerId: peerId, timeout: timeout)
            let response: MeshDaemonResponse = try await client.send(command)

            switch response {
            case .connectResult(let result):
                if result.success {
                    print("")
                    print("Connected!")
                    print("  Method: \(result.method)")
                    print("  Direct: \(result.isDirect ? "yes" : "no (relay)")")
                    if let endpoint = result.endpoint {
                        print("  Endpoint: \(endpoint)")
                    }
                    if let rtt = result.rttMs {
                        print("  RTT: \(String(format: "%.1f", rtt))ms")
                    }
                } else {
                    print("")
                    print("Connection failed: \(result.error ?? "unknown error")")
                    throw ExitCode.failure
                }

            case .error(let message):
                print("Error: \(message)")
                throw ExitCode.failure

            default:
                print("Unexpected response")
                throw ExitCode.failure
            }

            await client.disconnect()

        } catch let error as IPCError {
            print("Failed to connect to daemon: \(error)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Service Commands

struct SendCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "send",
        abstract: "Send a message to a peer"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Argument(help: "Peer ID to send to")
    var peerId: String

    @Argument(help: "Message to send")
    var message: String

    @Option(name: .shortAndLong, help: "Timeout in seconds")
    var timeout: Int = 10

    @Flag(name: .long, help: "Request delivery receipt")
    var receipt: Bool = false

    mutating func run() async throws {
        let client = ControlSocketClient.meshDaemon(networkId: networkId)

        do {
            try await client.connect()

            let content = message.data(using: .utf8) ?? Data()
            let command = MeshDaemonCommand.sendMessage(
                peerId: peerId,
                content: content,
                requestReceipt: receipt,
                timeout: timeout
            )
            let response: MeshDaemonResponse = try await client.send(command)

            switch response {
            case .sendMessageResult(let result):
                if result.success {
                    print("Message sent to \(peerId.prefix(16))...")
                    if let messageId = result.messageId {
                        print("  Message ID: \(messageId.prefix(8))...")
                    }
                    if result.deliveryConfirmed {
                        print("  Delivery confirmed")
                    }
                } else {
                    print("Failed to send message: \(result.error ?? "unknown error")")
                    throw ExitCode.failure
                }

            case .error(let message):
                print("Error: \(message)")
                throw ExitCode.failure

            default:
                print("Unexpected response")
                throw ExitCode.failure
            }

            await client.disconnect()

        } catch let error as IPCError {
            print("Failed to connect to daemon: \(error)")
            throw ExitCode.failure
        }
    }
}

struct HealthCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "health",
        abstract: "Check peer health"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Argument(help: "Peer ID to check")
    var peerId: String

    @Option(name: .shortAndLong, help: "Timeout in seconds")
    var timeout: Int = 5

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        let client = ControlSocketClient.meshDaemon(networkId: networkId)

        do {
            try await client.connect()

            let command = MeshDaemonCommand.healthCheck(peerId: peerId, timeout: timeout)
            let response: MeshDaemonResponse = try await client.send(command)

            switch response {
            case .healthCheckResult(let result):
                if json {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted]
                    encoder.dateEncodingStrategy = .iso8601
                    if let result = result {
                        let data = try encoder.encode(result)
                        print(String(data: data, encoding: .utf8)!)
                    } else {
                        print("{\"isHealthy\": false, \"error\": \"No response\"}")
                    }
                } else {
                    if let result = result {
                        print("Health Check: \(peerId.prefix(16))...")
                        print("")
                        print("  Status: \(result.isHealthy ? "HEALTHY" : "UNHEALTHY")")
                        if let rtt = result.rttMs {
                            print("  RTT: \(String(format: "%.1f", rtt))ms")
                        }
                        if let lastSeen = result.lastSeen {
                            print("  Last seen: \(formatDate(lastSeen))")
                        }
                        if let error = result.error {
                            print("  Error: \(error)")
                        }
                    } else {
                        print("Health Check: \(peerId.prefix(16))...")
                        print("")
                        print("  Status: UNREACHABLE")
                        print("  No response within \(timeout) seconds")
                    }
                }

            case .error(let message):
                print("Error: \(message)")
                throw ExitCode.failure

            default:
                print("Unexpected response")
                throw ExitCode.failure
            }

            await client.disconnect()

        } catch let error as IPCError {
            print("Failed to connect to daemon: \(error)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Status Commands

struct StatusCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show daemon status"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        let controlPath = DaemonSocketPaths.meshDaemonControl(networkId: networkId)

        guard DaemonSocketPaths.socketExists(controlPath) else {
            if json {
                print("{\"running\": false, \"networkId\": \"\(networkId)\"}")
            } else {
                print("Daemon Status: NOT RUNNING")
                print("")
                print("The mesh daemon is not running for network: \(networkId)")
                print("")
                print("To start the daemon:")
                print("  omerta-meshd start \(networkId)")
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
                    encoder.outputFormatting = [.prettyPrinted]
                    let data = try encoder.encode(status)
                    print(String(data: data, encoding: .utf8)!)
                } else {
                    print("Daemon Status")
                    print("=============")
                    print("")
                    print("Running:       \(status.isRunning ? "yes" : "no")")
                    print("Network:       \(status.networkId)")
                    print("Protocol:      v\(status.protocolVersion)")

                    if let uptime = status.uptime {
                        print("Uptime:        \(formatUptime(uptime))")
                    }

                    if !status.additionalInfo.isEmpty {
                        print("")
                        print("Mesh Network")
                        print("------------")

                        if let peerId = status.additionalInfo["peerId"] {
                            print("Peer ID:       \(peerId.prefix(16))...")
                        }
                        if let natType = status.additionalInfo["natType"] {
                            print("NAT Type:      \(natType)")
                        }
                        if let endpoint = status.additionalInfo["publicEndpoint"], !endpoint.isEmpty {
                            print("Public Addr:   \(endpoint)")
                        }
                        if let peerCount = status.additionalInfo["peerCount"] {
                            print("Known Peers:   \(peerCount)")
                        }
                        if let connCount = status.additionalInfo["connectionCount"] {
                            print("Connections:   \(connCount)")
                        }
                        if let directCount = status.additionalInfo["directConnectionCount"] {
                            print("Direct Conns:  \(directCount)")
                        }
                        if let relayCount = status.additionalInfo["relayCount"] {
                            print("Relays:        \(relayCount)")
                        }
                    }

                    print("")
                    print("Socket Paths")
                    print("------------")
                    print("Control: \(controlPath)")
                    print("Data:    \(DaemonSocketPaths.meshDaemonData(networkId: networkId))")
                }

            case .error(let message):
                print("Error: \(message)")
                throw ExitCode.failure

            default:
                print("Unexpected response")
                throw ExitCode.failure
            }

            await client.disconnect()

        } catch let error as IPCError {
            print("Failed to connect to daemon: \(error)")
            throw ExitCode.failure
        }
    }
}

struct NetworksCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "networks",
        abstract: "List joined networks (shortcut for 'network list')"
    )

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        var networkList = NetworkListCmd()
        networkList.json = json
        try await networkList.run()
    }
}

// MARK: - NAT Commands

struct NATCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "nat",
        abstract: "NAT detection and status",
        subcommands: [
            NATStatusCmd.self,
        ]
    )
}

struct NATStatusCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show NAT status"
    )

    @Argument(help: "Network ID")
    var networkId: String

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() async throws {
        let client = ControlSocketClient.meshDaemon(networkId: networkId)

        do {
            try await client.connect()

            let command = MeshDaemonCommand.natInfo
            let response: MeshDaemonResponse = try await client.send(command)

            switch response {
            case .natInfo(let info):
                if json {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted]
                    let data = try encoder.encode(info)
                    print(String(data: data, encoding: .utf8)!)
                } else {
                    print("NAT Status")
                    print("==========")
                    print("")
                    print("NAT Type:        \(info.natType)")
                    if let endpoint = info.publicEndpoint {
                        print("Public Endpoint: \(endpoint)")
                    } else {
                        print("Public Endpoint: unknown")
                    }
                    if let port = info.localPort {
                        print("Local Port:      \(port)")
                    }
                    print("")
                    print("Capabilities:")
                    print("  Hole Punchable: \(info.isHolePunchable ? "yes" : "no")")
                    print("  Can Relay:      \(info.canRelay ? "yes" : "no")")
                }

            case .error(let message):
                print("Error: \(message)")
                throw ExitCode.failure

            default:
                print("Unexpected response")
                throw ExitCode.failure
            }

            await client.disconnect()

        } catch let error as IPCError {
            print("Failed to connect to daemon: \(error)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Identity Commands

struct IdentityCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "identity",
        abstract: "Manage cryptographic identity",
        subcommands: [
            IdentityShow.self,
            IdentityGenerate.self,
        ]
    )
}

struct IdentityShow: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Show current identity"
    )

    @Flag(name: .long, help: "Show full peer ID")
    var full: Bool = false

    @Flag(name: .long, help: "Show public key")
    var publicKey: Bool = false

    @Flag(name: .long, help: "Output as JSON")
    var json: Bool = false

    mutating func run() throws {
        let identity: IdentityKeypair
        do {
            identity = try loadOrGenerateIdentity()
        } catch {
            print("Error: Failed to load identity: \(error)")
            throw ExitCode.failure
        }

        if json {
            var info: [String: String] = [
                "peerId": identity.peerId,
                "publicKey": identity.publicKeyBase64
            ]
            if full {
                info["peerIdFull"] = identity.peerId
            }

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(info)
            print(String(data: data, encoding: .utf8)!)
        } else {
            print("Identity")
            print("========")
            print("")
            if full {
                print("Peer ID: \(identity.peerId)")
            } else {
                print("Peer ID: \(identity.peerId.prefix(16))...")
            }
            if publicKey {
                print("Public Key: \(identity.publicKeyBase64)")
            }
            print("")

            let homeDir = FileManager.default.homeDirectoryForCurrentUser
            let identityPath = homeDir.appendingPathComponent(".omerta/mesh/identity.json").path
            print("Identity file: \(identityPath)")
        }
    }
}

struct IdentityGenerate: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "generate",
        abstract: "Generate a new identity"
    )

    @Flag(name: .long, help: "Force regeneration even if identity exists")
    var force: Bool = false

    mutating func run() throws {
        let homeDir = FileManager.default.homeDirectoryForCurrentUser
        let identityDir = homeDir.appendingPathComponent(".omerta/mesh")
        let identityFile = identityDir.appendingPathComponent("identity.json")

        if FileManager.default.fileExists(atPath: identityFile.path) && !force {
            print("Identity already exists at: \(identityFile.path)")
            print("")
            print("Use --force to regenerate (WARNING: this will invalidate your peer ID)")
            return
        }

        let identity = IdentityKeypair()

        let stored = StoredIdentity(
            privateKey: identity.privateKeyBase64,
            createdAt: Date()
        )

        try FileManager.default.createDirectory(at: identityDir, withIntermediateDirectories: true)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(stored)

        try data.write(to: identityFile)

        print("Generated new identity")
        print("")
        print("Peer ID: \(identity.peerId)")
        print("Saved to: \(identityFile.path)")
    }
}
