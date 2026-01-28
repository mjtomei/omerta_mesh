// MeshDaemonProtocol.swift - Mesh daemon specific IPC protocol
//
// Defines commands and responses specific to the mesh daemon (omerta-meshd).

import Foundation
import OmertaMesh

// MARK: - Mesh Daemon Commands

/// Commands supported by the mesh daemon
public enum MeshDaemonCommand: Codable, Sendable {
    // Base commands
    case base(BaseDaemonCommand)

    // Peer operations
    case peers
    case ping(peerId: String, timeout: Int, requestFullList: Bool)
    case connect(peerId: String, timeout: Int)

    // Network info
    case networkList
    case networkShow(networkId: String)

    // Services
    case sendMessage(peerId: String, content: Data, requestReceipt: Bool, timeout: Int)
    case healthCheck(peerId: String, timeout: Int)
    case negotiateNetwork(peerId: String, networkName: String, timeout: Int)
    case shareInvite(peerId: String, networkKey: Data, networkName: String?, timeout: Int)

    // Channel operations (for omertad to use)
    case registerChannel(channel: String, clientId: String)
    case unregisterChannel(channel: String, clientId: String)
    case sendOnChannel(channel: String, peerId: String, data: Data)
    case sendOnChannelToMachine(channel: String, machineId: String, data: Data)

    // Tunnel operations
    case createTunnel(peerId: String, tunnelId: String)
    case closeTunnel(tunnelId: String)

    // NAT info
    case natInfo
}

// MARK: - Mesh Daemon Responses

/// Responses from the mesh daemon
public enum MeshDaemonResponse: Codable, Sendable {
    // Base responses
    case base(BaseDaemonResponse)

    // Peer operation results
    case peers([PeerData])
    case pingResult(PingResultData?)
    case connectResult(ConnectResultData)

    // Network info results
    case networkList([NetworkInfoData])
    case networkShow(NetworkDetailData?)

    // Service results
    case sendMessageResult(SendMessageResultData)
    case healthCheckResult(HealthCheckResultData?)
    case negotiateResult(NegotiateResultData)
    case shareInviteResult(ShareInviteResultData)

    // Channel results
    case channelRegistered(success: Bool, error: String?)
    case channelUnregistered(success: Bool)
    case channelSendResult(success: Bool, error: String?)

    // Tunnel results
    case tunnelCreated(tunnelId: String, success: Bool, error: String?)
    case tunnelClosed(tunnelId: String, success: Bool)

    // NAT info result
    case natInfo(NATInfoData)

    // General results
    case ok
    case error(String)
}

// MARK: - NAT Info Data

/// NAT information
public struct NATInfoData: Codable, Sendable, Equatable {
    public let natType: String
    public let publicEndpoint: String?
    public let localPort: Int?
    public let isHolePunchable: Bool
    public let canRelay: Bool

    public init(
        natType: String,
        publicEndpoint: String? = nil,
        localPort: Int? = nil,
        isHolePunchable: Bool = false,
        canRelay: Bool = false
    ) {
        self.natType = natType
        self.publicEndpoint = publicEndpoint
        self.localPort = localPort
        self.isHolePunchable = isHolePunchable
        self.canRelay = canRelay
    }
}

// MARK: - Mesh Daemon Extended Status

/// Extended status data for mesh daemon
public struct MeshDaemonStatusData: Codable, Sendable, Equatable {
    public let base: DaemonStatusData
    public let peerId: String
    public let natType: String
    public let publicEndpoint: String?
    public let peerCount: Int
    public let connectionCount: Int
    public let directConnectionCount: Int
    public let relayCount: Int
    public let registeredChannels: [String]

    public init(
        base: DaemonStatusData,
        peerId: String,
        natType: String,
        publicEndpoint: String? = nil,
        peerCount: Int = 0,
        connectionCount: Int = 0,
        directConnectionCount: Int = 0,
        relayCount: Int = 0,
        registeredChannels: [String] = []
    ) {
        self.base = base
        self.peerId = peerId
        self.natType = natType
        self.publicEndpoint = publicEndpoint
        self.peerCount = peerCount
        self.connectionCount = connectionCount
        self.directConnectionCount = directConnectionCount
        self.relayCount = relayCount
        self.registeredChannels = registeredChannels
    }
}
