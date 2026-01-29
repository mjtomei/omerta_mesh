import Foundation
import Logging
import OmertaMesh
import OmertaTunnel
import OmertaNetwork

// MARK: - In-process mock channel provider & relay

actor E2EChannelProvider: ChannelProvider {
    let _machineId: MachineId
    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]
    private(set) var sentMessages: [(data: Data, target: MachineId, channel: String)] = []

    init(machineId: MachineId) {
        self._machineId = machineId
    }

    var peerId: PeerId { get async { "peer-\(_machineId)" } }

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        let machineId = peerId.hasPrefix("peer-") ? String(peerId.dropFirst(5)) : peerId
        sentMessages.append((data, machineId, channel))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        sentMessages.append((data, machineId, channel))
    }

    func deliverMessage(_ data: Data, from senderMachineId: MachineId, on channel: String) async {
        if let handler = handlers[channel] {
            await handler(senderMachineId, data)
        }
    }

    func clearSentMessages() {
        sentMessages.removeAll()
    }
}

actor E2ERelay {
    private var providers: [MachineId: E2EChannelProvider] = [:]
    private var relayTask: Task<Void, Never>?

    func register(machineId: MachineId, provider: E2EChannelProvider) {
        providers[machineId] = provider
    }

    func startRelay() {
        relayTask = Task {
            while !Task.isCancelled {
                await relayMessages()
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
    }

    func stopRelay() {
        relayTask?.cancel()
        relayTask = nil
    }

    private func relayMessages() async {
        var pending: [(from: MachineId, to: MachineId, data: Data, channel: String)] = []
        for (machineId, provider) in providers {
            let messages = await provider.sentMessages
            for msg in messages {
                pending.append((machineId, msg.target, msg.data, msg.channel))
            }
            await provider.clearSentMessages()
        }
        for msg in pending {
            if let target = providers[msg.to] {
                await target.deliverMessage(msg.data, from: msg.from, on: msg.channel)
            }
        }
    }
}

// MARK: - Stale process cleanup

/// Kill any other running instances of this binary so we don't get port conflicts.
func killStaleInstances() {
    let myPID = ProcessInfo.processInfo.processIdentifier
    // Use pgrep -x (exact comm name match) to avoid matching sudo wrappers.
    // Comm name is truncated to 15 chars: "DemoSOCKSGatewa"
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
    proc.arguments = ["-x", "DemoSOCKSGatewa"]
    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = FileHandle.nullDevice
    do {
        try proc.run()
        proc.waitUntilExit()
    } catch { return }
    let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    for line in output.split(separator: "\n") {
        guard let pid = Int32(line.trimmingCharacters(in: .whitespaces)),
              pid != myPID else { continue }
        kill(pid, SIGTERM)
        usleep(500_000)
        kill(pid, SIGKILL)
    }
}

// MARK: - Main

let logger = Logger(label: "demo.socks-gateway")

killStaleInstances()

logger.info("Setting up DemoSOCKSGateway...")

// Auto-detect a non-conflicting subnet for the virtual network
let vnetConfig = try VirtualNetworkConfig.autoDetect()
let gwIP = vnetConfig.gatewayIP
let peerIP = vnetConfig.poolStart
logger.info("Virtual network: \(vnetConfig.subnet)/\(vnetConfig.prefixLength), gw=\(gwIP), peer=\(peerIP)")

// 1. Peer node — runs SOCKS proxy, has a real netstack for TCP dial
let peerBridge = try NetstackBridge(config: .init(gatewayIP: peerIP))
let peerInterface = NetstackInterface(localIP: peerIP, bridge: peerBridge)

// 2. Gateway node — real netstack bridge for internet access
// Gateway netstack uses a separate internal IP for its own stack
guard let gwNetstackIP = vnetConfig.internalIP() else {
    fatalError("Failed to compute gateway netstack IP from subnet \(vnetConfig.subnet)")
}
let gatewayBridge = try NetstackBridge(config: .init(gatewayIP: gwNetstackIP))
let gatewayService = GatewayService(bridge: gatewayBridge)

// 3. Virtual networks
let peerVNet = VirtualNetwork(localMachineId: "peer", config: vnetConfig)
await peerVNet.setLocalAddress(peerIP)
await peerVNet.setGateway(machineId: "gw", ip: gwIP)

let gwVNet = VirtualNetwork(localMachineId: "gw", config: vnetConfig)
await gwVNet.setLocalAddress(gwIP)
await gwVNet.setGateway(machineId: "gw", ip: gwIP)
await gwVNet.registerAddress(ip: peerIP, machineId: "peer")

// 4. Mock channel providers + in-process relay
let peerProvider = E2EChannelProvider(machineId: "peer")
let gwProvider = E2EChannelProvider(machineId: "gw")

let relay = E2ERelay()
await relay.register(machineId: "peer", provider: peerProvider)
await relay.register(machineId: "gw", provider: gwProvider)

// 5. Tunnel managers
let peerTunnelManager = TunnelManager(provider: peerProvider)
let gwTunnelManager = TunnelManager(provider: gwProvider)

// 6. Packet routers
let peerRouter = PacketRouter(
    localInterface: peerInterface,
    virtualNetwork: peerVNet,
    tunnelManager: peerTunnelManager
)

let gwRouter = PacketRouter(
    localInterface: NetstackInterface(localIP: gwIP, bridge: StubNetstackBridge()),
    virtualNetwork: gwVNet,
    tunnelManager: gwTunnelManager,
    gatewayService: gatewayService
)

// 7. SOCKS proxy
let socksProxy = SOCKSProxy(port: 1080, interface: peerInterface)

// 8. Start everything
logger.info("Starting services...")
await relay.startRelay()
try await peerTunnelManager.start()
try await gwTunnelManager.start()
try await gatewayService.start()
try await peerRouter.start()
try await gwRouter.start()
try await socksProxy.start()

let actualPort = await socksProxy.actualPort
logger.info("DemoSOCKSGateway running!")
print("""

============================================================
  SOCKS5 Gateway Demo Running

  Proxy listening on: localhost:\(actualPort)

  Test with:
    curl -v -x socks5h://127.0.0.1:\(actualPort) http://example.com

  Press Ctrl+C to stop.
============================================================

""")
fflush(stdout)

// 9. Wait for SIGINT, printing stats periodically
signal(SIGINT, SIG_IGN)
let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)

await withTaskGroup(of: Void.self) { group in
    // Stats printer
    group.addTask {
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(5))

            let ps = await peerRouter.getStats()
            let gs = await gwRouter.getStats()
            let pns = peerBridge.getStats()
            let gns = gatewayBridge.getStats()
            let nat = await gatewayService.natEntryCount()

            logger.info("""
            --- Stats --- \
            Peer Router: routed=\(ps.packetsRouted) toGW=\(ps.packetsToGateway) \
            fromPeers=\(ps.packetsFromPeers) dropped=\(ps.packetsDropped) | \
            GW Router: routed=\(gs.packetsRouted) toGW=\(gs.packetsToGateway) \
            fromPeers=\(gs.packetsFromPeers) dropped=\(gs.packetsDropped) | \
            Peer Netstack: tcp=\(pns?.tcpConnections ?? 0) udp=\(pns?.udpConnections ?? 0) | \
            GW Netstack: tcp=\(gns?.tcpConnections ?? 0) udp=\(gns?.udpConnections ?? 0) | \
            NAT=\(nat)
            """)
        }
    }

    // Signal waiter
    group.addTask {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            sigintSource.setEventHandler { cont.resume() }
            sigintSource.resume()
        }
    }

    // Wait for signal, then cancel the stats printer
    await group.next()
    group.cancelAll()
}

// 10. Shutdown
logger.info("Shutting down...")
await socksProxy.stop()
await peerRouter.stop()
await gwRouter.stop()
await gatewayService.stop()
await peerTunnelManager.stop()
await gwTunnelManager.stop()
await relay.stopRelay()
logger.info("Done.")
