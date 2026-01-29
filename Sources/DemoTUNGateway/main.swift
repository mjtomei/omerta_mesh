// DemoTUNGateway - TUN-based mesh VPN gateway demo
//
// Two modes:
//
// Mode "tun" (default):
//   Peer: TUNInterface (omerta0, kernel) → PacketRouter → relay
//   Gateway: NetstackBridge (userspace) → GatewayService
//   Test: curl --interface omerta0 http://example.com
//
// Mode "socks-tun":
//   Peer: NetstackBridge (userspace) → SOCKSProxy(1080) + PacketRouter → relay
//   Gateway: TUNInterface (omerta-gw0, kernel) → TUNBridgeAdapter → GatewayService
//   No routing conflict because peer uses userspace netstack (no kernel TUN),
//   so return packets route back through omerta-gw0 correctly.
//   Test: curl -x socks5h://127.0.0.1:1080 http://example.com
//
// Usage:
//   sudo swift run DemoTUNGateway               # tun mode
//   sudo swift run DemoTUNGateway socks-tun      # socks-tun mode
//   sudo swift run DemoTUNGateway socks-tun 8080 # socks-tun on custom port

#if os(Linux)
import Foundation
import Logging
import OmertaMesh
import OmertaTunnel
import OmertaNetwork

// MARK: - In-process mock channel provider & relay (same as DemoSOCKSGateway)

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

// MARK: - Helpers

func cleanupStaleInterface(_ name: String) {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/sbin/ip")
    proc.arguments = ["link", "delete", name]
    proc.standardOutput = FileHandle.nullDevice
    proc.standardError = FileHandle.nullDevice
    try? proc.run()
    proc.waitUntilExit()
}

/// Detect the default outbound network interface (e.g. "eth0", "ens3").
func detectOutboundInterface() -> String {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/sbin/ip")
    proc.arguments = ["route", "show", "default"]
    let pipe = Pipe()
    proc.standardOutput = pipe
    proc.standardError = FileHandle.nullDevice
    do {
        try proc.run()
        proc.waitUntilExit()
    } catch { return "eth0" }
    let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    // Parse "default via X.X.X.X dev <iface> ..."
    let parts = output.split(separator: " ")
    if let devIdx = parts.firstIndex(of: "dev"), devIdx + 1 < parts.endIndex {
        return String(parts[devIdx + 1])
    }
    return "eth0"
}

// MARK: - Stale process cleanup

/// Kill any other running instances of DemoTUNGateway or DemoSOCKSGateway (since both may use port 1080).
/// Runs as root so it can kill any stale process regardless of owner.
func killStaleInstances() {
    let myPID = ProcessInfo.processInfo.processIdentifier
    // Use pgrep -x (exact process name match) to avoid matching the sudo wrapper,
    // whose full command line also contains "DemoTUNGateway".
    // comm names are truncated to 15 chars by the kernel
    for name in ["DemoTUNGateway", "DemoSOCKSGatewa"] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        proc.arguments = ["-x", name]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch { continue }
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        for line in output.split(separator: "\n") {
            guard let pid = Int32(line.trimmingCharacters(in: .whitespaces)),
                  pid != myPID else { continue }
            kill(pid, SIGTERM)
            usleep(500_000)
            kill(pid, SIGKILL)
        }
    }
}

// MARK: - Main

let logger = Logger(label: "demo.tun-gateway")

guard Glibc.geteuid() == 0 else {
    print("ERROR: This demo requires root. Run with: sudo swift run DemoTUNGateway [tun|socks-tun]")
    exit(1)
}

killStaleInstances()

let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "tun"

// --kill: just clean up stale processes and exit
if mode == "--kill" {
    exit(0)
}

// --restore-sysctl <file>: restore saved sysctl values and delete the file
if mode == "--restore-sysctl" {
    let filePath = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : ""
    guard !filePath.isEmpty else {
        print("ERROR: --restore-sysctl requires a file path")
        exit(1)
    }
    guard let contents = try? String(contentsOfFile: filePath, encoding: .utf8) else {
        print("ERROR: Cannot read \(filePath)")
        exit(1)
    }
    // Parse key=value lines
    var values: [String: String] = [:]
    for line in contents.split(separator: "\n") {
        let parts = line.split(separator: "=", maxSplits: 1)
        if parts.count == 2 {
            values[String(parts[0])] = String(parts[1])
        }
    }
    if let v = values["ip_forward"] {
        KernelNetworking.writeProcSysPublic("/proc/sys/net/ipv4/ip_forward", value: v)
    }
    if let v = values["rp_filter_all"] {
        KernelNetworking.writeProcSysPublic("/proc/sys/net/ipv4/conf/all/rp_filter", value: v)
    }
    try? FileManager.default.removeItem(atPath: filePath)
    exit(0)
}

guard mode == "tun" || mode == "socks-tun" else {
    print("ERROR: Unknown mode '\(mode)'. Use 'tun' or 'socks-tun'.")
    exit(1)
}

logger.info("Setting up DemoTUNGateway in '\(mode)' mode...")

// --- Shared setup ---

// Virtual networks
let peerVNet = VirtualNetwork(localMachineId: "peer")
await peerVNet.setLocalAddress("10.0.0.100")
await peerVNet.setGateway(machineId: "gw", ip: "10.0.0.1")

let gwVNet = VirtualNetwork(localMachineId: "gw")
await gwVNet.setLocalAddress("10.0.0.1")
await gwVNet.setGateway(machineId: "gw", ip: "10.0.0.1")
await gwVNet.registerAddress(ip: "10.0.0.100", machineId: "peer")

// Mock channel providers + in-process relay
let peerProvider = E2EChannelProvider(machineId: "peer")
let gwProvider = E2EChannelProvider(machineId: "gw")

let relay = E2ERelay()
await relay.register(machineId: "peer", provider: peerProvider)
await relay.register(machineId: "gw", provider: gwProvider)

// Tunnel managers
let peerTunnelManager = TunnelManager(provider: peerProvider)
let gwTunnelManager = TunnelManager(provider: gwProvider)

// --- Mode-specific setup ---

let peerRouter: PacketRouter
let gwRouter: PacketRouter

// Resources that need mode-specific cleanup
var peerTun: TUNInterface? = nil
var gwTunAdapter: TUNBridgeAdapter? = nil
var socksProxy: SOCKSProxy? = nil
var outInterface: String? = nil

if mode == "tun" {
    // Peer: TUNInterface (kernel) → PacketRouter
    // Gateway: NetstackBridge (userspace) → GatewayService
    cleanupStaleInterface("omerta0")

    let tun = TUNInterface(name: "omerta0", ip: "10.0.0.100", subnetBits: 16)
    peerTun = tun

    let gwBridge = try NetstackBridge(config: .init(gatewayIP: "10.200.0.1"))
    let gatewayService = GatewayService(bridge: gwBridge)

    peerRouter = PacketRouter(
        localInterface: tun,
        virtualNetwork: peerVNet,
        tunnelManager: peerTunnelManager
    )

    gwRouter = PacketRouter(
        localInterface: NetstackInterface(localIP: "10.0.0.1", bridge: StubNetstackBridge()),
        virtualNetwork: gwVNet,
        tunnelManager: gwTunnelManager,
        gatewayService: gatewayService
    )

    // Start services
    await relay.startRelay()
    try await peerTunnelManager.start()
    try await gwTunnelManager.start()
    try await gatewayService.start()
    try await peerRouter.start()
    try await gwRouter.start()

    print("""

    ============================================================
      TUN Gateway Demo Running (mode: tun)

      Peer TUN:    omerta0     (10.0.0.100/16)
      Gateway:     netstack    (10.200.0.1, userspace)

      Test with:
        curl --interface omerta0 http://example.com
        ping -c 3 -I omerta0 8.8.8.8

      Press Ctrl+C to stop.
    ============================================================

    """)
    fflush(stdout)

} else {
    // socks-tun mode
    // Peer: NetstackBridge (userspace) → SOCKSProxy(1080) + PacketRouter
    // Gateway: TUNInterface (omerta-gw0, kernel) → TUNBridgeAdapter → GatewayService
    cleanupStaleInterface("omerta-gw0")

    // Peer side: userspace netstack + SOCKS proxy
    let peerBridge = try NetstackBridge(config: .init(gatewayIP: "10.0.0.100"))
    let peerInterface = NetstackInterface(localIP: "10.0.0.100", bridge: peerBridge)

    // Gateway side: real TUN + kernel forwarding
    let gwTun = TUNInterface(name: "omerta-gw0", ip: "10.0.0.1", subnetBits: 16)
    let adapter = TUNBridgeAdapter(tun: gwTun)
    gwTunAdapter = adapter
    let gatewayService = GatewayService(bridge: adapter)

    peerRouter = PacketRouter(
        localInterface: peerInterface,
        virtualNetwork: peerVNet,
        tunnelManager: peerTunnelManager
    )

    gwRouter = PacketRouter(
        localInterface: NetstackInterface(localIP: "10.0.0.1", bridge: StubNetstackBridge()),
        virtualNetwork: gwVNet,
        tunnelManager: gwTunnelManager,
        gatewayService: gatewayService
    )

    let socksPort: UInt16 = {
        let args = CommandLine.arguments
        if args.count > 2, let p = UInt16(args[2]) { return p }
        return 1080
    }()
    let proxy = SOCKSProxy(port: socksPort, interface: peerInterface)
    socksProxy = proxy

    // Start services
    await relay.startRelay()
    try await peerTunnelManager.start()
    try await gwTunnelManager.start()
    try await gatewayService.start()
    try await peerRouter.start()
    try await gwRouter.start()
    try await proxy.start()

    // Kernel networking for gateway TUN
    let detectedIface = detectOutboundInterface()
    outInterface = detectedIface
    try KernelNetworking.enableForwarding()
    KernelNetworking.looseRPFilter(tunName: "omerta-gw0")
    try KernelNetworking.enableMasquerade(tunName: "omerta-gw0", outInterface: detectedIface)
    KernelNetworking.printDiagnostics(tunName: "omerta-gw0", outInterface: detectedIface)

    let actualPort = await proxy.actualPort

    print("""

    ============================================================
      TUN Gateway Demo Running (mode: socks-tun)

      Peer:        SOCKS5 proxy on localhost:\(actualPort) (userspace netstack)
      Gateway TUN: omerta-gw0  (10.0.0.1/16, kernel forwarding)
      Outbound:    \(detectedIface)

      Test with:
        curl -x socks5h://127.0.0.1:\(actualPort) http://example.com

      Press Ctrl+C to stop.
    ============================================================

    """)
    fflush(stdout)
}

// --- Shared: wait for signal, print stats, shutdown ---

signal(SIGINT, SIG_IGN)
signal(SIGTERM, SIG_IGN)
let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)

await withTaskGroup(of: Void.self) { group in
    group.addTask {
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(5))

            let ps = await peerRouter.getStats()
            let gs = await gwRouter.getStats()

            logger.info("""
            --- Stats --- \
            Peer Router: routed=\(ps.packetsRouted) toGW=\(ps.packetsToGateway) \
            fromPeers=\(ps.packetsFromPeers) dropped=\(ps.packetsDropped) | \
            GW Router: routed=\(gs.packetsRouted) toGW=\(gs.packetsToGateway) \
            fromPeers=\(gs.packetsFromPeers) dropped=\(gs.packetsDropped)
            """)
        }
    }

    group.addTask {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            var resumed = false
            sigintSource.setEventHandler {
                guard !resumed else { return }
                resumed = true
                cont.resume()
            }
            sigtermSource.setEventHandler {
                guard !resumed else { return }
                resumed = true
                cont.resume()
            }
            sigintSource.resume()
            sigtermSource.resume()
        }
    }

    await group.next()
    group.cancelAll()
}

// Shutdown
logger.info("Shutting down...")
if let proxy = socksProxy {
    await proxy.stop()
}
await peerRouter.stop()
await gwRouter.stop()
await peerTunnelManager.stop()
await gwTunnelManager.stop()
await relay.stopRelay()
if let tun = peerTun {
    await tun.stop()
}
if let adapter = gwTunAdapter {
    await adapter.stop()
    if let outIface = outInterface {
        KernelNetworking.disableMasquerade(tunName: "omerta-gw0", outInterface: outIface)
    }
}
logger.info("Done.")

#else
import Foundation
print("ERROR: DemoTUNGateway requires Linux.")
exit(1)
#endif
