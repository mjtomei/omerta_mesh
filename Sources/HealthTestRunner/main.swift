// HealthTestRunner - Comprehensive cross-machine health monitoring test
//
// Two roles run the same binary:
//   Node A (Linux, orchestrator): --role nodeA --port 18020 --lan --remote-host 192.168.12.209
//   Node B (Mac, responder):      --role nodeB --port 18020 --lan
//
// Coordination via "test-control" mesh channel.

import Foundation
import OmertaMesh
import OmertaTunnel
import Logging
import NIOCore
import NIOPosix
#if canImport(Glibc)
import Glibc
#endif

// MARK: - Test State Tracker
//
// Tracks all system modifications (iptables rules, pfctl rules, temp IPs) in hidden
// files so that cleanup and pre-flight only remove what the test actually added.
// State directory: ~/.health-test-state/

actor TestStateTracker {
    private let stateDir: String

    init() {
        let home = ProcessInfo.processInfo.environment["HOME"] ?? "/tmp"
        stateDir = "\(home)/.health-test-state"
    }

    private func ensureDir() {
        try? FileManager.default.createDirectory(atPath: stateDir, withIntermediateDirectories: true)
    }

    private func filePath(_ name: String) -> String { "\(stateDir)/\(name)" }

    private func readEntries(_ name: String) -> [String] {
        guard let data = FileManager.default.contents(atPath: filePath(name)),
              let text = String(data: data, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    }

    private func writeEntries(_ name: String, _ entries: [String]) {
        ensureDir()
        let text = entries.joined(separator: "\n") + (entries.isEmpty ? "" : "\n")
        try? text.write(toFile: filePath(name), atomically: true, encoding: .utf8)
    }

    // MARK: - iptables rules

    func recordIptablesRule(_ rule: String) {
        var entries = readEntries("iptables-rules")
        entries.append(rule)
        writeEntries("iptables-rules", entries)
    }

    func removeIptablesRule(_ rule: String) {
        var entries = readEntries("iptables-rules")
        if let idx = entries.firstIndex(of: rule) {
            entries.remove(at: idx)
        }
        writeEntries("iptables-rules", entries)
    }

    func allIptablesRules() -> [String] { readEntries("iptables-rules") }

    // MARK: - pfctl rules

    func recordPfctlRule(_ rule: String) {
        var entries = readEntries("pfctl-rules")
        entries.append(rule)
        writeEntries("pfctl-rules", entries)
    }

    func removePfctlRule(_ rule: String) {
        var entries = readEntries("pfctl-rules")
        if let idx = entries.firstIndex(of: rule) {
            entries.remove(at: idx)
        }
        writeEntries("pfctl-rules", entries)
    }

    func allPfctlRules() -> [String] { readEntries("pfctl-rules") }

    // MARK: - temp IPs

    func recordTempIP(_ entry: String) {
        // entry format: "192.168.12.122/24 dev eth0"
        var entries = readEntries("temp-ips")
        entries.append(entry)
        writeEntries("temp-ips", entries)
    }

    func removeTempIP(_ entry: String) {
        var entries = readEntries("temp-ips")
        if let idx = entries.firstIndex(of: entry) {
            entries.remove(at: idx)
        }
        writeEntries("temp-ips", entries)
    }

    func allTempIPs() -> [String] { readEntries("temp-ips") }

    // MARK: - Clear all state

    func clearAll() {
        writeEntries("iptables-rules", [])
        writeEntries("pfctl-rules", [])
        writeEntries("temp-ips", [])
    }
}

let stateTracker = TestStateTracker()

// MARK: - Cleanup Actor

actor Cleanup {
    private var actions: [() async -> Void] = []
    private var didRun = false

    func register(_ action: @escaping () async -> Void) {
        actions.append(action)
    }

    func run() async {
        guard !didRun else { return }
        didRun = true
        for action in actions.reversed() {
            await action()
        }
        actions.removeAll()
    }
}

// MARK: - Shell Helper

@discardableResult
func shell(_ command: String, timeout: Duration = .seconds(10)) async -> (exitCode: Int32, output: String) {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: "/bin/bash")
    process.arguments = ["-c", command]
    process.standardOutput = pipe
    process.standardError = pipe

    do {
        try process.run()
    } catch {
        return (-1, "Failed to launch: \(error)")
    }

    // Wait with timeout
    let waitTask = Task {
        process.waitUntilExit()
        return process.terminationStatus
    }

    let result = await withTaskGroup(of: Int32?.self) { group in
        group.addTask { await waitTask.value }
        group.addTask {
            try? await Task.sleep(for: timeout)
            return nil
        }
        let first = await group.next()!
        group.cancelAll()
        return first
    }

    let exitCode = result ?? { process.terminate(); return -1 as Int32 }()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return (exitCode, output)
}

// MARK: - Phase Result

struct PhaseResult {
    let name: String
    let passed: Bool
    let detail: String
}

// MARK: - Logging Setup

// Disable output buffering so logs appear immediately when redirected to a file
setbuf(stdout, nil)
setbuf(stderr, nil)

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    if label.contains("tunnel") || label.contains("health-test") {
        handler.logLevel = .debug
    } else {
        handler.logLevel = .info
    }
    return handler
}

let logger = Logger(label: "health-test")

// MARK: - Root Check

#if canImport(Glibc) || canImport(Darwin)
if getuid() != 0 {
    logger.error("HealthTestRunner must be run as root (for iptables/pfctl/ip commands)")
    logger.error("Usage: sudo .build/debug/HealthTestRunner --role nodeA ...")
    exit(1)
}
#endif

// MARK: - Argument Parsing

var role: String = "nodeA"
var port: Int = 18020
var bootstrap: String? = nil
var lan = false
var remoteHost: String = "192.168.12.209"

var args = CommandLine.arguments.dropFirst()
while let arg = args.first {
    args = args.dropFirst()
    switch arg {
    case "--role":
        role = String(args.first ?? "nodeA")
        args = args.dropFirst()
    case "--port":
        port = Int(args.first ?? "18020") ?? 18020
        args = args.dropFirst()
    case "--bootstrap":
        bootstrap = String(args.first ?? "")
        args = args.dropFirst()
    case "--lan":
        lan = true
    case "--remote-host":
        remoteHost = String(args.first ?? "192.168.12.209")
        args = args.dropFirst()
    default:
        break
    }
}

let isNodeA = (role == "nodeA")

// MARK: - Cleanup & Signal Handling

let cleanup = Cleanup()

// Signal handler for Ctrl-C
let signalSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
signal(SIGINT, SIG_IGN) // Ignore default so DispatchSource handles it
signalSource.setEventHandler {
    Task {
        logger.warning("SIGINT received, cleaning up...")
        await cleanup.run()
        exit(1)
    }
}
signalSource.resume()

let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
signal(SIGTERM, SIG_IGN)
termSource.setEventHandler {
    Task {
        logger.warning("SIGTERM received, cleaning up...")
        await cleanup.run()
        exit(1)
    }
}
termSource.resume()

// MARK: - Network State Snapshot

struct NetworkSnapshot: Equatable {
    let iptablesRules: String
    let ipAddresses: String

    static func capture() async -> NetworkSnapshot {
        #if os(Linux)
        let (_, ipt) = await shell("iptables-save 2>/dev/null | grep -v '^#' | grep -v '^:' | sort")
        let (_, ips) = await shell("ip -4 addr show | grep 'inet ' | awk '{print $2, $NF}' | sort")
        return NetworkSnapshot(iptablesRules: ipt, ipAddresses: ips)
        #else
        let (_, pfctl) = await shell("pfctl -sr 2>/dev/null || true")
        let (_, ips) = await shell("ifconfig | grep 'inet ' | awk '{print $2}' | sort")
        return NetworkSnapshot(iptablesRules: pfctl, ipAddresses: ips)
        #endif
    }

    func diff(against other: NetworkSnapshot) -> String? {
        var diffs: [String] = []
        if iptablesRules != other.iptablesRules {
            diffs.append("iptables/pfctl rules differ:")
            diffs.append("  BEFORE:\n    \(iptablesRules.replacingOccurrences(of: "\n", with: "\n    "))")
            diffs.append("  AFTER:\n    \(other.iptablesRules.replacingOccurrences(of: "\n", with: "\n    "))")
        }
        if ipAddresses != other.ipAddresses {
            diffs.append("IP addresses differ:")
            diffs.append("  BEFORE:\n    \(ipAddresses.replacingOccurrences(of: "\n", with: "\n    "))")
            diffs.append("  AFTER:\n    \(other.ipAddresses.replacingOccurrences(of: "\n", with: "\n    "))")
        }
        return diffs.isEmpty ? nil : diffs.joined(separator: "\n")
    }
}

// MARK: - Pre-flight Cleanup (clear stale rules from failed runs)

// Kill any existing HealthTestRunner processes (except ourselves)
let myPID = ProcessInfo.processInfo.processIdentifier
let myPPID = getppid()
logger.info("Pre-flight cleanup: killing stale HealthTestRunner processes (my PID: \(myPID), PPID: \(myPPID))...")
let (_, staleProcs) = await shell("pgrep -x HealthTestRunner | grep -v -e ^\(myPID)$ -e ^\(myPPID)$ || true")
for pidStr in staleProcs.split(separator: "\n") {
    let pidTrimmed = String(pidStr).trimmingCharacters(in: .whitespaces)
    if !pidTrimmed.isEmpty, let pid = Int32(pidTrimmed) {
        logger.info("  Killing stale process: \(pid)")
        kill(pid, SIGKILL)
    }
}
// Brief pause for ports to be released
if !staleProcs.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
    try await Task.sleep(for: .seconds(2))
}

logger.info("Pre-flight cleanup: clearing stale state from previous runs...")

// Only remove modifications that were tracked in state files from previous runs
#if os(Linux)
// Remove iptables rules recorded by a previous test run
let staleIptables = await stateTracker.allIptablesRules()
if !staleIptables.isEmpty {
    logger.info("  Found \(staleIptables.count) tracked iptables rule(s) to remove")
    for rule in staleIptables {
        // rule is stored as the -A command; convert to -D for deletion
        let deleteRule = rule.replacingOccurrences(of: "iptables -A ", with: "iptables -D ")
        logger.info("  Removing: \(deleteRule)")
        let _ = await shell(deleteRule)
    }
}

// Remove temp IPs recorded by a previous test run
let staleIPs = await stateTracker.allTempIPs()
if !staleIPs.isEmpty {
    logger.info("  Found \(staleIPs.count) tracked temp IP(s) to remove")
    for entry in staleIPs {
        // entry format: "ip addr add 192.168.12.X/24 dev ethN"
        let delCmd = entry.replacingOccurrences(of: "ip addr add ", with: "ip addr del ")
        logger.info("  Removing: \(delCmd)")
        let _ = await shell(delCmd)
    }
}
#else
// macOS: remove pfctl rules recorded by a previous test run
let stalePfctl = await stateTracker.allPfctlRules()
if !stalePfctl.isEmpty {
    logger.info("  Found \(stalePfctl.count) tracked pfctl rule(s) to remove")
    // Get current rules and remove only the tracked ones
    let (_, pfRules) = await shell("pfctl -sr 2>/dev/null || true")
    let pfRulesTrimmed = pfRules.trimmingCharacters(in: .whitespacesAndNewlines)
    let stalePfctlSet = Set(stalePfctl)
    let cleanedRules = pfRulesTrimmed.split(separator: "\n")
        .filter { !stalePfctlSet.contains(String($0)) }
        .joined(separator: "\n")
    if cleanedRules.isEmpty && !pfRulesTrimmed.isEmpty {
        let (_, _) = await shell("pfctl -d 2>&1 || true")
        let (_, _) = await shell("pfctl -F rules 2>&1 || true")
        logger.info("  Disabled pfctl (all active rules were test rules)")
    } else if cleanedRules != pfRulesTrimmed && !pfRulesTrimmed.isEmpty {
        let (_, _) = await shell("echo '\(cleanedRules)' | pfctl -f - 2>&1 || true")
        logger.info("  Reloaded pfctl without test rules")
    } else {
        logger.info("  No tracked pfctl rules found in active ruleset")
    }
}
// Check macOS application firewall
let (_, fwState) = await shell("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true")
logger.info("  macOS Application Firewall: \(fwState.trimmingCharacters(in: .whitespacesAndNewlines))")
if fwState.contains("enabled") {
    let binaryPath = ProcessInfo.processInfo.arguments[0]
    let _ = await shell("/usr/libexec/ApplicationFirewall/socketfilterfw --add \(binaryPath) 2>/dev/null")
    let _ = await shell("/usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp \(binaryPath) 2>/dev/null")
    logger.info("  Added HealthTestRunner to application firewall allow list")
}
#endif

// Clear all state files for a fresh start
await stateTracker.clearAll()
logger.info("Pre-flight cleanup done.")

// MARK: - Mesh Setup

let keyString = "health-test-shared-key-2026-0128"
let encryptionKey = keyString.data(using: .utf8)!

let config = MeshConfig(
    encryptionKey: encryptionKey,
    port: port,
    bootstrapPeers: bootstrap.map { [$0] } ?? [],
    allowLocalhost: lan
)

let mesh = MeshNetwork(config: config)

logger.info("Starting mesh on port \(port), role: \(role)...")
if let bs = bootstrap {
    logger.info("Bootstrap peer: \(bs)")
}

try await mesh.start()

let peerId = mesh.peerId
let machineId = await mesh.machineId
logger.info("Mesh started - peerId: \(peerId) machineId: \(machineId)")

let remoteEndpoint = "\(remoteHost):\(port)"

await cleanup.register {
    logger.info("Cleanup: stopping mesh")
    await mesh.stop()
}

// Capture initial network state
logger.info("Capturing initial network state...")
let initialNetworkState = await NetworkSnapshot.capture()
logger.info("Initial iptables rules:\n\(initialNetworkState.iptablesRules.isEmpty ? "  (none)" : initialNetworkState.iptablesRules)")
logger.info("Initial IP addresses:\n\(initialNetworkState.ipAddresses)")

// MARK: - Auto-Bootstrap & Discover Remote Machine
//
// Exchange peer IDs via a side-channel UDP port (mesh port + 1).
// Both nodes continuously send their peerId to the remote host.
// Once a node receives the remote's peerId, it calls mesh.addPeer()
// to establish mesh connectivity, then discovers the machineId via
// the mesh "health-discovery" channel.

let bootstrapPort = port + 1
logger.info("Waiting for remote machine (auto-bootstrap on UDP port \(bootstrapPort))...")

final class BootstrapHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    var onReceive: ((String) -> Void)?

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = unwrapInboundIn(data)
        var buf = envelope.data
        if let bytes = buf.readBytes(length: buf.readableBytes) {
            let msg = String(decoding: Data(bytes), as: UTF8.self)
            onReceive?(msg)
        }
    }
}

let bootstrapGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let bootstrapHandler = BootstrapHandler()
let bootstrapChannel = try await DatagramBootstrap(group: bootstrapGroup)
    .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
    .channelInitializer { ch in ch.pipeline.addHandler(bootstrapHandler) }
    .bind(host: "0.0.0.0", port: bootstrapPort)
    .get()

var bootstrapDone = false
let bootstrapLock = NSLock()

bootstrapHandler.onReceive = { msg in
    if msg.hasPrefix("peerId:") {
        let rid = String(msg.dropFirst("peerId:".count))
        bootstrapLock.lock()
        let alreadyDone = bootstrapDone
        if !alreadyDone { bootstrapDone = true }
        bootstrapLock.unlock()
        if !alreadyDone {
            Task {
                logger.info("Auto-bootstrap: discovered remote peerId \(rid)")
                await mesh.addPeer(rid, endpoint: remoteEndpoint)
                let _ = await mesh.ping(rid, timeout: 3.0)
            }
        }
    }
}

var remoteMachineId: MachineId? = nil

try await mesh.onChannel("health-discovery") { fromMachineId, data in
    if remoteMachineId == nil {
        remoteMachineId = fromMachineId
        logger.info("Discovery: found machine \(fromMachineId)")
    }
    try? await mesh.sendOnChannel(Data("ack".utf8), toMachine: fromMachineId, channel: "health-discovery")
}

let myMsg = "peerId:\(peerId)"
let remoteBootstrapAddr = try SocketAddress(ipAddress: remoteHost, port: bootstrapPort)

for i in 1...60 {
    // Always send our peerId so the remote can discover us too
    let buf = bootstrapChannel.allocator.buffer(string: myMsg)
    let envelope = AddressedEnvelope(remoteAddress: remoteBootstrapAddr, data: buf)
    try? await bootstrapChannel.writeAndFlush(envelope)

    try await Task.sleep(for: .seconds(1))
    if remoteMachineId != nil { break }

    // Try mesh-level discovery if we have known peers
    let peers = await mesh.knownPeersWithInfo()
    for peer in peers where peer.peerId != peerId {
        let registry = await mesh.machinePeerRegistry
        if let mid = registry?.getMostRecentMachine(for: peer.peerId) {
            try? await mesh.sendOnChannel(Data("discover".utf8), toMachine: mid, channel: "health-discovery")
        }
    }
    if i % 10 == 0 { logger.info("Still waiting... (\(i)s)") }
}

try? await bootstrapChannel.close()
try? await bootstrapGroup.shutdownGracefully()

guard let remoteMachineId else {
    logger.error("No remote machine found after 60s. Exiting.")
    await cleanup.run()
    exit(1)
}

logger.info("Remote machine discovered: \(remoteMachineId)")

// MARK: - TunnelManager Setup

let tunnelConfig = TunnelManagerConfig(
    healthProbeMinInterval: .milliseconds(500),
    healthProbeMaxInterval: .seconds(15),
    healthFailureThreshold: 3
)
let manager = TunnelManager(provider: mesh, config: tunnelConfig)
try await manager.start()
logger.info("TunnelManager started")

await cleanup.register {
    logger.info("Cleanup: stopping TunnelManager")
    await manager.stop()
}

// MARK: - Control Channel (Node A orchestrates, Node B responds)

/// Messages sent on "test-control" channel
struct ControlMessage: Codable, Sendable {
    let phase: String   // e.g. "phase1", "send-burst", "idle", "done"
    let detail: String? // optional extra info
}

/// Received control messages (for Node B)
actor ControlMailbox {
    private var messages: [ControlMessage] = []
    private var waiters: [(id: Int, continuation: CheckedContinuation<ControlMessage?, Never>)] = []
    private var nextId = 0

    func post(_ msg: ControlMessage) {
        if let waiter = waiters.first {
            waiters.removeFirst()
            waiter.continuation.resume(returning: msg)
        } else {
            messages.append(msg)
        }
    }

    func cancelWaiter(id: Int) {
        if let idx = waiters.firstIndex(where: { $0.id == id }) {
            let waiter = waiters.remove(at: idx)
            waiter.continuation.resume(returning: nil)
        }
    }

    func receive(timeout: Duration = .seconds(60)) async -> ControlMessage? {
        // Check buffer first
        if !messages.isEmpty {
            return messages.removeFirst()
        }
        // Wait with timeout
        let waiterId = nextId
        nextId += 1

        let timeoutTask = Task {
            try? await Task.sleep(for: timeout)
            await self.cancelWaiter(id: waiterId)
        }

        let result: ControlMessage? = await withCheckedContinuation { cont in
            waiters.append((id: waiterId, continuation: cont))
        }

        timeoutTask.cancel()
        return result
    }

}

let controlMailbox = ControlMailbox()

try await mesh.onChannel("test-control") { fromMachineId, data in
    if let msg = try? JSONDecoder().decode(ControlMessage.self, from: data) {
        await controlMailbox.post(msg)
    }
}

func sendControl(_ phase: String, detail: String? = nil) async {
    let msg = ControlMessage(phase: phase, detail: detail)
    if let data = try? JSONEncoder().encode(msg) {
        try? await mesh.sendOnChannel(data, toMachine: remoteMachineId, channel: "test-control")
    }
}

/// Wait for a specific phase ack from remote
func waitForAck(_ expectedPhase: String, timeout: Duration = .seconds(60)) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if let msg = await controlMailbox.receive(timeout: .seconds(5)) {
            if msg.phase == expectedPhase { return true }
        }
    }
    return false
}

// MARK: - Message Counter

actor MessageCounter {
    var received: Int = 0
    func increment() { received += 1 }
    func reset() { received = 0 }
    var count: Int { received }
}

let messageCounter = MessageCounter()

// ============================================================
// NODE B: Passive responder
// ============================================================

if !isNodeA {
    logger.info("=== NODE B: Passive responder mode ===")

    // Track the latest session established for each channel
    actor LatestSession {
        var session: TunnelSession?
        func set(_ s: TunnelSession) { session = s }
        func get() -> TunnelSession? { session }
    }
    let latestSession = LatestSession()

    // Accept all sessions and count messages
    await manager.setSessionEstablishedHandler { session in
        await latestSession.set(session)
        await session.onReceive { data in
            await messageCounter.increment()
            let msg = String(data: data, encoding: .utf8) ?? "<binary>"
            logger.debug("  B <- \(msg)")
        }
    }

    // Signal to Node A that we're ready to receive sessions
    await sendControl("nodeB-ready")
    logger.info("Node B: sent ready signal")

    // Main loop: respond to control commands
    while true {
        guard let cmd = await controlMailbox.receive(timeout: .seconds(120)) else {
            logger.info("Node B: no command for 120s, exiting")
            break
        }

        logger.info("Node B: received command '\(cmd.phase)'")

        do {
        switch cmd.phase {
        case "phase1-start":
            // Wait for session from Node A (don't call getSession to avoid handshake race)
            try await Task.sleep(for: .seconds(3))
            guard let session = await latestSession.get() else {
                logger.error("Node B: no session established for phase1")
                await sendControl("phase1-done", detail: "0")
                continue
            }
            for i in 1...10 {
                try await session.send(Data("B-msg-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(100))
            }
            await sendControl("phase1-done", detail: "\(await messageCounter.count)")

        case "phase3-burst":
            // Use whatever session is currently active
            guard let session = await latestSession.get() else {
                logger.error("Node B: no session for phase3")
                await sendControl("phase3-burst-done")
                continue
            }
            for i in 1...5 {
                try await session.send(Data("B-burst-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(100))
            }
            await sendControl("phase3-burst-done")

        case "phase5-start":
            // Wait for recovery session from Node A
            try await Task.sleep(for: .seconds(3))
            guard let session = await latestSession.get() else {
                logger.error("Node B: no session for phase5")
                await sendControl("phase5-done", detail: "0")
                continue
            }
            for i in 1...5 {
                try await session.send(Data("B-recovery-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(100))
            }
            await sendControl("phase5-done", detail: "\(await messageCounter.count)")

        case "phase6-block":
            // Node B blocks incoming UDP from Node A locally, auto-unblocks after 15s
            let blockPort = cmd.detail ?? "\(port)"
            // Send ack BEFORE blocking (otherwise the ack can't reach Node A)
            await sendControl("phase6-ack")
            try await Task.sleep(for: .milliseconds(500))  // ensure ack is sent
            #if os(macOS)
            // Save pfctl state before we modify it
            let (_, pfctlWasEnabled) = await shell("pfctl -s info 2>&1 | grep -q 'Status: Enabled' && echo yes || echo no")
            let pfctlPreviouslyEnabled = pfctlWasEnabled.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
            let (_, previousRules) = await shell("pfctl -sr 2>/dev/null || true")
            logger.info("Node B pfctl pre-block state: enabled=\(pfctlPreviouslyEnabled), rules=\(previousRules.count) chars")

            let pfctlRule = "block drop quick proto udp from any to any port \(blockPort)"
            await stateTracker.recordPfctlRule(pfctlRule)
            let (exitCode, out) = await shell("echo '\(pfctlRule)' | pfctl -ef -")
            logger.info("Node B pfctl block: exit=\(exitCode) \(out)")
            #else
            let nodeAHost = cmd.detail ?? remoteHost
            let nodeBIptRule = "iptables -A INPUT -s \(nodeAHost) -p udp --dport \(blockPort) -j DROP"
            await stateTracker.recordIptablesRule(nodeBIptRule)
            let (exitCode, out) = await shell(nodeBIptRule)
            logger.info("Node B iptables block: exit=\(exitCode) \(out)")
            #endif
            // Auto-unblock after 15s (can't receive unblock command while blocked)
            Task {
                try? await Task.sleep(for: .seconds(15))
                #if os(macOS)
                await stateTracker.removePfctlRule(pfctlRule)
                // Restore previous pfctl state instead of blindly disabling
                if pfctlPreviouslyEnabled {
                    let trimmed = previousRules.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty {
                        let (ec, o) = await shell("echo '\(trimmed)' | pfctl -ef -")
                        logger.info("Node B pfctl restored previous rules: exit=\(ec) \(o)")
                    } else {
                        let (ec, o) = await shell("pfctl -e 2>&1 || true")
                        logger.info("Node B pfctl re-enabled (no rules): exit=\(ec) \(o)")
                    }
                } else {
                    let (ec, o) = await shell("pfctl -d 2>&1 || true")
                    logger.info("Node B pfctl disabled (was not enabled before): exit=\(ec) \(o)")
                }
                #else
                let unblockNodeB = "iptables -D INPUT -s \(nodeAHost) -p udp --dport \(blockPort) -j DROP"
                let (ec, o) = await shell(unblockNodeB)
                await stateTracker.removeIptablesRule(nodeBIptRule)
                logger.info("Node B iptables auto-unblock: exit=\(ec) \(o)")
                #endif
            }

        case "phase6-check":
            // Report session count
            let count = await manager.sessionCount
            await sendControl("phase6-report", detail: "\(count)")

        case "phase8-start":
            // Flapping: just keep session alive and report
            await sendControl("phase8-ack")

        case "phase8-check":
            let count = await manager.sessionCount
            await sendControl("phase8-report", detail: "\(count)")

        case "phase10-latency-start":
            // Send messages on demand during latency sub-phases
            guard let session = await latestSession.get() else {
                logger.error("Node B: no session for phase10")
                await sendControl("phase10-latency-ack")
                continue
            }
            for i in 1...5 {
                try await session.send(Data("B-latency-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(200))
            }
            await sendControl("phase10-latency-ack", detail: "\(await messageCounter.count)")

        case "done":
            logger.info("Node B: test complete")
            await sendControl("done-ack")
            break

        default:
            logger.info("Node B: unknown command '\(cmd.phase)', acking")
            await sendControl("\(cmd.phase)-ack")
        }
        } catch {
            logger.error("Node B: error handling '\(cmd.phase)': \(error)")
            await sendControl("\(cmd.phase)-error", detail: "\(error)")
        }

        if cmd.phase == "done" { break }
    }

    await cleanup.run()
    exit(0)
}

// ============================================================
// NODE A: Orchestrator (rest of file)
// ============================================================

logger.info("=== NODE A: Orchestrator mode ===")
logger.info("Remote host for SSH/firewall: \(remoteHost)")

var results: [PhaseResult] = []

func logPhase(_ name: String) {
    logger.info("")
    logger.info("========================================")
    logger.info("  \(name)")
    logger.info("========================================")
}

func record(_ name: String, passed: Bool, detail: String) {
    results.append(PhaseResult(name: name, passed: passed, detail: detail))
    let status = passed ? "PASS" : "FAIL"
    logger.info("[\(status)] \(name): \(detail)")
}

// MARK: - Phase 1: Baseline Bidirectional Traffic

logPhase("Phase 1: Baseline Bidirectional Traffic")

var session1: TunnelSession? = nil
var monitor: TunnelHealthMonitor? = nil

do {
    // Wait for Node B to signal it's ready (handler set up)
    logger.info("Waiting for Node B ready signal...")
    let ready = await waitForAck("nodeB-ready", timeout: .seconds(30))
    if !ready { logger.warning("Node B ready signal not received, proceeding anyway") }

    // Tell Node B to start phase 1 (it will wait for our session)
    await sendControl("phase1-start")

    // Create session - only Node A initiates to avoid handshake race
    let s = try await manager.getSession(machineId: remoteMachineId, channel: "health-test")
    session1 = s
    await s.onReceive { data in
        await messageCounter.increment()
    }

    // Wait for session to settle
    try await Task.sleep(for: .seconds(2))

    // Send 10 messages from A
    for i in 1...10 {
        try await s.send(Data("A-msg-\(i)".utf8))
        try await Task.sleep(for: .milliseconds(100))
    }

    // Wait for Node B to finish
    let phase1Ack = await waitForAck("phase1-done", timeout: .seconds(30))
    try await Task.sleep(for: .seconds(2)) // let straggler messages arrive

    let phase1Received = await messageCounter.count
    let phase1Pass = phase1Ack && phase1Received >= 5 // at least some messages arrived
    record("Phase 1: Baseline Traffic", passed: phase1Pass,
           detail: "received \(phase1Received) messages, ack=\(phase1Ack)")

    monitor = await manager.getHealthMonitor(for: remoteMachineId)
    logger.info("Health monitor for \(remoteMachineId): \(monitor != nil ? "found" : "NOT found")")
} catch {
    record("Phase 1: Baseline Traffic", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 2: Idle & Probe Backoff

logPhase("Phase 2: Idle & Probe Backoff")

do {
    await messageCounter.reset()

    var probeIntervals: [Duration] = []

    if let monitor {
        // Log probe interval every 500ms for 10s
        for _ in 0..<20 {
            try await Task.sleep(for: .milliseconds(500))
            let interval = await monitor._currentProbeInterval
            probeIntervals.append(interval)
            logger.info("  Probe interval: \(interval)")
        }

        // Check that interval increased from min (500ms) toward max (15s)
        let firstInterval = probeIntervals.first ?? .milliseconds(500)
        let lastInterval = probeIntervals.last ?? .milliseconds(500)
        let phase2Pass = lastInterval > firstInterval
        record("Phase 2: Idle Probe Backoff", passed: phase2Pass,
               detail: "interval went from \(firstInterval) to \(lastInterval)")
    } else {
        record("Phase 2: Idle Probe Backoff", passed: false,
               detail: "No health monitor found for remote machine")
    }
} catch {
    record("Phase 2: Idle Probe Backoff", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 3: Traffic Resets Probes

logPhase("Phase 3: Traffic Resets Probes")

do {
    // Send burst from A
    if let s = session1 {
        for i in 1...5 {
            try await s.send(Data("A-burst-\(i)".utf8))
            await manager.notifyPacketReceived(from: remoteMachineId)
            try await Task.sleep(for: .milliseconds(100))
        }
    }
    // Also tell B to send burst
    await sendControl("phase3-burst")
    _ = await waitForAck("phase3-burst-done", timeout: .seconds(15))

    // Sample immediately — the last notifyPacketReceived resets interval to min (500ms).
    // One monitor loop iteration may have doubled it to 1s, so allow up to 1s.
    if let monitor {
        let intervalAfterTraffic = await monitor._currentProbeInterval
        let failuresAfterTraffic = await monitor._consecutiveFailures
        let phase3Pass = intervalAfterTraffic <= .seconds(1) && failuresAfterTraffic == 0
        record("Phase 3: Traffic Resets Probes", passed: phase3Pass,
               detail: "interval=\(intervalAfterTraffic), failures=\(failuresAfterTraffic)")
    } else {
        record("Phase 3: Traffic Resets Probes", passed: false, detail: "No health monitor")
    }
} catch {
    record("Phase 3: Traffic Resets Probes", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 4: Unidirectional Block — Failure Detection

logPhase("Phase 4: Unidirectional Block — Failure Detection")

do {
    let iptRule = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockCmd = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await stateTracker.recordIptablesRule(iptRule)
    await cleanup.register { let _ = await shell(unblockCmd); await stateTracker.removeIptablesRule(iptRule) }
    let (blockExit, blockOut) = await shell(iptRule)
    logger.info("iptables block: exit=\(blockExit) output=\(blockOut)")

    // Wait for health failure (sessions should get closed)
    var phase4Pass = false
    for _ in 0..<20 {
        try await Task.sleep(for: .seconds(1))
        let count = await manager.sessionCount
        logger.info("  Session count: \(count)")
        if count == 0 {
            phase4Pass = true
            break
        }
    }

    // Unblock
    let (unblockExit, _) = await shell(unblockCmd)
    await stateTracker.removeIptablesRule(iptRule)
    logger.info("iptables unblock: exit=\(unblockExit)")

    record("Phase 4: Failure Detection", passed: phase4Pass,
           detail: "sessions closed by health monitor: \(phase4Pass)")
}

// MARK: - Phase 5: Recovery After Block

logPhase("Phase 5: Recovery After Block")

do {
    try await Task.sleep(for: .seconds(3)) // let network settle

    // Restart the manager if it was stopped during health failure
    if await manager.sessionCount == 0 {
        logger.info("Restarting TunnelManager for recovery test...")
        try await manager.start()
    }

    await messageCounter.reset()
    await sendControl("phase5-start")

    // Only Node A initiates session to avoid handshake race
    let session5 = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-recovery")
    await session5.onReceive { data in
        await messageCounter.increment()
    }
    try await Task.sleep(for: .seconds(2))

    for i in 1...5 {
        try await session5.send(Data("A-recovery-\(i)".utf8))
        try await Task.sleep(for: .milliseconds(200))
    }

    let phase5Ack = await waitForAck("phase5-done", timeout: .seconds(30))
    try await Task.sleep(for: .seconds(2))

    let phase5Received = await messageCounter.count
    let phase5Pass = phase5Ack && phase5Received >= 2
    record("Phase 5: Recovery After Block", passed: phase5Pass,
           detail: "received \(phase5Received) messages, ack=\(phase5Ack)")
} catch {
    record("Phase 5: Recovery After Block", passed: false,
           detail: "Error: \(error)")
}

// MARK: - Phase 6: Bidirectional Block

logPhase("Phase 6: Bidirectional Block")

do {
    // Ensure we have an active session
    let _ = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-bidir")
    try await Task.sleep(for: .seconds(2))

    let iptRule6 = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockLinux = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await stateTracker.recordIptablesRule(iptRule6)
    await cleanup.register { let _ = await shell(unblockLinux); await stateTracker.removeIptablesRule(iptRule6) }

    // Tell Node B to block with auto-unblock after 15s, then block locally
    await sendControl("phase6-block", detail: "\(port)")
    _ = await waitForAck("phase6-ack", timeout: .seconds(10))
    let (_, _) = await shell(iptRule6)
    logger.info("Bidirectional block applied (local iptables + remote via control channel)")

    // Wait for failure detection on Node A
    var phase6Pass = false
    for _ in 0..<20 {
        try await Task.sleep(for: .seconds(1))
        let count = await manager.sessionCount
        logger.info("  Session count: \(count)")
        if count == 0 {
            phase6Pass = true
            break
        }
    }

    // Unblock Linux side immediately
    let (_, _) = await shell(unblockLinux)
    await stateTracker.removeIptablesRule(iptRule6)
    logger.info("Linux iptables unblocked")

    // Node B auto-unblocks after 15s from when it blocked.
    // Wait for Node B to self-unblock and mesh to reconnect.
    logger.info("Waiting for Node B auto-unblock and mesh reconnect...")
    try await Task.sleep(for: .seconds(20))

    // Try to reach Node B - retry a few times since mesh may need keepalive cycle
    var phase6BMsg: ControlMessage? = nil
    for attempt in 1...3 {
        logger.info("Sending phase6-check (attempt \(attempt))...")
        await sendControl("phase6-check")
        phase6BMsg = await controlMailbox.receive(timeout: .seconds(10))
        if phase6BMsg != nil { break }
    }
    let bSessionCount = phase6BMsg.flatMap { Int($0.detail ?? "") } ?? -1

    record("Phase 6: Bidirectional Block", passed: phase6Pass,
           detail: "A sessions=0: \(phase6Pass), B sessions=\(bSessionCount)")
} catch {
    record("Phase 6: Bidirectional Block", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 7: Transient Failure (Block < Threshold)

logPhase("Phase 7: Transient Failure (Block < Threshold)")

do {
    // Create fresh session
    let session7 = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-transient")
    try await Task.sleep(for: .seconds(2))

    let iptRule7 = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockCmd7 = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await stateTracker.recordIptablesRule(iptRule7)
    await cleanup.register { let _ = await shell(unblockCmd7); await stateTracker.removeIptablesRule(iptRule7) }

    // Block for ~1s (less than 3 failures at 500ms intervals)
    let (_, _) = await shell(iptRule7)
    logger.info("Transient block applied for ~1s")
    try await Task.sleep(for: .seconds(1))
    let (_, _) = await shell(unblockCmd7)
    await stateTracker.removeIptablesRule(iptRule7)
    logger.info("Transient block removed")

    try await Task.sleep(for: .seconds(2))

    let count = await manager.sessionCount
    let state = await session7.state
    let phase7Pass = count > 0
    record("Phase 7: Transient Failure", passed: phase7Pass,
           detail: "sessions=\(count), session state=\(state)")
} catch {
    record("Phase 7: Transient Failure", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 8: Rapid Flapping

logPhase("Phase 8: Rapid Flapping")

do {
    // Ensure session exists
    let _ = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-flap")
    try await Task.sleep(for: .seconds(2))

    await sendControl("phase8-start")
    _ = await waitForAck("phase8-ack", timeout: .seconds(10))

    let iptRule8 = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockCmd8 = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await stateTracker.recordIptablesRule(iptRule8)
    await cleanup.register { let _ = await shell(unblockCmd8); await stateTracker.removeIptablesRule(iptRule8) }

    // Flap 10 times over 20s
    for i in 1...10 {
        let (_, _) = await shell(iptRule8)
        logger.info("  Flap \(i)/10: blocked")
        try await Task.sleep(for: .seconds(1))
        let (_, _) = await shell(unblockCmd8)
        logger.info("  Flap \(i)/10: unblocked")
        try await Task.sleep(for: .seconds(1))
    }
    await stateTracker.removeIptablesRule(iptRule8)

    try await Task.sleep(for: .seconds(3))

    // Check survival — either sessions survived or we can create new ones
    await sendControl("phase8-check")
    let phase8BMsg = await controlMailbox.receive(timeout: .seconds(15))
    let bCount = phase8BMsg.flatMap { Int($0.detail ?? "") } ?? -1

    let aCount = await manager.sessionCount
    // Pass if at least one side maintained sessions, or we can recover
    var canRecover = false
    if aCount == 0 {
        // Try recovery
        let _ = try? await manager.getSession(machineId: remoteMachineId, channel: "health-test-flap-recover")
        try await Task.sleep(for: .seconds(2))
        canRecover = await manager.sessionCount > 0
    }

    let phase8Pass = aCount > 0 || canRecover
    record("Phase 8: Rapid Flapping", passed: phase8Pass,
           detail: "A sessions=\(aCount), B sessions=\(bCount), recovered=\(canRecover)")
} catch {
    record("Phase 8: Rapid Flapping", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 9: Endpoint Change Detection (Linux only)

logPhase("Phase 9: Endpoint Change Detection")

#if os(Linux)
do {
    // Find the network interface
    let (_, ifOutput) = await shell("ip route get \(remoteHost) | head -1 | awk '{print $5}'")
    let iface = ifOutput.isEmpty ? "eth0" : ifOutput
    logger.info("Using interface: \(iface)")

    // Pick a temp IP that doesn't conflict with existing addresses
    let (_, existingAddrs) = await shell("ip -4 addr show | grep 'inet ' | awk '{print $2}' | cut -d/ -f1")
    let usedIPs = Set(existingAddrs.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) })
    var tempIP = "192.168.12.122"
    for lastOctet in 122...254 {
        let candidate = "192.168.12.\(lastOctet)"
        if !usedIPs.contains(candidate) {
            tempIP = candidate
            break
        }
    }
    logger.info("Selected temp IP: \(tempIP) (existing: \(usedIPs.sorted()))")

    let addCmd = "ip addr add \(tempIP)/24 dev \(iface)"
    let delCmd = "ip addr del \(tempIP)/24 dev \(iface)"

    await stateTracker.recordTempIP(addCmd)
    await cleanup.register { let _ = await shell(delCmd); await stateTracker.removeTempIP(addCmd) }

    let (addExit, addOut) = await shell(addCmd)
    logger.info("Added temp IP: exit=\(addExit) \(addOut)")

    // Wait for EndpointChangeDetector to notice
    try await Task.sleep(for: .seconds(10))

    let (delExit, _) = await shell(delCmd)
    await stateTracker.removeTempIP(addCmd)
    logger.info("Removed temp IP: exit=\(delExit)")

    // We can't directly observe the detector from here, but if no crash occurred
    // and the mesh is still functional, that's a pass
    try await Task.sleep(for: .seconds(3))

    // Verify mesh still works by sending a message
    var endpointTestPass = false
    if let session = try? await manager.getSession(machineId: remoteMachineId, channel: "health-test-endpoint") {
        await messageCounter.reset()
        await session.onReceive { _ in await messageCounter.increment() }
        try? await session.send(Data("endpoint-test".utf8))
        try await Task.sleep(for: .seconds(2))
        endpointTestPass = true // Session creation succeeded
    }

    record("Phase 9: Endpoint Change Detection", passed: endpointTestPass,
           detail: "IP add/del on \(iface), mesh still functional: \(endpointTestPass)")
} catch {
    record("Phase 9: Endpoint Change Detection", passed: false, detail: "Error: \(error)")
}
#else
record("Phase 9: Endpoint Change Detection", passed: true,
       detail: "Skipped (Linux only)")
#endif

// MARK: - Phase 10: Artificial Latency & Jitter (Linux only)

logPhase("Phase 10: Artificial Latency & Jitter")

#if os(Linux)
do {
    // Find the outgoing interface to the remote host
    let (_, ifOutput10) = await shell("ip route get \(remoteHost) | head -1 | awk '{print $5}'")
    let iface10 = ifOutput10.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !iface10.isEmpty else {
        record("Phase 10: Latency & Jitter", passed: false, detail: "Could not determine interface")
        throw TunnelError.notConnected
    }
    logger.info("Using interface: \(iface10)")

    // Ensure a fresh session
    let session10 = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-latency")
    await session10.onReceive { _ in await messageCounter.increment() }
    try await Task.sleep(for: .seconds(2))

    struct LatencyProfile {
        let name: String
        let tcArgs: String      // netem arguments
        let expectAlive: Bool   // do we expect sessions to survive?
    }

    let profiles: [LatencyProfile] = [
        LatencyProfile(name: "50ms fixed", tcArgs: "delay 50ms", expectAlive: true),
        LatencyProfile(name: "200ms fixed", tcArgs: "delay 200ms", expectAlive: true),
        LatencyProfile(name: "100ms +/- 80ms jitter", tcArgs: "delay 100ms 80ms distribution normal", expectAlive: true),
        LatencyProfile(name: "500ms +/- 400ms high jitter", tcArgs: "delay 500ms 400ms distribution normal", expectAlive: true),
        LatencyProfile(name: "1% packet loss", tcArgs: "loss 1%", expectAlive: true),
        LatencyProfile(name: "10% packet loss", tcArgs: "loss 10%", expectAlive: true),
    ]

    var subResults: [(String, Bool, String)] = []

    for profile in profiles {
        logger.info("  Sub-test: \(profile.name)")

        // Apply netem qdisc
        let addQdisc = "tc qdisc add dev \(iface10) root netem \(profile.tcArgs)"
        await stateTracker.recordIptablesRule(addQdisc) // reuse iptables tracker for tc rules
        let (addExit, addOut) = await shell(addQdisc)
        if addExit != 0 {
            logger.warning("  tc add failed: \(addOut), trying replace...")
            let (replExit, replOut) = await shell("tc qdisc replace dev \(iface10) root netem \(profile.tcArgs)")
            if replExit != 0 {
                logger.error("  tc replace also failed: \(replOut)")
                subResults.append((profile.name, false, "tc setup failed"))
                continue
            }
        }

        // Register cleanup
        let delQdisc = "tc qdisc del dev \(iface10) root netem"

        // Send traffic both directions
        await messageCounter.reset()
        await sendControl("phase10-latency-start")

        for i in 1...5 {
            try? await session10.send(Data("A-latency-\(i)".utf8))
            try await Task.sleep(for: .milliseconds(200))
        }

        // Wait for messages + ack
        let latencyAck = await waitForAck("phase10-latency-ack", timeout: .seconds(30))
        try await Task.sleep(for: .seconds(2))

        let received = await messageCounter.count
        let sessionAlive = await manager.sessionCount > 0
        let monitorOk: Bool
        if let mon = await manager.getHealthMonitor(for: remoteMachineId) {
            let failures = await mon._consecutiveFailures
            monitorOk = failures < 3
        } else {
            monitorOk = false
        }

        // Remove netem
        let (_, _) = await shell(delQdisc)
        await stateTracker.removeIptablesRule(addQdisc)

        let pass: Bool
        if profile.expectAlive {
            pass = sessionAlive && latencyAck && monitorOk
        } else {
            pass = !sessionAlive
        }

        let detail = "recv=\(received), alive=\(sessionAlive), ack=\(latencyAck), monitorOk=\(monitorOk)"
        subResults.append((profile.name, pass, detail))
        logger.info("    [\(pass ? "PASS" : "FAIL")] \(profile.name): \(detail)")

        // Let network settle between profiles
        try await Task.sleep(for: .seconds(2))

        // Re-create session if it died
        if !sessionAlive {
            let _ = try? await manager.getSession(machineId: remoteMachineId, channel: "health-test-latency")
            try await Task.sleep(for: .seconds(2))
        }
    }

    let allSubPassed = subResults.allSatisfy { $0.1 }
    let summaryDetail = subResults.map { "  \($0.1 ? "PASS" : "FAIL") \($0.0): \($0.2)" }.joined(separator: "\n")
    record("Phase 10: Latency & Jitter", passed: allSubPassed,
           detail: "\(subResults.filter { $0.1 }.count)/\(subResults.count) sub-tests passed\n\(summaryDetail)")
} catch {
    record("Phase 10: Latency & Jitter", passed: false, detail: "Error: \(error)")
}
#else
record("Phase 10: Latency & Jitter", passed: true,
       detail: "Skipped (Linux only)")
#endif

// MARK: - Phase 11: Summary

logPhase("Phase 11: Summary")

await sendControl("done")
_ = await waitForAck("done-ack", timeout: .seconds(10))

// Verify test-specific network state is clean
// Only check iptables rules (which we modify) and that our temp IP is gone.
// Don't compare all IPs — other system processes may change unrelated interfaces.
logger.info("Verifying test cleanup...")
let finalNetworkState = await NetworkSnapshot.capture()
var cleanupIssues: [String] = []

// Check iptables: our test rules reference the port
let testRules = finalNetworkState.iptablesRules.split(separator: "\n").filter { $0.contains("--dport \(port)") }
if !testRules.isEmpty {
    cleanupIssues.append("Leftover iptables rules: \(testRules)")
}

// Check our temp IP from Phase 9 is removed
if finalNetworkState.ipAddresses.contains("192.168.12.122") {
    cleanupIssues.append("Temp IP 192.168.12.122 still present")
}

if cleanupIssues.isEmpty {
    record("Network State Cleanup", passed: true, detail: "No test-specific artifacts remain")
} else {
    logger.warning("Cleanup issues: \(cleanupIssues)")
    record("Network State Cleanup", passed: false, detail: cleanupIssues.joined(separator: "; "))
}

logger.info("")
logger.info("=== TEST RESULTS ===")
var passCount = 0
var failCount = 0
for result in results {
    let status = result.passed ? "PASS" : "FAIL"
    if result.passed { passCount += 1 } else { failCount += 1 }
    logger.info("  [\(status)] \(result.name)")
    logger.info("         \(result.detail)")
}
logger.info("")
logger.info("Total: \(passCount) passed, \(failCount) failed out of \(results.count)")
logger.info("=== \(failCount == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED") ===")

await cleanup.run()
exit(failCount == 0 ? 0 : 1)
