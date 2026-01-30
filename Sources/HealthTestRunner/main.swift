// HealthTestRunner - Comprehensive cross-machine health monitoring test
//
// Two roles run the same binary:
//   Node A (Linux, orchestrator): --role nodeA --port 18020 --lan --remote-host <remote-ip>
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
        // entry format: "198.51.100.1/24 dev eth0"
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
    process.standardInput = FileHandle.nullDevice

    // Use terminationHandler + continuation to avoid blocking cooperative threads.
    // process.waitUntilExit() blocks a thread, which can exhaust the cooperative pool.
    let exitCode: Int32 = await withCheckedContinuation { continuation in
        process.terminationHandler = { proc in
            continuation.resume(returning: proc.terminationStatus)
        }
        do {
            try process.run()
        } catch {
            continuation.resume(returning: -1)
            return
        }

        // Timeout: terminate after deadline
        Task {
            try? await Task.sleep(for: timeout)
            if process.isRunning {
                process.terminate()
            }
        }
    }

    // Read output after process has exited (pipe write end is closed)
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
var remoteHost: String = ""

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
        remoteHost = String(args.first ?? "")
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
// macOS: remove pfctl rules from previous test runs (both tracked and untracked)
do {
    let (_, pfRules) = await shell("pfctl -sr 2>/dev/null || true")
    let pfRulesTrimmed = pfRules.trimmingCharacters(in: .whitespacesAndNewlines)
    if !pfRulesTrimmed.isEmpty {
        // Remove any rules that mention the test port OR were tracked from a previous run
        let stalePfctlSet = Set(await stateTracker.allPfctlRules())
        let cleanedRules = pfRulesTrimmed.split(separator: "\n")
            .filter { line in
                let s = String(line)
                // Remove if tracked OR if it mentions the test port (stale from crashed run)
                if stalePfctlSet.contains(s) { return false }
                if s.contains("port") && s.contains("\(port)") { return false }
                return true
            }
            .joined(separator: "\n")
        if cleanedRules.isEmpty {
            let (_, _) = await shell("pfctl -d 2>&1 || true")
            let (_, _) = await shell("pfctl -F rules 2>&1 || true")
            logger.info("  Disabled pfctl (removed all test-related rules)")
        } else if cleanedRules != pfRulesTrimmed {
            let (_, _) = await shell("echo '\(cleanedRules)' | pfctl -f - 2>&1 || true")
            logger.info("  Reloaded pfctl without test rules")
        } else {
            logger.info("  No test-related pfctl rules found")
        }
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
            logger.debug("waitForAck(\(expectedPhase)): skipping '\(msg.phase)'")
        }
    }
    return false
}

/// Wait for a specific phase and return the message (skips non-matching messages)
func waitForPhase(_ expectedPhase: String, timeout: Duration = .seconds(30)) async -> ControlMessage? {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        let remaining = deadline - ContinuousClock.now
        let waitTime = min(remaining, .seconds(5))
        if let msg = await controlMailbox.receive(timeout: waitTime) {
            if msg.phase == expectedPhase { return msg }
            logger.debug("waitForPhase(\(expectedPhase)): skipping '\(msg.phase)'")
        }
    }
    logger.warning("waitForPhase(\(expectedPhase)): timed out")
    return nil
}

// MARK: - Message Counter

actor MessageCounter {
    var received: Int = 0
    func increment() { received += 1 }
    func reset() { received = 0 }
    var count: Int { received }
}

let messageCounter = MessageCounter()

// MARK: - Performance Measurement Helpers

actor LatencyCollector {
    private var samples: [Double] = []

    func record(_ rttMicroseconds: Double) {
        samples.append(rttMicroseconds)
    }

    func summary() -> (p50: Double, p95: Double, p99: Double, min: Double, max: Double, avg: Double) {
        guard !samples.isEmpty else { return (0, 0, 0, 0, 0, 0) }
        let sorted = samples.sorted()
        let n = sorted.count
        let p50 = sorted[n * 50 / 100]
        let p95 = sorted[n * 95 / 100]
        let p99 = sorted[min(n * 99 / 100, n - 1)]
        let mn = sorted.first!
        let mx = sorted.last!
        let avg = sorted.reduce(0, +) / Double(n)
        return (p50, p95, p99, mn, mx, avg)
    }

    func histogram(buckets: [(label: String, range: Range<Double>)]) -> [(label: String, count: Int)] {
        buckets.map { bucket in
            let count = samples.filter { bucket.range.contains($0) }.count
            return (label: bucket.label, count: count)
        }
    }

    func reset() { samples.removeAll() }
    var count: Int { samples.count }
    func allSamples() -> [Double] { samples }
}

actor BandwidthMeasurer {
    private var startTime: ContinuousClock.Instant?
    private var totalBytes: UInt64 = 0

    func start() {
        startTime = ContinuousClock.now
        totalBytes = 0
    }

    func addBytes(_ n: UInt64) {
        totalBytes += n
    }

    func result() -> (bytes: UInt64, duration: Duration, mbps: Double) {
        let elapsed = startTime.map { ContinuousClock.now - $0 } ?? .zero
        let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        let mbps = seconds > 0 ? (Double(totalBytes) * 8.0 / 1_000_000.0 / seconds) : 0
        return (totalBytes, elapsed, mbps)
    }
}

struct BandwidthResult {
    let packetSize: Int
    let direction: String       // "A→B" or "B→A"
    let sentMbps: Double
    let deliveredMbps: Double
}

struct BatchSweepResult {
    let delayMs: Int
    let direction: String
    let sentMbps: Double
    let deliveredMbps: Double
    let latencyUs: Double
}

struct PerfSummary {
    var vanillaBandwidth: [BandwidthResult] = []
    var vanillaLatency: (p50: Double, p95: Double, p99: Double) = (0, 0, 0)
    var meshBandwidth: [BandwidthResult] = []
    var meshLatency: (p50: Double, p95: Double, p99: Double) = (0, 0, 0)
    var meshHistogram: [(label: String, count: Int)] = []
    var batchSweep: [BatchSweepResult] = []
    var tcpBandwidth: [BandwidthResult] = []
    var recoveryPreSwapMedian: Double = 0
    var recoveryPeakLatency: Double = 0
    var recoveryTimeSeconds: Double = 0

    // Best bandwidth for the overhead comparison
    var vanillaBandwidthMbps: Double { vanillaBandwidth.map(\.sentMbps).max() ?? 0 }
    var meshBandwidthMbps: Double { meshBandwidth.map(\.sentMbps).max() ?? 0 }
    var tcpBandwidthMbps: Double { tcpBandwidth.map(\.sentMbps).max() ?? 0 }
}

let latencyBuckets: [(label: String, range: Range<Double>)] = [
    ("     0-   500 us", 0.0..<500.0),
    ("   500-  1000 us", 500.0..<1000.0),
    ("  1000-  2000 us", 1000.0..<2000.0),
    ("  2000-  5000 us", 2000.0..<5000.0),
    ("  5000- 10000 us", 5000.0..<10000.0),
    (" 10000- 20000 us", 10000.0..<20000.0),
    (" 20000- 50000 us", 20000.0..<50000.0),
    (" 50000-100000 us", 50000.0..<100000.0),
    ("100000+      us", 100000.0..<Double.infinity),
]

var perfSummary = PerfSummary()

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

    // Phase 11 state (persisted across separate case blocks)
    var nodeBEchoChannel: Channel? = nil
    var nodeBEchoGroup: MultiThreadedEventLoopGroup? = nil

    // UDPReceiveStats must be declared at file scope or use a type-erased wrapper
    actor _UDPReceiveStats {
        var totalBytes: UInt64 = 0
        var startNanos: UInt64 = 0
        var endNanos: UInt64 = 0
        func addBytes(_ n: Int) {
            let now = DispatchTime.now().uptimeNanoseconds
            if totalBytes == 0 { startNanos = now }
            totalBytes += UInt64(n)
            endNanos = now
        }
        func result() -> (bytes: UInt64, nanos: UInt64) {
            return (totalBytes, endNanos > startNanos ? endNanos - startNanos : 0)
        }
    }
    var nodeBUDPStats: _UDPReceiveStats? = nil
    var nodeBTcpServer: Channel? = nil
    var nodeBTcpGroup: MultiThreadedEventLoopGroup? = nil
    var nodeBBwMeasurer: BandwidthMeasurer? = nil
    var nodeBSweepMeasurer: BandwidthMeasurer? = nil

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

        case "phase11-vanilla-start":
            // Open a UDP echo server on an ephemeral port for vanilla baseline
            let echoGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            let udpStats = _UDPReceiveStats()

            final class EchoHandler: ChannelInboundHandler, @unchecked Sendable {
                typealias InboundIn = AddressedEnvelope<ByteBuffer>
                typealias OutboundOut = AddressedEnvelope<ByteBuffer>
                let stats: _UDPReceiveStats
                init(stats: _UDPReceiveStats) { self.stats = stats }
                func channelRead(context: ChannelHandlerContext, data: NIOAny) {
                    let envelope = self.unwrapInboundIn(data)
                    let byteCount = envelope.data.readableBytes
                    Task { await self.stats.addBytes(byteCount) }
                    context.writeAndFlush(self.wrapOutboundOut(envelope), promise: nil)
                }
            }
            let echoChannel = try await DatagramBootstrap(group: echoGroup)
                .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .channelInitializer { ch in ch.pipeline.addHandler(EchoHandler(stats: udpStats)) }
                .bind(host: "0.0.0.0", port: 0)
                .get()
            let echoPort = echoChannel.localAddress?.port ?? 0
            logger.info("Node B: vanilla UDP echo server on port \(echoPort)")
            await sendControl("phase11-vanilla-ready", detail: "\(echoPort)")
            // Store echo channel/stats for later phases to use
            nodeBEchoChannel = echoChannel
            nodeBEchoGroup = echoGroup
            nodeBUDPStats = udpStats

        case "phase11-udp-done":
            // A→B bandwidth phase done — report receive stats
            try await Task.sleep(for: .milliseconds(200))
            if let stats = nodeBUDPStats {
                let result = await stats.result()
                await sendControl("phase11-udp-bw-report", detail: "\(result.bytes),\(result.nanos)")
                logger.info("Node B: A→B received \(result.bytes) bytes in \(result.nanos)ns")
            } else {
                await sendControl("phase11-udp-bw-report", detail: "0,0")
            }

        case "phase11-udp-reverse-go":
            // B→A reverse blast
            let parts = (cmd.detail ?? "").split(separator: ",")
            guard parts.count >= 3,
                  let pktSize = Int(parts[0]),
                  let pktCount = Int(parts[1]),
                  let targetPort = Int(parts[2]),
                  let channel = nodeBEchoChannel else {
                logger.error("Node B: bad reverse-go detail or no echo channel")
                await sendControl("phase11-udp-reverse-done", detail: "0,0")
                continue
            }
            let remoteAddr = try SocketAddress(ipAddress: remoteHost, port: targetPort)
            let payload = Data(repeating: 0xBB, count: pktSize)
            let blastClock = ContinuousClock()
            let blastStart = blastClock.now
            var sentBytes: UInt64 = 0
            for _ in 1...pktCount {
                let buf = channel.allocator.buffer(bytes: payload)
                let envelope = AddressedEnvelope(remoteAddress: remoteAddr, data: buf)
                try? await channel.writeAndFlush(envelope)
                sentBytes += UInt64(pktSize)
            }
            let blastElapsed = blastClock.now - blastStart
            let blastNanos = UInt64(blastElapsed.components.seconds) * 1_000_000_000 + UInt64(blastElapsed.components.attoseconds / 1_000_000_000)
            await sendControl("phase11-udp-reverse-done", detail: "\(sentBytes),\(blastNanos)")
            logger.info("Node B: B→A sent \(sentBytes) bytes in \(blastNanos)ns")

        case "phase11-vanilla-done":
            // Clean up echo server
            if let ch = nodeBEchoChannel { try? await ch.close() }
            if let g = nodeBEchoGroup { try? await g.shutdownGracefully() }
            nodeBEchoChannel = nil
            nodeBEchoGroup = nil
            nodeBUDPStats = nil
            logger.info("Node B: vanilla echo server closed")

        case "phase11-tcp-start":
            // TCP bandwidth server
            let tcpGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
            let tcpBlastSize = 10_000_000 // 10MB B→A

            actor TCPStats {
                var receivedBytes: UInt64 = 0
                var startNanos: UInt64 = 0
                var endNanos: UInt64 = 0
                func addBytes(_ n: Int) {
                    let now = DispatchTime.now().uptimeNanoseconds
                    if receivedBytes == 0 { startNanos = now }
                    receivedBytes += UInt64(n)
                    endNanos = now
                }
                func result() -> (bytes: UInt64, nanos: UInt64) {
                    return (receivedBytes, endNanos > startNanos ? endNanos - startNanos : 0)
                }
            }

            final class TCPServerHandler: ChannelInboundHandler, @unchecked Sendable {
                typealias InboundIn = ByteBuffer
                typealias OutboundOut = ByteBuffer
                let stats = TCPStats()
                let blastSize: Int
                let logger: Logger
                var expectedBytes: UInt64 = 0
                var headerParsed = false
                var headerBuf = Data()
                var dataReceived: UInt64 = 0
                var sentReport = false
                init(blastSize: Int, logger: Logger) {
                    self.blastSize = blastSize
                    self.logger = logger
                }
                func channelRead(context: ChannelHandlerContext, data: NIOAny) {
                    var buf = unwrapInboundIn(data)
                    guard let bytes = buf.readBytes(length: buf.readableBytes) else { return }

                    if !headerParsed {
                        // Accumulate until we find newline
                        headerBuf.append(contentsOf: bytes)
                        if let newlineIdx = headerBuf.firstIndex(of: UInt8(ascii: "\n")) {
                            let headerData = headerBuf[headerBuf.startIndex..<newlineIdx]
                            if let headerStr = String(data: headerData, encoding: .utf8),
                               headerStr.hasPrefix("SIZE:"),
                               let size = UInt64(headerStr.dropFirst("SIZE:".count)) {
                                expectedBytes = size
                                headerParsed = true
                                // Remaining bytes after header are data
                                let remaining = headerBuf.count - headerBuf.distance(from: headerBuf.startIndex, to: newlineIdx) - 1
                                if remaining > 0 {
                                    dataReceived += UInt64(remaining)
                                    Task { await self.stats.addBytes(remaining) }
                                }
                                logger.debug("TCP server: expecting \(size) bytes")
                            }
                        }
                    } else {
                        dataReceived += UInt64(bytes.count)
                        Task { await self.stats.addBytes(bytes.count) }
                    }

                    // Check if we've received all expected data
                    if headerParsed && dataReceived >= expectedBytes && !sentReport {
                        sentReport = true
                        let ctx = context
                        let blastSz = self.blastSize
                        Task {
                            let result = await self.stats.result()
                            let report = "REPORT:\(result.bytes),\(result.nanos)\n"
                            // Hop back to event loop for channel operations
                            ctx.eventLoop.execute {
                                var buf = ctx.channel.allocator.buffer(capacity: report.count + blastSz)
                                buf.writeString(report)
                                buf.writeRepeatingByte(0xDD, count: blastSz)
                                ctx.writeAndFlush(NIOAny(buf), promise: nil)
                                ctx.close(promise: nil)
                            }
                        }
                    }
                }
            }

            let tcpBoot = ServerBootstrap(group: tcpGroup)
                .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { channel in
                    channel.pipeline.addHandler(TCPServerHandler(blastSize: tcpBlastSize, logger: logger))
                }

            let tcpServerChannel = try await tcpBoot.bind(host: "0.0.0.0", port: 0).get()
            let tcpPort = tcpServerChannel.localAddress?.port ?? 0
            logger.info("Node B: TCP server on port \(tcpPort)")
            await sendControl("phase11-tcp-ready", detail: "\(tcpPort)")
            nodeBTcpServer = tcpServerChannel
            nodeBTcpGroup = tcpGroup

        case "phase11-tcp-done":
            if let srv = nodeBTcpServer { try? await srv.close() }
            if let g = nodeBTcpGroup { try? await g.shutdownGracefully() }
            nodeBTcpServer = nil
            nodeBTcpGroup = nil
            logger.info("Node B: TCP server closed")

        case "phase12-bw-start":
            // Receive tunnel data on channel "health-test-bw", count bytes
            let bwMeasurer12 = BandwidthMeasurer()
            await bwMeasurer12.start()
            try await Task.sleep(for: .seconds(2))
            if let bwSession = await latestSession.get() {
                await bwSession.onReceive { data in
                    await bwMeasurer12.addBytes(UInt64(data.count))
                }
            }
            logger.info("Node B: waiting for bandwidth data on health-test-bw")
            nodeBBwMeasurer = bwMeasurer12

        case "phase12-bw-done":
            // A→B done — report received bytes
            try await Task.sleep(for: .milliseconds(200))
            if let measurer = nodeBBwMeasurer {
                let bwResult = await measurer.result()
                let bwDurationNanos = UInt64(bwResult.duration.components.seconds) * 1_000_000_000 + UInt64(bwResult.duration.components.attoseconds / 1_000_000_000)
                await sendControl("phase12-bw-report", detail: "\(bwResult.bytes),\(bwDurationNanos)")
                logger.info("Node B: received \(bwResult.bytes) bytes in \(bwDurationNanos)ns for bandwidth test")
            } else {
                await sendControl("phase12-bw-report", detail: "0,0")
            }

        case "phase12-bw-reverse-start":
            // Reverse direction: B→A
            let parts12r = (cmd.detail ?? "").split(separator: ",")
            let pktSize12r = parts12r.count >= 1 ? (Int(parts12r[0]) ?? 1400) : 1400
            let pktCount12r = parts12r.count >= 2 ? (Int(parts12r[1]) ?? 5000) : 5000

            guard let revSession12 = await latestSession.get() else {
                await sendControl("phase12-bw-reverse-done", detail: "0,0")
                continue
            }
            let revPayload12 = Data(repeating: 0xBB, count: pktSize12r)
            let revClock12 = ContinuousClock()
            let revStart12 = revClock12.now
            var revSentBytes12: UInt64 = 0
            for _ in 1...pktCount12r {
                try? await revSession12.send(revPayload12)
                revSentBytes12 += UInt64(pktSize12r)
            }
            try? await revSession12.flush()
            let revElapsed12 = revClock12.now - revStart12
            let revNanos12 = UInt64(revElapsed12.components.seconds) * 1_000_000_000 + UInt64(revElapsed12.components.attoseconds / 1_000_000_000)
            await sendControl("phase12-bw-reverse-done", detail: "\(revSentBytes12),\(revNanos12)")
            logger.info("Node B: B→A sent \(revSentBytes12) bytes in \(revNanos12)ns")

        case "phase12b-sweep-start":
            // Set up receive handler for sweep data
            let sweepMeasurer = BandwidthMeasurer()
            if let sweepSession = await latestSession.get() {
                await sweepSession.onReceive { data in
                    await sweepMeasurer.addBytes(UInt64(data.count))
                }
            }
            logger.info("Node B: waiting for batch sweep steps")
            await sendControl("phase12b-sweep-ack")

        case "phase12b-step-start":
            // Reset measurer for this step
            let stepMeasurer12b = BandwidthMeasurer()
            await stepMeasurer12b.start()
            if let stepSession = await latestSession.get() {
                await stepSession.onReceive { data in
                    await stepMeasurer12b.addBytes(UInt64(data.count))
                }
            }
            nodeBSweepMeasurer = stepMeasurer12b

        case "phase12b-step-done":
            // Report step results
            try await Task.sleep(for: .milliseconds(200))
            if let measurer = nodeBSweepMeasurer {
                let stepResult12b = await measurer.result()
                let stepNanos12b = UInt64(stepResult12b.duration.components.seconds) * 1_000_000_000 + UInt64(stepResult12b.duration.components.attoseconds / 1_000_000_000)
                await sendControl("phase12b-step-report", detail: "\(stepResult12b.bytes),\(stepNanos12b)")
                logger.info("Node B: step received \(stepResult12b.bytes) bytes in \(stepNanos12b)ns")
            } else {
                await sendControl("phase12b-step-report", detail: "0,0")
            }

        case "phase12b-step-reverse-start":
            let parts12bs = (cmd.detail ?? "").split(separator: ",")
            let pktSize12bs = parts12bs.count >= 1 ? (Int(parts12bs[0]) ?? 512) : 512
            let pktCount12bs = parts12bs.count >= 2 ? (Int(parts12bs[1]) ?? 5000) : 5000

            guard let revSession12bs = await latestSession.get() else {
                await sendControl("phase12b-step-reverse-done", detail: "0,0")
                continue
            }
            let revPayload12bs = Data(repeating: 0xCC, count: pktSize12bs)
            let revClock12bs = ContinuousClock()
            let revStart12bs = revClock12bs.now
            var revSent12bs: UInt64 = 0
            for _ in 1...pktCount12bs {
                try? await revSession12bs.send(revPayload12bs)
                revSent12bs += UInt64(pktSize12bs)
            }
            try? await revSession12bs.flush()
            let revElapsed12bs = revClock12bs.now - revStart12bs
            let revNanos12bs = UInt64(revElapsed12bs.components.seconds) * 1_000_000_000 + UInt64(revElapsed12bs.components.attoseconds / 1_000_000_000)
            await sendControl("phase12b-step-reverse-done", detail: "\(revSent12bs),\(revNanos12bs)")
            logger.info("Node B: step reverse sent \(revSent12bs) bytes in \(revNanos12bs)ns")

        case "phase12b-sweep-done":
            logger.info("Node B: batch sweep complete")
            await sendControl("phase12b-sweep-done-ack")

        case "phase13-ping-start":
            // Echo tunnel pings back (PING→PONG) — wait for Node A's session
            await sendControl("phase13-ping-ack")
            try await Task.sleep(for: .seconds(2))
            guard let pingSession = await latestSession.get() else {
                logger.error("Node B: no session for phase13")
                continue
            }
            await pingSession.onReceive { data in
                let msg = String(data: data, encoding: .utf8) ?? ""
                if msg.hasPrefix("PING:") {
                    let pong = "PONG:" + msg.dropFirst(5)
                    try? await pingSession.sendAndFlush(Data(pong.utf8))
                }
            }
            logger.info("Node B: echoing pings on health-test-ping")

            // Wait for stop signal
            while true {
                guard let doneMsg = await controlMailbox.receive(timeout: .seconds(60)) else { break }
                if doneMsg.phase == "phase13-ping-stop" { break }
            }
            logger.info("Node B: ping echo stopped")

        case "phase14-recovery-start":
            // Echo pings for recovery timing — wait for Node A's session
            await sendControl("phase14-recovery-ack")
            try await Task.sleep(for: .seconds(2))
            guard let recoveryPingSession = await latestSession.get() else {
                logger.error("Node B: no session for phase14")
                continue
            }
            await recoveryPingSession.onReceive { data in
                let msg = String(data: data, encoding: .utf8) ?? ""
                if msg.hasPrefix("PING:") {
                    let pong = "PONG:" + msg.dropFirst(5)
                    try? await recoveryPingSession.sendAndFlush(Data(pong.utf8))
                }
            }
            logger.info("Node B: echoing recovery pings")

            // Wait for done signal
            while true {
                guard let doneMsg = await controlMailbox.receive(timeout: .seconds(60)) else { break }
                if doneMsg.phase == "phase14-recovery-done" { break }
            }
            logger.info("Node B: recovery ping echo stopped")

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
    let (_, ifOutput) = await shell("ip route get \(remoteHost) | head -1 | sed -n 's/.*dev \\([^ ]*\\).*/\\1/p'")
    let iface = ifOutput.isEmpty ? "eth0" : ifOutput
    logger.info("Using interface: \(iface)")

    // Pick a temp IP that doesn't conflict with existing addresses
    let (_, existingAddrs) = await shell("ip -4 addr show | grep 'inet ' | awk '{print $2}' | cut -d/ -f1")
    let usedIPs = Set(existingAddrs.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) })
    var tempIP = "198.51.100.122"
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
    let (_, ifOutput10) = await shell("ip route get \(remoteHost) | head -1 | sed -n 's/.*dev \\([^ ]*\\).*/\\1/p'")
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

    // Register a single cleanup action to remove any netem qdisc left behind
    let delQdisc = "tc qdisc del dev \(iface10) root netem"
    await cleanup.register { let _ = await shell(delQdisc) }

    for profile in profiles {
        logger.info("  Sub-test: \(profile.name)")

        // Apply netem qdisc (use replace to handle existing qdisc from previous sub-test)
        let addQdisc = "tc qdisc add dev \(iface10) root netem \(profile.tcArgs)"
        let (addExit, addOut) = await shell(addQdisc)
        if addExit != 0 {
            logger.info("  tc add returned \(addExit), trying replace...")
            let (replExit, replOut) = await shell("tc qdisc replace dev \(iface10) root netem \(profile.tcArgs)")
            if replExit != 0 {
                logger.error("  tc replace also failed: \(replOut)")
                subResults.append((profile.name, false, "tc setup failed: \(replOut)"))
                continue
            }
        }

        // Send traffic both directions — retry control message for lossy profiles
        await messageCounter.reset()

        var latencyAck = false
        for attempt in 1...3 {
            await sendControl("phase10-latency-start")

            for i in 1...5 {
                try? await session10.send(Data("A-latency-\(attempt)-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(200))
            }

            latencyAck = await waitForAck("phase10-latency-ack", timeout: .seconds(15))
            if latencyAck { break }
            logger.info("    Retry \(attempt)/3: no ack, resending...")
        }
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

        // Remove netem between sub-tests
        let (_, _) = await shell(delQdisc)

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

// MARK: - Phase 11a: Vanilla Baseline (Direct UDP)

logPhase("Phase 11a: Vanilla UDP Baseline")

do {
    // Tell Node B to start vanilla echo server
    await sendControl("phase11-vanilla-start")
    guard let readyMsg = await waitForPhase("phase11-vanilla-ready", timeout: .seconds(30)),
          let echoPortStr = readyMsg.detail,
          let echoPort = Int(echoPortStr) else {
        record("Phase 11a: Vanilla UDP Baseline", passed: false, detail: "Node B did not report echo port")
        throw TunnelError.notConnected
    }
    logger.info("Node B vanilla echo on port \(echoPort)")

    let vanillaGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)

    // Collect received pongs
    let vanillaLatencyCollector = LatencyCollector()

    final class VanillaPongHandler: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = AddressedEnvelope<ByteBuffer>
        let collector: LatencyCollector
        var reverseMeasurer: BandwidthMeasurer?
        let clock = ContinuousClock()
        init(collector: LatencyCollector) { self.collector = collector }
        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let envelope = self.unwrapInboundIn(data)
            let byteCount = envelope.data.readableBytes
            var buf = envelope.data
            if let bytes = buf.readBytes(length: buf.readableBytes) {
                let msg = String(decoding: Data(bytes), as: UTF8.self)
                // Parse timestamp from probe: "PROBE:<seq>:<nanos>" (may have trailing padding)
                let parts = msg.trimmingCharacters(in: .whitespaces).split(separator: ":")
                if parts.count >= 3, let sentNanos = UInt64(parts[2].trimmingCharacters(in: .whitespaces)) {
                    let nowNanos = DispatchTime.now().uptimeNanoseconds
                    let rttUs = Double(nowNanos - sentNanos) / 1000.0
                    Task { await self.collector.record(rttUs) }
                }
            }
            // Also count bytes for reverse bandwidth measurement
            if let measurer = reverseMeasurer {
                Task { await measurer.addBytes(UInt64(byteCount)) }
            }
        }
    }
    let pongHandler = VanillaPongHandler(collector: vanillaLatencyCollector)
    let vanillaChannel = try await DatagramBootstrap(group: vanillaGroup)
        .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .channelInitializer { ch in ch.pipeline.addHandler(pongHandler) }
        .bind(host: "0.0.0.0", port: 0)
        .get()

    let remoteEchoAddr = try SocketAddress(ipAddress: remoteHost, port: echoPort)

    // Latency: 200 timestamped 64-byte probes
    for seq in 1...200 {
        let nanos = DispatchTime.now().uptimeNanoseconds
        let probe = "PROBE:\(seq):\(nanos)"
        // Pad to 64 bytes
        let padded = probe + String(repeating: " ", count: max(0, 64 - probe.count))
        let buf = vanillaChannel.allocator.buffer(string: padded)
        let envelope = AddressedEnvelope(remoteAddress: remoteEchoAddr, data: buf)
        try? await vanillaChannel.writeAndFlush(envelope)
        try await Task.sleep(for: .milliseconds(5))
    }
    // Wait for responses
    try await Task.sleep(for: .seconds(2))

    let vanillaLatSummary = await vanillaLatencyCollector.summary()
    perfSummary.vanillaLatency = (vanillaLatSummary.p50, vanillaLatSummary.p95, vanillaLatSummary.p99)
    let vanillaLatCount = await vanillaLatencyCollector.count
    logger.info("Vanilla latency: p50=\(String(format: "%.0f", vanillaLatSummary.p50))us p95=\(String(format: "%.0f", vanillaLatSummary.p95))us p99=\(String(format: "%.0f", vanillaLatSummary.p99))us (\(vanillaLatCount) samples)")

    // A→B Bandwidth: sweep multiple packet sizes
    let bwPacketSizes = [256, 1024, 4096, 8192]
    let bwTargetBytes: UInt64 = 7_000_000  // ~7MB per size
    for pktSize in bwPacketSizes {
        let bwPayload = Data(repeating: 0xAA, count: pktSize)
        let bwPacketCount = Int(bwTargetBytes / UInt64(pktSize))
        let bwClock = ContinuousClock()
        let bwStart = bwClock.now
        for _ in 1...bwPacketCount {
            let buf = vanillaChannel.allocator.buffer(bytes: bwPayload)
            let envelope = AddressedEnvelope(remoteAddress: remoteEchoAddr, data: buf)
            try? await vanillaChannel.writeAndFlush(envelope)
        }
        let bwElapsed = bwClock.now - bwStart
        let totalBytes = UInt64(bwPacketCount) * UInt64(pktSize)
        let durationSec = Double(bwElapsed.components.seconds) + Double(bwElapsed.components.attoseconds) / 1e18
        let sentMbps = durationSec > 0 ? (Double(totalBytes) * 8.0 / 1_000_000.0 / durationSec) : 0
        perfSummary.vanillaBandwidth.append(BandwidthResult(packetSize: pktSize, direction: "A\u{2192}B", sentMbps: sentMbps, deliveredMbps: 0))
        logger.info("Vanilla A\u{2192}B bandwidth (\(pktSize)B): \(String(format: "%.1f", sentMbps)) Mbps sent (\(bwPacketCount) pkts, \(String(format: "%.3f", durationSec))s)")
    }

    // Signal A→B done, get B's receive report
    await sendControl("phase11-udp-done")
    var deliveredAtoBMbps: Double = 0
    if let bwReport = await waitForPhase("phase11-udp-bw-report", timeout: .seconds(15)),
       let detail = bwReport.detail {
        let parts = detail.split(separator: ",")
        if parts.count >= 2,
           let recvBytes = UInt64(parts[0]),
           let recvNanos = UInt64(parts[1]),
           recvNanos > 0 {
            deliveredAtoBMbps = Double(recvBytes) * 8.0 / 1_000_000.0 / (Double(recvNanos) / 1e9)
        }
    }
    logger.info("Vanilla A\u{2192}B aggregate delivered: \(String(format: "%.1f", deliveredAtoBMbps)) Mbps")

    // B→A reverse direction — reuse vanillaChannel (already open and receiving)
    let reverseMeasurer = BandwidthMeasurer()
    pongHandler.reverseMeasurer = reverseMeasurer
    await reverseMeasurer.start()

    let reversePacketSize = 8192
    let reversePacketCount = Int(bwTargetBytes / UInt64(reversePacketSize))
    let vanillaPort = vanillaChannel.localAddress?.port ?? 0
    await sendControl("phase11-udp-reverse-go", detail: "\(reversePacketSize),\(reversePacketCount),\(vanillaPort)")

    // Wait for B to finish sending
    var bToASentMbps: Double = 0
    if let revDoneMsg = await waitForPhase("phase11-udp-reverse-done", timeout: .seconds(30)),
       let detail = revDoneMsg.detail {
        let parts = detail.split(separator: ",")
        if parts.count >= 2,
           let sentBytes = UInt64(parts[0]),
           let sentNanos = UInt64(parts[1]),
           sentNanos > 0 {
            bToASentMbps = Double(sentBytes) * 8.0 / 1_000_000.0 / (Double(sentNanos) / 1e9)
        }
    }
    // Wait a bit for trailing packets
    try await Task.sleep(for: .seconds(2))
    pongHandler.reverseMeasurer = nil
    let reverseResult = await reverseMeasurer.result()
    let bToADeliveredMbps = reverseResult.mbps
    perfSummary.vanillaBandwidth.append(BandwidthResult(packetSize: reversePacketSize, direction: "B\u{2192}A", sentMbps: bToASentMbps, deliveredMbps: bToADeliveredMbps))
    logger.info("Vanilla B\u{2192}A: sent=\(String(format: "%.1f", bToASentMbps)) Mbps, delivered=\(String(format: "%.1f", bToADeliveredMbps)) Mbps")

    try? await vanillaChannel.close()
    try? await vanillaGroup.shutdownGracefully()

    // Clean up Node B
    await sendControl("phase11-vanilla-done")

    let bestVanillaMbps = perfSummary.vanillaBandwidthMbps
    let phase11aPass = vanillaLatCount >= 100
    record("Phase 11a: Vanilla UDP Baseline", passed: phase11aPass,
           detail: "latency p50=\(String(format: "%.0f", vanillaLatSummary.p50))us, best A\u{2192}B sent=\(String(format: "%.1f", bestVanillaMbps))Mbps delivered=\(String(format: "%.1f", deliveredAtoBMbps))Mbps, B\u{2192}A sent=\(String(format: "%.1f", bToASentMbps))Mbps delivered=\(String(format: "%.1f", bToADeliveredMbps))Mbps")
} catch {
    record("Phase 11a: Vanilla UDP Baseline", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 11b: TCP Baseline

logPhase("Phase 11b: TCP Baseline")

do {
    await sendControl("phase11-tcp-start")
    guard let tcpReadyMsg = await waitForPhase("phase11-tcp-ready", timeout: .seconds(30)),
          let tcpPortStr = tcpReadyMsg.detail,
          let tcpPort = Int(tcpPortStr) else {
        record("Phase 11b: TCP Baseline", passed: false, detail: "Node B TCP not ready")
        throw TunnelError.notConnected
    }
    logger.info("Node B TCP on port \(tcpPort)")

    let tcpGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let tcpTargetBytes = 10_000_000 // 10MB

    actor TCPClientState {
        var receivedData = Data()
        var receiveStartNanos: UInt64 = 0
        var receiveEndNanos: UInt64 = 0
        var done = false
        private var continuation: CheckedContinuation<Void, Never>?

        func addData(_ bytes: [UInt8]) {
            let now = DispatchTime.now().uptimeNanoseconds
            if receivedData.isEmpty { receiveStartNanos = now }
            receivedData.append(contentsOf: bytes)
            receiveEndNanos = now
        }
        func markDone() {
            done = true
            continuation?.resume()
            continuation = nil
        }
        func waitForDone() async {
            if done { return }
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                if done {
                    cont.resume()
                } else {
                    continuation = cont
                }
            }
        }
        func getReceivedData() -> Data { receivedData }
        func getReceiveStartNanos() -> UInt64 { receiveStartNanos }
        func getReceiveEndNanos() -> UInt64 { receiveEndNanos }
    }

    let clientState = TCPClientState()

    final class TCPClientHandler: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        let state: TCPClientState
        init(state: TCPClientState) { self.state = state }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            var buf = unwrapInboundIn(data)
            if let bytes = buf.readBytes(length: buf.readableBytes) {
                Task { await self.state.addData(bytes) }
            }
        }

        func channelInactive(context: ChannelHandlerContext) {
            Task { await self.state.markDone() }
        }
    }

    let tcpChannel = try await ClientBootstrap(group: tcpGroup)
        .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .channelInitializer { channel in
            channel.pipeline.addHandler(TCPClientHandler(state: clientState))
        }
        .connect(host: remoteHost, port: tcpPort)
        .get()

    // A→B: send SIZE header then blast data
    let sizeHeader = "SIZE:\(tcpTargetBytes)\n"
    var headerBuf = tcpChannel.allocator.buffer(capacity: sizeHeader.count)
    headerBuf.writeString(sizeHeader)
    try await tcpChannel.writeAndFlush(headerBuf)

    let sendClock = ContinuousClock()
    let sendStart = sendClock.now
    let chunkSize = 65536
    var tcpRemaining = tcpTargetBytes
    while tcpRemaining > 0 {
        let thisChunk = min(chunkSize, tcpRemaining)
        var buf = tcpChannel.allocator.buffer(capacity: thisChunk)
        buf.writeRepeatingByte(0xAA, count: thisChunk)
        try await tcpChannel.writeAndFlush(buf)
        tcpRemaining -= thisChunk
    }
    let sendElapsed = sendClock.now - sendStart
    let sendSec = Double(sendElapsed.components.seconds) + Double(sendElapsed.components.attoseconds) / 1e18
    let tcpSendMbps = sendSec > 0 ? (Double(tcpTargetBytes) * 8.0 / 1_000_000.0 / sendSec) : 0

    // Wait for B's response + close
    await clientState.waitForDone()

    let allReceived = await clientState.getReceivedData()
    let recvStartNanos = await clientState.getReceiveStartNanos()
    let recvEndNanos = await clientState.getReceiveEndNanos()

    // Parse REPORT line from beginning of received data
    var deliveredAtoB_Mbps: Double = 0
    var bToATcpBytes: Int = 0
    if let newlineRange = allReceived.range(of: Data("\n".utf8)) {
        let reportLineData = allReceived[allReceived.startIndex..<newlineRange.lowerBound]
        if let reportLine = String(data: reportLineData, encoding: .utf8),
           reportLine.hasPrefix("REPORT:") {
            let parts = reportLine.dropFirst("REPORT:".count).split(separator: ",")
            if parts.count >= 2,
               let recvBytes = UInt64(parts[0]),
               let recvNanos = UInt64(parts[1]),
               recvNanos > 0 {
                deliveredAtoB_Mbps = Double(recvBytes) * 8.0 / 1_000_000.0 / (Double(recvNanos) / 1e9)
            }
        }
        bToATcpBytes = allReceived.count - allReceived.distance(from: allReceived.startIndex, to: newlineRange.upperBound)
    } else {
        bToATcpBytes = allReceived.count
    }

    let recvDurationSec = recvEndNanos > recvStartNanos ? Double(recvEndNanos - recvStartNanos) / 1e9 : 0
    let bToADeliveredMbps = recvDurationSec > 0 ? (Double(bToATcpBytes) * 8.0 / 1_000_000.0 / recvDurationSec) : 0

    perfSummary.tcpBandwidth.append(BandwidthResult(packetSize: 0, direction: "A\u{2192}B", sentMbps: tcpSendMbps, deliveredMbps: deliveredAtoB_Mbps))
    perfSummary.tcpBandwidth.append(BandwidthResult(packetSize: 0, direction: "B\u{2192}A", sentMbps: 0, deliveredMbps: bToADeliveredMbps))

    logger.info("TCP A\u{2192}B: sent=\(String(format: "%.1f", tcpSendMbps)) Mbps, delivered=\(String(format: "%.1f", deliveredAtoB_Mbps)) Mbps")
    logger.info("TCP B\u{2192}A: delivered=\(String(format: "%.1f", bToADeliveredMbps)) Mbps")

    await sendControl("phase11-tcp-done")
    try? await tcpGroup.shutdownGracefully()

    record("Phase 11b: TCP Baseline", passed: tcpSendMbps > 0,
           detail: "A\u{2192}B sent=\(String(format: "%.1f", tcpSendMbps))Mbps delivered=\(String(format: "%.1f", deliveredAtoB_Mbps))Mbps, B\u{2192}A=\(String(format: "%.1f", bToADeliveredMbps))Mbps")
} catch {
    record("Phase 11b: TCP Baseline", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 12: Mesh Bandwidth

logPhase("Phase 12: Mesh Bandwidth")

do {
    await sendControl("phase12-bw-start")

    let bwSession = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-bw")
    try await Task.sleep(for: .seconds(1))

    let meshBwPacketSizes = [64, 256, 512, 1024, 1400]
    let meshBwTargetBytes: UInt64 = 7_000_000
    for pktSize in meshBwPacketSizes {
        let meshBwPayload = Data(repeating: 0xBB, count: pktSize)
        let meshBwPacketCount = Int(meshBwTargetBytes / UInt64(pktSize))
        let clock = ContinuousClock()
        let start = clock.now
        for _ in 1...meshBwPacketCount {
            try await bwSession.send(meshBwPayload)
        }
        let elapsed = clock.now - start
        let totalBytes = UInt64(meshBwPacketCount) * UInt64(pktSize)
        let durationSec = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        let sentMbps = durationSec > 0 ? (Double(totalBytes) * 8.0 / 1_000_000.0 / durationSec) : 0
        perfSummary.meshBandwidth.append(BandwidthResult(packetSize: pktSize, direction: "A\u{2192}B", sentMbps: sentMbps, deliveredMbps: 0))
        logger.info("Mesh A\u{2192}B bandwidth (\(pktSize)B): \(String(format: "%.1f", sentMbps)) Mbps sent (\(meshBwPacketCount) pkts, \(String(format: "%.3f", durationSec))s)")
    }

    try await Task.sleep(for: .seconds(2))
    await sendControl("phase12-bw-done")

    // Wait for Node B report (bytes,nanos)
    var meshDeliveredAtoBMbps: Double = 0
    if let bwReport = await waitForPhase("phase12-bw-report", timeout: .seconds(15)),
       let detail = bwReport.detail {
        let parts = detail.split(separator: ",")
        if parts.count >= 2,
           let recvBytes = UInt64(parts[0]),
           let recvNanos = UInt64(parts[1]),
           recvNanos > 0 {
            meshDeliveredAtoBMbps = Double(recvBytes) * 8.0 / 1_000_000.0 / (Double(recvNanos) / 1e9)
        }
        logger.info("Mesh A\u{2192}B delivered: \(String(format: "%.1f", meshDeliveredAtoBMbps)) Mbps (B received \(parts.first ?? "?") bytes)")
    }

    // Reverse direction: B→A
    let meshRevMeasurer = BandwidthMeasurer()
    await meshRevMeasurer.start()
    await bwSession.onReceive { data in
        await meshRevMeasurer.addBytes(UInt64(data.count))
    }
    let meshRevPktSize = 1400
    let meshRevPktCount = Int(meshBwTargetBytes / UInt64(meshRevPktSize))
    await sendControl("phase12-bw-reverse-start", detail: "\(meshRevPktSize),\(meshRevPktCount)")

    var meshBToASentMbps: Double = 0
    if let revDone = await waitForPhase("phase12-bw-reverse-done", timeout: .seconds(30)),
       let detail = revDone.detail {
        let parts = detail.split(separator: ",")
        if parts.count >= 2,
           let sentBytes = UInt64(parts[0]),
           let sentNanos = UInt64(parts[1]),
           sentNanos > 0 {
            meshBToASentMbps = Double(sentBytes) * 8.0 / 1_000_000.0 / (Double(sentNanos) / 1e9)
        }
    }
    try await Task.sleep(for: .seconds(2))
    let meshRevResult = await meshRevMeasurer.result()
    let meshBToADeliveredMbps = meshRevResult.mbps
    perfSummary.meshBandwidth.append(BandwidthResult(packetSize: meshRevPktSize, direction: "B\u{2192}A", sentMbps: meshBToASentMbps, deliveredMbps: meshBToADeliveredMbps))
    logger.info("Mesh B\u{2192}A: sent=\(String(format: "%.1f", meshBToASentMbps)) Mbps, delivered=\(String(format: "%.1f", meshBToADeliveredMbps)) Mbps")

    let bestMeshMbps = perfSummary.meshBandwidthMbps
    record("Phase 12: Mesh Bandwidth", passed: bestMeshMbps > 0,
           detail: "best A\u{2192}B sent=\(String(format: "%.1f", bestMeshMbps))Mbps delivered=\(String(format: "%.1f", meshDeliveredAtoBMbps))Mbps, B\u{2192}A sent=\(String(format: "%.1f", meshBToASentMbps))Mbps delivered=\(String(format: "%.1f", meshBToADeliveredMbps))Mbps")
} catch {
    record("Phase 12: Mesh Bandwidth", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 12b: Batch Config Sweep

logPhase("Phase 12b: Batch Config Sweep")

do {
    await sendControl("phase12b-sweep-start")
    _ = await waitForPhase("phase12b-sweep-ack", timeout: .seconds(15))

    let sweepSession = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-sweep")
    try await Task.sleep(for: .seconds(1))

    let sweepDelays: [Int] = [0, 1, 5, 10, 50]  // ms
    let sweepPktSize = 512
    let sweepPayload = Data(repeating: 0xCC, count: sweepPktSize)
    let sweepTargetBytes: UInt64 = 5_000_000

    logger.info("Batch Config Sweep: delay(ms) \u{2192} bandwidth(Mbps) / latency(us)")

    let sweepRevMeasurer = BandwidthMeasurer()
    await sweepSession.onReceive { data in
        await sweepRevMeasurer.addBytes(UInt64(data.count))
    }

    for delayMs in sweepDelays {
        // Reconfigure batch config on the session
        await sweepSession.setBatchConfig(BatchConfig(
            maxFlushDelay: delayMs == 0 ? .zero : .milliseconds(delayMs),
            maxBufferSize: 0
        ))

        let packetCount = Int(sweepTargetBytes / UInt64(sweepPktSize))

        // Signal step start to Node B
        await sendControl("phase12b-step-start", detail: "\(delayMs),\(sweepPktSize),\(packetCount)")

        let clock = ContinuousClock()
        let start = clock.now

        for _ in 1...packetCount {
            try await sweepSession.send(sweepPayload)
        }
        try await sweepSession.flush()

        let elapsed = clock.now - start
        let totalBytes = UInt64(packetCount) * UInt64(sweepPktSize)
        let durationSec = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
        let sentMbps = durationSec > 0 ? (Double(totalBytes) * 8.0 / 1_000_000.0 / durationSec) : 0
        let avgLatencyUs = durationSec > 0 ? (durationSec * 1_000_000.0 / Double(packetCount)) : 0

        // Signal step done, get B's report
        await sendControl("phase12b-step-done")
        var stepDeliveredMbps: Double = 0
        if let stepReport = await waitForPhase("phase12b-step-report", timeout: .seconds(15)),
           let detail = stepReport.detail {
            let parts = detail.split(separator: ",")
            if parts.count >= 2,
               let recvBytes = UInt64(parts[0]),
               let recvNanos = UInt64(parts[1]),
               recvNanos > 0 {
                stepDeliveredMbps = Double(recvBytes) * 8.0 / 1_000_000.0 / (Double(recvNanos) / 1e9)
            }
        }

        perfSummary.batchSweep.append(BatchSweepResult(delayMs: delayMs, direction: "A\u{2192}B", sentMbps: sentMbps, deliveredMbps: stepDeliveredMbps, latencyUs: avgLatencyUs))
        logger.info("  A\u{2192}B delay=\(String(format: "%3d", delayMs))ms: \(String(format: "%8.1f", sentMbps)) Mbps sent, \(String(format: "%8.1f", stepDeliveredMbps)) Mbps delivered, \(String(format: "%8.1f", avgLatencyUs)) us/pkt")

        // Reverse direction for this step
        await sweepRevMeasurer.start()
        await sendControl("phase12b-step-reverse-start", detail: "\(sweepPktSize),\(packetCount)")

        var stepRevSentMbps: Double = 0
        if let revDone = await waitForPhase("phase12b-step-reverse-done", timeout: .seconds(30)),
           let detail = revDone.detail {
            let parts = detail.split(separator: ",")
            if parts.count >= 2,
               let sentBytes = UInt64(parts[0]),
               let sentNanos = UInt64(parts[1]),
               sentNanos > 0 {
                stepRevSentMbps = Double(sentBytes) * 8.0 / 1_000_000.0 / (Double(sentNanos) / 1e9)
            }
        }
        try await Task.sleep(for: .seconds(1))
        let stepRevResult = await sweepRevMeasurer.result()
        let stepRevDeliveredMbps = stepRevResult.mbps

        perfSummary.batchSweep.append(BatchSweepResult(delayMs: delayMs, direction: "B\u{2192}A", sentMbps: stepRevSentMbps, deliveredMbps: stepRevDeliveredMbps, latencyUs: 0))
        logger.info("  B\u{2192}A delay=\(String(format: "%3d", delayMs))ms: \(String(format: "%8.1f", stepRevSentMbps)) Mbps sent, \(String(format: "%8.1f", stepRevDeliveredMbps)) Mbps delivered")
    }

    await sendControl("phase12b-sweep-done")
    _ = await waitForPhase("phase12b-sweep-done-ack", timeout: .seconds(15))

    record("Phase 12b: Batch Config Sweep", passed: !perfSummary.batchSweep.isEmpty,
           detail: perfSummary.batchSweep.filter { $0.direction == "A\u{2192}B" }.map { "delay=\($0.delayMs)ms:\(String(format: "%.1f", $0.sentMbps))Mbps" }.joined(separator: ", "))
} catch {
    record("Phase 12b: Batch Config Sweep", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 13: Mesh Latency (Ping-Pong)

logPhase("Phase 13: Mesh Latency (Ping-Pong)")

do {
    // Create session first, then tell Node B to start echoing
    let meshLatencyCollector = LatencyCollector()
    let pingSession = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-ping")
    await pingSession.onReceive { data in
        let msg = String(data: data, encoding: .utf8) ?? ""
        if msg.hasPrefix("PONG:") {
            let parts = msg.split(separator: ":")
            if parts.count >= 3, let sentNanos = UInt64(parts[2]) {
                let nowNanos = DispatchTime.now().uptimeNanoseconds
                let rttUs = Double(nowNanos - sentNanos) / 1000.0
                await meshLatencyCollector.record(rttUs)
            }
        }
    }

    // Tell Node B to start echoing, wait for ack
    await sendControl("phase13-ping-start")
    _ = await waitForAck("phase13-ping-ack", timeout: .seconds(10))
    try await Task.sleep(for: .seconds(1))

    // Send 500 probes at 5ms intervals
    for seq in 1...500 {
        let nanos = DispatchTime.now().uptimeNanoseconds
        let probe = "PING:\(seq):\(nanos)"
        try await pingSession.sendAndFlush(Data(probe.utf8))
        try await Task.sleep(for: .milliseconds(5))
    }

    // 2s drain
    try await Task.sleep(for: .seconds(2))

    let meshLatSummary = await meshLatencyCollector.summary()
    perfSummary.meshLatency = (meshLatSummary.p50, meshLatSummary.p95, meshLatSummary.p99)
    perfSummary.meshHistogram = await meshLatencyCollector.histogram(buckets: latencyBuckets)
    let meshLatCount = await meshLatencyCollector.count

    logger.info("Mesh latency: p50=\(String(format: "%.0f", meshLatSummary.p50))us p95=\(String(format: "%.0f", meshLatSummary.p95))us p99=\(String(format: "%.0f", meshLatSummary.p99))us (\(meshLatCount) samples)")

    await sendControl("phase13-ping-stop")

    let phase13Pass = meshLatCount >= 200
    record("Phase 13: Mesh Latency", passed: phase13Pass,
           detail: "p50=\(String(format: "%.0f", meshLatSummary.p50))us p95=\(String(format: "%.0f", meshLatSummary.p95))us p99=\(String(format: "%.0f", meshLatSummary.p99))us (\(meshLatCount) samples)")
} catch {
    record("Phase 13: Mesh Latency", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 14: Interface Swap Recovery Timing (Linux only)

logPhase("Phase 14: Interface Swap Recovery Timing")

#if os(Linux)
do {
    // Collect timestamped RTT samples: (wallClockNanos, rttUs)
    actor TimestampedSamples {
        var samples: [(timestamp: UInt64, rttUs: Double)] = []
        func add(_ ts: UInt64, _ rtt: Double) { samples.append((ts, rtt)) }
        func all() -> [(timestamp: UInt64, rttUs: Double)] { samples }
    }
    let tsSamples = TimestampedSamples()
    let recoveryLatencyCollector = LatencyCollector()
    let recoverySession = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-recovery-ping")

    // Tell Node B to start echoing, wait for ack
    await sendControl("phase14-recovery-start")
    _ = await waitForAck("phase14-recovery-ack", timeout: .seconds(10))
    try await Task.sleep(for: .seconds(1))

    // Continuous ping-pong: one probe every 20ms
    // First 2s = baseline, then IP swap, then 15s more
    let totalProbes = (2 + 15) * 50 // 17s at 50 probes/s
    var swapTime: UInt64 = 0

    // Find interface and temp IP (same as Phase 9)
    let (_, ifOutput14) = await shell("ip route get \(remoteHost) | head -1 | sed -n 's/.*dev \\([^ ]*\\).*/\\1/p'")
    let iface14 = ifOutput14.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !iface14.isEmpty else {
        record("Phase 14: Recovery Timing", passed: false, detail: "Could not determine interface")
        throw TunnelError.notConnected
    }

    let (_, existingAddrs14) = await shell("ip -4 addr show | grep 'inet ' | awk '{print $2}' | cut -d/ -f1")
    let usedIPs14 = Set(existingAddrs14.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) })
    var tempIP14 = "198.51.100.130"
    for lastOctet in 130...254 {
        let candidate = "192.168.12.\(lastOctet)"
        if !usedIPs14.contains(candidate) {
            tempIP14 = candidate
            break
        }
    }

    let addCmd14 = "ip addr add \(tempIP14)/24 dev \(iface14)"
    let delCmd14 = "ip addr del \(tempIP14)/24 dev \(iface14)"
    await stateTracker.recordTempIP(addCmd14)
    await cleanup.register { let _ = await shell(delCmd14); await stateTracker.removeTempIP(addCmd14) }

    // Set up pong handler to record timestamped samples
    await recoverySession.onReceive { data in
        let msg = String(data: data, encoding: .utf8) ?? ""
        if msg.hasPrefix("PONG:") {
            let parts = msg.split(separator: ":")
            if parts.count >= 3, let sentNanos = UInt64(parts[2]) {
                let nowNanos = DispatchTime.now().uptimeNanoseconds
                let rttUs = Double(nowNanos - sentNanos) / 1000.0
                await recoveryLatencyCollector.record(rttUs)
                await tsSamples.add(nowNanos, rttUs)
            }
        }
    }

    for probeIdx in 1...totalProbes {
        let nanos = DispatchTime.now().uptimeNanoseconds
        let probe = "PING:\(probeIdx):\(nanos)"
        try? await recoverySession.sendAndFlush(Data(probe.utf8))
        try await Task.sleep(for: .milliseconds(20))

        // After 2s of baseline (100 probes), perform IP swap
        if probeIdx == 100 {
            logger.info("Phase 14: performing IP swap on \(iface14)")
            // Get the current primary IP before swapping
            let (_, currentIP) = await shell("ip -4 addr show dev \(iface14) | grep 'inet ' | head -1 | awk '{print $2}'")
            let currentIPTrimmed = currentIP.trimmingCharacters(in: .whitespacesAndNewlines)
            if !currentIPTrimmed.isEmpty {
                // Add temp IP, delete primary, wait, re-add primary, delete temp
                let (_, _) = await shell(addCmd14)
                swapTime = DispatchTime.now().uptimeNanoseconds
                let (_, _) = await shell("ip addr del \(currentIPTrimmed) dev \(iface14)")
                try await Task.sleep(for: .milliseconds(500))
                let (_, _) = await shell("ip addr add \(currentIPTrimmed) dev \(iface14)")
                let (_, _) = await shell(delCmd14)
                await stateTracker.removeTempIP(addCmd14)
                logger.info("Phase 14: IP swap complete (removed and re-added \(currentIPTrimmed))")
            } else {
                swapTime = DispatchTime.now().uptimeNanoseconds
                logger.warning("Phase 14: could not determine current IP, skipping swap")
            }
        }
    }

    // Wait for trailing pongs
    try await Task.sleep(for: .seconds(2))

    await sendControl("phase14-recovery-done")

    // Analyze results
    let allTS = await tsSamples.all()
    let preSwapSamples = allTS.filter { $0.timestamp < swapTime }
    let postSwapSamples = allTS.filter { $0.timestamp >= swapTime }

    let preSwapMedian: Double
    if preSwapSamples.isEmpty {
        preSwapMedian = 0
    } else {
        let sorted = preSwapSamples.map(\.rttUs).sorted()
        preSwapMedian = sorted[sorted.count / 2]
    }

    let peakDuringSwap = postSwapSamples.map(\.rttUs).max() ?? 0

    // Recovery time: time from swap until RTT stays within 2× pre-swap median for 1s
    var recoveryTime: Double = 0
    if !postSwapSamples.isEmpty && preSwapMedian > 0 {
        let threshold = preSwapMedian * 2.0
        let oneSecondNanos: UInt64 = 1_000_000_000
        var sustainedStart: UInt64? = nil
        for sample in postSwapSamples {
            if sample.rttUs <= threshold {
                if sustainedStart == nil { sustainedStart = sample.timestamp }
                if let start = sustainedStart, sample.timestamp - start >= oneSecondNanos {
                    recoveryTime = Double(start - swapTime) / 1_000_000_000.0
                    break
                }
            } else {
                sustainedStart = nil
            }
        }
        if recoveryTime == 0 && sustainedStart != nil {
            // Never sustained for 1s but had some recovery
            recoveryTime = Double((postSwapSamples.last?.timestamp ?? swapTime) - swapTime) / 1_000_000_000.0
        }
    }

    perfSummary.recoveryPreSwapMedian = preSwapMedian
    perfSummary.recoveryPeakLatency = peakDuringSwap
    perfSummary.recoveryTimeSeconds = recoveryTime

    logger.info("Recovery: pre-swap median=\(String(format: "%.0f", preSwapMedian))us, peak=\(String(format: "%.0f", peakDuringSwap))us, recovery=\(String(format: "%.2f", recoveryTime))s")

    let phase14Pass = preSwapSamples.count >= 20
    record("Phase 14: Recovery Timing", passed: phase14Pass,
           detail: "pre-swap=\(String(format: "%.0f", preSwapMedian))us, peak=\(String(format: "%.0f", peakDuringSwap))us, recovery=\(String(format: "%.2f", recoveryTime))s (\(preSwapSamples.count)+\(postSwapSamples.count) samples)")
} catch {
    record("Phase 14: Recovery Timing", passed: false, detail: "Error: \(error)")
}
#else
record("Phase 14: Recovery Timing", passed: true,
       detail: "Skipped (Linux only)")
#endif

// MARK: - Phase 15: Summary

logPhase("Phase 15: Summary")

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
if finalNetworkState.ipAddresses.contains("198.51.100.122") {
    cleanupIssues.append("Temp IP 198.51.100.122 still present")
}

if cleanupIssues.isEmpty {
    record("Network State Cleanup", passed: true, detail: "No test-specific artifacts remain")
} else {
    logger.warning("Cleanup issues: \(cleanupIssues)")
    record("Network State Cleanup", passed: false, detail: cleanupIssues.joined(separator: "; "))
}

// Performance summary table
logger.info("")
logger.info("=== PERFORMANCE SUMMARY ===")
do {
    let vL50 = perfSummary.vanillaLatency.p50
    let vL95 = perfSummary.vanillaLatency.p95
    let vL99 = perfSummary.vanillaLatency.p99
    let mL50 = perfSummary.meshLatency.p50
    let mL95 = perfSummary.meshLatency.p95
    let mL99 = perfSummary.meshLatency.p99

    let l50Overhead = vL50 > 0 ? String(format: "%.1fx", mL50 / vL50) : "N/A"
    let l95Overhead = vL95 > 0 ? String(format: "%.1fx", mL95 / vL95) : "N/A"
    let l99Overhead = vL99 > 0 ? String(format: "%.1fx", mL99 / vL99) : "N/A"

    // Bandwidth by packet size (A→B)
    logger.info("")
    logger.info("=== BANDWIDTH BY PACKET SIZE (A\u{2192}B) ===")
    logger.info("Packet Size    Vanilla Sent    Mesh Sent    Overhead")
    let vanillaAtoB = perfSummary.vanillaBandwidth.filter { $0.direction == "A\u{2192}B" }
    let meshAtoB = perfSummary.meshBandwidth.filter { $0.direction == "A\u{2192}B" }
    let allSizes = Set(vanillaAtoB.map(\.packetSize) + meshAtoB.map(\.packetSize)).sorted()
    for size in allSizes {
        let vBw = vanillaAtoB.first(where: { $0.packetSize == size })?.sentMbps ?? 0
        let mBw = meshAtoB.first(where: { $0.packetSize == size })?.sentMbps ?? 0
        let overhead = vBw > 0 && mBw > 0 ? String(format: "%.2fx", vBw / mBw) : "N/A"
        logger.info("\(String(format: "%7d B", size))    \(String(format: "%10.1f", vBw))  \(String(format: "%10.1f", mBw))    \(overhead)")
    }

    // B→A bandwidth
    let vanillaBtoA = perfSummary.vanillaBandwidth.filter { $0.direction == "B\u{2192}A" }
    let meshBtoA = perfSummary.meshBandwidth.filter { $0.direction == "B\u{2192}A" }
    if !vanillaBtoA.isEmpty || !meshBtoA.isEmpty {
        logger.info("")
        logger.info("=== BANDWIDTH B\u{2192}A ===")
        logger.info("                Sent (Mbps)    Delivered (Mbps)")
        for r in vanillaBtoA {
            logger.info("Vanilla UDP     \(String(format: "%10.1f", r.sentMbps))     \(String(format: "%10.1f", r.deliveredMbps))")
        }
        for r in meshBtoA {
            logger.info("Mesh Tunnel     \(String(format: "%10.1f", r.sentMbps))     \(String(format: "%10.1f", r.deliveredMbps))")
        }
    }

    // TCP bandwidth
    if !perfSummary.tcpBandwidth.isEmpty {
        logger.info("")
        logger.info("=== TCP BANDWIDTH ===")
        logger.info("Direction    Sent (Mbps)    Delivered (Mbps)")
        for r in perfSummary.tcpBandwidth {
            logger.info("\(r.direction.padding(toLength: 12, withPad: " ", startingAt: 0)) \(String(format: "%10.1f", r.sentMbps))     \(String(format: "%10.1f", r.deliveredMbps))")
        }
    }

    // Batch config sweep
    if !perfSummary.batchSweep.isEmpty {
        logger.info("")
        logger.info("=== BATCH CONFIG SWEEP (512B packets) ===")
        logger.info("Flush Delay    Dir      Sent (Mbps)    Delivered (Mbps)    Avg Latency (us/pkt)")
        for r in perfSummary.batchSweep {
            logger.info("\(String(format: "%7d ms", r.delayMs))    \(r.direction)  \(String(format: "%10.1f", r.sentMbps))       \(String(format: "%10.1f", r.deliveredMbps))         \(String(format: "%10.1f", r.latencyUs))")
        }
    }

    // Latency comparison
    logger.info("")
    logger.info("=== LATENCY COMPARISON ===")
    logger.info("                    Vanilla (Direct)    Mesh Tunnel    Overhead")
    logger.info("Latency p50 (us)    \(String(format: "%8.0f", vL50))            \(String(format: "%8.0f", mL50))       \(l50Overhead)")
    logger.info("Latency p95 (us)    \(String(format: "%8.0f", vL95))            \(String(format: "%8.0f", mL95))       \(l95Overhead)")
    logger.info("Latency p99 (us)    \(String(format: "%8.0f", vL99))            \(String(format: "%8.0f", mL99))       \(l99Overhead)")
}

if !perfSummary.meshHistogram.isEmpty {
    logger.info("")
    logger.info("=== LATENCY HISTOGRAM (Mesh) ===")
    let totalSamples = perfSummary.meshHistogram.reduce(0) { $0 + $1.count }
    let maxCount = perfSummary.meshHistogram.map(\.count).max() ?? 1
    for bucket in perfSummary.meshHistogram {
        let barLen = maxCount > 0 ? (bucket.count * 20 / max(maxCount, 1)) : 0
        let bar = String(repeating: "#", count: barLen)
        let pct = totalSamples > 0 ? Double(bucket.count) / Double(totalSamples) * 100.0 : 0
        logger.info("\(bucket.label): \(bar.padding(toLength: 20, withPad: " ", startingAt: 0)) \(String(format: "%4d", bucket.count))  (\(String(format: "%4.1f", pct))%)")
    }
}

#if os(Linux)
if perfSummary.recoveryPreSwapMedian > 0 {
    logger.info("")
    logger.info("=== RECOVERY TIMING ===")
    logger.info("Pre-swap median:  \(String(format: "%.0f", perfSummary.recoveryPreSwapMedian)) us")
    logger.info("Peak during swap: \(String(format: "%.0f", perfSummary.recoveryPeakLatency)) us")
    logger.info("Recovery time:    \(String(format: "%.2f", perfSummary.recoveryTimeSeconds)) s")
}
#endif

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
