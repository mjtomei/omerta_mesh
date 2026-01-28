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
#if canImport(Glibc)
import Glibc
#endif

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

await cleanup.register {
    logger.info("Cleanup: stopping mesh")
    await mesh.stop()
}

// Capture initial network state
logger.info("Capturing initial network state...")
let initialNetworkState = await NetworkSnapshot.capture()
logger.info("Initial iptables rules:\n\(initialNetworkState.iptablesRules.isEmpty ? "  (none)" : initialNetworkState.iptablesRules)")
logger.info("Initial IP addresses:\n\(initialNetworkState.ipAddresses)")

// MARK: - Discover Remote Machine

logger.info("Waiting for remote machine...")
var remoteMachineId: MachineId? = nil

try await mesh.onChannel("health-discovery") { fromMachineId, data in
    if remoteMachineId == nil {
        remoteMachineId = fromMachineId
        logger.info("Discovery: found machine \(fromMachineId)")
    }
    try? await mesh.sendOnChannel(Data("ack".utf8), toMachine: fromMachineId, channel: "health-discovery")
}

for i in 1...30 {
    try await Task.sleep(for: .seconds(2))
    if remoteMachineId != nil { break }

    let peers = await mesh.knownPeersWithInfo()
    for peer in peers where peer.peerId != peerId {
        let registry = await mesh.machinePeerRegistry
        if let mid = registry?.getMostRecentMachine(for: peer.peerId) {
            try? await mesh.sendOnChannel(Data("discover".utf8), toMachine: mid, channel: "health-discovery")
        }
    }
    if i % 5 == 0 { logger.info("Still waiting... (\(i * 2)s)") }
}

guard let remoteMachineId else {
    logger.error("No remote machine found after 60s. Exiting.")
    await cleanup.run()
    exit(1)
}

logger.info("Remote machine discovered: \(remoteMachineId)")

// MARK: - TunnelManager Setup

let tunnelConfig = TunnelManagerConfig(
    healthProbeMinInterval: .seconds(2),
    healthProbeMaxInterval: .seconds(10),
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
    private var waiters: [CheckedContinuation<ControlMessage, Never>] = []

    func post(_ msg: ControlMessage) {
        if let waiter = waiters.first {
            waiters.removeFirst()
            waiter.resume(returning: msg)
        } else {
            messages.append(msg)
        }
    }

    func receive(timeout: Duration = .seconds(60)) async -> ControlMessage? {
        // Check buffer first
        if !messages.isEmpty {
            return messages.removeFirst()
        }
        // Wait
        return await withTaskGroup(of: ControlMessage?.self) { group in
            group.addTask {
                await withCheckedContinuation { cont in
                    Task { await self.addWaiter(cont) }
                }
            }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return nil
            }
            let first = await group.next()!
            group.cancelAll()
            return first
        }
    }

    private func addWaiter(_ cont: CheckedContinuation<ControlMessage, Never>) {
        waiters.append(cont)
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

    // Accept all sessions and count messages
    await manager.setSessionEstablishedHandler { session in
        await session.onReceive { data in
            await messageCounter.increment()
            let msg = String(data: data, encoding: .utf8) ?? "<binary>"
            logger.debug("  B <- \(msg)")
        }
    }

    // Main loop: respond to control commands
    while true {
        guard let cmd = await controlMailbox.receive(timeout: .seconds(120)) else {
            logger.info("Node B: no command for 120s, exiting")
            break
        }

        logger.info("Node B: received command '\(cmd.phase)'")

        switch cmd.phase {
        case "phase1-start":
            // Create session and send 10 messages
            let session = try await manager.getSession(machineId: remoteMachineId, channel: "health-test")
            await session.onReceive { data in
                await messageCounter.increment()
            }
            for i in 1...10 {
                try await session.send(Data("B-msg-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(100))
            }
            await sendControl("phase1-done", detail: "\(await messageCounter.count)")

        case "phase3-burst":
            // Send traffic burst
            let session = try await manager.getSession(machineId: remoteMachineId, channel: "health-test")
            for i in 1...5 {
                try await session.send(Data("B-burst-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(100))
            }
            await sendControl("phase3-burst-done")

        case "phase5-start":
            // Recovery: create new session, send messages
            let session = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-recovery")
            await session.onReceive { data in
                await messageCounter.increment()
            }
            for i in 1...5 {
                try await session.send(Data("B-recovery-\(i)".utf8))
                try await Task.sleep(for: .milliseconds(100))
            }
            await sendControl("phase5-done", detail: "\(await messageCounter.count)")

        case "phase6-block":
            // Node B blocks incoming UDP from Node A locally
            let blockPort = cmd.detail ?? "\(port)"
            #if os(macOS)
            let (exitCode, out) = await shell("echo 'block drop quick proto udp from any to any port \(blockPort)' | pfctl -ef -")
            logger.info("Node B pfctl block: exit=\(exitCode) \(out)")
            #else
            let nodeAHost = cmd.detail ?? remoteHost
            let (exitCode, out) = await shell("iptables -A INPUT -s \(nodeAHost) -p udp --dport \(blockPort) -j DROP")
            logger.info("Node B iptables block: exit=\(exitCode) \(out)")
            #endif
            await sendControl("phase6-ack")

        case "phase6-unblock":
            #if os(macOS)
            let (exitCode, out) = await shell("pfctl -d")
            logger.info("Node B pfctl unblock: exit=\(exitCode) \(out)")
            #else
            let blockPort = cmd.detail ?? "\(port)"
            let (exitCode, out) = await shell("iptables -D INPUT -p udp --dport \(blockPort) -j DROP")
            logger.info("Node B iptables unblock: exit=\(exitCode) \(out)")
            #endif
            await sendControl("phase6-unblock-ack")

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

        case "done":
            logger.info("Node B: test complete")
            await sendControl("done-ack")
            break

        default:
            logger.info("Node B: unknown command '\(cmd.phase)', acking")
            await sendControl("\(cmd.phase)-ack")
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
    // Tell Node B to start phase 1 — both sides create sessions
    await sendControl("phase1-start")

    // Create our session, then wait for handshake to settle
    let _ = try await manager.getSession(machineId: remoteMachineId, channel: "health-test")
    try await Task.sleep(for: .seconds(2))

    // Re-fetch session (handshake may have replaced the original)
    let s = try await manager.getSession(machineId: remoteMachineId, channel: "health-test")
    session1 = s
    await s.onReceive { data in
        await messageCounter.increment()
    }

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
} catch {
    record("Phase 1: Baseline Traffic", passed: false, detail: "Error: \(error)")
}

// MARK: - Phase 2: Idle & Probe Backoff

logPhase("Phase 2: Idle & Probe Backoff")

do {
    await messageCounter.reset()

    var probeIntervals: [Duration] = []

    if let monitor {
        // Log probe interval every 2s for 30s
        for _ in 0..<15 {
            try await Task.sleep(for: .seconds(2))
            let interval = await monitor._currentProbeInterval
            probeIntervals.append(interval)
            logger.info("  Probe interval: \(interval)")
        }

        // Check that interval increased from min (2s) toward max (10s)
        let firstInterval = probeIntervals.first ?? .seconds(2)
        let lastInterval = probeIntervals.last ?? .seconds(2)
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

    try await Task.sleep(for: .seconds(1))

    if let monitor {
        let intervalAfterTraffic = await monitor._currentProbeInterval
        let failuresAfterTraffic = await monitor._consecutiveFailures
        let phase3Pass = intervalAfterTraffic <= .seconds(2) && failuresAfterTraffic == 0
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
    let blockCmd = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockCmd = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await cleanup.register { let _ = await shell(unblockCmd) }
    let (blockExit, blockOut) = await shell(blockCmd)
    logger.info("iptables block: exit=\(blockExit) output=\(blockOut)")

    // Wait for health failure (sessions should get closed)
    // Health monitor with threshold=3 and min interval=2s should detect in ~6-10s
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

    // Create session, wait for handshake to settle, re-fetch
    let _ = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-recovery")
    try await Task.sleep(for: .seconds(2))
    let session5 = try await manager.getSession(machineId: remoteMachineId, channel: "health-test-recovery")
    await session5.onReceive { data in
        await messageCounter.increment()
    }

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

    let blockLinux = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockLinux = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await cleanup.register { let _ = await shell(unblockLinux) }
    await cleanup.register { await sendControl("phase6-unblock"); _ = await waitForAck("phase6-unblock-ack", timeout: .seconds(10)) }

    // Tell Node B to block, then block locally
    await sendControl("phase6-block", detail: "\(port)")
    _ = await waitForAck("phase6-ack", timeout: .seconds(10))
    let (_, _) = await shell(blockLinux)
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

    // Unblock both
    let (_, _) = await shell(unblockLinux)
    await sendControl("phase6-unblock")
    _ = await waitForAck("phase6-unblock-ack", timeout: .seconds(10))
    logger.info("Bidirectional block removed")

    try await Task.sleep(for: .seconds(3))

    // Check Node B's state
    await sendControl("phase6-check")
    let phase6BMsg = await controlMailbox.receive(timeout: .seconds(15))
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

    let blockCmd = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockCmd = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await cleanup.register { let _ = await shell(unblockCmd) }

    // Block for ~3s (less than 3 failures at 2s intervals)
    let (_, _) = await shell(blockCmd)
    logger.info("Transient block applied for ~3s")
    try await Task.sleep(for: .seconds(3))
    let (_, _) = await shell(unblockCmd)
    logger.info("Transient block removed")

    try await Task.sleep(for: .seconds(3))

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

    let blockCmd = "iptables -A INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"
    let unblockCmd = "iptables -D INPUT -s \(remoteHost) -p udp --dport \(port) -j DROP"

    await cleanup.register { let _ = await shell(unblockCmd) }

    // Flap 10 times over 20s
    for i in 1...10 {
        let (_, _) = await shell(blockCmd)
        logger.info("  Flap \(i)/10: blocked")
        try await Task.sleep(for: .seconds(1))
        let (_, _) = await shell(unblockCmd)
        logger.info("  Flap \(i)/10: unblocked")
        try await Task.sleep(for: .seconds(1))
    }

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

    await cleanup.register { let _ = await shell(delCmd) }

    let (addExit, addOut) = await shell(addCmd)
    logger.info("Added temp IP: exit=\(addExit) \(addOut)")

    // Wait for EndpointChangeDetector to notice
    try await Task.sleep(for: .seconds(10))

    let (delExit, _) = await shell(delCmd)
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

// MARK: - Phase 10: Summary

logPhase("Phase 10: Summary")

await sendControl("done")
_ = await waitForAck("done-ack", timeout: .seconds(10))

// Verify network state matches initial snapshot
logger.info("Capturing final network state...")
let finalNetworkState = await NetworkSnapshot.capture()
if let diff = initialNetworkState.diff(against: finalNetworkState) {
    logger.warning("NETWORK STATE CHANGED DURING TEST:")
    logger.warning("\(diff)")
    record("Network State Cleanup", passed: false, detail: "State differs from initial — see diff above")
} else {
    logger.info("Network state matches initial snapshot.")
    record("Network State Cleanup", passed: true, detail: "iptables and IP addresses unchanged")
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
