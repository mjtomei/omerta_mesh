// HealthTestRunner - Cross-machine test for TunnelHealthMonitor
//
// Usage:
//   Node A (first):  health-test-runner --port 18020 --lan
//   Node B (second): health-test-runner --port 18020 --lan --bootstrap "<peerIdA>@<hostA>:18020"

import Foundation
import OmertaMesh
import OmertaTunnel
import Logging

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

// Parse args
var port: Int = 18020
var bootstrap: String? = nil
var lan = false

var args = CommandLine.arguments.dropFirst()
while let arg = args.first {
    args = args.dropFirst()
    switch arg {
    case "--port":
        port = Int(args.first ?? "18020") ?? 18020
        args = args.dropFirst()
    case "--bootstrap":
        bootstrap = String(args.first ?? "")
        args = args.dropFirst()
    case "--lan":
        lan = true
    default:
        break
    }
}

// Create encryption key (must match on both nodes)
let keyString = "health-test-shared-key-2026-0128"
let encryptionKey = keyString.data(using: .utf8)!

var config = MeshConfig(
    encryptionKey: encryptionKey,
    port: port,
    bootstrapPeers: bootstrap.map { [$0] } ?? [],
    allowLocalhost: lan
)

let mesh = MeshNetwork(config: config)

logger.info("Starting mesh on port \(port)...")
if let bs = bootstrap {
    logger.info("Bootstrap peer: \(bs)")
}

try await mesh.start()

let peerId = mesh.peerId
let machineId = await mesh.machineId
logger.info("Mesh started - peerId: \(peerId) machineId: \(machineId)")

if bootstrap == nil {
    logger.info("=== THIS IS NODE A (no bootstrap) ===")
    logger.info("Run Node B with: --bootstrap \"\(peerId)@<this-ip>:\(port)\" --lan")
} else {
    logger.info("=== THIS IS NODE B (bootstrapped) ===")
}

// Discover remote machine via a ping channel
logger.info("Waiting for remote machine...")
var remoteMachineId: MachineId? = nil

// Register a discovery channel - when remote sends us a ping, we learn its machineId
try await mesh.onChannel("health-discovery") { fromMachineId, data in
    logger.info("Discovery: received from machine \(fromMachineId)")
    if remoteMachineId == nil {
        remoteMachineId = fromMachineId
    }
    // Echo back so the other side discovers us too
    try? await mesh.sendOnChannel(Data("ack".utf8), toMachine: fromMachineId, channel: "health-discovery")
}

// Wait for peer, then send discovery pings
for i in 1...30 {
    try await Task.sleep(for: .seconds(2))

    if remoteMachineId != nil { break }

    // Try to find peers and send discovery pings
    let peers = await mesh.knownPeersWithInfo()
    for peer in peers where peer.peerId != peerId {
        logger.info("Sending discovery ping to peer \(peer.peerId.prefix(16))...")
        let registry = await mesh.machinePeerRegistry
        if let mid = registry?.getMostRecentMachine(for: peer.peerId) {
            logger.info("Registry has machine \(mid) for peer \(peer.peerId.prefix(16))...")
            try? await mesh.sendOnChannel(Data("discover".utf8), toMachine: mid, channel: "health-discovery")
        }
    }

    if i % 5 == 0 {
        logger.info("Still waiting... (\(i * 2)s)")
    }
}

guard let remoteMachineId else {
    logger.error("No remote machine found after 60s. Exiting.")
    await mesh.stop()
    exit(1)
}

logger.info("Remote machine discovered: \(remoteMachineId)")

// Create TunnelManager with visible health monitoring intervals
let tunnelConfig = TunnelManagerConfig(
    healthProbeMinInterval: .seconds(2),
    healthProbeMaxInterval: .seconds(10),
    healthFailureThreshold: 3
)
let manager = TunnelManager(provider: mesh, config: tunnelConfig)
try await manager.start()
logger.info("TunnelManager started with health monitoring")

// --- TEST 1: Create session ---
logger.info("")
logger.info("=== TEST 1: Create session ===")
let session = try await manager.getSession(machineId: remoteMachineId, channel: "health-test")
let state = await session.state
logger.info("Session created, state: \(state)")

await session.onReceive { data in
    let msg = String(data: data, encoding: .utf8) ?? "<binary \(data.count)b>"
    logger.info("  <- Received: \(msg)")
}

// --- TEST 2: Send traffic (resets probe interval) ---
logger.info("")
logger.info("=== TEST 2: Send traffic (probe interval should stay at min) ===")
for i in 1...5 {
    let msg = "msg-\(i) from \(machineId.prefix(8))"
    try await session.send(Data(msg.utf8))
    logger.info("  -> Sent: \(msg)")
    // Also notify health monitor of outgoing traffic
    await manager.notifyPacketReceived(from: remoteMachineId)
    try await Task.sleep(for: .milliseconds(500))
}

// --- TEST 3: Go idle, observe health probes ---
logger.info("")
logger.info("=== TEST 3: Idle for 15s (health probes should fire, then back off) ===")
try await Task.sleep(for: .seconds(15))

// --- TEST 4: Resume traffic ---
logger.info("")
logger.info("=== TEST 4: Resume traffic after idle ===")
for i in 1...3 {
    let msg = "resumed-\(i) from \(machineId.prefix(8))"
    try await session.send(Data(msg.utf8))
    logger.info("  -> Sent: \(msg)")
    try await Task.sleep(for: .seconds(1))
}

// Stats
let stats = await session.stats
logger.info("")
logger.info("=== Session Stats ===")
logger.info("  Sent: \(stats.packetsSent) packets, \(stats.bytesSent) bytes")
logger.info("  Received: \(stats.packetsReceived) packets, \(stats.bytesReceived) bytes")

// Cleanup
logger.info("")
logger.info("=== TESTS COMPLETE ===")
await manager.stop()
await mesh.stop()
logger.info("Done.")
