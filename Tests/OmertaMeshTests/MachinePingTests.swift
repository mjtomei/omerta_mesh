// MachinePingTests.swift - Tests for machine-level ping (Phase 1: In-VM Mesh Daemon)

import XCTest
@testable import OmertaMesh

final class MachinePingTests: XCTestCase {

    // MARK: - Test Helpers

    private func makeTestNode(port: UInt16 = 0) throws -> MeshNode {
        let identity = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let config = MeshNode.Config(
            encryptionKey: testKey,
            port: port,
            endpointValidationMode: .allowAll
        )
        return try MeshNode(identity: identity, config: config)
    }

    // MARK: - Machine Ping Tests

    /// Ping a known machine that has a registered peer and endpoint — verify PingResult returned
    func testPingByMachineId() async throws {
        let nodeA = try makeTestNode()
        let nodeB = try makeTestNode()

        // Start both nodes so they bind UDP ports
        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }

        let peerIdB = await nodeB.identity.peerId
        let machineIdB: MachineId = "machine-B"
        let endpointB = "127.0.0.1:\(await nodeB.port!)"

        // Register machine → peer mapping and endpoint on nodeA
        await nodeA.machinePeerRegistry.setMachine(machineIdB, peer: peerIdB)
        await nodeA.endpointManager.recordMessageReceived(from: peerIdB, machineId: machineIdB, endpoint: endpointB)

        let result = await nodeA.sendPingWithDetails(toMachine: machineIdB, timeout: 3.0)
        XCTAssertNotNil(result, "Ping to known machine should return a result")
        XCTAssertEqual(result?.peerId, peerIdB)
        XCTAssertEqual(result?.endpoint, endpointB)
        XCTAssertGreaterThanOrEqual(result?.latencyMs ?? -1, 0)
    }

    /// Unknown machineId returns nil
    func testPingByMachineIdUnknownMachine() async throws {
        let node = try makeTestNode()

        let result = await node.sendPingWithDetails(toMachine: "nonexistent-machine")
        XCTAssertNil(result, "Ping to unknown machine should return nil")
    }

    /// Existing peer-level ping API still works unchanged
    func testPingByPeerIdStillWorks() async throws {
        let nodeA = try makeTestNode()
        let nodeB = try makeTestNode()

        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }

        let peerIdB = await nodeB.identity.peerId
        let machineIdB: MachineId = "machine-B"
        let endpointB = "127.0.0.1:\(await nodeB.port!)"

        // Register endpoint via the standard peer path
        await nodeA.endpointManager.recordMessageReceived(from: peerIdB, machineId: machineIdB, endpoint: endpointB)

        let result = await nodeA.sendPingWithDetails(to: peerIdB, timeout: 3.0)
        XCTAssertNotNil(result, "Peer-level ping should still work")
        XCTAssertEqual(result?.peerId, peerIdB)
    }

    /// Two machines share the same PeerId — ping each individually
    func testPingByMachineIdWhenMultipleMachinesSamePeer() async throws {
        let nodeA = try makeTestNode()
        let nodeB = try makeTestNode()

        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }

        let sharedPeerId = await nodeB.identity.peerId
        let machineId1: MachineId = "machine-laptop"
        let machineId2: MachineId = "machine-desktop"
        let endpointB = "127.0.0.1:\(await nodeB.port!)"

        // Both machines map to the same peer, but with different machine-specific endpoints
        // In practice they'd have different endpoints; here nodeB handles both
        await nodeA.machinePeerRegistry.setMachine(machineId1, peer: sharedPeerId)
        await nodeA.machinePeerRegistry.setMachine(machineId2, peer: sharedPeerId)
        await nodeA.endpointManager.recordMessageReceived(from: sharedPeerId, machineId: machineId1, endpoint: endpointB)
        await nodeA.endpointManager.recordMessageReceived(from: sharedPeerId, machineId: machineId2, endpoint: endpointB)

        let result1 = await nodeA.sendPingWithDetails(toMachine: machineId1, timeout: 3.0)
        let result2 = await nodeA.sendPingWithDetails(toMachine: machineId2, timeout: 3.0)

        XCTAssertNotNil(result1, "Ping to machine-laptop should succeed")
        XCTAssertNotNil(result2, "Ping to machine-desktop should succeed")
        XCTAssertEqual(result1?.peerId, sharedPeerId)
        XCTAssertEqual(result2?.peerId, sharedPeerId)
    }

    /// Machine exists in registry but endpoint is unreachable — returns nil on timeout
    func testPingByMachineIdTimeout() async throws {
        let node = try makeTestNode()

        let machineId: MachineId = "unreachable-machine"
        let fakePeerId: PeerId = "fake-peer-id"

        await node.machinePeerRegistry.setMachine(machineId, peer: fakePeerId)
        // Register an unreachable endpoint
        await node.endpointManager.recordMessageReceived(from: fakePeerId, machineId: machineId, endpoint: "192.0.2.1:9999")

        let result = await node.sendPingWithDetails(toMachine: machineId, timeout: 0.5)
        XCTAssertNil(result, "Ping to unreachable machine should return nil after timeout")
    }

    /// Verify that machine ping uses the machine-specific endpoint, not another machine's
    func testPingByMachineIdUsesCorrectEndpoint() async throws {
        let nodeA = try makeTestNode()
        let nodeB = try makeTestNode()

        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }

        let peerIdB = await nodeB.identity.peerId
        let machineId1: MachineId = "machine-1"
        let machineId2: MachineId = "machine-2"
        let realEndpoint = "127.0.0.1:\(await nodeB.port!)"
        let fakeEndpoint = "192.0.2.1:9999" // unreachable

        await nodeA.machinePeerRegistry.setMachine(machineId1, peer: peerIdB)
        await nodeA.machinePeerRegistry.setMachine(machineId2, peer: peerIdB)
        // machine-1 has the real endpoint, machine-2 has a fake one
        await nodeA.endpointManager.recordMessageReceived(from: peerIdB, machineId: machineId1, endpoint: realEndpoint)
        await nodeA.endpointManager.recordMessageReceived(from: peerIdB, machineId: machineId2, endpoint: fakeEndpoint)

        // Pinging machine-1 should succeed (uses real endpoint)
        let result1 = await nodeA.sendPingWithDetails(toMachine: machineId1, timeout: 3.0)
        XCTAssertNotNil(result1, "Ping to machine-1 should succeed using its specific endpoint")
        XCTAssertEqual(result1?.endpoint, realEndpoint)

        // Pinging machine-2 should fail (uses fake endpoint)
        let result2 = await nodeA.sendPingWithDetails(toMachine: machineId2, timeout: 0.5)
        XCTAssertNil(result2, "Ping to machine-2 should fail because its endpoint is unreachable")
    }

    /// Single machine: peer ping and machine ping give same result
    func testPingByPeerIdWithSingleMachine() async throws {
        let nodeA = try makeTestNode()
        let nodeB = try makeTestNode()

        try await nodeA.start()
        try await nodeB.start()
        defer {
            Task { await nodeA.stop() }
            Task { await nodeB.stop() }
        }

        let peerIdB = await nodeB.identity.peerId
        let machineIdB: MachineId = "only-machine"
        let endpointB = "127.0.0.1:\(await nodeB.port!)"

        await nodeA.machinePeerRegistry.setMachine(machineIdB, peer: peerIdB)
        await nodeA.endpointManager.recordMessageReceived(from: peerIdB, machineId: machineIdB, endpoint: endpointB)

        let peerResult = await nodeA.sendPingWithDetails(to: peerIdB, timeout: 3.0)
        let machineResult = await nodeA.sendPingWithDetails(toMachine: machineIdB, timeout: 3.0)

        XCTAssertNotNil(peerResult)
        XCTAssertNotNil(machineResult)
        XCTAssertEqual(peerResult?.peerId, machineResult?.peerId)
        XCTAssertEqual(peerResult?.endpoint, machineResult?.endpoint)
    }
}
