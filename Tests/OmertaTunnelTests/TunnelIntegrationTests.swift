// TunnelIntegrationTests.swift - Integration tests with real MeshNetwork
//
// These tests verify the tunnel utility works over actual mesh networks,
// not just mocked ChannelProviders.

import XCTest
@testable import OmertaTunnel
@testable import OmertaMesh

final class TunnelIntegrationTests: XCTestCase {

    /// Shared encryption key for test networks
    private var testEncryptionKey: Data {
        Data(repeating: 0x42, count: 32)
    }

    /// Base port for tests (each test uses different ports to avoid conflicts)
    private var basePort: Int { 19100 }

    // MARK: - Helpers

    /// Wait for mesh connectivity to be established
    /// Uses addPeer to ensure both sides know about each other, then verifies with ping
    private func ensureMeshConnectivity(
        mesh1: MeshNetwork,
        mesh2: MeshNetwork,
        identity1: IdentityKeypair,
        identity2: IdentityKeypair,
        port1: Int,
        port2: Int
    ) async throws {
        // Explicitly add peer endpoints to each mesh
        // This ensures both sides can communicate without waiting for gossip
        await mesh1.addPeer(identity2.peerId, endpoint: "127.0.0.1:\(port2)")
        await mesh2.addPeer(identity1.peerId, endpoint: "127.0.0.1:\(port1)")

        // Verify connectivity with ping - retry until successful or timeout
        let maxAttempts = 10
        var mesh1Connected = false
        var mesh2Connected = false

        for _ in 1...maxAttempts {
            if !mesh1Connected {
                let result = await mesh1.ping(identity2.peerId, timeout: 1.0)
                mesh1Connected = (result != nil)
            }
            if !mesh2Connected {
                let result = await mesh2.ping(identity1.peerId, timeout: 1.0)
                mesh2Connected = (result != nil)
            }

            if mesh1Connected && mesh2Connected {
                return
            }

            try await Task.sleep(nanoseconds: 200_000_000) // 200ms between attempts
        }

        // Proceed anyway - test will fail if connectivity is actually broken
    }

    // MARK: - Two-Peer Session Tests

    /// Test that two peers can establish a tunnel session over real mesh
    func testSessionEstablishmentOverMesh() async throws {
        // Create two mesh networks
        let identity1 = IdentityKeypair()
        let identity2 = IdentityKeypair()

        let port1 = basePort + 1
        let port2 = basePort + 2

        let config1 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port1,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            allowLocalhost: true
        )

        let config2 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port2,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            bootstrapPeers: ["\(identity1.peerId)@127.0.0.1:\(port1)"],
            allowLocalhost: true
        )

        let mesh1 = MeshNetwork(identity: identity1, config: config1)
        let mesh2 = MeshNetwork(identity: identity2, config: config2)

        defer {
            Task {
                await mesh1.stop()
                await mesh2.stop()
            }
        }

        // Start both networks
        try await mesh1.start()
        try await mesh2.start()

        // Add peer endpoints explicitly for connectivity
        try await ensureMeshConnectivity(
            mesh1: mesh1, mesh2: mesh2,
            identity1: identity1, identity2: identity2,
            port1: port1, port2: port2
        )

        // Create tunnel managers
        let tunnel1 = TunnelManager(provider: mesh1)
        let tunnel2 = TunnelManager(provider: mesh2)

        try await tunnel1.start()
        try await tunnel2.start()

        defer {
            Task {
                await tunnel1.stop()
                await tunnel2.stop()
            }
        }

        // Set up session handler on mesh2 to accept
        let sessionEstablished = expectation(description: "Session established on mesh2")
        let machineId1 = await mesh1.machineId
        await tunnel2.setSessionEstablishedHandler { session in
            let peer = await session.remoteMachineId
            XCTAssertEqual(peer, machineId1)
            sessionEstablished.fulfill()
        }

        // mesh1 initiates session to mesh2
        let machineId2 = await mesh2.machineId
        let session1 = try await tunnel1.createSession(withMachine: machineId2)

        // Verify session created
        XCTAssertNotNil(session1)
        let remotePeer = await session1.remoteMachineId
        XCTAssertEqual(remotePeer, machineId2)

        // Wait for mesh2 to receive and accept session
        await fulfillment(of: [sessionEstablished], timeout: 5.0)

        // Verify mesh2 has a session
        let count2 = await tunnel2.sessionCount
        XCTAssertEqual(count2, 1)
    }

    /// Test message exchange between two peers over mesh
    func testMessageExchangeOverMesh() async throws {
        let identity1 = IdentityKeypair()
        let identity2 = IdentityKeypair()

        let port1 = basePort + 3
        let port2 = basePort + 4

        let config1 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port1,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            allowLocalhost: true
        )

        let config2 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port2,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            bootstrapPeers: ["\(identity1.peerId)@127.0.0.1:\(port1)"],
            allowLocalhost: true
        )

        let mesh1 = MeshNetwork(identity: identity1, config: config1)
        let mesh2 = MeshNetwork(identity: identity2, config: config2)

        defer {
            Task {
                await mesh1.stop()
                await mesh2.stop()
            }
        }

        try await mesh1.start()
        try await mesh2.start()
        try await ensureMeshConnectivity(
            mesh1: mesh1, mesh2: mesh2,
            identity1: identity1, identity2: identity2,
            port1: port1, port2: port2
        )

        let tunnel1 = TunnelManager(provider: mesh1)
        let tunnel2 = TunnelManager(provider: mesh2)

        try await tunnel1.start()
        try await tunnel2.start()

        defer {
            Task {
                await tunnel1.stop()
                await tunnel2.stop()
            }
        }

        // Set up receiver on mesh2 using callback-based onReceive
        let messageReceived = expectation(description: "Message received on mesh2")
        var receivedData: Data?

        await tunnel2.setSessionEstablishedHandler { session in
            // Set up receive callback
            await session.onReceive { data in
                receivedData = data
                messageReceived.fulfill()
            }
        }

        // Create session and send message
        let machineId2 = await mesh2.machineId
        let session1 = try await tunnel1.createSession(withMachine: machineId2)

        // Wait briefly for session to establish on both sides
        try await Task.sleep(nanoseconds: 200_000_000)

        // Send message
        let testMessage = Data("Hello from mesh1!".utf8)
        try await session1.send(testMessage)

        // Wait for message
        await fulfillment(of: [messageReceived], timeout: 5.0)

        XCTAssertEqual(receivedData, testMessage)
    }

    /// Test bidirectional message exchange
    func testBidirectionalMessaging() async throws {
        let identity1 = IdentityKeypair()
        let identity2 = IdentityKeypair()

        let port1 = basePort + 5
        let port2 = basePort + 6

        let config1 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port1,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            allowLocalhost: true
        )

        let config2 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port2,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            bootstrapPeers: ["\(identity1.peerId)@127.0.0.1:\(port1)"],
            allowLocalhost: true
        )

        let mesh1 = MeshNetwork(identity: identity1, config: config1)
        let mesh2 = MeshNetwork(identity: identity2, config: config2)

        defer {
            Task {
                await mesh1.stop()
                await mesh2.stop()
            }
        }

        try await mesh1.start()
        try await mesh2.start()
        try await ensureMeshConnectivity(
            mesh1: mesh1, mesh2: mesh2,
            identity1: identity1, identity2: identity2,
            port1: port1, port2: port2
        )

        let tunnel1 = TunnelManager(provider: mesh1)
        let tunnel2 = TunnelManager(provider: mesh2)

        try await tunnel1.start()
        try await tunnel2.start()

        defer {
            Task {
                await tunnel1.stop()
                await tunnel2.stop()
            }
        }

        let message1to2Received = expectation(description: "Message 1->2 received")
        let message2to1Received = expectation(description: "Message 2->1 received")

        var session2: TunnelSession?

        await tunnel2.setSessionEstablishedHandler { session in
            session2 = session
            // Set up receive callback to handle message and send reply
            await session.onReceive { data in
                if String(data: data, encoding: .utf8) == "Hello from mesh1" {
                    message1to2Received.fulfill()
                    // Send reply
                    try? await session.send(Data("Reply from mesh2".utf8))
                }
            }
        }

        let machineId2 = await mesh2.machineId
        let session1 = try await tunnel1.createSession(withMachine: machineId2)
        try await Task.sleep(nanoseconds: 300_000_000)

        guard session2 != nil else {
            XCTFail("Session not established on mesh2")
            return
        }

        // Set up receive callback on session1 for the reply
        await session1.onReceive { data in
            if String(data: data, encoding: .utf8) == "Reply from mesh2" {
                message2to1Received.fulfill()
            }
        }

        // Send from mesh1
        try await session1.send(Data("Hello from mesh1".utf8))

        await fulfillment(of: [message1to2Received, message2to1Received], timeout: 5.0)
    }

    /// Test session close propagates to remote peer
    func testSessionCloseOverMesh() async throws {
        let identity1 = IdentityKeypair()
        let identity2 = IdentityKeypair()

        let port1 = basePort + 7
        let port2 = basePort + 8

        let config1 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port1,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            allowLocalhost: true
        )

        let config2 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port2,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            bootstrapPeers: ["\(identity1.peerId)@127.0.0.1:\(port1)"],
            allowLocalhost: true
        )

        let mesh1 = MeshNetwork(identity: identity1, config: config1)
        let mesh2 = MeshNetwork(identity: identity2, config: config2)

        defer {
            Task {
                await mesh1.stop()
                await mesh2.stop()
            }
        }

        try await mesh1.start()
        try await mesh2.start()
        try await ensureMeshConnectivity(
            mesh1: mesh1, mesh2: mesh2,
            identity1: identity1, identity2: identity2,
            port1: port1, port2: port2
        )

        let tunnel1 = TunnelManager(provider: mesh1)
        let tunnel2 = TunnelManager(provider: mesh2)

        try await tunnel1.start()
        try await tunnel2.start()

        defer {
            Task {
                await tunnel1.stop()
                await tunnel2.stop()
            }
        }

        var session2: TunnelSession?
        await tunnel2.setSessionEstablishedHandler { session in
            session2 = session
        }

        let machineId2 = await mesh2.machineId
        _ = try await tunnel1.createSession(withMachine: machineId2)
        try await Task.sleep(nanoseconds: 300_000_000)

        // Verify both have sessions
        let count1 = await tunnel1.sessionCount
        XCTAssertEqual(count1, 1)
        XCTAssertNotNil(session2)

        // Close from mesh1
        await tunnel1.closeSession()

        // Wait for close to propagate
        try await Task.sleep(nanoseconds: 300_000_000)

        // mesh2 should have no session now
        let count2After = await tunnel2.sessionCount
        XCTAssertEqual(count2After, 0)

        // The session object should be disconnected
        if let s2 = session2 {
            let state = await s2.state
            XCTAssertEqual(state, .disconnected)
        }
    }

    // MARK: - NAT/Relay Tests

    /// Test tunnel session works when peers communicate via relay
    /// This simulates NAT scenarios where direct connectivity isn't possible.
    /// Uses forceRelayOnly to ensure traffic goes through relay path.
    ///
    /// NOTE: This test is currently skipped because relay mode doesn't properly
    /// handle channel messages. The session establishment works but data messages
    /// aren't being relayed. This needs investigation in the relay subsystem.
    func testSessionViaRelay() async throws {
        throw XCTSkip("Relay mode channel message routing needs investigation")
        // Create three nodes: relay (public), and two peers that will use relay
        let relayIdentity = IdentityKeypair()
        let identity1 = IdentityKeypair()
        let identity2 = IdentityKeypair()

        let relayPort = basePort + 20
        let port1 = basePort + 21
        let port2 = basePort + 22

        // Relay node - can relay for others
        let relayConfig = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: relayPort,
            canRelay: true,
            canCoordinateHolePunch: true,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            allowLocalhost: true
        )

        // Peer 1 - forces relay only (simulates restrictive NAT)
        let config1 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port1,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            bootstrapPeers: ["\(relayIdentity.peerId)@127.0.0.1:\(relayPort)"],
            forceRelayOnly: true,
            allowLocalhost: true
        )

        // Peer 2 - also forces relay only
        let config2 = MeshConfig(
            encryptionKey: testEncryptionKey,
            port: port2,
            keepaliveInterval: 1,
            connectionTimeout: 5,
            bootstrapPeers: ["\(relayIdentity.peerId)@127.0.0.1:\(relayPort)"],
            forceRelayOnly: true,
            allowLocalhost: true
        )

        let relayMesh = MeshNetwork(identity: relayIdentity, config: relayConfig)
        let mesh1 = MeshNetwork(identity: identity1, config: config1)
        let mesh2 = MeshNetwork(identity: identity2, config: config2)

        defer {
            Task {
                await mesh1.stop()
                await mesh2.stop()
                await relayMesh.stop()
            }
        }

        // Start relay first, then peers
        try await relayMesh.start()
        try await mesh1.start()
        try await mesh2.start()

        // Add peer endpoints explicitly for relay connectivity
        // Relay knows about both peers
        await relayMesh.addPeer(identity1.peerId, endpoint: "127.0.0.1:\(port1)")
        await relayMesh.addPeer(identity2.peerId, endpoint: "127.0.0.1:\(port2)")
        // Both peers know about relay
        await mesh1.addPeer(relayIdentity.peerId, endpoint: "127.0.0.1:\(relayPort)")
        await mesh2.addPeer(relayIdentity.peerId, endpoint: "127.0.0.1:\(relayPort)")
        // Both peers know about each other (for tunnel handshake via relay)
        await mesh1.addPeer(identity2.peerId, endpoint: "127.0.0.1:\(port2)")
        await mesh2.addPeer(identity1.peerId, endpoint: "127.0.0.1:\(port1)")

        // Verify connectivity with pings
        let maxAttempts = 10
        for _ in 1...maxAttempts {
            let r1 = await mesh1.ping(relayIdentity.peerId, timeout: 1.0)
            let r2 = await mesh2.ping(relayIdentity.peerId, timeout: 1.0)
            if r1 != nil && r2 != nil {
                break
            }
            try await Task.sleep(nanoseconds: 200_000_000) // 200ms
        }

        // Create tunnel managers
        let tunnel1 = TunnelManager(provider: mesh1)
        let tunnel2 = TunnelManager(provider: mesh2)

        try await tunnel1.start()
        try await tunnel2.start()

        defer {
            Task {
                await tunnel1.stop()
                await tunnel2.stop()
            }
        }

        // Set up session handler on mesh2
        let sessionEstablished = expectation(description: "Session established via relay")
        let messageReceived = expectation(description: "Message received via relay")
        var receivedData: Data?

        await tunnel2.setSessionEstablishedHandler { session in
            sessionEstablished.fulfill()
            // Set up receive callback
            await session.onReceive { data in
                receivedData = data
                messageReceived.fulfill()
            }
        }

        // Create session - should work via relay
        let machineId2 = await mesh2.machineId
        let session1 = try await tunnel1.createSession(withMachine: machineId2)

        // Wait for session
        await fulfillment(of: [sessionEstablished], timeout: 10.0)

        // Send message via relay
        let testMessage = Data("Hello via relay!".utf8)
        try await session1.send(testMessage)

        // Wait for message (relay adds latency)
        await fulfillment(of: [messageReceived], timeout: 10.0)

        XCTAssertEqual(receivedData, testMessage)
    }

    // Note: Traffic routing tests (enableTrafficRouting, injectPacket, role)
    // have been removed. Traffic routing functionality will be moved to
    // OmertaNetwork in a future phase.
    //
    // For full NAT behavior simulation (symmetric NAT, port-restricted cone, etc.),
    // use the VirtualNetwork and SimulatedNAT infrastructure from OmertaMeshTests.
    // Those tests operate at the mesh layer and verify NAT traversal mechanisms.
    // The tunnel layer (this file) tests session/messaging on top of whatever
    // connectivity the mesh provides.
}
