// MultiEndpointIntegrationTests.swift - Integration tests for multi-endpoint tunnels

import XCTest
@testable import OmertaTunnel
@testable import OmertaMesh

final class MultiEndpointIntegrationTests: XCTestCase {

    /// Shared encryption key for test networks
    private var testEncryptionKey: Data {
        Data(repeating: 0x42, count: 32)
    }

    private var basePort: Int { 19200 }

    private func ensureMeshConnectivity(
        mesh1: MeshNetwork,
        mesh2: MeshNetwork,
        identity1: IdentityKeypair,
        identity2: IdentityKeypair,
        port1: Int,
        port2: Int
    ) async throws {
        await mesh1.addPeer(identity2.peerId, endpoint: "127.0.0.1:\(port2)")
        await mesh2.addPeer(identity1.peerId, endpoint: "127.0.0.1:\(port1)")

        for _ in 1...10 {
            let r1 = await mesh1.ping(identity2.peerId, timeout: 1.0)
            let r2 = await mesh2.ping(identity1.peerId, timeout: 1.0)
            if r1 != nil && r2 != nil { return }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    // MARK: - Tests

    func testMultiEndpointSessionEstablishment() async throws {
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

        defer { Task { await mesh1.stop(); await mesh2.stop() } }

        try await mesh1.start()
        try await mesh2.start()
        try await ensureMeshConnectivity(
            mesh1: mesh1, mesh2: mesh2,
            identity1: identity1, identity2: identity2,
            port1: port1, port2: port2
        )

        // Use config requesting extra endpoints
        let tunnelConfig = TunnelManagerConfig(extraEndpoints: 2)
        let tunnel1 = TunnelManager(provider: mesh1, config: tunnelConfig)
        let tunnel2 = TunnelManager(provider: mesh2)

        try await tunnel1.start()
        try await tunnel2.start()

        defer { Task { await tunnel1.stop(); await tunnel2.stop() } }

        let machineId1 = await mesh1.machineId
        await tunnel2.setInboundSessionHandler { machineId, channel in
            return { _ in }
        }

        let machineId2 = await mesh2.machineId
        let session = try await tunnel1.createSession(withMachine: machineId2)
        XCTAssertNotNil(session)

        // Verify session has an endpoint set
        let endpointSet = await session.getEndpointSet()
        XCTAssertNotNil(endpointSet)

        // Wait for session on mesh2
        for _ in 1...25 {
            let count = await tunnel2.sessionCount
            if count == 1 { break }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        let count2 = await tunnel2.sessionCount
        XCTAssertEqual(count2, 1)
    }

    func testMultiEndpointMessageExchange() async throws {
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

        defer { Task { await mesh1.stop(); await mesh2.stop() } }

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

        defer { Task { await tunnel1.stop(); await tunnel2.stop() } }

        let messageReceived = expectation(description: "Message received")
        var receivedData: Data?

        await tunnel2.setInboundSessionHandler { _, _ in
            return { data in
                receivedData = data
                messageReceived.fulfill()
            }
        }

        let machineId2 = await mesh2.machineId
        let session = try await tunnel1.createSession(withMachine: machineId2)
        try await Task.sleep(nanoseconds: 200_000_000)

        let testMessage = Data("Multi-endpoint test".utf8)
        try await session.send(testMessage)

        await fulfillment(of: [messageReceived], timeout: 5.0)
        XCTAssertEqual(receivedData, testMessage)
    }

    func testEndpointSetSchedulingWithSingleEndpoint() async throws {
        // Verify that with only one endpoint in the set, flush still works normally
        let provider = MockChannelProvider()
        let session = TunnelSession(
            remoteMachineId: "machine-1",
            channel: "data",
            provider: provider
        )
        await session.activate()

        let endpointSet = EndpointSet()
        await endpointSet.add(address: "10.0.0.1:5000", localPort: nil)
        await session.setEndpointSet(endpointSet)

        // With only 1 endpoint, flush should use standard send path
        try await session.sendAndFlush(Data([1, 2, 3]))

        let messages = await provider.getSentMessages()
        XCTAssertEqual(messages.count, 1)

        await session.close()
    }
}
