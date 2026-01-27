// ObservedEndpointTests.swift - Tests for peer-reported endpoint feature
//
// Tests the endpoint observation functionality where peers report our public
// endpoint in pong messages, eliminating the need for STUN.

import XCTest
@testable import OmertaMesh

final class ObservedEndpointTests: XCTestCase {

    // MARK: - Test Fixtures

    /// Create a test encryption key
    private func createTestKey() -> Data {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }

    /// Create a MeshNode for testing
    private func createTestNode() throws -> MeshNode {
        let identity = IdentityKeypair()
        let config = MeshNode.Config(
            encryptionKey: createTestKey(),
            port: 0,
            endpointValidationMode: .allowAll
        )
        return try MeshNode(identity: identity, config: config)
    }

    // MARK: - Observed Endpoint Tests

    /// Test that observed endpoint starts as nil
    func testObservedEndpointStartsNil() async throws {
        let node = try createTestNode()

        let endpoint = await node.getObservedEndpoint
        XCTAssertNil(endpoint, "Observed endpoint should start as nil")
    }

    /// Test that endpoint change handler can be set
    func testEndpointChangeHandlerCanBeSet() async throws {
        let node = try createTestNode()

        var handlerCalled = false
        var receivedNewEndpoint: String?
        var receivedOldEndpoint: String?

        await node.setEndpointChangeHandler { newEndpoint, oldEndpoint in
            handlerCalled = true
            receivedNewEndpoint = newEndpoint
            receivedOldEndpoint = oldEndpoint
        }

        // Handler set but not yet called
        XCTAssertFalse(handlerCalled, "Handler should not be called until endpoint changes")
    }

    /// Test pong message includes yourEndpoint field
    func testPongMessageIncludesYourEndpoint() throws {
        let recentPeers: [PeerEndpointInfo] = []
        let yourEndpoint = "203.0.113.50:12345"

        let pong = MeshMessage.pong(recentPeers: recentPeers, yourEndpoint: yourEndpoint, myNATType: .unknown)

        // Verify we can pattern match and extract the endpoint
        if case .pong(let peers, let endpoint, _) = pong {
            XCTAssertEqual(peers.count, 0, "Should have no recent peers")
            XCTAssertEqual(endpoint, yourEndpoint, "Should contain the yourEndpoint value")
        } else {
            XCTFail("Should match pong pattern")
        }
    }

    /// Test pong message encodes and decodes correctly with yourEndpoint
    func testPongMessageEncodesDecodes() throws {
        let peerInfo = PeerEndpointInfo(
            peerId: "test-peer-123",
            machineId: "test-machine-456",
            endpoint: "192.168.1.100:9999",
            natType: .unknown
        )
        let yourEndpoint = "203.0.113.50:12345"

        let original = MeshMessage.pong(recentPeers: [peerInfo], yourEndpoint: yourEndpoint, myNATType: .unknown)

        // Encode
        let encoder = JSONEncoder()
        let data = try encoder.encode(original)

        // Decode
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(MeshMessage.self, from: data)

        // Verify
        if case .pong(let peers, let endpoint, _) = decoded {
            XCTAssertEqual(peers.count, 1, "Should have 1 peer")
            XCTAssertEqual(peers[0].peerId, "test-peer-123", "Peer ID should match")
            XCTAssertEqual(endpoint, yourEndpoint, "yourEndpoint should match")
        } else {
            XCTFail("Should decode to pong message")
        }
    }

    /// Test ping message format (should not include yourEndpoint)
    func testPingMessageFormat() throws {
        let peerInfo = PeerEndpointInfo(
            peerId: "test-peer-123",
            machineId: "test-machine-456",
            endpoint: "192.168.1.100:9999",
            natType: .unknown
        )

        let ping = MeshMessage.ping(recentPeers: [peerInfo], myNATType: .unknown)

        // Verify ping has recentPeers, myNATType, and requestFullList
        if case .ping(let peers, _, let requestFullList) = ping {
            XCTAssertEqual(peers.count, 1, "Should have 1 peer")
            XCTAssertEqual(peers[0].peerId, "test-peer-123", "Peer ID should match")
            XCTAssertFalse(requestFullList, "requestFullList should default to false")
        } else {
            XCTFail("Should match ping pattern")
        }
    }

    // MARK: - MeshEnvelope Tests with Pong

    /// Test that MeshEnvelope can contain pong with yourEndpoint
    func testMeshEnvelopeWithPong() throws {
        let identity = IdentityKeypair()
        let machineId = "test-machine-\(UUID().uuidString.prefix(8))"
        let yourEndpoint = "198.51.100.1:5678"

        let pong = MeshMessage.pong(recentPeers: [], yourEndpoint: yourEndpoint, myNATType: .unknown)

        let envelope = try MeshEnvelope.signed(
            from: identity,
            machineId: machineId,
            to: nil,
            payload: pong
        )

        // Verify envelope
        XCTAssertEqual(envelope.fromPeerId, identity.peerId, "From peer ID should match")
        XCTAssertEqual(envelope.machineId, machineId, "Machine ID should match")

        // Verify payload
        if case .pong(_, let endpoint, _) = envelope.payload {
            XCTAssertEqual(endpoint, yourEndpoint, "yourEndpoint should be preserved in envelope")
        } else {
            XCTFail("Payload should be pong")
        }

        // Verify signature is valid
        XCTAssertTrue(envelope.verifySignature(), "Envelope signature should be valid")
    }

    /// Test envelope encode/decode preserves pong yourEndpoint
    func testEnvelopeEncodeDecodePreservesPongEndpoint() throws {
        let identity = IdentityKeypair()
        let machineId = "test-machine-\(UUID().uuidString.prefix(8))"
        let yourEndpoint = "198.51.100.1:5678"

        let pong = MeshMessage.pong(recentPeers: [], yourEndpoint: yourEndpoint, myNATType: .unknown)

        let original = try MeshEnvelope.signed(
            from: identity,
            machineId: machineId,
            to: nil,
            payload: pong
        )

        // Encode
        let encoder = JSONEncoder()
        let data = try encoder.encode(original)

        // Decode
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(MeshEnvelope.self, from: data)

        // Verify payload preserved
        if case .pong(_, let endpoint, _) = decoded.payload {
            XCTAssertEqual(endpoint, yourEndpoint, "yourEndpoint should survive encode/decode")
        } else {
            XCTFail("Decoded payload should be pong")
        }
    }

    // MARK: - Endpoint Prioritization Tests (Phase 10)

    /// Test that incoming message endpoint is prioritized
    func testIncomingEndpointPrioritized() async throws {
        let manager = PeerEndpointManager(
            networkId: "test-network-\(UUID().uuidString.prefix(8))",
            validationMode: .allowAll
        )

        let peerId = "peer1"
        let machineId = "machine1"

        // Add announced endpoint
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "announced:5000")

        // Receive message from different endpoint (NAT-mapped)
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "natmapped:6000")

        // Best endpoint should be the one we received from most recently
        let endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints.first, "natmapped:6000", "Most recent endpoint should be first")

        // The old endpoint should still be there but second
        XCTAssertTrue(endpoints.contains("announced:5000"), "Old endpoint should still be present")
    }

    /// Test that send success promotes endpoint
    func testSendSuccessPromotesEndpoint() async throws {
        let manager = PeerEndpointManager(
            networkId: "test-network-\(UUID().uuidString.prefix(8))",
            validationMode: .allowAll
        )

        let peerId = "peer1"
        let machineId = "machine1"

        // Record two endpoints (endpoint2 is current best)
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "endpoint1:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "endpoint2:5001")

        // Verify endpoint2 is best
        var endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints.first, "endpoint2:5001", "endpoint2 should be best initially")

        // Record successful send to endpoint1
        await manager.recordSendSuccess(to: peerId, machineId: machineId, endpoint: "endpoint1:5000")

        // Now endpoint1 should be best
        endpoints = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(endpoints.first, "endpoint1:5000", "endpoint1 should be best after send success")
    }

    /// Test that bestEndpoint returns most recent endpoint
    func testBestEndpointReturnsMostRecent() async throws {
        let manager = PeerEndpointManager(
            networkId: "test-network-\(UUID().uuidString.prefix(8))",
            validationMode: .allowAll
        )

        let peerId = "peer1"
        let machineId = "machine1"

        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "old:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "new:5001")

        let machines = await manager.getAllMachines(peerId: peerId)
        XCTAssertEqual(machines.count, 1)
        XCTAssertEqual(machines[0].bestEndpoint, "new:5001", "Best endpoint should be most recent")
    }

    /// Test endpoint prioritization with multiple machines
    func testEndpointPrioritizationMultipleMachines() async throws {
        let manager = PeerEndpointManager(
            networkId: "test-network-\(UUID().uuidString.prefix(8))",
            validationMode: .allowAll
        )

        let peerId = "peer1"
        let machine1 = "machine1"
        let machine2 = "machine2"

        // Add endpoints for two machines
        await manager.recordMessageReceived(from: peerId, machineId: machine1, endpoint: "m1-old:5000")
        await manager.recordMessageReceived(from: peerId, machineId: machine2, endpoint: "m2-old:5001")

        // Update endpoint for machine1
        await manager.recordMessageReceived(from: peerId, machineId: machine1, endpoint: "m1-new:5002")

        // Machine1's best should be new, machine2's should be unchanged
        let m1Endpoints = await manager.getEndpoints(peerId: peerId, machineId: machine1)
        let m2Endpoints = await manager.getEndpoints(peerId: peerId, machineId: machine2)

        XCTAssertEqual(m1Endpoints.first, "m1-new:5002", "Machine1 best should be updated")
        XCTAssertEqual(m2Endpoints.first, "m2-old:5001", "Machine2 best should be unchanged")

        // getAllEndpoints should return endpoints from both machines
        let allEndpoints = await manager.getAllEndpoints(peerId: peerId)
        XCTAssertTrue(allEndpoints.contains("m1-new:5002"), "Should contain machine1's endpoint")
        XCTAssertTrue(allEndpoints.contains("m2-old:5001"), "Should contain machine2's endpoint")
    }
}
