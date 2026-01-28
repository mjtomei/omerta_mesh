// Phase1Tests.swift - Tests for core transport layer (Phase 1)

import XCTest
import NIOCore
import NIOPosix
@testable import OmertaMesh

/// Thread-safe counter for async tests
private actor MessageCounter {
    private var count = 0

    func increment() {
        count += 1
    }

    var value: Int {
        count
    }
}

final class Phase1Tests: XCTestCase {

    // MARK: - Test Helpers

    /// Create a test MeshNode with default test configuration
    private func makeTestNode(port: UInt16 = 0) async throws -> MeshNode {
        let identity = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let config = MeshNode.Config(
            encryptionKey: testKey,
            port: port,
            endpointValidationMode: .allowAll  // Use IPv4 for localhost testing
        )
        return try MeshNode(identity: identity, config: config)
    }

    // MARK: - Identity Tests

    /// Test keypair generation
    func testKeypairGeneration() throws {
        let keypair = IdentityKeypair()

        // Check keys are non-empty
        XCTAssertFalse(keypair.publicKeyData.isEmpty)
        XCTAssertFalse(keypair.privateKeyData.isEmpty)

        // Check peer ID is derived from public key using SHA256
        // Format: 16 lowercase hex characters (first 8 bytes of SHA256)
        XCTAssertEqual(keypair.peerId.count, 16)
        XCTAssertTrue(keypair.peerId.allSatisfy { $0.isHexDigit })

        // Verify peer ID derivation is consistent
        let derivedPeerId = IdentityKeypair.derivePeerId(from: keypair.publicKeyData)
        XCTAssertEqual(keypair.peerId, derivedPeerId)
    }

    /// Test signing and verification
    func testSignAndVerify() throws {
        let keypair = IdentityKeypair()
        let message = "Hello, mesh network!".data(using: .utf8)!

        // Sign the message
        let signature = try keypair.sign(message)

        // Verify with correct key
        XCTAssertTrue(signature.verify(message, publicKey: keypair.publicKey))

        // Verify with base64 key
        XCTAssertTrue(signature.verify(message, publicKeyBase64: keypair.publicKeyBase64))

        // Tampered message should fail
        let tamperedMessage = "Hello, tampered!".data(using: .utf8)!
        XCTAssertFalse(signature.verify(tamperedMessage, publicKey: keypair.publicKey))
    }

    /// Test keypair serialization
    func testKeypairSerialization() throws {
        let original = IdentityKeypair()

        // Export and reimport
        let exported = original.privateKeyBase64
        let restored = try IdentityKeypair(privateKeyBase64: exported)

        // Should have same peer ID (derived from public key)
        XCTAssertEqual(original.peerId, restored.peerId, "Peer IDs should match")

        // Private key data should round-trip
        XCTAssertEqual(original.privateKeyData, restored.privateKeyData, "Private key data should match")

        // Public key data should match
        XCTAssertEqual(original.publicKeyData, restored.publicKeyData, "Public key data should match")

        // Test that signatures from both keys verify correctly
        // Note: CryptoKit may use randomized Ed25519 signing, so we don't test for
        // determinism - only that signatures verify with the correct public key
        let message = "Test message".data(using: .utf8)!

        let sigOriginal = try original.sign(message)
        let sigRestored = try restored.sign(message)

        // Original key's signature should verify with original's public key
        XCTAssertTrue(sigOriginal.verify(message, publicKey: original.publicKey),
                      "Original signature should verify with original key")

        // Restored key's signature should verify with restored's public key
        XCTAssertTrue(sigRestored.verify(message, publicKey: restored.publicKey),
                      "Restored signature should verify with restored key")

        // Cross-verification: both public keys are the same, so both should work
        XCTAssertTrue(sigOriginal.verify(message, publicKeyBase64: restored.publicKeyBase64),
                      "Original sig should verify with restored pubkey")
        XCTAssertTrue(sigRestored.verify(message, publicKeyBase64: original.publicKeyBase64),
                      "Restored sig should verify with original pubkey")

        // Wrong message should fail
        let wrongMessage = "Wrong message".data(using: .utf8)!
        XCTAssertFalse(sigOriginal.verify(wrongMessage, publicKey: original.publicKey),
                       "Signature should not verify wrong message")
    }

    // MARK: - Envelope Tests

    /// Test envelope signing and verification
    func testEnvelopeSignature() throws {
        let keypair = IdentityKeypair()

        // First, test basic signing works
        let testData = "test".data(using: .utf8)!
        let testSig = try keypair.sign(testData)
        XCTAssertTrue(testSig.verify(testData, publicKey: keypair.publicKey), "Basic signing should work")

        // Now test envelope signing
        // Manually create the envelope and sign it step by step
        let messageId = UUID().uuidString
        let timestamp = Date()

        var envelope = MeshEnvelope(
            messageId: messageId,
            fromPeerId: keypair.peerId,
            publicKey: keypair.publicKeyBase64,
            machineId: "test-machine-id",
            toPeerId: "recipient",
            hopCount: 0,
            timestamp: timestamp,
            payload: .ping(recentPeers: [], myNATType: .unknown),
            signature: ""
        )

        // Get data to sign BEFORE signing
        let dataToSignBefore = try envelope.dataToSign()

        // Sign the data
        let sig = try keypair.sign(dataToSignBefore)
        envelope.signature = sig.base64

        // Get data to sign AFTER signing
        let dataToSignAfter = try envelope.dataToSign()

        // Debug: print the JSON to see what's different
        if dataToSignBefore != dataToSignAfter {
            print("BEFORE: \(String(data: dataToSignBefore, encoding: .utf8) ?? "nil")")
            print("AFTER:  \(String(data: dataToSignAfter, encoding: .utf8) ?? "nil")")
        }

        // These should be the same!
        XCTAssertEqual(dataToSignBefore, dataToSignAfter, "dataToSign should be consistent")

        // Verify the signature
        XCTAssertTrue(sig.verify(dataToSignAfter, publicKey: keypair.publicKey), "Signature should verify")

        // Signature should be present
        XCTAssertFalse(envelope.signature.isEmpty)

        // Verification using embedded public key should succeed
        XCTAssertTrue(envelope.verifySignature())

        // Envelope with tampered signature should fail
        var tamperedEnvelope = envelope
        tamperedEnvelope.signature = "invalid-signature"
        XCTAssertFalse(tamperedEnvelope.verifySignature())
    }

    /// Test envelope serialization
    func testEnvelopeSerialization() throws {
        let keypair = IdentityKeypair()

        let original = try MeshEnvelope.signed(
            from: keypair,
            machineId: "test-machine-id",
            to: "recipient",
            payload: .ping(recentPeers: [
                PeerEndpointInfo(peerId: "peer1", machineId: "machine1", endpoint: "endpoint1", natType: .unknown),
                PeerEndpointInfo(peerId: "peer2", machineId: "machine2", endpoint: "endpoint2", natType: .unknown)
            ], myNATType: .unknown)
        )

        // Encode and decode
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(MeshEnvelope.self, from: data)

        // Should preserve all fields
        XCTAssertEqual(original.messageId, decoded.messageId)
        XCTAssertEqual(original.fromPeerId, decoded.fromPeerId)
        XCTAssertEqual(original.publicKey, decoded.publicKey)
        XCTAssertEqual(original.toPeerId, decoded.toPeerId)
        XCTAssertEqual(original.signature, decoded.signature)

        // Signature should still verify using embedded public key
        XCTAssertTrue(decoded.verifySignature())
    }

    // MARK: - UDP Socket Tests

    /// Test basic UDP send and receive
    func testUDPSendReceive() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }

        let socket1 = UDPSocket(eventLoopGroup: group)
        let socket2 = UDPSocket(eventLoopGroup: group)

        try await socket1.bind(host: "127.0.0.1", port: 0)
        try await socket2.bind(host: "127.0.0.1", port: 0)

        defer {
            Task {
                await socket1.close()
                await socket2.close()
            }
        }

        _ = await socket1.port!
        let port2 = await socket2.port!

        // Set up receiver
        let receivedExpectation = expectation(description: "Data received")
        var receivedData: Data?

        await socket2.onReceive { data, _ in
            receivedData = data
            receivedExpectation.fulfill()
        }

        // Send data
        let testData = "Hello UDP!".data(using: .utf8)!
        try await socket1.send(testData, to: "127.0.0.1:\(port2)")

        await fulfillment(of: [receivedExpectation], timeout: 5.0)

        XCTAssertEqual(receivedData, testData)
    }

    // MARK: - MeshNode Tests

    /// Test two nodes exchanging ping/pong
    func testTwoNodePingPong() async throws {
        let nodeA = try await makeTestNode()
        let nodeB = try await makeTestNode()

        try await nodeA.start()
        try await nodeB.start()

        // Wait for nodes to be fully ready
        try await Task.sleep(nanoseconds: 100_000_000) // 100ms

        // Public keys are now embedded in every message, no registration needed
        let portB = await nodeB.port!

        var response: MeshMessage?
        var testError: Error?

        do {
            // A sends ping to B with longer timeout
            response = try await nodeA.sendAndReceive(
                .ping(recentPeers: [], myNATType: .unknown),
                to: "127.0.0.1:\(portB)",
                timeout: 10.0  // Increased timeout
            )
        } catch {
            testError = error
        }

        // Clean up
        await nodeA.stop()
        await nodeB.stop()

        // Check result
        if let error = testError {
            throw error
        }

        // Should get pong back
        if case .pong = response {
            // Success
        } else {
            XCTFail("Expected pong response, got \(String(describing: response))")
        }
    }

    /// Test message deduplication
    func testMessageDeduplication() async throws {
        let nodeA = try await makeTestNode()
        let nodeB = try await makeTestNode()

        defer {
            Task {
                await nodeA.stop()
                await nodeB.stop()
            }
        }

        try await nodeA.start()
        try await nodeB.start()

        let portB = await nodeB.port!

        // Track received messages on B using actor for thread-safe counting
        let counter = MessageCounter()
        await nodeB.onMessage { message, _ in
            await counter.increment()
            if case .ping = message {
                return .pong(recentPeers: [], yourEndpoint: "test-endpoint", myNATType: .unknown)
            }
            return nil
        }

        // Wait longer for handler to be fully registered
        try await Task.sleep(nanoseconds: 300_000_000) // 300ms

        // Create a keypair (public key is embedded in message, no registration needed)
        let keypair = IdentityKeypair()

        // Create a signed envelope with a fixed message ID
        let envelope = try MeshEnvelope.signed(
            messageId: "test-dedup-id-\(UUID().uuidString)",
            from: keypair,
            machineId: "test-machine-id",
            to: nil,
            payload: .ping(recentPeers: [], myNATType: .unknown)
        )
        let jsonData = try JSONEncoder().encode(envelope)

        // Encrypt the message using the same key as the test nodes
        let testKey = Data(repeating: 0x42, count: 32)
        let encryptedData = try MessageEncryption.encrypt(jsonData, key: testKey)

        // Use UDP socket directly to send duplicate
        let socket = UDPSocket()
        try await socket.bind(port: 0)
        defer { Task { await socket.close() } }

        // Send first message
        try await socket.send(encryptedData, to: "127.0.0.1:\(portB)")

        // Wait for first message to be processed
        try await Task.sleep(nanoseconds: 300_000_000) // 300ms

        // Send duplicate
        try await socket.send(encryptedData, to: "127.0.0.1:\(portB)")

        // Wait for potential second processing
        try await Task.sleep(nanoseconds: 300_000_000) // 300ms

        // Should only receive once due to deduplication
        let count = await counter.value
        XCTAssertEqual(count, 1, "Message should be deduplicated")
    }

    /// Test invalid signature rejection (when peer is known)
    func testInvalidSignatureRejection() async throws {
        let nodeA = try await makeTestNode()
        let nodeB = try await makeTestNode()

        defer {
            Task {
                await nodeA.stop()
                await nodeB.stop()
            }
        }

        try await nodeA.start()
        try await nodeB.start()

        // Create envelope with valid public key but wrong signature
        let nodeAIdentity = await nodeA.identity
        let nodeBPeerId = await nodeB.peerId
        var envelope = MeshEnvelope(
            fromPeerId: nodeAIdentity.peerId,
            publicKey: nodeAIdentity.publicKeyBase64,
            machineId: "test-machine-id",
            toPeerId: nodeBPeerId,
            payload: .ping(recentPeers: [], myNATType: .unknown)
        )
        envelope.signature = "invalid-signature-base64"

        // B should reject it - signature doesn't match the embedded public key
        let accepted = await nodeB.receiveEnvelope(envelope)
        XCTAssertFalse(accepted, "Invalid signature should be rejected")
    }

    /// Test concurrent messages
    func testConcurrentMessages() async throws {
        let nodeA = try await makeTestNode()
        let nodeB = try await makeTestNode()

        try await nodeA.start()
        try await nodeB.start()

        // Public keys are embedded in every message, no registration needed
        let portB = await nodeB.port!

        // Wait for nodes to be fully ready
        try await Task.sleep(nanoseconds: 100_000_000) // 100ms

        // Send multiple concurrent pings
        var results: [MeshMessage] = []
        var testError: Error?

        do {
            results = try await withThrowingTaskGroup(of: MeshMessage.self) { group in
                for _ in 0..<5 {
                    group.addTask {
                        try await nodeA.sendAndReceive(
                            .ping(recentPeers: [], myNATType: .unknown),
                            to: "127.0.0.1:\(portB)",
                            timeout: 10.0  // Increase timeout
                        )
                    }
                }

                var responses: [MeshMessage] = []
                for try await response in group {
                    responses.append(response)
                }
                return responses
            }
        } catch {
            testError = error
        }

        // Always clean up properly - wait a bit before stopping to let in-flight operations complete
        try? await Task.sleep(nanoseconds: 100_000_000) // 100ms grace period
        await nodeA.stop()
        await nodeB.stop()

        // Now check results
        if let error = testError {
            throw error
        }

        // All should get pong responses
        XCTAssertEqual(results.count, 5)
        for result in results {
            if case .pong = result {
                // Good
            } else {
                XCTFail("Expected pong, got \(result)")
            }
        }
    }

    /// Test timeout behavior
    func testTimeout() async throws {
        let nodeA = try await makeTestNode()

        defer {
            Task {
                await nodeA.stop()
            }
        }

        try await nodeA.start()

        // Try to send to non-existent node
        do {
            _ = try await nodeA.sendAndReceive(
                .ping(recentPeers: [], myNATType: .unknown),
                to: "127.0.0.1:59999",  // Unlikely to be listening
                timeout: 0.5
            )
            XCTFail("Should have timed out")
        } catch MeshNodeError.timeout {
            // Expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // MARK: - Peer Connection Tests

    /// Test peer connection state management
    func testPeerConnectionState() async throws {
        let keypair = IdentityKeypair()
        let connection = PeerConnection(
            peerId: keypair.peerId,
            publicKey: keypair.publicKey
        )

        // Initial state
        let initialState = await connection.state
        if case .disconnected = initialState {
            // Good
        } else {
            XCTFail("Should start disconnected")
        }

        // Mark connecting
        await connection.markConnecting()
        let connectingState = await connection.state
        if case .connecting = connectingState {
            // Good
        } else {
            XCTFail("Should be connecting")
        }

        // Mark connected
        await connection.markConnected()
        let connectedState = await connection.state
        if case .connected = connectedState {
            // Good
        } else {
            XCTFail("Should be connected")
        }

        // Last seen should be set
        let lastSeen = await connection.lastSeen
        XCTAssertNotNil(lastSeen)
    }

    /// Test peer active endpoint management
    func testPeerActiveEndpoint() async throws {
        let keypair = IdentityKeypair()
        let connection = PeerConnection(
            peerId: keypair.peerId,
            publicKey: keypair.publicKey
        )

        // Initially no active endpoint
        let initial = await connection.activeEndpoint
        XCTAssertNil(initial)

        // Set active endpoint
        await connection.setActiveEndpoint("1.2.3.4:5000")
        let active = await connection.activeEndpoint
        XCTAssertEqual(active, "1.2.3.4:5000")

        // Change active endpoint
        await connection.setActiveEndpoint("5.6.7.8:5000")
        let newActive = await connection.activeEndpoint
        XCTAssertEqual(newActive, "5.6.7.8:5000")

        // Clear active endpoint
        await connection.setActiveEndpoint(nil)
        let cleared = await connection.activeEndpoint
        XCTAssertNil(cleared)
    }

    /// Test PeerEndpointManager endpoint tracking
    func testPeerEndpointManager() async throws {
        let manager = PeerEndpointManager()

        let peerId = "test-peer-123"
        let machineId = "test-machine-456"

        // Initially no endpoints
        let initial = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertTrue(initial.isEmpty)

        // Record message received - should add endpoint
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "1.2.3.4:5000")
        let afterFirst = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(afterFirst, ["1.2.3.4:5000"])

        // Record from different endpoint - should add to front
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "5.6.7.8:5000")
        let afterSecond = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(afterSecond, ["5.6.7.8:5000", "1.2.3.4:5000"])

        // Record from first endpoint again - should move to front
        await manager.recordMessageReceived(from: peerId, machineId: machineId, endpoint: "1.2.3.4:5000")
        let afterPromote = await manager.getEndpoints(peerId: peerId, machineId: machineId)
        XCTAssertEqual(afterPromote, ["1.2.3.4:5000", "5.6.7.8:5000"])

        // Best endpoint should be first
        let best = await manager.getBestEndpoint(peerId: peerId, machineId: machineId)
        XCTAssertEqual(best, "1.2.3.4:5000")
    }

    /// Test message deduplication in peer connection
    func testPeerMessageDeduplication() async throws {
        let keypair = IdentityKeypair()
        let connection = PeerConnection(
            peerId: keypair.peerId,
            publicKey: keypair.publicKey
        )

        let messageId = "test-message-123"

        // First time should not be seen
        let firstCheck = await connection.hasSeenMessage(messageId)
        XCTAssertFalse(firstCheck)

        // Mark as seen
        await connection.markMessageSeen(messageId)

        // Now should be seen
        let secondCheck = await connection.hasSeenMessage(messageId)
        XCTAssertTrue(secondCheck)
    }
}
