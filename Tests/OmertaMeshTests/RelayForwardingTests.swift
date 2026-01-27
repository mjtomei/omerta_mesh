// RelayForwardingTests.swift - Tests for relay message forwarding

import XCTest
@testable import OmertaMesh

final class RelayForwardingTests: XCTestCase {

    // MARK: - Message Encoding Tests

    /// Test relayForward message encoding/decoding
    func testRelayForwardMessageEncoding() throws {
        let payload = "test payload".data(using: .utf8)!
        let message = MeshMessage.relayForward(targetPeerId: "target-peer", payload: payload)

        let encoded = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)

        if case .relayForward(let target, let data) = decoded {
            XCTAssertEqual(target, "target-peer")
            XCTAssertEqual(data, payload)
        } else {
            XCTFail("Expected relayForward message")
        }
    }

    /// Test relayForwardResult message encoding/decoding (success)
    func testRelayForwardResultSuccessEncoding() throws {
        let message = MeshMessage.relayForwardResult(targetPeerId: "target-peer", success: true)

        let encoded = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)

        if case .relayForwardResult(let target, let success) = decoded {
            XCTAssertEqual(target, "target-peer")
            XCTAssertTrue(success)
        } else {
            XCTFail("Expected relayForwardResult message")
        }
    }

    /// Test relayForwardResult message encoding/decoding (failure)
    func testRelayForwardResultFailureEncoding() throws {
        let message = MeshMessage.relayForwardResult(targetPeerId: "target-peer", success: false)

        let encoded = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(MeshMessage.self, from: encoded)

        if case .relayForwardResult(let target, let success) = decoded {
            XCTAssertEqual(target, "target-peer")
            XCTAssertFalse(success)
        } else {
            XCTFail("Expected relayForwardResult message")
        }
    }

    // MARK: - sendViaRelay Tests

    /// Test sendViaRelay throws when no relays available
    func testSendViaRelayThrowsWhenNoRelays() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        // Try to send via relay to unknown peer (no relays recorded)
        do {
            try await sender.sendViaRelay(.data("test".data(using: .utf8)!), to: "unknown-peer")
            XCTFail("Should have thrown noRelayAvailable")
        } catch MeshNodeError.noRelayAvailable {
            // Expected
        }
    }

    /// Test sendViaRelay throws when relay has no endpoint
    func testSendViaRelayThrowsWhenRelayHasNoEndpoint() async throws {
        // Use random key for test isolation (different network ID)
        let encryptionKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        // Use unique peer IDs to avoid collision with persisted data
        let symmetricPeerId = "test-symmetric-\(UUID().uuidString.prefix(8))"
        let relayPeerId = "test-relay-\(UUID().uuidString.prefix(8))"

        // Record relay but don't add endpoint for it
        await sender.recordPotentialRelay(for: symmetricPeerId, via: relayPeerId)

        // Try to send via relay
        do {
            try await sender.sendViaRelay(.data("test".data(using: .utf8)!), to: symmetricPeerId)
            XCTFail("Should have thrown noRelayAvailable")
        } catch MeshNodeError.noRelayAvailable {
            // Expected - relay exists but has no endpoint
        }
    }

    /// Test sendViaRelay tries relays in order
    func testSendViaRelayTriesRelaysInOrder() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        let symmetricPeerId = "symmetric-peer"

        // Record two relays (relay2 more recent)
        await sender.recordPotentialRelay(for: symmetricPeerId, via: "relay1")
        await sender.recordPotentialRelay(for: symmetricPeerId, via: "relay2")

        // Add endpoint only for relay2 (most recent)
        await sender.updatePeerEndpoint("relay2", endpoint: "127.0.0.1:9999")

        // Send should succeed using relay2
        do {
            try await sender.sendViaRelay(.ping(recentPeers: [], myNATType: .public), to: symmetricPeerId)
            // Success - relay2 was used
        } catch {
            XCTFail("Should have succeeded with relay2: \(error)")
        }
    }

    // MARK: - MeshNodeError Tests

    /// Test noRelayAvailable error description
    func testNoRelayAvailableErrorDescription() {
        let error = MeshNodeError.noRelayAvailable
        XCTAssertEqual(error.description, "No relay available for symmetric NAT peer")
    }

    /// Test noRelayAvailable error converts to MeshError
    func testNoRelayAvailableConvertsToMeshError() {
        let error = MeshNodeError.noRelayAvailable
        let meshError = error.asMeshError

        if case .sendFailed(let reason) = meshError {
            XCTAssertTrue(reason.contains("relay"))
        } else {
            XCTFail("Expected sendFailed error")
        }
    }
}
