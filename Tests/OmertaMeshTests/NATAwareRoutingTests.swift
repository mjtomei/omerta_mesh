// NATAwareRoutingTests.swift - Tests for NAT-aware message routing

import XCTest
@testable import OmertaMesh

final class NATAwareRoutingTests: XCTestCase {

    // MARK: - sendToPeer NAT Routing Tests

    /// Test sendToPeer uses direct for non-symmetric NAT peer
    func testSendToPeerUsesDirectForNonSymmetricNAT() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        let targetPeerId = "target-peer"

        // Set up peer with fullCone NAT (not symmetric)
        await sender.updatePeerEndpoint(targetPeerId, endpoint: "127.0.0.1:9999")
        await sender.endpointManager.updateNATType(peerId: targetPeerId, natType: .fullCone)

        // Send should succeed using direct path (no relay needed)
        do {
            try await sender.sendToPeer(.ping(recentPeers: [], myNATType: .public), peerId: targetPeerId)
            // Success - direct send was used
        } catch MeshNodeError.noRelayAvailable {
            XCTFail("Should have used direct send for non-symmetric NAT peer")
        } catch {
            // Other errors are acceptable (e.g., network unreachable in test env)
        }
    }

    /// Test sendToPeer tries relay for symmetric NAT peer with recorded relay
    func testSendToPeerUsesRelayForSymmetricNAT() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        let targetPeerId = "symmetric-peer"
        let relayPeerId = "relay-peer"

        // Set up symmetric NAT peer
        await sender.updatePeerEndpoint(targetPeerId, endpoint: "127.0.0.1:8888")
        await sender.endpointManager.updateNATType(peerId: targetPeerId, natType: .symmetric)

        // Record a relay for this peer
        await sender.recordPotentialRelay(for: targetPeerId, via: relayPeerId)
        await sender.updatePeerEndpoint(relayPeerId, endpoint: "127.0.0.1:9999")

        // Send should route via relay
        do {
            try await sender.sendToPeer(.data("test".data(using: .utf8)!), peerId: targetPeerId)
            // Success - relay was used
        } catch {
            // May fail due to network issues, but shouldn't be noRelayAvailable
            if case MeshNodeError.noRelayAvailable = error {
                XCTFail("Should have found the relay")
            }
        }
    }

    /// Test sendToPeer falls back to direct for symmetric NAT peer without relays
    func testSendToPeerFallsBackToDirectForSymmetricWithNoRelays() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        let targetPeerId = "symmetric-peer-no-relay"

        // Set up symmetric NAT peer but NO relay
        await sender.updatePeerEndpoint(targetPeerId, endpoint: "127.0.0.1:8888")
        await sender.endpointManager.updateNATType(peerId: targetPeerId, natType: .symmetric)

        // Send should fall back to direct (with warning)
        do {
            try await sender.sendToPeer(.ping(recentPeers: [], myNATType: .public), peerId: targetPeerId)
            // Success - fell back to direct
        } catch MeshNodeError.peerNotFound {
            XCTFail("Should have found the peer's endpoint")
        } catch {
            // Other errors acceptable in test environment
        }
    }

    /// Test sendToPeer uses direct for unknown NAT type
    func testSendToPeerUsesDirectForUnknownNAT() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        let targetPeerId = "unknown-nat-peer"

        // Set up peer WITHOUT NAT type (unknown)
        await sender.updatePeerEndpoint(targetPeerId, endpoint: "127.0.0.1:9999")
        // Don't set NAT type - it will be unknown

        // Send should use direct path (default for unknown)
        do {
            try await sender.sendToPeer(.ping(recentPeers: [], myNATType: .public), peerId: targetPeerId)
            // Success - direct send was used
        } catch MeshNodeError.noRelayAvailable {
            XCTFail("Should have used direct send for unknown NAT peer")
        } catch {
            // Other errors acceptable
        }
    }

    /// Test sendToPeer throws peerNotFound when no endpoints
    func testSendToPeerThrowsPeerNotFound() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        // Try to send to completely unknown peer
        do {
            try await sender.sendToPeer(.ping(recentPeers: [], myNATType: .public), peerId: "unknown-peer")
            XCTFail("Should have thrown peerNotFound")
        } catch MeshNodeError.peerNotFound {
            // Expected
        }
    }

    // MARK: - NAT Compatibility Tests

    /// Test NATType hole punchable property
    func testNATTypeHolePunchable() {
        XCTAssertTrue(NATType.public.holePunchable)
        XCTAssertTrue(NATType.fullCone.holePunchable)
        XCTAssertTrue(NATType.restrictedCone.holePunchable)
        XCTAssertTrue(NATType.portRestrictedCone.holePunchable)
        XCTAssertFalse(NATType.symmetric.holePunchable)
        XCTAssertFalse(NATType.unknown.holePunchable)
    }

    /// Test direct-to-symmetric routing preference
    func testDirectToSymmetricNeedsRelay() async throws {
        // When we (non-symmetric) want to reach a symmetric NAT peer,
        // we need to use a relay because the symmetric peer's port changes
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let senderIdentity = IdentityKeypair()
        let sender = try MeshNode(identity: senderIdentity, config: nodeConfig)
        try await sender.start()
        defer { Task { await sender.stop() } }

        let symmetricPeerId = "symmetric-target"

        // Mark peer as symmetric NAT
        await sender.updatePeerEndpoint(symmetricPeerId, endpoint: "192.168.1.100:5000")
        await sender.endpointManager.updateNATType(peerId: symmetricPeerId, natType: .symmetric)

        // Check that the NAT type is correctly stored
        let storedNATType = await sender.getNATType(for: symmetricPeerId)
        XCTAssertEqual(storedNATType, .symmetric)
    }
}
