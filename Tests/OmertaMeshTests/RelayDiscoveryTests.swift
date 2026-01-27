// RelayDiscoveryTests.swift - Tests for gossip-based relay discovery

import XCTest
@testable import OmertaMesh

final class RelayDiscoveryTests: XCTestCase {

    // MARK: - Potential Relay Recording

    /// Test potential relay is recorded from gossip about symmetric NAT peer
    func testPotentialRelayRecordedFromGossip() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        // Simulate receiving gossip about a symmetric NAT peer from a relay
        let symmetricPeerId = "symmetric-peer-id"
        let relayPeerId = "relay-peer-id"

        await requester.recordPotentialRelay(for: symmetricPeerId, via: relayPeerId)

        // Verify relay was recorded
        let relays = await requester.getPotentialRelays(for: symmetricPeerId)
        XCTAssertEqual(relays.count, 1)
        XCTAssertEqual(relays.first?.relayPeerId, relayPeerId)
    }

    /// Test relay list is ordered most recent first
    func testRelayListOrderedByRecency() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let symmetricPeerId = "symmetric-peer"

        // Record relay1 first
        await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay1")

        // Small delay to ensure different timestamps
        try await Task.sleep(nanoseconds: 10_000_000)

        // Record relay2 second (more recent)
        await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay2")

        let relays = await requester.getPotentialRelays(for: symmetricPeerId)
        XCTAssertEqual(relays.count, 2)
        XCTAssertEqual(relays.first?.relayPeerId, "relay2") // Most recent first
        XCTAssertEqual(relays.last?.relayPeerId, "relay1")
    }

    /// Test relay list capped at 10
    func testRelayListCappedAt10() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let symmetricPeerId = "symmetric-peer"

        // Record 15 relays
        for i in 0..<15 {
            await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay\(i)")
        }

        let relays = await requester.getPotentialRelays(for: symmetricPeerId)
        XCTAssertEqual(relays.count, 10)
        // Most recent (relay14) should be first
        XCTAssertEqual(relays.first?.relayPeerId, "relay14")
    }

    /// Test duplicate relay updates position
    func testDuplicateRelayUpdatesPosition() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let symmetricPeerId = "symmetric-peer"

        await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay1")
        await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay2")
        await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay1") // Update relay1

        let relays = await requester.getPotentialRelays(for: symmetricPeerId)
        XCTAssertEqual(relays.count, 2)
        XCTAssertEqual(relays.first?.relayPeerId, "relay1") // Now most recent
    }

    /// Test self is not recorded as relay
    func testSelfNotRecordedAsRelay() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let symmetricPeerId = "symmetric-peer"

        // Try to record self as relay
        await requester.recordPotentialRelay(for: symmetricPeerId, via: requesterIdentity.peerId)

        let relays = await requester.getPotentialRelays(for: symmetricPeerId)
        XCTAssertTrue(relays.isEmpty)
    }

    /// Test symmetric peer not recorded as own relay
    func testSymmetricPeerNotRecordedAsOwnRelay() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let symmetricPeerId = "symmetric-peer"

        // Try to record symmetric peer as its own relay
        await requester.recordPotentialRelay(for: symmetricPeerId, via: symmetricPeerId)

        let relays = await requester.getPotentialRelays(for: symmetricPeerId)
        XCTAssertTrue(relays.isEmpty)
    }

    /// Test clear potential relays
    func testClearPotentialRelays() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let symmetricPeerId = "symmetric-peer"

        await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay1")
        await requester.recordPotentialRelay(for: symmetricPeerId, via: "relay2")

        // Clear relays
        await requester.clearPotentialRelays(for: symmetricPeerId)

        let relays = await requester.getPotentialRelays(for: symmetricPeerId)
        XCTAssertTrue(relays.isEmpty)
    }

    /// Test getPotentialRelays for unknown peer returns empty
    func testGetPotentialRelaysUnknownPeer() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let relays = await requester.getPotentialRelays(for: "unknown-peer")
        XCTAssertTrue(relays.isEmpty)
    }

    /// Test multiple symmetric peers have separate relay lists
    func testMultipleSymmetricPeersSeparateRelays() async throws {
        let encryptionKey = Data(repeating: 0x42, count: 32)
        let nodeConfig = MeshNode.Config(
            encryptionKey: encryptionKey,
            endpointValidationMode: .allowAll
        )

        let requesterIdentity = IdentityKeypair()
        let requester = try MeshNode(identity: requesterIdentity, config: nodeConfig)
        try await requester.start()
        defer { Task { await requester.stop() } }

        let symmetric1 = "symmetric-peer-1"
        let symmetric2 = "symmetric-peer-2"

        await requester.recordPotentialRelay(for: symmetric1, via: "relay-a")
        await requester.recordPotentialRelay(for: symmetric2, via: "relay-b")
        await requester.recordPotentialRelay(for: symmetric2, via: "relay-c")

        let relays1 = await requester.getPotentialRelays(for: symmetric1)
        let relays2 = await requester.getPotentialRelays(for: symmetric2)

        XCTAssertEqual(relays1.count, 1)
        XCTAssertEqual(relays1.first?.relayPeerId, "relay-a")

        XCTAssertEqual(relays2.count, 2)
        XCTAssertEqual(relays2.first?.relayPeerId, "relay-c") // Most recent
    }
}
