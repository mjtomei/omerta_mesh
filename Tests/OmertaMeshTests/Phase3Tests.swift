// Phase3Tests.swift - Tests for Bootstrap and Peer Discovery (Phase 3)

import XCTest
import Foundation
@testable import OmertaMesh

final class Phase3Tests: XCTestCase {

    // MARK: - PeerCache Tests

    /// Test basic insert and retrieve
    func testPeerCacheInsertAndRetrieve() async throws {
        let cache = PeerCache(maxEntries: 100)

        let announcement = createTestAnnouncement(peerId: "peer1")
        await cache.insert(announcement)

        let retrieved = await cache.get("peer1")
        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.peerId, "peer1")
    }

    /// Test LRU eviction
    func testPeerCacheLRUEviction() async throws {
        let cache = PeerCache(maxEntries: 3)

        // Insert 4 peers
        for i in 1...4 {
            let announcement = createTestAnnouncement(peerId: "peer\(i)")
            await cache.insert(announcement)
        }

        // peer1 should be evicted (LRU)
        let peer1 = await cache.get("peer1")
        XCTAssertNil(peer1, "peer1 should be evicted")

        // peer4 should still be there
        let peer4 = await cache.get("peer4")
        XCTAssertNotNil(peer4)
    }

    /// Test access updates LRU order
    func testPeerCacheAccessUpdatesLRU() async throws {
        let cache = PeerCache(maxEntries: 3)

        // Insert 3 peers
        for i in 1...3 {
            let announcement = createTestAnnouncement(peerId: "peer\(i)")
            await cache.insert(announcement)
        }

        // Access peer1 to make it recently used
        _ = await cache.get("peer1")

        // Insert peer4, should evict peer2 (now oldest)
        let announcement4 = createTestAnnouncement(peerId: "peer4")
        await cache.insert(announcement4)

        let peer1 = await cache.get("peer1")
        let peer2 = await cache.get("peer2")

        XCTAssertNotNil(peer1, "peer1 was accessed, should not be evicted")
        XCTAssertNil(peer2, "peer2 should be evicted")
    }

    /// Test TTL expiration
    func testPeerCacheTTLExpiration() async throws {
        let cache = PeerCache(maxEntries: 100)

        // Create an announcement that expires immediately
        let announcement = PeerAnnouncement(
            peerId: "peer1",
            publicKey: "testkey",
            reachability: [.direct(endpoint: "127.0.0.1:5000")],
            capabilities: [],
            timestamp: Date().addingTimeInterval(-3700), // 1 hour + 100 seconds ago
            ttlSeconds: 3600  // 1 hour TTL
        )

        await cache.insert(announcement)

        // Should return nil because expired
        let retrieved = await cache.get("peer1")
        XCTAssertNil(retrieved, "Expired announcement should not be returned")
    }

    /// Test capability filtering
    func testPeerCacheCapabilityFilter() async throws {
        let cache = PeerCache(maxEntries: 100)

        let relay = createTestAnnouncement(peerId: "relay1", capabilities: ["relay"])
        let consumer = createTestAnnouncement(peerId: "consumer1", capabilities: ["consumer"])
        let both = createTestAnnouncement(peerId: "both1", capabilities: ["relay", "consumer"])

        await cache.insert(relay)
        await cache.insert(consumer)
        await cache.insert(both)

        let relays = await cache.relayCapablePeers
        XCTAssertEqual(relays.count, 2)

        let consumers = await cache.peers(withCapability: "consumer")
        XCTAssertEqual(consumers.count, 2)
    }

    /// Test direct reachability filter
    func testPeerCacheDirectReachability() async throws {
        let cache = PeerCache(maxEntries: 100)

        let direct = PeerAnnouncement(
            peerId: "direct1",
            publicKey: "key1",
            reachability: [.direct(endpoint: "1.2.3.4:5000")],
            capabilities: [],
            ttlSeconds: 3600
        )

        let relayed = PeerAnnouncement(
            peerId: "relayed1",
            publicKey: "key2",
            reachability: [.relay(relayPeerId: "relay", relayEndpoint: "5.6.7.8:5000")],
            capabilities: [],
            ttlSeconds: 3600
        )

        await cache.insert(direct)
        await cache.insert(relayed)

        let directPeers = await cache.directlyReachablePeers
        XCTAssertEqual(directPeers.count, 1)
        XCTAssertEqual(directPeers.first?.peerId, "direct1")
    }

    // MARK: - PeerStore Tests

    /// Test peer store save and load
    func testPeerStorePersistence() async throws {
        let tempDir = FileManager.default.temporaryDirectory
        let storePath = tempDir.appendingPathComponent("test_peers_\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: storePath)
        }

        let networkId = "test-network"
        let store = PeerStore(networkId: networkId, validationMode: .strict, storePath: storePath)

        // Add some peers (using public IP addresses)
        let peer1 = createTestAnnouncement(peerId: "peer1", endpoint: "8.8.8.1:5000")
        let peer2 = createTestAnnouncement(peerId: "peer2", endpoint: "8.8.8.2:5000")

        await store.update(peer1, contactSuccessful: true)
        await store.update(peer2, contactSuccessful: true)

        // Save
        try await store.save()

        // Load into new store with same networkId
        let store2 = PeerStore(networkId: networkId, validationMode: .strict, storePath: storePath)
        try await store2.load()

        let loadedPeers = await store2.allPeers()
        XCTAssertEqual(loadedPeers.count, 2)
    }

    /// Test reliability tracking
    func testPeerStoreReliability() async throws {
        let tempDir = FileManager.default.temporaryDirectory
        let storePath = tempDir.appendingPathComponent("test_reliability_\(UUID().uuidString).json")
        defer {
            try? FileManager.default.removeItem(at: storePath)
        }

        let store = PeerStore(networkId: "test-network", validationMode: .strict, storePath: storePath)

        // Use public IP addresses
        let peer1 = createTestAnnouncement(peerId: "reliable", endpoint: "8.8.8.1:5000")
        let peer2 = createTestAnnouncement(peerId: "unreliable", endpoint: "8.8.8.2:5000")

        // Reliable peer: 10 successes
        for _ in 0..<10 {
            await store.update(peer1, contactSuccessful: true)
        }

        // Unreliable peer: 2 successes, 8 failures
        await store.update(peer2, contactSuccessful: true)
        await store.update(peer2, contactSuccessful: true)
        for _ in 0..<8 {
            await store.markFailed("unreliable")
        }

        let peers = await store.allPeers()
        XCTAssertEqual(peers.first?.peerId, "reliable", "Reliable peer should be first")
    }

    // MARK: - Announcement Signature Tests

    /// Test announcement signing and verification
    func testAnnouncementSignature() async throws {
        let keypair = IdentityKeypair()

        let announcement = try Gossip.createAnnouncement(
            identity: keypair,
            reachability: [.direct(endpoint: "192.168.1.1:5000")],
            capabilities: ["relay", "consumer"],
            ttlSeconds: 3600
        )

        XCTAssertFalse(announcement.signature.isEmpty)
        XCTAssertTrue(announcement.verifySignature())
    }

    /// Test tampered announcement fails verification
    func testTamperedAnnouncementFails() async throws {
        let keypair = IdentityKeypair()

        var announcement = try Gossip.createAnnouncement(
            identity: keypair,
            reachability: [.direct(endpoint: "192.168.1.1:5000")],
            capabilities: ["relay"],
            ttlSeconds: 3600
        )

        // Create tampered announcement with wrong capabilities
        announcement = PeerAnnouncement(
            peerId: announcement.peerId,
            publicKey: announcement.publicKey,
            reachability: announcement.reachability,
            capabilities: ["tampered"],  // Changed!
            timestamp: announcement.timestamp,
            ttlSeconds: announcement.ttlSeconds,
            signature: announcement.signature  // Original signature
        )

        XCTAssertFalse(announcement.verifySignature())
    }

    // MARK: - Best Path Tests

    /// Test best path selection prefers direct
    func testBestPathPreferssDirect() async throws {
        let cache = PeerCache(maxEntries: 100)

        let announcement = PeerAnnouncement(
            peerId: "peer1",
            publicKey: "key1",
            reachability: [
                .relay(relayPeerId: "relay", relayEndpoint: "5.6.7.8:5000"),
                .direct(endpoint: "1.2.3.4:5000"),
                .holePunch(publicIP: "1.2.3.4", localPort: 5000)
            ],
            capabilities: [],
            ttlSeconds: 3600
        )

        await cache.insert(announcement)

        let bestPath = await cache.bestPath(to: "peer1")
        XCTAssertNotNil(bestPath)

        if case .direct(let endpoint) = bestPath {
            XCTAssertEqual(endpoint, "1.2.3.4:5000")
        } else {
            XCTFail("Expected direct path")
        }
    }

    /// Test best path falls back to relay
    func testBestPathFallsBackToRelay() async throws {
        let cache = PeerCache(maxEntries: 100)

        let announcement = PeerAnnouncement(
            peerId: "peer1",
            publicKey: "key1",
            reachability: [
                .holePunch(publicIP: "1.2.3.4", localPort: 5000),
                .relay(relayPeerId: "relay", relayEndpoint: "5.6.7.8:5000")
            ],
            capabilities: [],
            ttlSeconds: 3600
        )

        await cache.insert(announcement)

        let bestPath = await cache.bestPath(to: "peer1")
        XCTAssertNotNil(bestPath)

        if case .relay(let relayPeerId, _) = bestPath {
            XCTAssertEqual(relayPeerId, "relay")
        } else {
            XCTFail("Expected relay path")
        }
    }

    // MARK: - GossipConfig Tests

    /// Test gossip config defaults
    func testGossipConfigDefaults() {
        let config = GossipConfig()

        XCTAssertEqual(config.fanout, 6)
        XCTAssertEqual(config.interval, 30.0)
        XCTAssertEqual(config.maxHops, 3)
        XCTAssertEqual(config.maxAnnouncementsPerMessage, 10)
    }

    // MARK: - BootstrapConfig Tests

    /// Test bootstrap config defaults
    func testBootstrapConfigDefaults() {
        let config = BootstrapConfig.default

        XCTAssertFalse(config.bootstrapNodes.isEmpty)
        XCTAssertEqual(config.maxPeersPerNode, 50)
        XCTAssertEqual(config.timeout, 10.0)
    }

    // MARK: - Helper Methods

    private func createTestAnnouncement(
        peerId: String,
        capabilities: [String] = [],
        endpoint: String = "8.8.8.8:5000"
    ) -> PeerAnnouncement {
        PeerAnnouncement(
            peerId: peerId,
            publicKey: "testkey_\(peerId)",
            reachability: [.direct(endpoint: endpoint)],
            capabilities: capabilities,
            timestamp: Date(),
            ttlSeconds: 3600
        )
    }
}
