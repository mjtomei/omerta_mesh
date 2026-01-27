// NetworkManagementTests.swift - Tests for MeshNetwork's network management API

import XCTest
@testable import OmertaMesh

final class NetworkManagementTests: XCTestCase {

    /// Test encryption key
    private var testKey: Data {
        Data(repeating: 0x42, count: 32)
    }

    /// Create a temporary network store for testing
    private func createTempStore() -> NetworkStore {
        let tempDir = FileManager.default.temporaryDirectory
        let storePath = tempDir.appendingPathComponent("test-\(UUID().uuidString).json")
        return NetworkStore(storePath: storePath)
    }

    // MARK: - NetworkStore Tests

    func testNetworkStoreJoinAndLeave() async throws {
        let store = createTempStore()

        let key = NetworkKey.generate(networkName: "Test Network", bootstrapPeers: ["peer1@localhost:8080"])
        let network = try await store.join(key, name: "Test")

        XCTAssertEqual(network.name, "Test")
        var count = await store.count
        XCTAssertEqual(count, 1)
        var contains = await store.contains(network.id)
        XCTAssertTrue(contains)

        try await store.leave(network.id)
        count = await store.count
        XCTAssertEqual(count, 0)
        contains = await store.contains(network.id)
        XCTAssertFalse(contains)
    }

    func testNetworkStoreAlreadyJoined() async throws {
        let store = createTempStore()

        let key = NetworkKey.generate(networkName: "Test", bootstrapPeers: [])
        _ = try await store.join(key, name: nil)

        // Joining again should throw
        do {
            _ = try await store.join(key, name: nil)
            XCTFail("Should have thrown alreadyJoined")
        } catch NetworkStoreError.alreadyJoined {
            // Expected
        }
    }

    func testNetworkStoreLeaveNotFound() async {
        let store = createTempStore()

        do {
            try await store.leave("nonexistent-id")
            XCTFail("Should have thrown notFound")
        } catch NetworkStoreError.notFound {
            // Expected
        } catch {
            XCTFail("Wrong error: \(error)")
        }
    }

    func testNetworkStorePersistence() async throws {
        let tempDir = FileManager.default.temporaryDirectory
        let storePath = tempDir.appendingPathComponent("persist-test-\(UUID().uuidString).json")

        // Create and populate store
        let store1 = NetworkStore(storePath: storePath)
        let key = NetworkKey.generate(networkName: "Persistent", bootstrapPeers: ["peer@host:1234"])
        let network = try await store1.join(key, name: nil)
        try await store1.save()

        // Load in new store instance
        let store2 = NetworkStore(storePath: storePath)
        try await store2.load()

        let count = await store2.count
        XCTAssertEqual(count, 1)
        let loaded = await store2.network(id: network.id)
        XCTAssertNotNil(loaded)
        XCTAssertEqual(loaded?.name, "Persistent")

        // Cleanup
        try? FileManager.default.removeItem(at: storePath)
    }

    func testNetworkStoreActiveNetworks() async throws {
        let store = createTempStore()

        let key1 = NetworkKey.generate(networkName: "Active", bootstrapPeers: [])
        let key2 = NetworkKey.generate(networkName: "Inactive", bootstrapPeers: [])

        let net1 = try await store.join(key1, name: nil)
        let net2 = try await store.join(key2, name: nil)

        // Deactivate one
        try await store.setActive(net2.id, active: false)

        let active = await store.activeNetworks()
        let activeCount = active.count
        XCTAssertEqual(activeCount, 1)
        XCTAssertEqual(active.first?.id, net1.id)
    }

    // MARK: - MeshNetwork Integration Tests

    func testMeshNetworkCreateNetwork() async throws {
        let store = createTempStore()
        let config = MeshConfig(encryptionKey: testKey)
        let mesh = MeshNetwork(config: config, networkStore: store)

        let key = try await mesh.createNetwork(name: "My Network", bootstrapEndpoint: "localhost:9000")

        XCTAssertEqual(key.networkName, "My Network")
        XCTAssertFalse(key.bootstrapPeers.isEmpty)

        // Network should be auto-joined
        let networks = await mesh.networks()
        let networkCount = networks.count
        XCTAssertEqual(networkCount, 1)
        XCTAssertEqual(networks.first?.name, "My Network")
    }

    func testMeshNetworkJoinByInviteLink() async throws {
        let store = createTempStore()
        let config = MeshConfig(encryptionKey: testKey)
        let mesh = MeshNetwork(config: config, networkStore: store)

        // Create invite link
        let key = NetworkKey.generate(networkName: "Invite Test", bootstrapPeers: ["peer@host:1234"])
        let inviteLink = try key.encode()

        // Join via invite link
        let network = try await mesh.joinNetwork(inviteLink: inviteLink, name: "Custom Name")

        XCTAssertEqual(network.name, "Custom Name")

        let networks = await mesh.networks()
        let networkCount = networks.count
        XCTAssertEqual(networkCount, 1)
    }

    func testMeshNetworkJoinByKey() async throws {
        let store = createTempStore()
        let config = MeshConfig(encryptionKey: testKey)
        let mesh = MeshNetwork(config: config, networkStore: store)

        let key = NetworkKey.generate(networkName: "Key Test", bootstrapPeers: [])
        let network = try await mesh.joinNetwork(key: key, name: nil)

        XCTAssertEqual(network.name, "Key Test")  // Uses network name from key
    }

    func testMeshNetworkLeaveNetwork() async throws {
        let store = createTempStore()
        let config = MeshConfig(encryptionKey: testKey)
        let mesh = MeshNetwork(config: config, networkStore: store)

        let key = NetworkKey.generate(networkName: "Leave Test", bootstrapPeers: [])
        let network = try await mesh.joinNetwork(key: key, name: nil)

        var networks = await mesh.networks()
        XCTAssertEqual(networks.count, 1)

        try await mesh.leaveNetwork(id: network.id)

        networks = await mesh.networks()
        XCTAssertEqual(networks.count, 0)
    }

    func testMeshNetworkGetSpecificNetwork() async throws {
        let store = createTempStore()
        let config = MeshConfig(encryptionKey: testKey)
        let mesh = MeshNetwork(config: config, networkStore: store)

        let key = NetworkKey.generate(networkName: "Specific", bootstrapPeers: [])
        let network = try await mesh.joinNetwork(key: key, name: nil)

        let retrieved = await mesh.network(id: network.id)
        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.id, network.id)

        let notFound = await mesh.network(id: "nonexistent")
        XCTAssertNil(notFound)
    }

    // MARK: - NetworkKey Tests

    func testNetworkKeyRoundTrip() throws {
        let original = NetworkKey.generate(
            networkName: "Round Trip Test",
            bootstrapPeers: ["peer1@host1:1234", "peer2@host2:5678"]
        )

        let encoded = try original.encode()
        let decoded = try NetworkKey.decode(from: encoded)

        XCTAssertEqual(decoded.networkName, original.networkName)
        XCTAssertEqual(decoded.networkKey, original.networkKey)
        XCTAssertEqual(decoded.bootstrapPeers, original.bootstrapPeers)
    }

    func testNetworkKeyDeriveId() {
        let key = NetworkKey.generate(networkName: "ID Test", bootstrapPeers: [])

        let id1 = key.deriveNetworkId()
        let id2 = key.deriveNetworkId()

        XCTAssertEqual(id1, id2)  // Deterministic
        XCTAssertFalse(id1.isEmpty)
    }
}
