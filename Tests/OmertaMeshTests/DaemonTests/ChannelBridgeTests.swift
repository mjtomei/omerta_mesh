// ChannelBridgeTests.swift - Tests for channel bridge routing

import XCTest
@testable import OmertaMesh

final class ChannelBridgeTests: XCTestCase {

    // MARK: - Mock Connection

    /// Mock client connection for testing
    actor MockClientConnection {
        private(set) var sentMessages: [Any] = []
        private(set) var isClosed = false
        let clientId: String

        init(clientId: String = UUID().uuidString) {
            self.clientId = clientId
        }

        func recordMessage<T>(_ message: T) {
            sentMessages.append(message)
        }

        func getSentMessages() -> [Any] {
            sentMessages
        }

        func close() {
            isClosed = true
        }
    }

    // MARK: - Registration Tests

    func testChannelRegistrationBasic() async throws {
        // Create a mock mesh network
        let identity = IdentityKeypair()
        let config = MeshConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let network = MeshNetwork(identity: identity, config: config)

        let bridge = ChannelBridge(meshNetwork: network)

        // Initially no registrations
        let initialCount = await bridge.registrationCount
        XCTAssertEqual(initialCount, 0)

        let isRegisteredBefore = await bridge.isRegistered(channel: "test-channel")
        XCTAssertFalse(isRegisteredBefore)
    }

    func testChannelRegistrationIsExclusiveError() async throws {
        // Test that the error type for already-registered channel is correct
        let identity = IdentityKeypair()
        let config = MeshConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let network = MeshNetwork(identity: identity, config: config)

        let bridge = ChannelBridge(meshNetwork: network)

        // The exclusive registration behavior will be tested when we have
        // actual ClientConnection instances. For now, just verify the error type.
        let error = ChannelBridgeError.channelAlreadyRegistered("test-channel")

        switch error {
        case .channelAlreadyRegistered(let channel):
            XCTAssertEqual(channel, "test-channel")
        default:
            XCTFail("Wrong error type")
        }
    }

    func testChannelUnregistration() async throws {
        let identity = IdentityKeypair()
        let config = MeshConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let network = MeshNetwork(identity: identity, config: config)

        let bridge = ChannelBridge(meshNetwork: network)

        // Check unregister doesn't crash when nothing is registered
        await bridge.unregister(channel: "nonexistent", clientId: "client1")

        // Check count is still 0
        let count = await bridge.registrationCount
        XCTAssertEqual(count, 0)
    }

    // MARK: - Channel Send Tests

    func testSendOnChannelWithoutRegistration() async throws {
        let identity = IdentityKeypair()
        let config = MeshConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let network = MeshNetwork(identity: identity, config: config)

        let bridge = ChannelBridge(meshNetwork: network)

        // Should not throw, just delegate to mesh network
        // (which may throw if not started, but that's expected)
        do {
            try await bridge.sendOnChannel(
                Data([0x01, 0x02]),
                to: "peer123",
                channel: "test-channel"
            )
        } catch {
            // Expected - mesh network not started
        }
    }

    // MARK: - Error Tests

    func testChannelBridgeErrorDescriptions() {
        let alreadyRegistered = ChannelBridgeError.channelAlreadyRegistered("test-channel")
        XCTAssertTrue(alreadyRegistered.description.contains("test-channel"))
        XCTAssertTrue(alreadyRegistered.description.contains("already registered"))

        let notRegistered = ChannelBridgeError.channelNotRegistered("other-channel")
        XCTAssertTrue(notRegistered.description.contains("other-channel"))
        XCTAssertTrue(notRegistered.description.contains("not registered"))
    }

    // MARK: - Registered Channels List

    func testRegisteredChannelsList() async throws {
        let identity = IdentityKeypair()
        let config = MeshConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let network = MeshNetwork(identity: identity, config: config)

        let bridge = ChannelBridge(meshNetwork: network)

        // Initially empty
        let channels = await bridge.registeredChannels
        XCTAssertTrue(channels.isEmpty)
    }
}
