import XCTest
@testable import OmertaMesh

final class MessageServiceTests: XCTestCase {

    // MARK: - Message Handler Tests

    func testMessageHandlerStartStop() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = MessageHandler(provider: provider)

        // Start handler
        try await handler.start()
        let inboxChannel = MessageChannels.inbox(for: "handler-peer")
        let isRegistered = await provider.hasHandler(for: inboxChannel)
        XCTAssertTrue(isRegistered)

        // Stop handler
        await handler.stop()
        let isUnregistered = await provider.hasHandler(for: inboxChannel)
        XCTAssertFalse(isUnregistered)
    }

    func testMessageHandlerReceivesMessage() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = MessageHandler(provider: provider)

        var receivedMessage: PeerMessage?
        var receivedFrom: PeerId?

        await handler.setMessageHandler { from, message in
            receivedMessage = message
            receivedFrom = from
        }

        try await handler.start()

        // Create and send a message
        let message = PeerMessage(
            content: Data("Hello, World!".utf8),
            requestReceipt: false,
            messageType: "greeting"
        )
        let messageData = try JSONCoding.encoder.encode(message)

        // Simulate receiving the message
        let inboxChannel = MessageChannels.inbox(for: "handler-peer")
        await provider.simulateReceive(messageData, from: "sender-peer", on: inboxChannel)

        // Verify handler was called
        XCTAssertNotNil(receivedMessage)
        XCTAssertEqual(receivedMessage?.messageId, message.messageId)
        XCTAssertEqual(receivedMessage?.content, Data("Hello, World!".utf8))
        XCTAssertEqual(receivedMessage?.messageType, "greeting")
        XCTAssertEqual(receivedFrom, "sender-peer")

        await handler.stop()
    }

    func testMessageHandlerSendsReceipt() async throws {
        let provider = MockChannelProvider(peerId: "handler-peer")
        let handler = MessageHandler(provider: provider)

        await handler.setMessageHandler { _, _ in
            // Just receive the message
        }

        try await handler.start()

        // Create a message that requests receipt
        let message = PeerMessage(
            content: Data("Important message".utf8),
            requestReceipt: true
        )
        let messageData = try JSONCoding.encoder.encode(message)

        // Simulate receiving the message
        let inboxChannel = MessageChannels.inbox(for: "handler-peer")
        await provider.simulateReceive(messageData, from: "sender-peer", on: inboxChannel)

        // Check that a receipt was sent
        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let sent = sentMessages[0]
        XCTAssertEqual(sent.target, "sender-peer")
        XCTAssertEqual(sent.channel, MessageChannels.receipt(for: "sender-peer"))

        // Decode and verify receipt
        let receipt = try JSONCoding.decoder.decode(MessageReceipt.self, from: sent.data)
        XCTAssertEqual(receipt.messageId, message.messageId)
        XCTAssertEqual(receipt.status, .delivered)

        await handler.stop()
    }

    // MARK: - Message Client Tests

    func testMessageClientSend() async throws {
        let provider = MockChannelProvider(peerId: "client-peer")
        let client = MessageClient(provider: provider)

        let messageId = try await client.send(
            Data("Test message".utf8),
            to: "recipient-peer",
            messageType: "test"
        )

        XCTAssertNotNil(messageId)

        // Check that message was sent
        let sentMessages = await provider.sentMessages
        XCTAssertEqual(sentMessages.count, 1)

        let sent = sentMessages[0]
        XCTAssertEqual(sent.target, "recipient-peer")
        XCTAssertEqual(sent.channel, MessageChannels.inbox(for: "recipient-peer"))

        // Decode and verify
        let message = try JSONCoding.decoder.decode(PeerMessage.self, from: sent.data)
        XCTAssertEqual(message.messageId, messageId)
        XCTAssertEqual(message.content, Data("Test message".utf8))
        XCTAssertEqual(message.messageType, "test")
        XCTAssertFalse(message.requestReceipt)

        await client.stop()
    }

    // MARK: - Service Messages Tests

    func testPeerMessageEncoding() throws {
        let message = PeerMessage(
            content: Data([1, 2, 3, 4, 5]),
            requestReceipt: true,
            messageType: "binary"
        )

        let encoded = try JSONCoding.encoder.encode(message)
        let decoded = try JSONCoding.decoder.decode(PeerMessage.self, from: encoded)

        XCTAssertEqual(decoded.messageId, message.messageId)
        XCTAssertEqual(decoded.content, message.content)
        XCTAssertEqual(decoded.requestReceipt, true)
        XCTAssertEqual(decoded.messageType, "binary")
    }

    func testMessageReceiptEncoding() throws {
        let receipt = MessageReceipt(
            messageId: UUID(),
            status: .delivered
        )

        let encoded = try JSONCoding.encoder.encode(receipt)
        let decoded = try JSONCoding.decoder.decode(MessageReceipt.self, from: encoded)

        XCTAssertEqual(decoded.messageId, receipt.messageId)
        XCTAssertEqual(decoded.status, receipt.status)
    }

    func testMessageStatusValues() {
        let statuses: [MessageStatus] = [.delivered, .read, .rejected, .failed]

        for status in statuses {
            XCTAssertFalse(status.rawValue.isEmpty)
        }
    }

    // MARK: - Channel Names Tests

    func testMessageChannelNames() {
        let peerId = "test-peer-id-12345"

        let inbox = MessageChannels.inbox(for: peerId)
        let receipt = MessageChannels.receipt(for: peerId)

        XCTAssertTrue(inbox.contains(peerId))
        XCTAssertTrue(receipt.contains(peerId))
        XCTAssertTrue(inbox.hasPrefix("msg-inbox-"))
        XCTAssertTrue(receipt.hasPrefix("msg-receipt-"))

        // Channels should be valid
        XCTAssertTrue(ChannelUtils.isValid(inbox))
        XCTAssertTrue(ChannelUtils.isValid(receipt))
    }
}
