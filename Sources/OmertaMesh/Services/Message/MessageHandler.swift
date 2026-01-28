// MessageHandler.swift - Handler for incoming peer messages
//
// Listens for incoming messages and sends delivery receipts.

import Foundation
import Logging

/// Handler for incoming peer messages
public actor MessageHandler {
    /// The channel provider for receiving messages and sending receipts
    private let provider: any ChannelProvider

    /// Application message handler (receives machineId of sender)
    private var messageHandler: (@Sendable (MachineId, PeerMessage) async -> Void)?

    /// Logger
    private let logger = Logger(label: "io.omerta.mesh.services.message.handler")

    /// Whether the handler is running
    private var isRunning: Bool = false

    /// Initialize with a channel provider
    public init(provider: any ChannelProvider) {
        self.provider = provider
    }

    // MARK: - Lifecycle

    /// Start listening for incoming messages
    public func start() async throws {
        guard !isRunning else {
            throw ServiceError.alreadyRunning
        }

        let myPeerId = await provider.peerId
        let inboxChannel = MessageChannels.inbox(for: myPeerId)

        do {
            try await provider.onChannel(inboxChannel) { [weak self] fromMachineId, data in
                await self?.handleIncomingMessage(data, from: fromMachineId)
            }
            isRunning = true
            logger.info("Message handler started, listening on \(inboxChannel)")
        } catch {
            throw ServiceError.channelRegistrationFailed(inboxChannel)
        }
    }

    /// Stop listening for incoming messages
    public func stop() async {
        let myPeerId = await provider.peerId
        await provider.offChannel(MessageChannels.inbox(for: myPeerId))
        isRunning = false
        logger.info("Message handler stopped")
    }

    // MARK: - Configuration

    /// Set the message handler
    /// - Parameter handler: Async closure called when messages are received (receives machineId of sender)
    public func setMessageHandler(_ handler: @escaping @Sendable (MachineId, PeerMessage) async -> Void) {
        messageHandler = handler
    }

    // MARK: - Internal

    private func handleIncomingMessage(_ data: Data, from machineId: MachineId) async {
        guard let message = try? JSONCoding.decoder.decode(PeerMessage.self, from: data) else {
            logger.warning("Failed to decode message from machine \(machineId.prefix(8))...")
            return
        }

        logger.debug("Received message \(message.messageId) from machine \(machineId.prefix(8))..., type: \(message.messageType ?? "none")")

        // Send receipt if requested
        if message.requestReceipt {
            await sendReceipt(for: message, to: machineId, status: .delivered)
        }

        // Forward to application handler
        if let handler = messageHandler {
            await handler(machineId, message)
        } else {
            logger.warning("No message handler set, dropping message \(message.messageId)")
        }
    }

    private func sendReceipt(for message: PeerMessage, to machineId: MachineId, status: MessageStatus) async {
        let receipt = MessageReceipt(
            messageId: message.messageId,
            status: status
        )

        do {
            let receiptData = try JSONCoding.encoder.encode(receipt)
            // Use sender's machineId for the receipt channel so they know where to listen
            let receiptChannel = MessageChannels.receipt(for: machineId)
            try await provider.sendOnChannel(receiptData, toMachine: machineId, channel: receiptChannel)
            logger.debug("Sent receipt for \(message.messageId) to machine \(machineId.prefix(8))...")
        } catch {
            logger.error("Failed to send receipt for \(message.messageId) to machine \(machineId.prefix(8))...: \(error)")
        }
    }
}
