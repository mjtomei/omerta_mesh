// MessageClient.swift - Client for peer-to-peer messaging
//
// Sends messages to peers and optionally tracks delivery receipts.

import Foundation
import Logging

/// Client for sending messages to peers
public actor MessageClient {
    /// The channel provider for sending messages
    private let provider: any ChannelProvider

    /// Pending receipts waiting for responses
    private var pendingReceipts: [UUID: CheckedContinuation<MessageReceipt, Error>] = [:]

    /// Timeout cleanup tasks
    private var timeoutTasks: [UUID: Task<Void, Never>] = [:]

    /// Logger
    private let logger = Logger(label: "io.omerta.mesh.services.message.client")

    /// Whether the receipt handler is registered
    private var isRegistered: Bool = false

    /// Initialize with a channel provider
    public init(provider: any ChannelProvider) {
        self.provider = provider
    }

    // MARK: - Public API

    /// Send a message to a peer
    /// - Parameters:
    ///   - content: Message content
    ///   - peerId: Recipient peer ID
    ///   - messageType: Optional application-defined message type
    /// - Returns: The message ID
    @discardableResult
    public func send(
        _ content: Data,
        to peerId: PeerId,
        messageType: String? = nil
    ) async throws -> UUID {
        let message = PeerMessage(
            content: content,
            requestReceipt: false,
            messageType: messageType
        )

        let messageData = try JSONCoding.encoder.encode(message)
        let inboxChannel = MessageChannels.inbox(for: peerId)

        try await provider.sendOnChannel(messageData, to: peerId, channel: inboxChannel)
        logger.debug("Sent message \(message.messageId) to \(peerId.prefix(8))...")

        return message.messageId
    }

    /// Send a message to a peer and wait for delivery receipt
    /// - Parameters:
    ///   - content: Message content
    ///   - peerId: Recipient peer ID
    ///   - messageType: Optional application-defined message type
    ///   - timeout: How long to wait for receipt
    /// - Returns: The delivery receipt
    public func sendWithReceipt(
        _ content: Data,
        to peerId: PeerId,
        messageType: String? = nil,
        timeout: TimeInterval = 10.0
    ) async throws -> MessageReceipt {
        // Ensure receipt channel is registered
        if !isRegistered {
            try await registerReceiptHandler()
        }

        let message = PeerMessage(
            content: content,
            requestReceipt: true,
            messageType: messageType
        )

        let messageData = try JSONCoding.encoder.encode(message)
        let inboxChannel = MessageChannels.inbox(for: peerId)

        // Send message and wait for receipt
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                // Store continuation
                await self.storeContinuation(message.messageId, continuation)

                // Set up timeout
                await self.setupTimeout(message.messageId, timeout: timeout)

                // Send message
                do {
                    try await self.provider.sendOnChannel(messageData, to: peerId, channel: inboxChannel)
                    self.logger.debug("Sent message with receipt request \(message.messageId) to \(peerId.prefix(8))...")
                } catch {
                    await self.removeContinuation(message.messageId)
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Internal

    private func storeContinuation(_ messageId: UUID, _ continuation: CheckedContinuation<MessageReceipt, Error>) {
        pendingReceipts[messageId] = continuation
    }

    private func removeContinuation(_ messageId: UUID) {
        pendingReceipts.removeValue(forKey: messageId)
        timeoutTasks[messageId]?.cancel()
        timeoutTasks.removeValue(forKey: messageId)
    }

    private func setupTimeout(_ messageId: UUID, timeout: TimeInterval) {
        let task = Task {
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            if let continuation = self.pendingReceipts.removeValue(forKey: messageId) {
                continuation.resume(throwing: ServiceError.timeout)
            }
            self.timeoutTasks.removeValue(forKey: messageId)
        }
        timeoutTasks[messageId] = task
    }

    private func registerReceiptHandler() async throws {
        let myPeerId = await provider.peerId
        let receiptChannel = MessageChannels.receipt(for: myPeerId)

        do {
            try await provider.onChannel(receiptChannel) { [weak self] fromMachineId, data in
                await self?.handleReceipt(data, from: fromMachineId)
            }
            isRegistered = true
            logger.debug("Registered message receipt handler on \(receiptChannel)")
        } catch {
            throw ServiceError.channelRegistrationFailed(receiptChannel)
        }
    }

    private func handleReceipt(_ data: Data, from machineId: MachineId) async {
        guard let receipt = try? JSONCoding.decoder.decode(MessageReceipt.self, from: data) else {
            logger.warning("Failed to decode message receipt from machine \(machineId.prefix(8))...")
            return
        }

        if let continuation = pendingReceipts.removeValue(forKey: receipt.messageId) {
            timeoutTasks[receipt.messageId]?.cancel()
            timeoutTasks.removeValue(forKey: receipt.messageId)
            continuation.resume(returning: receipt)
        } else {
            logger.debug("Received receipt for unknown message: \(receipt.messageId)")
        }
    }

    /// Stop the client and cancel pending operations
    public func stop() async {
        let myPeerId = await provider.peerId
        await provider.offChannel(MessageChannels.receipt(for: myPeerId))
        isRegistered = false

        // Cancel all pending receipts
        for (messageId, continuation) in pendingReceipts {
            continuation.resume(throwing: ServiceError.notStarted)
            timeoutTasks[messageId]?.cancel()
        }
        pendingReceipts.removeAll()
        timeoutTasks.removeAll()
    }
}
