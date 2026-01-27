// CloisterHandler.swift - Handler for incoming cloister requests
//
// Handles network key negotiation and invite sharing requests from peers.

import Foundation
import Crypto
import Logging

/// Handler for incoming cloister (private network) requests
public actor CloisterHandler {
    /// The channel provider for receiving requests and sending responses
    private let provider: any ChannelProvider

    /// Request handler (decides whether to accept negotiation)
    private var requestHandler: (@Sendable (MachineId, String) async -> Bool)?

    /// Invite handler (decides whether to accept shared invites)
    private var inviteHandler: (@Sendable (MachineId, String?) async -> Bool)?

    /// Callback when a new network key is derived
    private var networkKeyCallback: (@Sendable (CloisterResult) async -> Void)?

    /// Logger
    private let logger = Logger(label: "io.omerta.mesh.services.cloister.handler")

    /// Whether the handler is running
    private var isRunning: Bool = false

    /// Pending invite sessions (waiting for round 2 payload)
    private var pendingInviteSessions: [UUID: PendingInviteSession] = [:]

    /// State for pending invite sessions
    private struct PendingInviteSession {
        let session: KeyExchangeSession
        let fromMachineId: MachineId
        let networkNameHint: String?
        let expiresAt: Date
    }

    /// Initialize with a channel provider
    public init(provider: any ChannelProvider) {
        self.provider = provider
    }

    // MARK: - Lifecycle

    /// Start listening for cloister requests
    public func start() async throws {
        guard !isRunning else {
            throw ServiceError.alreadyRunning
        }

        let myPeerId = await provider.peerId

        // Register negotiation request handler
        try await provider.onChannel(CloisterChannels.negotiate) { [weak self] fromMachineId, data in
            await self?.handleNegotiationRequest(data, from: fromMachineId)
        }

        // Register invite key exchange handler (round 1)
        try await provider.onChannel(CloisterChannels.inviteKeyExchange) { [weak self] fromMachineId, data in
            await self?.handleInviteKeyExchange(data, from: fromMachineId)
        }

        // Register invite payload handler (round 2)
        let payloadChannel = CloisterChannels.invitePayload(for: myPeerId)
        try await provider.onChannel(payloadChannel) { [weak self] fromMachineId, data in
            await self?.handleInvitePayload(data, from: fromMachineId)
        }

        isRunning = true
        logger.info("Cloister handler started")
    }

    /// Stop listening for cloister requests
    public func stop() async {
        let myPeerId = await provider.peerId
        await provider.offChannel(CloisterChannels.negotiate)
        await provider.offChannel(CloisterChannels.inviteKeyExchange)
        await provider.offChannel(CloisterChannels.invitePayload(for: myPeerId))
        pendingInviteSessions.removeAll()
        isRunning = false
        logger.info("Cloister handler stopped")
    }

    // MARK: - Configuration

    /// Set the request handler for negotiation requests
    /// - Parameter handler: Async closure that decides whether to accept
    ///   Parameters: (fromMachineId, networkName) -> accept?
    public func setRequestHandler(_ handler: @escaping @Sendable (MachineId, String) async -> Bool) {
        requestHandler = handler
    }

    /// Set the invite handler for shared invites
    /// - Parameter handler: Async closure that decides whether to accept
    ///   Parameters: (fromMachineId, networkNameHint) -> accept?
    public func setInviteHandler(_ handler: @escaping @Sendable (MachineId, String?) async -> Bool) {
        inviteHandler = handler
    }

    /// Set a callback for when network keys are successfully derived
    /// - Parameter callback: Called with the derived network key result
    public func setNetworkKeyCallback(_ callback: @escaping @Sendable (CloisterResult) async -> Void) {
        networkKeyCallback = callback
    }

    // MARK: - Internal

    private func handleNegotiationRequest(_ data: Data, from machineId: MachineId) async {
        guard let request = try? JSONCoding.decoder.decode(CloisterRequest.self, from: data) else {
            logger.warning("Failed to decode cloister request from machine \(machineId.prefix(8))...")
            return
        }

        logger.debug("Received cloister request from machine \(machineId.prefix(8))..., networkName: \(request.networkName)")

        // Check if we should accept
        let accepted: Bool
        if let handler = requestHandler {
            accepted = await handler(machineId, request.networkName)
        } else {
            // Default: reject if no handler
            accepted = false
            logger.warning("No cloister request handler set, rejecting request from machine \(machineId.prefix(8))...")
        }

        if !accepted {
            await sendNegotiationResponse(
                requestId: request.requestId,
                to: machineId,
                accepted: false,
                rejectReason: "Request not accepted"
            )
            return
        }

        // Generate our ephemeral X25519 keypair
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyData = Data(privateKey.publicKey.rawRepresentation)

        do {
            let theirPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: request.ephemeralPublicKey)

            // Derive shared secret using X25519
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: theirPublicKey)

            // Derive network key using HKDF
            let networkKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: Data("omerta-network-key".utf8),
                outputByteCount: 32
            )

            let networkKeyData = networkKey.withUnsafeBytes { Data($0) }

            // Compute network ID
            let hash = SHA256.hash(data: networkKeyData)
            let networkId = hash.prefix(8).map { String(format: "%02x", $0) }.joined()

            // Create confirmation (prove we derived the same key)
            let confirmationData = try ChaChaPoly.seal(
                Data("confirmed".utf8),
                using: networkKey
            ).combined

            // Send response with our public key
            await sendNegotiationResponse(
                requestId: request.requestId,
                to: machineId,
                accepted: true,
                publicKey: publicKeyData,
                confirmation: confirmationData
            )

            // Notify about the new network key
            let result = CloisterResult(
                networkKey: networkKeyData,
                networkId: networkId,
                networkName: request.networkName,
                sharedWith: machineId
            )

            if let callback = networkKeyCallback {
                await callback(result)
            }

            logger.info("Successfully negotiated network key with machine \(machineId.prefix(8))..., networkId: \(networkId)")

        } catch {
            logger.error("Key exchange failed with machine \(machineId.prefix(8))...: \(error)")
            await sendNegotiationResponse(
                requestId: request.requestId,
                to: machineId,
                accepted: false,
                rejectReason: "Key exchange failed"
            )
        }
    }

    private func sendNegotiationResponse(
        requestId: UUID,
        to machineId: MachineId,
        accepted: Bool,
        publicKey: Data? = nil,
        confirmation: Data? = nil,
        rejectReason: String? = nil
    ) async {
        let response = CloisterResponse(
            requestId: requestId,
            accepted: accepted,
            ephemeralPublicKey: publicKey,
            encryptedConfirmation: confirmation,
            rejectReason: rejectReason
        )

        do {
            let responseData = try JSONCoding.encoder.encode(response)
            let myPeerId = await provider.peerId
            let responseChannel = CloisterChannels.response(for: myPeerId)
            try await provider.sendOnChannel(responseData, toMachine: machineId, channel: responseChannel)
        } catch {
            logger.error("Failed to send cloister response to machine \(machineId.prefix(8))...: \(error)")
        }
    }

    /// Handle invite key exchange request (round 1)
    /// Creates session and sends back our public key
    private func handleInviteKeyExchange(_ data: Data, from machineId: MachineId) async {
        guard let request = try? JSONCoding.decoder.decode(InviteKeyExchangeRequest.self, from: data) else {
            logger.warning("Failed to decode invite key exchange request from machine \(machineId.prefix(8))...")
            return
        }

        logger.debug("Received invite key exchange from machine \(machineId.prefix(8))..., hint: \(request.networkNameHint ?? "none")")

        // Check if we should accept
        let accepted: Bool
        if let handler = inviteHandler {
            accepted = await handler(machineId, request.networkNameHint)
        } else {
            accepted = false
            logger.warning("No invite handler set, rejecting invite from machine \(machineId.prefix(8))...")
        }

        // Create our key exchange session
        let session = KeyExchangeSession()
        let ourPublicKey = await session.publicKey

        if !accepted {
            await sendInviteKeyExchangeResponse(
                requestId: request.requestId,
                to: machineId,
                publicKey: ourPublicKey,
                accepted: false,
                rejectReason: "Invite not accepted"
            )
            return
        }

        do {
            // Complete our side of the key exchange
            try await session.completeExchange(peerPublicKey: request.ephemeralPublicKey)

            // Store session for round 2
            let expiresAt = Date().addingTimeInterval(60) // 60 second timeout
            pendingInviteSessions[request.requestId] = PendingInviteSession(
                session: session,
                fromMachineId: machineId,
                networkNameHint: request.networkNameHint,
                expiresAt: expiresAt
            )

            // Send our public key back
            await sendInviteKeyExchangeResponse(
                requestId: request.requestId,
                to: machineId,
                publicKey: ourPublicKey,
                accepted: true
            )

            logger.debug("Sent invite key exchange response to machine \(machineId.prefix(8))..., awaiting payload")

        } catch {
            logger.error("Key exchange failed with machine \(machineId.prefix(8))...: \(error)")
            await sendInviteKeyExchangeResponse(
                requestId: request.requestId,
                to: machineId,
                publicKey: ourPublicKey,
                accepted: false,
                rejectReason: "Key exchange failed"
            )
        }
    }

    /// Send invite key exchange response (round 1)
    private func sendInviteKeyExchangeResponse(
        requestId: UUID,
        to machineId: MachineId,
        publicKey: Data,
        accepted: Bool,
        rejectReason: String? = nil
    ) async {
        let response = InviteKeyExchangeResponse(
            requestId: requestId,
            ephemeralPublicKey: publicKey,
            accepted: accepted,
            rejectReason: rejectReason
        )

        do {
            let responseData = try JSONCoding.encoder.encode(response)
            let myPeerId = await provider.peerId
            let responseChannel = CloisterChannels.inviteKeyExchangeResponse(for: myPeerId)
            try await provider.sendOnChannel(responseData, toMachine: machineId, channel: responseChannel)
        } catch {
            logger.error("Failed to send invite key exchange response to machine \(machineId.prefix(8))...: \(error)")
        }
    }

    /// Handle invite payload (round 2)
    /// Decrypts the network key and joins the network
    private func handleInvitePayload(_ data: Data, from machineId: MachineId) async {
        guard let payload = try? JSONCoding.decoder.decode(InvitePayload.self, from: data) else {
            logger.warning("Failed to decode invite payload from machine \(machineId.prefix(8))...")
            return
        }

        // Find and remove the pending session
        guard let sessionData = pendingInviteSessions.removeValue(forKey: payload.requestId) else {
            logger.warning("Received invite payload for unknown request: \(payload.requestId)")
            await sendInviteFinalAck(
                requestId: payload.requestId,
                to: machineId,
                success: false,
                error: "No pending session found"
            )
            return
        }

        // Check if session has expired
        if Date() > sessionData.expiresAt {
            logger.warning("Invite session expired for request: \(payload.requestId)")
            await sendInviteFinalAck(
                requestId: payload.requestId,
                to: machineId,
                success: false,
                error: "Session expired"
            )
            return
        }

        // Verify the machine ID matches
        guard sessionData.fromMachineId == machineId else {
            logger.warning("Invite payload from wrong machine: expected \(sessionData.fromMachineId.prefix(8))..., got \(machineId.prefix(8))...")
            await sendInviteFinalAck(
                requestId: payload.requestId,
                to: machineId,
                success: false,
                error: "Machine ID mismatch"
            )
            return
        }

        do {
            // Derive the invite key
            let inviteKey = try await sessionData.session.deriveInviteKey()

            // Decrypt the network key
            let sealedBox = try ChaChaPoly.SealedBox(combined: payload.encryptedNetworkKey)
            let networkKey = try ChaChaPoly.open(sealedBox, using: inviteKey)

            // Optionally decrypt network name
            var networkName = sessionData.networkNameHint ?? "shared-network"
            if let encryptedName = payload.encryptedNetworkName {
                let nameSealedBox = try ChaChaPoly.SealedBox(combined: encryptedName)
                let nameData = try ChaChaPoly.open(nameSealedBox, using: inviteKey)
                networkName = String(data: nameData, encoding: .utf8) ?? networkName
            }

            // Compute network ID
            let hash = SHA256.hash(data: networkKey)
            let networkId = hash.prefix(8).map { String(format: "%02x", $0) }.joined()

            // Send success ack
            await sendInviteFinalAck(
                requestId: payload.requestId,
                to: machineId,
                success: true,
                joinedNetworkId: networkId
            )

            // Notify about the new network key
            let result = CloisterResult(
                networkKey: networkKey,
                networkId: networkId,
                networkName: networkName,
                sharedWith: machineId
            )

            if let callback = networkKeyCallback {
                await callback(result)
            }

            logger.info("Successfully received invite from machine \(machineId.prefix(8))..., networkId: \(networkId)")

        } catch {
            logger.error("Failed to process invite payload from machine \(machineId.prefix(8))...: \(error)")
            await sendInviteFinalAck(
                requestId: payload.requestId,
                to: machineId,
                success: false,
                error: "Failed to decrypt invite: \(error.localizedDescription)"
            )
        }
    }

    /// Send final invite acknowledgment (round 2)
    private func sendInviteFinalAck(
        requestId: UUID,
        to machineId: MachineId,
        success: Bool,
        joinedNetworkId: String? = nil,
        error: String? = nil
    ) async {
        let ack = InviteFinalAck(
            requestId: requestId,
            success: success,
            joinedNetworkId: joinedNetworkId,
            error: error
        )

        do {
            let ackData = try JSONCoding.encoder.encode(ack)
            let myPeerId = await provider.peerId
            let ackChannel = CloisterChannels.inviteFinalAck(for: myPeerId)
            try await provider.sendOnChannel(ackData, toMachine: machineId, channel: ackChannel)
        } catch {
            logger.error("Failed to send invite final ack to machine \(machineId.prefix(8))...: \(error)")
        }
    }
}
