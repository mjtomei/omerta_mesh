// CloisterClient.swift - Client for private network key negotiation
//
// Performs X25519 key exchange with peers to create new private networks
// or share existing network invites securely.

import Foundation
import Crypto
import Logging

/// Client for negotiating private network keys with peers
public actor CloisterClient {
    /// The channel provider for sending requests
    private let provider: any ChannelProvider

    /// Pending negotiation requests
    private var pendingNegotiations: [UUID: NegotiationState] = [:]

    /// Pending invite shares
    private var pendingInvites: [UUID: InviteState] = [:]

    /// Logger
    private let logger = Logger(label: "io.omerta.mesh.services.cloister.client")

    /// Whether response handlers are registered
    private var isRegistered: Bool = false

    /// Initialize with a channel provider
    public init(provider: any ChannelProvider) {
        self.provider = provider
    }

    // MARK: - Negotiation State

    private struct NegotiationState {
        let privateKey: Curve25519.KeyAgreement.PrivateKey
        let networkName: String
        let continuation: CheckedContinuation<CloisterResult, Error>
        let timeoutTask: Task<Void, Never>
    }

    private struct InviteState {
        let session: KeyExchangeSession
        let networkKey: Data
        let networkName: String?
        let continuation: CheckedContinuation<NetworkInviteResult, Error>
        let timeoutTask: Task<Void, Never>
    }

    // MARK: - Public API

    /// Negotiate a new private network key with a peer
    /// Both peers will derive the same network key using X25519 key agreement
    /// - Parameters:
    ///   - peer: The peer to negotiate with
    ///   - networkName: Name for the new network
    ///   - timeout: How long to wait for response
    /// - Returns: The result containing the derived network key
    public func negotiate(
        with peer: PeerId,
        networkName: String,
        timeout: TimeInterval = 30.0
    ) async throws -> CloisterResult {
        // Ensure response channel is registered
        if !isRegistered {
            try await registerResponseHandlers()
        }

        // Generate ephemeral X25519 keypair
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyData = Data(privateKey.publicKey.rawRepresentation)

        let request = CloisterRequest(
            networkName: networkName,
            ephemeralPublicKey: publicKeyData
        )

        let requestData = try JSONCoding.encoder.encode(request)

        return try await withCheckedThrowingContinuation { continuation in
            Task {
                // Set up timeout
                let timeoutTask = Task {
                    try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                    if let _ = self.pendingNegotiations.removeValue(forKey: request.requestId) {
                        continuation.resume(throwing: ServiceError.timeout)
                    }
                }

                // Store state
                self.pendingNegotiations[request.requestId] = NegotiationState(
                    privateKey: privateKey,
                    networkName: networkName,
                    continuation: continuation,
                    timeoutTask: timeoutTask
                )

                // Send request
                do {
                    try await self.provider.sendOnChannel(requestData, to: peer, channel: CloisterChannels.negotiate)
                    self.logger.debug("Sent cloister negotiation request to \(peer.prefix(8))...")
                } catch {
                    self.pendingNegotiations.removeValue(forKey: request.requestId)
                    timeoutTask.cancel()
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Share an existing network invite with a peer
    /// Uses two-round X25519 key exchange for secure invite transmission
    /// - Parameters:
    ///   - networkKey: The network key to share
    ///   - peer: The peer to share with
    ///   - networkName: Optional name hint for the network
    ///   - timeout: How long to wait for response
    /// - Returns: The result indicating if the peer joined
    public func shareInvite(
        _ networkKey: Data,
        with peer: PeerId,
        networkName: String? = nil,
        timeout: TimeInterval = 30.0
    ) async throws -> NetworkInviteResult {
        // Ensure response channel is registered
        if !isRegistered {
            try await registerResponseHandlers()
        }

        // Create key exchange session
        let session = KeyExchangeSession()
        let publicKeyData = await session.publicKey

        // Round 1: Send our public key to initiate key exchange
        let keyExchangeRequest = InviteKeyExchangeRequest(
            ephemeralPublicKey: publicKeyData,
            networkNameHint: networkName
        )

        let requestData = try JSONCoding.encoder.encode(keyExchangeRequest)

        return try await withCheckedThrowingContinuation { continuation in
            Task {
                let timeoutTask = Task {
                    try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                    if let _ = self.pendingInvites.removeValue(forKey: keyExchangeRequest.requestId) {
                        continuation.resume(throwing: ServiceError.timeout)
                    }
                }

                self.pendingInvites[keyExchangeRequest.requestId] = InviteState(
                    session: session,
                    networkKey: networkKey,
                    networkName: networkName,
                    continuation: continuation,
                    timeoutTask: timeoutTask
                )

                do {
                    try await self.provider.sendOnChannel(requestData, to: peer, channel: CloisterChannels.inviteKeyExchange)
                    self.logger.debug("Sent invite key exchange request to \(peer.prefix(8))...")
                } catch {
                    self.pendingInvites.removeValue(forKey: keyExchangeRequest.requestId)
                    timeoutTask.cancel()
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Internal

    private func registerResponseHandlers() async throws {
        let myPeerId = await provider.peerId

        // Register negotiation response handler
        let negotiateResponseChannel = CloisterChannels.response(for: myPeerId)
        try await provider.onChannel(negotiateResponseChannel) { [weak self] fromMachineId, data in
            await self?.handleNegotiationResponse(data, from: fromMachineId)
        }

        // Register invite key exchange response handler (round 1 response)
        let inviteKeyExchangeResponseChannel = CloisterChannels.inviteKeyExchangeResponse(for: myPeerId)
        try await provider.onChannel(inviteKeyExchangeResponseChannel) { [weak self] fromMachineId, data in
            await self?.handleInviteKeyExchangeResponse(data, from: fromMachineId)
        }

        // Register final invite ack handler (round 2 response)
        let inviteFinalAckChannel = CloisterChannels.inviteFinalAck(for: myPeerId)
        try await provider.onChannel(inviteFinalAckChannel) { [weak self] fromMachineId, data in
            await self?.handleInviteFinalAck(data, from: fromMachineId)
        }

        isRegistered = true
        logger.debug("Registered cloister response handlers")
    }

    private func handleNegotiationResponse(_ data: Data, from machineId: MachineId) async {
        guard let response = try? JSONCoding.decoder.decode(CloisterResponse.self, from: data) else {
            logger.warning("Failed to decode cloister response from machine \(machineId.prefix(8))...")
            return
        }

        guard let state = pendingNegotiations.removeValue(forKey: response.requestId) else {
            logger.debug("Received cloister response for unknown request: \(response.requestId)")
            return
        }

        state.timeoutTask.cancel()

        if !response.accepted {
            state.continuation.resume(throwing: ServiceError.rejected(
                reason: response.rejectReason ?? "Unknown reason"
            ))
            return
        }

        guard let theirPublicKeyData = response.ephemeralPublicKey else {
            state.continuation.resume(throwing: ServiceError.keyExchangeFailed("No public key in response"))
            return
        }

        do {
            let theirPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPublicKeyData)

            // Derive shared secret using X25519
            let sharedSecret = try state.privateKey.sharedSecretFromKeyAgreement(with: theirPublicKey)

            // Derive network key using HKDF
            let networkKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: Data("omerta-network-key".utf8),
                outputByteCount: 32
            )

            let networkKeyData = networkKey.withUnsafeBytes { Data($0) }

            // Compute network ID (first 16 hex chars of SHA256 hash)
            let hash = SHA256.hash(data: networkKeyData)
            let networkId = hash.prefix(8).map { String(format: "%02x", $0) }.joined()

            let result = CloisterResult(
                networkKey: networkKeyData,
                networkId: networkId,
                networkName: state.networkName,
                sharedWith: machineId
            )

            state.continuation.resume(returning: result)
            logger.info("Successfully negotiated network key with machine \(machineId.prefix(8))..., networkId: \(networkId)")

        } catch {
            state.continuation.resume(throwing: ServiceError.keyExchangeFailed(error.localizedDescription))
        }
    }

    /// Handle invite key exchange response (round 1)
    /// If accepted, complete key exchange and send encrypted invite
    private func handleInviteKeyExchangeResponse(_ data: Data, from machineId: MachineId) async {
        guard let response = try? JSONCoding.decoder.decode(InviteKeyExchangeResponse.self, from: data) else {
            logger.warning("Failed to decode invite key exchange response from machine \(machineId.prefix(8))...")
            return
        }

        guard let state = pendingInvites[response.requestId] else {
            logger.debug("Received invite key exchange response for unknown request: \(response.requestId)")
            return
        }

        // If rejected, complete with failure
        if !response.accepted {
            pendingInvites.removeValue(forKey: response.requestId)
            state.timeoutTask.cancel()
            state.continuation.resume(returning: NetworkInviteResult(
                accepted: false,
                joinedNetworkId: nil,
                rejectReason: response.rejectReason ?? "Invite rejected"
            ))
            return
        }

        // Complete key exchange
        do {
            try await state.session.completeExchange(peerPublicKey: response.ephemeralPublicKey)

            // Derive invite key and encrypt the network key
            let inviteKey = try await state.session.deriveInviteKey()
            let encryptedNetworkKey = try ChaChaPoly.seal(state.networkKey, using: inviteKey).combined

            // Optionally encrypt network name
            var encryptedNetworkName: Data? = nil
            if let name = state.networkName {
                encryptedNetworkName = try ChaChaPoly.seal(Data(name.utf8), using: inviteKey).combined
            }

            // Round 2: Send encrypted invite payload to the responding machine
            let payload = InvitePayload(
                requestId: response.requestId,
                encryptedNetworkKey: encryptedNetworkKey,
                encryptedNetworkName: encryptedNetworkName
            )

            let payloadData = try JSONCoding.encoder.encode(payload)
            let myPeerId = await provider.peerId
            let payloadChannel = CloisterChannels.invitePayload(for: myPeerId)
            try await provider.sendOnChannel(payloadData, toMachine: machineId, channel: payloadChannel)
            logger.debug("Sent encrypted invite payload to machine \(machineId.prefix(8))...")

            // Keep state for final ack (don't remove from pendingInvites yet)

        } catch {
            pendingInvites.removeValue(forKey: response.requestId)
            state.timeoutTask.cancel()
            state.continuation.resume(throwing: ServiceError.keyExchangeFailed(error.localizedDescription))
        }
    }

    /// Handle final invite ack (round 2)
    private func handleInviteFinalAck(_ data: Data, from machineId: MachineId) async {
        guard let ack = try? JSONCoding.decoder.decode(InviteFinalAck.self, from: data) else {
            logger.warning("Failed to decode invite final ack from machine \(machineId.prefix(8))...")
            return
        }

        guard let state = pendingInvites.removeValue(forKey: ack.requestId) else {
            logger.debug("Received invite final ack for unknown request: \(ack.requestId)")
            return
        }

        state.timeoutTask.cancel()

        let result = NetworkInviteResult(
            accepted: ack.success,
            joinedNetworkId: ack.joinedNetworkId,
            rejectReason: ack.error
        )

        if ack.success {
            logger.info("Successfully shared invite with machine \(machineId.prefix(8))..., networkId: \(ack.joinedNetworkId ?? "unknown")")
        } else {
            logger.warning("Invite sharing failed with machine \(machineId.prefix(8))...: \(ack.error ?? "unknown error")")
        }

        state.continuation.resume(returning: result)
    }

    /// Stop the client and cancel pending operations
    public func stop() async {
        let myPeerId = await provider.peerId
        await provider.offChannel(CloisterChannels.response(for: myPeerId))
        await provider.offChannel(CloisterChannels.inviteKeyExchangeResponse(for: myPeerId))
        await provider.offChannel(CloisterChannels.inviteFinalAck(for: myPeerId))
        isRegistered = false

        // Cancel all pending operations
        for (_, state) in pendingNegotiations {
            state.timeoutTask.cancel()
            state.continuation.resume(throwing: ServiceError.notStarted)
        }
        pendingNegotiations.removeAll()

        for (_, state) in pendingInvites {
            state.timeoutTask.cancel()
            state.continuation.resume(throwing: ServiceError.notStarted)
        }
        pendingInvites.removeAll()
    }
}
