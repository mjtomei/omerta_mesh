// DHCPClient.swift - Native DHCP client for mesh networks
//
// Runs on peers to obtain IP addresses from the gateway's DHCP service.
// Sends requests over the "dhcp" mesh channel and handles lease renewals.

import Foundation
import OmertaMesh
import Logging

/// Configuration for the native DHCP client
public struct NativeDHCPClientConfig: Sendable {
    /// Machine ID of the gateway (DHCP server)
    public let gatewayMachineId: MachineId

    /// Timeout for DHCP operations in seconds
    public let timeout: TimeInterval

    /// Number of retries before giving up
    public let retries: Int

    /// Whether to auto-renew leases before expiration
    public let autoRenew: Bool

    /// Hostname to send in DHCP requests
    public let hostname: String?

    public init(
        gatewayMachineId: MachineId,
        timeout: TimeInterval = 10,
        retries: Int = 3,
        autoRenew: Bool = true,
        hostname: String? = nil
    ) {
        self.gatewayMachineId = gatewayMachineId
        self.timeout = timeout
        self.retries = retries
        self.autoRenew = autoRenew
        self.hostname = hostname
    }
}

/// Native DHCP client for mesh networks
///
/// Usage on peer:
/// ```swift
/// let client = DHCPClient(machineId: myMachineId, config: config, provider: meshNetwork)
/// try await client.start()
/// let lease = try await client.requestAddress()
/// print("Got IP: \(lease.assignedIP)")
/// ```
public actor DHCPClient {
    private let machineId: MachineId
    private let config: NativeDHCPClientConfig
    private let provider: any ChannelProvider
    private let logger: Logger

    /// Current lease (if any)
    private var currentLease: DHCPResponse?

    /// When the current lease was obtained
    private var leaseObtainedAt: Date?

    /// Pending response continuation for request/response matching
    private var pendingResponse: CheckedContinuation<DHCPMessage, Never>?

    /// Whether the client is running (listening for responses)
    private var isRunning = false

    /// Renewal task handle
    private var renewalTask: Task<Void, Never>?

    /// Initialize the DHCP client
    /// - Parameters:
    ///   - machineId: This machine's ID
    ///   - config: Client configuration
    ///   - provider: Channel provider for sending/receiving messages
    public init(machineId: MachineId, config: NativeDHCPClientConfig, provider: any ChannelProvider) {
        self.machineId = machineId
        self.config = config
        self.provider = provider
        self.logger = Logger(label: "io.omerta.dhcp.client")
    }

    /// Start the DHCP client (begin listening for responses)
    public func start() async throws {
        guard !isRunning else { return }

        // Register handler for DHCP responses
        try await provider.onChannel(DHCPService.channelName) { [weak self] _, data in
            await self?.handleMessage(data: data)
        }

        isRunning = true
        logger.info("DHCP client started")
    }

    /// Stop the DHCP client
    public func stop() async {
        guard isRunning else { return }

        renewalTask?.cancel()
        renewalTask = nil

        await provider.offChannel(DHCPService.channelName)

        // Cancel any pending request - not possible with Never error, so just clear
        pendingResponse = nil

        isRunning = false
        logger.info("DHCP client stopped")
    }

    /// Request an IP address from the DHCP server
    /// - Parameter requestedIP: Optional preferred IP address
    /// - Returns: The DHCP response with assigned address
    /// - Throws: DHCPError if request fails
    public func requestAddress(requestedIP: String? = nil) async throws -> DHCPResponse {
        guard isRunning else {
            throw DHCPError.notRunning
        }

        let request = DHCPRequest(
            machineId: machineId,
            requestedIP: requestedIP,
            hostname: config.hostname
        )

        var lastError: Error = DHCPError.timeout

        for attempt in 1...config.retries {
            logger.debug("Sending DHCP request", metadata: [
                "attempt": "\(attempt)",
                "requestedIP": "\(requestedIP ?? "none")"
            ])

            do {
                let response = try await sendRequestAndWait(.request(request))

                switch response {
                case .response(let dhcpResponse):
                    currentLease = dhcpResponse
                    leaseObtainedAt = Date()

                    logger.info("IP address obtained", metadata: [
                        "ip": "\(dhcpResponse.assignedIP)",
                        "lease": "\(dhcpResponse.leaseSeconds)s"
                    ])

                    // Start renewal task if auto-renew is enabled
                    if config.autoRenew {
                        startRenewalTask()
                    }

                    return dhcpResponse

                case .nak(let reason):
                    logger.warning("DHCP request rejected", metadata: ["reason": "\(reason)"])
                    throw DHCPError.noAddressAvailable

                default:
                    logger.warning("Unexpected response type")
                    lastError = DHCPError.invalidRequest("Unexpected response type")
                }

            } catch {
                lastError = error
                if attempt < config.retries {
                    logger.debug("Retrying after error", metadata: ["error": "\(error)"])
                    try? await Task.sleep(for: .milliseconds(500 * UInt64(attempt)))
                }
            }
        }

        throw lastError
    }

    /// Renew the current lease
    /// - Returns: The renewed DHCP response
    /// - Throws: DHCPError if renewal fails
    public func renewLease() async throws -> DHCPResponse {
        guard isRunning else {
            throw DHCPError.notRunning
        }

        guard let lease = currentLease else {
            throw DHCPError.leaseExpired
        }

        let renewal = DHCPRenewal(
            machineId: machineId,
            currentIP: lease.assignedIP
        )

        logger.debug("Sending lease renewal", metadata: ["ip": "\(lease.assignedIP)"])

        let response = try await sendRequestAndWait(.renewal(renewal))

        switch response {
        case .response(let dhcpResponse):
            currentLease = dhcpResponse
            leaseObtainedAt = Date()
            logger.info("Lease renewed", metadata: [
                "ip": "\(dhcpResponse.assignedIP)",
                "lease": "\(dhcpResponse.leaseSeconds)s"
            ])
            return dhcpResponse

        case .nak(let reason):
            logger.warning("Lease renewal rejected", metadata: ["reason": "\(reason)"])
            currentLease = nil
            leaseObtainedAt = nil
            throw DHCPError.leaseExpired

        default:
            throw DHCPError.invalidRequest("Unexpected response type")
        }
    }

    /// Release the current lease
    public func releaseLease() async throws {
        guard let lease = currentLease else {
            return // Nothing to release
        }

        renewalTask?.cancel()
        renewalTask = nil

        let release = DHCPRelease(
            machineId: machineId,
            ip: lease.assignedIP
        )

        guard let data = try? JSONEncoder().encode(DHCPMessage.release(release)) else {
            throw DHCPError.encodingFailed
        }

        try await provider.sendOnChannel(data, toMachine: config.gatewayMachineId, channel: DHCPService.channelName)

        logger.info("Lease released", metadata: ["ip": "\(lease.assignedIP)"])

        currentLease = nil
        leaseObtainedAt = nil
    }

    /// Get the current lease (if any)
    public func getCurrentLease() -> DHCPResponse? {
        currentLease
    }

    /// Check if the current lease is still valid
    public func isLeaseValid() -> Bool {
        guard let lease = currentLease, let obtainedAt = leaseObtainedAt else {
            return false
        }

        let expiresAt = obtainedAt.addingTimeInterval(Double(lease.leaseSeconds))
        return Date() < expiresAt
    }

    /// Get remaining time on the current lease
    public func leaseTimeRemaining() -> TimeInterval {
        guard let lease = currentLease, let obtainedAt = leaseObtainedAt else {
            return 0
        }

        let expiresAt = obtainedAt.addingTimeInterval(Double(lease.leaseSeconds))
        return max(0, expiresAt.timeIntervalSinceNow)
    }

    // MARK: - Private

    private func handleMessage(data: Data) async {
        guard let message = try? JSONDecoder().decode(DHCPMessage.self, from: data) else {
            logger.warning("Invalid DHCP message received")
            return
        }

        // Resume the pending continuation
        if let continuation = pendingResponse {
            pendingResponse = nil
            continuation.resume(returning: message)
        }
    }

    private func sendRequestAndWait(_ message: DHCPMessage) async throws -> DHCPMessage {
        guard let data = try? JSONEncoder().encode(message) else {
            throw DHCPError.encodingFailed
        }

        // Send the request first
        try await provider.sendOnChannel(data, toMachine: config.gatewayMachineId, channel: DHCPService.channelName)

        // Wait for response with timeout.
        // withCheckedContinuation's closure runs synchronously on the actor
        // before suspending, so queued handleMessage calls will see pendingResponse.
        let timeoutSeconds = config.timeout

        // Set up timeout that will resume the continuation if it hasn't been resumed
        let result: DHCPMessage = await withCheckedContinuation { continuation in
            self.pendingResponse = continuation

            // Schedule timeout
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(timeoutSeconds))
                // If still pending, resume with a timeout indicator
                await self?.timeoutPendingResponse()
            }
        }

        // Check if result is a timeout sentinel (nak with timeout message)
        if case .nak(let reason) = result, reason == "__timeout__" {
            throw DHCPError.timeout
        }

        return result
    }

    private func timeoutPendingResponse() {
        if let continuation = pendingResponse {
            pendingResponse = nil
            continuation.resume(returning: .nak("__timeout__"))
        }
    }

    private func startRenewalTask() {
        renewalTask?.cancel()

        renewalTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { return }

                // Wait until 50% of lease time has passed before renewing
                let remaining = await self.leaseTimeRemaining()
                let renewTime = remaining * 0.5

                if renewTime > 0 {
                    try? await Task.sleep(for: .seconds(renewTime))
                }

                guard !Task.isCancelled else { return }

                // Attempt renewal
                do {
                    _ = try await self.renewLease()
                } catch {
                    // If renewal fails, try again sooner
                    try? await Task.sleep(for: .seconds(10))
                }
            }
        }
    }
}
