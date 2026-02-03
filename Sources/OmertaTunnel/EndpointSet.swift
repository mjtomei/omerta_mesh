// EndpointSet.swift - Per-tunnel active endpoint set with DWRR scheduler
//
// Tracks active endpoints for a tunnel session, distributes traffic using
// deficit weighted round-robin (DWRR), and prunes endpoints on failure.

import Foundation

/// Per-tunnel endpoint set with weighted round-robin scheduling and failure pruning.
public actor EndpointSet {
    /// An active endpoint in the set.
    public struct ActiveEndpoint: Sendable {
        /// Remote address "host:port"
        public let address: String
        /// Local auxiliary port to send from (nil = primary socket)
        public let localPort: UInt16?
        /// Scheduling weight (starts at 1.0)
        public internal(set) var weight: Double
        /// Total bytes sent via this endpoint
        public internal(set) var bytesSent: UInt64
        /// Bytes acknowledged via health probe feedback
        public internal(set) var bytesAcked: UInt64
        /// DWRR deficit counter
        public internal(set) var deficit: Double
        /// Consecutive send failures
        public internal(set) var consecutiveFailures: Int
        /// Last successful send time
        public internal(set) var lastSuccess: ContinuousClock.Instant
    }

    private var endpoints: [ActiveEndpoint] = []

    /// Number of consecutive failures before pruning an endpoint
    public static let failureThreshold = 3

    public init() {}

    // MARK: - Endpoint Management

    /// Add an endpoint to the active set.
    public func add(address: String, localPort: UInt16?) {
        // Don't add duplicates
        guard !endpoints.contains(where: { $0.address == address }) else { return }
        endpoints.append(ActiveEndpoint(
            address: address,
            localPort: localPort,
            weight: 1.0,
            bytesSent: 0,
            bytesAcked: 0,
            deficit: 0,
            consecutiveFailures: 0,
            lastSuccess: .now
        ))
    }

    /// Update the local port for an existing endpoint (used when pairing local aux with remote aux).
    public func updateLocalPort(for address: String, localPort: UInt16) {
        guard let idx = endpoints.firstIndex(where: { $0.address == address }) else { return }
        var ep = endpoints[idx]
        endpoints[idx] = ActiveEndpoint(
            address: ep.address,
            localPort: localPort,
            weight: ep.weight,
            bytesSent: ep.bytesSent,
            bytesAcked: ep.bytesAcked,
            deficit: ep.deficit,
            consecutiveFailures: ep.consecutiveFailures,
            lastSuccess: ep.lastSuccess
        )
    }

    /// Remove an endpoint from the set. Returns true if any endpoints remain.
    @discardableResult
    public func prune(address: String) -> Bool {
        endpoints.removeAll { $0.address == address }
        return !endpoints.isEmpty
    }

    // MARK: - DWRR Scheduling

    /// Pick the next endpoint for a packet of the given byte count.
    /// Returns nil if no endpoints are available.
    public func next(byteCount: Int) -> ActiveEndpoint? {
        guard !endpoints.isEmpty else { return nil }

        // Add weight to each endpoint's deficit
        for i in endpoints.indices {
            endpoints[i].deficit += endpoints[i].weight
        }

        // Pick endpoint with highest deficit
        guard let maxIndex = endpoints.indices.max(by: { endpoints[$0].deficit < endpoints[$1].deficit }) else {
            return nil
        }

        // Subtract byte cost from chosen endpoint's deficit
        endpoints[maxIndex].deficit -= Double(byteCount)

        return endpoints[maxIndex]
    }

    // MARK: - Stats Recording

    /// Record a successful send to an endpoint.
    public func recordSend(to address: String, bytes: Int) {
        guard let idx = endpoints.firstIndex(where: { $0.address == address }) else { return }
        endpoints[idx].bytesSent += UInt64(bytes)
        endpoints[idx].consecutiveFailures = 0
        endpoints[idx].lastSuccess = .now
    }

    /// Record a send failure. Returns true if the endpoint was pruned.
    @discardableResult
    public func recordFailure(address: String) -> Bool {
        guard let idx = endpoints.firstIndex(where: { $0.address == address }) else { return false }
        endpoints[idx].consecutiveFailures += 1
        if endpoints[idx].consecutiveFailures >= Self.failureThreshold {
            endpoints.remove(at: idx)
            return true
        }
        return false
    }

    /// Record delivery feedback from health probes.
    public func recordDelivery(from address: String, bytes: UInt64) {
        guard let idx = endpoints.firstIndex(where: { $0.address == address }) else { return }
        endpoints[idx].bytesAcked = bytes
    }

    // MARK: - Rebalancing

    /// Update weights based on delivery ratio (bytesAcked / bytesSent).
    public func rebalance() {
        // Need at least 2 endpoints with send data to rebalance
        let withData = endpoints.filter { $0.bytesSent > 0 }
        guard withData.count >= 2 else { return }

        for i in endpoints.indices {
            guard endpoints[i].bytesSent > 0 else { continue }
            let ratio = Double(endpoints[i].bytesAcked) / Double(endpoints[i].bytesSent)
            // Weight = delivery ratio + 0.5 baseline so even endpoints with 0% delivery
            // keep some traffic (needed to detect recovery). Clamped to [0.1, 10.0].
            endpoints[i].weight = max(0.1, min(10.0, ratio + 0.5))
        }
    }

    // MARK: - Accessors

    /// All active endpoint addresses.
    public var activeAddresses: [String] {
        endpoints.map(\.address)
    }

    /// Number of active endpoints.
    public var count: Int {
        endpoints.count
    }

    /// All active endpoints (for inspection/testing).
    public var allEndpoints: [ActiveEndpoint] {
        endpoints
    }
}
