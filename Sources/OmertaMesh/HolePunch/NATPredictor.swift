// NATPredictor.swift - Peer-based NAT type prediction
//
// Predicts NAT type by analyzing endpoint observations reported by peers in pong messages.
// This replaces STUN-based detection with a decentralized approach.

import Foundation
import Logging

/// Predicts NAT type based on endpoint observations from peers
public actor NATPredictor {
    /// An observation of our endpoint as reported by a peer
    struct EndpointObservation {
        let endpoint: String
        let timestamp: Date
        let isBootstrapNode: Bool
    }

    /// Observations keyed by the peer that reported them
    private var observations: [PeerId: EndpointObservation] = [:]

    /// Minimum number of observations needed for prediction
    private let minimumObservations: Int

    /// Our local endpoint (if known) for public IP detection
    private var localEndpoint: String?

    /// Event logger for persistent logging
    private var eventLogger: MeshEventLogger?

    /// Last predicted NAT type (for change detection)
    private var lastNATType: NATType?

    /// Last predicted endpoint (for change detection)
    private var lastEndpoint: String?

    private let logger = Logger(label: "io.omerta.mesh.nat.predictor")

    /// Create a NAT predictor
    /// - Parameters:
    ///   - localEndpoint: Our local bind endpoint (for public IP detection)
    ///   - minimumObservations: Minimum observations needed for prediction (default: 2)
    public init(localEndpoint: String? = nil, minimumObservations: Int = 2) {
        self.localEndpoint = localEndpoint
        self.minimumObservations = minimumObservations
    }

    /// Set the event logger for persistent logging
    public func setEventLogger(_ logger: MeshEventLogger?) {
        self.eventLogger = logger
    }

    /// Set the local endpoint for public IP detection
    public func setLocalEndpoint(_ endpoint: String) {
        self.localEndpoint = endpoint
    }

    /// Record an endpoint observation from a peer
    /// - Parameters:
    ///   - endpoint: The endpoint the peer reports seeing us at
    ///   - peerId: The peer reporting the observation
    ///   - isBootstrap: Whether this peer is a bootstrap node (higher weight)
    public func recordObservation(endpoint: String, from peerId: PeerId, isBootstrap: Bool) {
        let observation = EndpointObservation(
            endpoint: endpoint,
            timestamp: Date(),
            isBootstrapNode: isBootstrap
        )

        // Update or add observation for this peer
        observations[peerId] = observation

        logger.debug("Recorded endpoint observation", metadata: [
            "endpoint": "\(endpoint)",
            "from": "\(peerId)",
            "isBootstrap": "\(isBootstrap)",
            "totalObservations": "\(observations.count)"
        ])
    }

    /// Predict NAT type based on collected observations
    /// - Returns: Tuple of (NAT type, public endpoint if stable, confidence level)
    public func predictNATType() -> (type: NATType, publicEndpoint: String?, confidence: Int) {
        let observationCount = observations.count

        // Not enough observations
        if observationCount < minimumObservations {
            return (type: .unknown, publicEndpoint: nil, confidence: observationCount)
        }

        // Extract endpoints and filter to valid (parseable) ones
        let allEndpoints = observations.values.map { $0.endpoint }
        let validEndpoints = allEndpoints.filter { parseEndpoint($0) != nil }
        let validCount = validEndpoints.count

        // Not enough valid observations
        guard validCount >= minimumObservations else {
            return (type: .unknown, publicEndpoint: nil, confidence: 0)
        }

        let uniqueValidEndpoints = Set(validEndpoints)

        // Parse endpoints to analyze IPs and ports
        let parsed = validEndpoints.compactMap { parseEndpoint($0) }
        let uniqueIPs = Set(parsed.map { $0.ip })
        let uniquePorts = Set(parsed.map { $0.port })

        // Check for public IP (no NAT)
        if let local = localEndpoint, let localParsed = parseEndpoint(local) {
            // If observed IP matches local IP, we're public
            if uniqueIPs.count == 1, let observedIP = uniqueIPs.first, observedIP == localParsed.ip {
                // Also check port matches
                if uniquePorts.count == 1, let observedPort = uniquePorts.first, observedPort == localParsed.port {
                    logNATTypeChange(.public)
                    logEndpointChange(uniqueValidEndpoints.first)
                    return (type: .public, publicEndpoint: uniqueValidEndpoints.first, confidence: validCount)
                }
            }
        }

        // All peers report same endpoint → Cone NAT
        if uniqueValidEndpoints.count == 1 {
            let stableEndpoint = uniqueValidEndpoints.first!
            logNATTypeChange(.portRestrictedCone)
            logEndpointChange(stableEndpoint)
            return (type: .portRestrictedCone, publicEndpoint: stableEndpoint, confidence: validCount)
        }

        // Same IP, different ports → Symmetric NAT
        if uniqueIPs.count == 1 && uniquePorts.count > 1 {
            logNATTypeChange(.symmetric)
            logEndpointChange(nil)
            return (type: .symmetric, publicEndpoint: nil, confidence: validCount)
        }

        // Different IPs → Also symmetric (very restrictive NAT)
        if uniqueIPs.count > 1 {
            logNATTypeChange(.symmetric)
            logEndpointChange(nil)
            return (type: .symmetric, publicEndpoint: nil, confidence: validCount)
        }

        // Shouldn't reach here, but default to unknown
        return (type: .unknown, publicEndpoint: nil, confidence: validCount)
    }

    /// Reset all observations (e.g., after network change)
    public func reset() {
        observations.removeAll()
        lastNATType = nil
        lastEndpoint = nil
        logger.info("NAT predictor reset")
    }

    /// Get the number of current observations
    public var observationCount: Int {
        observations.count
    }

    /// Check if a specific peer has provided an observation
    public func hasObservation(from peerId: PeerId) -> Bool {
        observations[peerId] != nil
    }

    /// Get the most recently observed endpoint (most common)
    public var mostCommonEndpoint: String? {
        let endpoints = observations.values.map { $0.endpoint }
        guard !endpoints.isEmpty else { return nil }

        // Count occurrences
        var counts: [String: Int] = [:]
        for endpoint in endpoints {
            counts[endpoint, default: 0] += 1
        }

        return counts.max(by: { $0.value < $1.value })?.key
    }

    // MARK: - Private Methods

    private func parseEndpoint(_ endpoint: String) -> (ip: String, port: UInt16)? {
        // Handle IPv6 [ip]:port format
        if endpoint.hasPrefix("[") {
            guard let closeBracket = endpoint.lastIndex(of: "]"),
                  let colonIndex = endpoint[closeBracket...].firstIndex(of: ":"),
                  colonIndex > closeBracket else {
                return nil
            }
            let ip = String(endpoint[endpoint.index(after: endpoint.startIndex)..<closeBracket])
            let portStr = String(endpoint[endpoint.index(after: colonIndex)...])
            guard let port = UInt16(portStr) else { return nil }
            return (ip, port)
        }

        // Handle IPv4 ip:port format
        let parts = endpoint.split(separator: ":")
        guard parts.count == 2,
              let port = UInt16(parts[1]) else {
            return nil
        }
        return (String(parts[0]), port)
    }

    private func logNATTypeChange(_ newType: NATType) {
        if let last = lastNATType, last != newType {
            Task {
                await eventLogger?.recordNATTypeChange(oldType: last.rawValue, newType: newType.rawValue)
            }
            logger.info("NAT type changed", metadata: [
                "oldType": "\(last.rawValue)",
                "newType": "\(newType.rawValue)"
            ])
        } else if lastNATType == nil {
            Task {
                await eventLogger?.recordNATTypeChange(oldType: nil, newType: newType.rawValue)
            }
            logger.info("NAT type predicted", metadata: ["type": "\(newType.rawValue)"])
        }
        lastNATType = newType
    }

    private func logEndpointChange(_ newEndpoint: String?) {
        if let last = lastEndpoint, last != newEndpoint {
            Task {
                await eventLogger?.recordEndpointChange(oldEndpoint: last, newEndpoint: newEndpoint ?? "none")
            }
        } else if lastEndpoint == nil, let new = newEndpoint {
            Task {
                await eventLogger?.recordEndpointChange(oldEndpoint: nil, newEndpoint: new)
            }
        }
        lastEndpoint = newEndpoint
    }
}
