// SimulatedNAT.swift - Simulates NAT behavior for testing

import Foundation
@testable import OmertaMesh

/// Simulates NAT behavior for testing hole punching and relay scenarios
public actor SimulatedNAT {
    /// The type of NAT being simulated
    public let type: NATType

    /// The public IP address of this NAT
    public let publicIP: String

    /// Port allocation strategy for symmetric NAT
    public let portAllocation: PortAllocationStrategy

    /// Configuration for NAT behavior
    public let config: NATConfig

    /// Active mappings from internal to external endpoints
    private var mappings: [String: NATMapping] = [:]

    /// Next external port to allocate
    private var nextExternalPort: UInt16 = 10000

    /// Mapping timeout in seconds (from config)
    private var mappingTimeout: TimeInterval { config.mappingTimeout }

    /// Whether the NAT is currently functioning
    private var isEnabled: Bool = true

    /// Statistics for testing
    private var stats = NATStats()

    /// Configuration for NAT simulation
    public struct NATConfig: Sendable {
        /// Mapping timeout in seconds
        public let mappingTimeout: TimeInterval

        /// Whether hairpin NAT is supported (internal -> external -> internal)
        public let supportsHairpin: Bool

        /// Port range for external port allocation
        public let portRange: ClosedRange<UInt16>

        /// Whether to simulate port prediction (for symmetric NAT)
        public let predictablePortDelta: UInt16?

        /// Maximum number of mappings (0 = unlimited)
        public let maxMappings: Int

        public init(
            mappingTimeout: TimeInterval = 120,
            supportsHairpin: Bool = false,
            portRange: ClosedRange<UInt16> = 10000...60000,
            predictablePortDelta: UInt16? = nil,
            maxMappings: Int = 0
        ) {
            self.mappingTimeout = mappingTimeout
            self.supportsHairpin = supportsHairpin
            self.portRange = portRange
            self.predictablePortDelta = predictablePortDelta
            self.maxMappings = maxMappings
        }

        public static let `default` = NATConfig()

        /// Config for aggressive NAT (short timeouts)
        public static let aggressive = NATConfig(mappingTimeout: 30)

        /// Config for carrier-grade NAT
        public static let carrierGrade = NATConfig(
            mappingTimeout: 60,
            maxMappings: 100
        )
    }

    /// Statistics about NAT operations
    public struct NATStats: Sendable {
        public var packetsTranslated: Int = 0
        public var packetsDropped: Int = 0
        public var mappingsCreated: Int = 0
        public var mappingsExpired: Int = 0
        public var inboundAllowed: Int = 0
        public var inboundBlocked: Int = 0
    }

    /// Port allocation strategies for symmetric NAT
    public enum PortAllocationStrategy: Sendable {
        case sequential      // Ports increase by 1 each time
        case random          // Random port each time
        case preserving      // Try to use same port as internal
    }

    /// A NAT mapping entry
    public struct NATMapping: Sendable {
        public let internalEndpoint: String
        public let externalEndpoint: String
        public let createdAt: Date
        public var lastUsed: Date

        /// For restricted NATs: which destinations we've sent to
        public var allowedDestinations: Set<String>

        /// For port-restricted: exact IP:port pairs
        public var allowedDestinationPorts: Set<String>

        public var isExpired: Bool {
            Date().timeIntervalSince(lastUsed) > 120
        }
    }

    public init(
        type: NATType,
        publicIP: String = "10.0.0.1",
        portAllocation: PortAllocationStrategy = .sequential,
        config: NATConfig = .default
    ) {
        self.type = type
        self.publicIP = publicIP
        self.portAllocation = portAllocation
        self.config = config
        self.nextExternalPort = config.portRange.lowerBound
    }

    // MARK: - Outbound Translation

    /// Translate an outbound packet (internal -> external)
    /// Returns the external source endpoint to use, or nil if blocked
    public func translateOutbound(
        from internalEndpoint: String,
        to destination: String
    ) -> String? {
        // Check if NAT is enabled
        guard isEnabled else {
            stats.packetsDropped += 1
            return nil
        }

        // Public NAT doesn't translate
        if type == .public {
            stats.packetsTranslated += 1
            return internalEndpoint
        }

        // Check max mappings limit
        if config.maxMappings > 0 && mappings.count >= config.maxMappings {
            // At capacity, check if any expired
            cleanupExpired()
            if mappings.count >= config.maxMappings {
                stats.packetsDropped += 1
                return nil
            }
        }

        // Get or create mapping
        let mapping = getOrCreateMapping(for: internalEndpoint, destination: destination)

        // Update allowed destinations for restricted NATs
        var updatedMapping = mapping
        updatedMapping.lastUsed = Date()

        switch type {
        case .restrictedCone:
            // Track IP only
            let destIP = destination.split(separator: ":").first.map(String.init) ?? destination
            updatedMapping.allowedDestinations.insert(destIP)

        case .portRestrictedCone:
            // Track IP:port
            updatedMapping.allowedDestinationPorts.insert(destination)

        case .symmetric:
            // Track exact destination
            updatedMapping.allowedDestinationPorts.insert(destination)

        default:
            break
        }

        // Store updated mapping
        let key = mappingKey(internalEndpoint, destination: destination)
        mappings[key] = updatedMapping

        stats.packetsTranslated += 1
        return mapping.externalEndpoint
    }

    /// Get or create a NAT mapping
    private func getOrCreateMapping(for internalEndpoint: String, destination: String) -> NATMapping {
        let key = mappingKey(internalEndpoint, destination: destination)

        // Check for existing mapping
        if let existing = mappings[key], !existing.isExpired {
            return existing
        }

        // If there was an expired mapping, count it
        if mappings[key] != nil {
            stats.mappingsExpired += 1
        }

        // Create new mapping
        let externalPort = allocatePort(for: internalEndpoint, destination: destination)
        let externalEndpoint = "\(publicIP):\(externalPort)"

        stats.mappingsCreated += 1

        let mapping = NATMapping(
            internalEndpoint: internalEndpoint,
            externalEndpoint: externalEndpoint,
            createdAt: Date(),
            lastUsed: Date(),
            allowedDestinations: [],
            allowedDestinationPorts: []
        )

        mappings[key] = mapping
        return mapping
    }

    /// Generate mapping key based on NAT type
    private func mappingKey(_ internalEndpoint: String, destination: String) -> String {
        switch type {
        case .symmetric:
            // Different mapping per destination
            return "\(internalEndpoint)->\(destination)"
        default:
            // Same mapping for all destinations
            return internalEndpoint
        }
    }

    /// Allocate an external port
    private func allocatePort(for internalEndpoint: String, destination: String) -> UInt16 {
        // For non-symmetric NAT, try to reuse existing port
        if type != .symmetric {
            for (_, mapping) in mappings {
                if mapping.internalEndpoint == internalEndpoint && !mapping.isExpired {
                    let port = mapping.externalEndpoint.split(separator: ":").last
                        .flatMap { UInt16($0) }
                    if let port = port {
                        return port
                    }
                }
            }
        }

        // Allocate new port based on strategy
        let port: UInt16
        switch portAllocation {
        case .sequential:
            port = nextExternalPort
            nextExternalPort += 1

        case .random:
            port = UInt16.random(in: 10000..<60000)

        case .preserving:
            // Try to use internal port
            if let internalPort = internalEndpoint.split(separator: ":").last.flatMap({ UInt16($0) }) {
                port = internalPort
            } else {
                port = nextExternalPort
                nextExternalPort += 1
            }
        }

        return port
    }

    // MARK: - Inbound Filtering

    /// Check if an inbound packet should be allowed
    /// Returns the internal destination if allowed, nil if blocked
    public func filterInbound(
        from sourceEndpoint: String,
        to externalEndpoint: String
    ) -> String? {
        // Check if NAT is enabled
        guard isEnabled else {
            stats.inboundBlocked += 1
            return nil
        }

        // Public NAT allows everything
        if type == .public {
            stats.inboundAllowed += 1
            return externalEndpoint // No translation needed
        }

        // Find mapping for this external endpoint
        guard let mapping = findMappingByExternal(externalEndpoint) else {
            stats.inboundBlocked += 1
            return nil // No mapping, packet dropped
        }

        // Check if source is allowed based on NAT type
        switch type {
        case .fullCone:
            // Anyone can send to mapped port
            stats.inboundAllowed += 1
            return mapping.internalEndpoint

        case .restrictedCone:
            // Source IP must be in allowed list
            let sourceIP = sourceEndpoint.split(separator: ":").first.map(String.init) ?? sourceEndpoint
            if mapping.allowedDestinations.contains(sourceIP) {
                stats.inboundAllowed += 1
                return mapping.internalEndpoint
            }
            stats.inboundBlocked += 1
            return nil

        case .portRestrictedCone, .symmetric:
            // Source IP:port must be in allowed list
            if mapping.allowedDestinationPorts.contains(sourceEndpoint) {
                stats.inboundAllowed += 1
                return mapping.internalEndpoint
            }
            stats.inboundBlocked += 1
            return nil

        default:
            stats.inboundBlocked += 1
            return nil
        }
    }

    /// Find a mapping by its external endpoint
    private func findMappingByExternal(_ externalEndpoint: String) -> NATMapping? {
        for (_, mapping) in mappings {
            if mapping.externalEndpoint == externalEndpoint && !mapping.isExpired {
                return mapping
            }
        }
        return nil
    }

    // MARK: - Management

    /// Get the external endpoint for an internal endpoint (if mapped)
    public func getExternalEndpoint(for internalEndpoint: String) -> String? {
        for (_, mapping) in mappings {
            if mapping.internalEndpoint == internalEndpoint && !mapping.isExpired {
                return mapping.externalEndpoint
            }
        }
        return nil
    }

    /// Get all active mappings
    public func getMappings() -> [NATMapping] {
        Array(mappings.values.filter { !$0.isExpired })
    }

    /// Expire all mappings (simulates NAT timeout)
    public func expireAllMappings() {
        let expiredCount = mappings.count
        mappings.removeAll()
        stats.mappingsExpired += expiredCount
    }

    /// Clean up expired mappings
    public func cleanupExpired() {
        let before = mappings.count
        mappings = mappings.filter { !$0.value.isExpired }
        let after = mappings.count
        stats.mappingsExpired += (before - after)
    }

    // MARK: - Control Methods (for fault injection)

    /// Enable or disable the NAT
    public func setEnabled(_ enabled: Bool) {
        isEnabled = enabled
    }

    /// Check if NAT is enabled
    public func getEnabled() -> Bool {
        isEnabled
    }

    /// Expire a specific mapping by internal endpoint
    public func expireMapping(for internalEndpoint: String) {
        for (key, mapping) in mappings {
            if mapping.internalEndpoint == internalEndpoint {
                mappings.removeValue(forKey: key)
                stats.mappingsExpired += 1
            }
        }
    }

    /// Get NAT statistics
    public func getStats() -> NATStats {
        stats
    }

    /// Reset statistics
    public func resetStats() {
        stats = NATStats()
    }

    /// Get mapping count
    public func getMappingCount() -> Int {
        mappings.count
    }

    /// Get active mapping count (non-expired)
    public func getActiveMappingCount() -> Int {
        mappings.values.filter { !$0.isExpired }.count
    }

    // MARK: - Hairpin NAT

    /// Translate a hairpin packet (internal -> external -> internal on same NAT)
    /// This is for when a host behind the NAT tries to connect to another host
    /// behind the same NAT using the external address
    public func translateHairpin(
        from internalEndpoint: String,
        to externalEndpoint: String
    ) -> String? {
        guard config.supportsHairpin else {
            stats.packetsDropped += 1
            return nil
        }

        // Find the mapping for the target external endpoint
        guard let targetMapping = findMappingByExternal(externalEndpoint) else {
            stats.packetsDropped += 1
            return nil
        }

        // Return the internal endpoint of the target
        stats.packetsTranslated += 1
        return targetMapping.internalEndpoint
    }

    // MARK: - Port Prediction (for symmetric NAT testing)

    /// Predict the next external port (for hole punch testing with symmetric NAT)
    public func predictNextPort(for internalEndpoint: String, currentDestination: String) -> UInt16? {
        guard type == .symmetric else { return nil }

        // Get current mapping
        let key = mappingKey(internalEndpoint, destination: currentDestination)
        guard let currentMapping = mappings[key],
              let currentPort = currentMapping.externalEndpoint.split(separator: ":").last.flatMap({ UInt16($0) }) else {
            return nil
        }

        // If predictable delta is configured, use it
        if let delta = config.predictablePortDelta {
            return currentPort + delta
        }

        // Otherwise, based on allocation strategy
        switch portAllocation {
        case .sequential:
            return nextExternalPort
        case .random:
            return nil // Can't predict random
        case .preserving:
            return nil // Depends on internal port
        }
    }
}
