// HolePunchStrategySelector.swift - Strategy selection based on NAT types

import Foundation

/// Extension to add strategy selection to HolePunchStrategy
extension HolePunchStrategy {
    /// Select the appropriate hole punch strategy based on NAT types
    /// - Parameters:
    ///   - initiator: NAT type of the peer initiating the connection
    ///   - responder: NAT type of the peer receiving the connection request
    /// - Returns: The recommended strategy
    public static func select(initiator: NATType, responder: NATType) -> HolePunchStrategy {
        // Both public or full cone - can connect directly, no hole punching needed
        if initiator.isDirectlyReachable && responder.isDirectlyReachable {
            return .simultaneous
        }

        // Both symmetric - hole punching impossible
        if initiator == .symmetric && responder == .symmetric {
            return .impossible
        }

        // One symmetric, one cone-type - symmetric sends first
        if initiator == .symmetric && responder.isConeType {
            return .initiatorFirst
        }
        if responder == .symmetric && initiator.isConeType {
            return .responderFirst
        }

        // Both cone types - simultaneous works
        if initiator.isConeType && responder.isConeType {
            return .simultaneous
        }

        // Unknown NAT types - try simultaneous as fallback
        if initiator == .unknown || responder == .unknown {
            return .simultaneous
        }

        // Default to simultaneous
        return .simultaneous
    }

    /// Check if this strategy can succeed
    public var canSucceed: Bool {
        self != .impossible
    }

    /// Human-readable description of what this strategy does
    public var explanation: String {
        switch self {
        case .simultaneous:
            return "Both peers send probes at coordinated time"
        case .initiatorFirst:
            return "Initiator sends first to create NAT mapping, then responder connects"
        case .responderFirst:
            return "Responder sends first to create NAT mapping, then initiator connects"
        case .impossible:
            return "Hole punching not possible (both symmetric NAT)"
        }
    }
}

/// Extension to NATType for hole punch compatibility checks
extension NATType {
    /// Whether this NAT type allows direct incoming connections
    public var isDirectlyReachable: Bool {
        switch self {
        case .public, .fullCone:
            return true
        default:
            return false
        }
    }

    /// Whether this is a cone-type NAT (can be hole punched)
    public var isConeType: Bool {
        switch self {
        case .fullCone, .restrictedCone, .portRestrictedCone:
            return true
        default:
            return false
        }
    }

    /// Whether hole punching is possible with this NAT type
    public var canHolePunch: Bool {
        switch self {
        case .public, .fullCone, .restrictedCone, .portRestrictedCone:
            return true
        case .symmetric, .unknown:
            return false
        }
    }

    /// Difficulty level for hole punching (higher = harder)
    public var holePunchDifficulty: Int {
        switch self {
        case .public:
            return 0
        case .fullCone:
            return 1
        case .restrictedCone:
            return 2
        case .portRestrictedCone:
            return 3
        case .symmetric:
            return 10  // Very difficult, usually fails
        case .unknown:
            return 5
        }
    }
}

/// Result of hole punch compatibility check
public struct HolePunchCompatibility: Sendable {
    /// The recommended strategy
    public let strategy: HolePunchStrategy

    /// Whether hole punching is likely to succeed
    public let likely: Bool

    /// Estimated difficulty (0-10)
    public let difficulty: Int

    /// Recommendation message
    public let recommendation: String

    /// Check compatibility between two NAT types
    public static func check(initiator: NATType, responder: NATType) -> HolePunchCompatibility {
        let strategy = HolePunchStrategy.select(initiator: initiator, responder: responder)
        let difficulty = max(initiator.holePunchDifficulty, responder.holePunchDifficulty)

        let likely: Bool
        let recommendation: String

        switch strategy {
        case .impossible:
            likely = false
            recommendation = "Use relay - both peers have symmetric NAT"

        case .simultaneous:
            if initiator.isDirectlyReachable || responder.isDirectlyReachable {
                likely = true
                recommendation = "Direct connection should work"
            } else {
                likely = difficulty <= 3
                recommendation = "Simultaneous hole punch recommended"
            }

        case .initiatorFirst:
            likely = difficulty <= 5
            recommendation = "Initiator should send first due to symmetric NAT"

        case .responderFirst:
            likely = difficulty <= 5
            recommendation = "Responder should send first due to symmetric NAT"
        }

        return HolePunchCompatibility(
            strategy: strategy,
            likely: likely,
            difficulty: difficulty,
            recommendation: recommendation
        )
    }
}
