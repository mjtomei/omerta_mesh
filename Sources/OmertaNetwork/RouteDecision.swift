// RouteDecision.swift - Routing decisions for virtual network packets

import OmertaMesh

/// Routing decision for a packet based on its destination IP
public enum RouteDecision: Equatable, Sendable {
    /// Packet is destined for the local machine
    case local
    /// Packet should be sent to a specific peer via tunnel
    case peer(MachineId)
    /// Packet should be sent to the gateway for internet access
    case gateway
    /// Packet should be dropped with a reason
    case drop(String)
}
