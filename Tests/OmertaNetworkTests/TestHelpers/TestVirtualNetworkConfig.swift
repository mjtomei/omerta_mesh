// TestVirtualNetworkConfig.swift - Test-only convenience for VirtualNetworkConfig
import OmertaNetwork

extension VirtualNetworkConfig {
    /// Fixed config for unit tests. NOT for production use — use autoDetect() instead.
    static let testDefault = VirtualNetworkConfig(
        subnet: "10.0.0.0", netmask: "255.255.0.0", prefixLength: 16,
        gatewayIP: "10.0.0.1", poolStart: "10.0.0.100", poolEnd: "10.0.255.254"
    )
}
