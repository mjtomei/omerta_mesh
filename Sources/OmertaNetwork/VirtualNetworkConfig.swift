// VirtualNetworkConfig.swift - Configuration for virtual network

/// Configuration for the virtual network subnet and gateway
public struct VirtualNetworkConfig: Sendable {
    /// Subnet base address
    public var subnet: String = "10.0.0.0"
    /// Subnet mask
    public var netmask: String = "255.255.0.0"
    /// Default gateway IP within the subnet
    public var gatewayIP: String = "10.0.0.1"

    public static let `default` = VirtualNetworkConfig()

    public init(subnet: String = "10.0.0.0", netmask: String = "255.255.0.0", gatewayIP: String = "10.0.0.1") {
        self.subnet = subnet
        self.netmask = netmask
        self.gatewayIP = gatewayIP
    }
}
