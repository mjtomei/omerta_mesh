// VirtualNetworkConfig.swift - Configuration for virtual network

/// Configuration for the virtual network subnet and gateway
public struct VirtualNetworkConfig: Sendable {
    /// Subnet base address
    public var subnet: String
    /// Subnet mask
    public var netmask: String
    /// CIDR prefix length
    public var prefixLength: Int
    /// Default gateway IP within the subnet
    public var gatewayIP: String
    /// First IP in the DHCP pool
    public var poolStart: String
    /// Last IP in the DHCP pool
    public var poolEnd: String

    public static let `default` = VirtualNetworkConfig(
        subnet: "10.0.0.0", netmask: "255.255.0.0", prefixLength: 16,
        gatewayIP: "10.0.0.1", poolStart: "10.0.0.100", poolEnd: "10.0.255.254"
    )

    /// Dynamically generate a non-conflicting config at startup
    public static func autoDetect() throws -> VirtualNetworkConfig {
        let generated = try SubnetSelector.generateSubnet()
        return VirtualNetworkConfig(generated: generated)
    }

    public init(generated: GeneratedSubnet) {
        self.subnet = generated.subnet
        self.netmask = generated.netmask
        self.prefixLength = generated.prefixLength
        self.gatewayIP = generated.gatewayIP
        self.poolStart = generated.poolStart
        self.poolEnd = generated.poolEnd
    }

    public init(subnet: String = "10.0.0.0", netmask: String = "255.255.0.0",
                prefixLength: Int = 16, gatewayIP: String = "10.0.0.1",
                poolStart: String = "10.0.0.100", poolEnd: String = "10.0.255.254") {
        self.subnet = subnet
        self.netmask = netmask
        self.prefixLength = prefixLength
        self.gatewayIP = gatewayIP
        self.poolStart = poolStart
        self.poolEnd = poolEnd
    }
}
