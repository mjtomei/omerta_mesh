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

    /// Dynamically generate a non-conflicting config at startup.
    /// Uses SubnetSelector to find a /16 that doesn't conflict with local interfaces.
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

    /// Generate an internal IP for a netstack instance within this subnet.
    /// Uses the third-octet offset (e.g. offset 200 yields X.Y.200.1).
    /// Returns nil if the subnet address cannot be parsed.
    public func internalIP(thirdOctet: UInt8 = 200, hostOctet: UInt8 = 1) -> String? {
        guard let addr = SubnetSelector.parseIPv4(subnet) else { return nil }
        let a = (addr >> 24) & 0xFF
        let b = (addr >> 16) & 0xFF
        return "\(a).\(b).\(thirdOctet).\(hostOctet)"
    }

    public init(subnet: String, netmask: String, prefixLength: Int,
                gatewayIP: String, poolStart: String, poolEnd: String) {
        self.subnet = subnet
        self.netmask = netmask
        self.prefixLength = prefixLength
        self.gatewayIP = gatewayIP
        self.poolStart = poolStart
        self.poolEnd = poolEnd
    }
}
