// SubnetSelector.swift - LAN-aware subnet generation
//
// Detects local network interfaces and generates a non-colliding /16 subnet
// from RFC 1918 private address space. Similar to how Docker generates
// bridge subnets dynamically.

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

import Foundation

/// A generated subnet that avoids collisions with local LAN networks.
public struct GeneratedSubnet: Sendable, Equatable {
    /// Subnet base address, e.g. "10.42.0.0"
    public let subnet: String
    /// CIDR prefix length, e.g. 16
    public let prefixLength: Int
    /// Netmask string, e.g. "255.255.0.0"
    public let netmask: String
    /// Gateway IP within the subnet, e.g. "10.42.0.1"
    public let gatewayIP: String
    /// First IP in the DHCP pool, e.g. "10.42.0.100"
    public let poolStart: String
    /// Last IP in the DHCP pool, e.g. "10.42.255.254"
    public let poolEnd: String

    public init(subnet: String, prefixLength: Int, netmask: String,
                gatewayIP: String, poolStart: String, poolEnd: String) {
        self.subnet = subnet
        self.prefixLength = prefixLength
        self.netmask = netmask
        self.gatewayIP = gatewayIP
        self.poolStart = poolStart
        self.poolEnd = poolEnd
    }
}

/// Detects LAN conflicts and dynamically generates a non-colliding /16 subnet
/// from RFC 1918 private address space.
///
/// Strategy: randomly pick a subnet from the 10.x.0.0/16 range (256
/// possible /16 blocks in 10.0.0.0/8) and check against local interfaces.
/// Falls back to 172.16-31.0.0/16 (16 blocks) if all 10.x collide.
public struct SubnetSelector {

    /// Information about a local subnet detected on a host interface
    public struct SubnetInfo: Sendable, Equatable {
        /// Interface address string
        public let address: String
        /// CIDR prefix length
        public let prefixLength: Int
        /// Network address as UInt32 for fast bitwise comparison
        public let networkAddress: UInt32

        public init(address: String, prefixLength: Int, networkAddress: UInt32) {
            self.address = address
            self.prefixLength = prefixLength
            self.networkAddress = networkAddress
        }
    }

    /// Returns the list of subnets currently in use on local interfaces.
    /// Uses `getifaddrs()` on POSIX to enumerate all interface addresses.
    public static func detectLocalSubnets() -> [SubnetInfo] {
        var results: [SubnetInfo] = []

        #if canImport(Darwin) || canImport(Glibc)
        var ifaddrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrs) == 0, let firstAddr = ifaddrs else {
            return results
        }
        defer { freeifaddrs(ifaddrs) }

        var current: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let ifa = current {
            defer { current = ifa.pointee.ifa_next }

            guard let addr = ifa.pointee.ifa_addr,
                  addr.pointee.sa_family == UInt8(AF_INET),
                  let netmask = ifa.pointee.ifa_netmask else {
                continue
            }

            let ipAddr = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            let mask = netmask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }

            // Network byte order (big-endian) to host
            let ipHost = UInt32(bigEndian: ipAddr)
            let maskHost = UInt32(bigEndian: mask)
            let networkAddr = ipHost & maskHost

            let prefixLength = maskHost.nonzeroBitCount

            let addrString = ipv4String(ipHost)
            results.append(SubnetInfo(
                address: addrString,
                prefixLength: prefixLength,
                networkAddress: networkAddr
            ))
        }
        #endif

        return results
    }

    /// Dynamically generates a /16 subnet that does not collide with any
    /// locally detected network. Tries random 10.x.0.0/16 first, then
    /// 172.(16-31).0.0/16 as fallback.
    public static func generateSubnet() throws -> GeneratedSubnet {
        let locals = detectLocalSubnets()
        return try generateSubnet(avoiding: locals)
    }

    /// Generate a subnet avoiding the given local subnets.
    /// Visible for testing.
    public static func generateSubnet(avoiding locals: [SubnetInfo]) throws -> GeneratedSubnet {
        // Try 10.x.0.0/16 — shuffle to randomize
        var tenRange = Array(0..<256)
        tenRange.shuffle()

        for x in tenRange {
            let networkAddr = UInt32(0x0A000000) | (UInt32(x) << 16)  // 10.x.0.0
            if !conflicts(subnet: networkAddr, prefixLength: 16, with: locals) {
                return makeSubnet(networkAddr: networkAddr, prefixLength: 16)
            }
        }

        // Fallback: 172.(16-31).0.0/16
        var oneSeventyTwoRange = Array(16..<32)
        oneSeventyTwoRange.shuffle()

        for x in oneSeventyTwoRange {
            let networkAddr = UInt32(0xAC000000) | (UInt32(x) << 16)  // 172.x.0.0
            if !conflicts(subnet: networkAddr, prefixLength: 16, with: locals) {
                return makeSubnet(networkAddr: networkAddr, prefixLength: 16)
            }
        }

        throw SubnetSelectorError.noAvailableSubnet
    }

    /// Check if a specific CIDR overlaps with any local subnet.
    public static func conflicts(subnet: UInt32, prefixLength: Int,
                                  with locals: [SubnetInfo]) -> Bool {
        for local in locals {
            if cidrsOverlap(
                net1: subnet, prefix1: prefixLength,
                net2: local.networkAddress, prefix2: local.prefixLength
            ) {
                return true
            }
        }
        return false
    }

    // MARK: - Internal helpers

    static func cidrsOverlap(net1: UInt32, prefix1: Int, net2: UInt32, prefix2: Int) -> Bool {
        // Use the shorter (wider) prefix to compare
        let shorter = min(prefix1, prefix2)
        guard shorter > 0 else { return true }  // /0 overlaps everything
        let mask = UInt32.max << (32 - shorter)
        return (net1 & mask) == (net2 & mask)
    }

    static func makeSubnet(networkAddr: UInt32, prefixLength: Int) -> GeneratedSubnet {
        let subnet = ipv4String(networkAddr)
        let netmask = ipv4String(UInt32.max << (32 - prefixLength))
        let gatewayIP = ipv4String(networkAddr | 1)
        let poolStart = ipv4String(networkAddr | 100)
        let poolEnd = ipv4String(networkAddr | 0x0000FFFE)  // x.x.255.254

        return GeneratedSubnet(
            subnet: subnet,
            prefixLength: prefixLength,
            netmask: netmask,
            gatewayIP: gatewayIP,
            poolStart: poolStart,
            poolEnd: poolEnd
        )
    }

    static func ipv4String(_ addr: UInt32) -> String {
        let a = (addr >> 24) & 0xFF
        let b = (addr >> 16) & 0xFF
        let c = (addr >> 8) & 0xFF
        let d = addr & 0xFF
        return "\(a).\(b).\(c).\(d)"
    }

    /// Parse an IPv4 string to UInt32 (host byte order)
    public static func parseIPv4(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        return (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16) |
               (UInt32(parts[2]) << 8) | UInt32(parts[3])
    }
}

public enum SubnetSelectorError: Error, LocalizedError {
    case noAvailableSubnet

    public var errorDescription: String? {
        switch self {
        case .noAvailableSubnet:
            return "No available non-conflicting subnet found"
        }
    }
}
