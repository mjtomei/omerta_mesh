// EndpointUtils.swift - Endpoint utilities for IPv4/IPv6 prioritization
//
// Endpoints are stored as-is (IPv4 or IPv6 format). When selecting which
// endpoint to use, IPv6 is preferred. The dual-stack socket handles both.

import Foundation

/// Utilities for working with endpoints and prioritizing IPv6
public enum EndpointUtils {

    // MARK: - Detection

    /// Check if an endpoint is IPv6
    /// Handles: [::1]:5000, ::1:5000 (if parseable)
    public static func isIPv6(_ endpoint: String) -> Bool {
        // Bracket notation is definitely IPv6
        if endpoint.hasPrefix("[") {
            return true
        }

        // Check if it's an IPv6 address (contains multiple colons)
        // IPv4 has format x.x.x.x:port (one colon)
        // IPv6 has format x:x:x:x:x:x:x:x:port (multiple colons)
        let colonCount = endpoint.filter { $0 == ":" }.count
        return colonCount > 1
    }

    /// Check if an endpoint is IPv4
    public static func isIPv4(_ endpoint: String) -> Bool {
        !isIPv6(endpoint)
    }

    // MARK: - Sorting

    /// Sort endpoints with IPv6 first
    public static func sortPreferringIPv6(_ endpoints: [String]) -> [String] {
        endpoints.sorted { a, b in
            let aIsIPv6 = isIPv6(a)
            let bIsIPv6 = isIPv6(b)
            if aIsIPv6 != bIsIPv6 {
                return aIsIPv6  // IPv6 comes first
            }
            return a < b  // Stable sort within same type
        }
    }

    /// Get the preferred endpoint (IPv6 if available)
    public static func preferredEndpoint(from endpoints: [String]) -> String? {
        // Return first IPv6, or first IPv4 if no IPv6
        endpoints.first { isIPv6($0) } ?? endpoints.first
    }

    // MARK: - Address Validation

    /// Check if a string is a valid IPv4 address (not endpoint)
    public static func isIPv4Address(_ string: String) -> Bool {
        var addr = in_addr()
        return inet_pton(AF_INET, string, &addr) == 1
    }

    /// Check if a string is a valid IPv6 address (not endpoint)
    public static func isIPv6Address(_ string: String) -> Bool {
        var addr = in6_addr()
        return inet_pton(AF_INET6, string, &addr) == 1
    }

    // MARK: - Local Address Discovery

    /// Get all local IPv6 addresses (global unicast, not link-local)
    /// Returns addresses suitable for external connectivity
    public static func getLocalIPv6Addresses() -> [String] {
        var addresses: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?

        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return addresses
        }

        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let addr = ptr {
            defer { ptr = addr.pointee.ifa_next }

            // Check for IPv6
            guard addr.pointee.ifa_addr?.pointee.sa_family == sa_family_t(AF_INET6) else {
                continue
            }

            // Get the address
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(
                addr.pointee.ifa_addr,
                socklen_t(MemoryLayout<sockaddr_in6>.size),
                &hostname,
                socklen_t(hostname.count),
                nil,
                0,
                NI_NUMERICHOST
            )

            guard result == 0 else { continue }

            let address = String(cString: hostname)

            // Skip link-local (fe80::) and loopback (::1)
            if address.hasPrefix("fe80:") || address == "::1" {
                continue
            }

            // Remove zone ID suffix if present (e.g., %en0)
            let cleanAddress = address.split(separator: "%").first.map(String.init) ?? address

            addresses.append(cleanAddress)
        }

        return addresses
    }

    /// Get the best local IPv6 address for external connectivity
    /// Returns nil if no suitable IPv6 address is found
    public static func getBestLocalIPv6Address() -> String? {
        let addresses = getLocalIPv6Addresses()

        // Prefer global unicast (2000::/3) over unique local (fc00::/7)
        // Global addresses start with 2 or 3
        if let global = addresses.first(where: { $0.hasPrefix("2") || $0.hasPrefix("3") }) {
            return global
        }

        // Fall back to any non-link-local address
        return addresses.first
    }
}
