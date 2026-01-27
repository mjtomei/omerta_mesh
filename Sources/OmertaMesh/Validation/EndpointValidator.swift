// EndpointValidator.swift - Validation for network endpoints

import Foundation

/// Validates network endpoints (ip:port format)
/// Used to filter invalid endpoints like localhost, private IPs, and malformed addresses
public struct EndpointValidator: Sendable {

    /// Validation mode for endpoint filtering
    public enum ValidationMode: Sendable {
        /// Reject localhost and private IPs (production mode)
        case strict
        /// Allow private IPs but reject localhost (LAN testing)
        case permissive
        /// Allow everything except malformed endpoints
        case allowAll
    }

    /// Result of endpoint validation
    public struct ValidationResult: Sendable {
        public let isValid: Bool
        public let reason: String?

        public static func valid() -> ValidationResult {
            ValidationResult(isValid: true, reason: nil)
        }

        public static func invalid(_ reason: String) -> ValidationResult {
            ValidationResult(isValid: false, reason: reason)
        }
    }

    // MARK: - Public API

    /// Validate an endpoint string
    /// - Parameters:
    ///   - endpoint: Endpoint in "ip:port" or "[ipv6]:port" format
    ///   - mode: Validation strictness
    /// - Returns: Validation result
    public static func validate(_ endpoint: String, mode: ValidationMode = .strict) -> ValidationResult {
        // Parse endpoint
        guard let (host, port) = parse(endpoint) else {
            return .invalid("malformed endpoint")
        }

        // Validate port
        guard port > 0 && port <= 65535 else {
            return .invalid("invalid port")
        }

        // In allowAll mode, accept anything that parses correctly
        if mode == .allowAll {
            return .valid()
        }

        // Check localhost (rejected in strict and permissive modes)
        if isLocalhost(host) {
            return .invalid("localhost not allowed")
        }

        // Check private IPs (rejected only in strict mode)
        if mode == .strict && isPrivateIP(host) {
            return .invalid("private IP not allowed in strict mode")
        }

        return .valid()
    }

    /// Check if an IP address is localhost/loopback
    /// - Parameter ip: IP address string
    /// - Returns: true if localhost
    public static func isLocalhost(_ ip: String) -> Bool {
        // IPv4 loopback: 127.0.0.0/8
        if ip.hasPrefix("127.") {
            return true
        }

        // IPv6 loopback
        let normalized = ip.lowercased()
        if normalized == "::1" || normalized == "0:0:0:0:0:0:0:1" {
            return true
        }

        // localhost hostname
        if normalized == "localhost" {
            return true
        }

        return false
    }

    /// Check if an IP address is in a private range
    /// - Parameter ip: IP address string
    /// - Returns: true if private IP
    public static func isPrivateIP(_ ip: String) -> Bool {
        // Parse IPv4
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        if parts.count == 4 {
            let (a, b, _, _) = (parts[0], parts[1], parts[2], parts[3])

            // 10.0.0.0/8
            if a == 10 {
                return true
            }

            // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
            if a == 172 && b >= 16 && b <= 31 {
                return true
            }

            // 192.168.0.0/16
            if a == 192 && b == 168 {
                return true
            }

            // 169.254.0.0/16 (link-local)
            if a == 169 && b == 254 {
                return true
            }
        }

        // IPv6 private ranges
        let normalized = ip.lowercased()

        // fd00::/8 - Unique local addresses
        if normalized.hasPrefix("fd") {
            return true
        }

        // fe80::/10 - Link-local
        if normalized.hasPrefix("fe80:") {
            return true
        }

        return false
    }

    /// Filter a list of endpoints, returning only valid ones
    /// - Parameters:
    ///   - endpoints: List of endpoint strings
    ///   - mode: Validation strictness
    /// - Returns: Filtered list of valid endpoints
    public static func filterValid(_ endpoints: [String], mode: ValidationMode = .strict) -> [String] {
        endpoints.filter { validate($0, mode: mode).isValid }
    }

    /// Parse an endpoint string into host and port
    /// - Parameter endpoint: Endpoint string (ip:port or [ipv6]:port)
    /// - Returns: Tuple of (host, port) or nil if malformed
    public static func parse(_ endpoint: String) -> (host: String, port: UInt16)? {
        // Handle IPv6 format: [::1]:port
        if endpoint.hasPrefix("[") {
            guard let closeBracket = endpoint.firstIndex(of: "]") else {
                return nil
            }

            let hostStart = endpoint.index(after: endpoint.startIndex)
            let host = String(endpoint[hostStart..<closeBracket])

            // Expect :port after ]
            let afterBracket = endpoint.index(after: closeBracket)
            guard afterBracket < endpoint.endIndex,
                  endpoint[afterBracket] == ":" else {
                return nil
            }

            let portStart = endpoint.index(after: afterBracket)
            guard let port = UInt16(endpoint[portStart...]) else {
                return nil
            }

            return (host, port)
        }

        // Handle IPv4 format: ip:port
        let parts = endpoint.split(separator: ":")
        guard parts.count == 2,
              let port = UInt16(parts[1]) else {
            return nil
        }

        return (String(parts[0]), port)
    }

    /// Check if an endpoint is valid for the given mode
    /// - Parameters:
    ///   - endpoint: Endpoint string
    ///   - mode: Validation mode
    /// - Returns: true if valid
    public static func isValid(_ endpoint: String, mode: ValidationMode = .strict) -> Bool {
        validate(endpoint, mode: mode).isValid
    }
}
