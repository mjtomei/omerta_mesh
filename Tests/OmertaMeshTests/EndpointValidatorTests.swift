// EndpointValidatorTests.swift - Tests for endpoint validation

import XCTest
@testable import OmertaMesh

final class EndpointValidatorTests: XCTestCase {

    // MARK: - Parsing Tests

    func testParseIPv4Endpoint() {
        let result = EndpointValidator.parse("192.168.1.1:8080")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.host, "192.168.1.1")
        XCTAssertEqual(result?.port, 8080)
    }

    func testParseIPv6Endpoint() {
        let result = EndpointValidator.parse("[::1]:8080")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.host, "::1")
        XCTAssertEqual(result?.port, 8080)
    }

    func testParseIPv6Full() {
        let result = EndpointValidator.parse("[2001:db8::1]:9000")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.host, "2001:db8::1")
        XCTAssertEqual(result?.port, 9000)
    }

    func testParseMalformedEndpoint() {
        XCTAssertNil(EndpointValidator.parse("invalid"))
        XCTAssertNil(EndpointValidator.parse("192.168.1.1"))
        XCTAssertNil(EndpointValidator.parse(":8080"))
        XCTAssertNil(EndpointValidator.parse("[::1]8080"))  // Missing colon
        XCTAssertNil(EndpointValidator.parse("192.168.1.1:abc"))
    }

    // MARK: - Localhost Detection Tests

    func testIsLocalhost_IPv4Loopback() {
        XCTAssertTrue(EndpointValidator.isLocalhost("127.0.0.1"))
        XCTAssertTrue(EndpointValidator.isLocalhost("127.0.0.0"))
        XCTAssertTrue(EndpointValidator.isLocalhost("127.255.255.255"))
        XCTAssertTrue(EndpointValidator.isLocalhost("127.1.2.3"))
    }

    func testIsLocalhost_IPv6Loopback() {
        XCTAssertTrue(EndpointValidator.isLocalhost("::1"))
        XCTAssertTrue(EndpointValidator.isLocalhost("0:0:0:0:0:0:0:1"))
    }

    func testIsLocalhost_Hostname() {
        XCTAssertTrue(EndpointValidator.isLocalhost("localhost"))
        XCTAssertTrue(EndpointValidator.isLocalhost("LOCALHOST"))
    }

    func testIsLocalhost_NotLocalhost() {
        XCTAssertFalse(EndpointValidator.isLocalhost("192.168.1.1"))
        XCTAssertFalse(EndpointValidator.isLocalhost("10.0.0.1"))
        XCTAssertFalse(EndpointValidator.isLocalhost("8.8.8.8"))
        XCTAssertFalse(EndpointValidator.isLocalhost("2001:db8::1"))
    }

    // MARK: - Private IP Detection Tests

    func testIsPrivateIP_10Network() {
        XCTAssertTrue(EndpointValidator.isPrivateIP("10.0.0.1"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("10.255.255.255"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("10.1.2.3"))
    }

    func testIsPrivateIP_172Network() {
        // 172.16.0.0 - 172.31.255.255
        XCTAssertTrue(EndpointValidator.isPrivateIP("172.16.0.1"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("172.31.255.255"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("172.20.1.1"))

        // Not in private range
        XCTAssertFalse(EndpointValidator.isPrivateIP("172.15.255.255"))
        XCTAssertFalse(EndpointValidator.isPrivateIP("172.32.0.0"))
    }

    func testIsPrivateIP_192168Network() {
        XCTAssertTrue(EndpointValidator.isPrivateIP("192.168.0.1"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("192.168.255.255"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("192.168.1.100"))
    }

    func testIsPrivateIP_LinkLocal() {
        XCTAssertTrue(EndpointValidator.isPrivateIP("169.254.0.1"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("169.254.255.255"))
    }

    func testIsPrivateIP_IPv6Private() {
        XCTAssertTrue(EndpointValidator.isPrivateIP("fd00::1"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("fd12:3456::1"))
        XCTAssertTrue(EndpointValidator.isPrivateIP("fe80::1"))
    }

    func testIsPrivateIP_PublicAddresses() {
        XCTAssertFalse(EndpointValidator.isPrivateIP("8.8.8.8"))
        XCTAssertFalse(EndpointValidator.isPrivateIP("1.1.1.1"))
        XCTAssertFalse(EndpointValidator.isPrivateIP("203.0.113.1"))
        XCTAssertFalse(EndpointValidator.isPrivateIP("2001:db8::1"))
    }

    // MARK: - Validation Mode Tests

    func testValidateStrictMode_RejectsLocalhost() {
        let result = EndpointValidator.validate("127.0.0.1:8080", mode: .strict)
        XCTAssertFalse(result.isValid)
        XCTAssertEqual(result.reason, "localhost not allowed")
    }

    func testValidateStrictMode_RejectsPrivateIP() {
        let result = EndpointValidator.validate("192.168.1.1:8080", mode: .strict)
        XCTAssertFalse(result.isValid)
        XCTAssertEqual(result.reason, "private IP not allowed in strict mode")
    }

    func testValidateStrictMode_AcceptsPublicIP() {
        let result = EndpointValidator.validate("8.8.8.8:8080", mode: .strict)
        XCTAssertTrue(result.isValid)
        XCTAssertNil(result.reason)
    }

    func testValidatePermissiveMode_RejectsLocalhost() {
        let result = EndpointValidator.validate("127.0.0.1:8080", mode: .permissive)
        XCTAssertFalse(result.isValid)
        XCTAssertEqual(result.reason, "localhost not allowed")
    }

    func testValidatePermissiveMode_AcceptsPrivateIP() {
        let result = EndpointValidator.validate("192.168.1.1:8080", mode: .permissive)
        XCTAssertTrue(result.isValid)
    }

    func testValidateAllowAllMode_AcceptsPrivateIP() {
        let result = EndpointValidator.validate("192.168.1.1:8080", mode: .allowAll)
        XCTAssertTrue(result.isValid)
    }

    func testValidateAllowAllMode_AcceptsLocalhost() {
        // allowAll mode accepts everything including localhost (for testing)
        let result = EndpointValidator.validate("127.0.0.1:8080", mode: .allowAll)
        XCTAssertTrue(result.isValid)
    }

    func testValidateAllowAllMode_RejectsMalformed() {
        let result = EndpointValidator.validate("invalid", mode: .allowAll)
        XCTAssertFalse(result.isValid)
        XCTAssertEqual(result.reason, "malformed endpoint")
    }

    func testValidate_InvalidPort() {
        let result = EndpointValidator.validate("8.8.8.8:0", mode: .strict)
        XCTAssertFalse(result.isValid)
        XCTAssertEqual(result.reason, "invalid port")
    }

    // MARK: - Filter Tests

    func testFilterValid_StrictMode() {
        let endpoints = [
            "8.8.8.8:8080",       // Valid public
            "127.0.0.1:8080",     // Localhost
            "192.168.1.1:8080",   // Private
            "1.1.1.1:443",        // Valid public
            "invalid",            // Malformed
        ]

        let filtered = EndpointValidator.filterValid(endpoints, mode: .strict)
        XCTAssertEqual(filtered, ["8.8.8.8:8080", "1.1.1.1:443"])
    }

    func testFilterValid_PermissiveMode() {
        let endpoints = [
            "8.8.8.8:8080",       // Valid public
            "127.0.0.1:8080",     // Localhost (rejected)
            "192.168.1.1:8080",   // Private (allowed in permissive)
            "10.0.0.1:9000",      // Private (allowed)
        ]

        let filtered = EndpointValidator.filterValid(endpoints, mode: .permissive)
        XCTAssertEqual(filtered, ["8.8.8.8:8080", "192.168.1.1:8080", "10.0.0.1:9000"])
    }

    // MARK: - isValid Convenience Tests

    func testIsValid() {
        XCTAssertTrue(EndpointValidator.isValid("8.8.8.8:8080", mode: .strict))
        XCTAssertFalse(EndpointValidator.isValid("127.0.0.1:8080", mode: .strict))
    }
}
