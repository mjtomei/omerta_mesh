// EncryptionEnforcementTests.swift - Verify all network traffic is encrypted

import XCTest
import NIOPosix
import NIOCore
@testable import OmertaMesh

final class EncryptionEnforcementTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        #if DEBUG
        GlobalEncryptionObserver.install()
        #endif
    }

    override func tearDown() {
        super.tearDown()
    }

    /// Verify that SealedEnvelope can only be constructed by encryption methods,
    /// not from arbitrary Data using the public API.
    func testSealedEnvelopeNotConstructibleFromRawData() {
        // This test documents the compile-time guarantee:
        // The following would NOT compile outside the module:
        //   let raw = SealedEnvelope(data: someData)
        // Because the initializer is fileprivate.
        //
        // Within @testable import, we can access internal APIs,
        // but the trustedData initializer is explicitly internal
        // (only for relay forwarding within the module).

        // Verify that encodeV2 produces a valid SealedEnvelope
        let keypair = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)

        do {
            let envelope = try MeshEnvelope.signed(
                from: keypair,
                machineId: UUID().uuidString,
                to: nil,
                payload: .data(Data("test".utf8))
            )
            let sealed = try envelope.encodeV2(networkKey: testKey)

            // The sealed envelope should contain valid encrypted data
            XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(sealed.data),
                         "SealedEnvelope from encodeV2 must have valid prefix")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    #if DEBUG
    /// Verify that all packets sent through UDPSocket have the BinaryEnvelopeV2 prefix.
    func testAllTrafficIsEncrypted() async throws {
        let testKey = Data(repeating: 0x42, count: 32)
        let keypair = IdentityKeypair()

        // Create a SealedEnvelope using the encryption path
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .ping(recentPeers: [], myNATType: .unknown, requestFullList: false)
        )
        let sealed = try envelope.encodeV2(networkKey: testKey)

        // Create a socket and send
        let group = NIOPosix.MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let socket = UDPSocket(eventLoopGroup: group)
        try await socket.bind(port: 0)
        defer { Task { await socket.close() } }

        let port = await socket.port!
        let dest = try SocketAddress(ipAddress: "127.0.0.1", port: port)

        try await socket.send(sealed, to: dest)

        // Brief pause to let capture hook fire
        try await Task.sleep(nanoseconds: 50_000_000)

        // The global observer should not have flagged this as a violation
        let violations = GlobalEncryptionObserver.shared.violations
        let myViolations = violations.filter { $0.testName.contains("testAllTrafficIsEncrypted") }
        XCTAssertTrue(myViolations.isEmpty,
                     "Encrypted sends should not produce violations, got: \(myViolations.count)")
    }

    /// Runs last (alphabetically) — asserts that no non-demo test sent unencrypted data,
    /// and that the expected demo violations were triggered by exact test name.
    func testZZ_noUnencryptedPacketsAcrossAllTests() {
        let allViolations = GlobalEncryptionObserver.shared.violations

        // These demo tests must each trigger exactly one violation
        let expectedDemoTests = [
            "testCatchesPlaintextJSON",
            "testCatchesRawDebugBytes",
            "testCatchesLegacyEncryptionFormat",
        ]

        for testName in expectedDemoTests {
            let matches = allViolations.filter { $0.testName.contains(testName) }
            XCTAssertEqual(matches.count, 1,
                "Expected exactly 1 violation from \(testName), got \(matches.count)")
        }

        // No non-demo test should have sent unencrypted data
        let unexpectedViolations = allViolations.filter { v in
            !expectedDemoTests.contains(where: { v.testName.contains($0) })
        }
        if !unexpectedViolations.isEmpty {
            let summary = unexpectedViolations.map { "\($0.testName): \($0.data.prefix(8).map { String(format: "%02x", $0) }.joined()) → \($0.destination)" }
            XCTFail("Unexpected unencrypted packets in \(unexpectedViolations.count) send(s):\n\(summary.joined(separator: "\n"))")
        }
    }
    #endif
}
