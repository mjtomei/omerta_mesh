// SignatureProcessPoolTests.swift - Tests for Ed25519 signature process pool

import XCTest
import Crypto
@testable import OmertaMesh

#if os(Linux)

final class SignatureProcessPoolTests: XCTestCase {

    var pool: SignatureProcessPool!

    override func setUp() async throws {
        pool = try SignatureProcessPool(workerCount: 2, slotCount: 8)
    }

    override func tearDown() async throws {
        pool?.shutdown()
        pool = nil
    }

    // MARK: - Valid Signature Verifies True

    func testValidSignatureVerifies() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let data = Data("Sign this message".utf8)
        let signature = try privateKey.signature(for: data)

        let result = try await pool.verify(
            data: data,
            signature: signature,
            publicKey: publicKey.rawRepresentation
        )

        XCTAssertTrue(result)
    }

    // MARK: - Invalid Signature Verifies False

    func testInvalidSignatureVerifiesFalse() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let data = Data("Sign this message".utf8)
        let signature = try privateKey.signature(for: data)

        // Tamper with the data
        let tamperedData = Data("Tampered message".utf8)

        let result = try await pool.verify(
            data: tamperedData,
            signature: signature,
            publicKey: publicKey.rawRepresentation
        )

        XCTAssertFalse(result)
    }

    // MARK: - Sign and Verify Round-Trip

    func testSignAndVerifyRoundTrip() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let data = Data("Round-trip test data".utf8)

        // Sign via pool
        let signature = try await pool.sign(
            data: data,
            privateKey: privateKey.rawRepresentation
        )

        XCTAssertEqual(signature.count, 64)

        // Verify via pool
        let result = try await pool.verify(
            data: data,
            signature: signature,
            publicKey: publicKey.rawRepresentation
        )

        XCTAssertTrue(result)
    }

    // MARK: - Concurrent Verifications

    func testConcurrentVerifications() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        try await withThrowingTaskGroup(of: Bool.self) { group in
            for i in 0..<10 {
                let data = Data("Message \(i)".utf8)
                let signature = try privateKey.signature(for: data)

                group.addTask {
                    try await self.pool.verify(
                        data: data,
                        signature: signature,
                        publicKey: publicKey.rawRepresentation
                    )
                }
            }

            for try await result in group {
                XCTAssertTrue(result)
            }
        }
    }

    // MARK: - Wrong Key Returns False

    func testWrongKeyReturnsFalse() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let wrongKey = Curve25519.Signing.PrivateKey().publicKey
        let data = Data("Test data".utf8)
        let signature = try privateKey.signature(for: data)

        let result = try await pool.verify(
            data: data,
            signature: signature,
            publicKey: wrongKey.rawRepresentation
        )

        XCTAssertFalse(result)
    }

    // MARK: - Pool Signature Matches Inline

    func testPoolSignatureMatchesInlineVerification() async throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let data = Data("Cross-verification test".utf8)

        // Sign via pool
        let poolSignature = try await pool.sign(
            data: data,
            privateKey: privateKey.rawRepresentation
        )

        // Verify inline (not via pool)
        let isValid = publicKey.isValidSignature(poolSignature, for: data)
        XCTAssertTrue(isValid, "Pool-generated signature must be verifiable inline")
    }
}

#endif // os(Linux)
