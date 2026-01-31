// DirectCryptoTests.swift - Tests for DirectCrypto BoringSSL AEAD API

import XCTest
import Crypto
@testable import OmertaMesh

final class DirectCryptoTests: XCTestCase {

    let testKey: [UInt8] = (0..<32).map { UInt8($0) }
    let testNonce: [UInt8] = (0..<12).map { UInt8($0) }

    // MARK: - Basic Round Trip

    func testSealOpenRoundTrip() throws {
        let plaintext: [UInt8] = [UInt8]("Hello, DirectCrypto!".utf8)
        let (ciphertext, tag) = try DirectCrypto.seal(plaintext: plaintext, key: testKey, nonce: testNonce)
        let decrypted = try DirectCrypto.open(ciphertext: ciphertext, tag: tag, key: testKey, nonce: testNonce)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testCombinedFormatRoundTrip() throws {
        let plaintext: [UInt8] = [UInt8]("Combined format test".utf8)
        let combined = try DirectCrypto.sealCombined(plaintext, key: testKey)
        let decrypted = try DirectCrypto.openCombined(combined, key: testKey)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEmptyPlaintext() throws {
        let plaintext: [UInt8] = []
        let (ciphertext, tag) = try DirectCrypto.seal(plaintext: plaintext, key: testKey, nonce: testNonce)
        XCTAssertTrue(ciphertext.isEmpty)
        XCTAssertEqual(tag.count, 16)
        let decrypted = try DirectCrypto.open(ciphertext: ciphertext, tag: tag, key: testKey, nonce: testNonce)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEmptyPlaintextCombined() throws {
        let combined = try DirectCrypto.sealCombined([], key: testKey)
        // Combined = 12 (nonce) + 0 (ciphertext) + 16 (tag)
        XCTAssertEqual(combined.count, 28)
        let decrypted = try DirectCrypto.openCombined(combined, key: testKey)
        XCTAssertEqual(decrypted, [])
    }

    // MARK: - AEADContext Reuse

    func testAEADContextReuse() throws {
        let ctx = try AEADContext(key: testKey)
        let messages = ["first", "second", "third"].map { [UInt8]($0.utf8) }

        for msg in messages {
            let combined = try ctx.sealCombined(msg)
            let decrypted = try ctx.openCombined(combined)
            XCTAssertEqual(decrypted, msg)
        }
    }

    func testAEADContextSealWithExplicitNonce() throws {
        let ctx = try AEADContext(key: testKey)
        let plaintext: [UInt8] = [UInt8]("context test".utf8)
        let (ct, tag) = try ctx.seal(plaintext: plaintext, nonce: testNonce)
        let decrypted = try ctx.open(ciphertext: ct, tag: tag, nonce: testNonce)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Error Cases

    func testWrongKeyFails() throws {
        let plaintext: [UInt8] = [UInt8]("secret".utf8)
        let combined = try DirectCrypto.sealCombined(plaintext, key: testKey)

        let wrongKey: [UInt8] = (0..<32).map { UInt8($0 ^ 0xFF) }
        XCTAssertThrowsError(try DirectCrypto.openCombined(combined, key: wrongKey))
    }

    func testTamperedCiphertextFails() throws {
        let plaintext: [UInt8] = [UInt8]("tamper test".utf8)
        var combined = try DirectCrypto.sealCombined(plaintext, key: testKey)

        // Flip a bit in the ciphertext portion (after 12-byte nonce)
        if combined.count > 12 {
            combined[12] ^= 0x01
        }
        XCTAssertThrowsError(try DirectCrypto.openCombined(combined, key: testKey))
    }

    func testTamperedTagFails() throws {
        let plaintext: [UInt8] = [UInt8]("tag test".utf8)
        var combined = try DirectCrypto.sealCombined(plaintext, key: testKey)

        // Flip a bit in the last byte (tag)
        combined[combined.count - 1] ^= 0x01
        XCTAssertThrowsError(try DirectCrypto.openCombined(combined, key: testKey))
    }

    func testInvalidKeySize() throws {
        let shortKey: [UInt8] = [1, 2, 3]
        XCTAssertThrowsError(try AEADContext(key: shortKey)) { error in
            XCTAssertEqual(error as? DirectCryptoError, .invalidKeySize)
        }
    }

    func testInvalidNonceSize() throws {
        let ctx = try AEADContext(key: testKey)
        let badNonce: [UInt8] = [1, 2, 3] // too short
        XCTAssertThrowsError(try ctx.seal(plaintext: [0], nonce: badNonce)) { error in
            XCTAssertEqual(error as? DirectCryptoError, .invalidNonceSize)
        }
    }

    // MARK: - Cross-compatibility with ChaChaPoly (swift-crypto)

    func testDirectMatchesChaChaPoly() throws {
        let plaintext = Data("cross-compat test".utf8)
        let key = SymmetricKey(data: testKey)
        let nonce = try ChaChaPoly.Nonce(data: testNonce)

        // Encrypt with swift-crypto ChaChaPoly
        let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        let chachaCiphertext = [UInt8](sealedBox.ciphertext)
        let chachaTag = [UInt8](sealedBox.tag)

        // Encrypt with DirectCrypto
        let (directCiphertext, directTag) = try DirectCrypto.seal(
            plaintext: [UInt8](plaintext), key: testKey, nonce: testNonce)

        // Both must produce identical output
        XCTAssertEqual(directCiphertext, chachaCiphertext,
                       "DirectCrypto ciphertext must match ChaChaPoly")
        XCTAssertEqual(directTag, chachaTag,
                       "DirectCrypto tag must match ChaChaPoly")
    }

    func testChaChaPolyOutputOpenableByDirect() throws {
        let plaintext = Data("chacha-to-direct".utf8)
        let key = SymmetricKey(data: testKey)
        let nonce = try ChaChaPoly.Nonce(data: testNonce)

        let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)

        let decrypted = try DirectCrypto.open(
            ciphertext: [UInt8](sealedBox.ciphertext),
            tag: [UInt8](sealedBox.tag),
            key: testKey,
            nonce: testNonce)

        XCTAssertEqual(decrypted, [UInt8](plaintext))
    }

    func testDirectOutputOpenableByChaChaPoly() throws {
        let plaintext: [UInt8] = [UInt8]("direct-to-chacha".utf8)

        let (ciphertext, tag) = try DirectCrypto.seal(
            plaintext: plaintext, key: testKey, nonce: testNonce)

        let key = SymmetricKey(data: testKey)
        let nonce = try ChaChaPoly.Nonce(data: testNonce)
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: Data(ciphertext),
            tag: Data(tag))
        let decrypted = try ChaChaPoly.open(sealedBox, using: key)

        XCTAssertEqual([UInt8](decrypted), plaintext)
    }

    func testCombinedFormatCrossCompat() throws {
        // Seal with DirectCrypto combined format
        let plaintext: [UInt8] = [UInt8]("combined cross".utf8)
        let combined = try DirectCrypto.sealCombined(plaintext, key: testKey)

        // Open with ChaChaPoly
        let key = SymmetricKey(data: testKey)
        let sealedBox = try ChaChaPoly.SealedBox(combined: Data(combined))
        let decrypted = try ChaChaPoly.open(sealedBox, using: key)
        XCTAssertEqual([UInt8](decrypted), plaintext)

        // Seal with ChaChaPoly combined format
        let chachaCombined = try ChaChaPoly.seal(Data(plaintext), using: key).combined

        // Open with DirectCrypto
        let decrypted2 = try DirectCrypto.openCombined([UInt8](chachaCombined), key: testKey)
        XCTAssertEqual(decrypted2, plaintext)
    }

    // MARK: - NetworkKey AEADContext

    func testNetworkKeyHasAEADContext() throws {
        let nk = NetworkKey.generate(networkName: "test")
        let plaintext: [UInt8] = [UInt8]("network key context".utf8)
        let combined = try nk.aeadContext.sealCombined(plaintext)
        let decrypted = try nk.aeadContext.openCombined(combined)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testNetworkKeyHeaderContext() throws {
        let nk = NetworkKey.generate(networkName: "test")
        let plaintext: [UInt8] = [UInt8]("header context".utf8)
        let combined = try nk.headerAeadContext.sealCombined(plaintext)
        let decrypted = try nk.headerAeadContext.openCombined(combined)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Random Nonce

    func testRandomNonceLength() {
        let nonce = DirectCrypto.randomNonce()
        XCTAssertEqual(nonce.count, 12)
    }

    func testRandomNoncesAreDifferent() {
        let n1 = DirectCrypto.randomNonce()
        let n2 = DirectCrypto.randomNonce()
        XCTAssertNotEqual(n1, n2)
    }

    // MARK: - Large Payload

    func testLargePayload() throws {
        let plaintext = [UInt8](repeating: 0xAB, count: 65536)
        let combined = try DirectCrypto.sealCombined(plaintext, key: testKey)
        let decrypted = try DirectCrypto.openCombined(combined, key: testKey)
        XCTAssertEqual(decrypted, plaintext)
    }
}

extension DirectCryptoError: Equatable {
    public static func == (lhs: DirectCryptoError, rhs: DirectCryptoError) -> Bool {
        switch (lhs, rhs) {
        case (.sealFailed, .sealFailed),
             (.openFailed, .openFailed),
             (.invalidKeySize, .invalidKeySize),
             (.invalidNonceSize, .invalidNonceSize),
             (.initFailed, .initFailed):
            return true
        default:
            return false
        }
    }
}
