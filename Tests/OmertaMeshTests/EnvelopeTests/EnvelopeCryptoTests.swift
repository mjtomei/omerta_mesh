// EnvelopeCryptoTests.swift - Tests for envelope cryptographic operations

import XCTest
import Crypto
@testable import OmertaMesh

final class EnvelopeCryptoTests: XCTestCase {

    let testKey = Data(repeating: 0x42, count: 32)

    // MARK: - Network Hash Tests

    func testNetworkHashComputation() {
        let hash = BinaryEnvelope.computeNetworkHash(testKey)

        XCTAssertEqual(hash.count, 8, "Network hash should be 8 bytes")

        // Same key should produce same hash
        let hash2 = BinaryEnvelope.computeNetworkHash(testKey)
        XCTAssertEqual(hash, hash2, "Same key should produce same hash")
    }

    func testNetworkHashDifferentKeys() {
        let key1 = Data(repeating: 0x01, count: 32)
        let key2 = Data(repeating: 0x02, count: 32)

        let hash1 = BinaryEnvelope.computeNetworkHash(key1)
        let hash2 = BinaryEnvelope.computeNetworkHash(key2)

        XCTAssertNotEqual(hash1, hash2, "Different keys should produce different hashes")
    }

    // MARK: - HKDF Key Derivation Tests

    func testHKDFKeyDerivation() {
        // Test that HKDF produces consistent results
        let inputKey = SymmetricKey(data: testKey)
        let info = Data("omerta-header-v2".utf8)

        let derivedKey1 = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            info: info,
            outputByteCount: 32
        )

        let derivedKey2 = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            info: info,
            outputByteCount: 32
        )

        // Compare key data
        let data1 = derivedKey1.withUnsafeBytes { Data($0) }
        let data2 = derivedKey2.withUnsafeBytes { Data($0) }
        XCTAssertEqual(data1, data2, "HKDF should produce consistent results")
    }

    func testHKDFDifferentInfoProducesDifferentKeys() {
        let inputKey = SymmetricKey(data: testKey)
        let info1 = Data("omerta-header-v2".utf8)
        let info2 = Data("omerta-payload-v2".utf8)

        let key1 = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            info: info1,
            outputByteCount: 32
        )

        let key2 = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            info: info2,
            outputByteCount: 32
        )

        let data1 = key1.withUnsafeBytes { Data($0) }
        let data2 = key2.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(data1, data2, "Different HKDF info should produce different keys")
    }

    // MARK: - Nonce Derivation Tests

    func testNonceDerivation() {
        // Test the XOR-based nonce derivation
        var headerNonce: [UInt8] = Array(repeating: 0x00, count: 12)
        headerNonce[11] = 0x00

        var bodyNonce = headerNonce
        bodyNonce[11] ^= 0x01

        XCTAssertNotEqual(headerNonce, bodyNonce, "Body nonce should differ from header nonce")
        XCTAssertEqual(bodyNonce[11], 0x01, "Last byte should be XOR'd")
    }

    func testNonceDerivationPreservesOtherBytes() {
        var headerNonce: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                    0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF]

        var bodyNonce = headerNonce
        bodyNonce[11] ^= 0x01

        // First 11 bytes should be unchanged
        for i in 0..<11 {
            XCTAssertEqual(headerNonce[i], bodyNonce[i], "Byte \(i) should be unchanged")
        }

        // Last byte should be XOR'd
        XCTAssertEqual(bodyNonce[11], 0xFE, "Last byte should be 0xFF XOR 0x01 = 0xFE")
    }

    func testNonceDerivationIsReversible() {
        var headerNonce: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
                                    0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44]

        var bodyNonce = headerNonce
        bodyNonce[11] ^= 0x01

        // XOR again to reverse
        bodyNonce[11] ^= 0x01

        XCTAssertEqual(headerNonce, bodyNonce, "XOR is reversible")
    }

    // MARK: - Channel Hash Tests

    func testChannelHashConsistency() {
        let channel = "health-request"
        let hash1 = ChannelHash.hash(channel)
        let hash2 = ChannelHash.hash(channel)

        XCTAssertEqual(hash1, hash2, "Same channel should produce same hash")
    }

    func testChannelHashDifferentChannels() {
        let hash1 = ChannelHash.hash("health-request")
        let hash2 = ChannelHash.hash("health-response")

        XCTAssertNotEqual(hash1, hash2, "Different channels should produce different hashes")
    }

    func testChannelHashEmptyChannel() {
        let hash = ChannelHash.hash("")
        XCTAssertEqual(hash, 0, "Empty channel should hash to 0")
    }

    func testChannelHashNonZeroForNonEmpty() {
        // The hash function ensures non-empty channels don't hash to 0
        let hash = ChannelHash.hash("test")
        XCTAssertNotEqual(hash, 0, "Non-empty channel should not hash to 0")
    }

    func testPrecomputedChannelHashes() {
        // Verify precomputed hashes match runtime computation
        XCTAssertEqual(ChannelHash.meshPing, ChannelHash.hash("mesh-ping"))
        XCTAssertEqual(ChannelHash.meshGossip, ChannelHash.hash("mesh-gossip"))
        XCTAssertEqual(ChannelHash.healthRequest, ChannelHash.hash("health-request"))
        XCTAssertEqual(ChannelHash.cloisterNegotiate, ChannelHash.hash("cloister-negotiate"))
    }

    // MARK: - ChaCha20-Poly1305 Tests

    func testChaChaPolyRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("Hello, World!".utf8)

        let sealedBox = try ChaChaPoly.seal(plaintext, using: key)
        let decrypted = try ChaChaPoly.open(sealedBox, using: key)

        XCTAssertEqual(plaintext, decrypted)
    }

    func testChaChaPolyWithCustomNonce() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("Test message".utf8)
        let nonce = ChaChaPoly.Nonce()

        let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        let decrypted = try ChaChaPoly.open(sealedBox, using: key)

        XCTAssertEqual(plaintext, decrypted)
    }

    func testChaChaPolyWrongKeyFails() throws {
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)
        let plaintext = Data("Secret data".utf8)

        let sealedBox = try ChaChaPoly.seal(plaintext, using: key1)

        XCTAssertThrowsError(try ChaChaPoly.open(sealedBox, using: key2)) { error in
            // Should fail with authentication error
            XCTAssertNotNil(error)
        }
    }

    func testChaChaPolyTamperedCiphertextFails() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Data("Tamper test".utf8)

        let sealedBox = try ChaChaPoly.seal(plaintext, using: key)

        // Tamper with the ciphertext
        var tamperedCiphertext = Data(sealedBox.ciphertext)
        if !tamperedCiphertext.isEmpty {
            tamperedCiphertext[0] ^= 0xFF
        }

        // Try to create a new sealed box with tampered ciphertext
        let tamperedBox = try ChaChaPoly.SealedBox(
            nonce: sealedBox.nonce,
            ciphertext: tamperedCiphertext,
            tag: sealedBox.tag
        )

        XCTAssertThrowsError(try ChaChaPoly.open(tamperedBox, using: key))
    }

    // MARK: - Full Envelope Crypto Flow Tests

    func testEnvelopeEncryptDecryptConsistency() throws {
        let keypair = IdentityKeypair()
        let networkKey = Data(repeating: 0x55, count: 32)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: "target-peer",
            channel: "test-channel",
            payload: .data(Data("test".utf8))
        )

        // Encode and decode
        let encoded = try envelope.encodeV2(networkKey: networkKey)
        let (decoded, channelHash) = try MeshEnvelope.decodeV2WithHash(encoded.data, networkKey: networkKey)

        // Verify round-trip
        XCTAssertEqual(decoded.fromPeerId, envelope.fromPeerId)
        // Full toPeerId string is not recoverable from truncated 16-byte wire format;
        // verify non-nil (non-broadcast) status is preserved
        XCTAssertNotNil(decoded.toPeerId, "Non-broadcast toPeerId should be non-nil")
        XCTAssertEqual(channelHash, ChannelHash.hash("test-channel"))
    }

    func testEnvelopeWrongNetworkKeyFails() throws {
        let keypair = IdentityKeypair()
        let networkKey1 = Data(repeating: 0x11, count: 32)
        let networkKey2 = Data(repeating: 0x22, count: 32)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "",
            payload: .ping(recentPeers: [], myNATType: .unknown, requestFullList: false)
        )

        let encoded = try envelope.encodeV2(networkKey: networkKey1)

        // Should fail with wrong key
        XCTAssertThrowsError(try MeshEnvelope.decodeV2(encoded.data, networkKey: networkKey2))
    }
}
