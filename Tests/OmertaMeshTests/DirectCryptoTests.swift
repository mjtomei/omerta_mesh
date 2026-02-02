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

    // MARK: - Wire Format Cross-Compatibility

    /// Encode a v3 envelope using ChaChaPoly directly (simulating the old code path),
    /// then decode it with the NEW DirectCrypto-based BinaryEnvelope.decode.
    /// This proves the wire format is compatible across the migration.
    func testChaChaPolyEncodedEnvelopeDecodableByDirectCrypto() throws {
        let keypair = IdentityKeypair()
        let networkKey = Data(repeating: 0x42, count: 32)
        let networkHash = BinaryEnvelope.computeNetworkHash(networkKey)
        let payload = MeshMessage.ping(recentPeers: [], myNATType: .unknown, requestFullList: false)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "test",
            payload: payload
        )

        // Build an EnvelopeHeader the same way encodeV2 does
        let channelHash = ChannelHash.hash(envelope.channel)
        let messageUUID = UUID(uuidString: envelope.messageId) ?? UUID.fromString(envelope.messageId)
        let publicKeyData = Data(base64Encoded: envelope.publicKey)!
        let signatureData = Data(base64Encoded: envelope.signature)!

        let header = EnvelopeHeader(
            networkHash: networkHash,
            fromPeerId: envelope.fromPeerId,
            toPeerId: envelope.toPeerId,
            channel: channelHash,
            channelString: envelope.channel,
            hopCount: UInt8(min(max(envelope.hopCount, 0), 255)),
            timestamp: envelope.timestamp,
            messageId: messageUUID,
            machineId: envelope.machineId,
            publicKey: publicKeyData,
            signature: signatureData
        )

        let payloadData = try JSONCoding.encoder.encode(envelope.payload)

        // Build a v3 packet using ChaChaPoly directly (simulating old code path)
        let baseNonce = DirectCrypto.randomNonce()
        let headerKeyBytes = NetworkKey.deriveHeaderKeyBytes(from: networkKey)
        let headerKey = SymmetricKey(data: headerKeyBytes)
        let payloadKey = SymmetricKey(data: networkKey)

        // Encrypt routing header with ChaChaPoly (old way)
        let routingData = try header.encodeRouting()
        var routingNonce = baseNonce
        routingNonce[11] ^= 0x00
        let routingSealedBox = try ChaChaPoly.seal(
            routingData,
            using: headerKey,
            nonce: try ChaChaPoly.Nonce(data: routingNonce))
        let routingCiphertext = [UInt8](routingSealedBox.ciphertext)
        let routingTag = [UInt8](routingSealedBox.tag)

        // Encrypt auth header with ChaChaPoly (old way)
        let authData = try header.encodeAuth()
        var authNonce = baseNonce
        authNonce[11] ^= 0x01
        let authSealedBox = try ChaChaPoly.seal(
            authData,
            using: payloadKey,
            nonce: try ChaChaPoly.Nonce(data: authNonce))
        let authCiphertext = [UInt8](authSealedBox.ciphertext)
        let authTag = [UInt8](authSealedBox.tag)

        // Encrypt payload chunks with ChaChaPoly (old way)
        let payloadBytes = [UInt8](payloadData)
        let chunkSize = 512
        let chunks: [[UInt8]] = payloadBytes.isEmpty ? [[]] :
            stride(from: 0, to: payloadBytes.count, by: chunkSize).map { start in
                Array(payloadBytes[start..<min(start + chunkSize, payloadBytes.count)])
            }

        var encryptedChunks: [(ciphertext: [UInt8], tag: [UInt8])] = []
        for (i, chunk) in chunks.enumerated() {
            var chunkNonce = baseNonce
            chunkNonce[11] ^= 0x02
            chunkNonce[9] ^= UInt8(truncatingIfNeeded: i >> 8)
            chunkNonce[10] ^= UInt8(truncatingIfNeeded: i)
            let box = try ChaChaPoly.seal(
                Data(chunk),
                using: payloadKey,
                nonce: try ChaChaPoly.Nonce(data: chunkNonce))
            encryptedChunks.append(([UInt8](box.ciphertext), [UInt8](box.tag)))
        }

        // Assemble the wire packet manually
        var packet = Data()
        packet.append(Data("OMR".utf8))          // magic
        packet.append(0x03)                       // version
        packet.append(contentsOf: baseNonce)      // 12 bytes nonce
        packet.append(contentsOf: routingTag)     // 16 bytes
        packet.append(contentsOf: routingCiphertext) // 44 bytes
        packet.append(contentsOf: authTag)        // 16 bytes
        packet.append(contentsOf: authCiphertext) // 136 bytes
        var lenBytes = [UInt8](repeating: 0, count: 4)
        let len = UInt32(payloadData.count)
        // Big-endian (matches BinaryWriter.writeUInt32)
        lenBytes[0] = UInt8(truncatingIfNeeded: len >> 24)
        lenBytes[1] = UInt8(truncatingIfNeeded: len >> 16)
        lenBytes[2] = UInt8(truncatingIfNeeded: len >> 8)
        lenBytes[3] = UInt8(truncatingIfNeeded: len)
        packet.append(contentsOf: lenBytes)
        for chunk in encryptedChunks {
            packet.append(contentsOf: chunk.ciphertext)
            packet.append(contentsOf: chunk.tag)
        }

        // Decode with the new DirectCrypto-based decoder
        let (decodedHeader, decodedPayload) = try BinaryEnvelope.decode(packet, networkKey: networkKey)

        // Verify fields match
        XCTAssertEqual(decodedHeader.fromPeerId, header.fromPeerId)
        XCTAssertEqual(decodedHeader.networkHash, header.networkHash)
        XCTAssertEqual(decodedHeader.hopCount, header.hopCount)
        XCTAssertEqual(decodedPayload, payloadData)
    }

    /// Encode with the new DirectCrypto-based BinaryEnvelope.encode,
    /// then manually decrypt each section with ChaChaPoly to verify
    /// the wire format is readable by the old code path.
    func testDirectCryptoEncodedEnvelopeDecodableByChaChaPoly() throws {
        let keypair = IdentityKeypair()
        let networkKey = Data(repeating: 0x42, count: 32)
        let payload = MeshMessage.ping(recentPeers: [], myNATType: .unknown, requestFullList: false)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            channel: "test",
            payload: payload
        )

        // Encode with new DirectCrypto path
        let sealed = try envelope.encodeV2(networkKey: networkKey)
        let data = sealed.data

        // Verify prefix
        XCTAssertEqual(data.prefix(3), Data("OMR".utf8))
        XCTAssertEqual(data[3], 0x03)

        // Extract fields from wire format
        let baseNonce = [UInt8](data[4..<16])
        let routingTag = Data(data[16..<32])
        let routingCiphertext = Data(data[32..<76])
        let authTag = Data(data[76..<92])
        let authCiphertext = Data(data[92..<228])
        // Big-endian (matches BinaryWriter.writeUInt32)
        let payloadLen = Int(UInt32(data[228]) << 24 | UInt32(data[229]) << 16 |
                             UInt32(data[230]) << 8 | UInt32(data[231]))

        // Decrypt routing header with ChaChaPoly (old way)
        let headerKeyBytes = NetworkKey.deriveHeaderKeyBytes(from: networkKey)
        let headerKey = SymmetricKey(data: headerKeyBytes)
        var routingNonce = baseNonce
        routingNonce[11] ^= 0x00
        let routingBox = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: routingNonce),
            ciphertext: routingCiphertext,
            tag: routingTag)
        let routingPlaintext = try ChaChaPoly.open(routingBox, using: headerKey)
        XCTAssertEqual(routingPlaintext.count, 44)

        // Decrypt auth header with ChaChaPoly (old way)
        let payloadKey = SymmetricKey(data: networkKey)
        var authNonce = baseNonce
        authNonce[11] ^= 0x01
        let authBox = try ChaChaPoly.SealedBox(
            nonce: try ChaChaPoly.Nonce(data: authNonce),
            ciphertext: authCiphertext,
            tag: authTag)
        let authPlaintext = try ChaChaPoly.open(authBox, using: payloadKey)
        XCTAssertEqual(authPlaintext.count, 136)

        // Decrypt payload chunks with ChaChaPoly (old way)
        let chunkSize = 512
        let numChunks = max(1, (payloadLen + chunkSize - 1) / chunkSize)
        var offset = 232  // after fixed header
        var decryptedPayload = Data()
        for i in 0..<numChunks {
            let thisChunkPlainSize: Int
            if payloadLen == 0 {
                thisChunkPlainSize = 0
            } else {
                let remaining = payloadLen - i * chunkSize
                thisChunkPlainSize = min(chunkSize, remaining)
            }
            let chunkCiphertext = Data(data[offset..<(offset + thisChunkPlainSize)])
            offset += thisChunkPlainSize
            let chunkTag = Data(data[offset..<(offset + 16)])
            offset += 16

            var chunkNonce = baseNonce
            chunkNonce[11] ^= 0x02
            chunkNonce[9] ^= UInt8(truncatingIfNeeded: i >> 8)
            chunkNonce[10] ^= UInt8(truncatingIfNeeded: i)
            let chunkBox = try ChaChaPoly.SealedBox(
                nonce: try ChaChaPoly.Nonce(data: chunkNonce),
                ciphertext: chunkCiphertext,
                tag: chunkTag)
            let chunkPlaintext = try ChaChaPoly.open(chunkBox, using: payloadKey)
            decryptedPayload.append(chunkPlaintext)
        }

        XCTAssertEqual(decryptedPayload.count, payloadLen)

        // Verify the payload decodes to the same message
        let decodedMessage = try JSONCoding.decoder.decode(MeshMessage.self, from: decryptedPayload)
        if case .ping = decodedMessage {
            // Expected
        } else {
            XCTFail("Expected .ping, got \(decodedMessage)")
        }
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
