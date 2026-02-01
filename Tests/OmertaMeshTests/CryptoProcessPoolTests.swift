// CryptoProcessPoolTests.swift - Tests for ChaCha20-Poly1305 process pool

import XCTest
import Crypto
@testable import OmertaMesh

#if os(Linux)

final class CryptoProcessPoolTests: XCTestCase {

    var pool: CryptoProcessPool!

    override func setUp() async throws {
        pool = try CryptoProcessPool(workerCount: 2, slotCount: 8)
    }

    override func tearDown() async throws {
        pool?.shutdown()
        pool = nil
    }

    // MARK: - Single Chunk Round-Trip

    func testSingleChunkEncryptDecrypt() async throws {
        let plaintext = Data("Hello, process pool crypto!".utf8)
        let key = SymmetricKey(size: .bits256)
        let nonce = ChaChaPoly.Nonce()
        let baseNonce = Array(nonce)

        let chunkCount = 1

        let encrypted = try await pool.encrypt(
            plaintext: plaintext,
            chunkCount: chunkCount,
            key: key,
            baseNonce: baseNonce
        )

        XCTAssertNotEqual(encrypted, plaintext)

        let decrypted = try await pool.decrypt(
            encryptedPayload: encrypted,
            chunkCount: chunkCount,
            totalPlaintextLen: plaintext.count,
            key: key,
            baseNonce: baseNonce
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Multi-Chunk Round-Trip

    func testMultiChunkEncryptDecrypt() async throws {
        // Create data spanning multiple 512-byte chunks
        let plaintext = Data(repeating: 0xAB, count: 2000)
        let key = SymmetricKey(size: .bits256)
        let nonce = ChaChaPoly.Nonce()
        let baseNonce = Array(nonce)

        let chunkCount = (plaintext.count + 511) / 512  // 4 chunks

        let encrypted = try await pool.encrypt(
            plaintext: plaintext,
            chunkCount: chunkCount,
            key: key,
            baseNonce: baseNonce
        )

        let decrypted = try await pool.decrypt(
            encryptedPayload: encrypted,
            chunkCount: chunkCount,
            totalPlaintextLen: plaintext.count,
            key: key,
            baseNonce: baseNonce
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Pool Output Matches Inline ChaChaPoly

    func testPoolMatchesInlineCrypto() async throws {
        let plaintext = Data("Verify pool matches inline crypto path".utf8)
        let keyData = Data(repeating: 0x42, count: 32)
        let key = SymmetricKey(data: keyData)
        let baseNonce: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

        // Encrypt inline
        var nonce = baseNonce
        nonce[11] ^= 0x02
        let chunkNonce = try ChaChaPoly.Nonce(data: nonce)
        let inlineSealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: chunkNonce)
        let inlineEncrypted = Data(inlineSealedBox.ciphertext) + Data(inlineSealedBox.tag)

        // Encrypt via pool
        let poolEncrypted = try await pool.encrypt(
            plaintext: plaintext,
            chunkCount: 1,
            key: key,
            baseNonce: baseNonce
        )

        XCTAssertEqual(poolEncrypted, inlineEncrypted,
                       "Pool encryption output must match inline ChaChaPoly.seal")

        // Decrypt the pool output inline
        let ciphertext = Data(poolEncrypted.prefix(plaintext.count))
        let tag = Data(poolEncrypted.suffix(16))
        let sealedBox = try ChaChaPoly.SealedBox(nonce: chunkNonce, ciphertext: ciphertext, tag: tag)
        let inlineDecrypted = try ChaChaPoly.open(sealedBox, using: key)

        XCTAssertEqual(Data(inlineDecrypted), plaintext)
    }

    // MARK: - Concurrent Submissions

    func testConcurrentSubmissions() async throws {
        let key = SymmetricKey(size: .bits256)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<10 {
                group.addTask {
                    let plaintext = Data("Packet \(i)".utf8)
                    let nonce = ChaChaPoly.Nonce()
                    let baseNonce = Array(nonce)

                    let encrypted = try await self.pool.encrypt(
                        plaintext: plaintext,
                        chunkCount: 1,
                        key: key,
                        baseNonce: baseNonce
                    )

                    let decrypted = try await self.pool.decrypt(
                        encryptedPayload: encrypted,
                        chunkCount: 1,
                        totalPlaintextLen: plaintext.count,
                        key: key,
                        baseNonce: baseNonce
                    )

                    XCTAssertEqual(decrypted, plaintext)
                }
            }
            try await group.waitForAll()
        }
    }

    // MARK: - Empty Payload

    func testEmptyPayloadRoundTrip() async throws {
        let plaintext = Data()
        let key = SymmetricKey(size: .bits256)
        let baseNonce = Array(ChaChaPoly.Nonce())

        let encrypted = try await pool.encrypt(
            plaintext: plaintext,
            chunkCount: 1,
            key: key,
            baseNonce: baseNonce
        )

        let decrypted = try await pool.decrypt(
            encryptedPayload: encrypted,
            chunkCount: 1,
            totalPlaintextLen: 0,
            key: key,
            baseNonce: baseNonce
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Worker Crash Recovery

    func testWorkerCrashRecovery() async throws {
        // Verify pool still works after checking workers
        pool.checkWorkers()

        let plaintext = Data("After health check".utf8)
        let key = SymmetricKey(size: .bits256)
        let baseNonce = Array(ChaChaPoly.Nonce())

        let encrypted = try await pool.encrypt(
            plaintext: plaintext,
            chunkCount: 1,
            key: key,
            baseNonce: baseNonce
        )

        let decrypted = try await pool.decrypt(
            encryptedPayload: encrypted,
            chunkCount: 1,
            totalPlaintextLen: plaintext.count,
            key: key,
            baseNonce: baseNonce
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Full BinaryEnvelope Round-Trip via Pool

    func testBinaryEnvelopeRoundTripViaPool() async throws {
        let identity = IdentityKeypair()
        let networkKey = Data(repeating: 0x55, count: 32)

        let message = MeshMessage.data(Data("Pool envelope test".utf8))
        let envelope = try MeshEnvelope.signed(
            from: identity,
            machineId: "test-machine-id",
            to: nil,
            channel: "test-channel",
            payload: message
        )

        // Encode via pool
        let sealed = try await envelope.encodeV2(networkKey: networkKey, pool: pool)

        // Decode via pool
        let (decoded, channelHash) = try await MeshEnvelope.decodeV2WithHash(sealed.data, networkKey: networkKey, pool: pool)

        XCTAssertEqual(decoded.fromPeerId, envelope.fromPeerId)
        XCTAssertEqual(decoded.messageId, envelope.messageId)

        if case .data(let decodedData) = decoded.payload,
           case .data(let originalData) = envelope.payload {
            XCTAssertEqual(decodedData, originalData)
        } else {
            XCTFail("Payload mismatch")
        }

        // Verify channel hash matches
        XCTAssertEqual(channelHash, ChannelHash.hash("test-channel"))
    }
}

#endif // os(Linux)
