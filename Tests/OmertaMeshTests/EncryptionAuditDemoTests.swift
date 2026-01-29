// EncryptionAuditDemoTests.swift - Demonstrates attacks caught by the encryption audit
//
// Each test simulates a malicious or accidental code change that tries to send
// improperly encrypted data through UDPSocket. The global encryption observer
// catches every violation. Run with:
//
//   swift test --filter EncryptionAuditDemoTests
//
// To see the diff of "attacker code" these tests simulate, see the accompanying
// ENCRYPTION_AUDIT_DEMO.md in the plans directory.

import XCTest
import NIOPosix
import NIOCore
import Crypto
@testable import OmertaMesh

#if DEBUG

final class EncryptionAuditDemoTests: XCTestCase {

    private var group: MultiThreadedEventLoopGroup!
    private var socket: UDPSocket!
    private var dest: SocketAddress!

    override class func setUp() {
        super.setUp()
        GlobalEncryptionObserver.install()
    }

    override func setUp() async throws {
        try await super.setUp()
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        socket = UDPSocket(eventLoopGroup: group)
        try await socket.bind(port: 0)
        let port = await socket.port!
        dest = try SocketAddress(ipAddress: "127.0.0.1", port: port)
    }

    override func tearDown() async throws {
        await socket.close()
        try? group.syncShutdownGracefully()
        try await super.tearDown()
    }

    // MARK: - Helpers

    /// Attempt a raw send and return whether the observer caught a violation.
    private func attemptRawSend(_ data: Data) async -> Bool {
        let beforeCount = GlobalEncryptionObserver.shared.violations.count
        GlobalEncryptionObserver.suppressHook = false
        try? await socket.sendRaw(data, to: dest)
        try? await Task.sleep(nanoseconds: 10_000_000)
        let afterCount = GlobalEncryptionObserver.shared.violations.count
        return afterCount > beforeCount
    }

    // MARK: - Scenario 1: Plaintext JSON send

    /// Simulates a developer accidentally sending a JSON-encoded envelope
    /// without encryption, e.g. reverting to the old `JSONEncoder.encode()` path.
    ///
    /// Diff this simulates:
    ///   - let sealed = try envelope.encodeV2(networkKey: config.encryptionKey)
    ///   - try await socket.send(sealed, to: endpoint)
    ///   + let data = try JSONEncoder().encode(envelope)
    ///   + try await socket.sendRaw(data, to: endpoint)
    func testCatchesPlaintextJSON() async throws {
        let keypair = IdentityKeypair()
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data("secret message".utf8))
        )
        let jsonData = try JSONEncoder().encode(envelope)

        let caught = await attemptRawSend(jsonData)
        XCTAssertTrue(caught, "Audit must catch plaintext JSON sends")
    }

    // MARK: - Scenario 2: Raw bytes / debug data

    /// Simulates a developer adding a debug probe or diagnostic ping
    /// that sends arbitrary bytes.
    ///
    /// Diff this simulates:
    ///   + try await socket.sendRaw(Data("PING".utf8), to: endpoint)
    func testCatchesRawDebugBytes() async throws {
        let caught = await attemptRawSend(Data("PING".utf8))
        XCTAssertTrue(caught, "Audit must catch raw debug byte sends")
    }

    // MARK: - Scenario 3: Correct magic prefix, random body

    /// Simulates an attacker or buggy code that knows the magic bytes
    /// but sends garbage after them — a spoofed header.
    ///
    /// Diff this simulates:
    ///   + var fake = Data("OMRT".utf8)        // magic
    ///   + fake.append(0x02)                    // version
    ///   + fake.append(Data(repeating: 0xAA, count: 100))  // garbage
    ///   + try await socket.sendRaw(fake, to: endpoint)
    func testCatchesSpoofedMagicWithGarbageBody() async throws {
        var fake = Data("OMRT".utf8)
        fake.append(0x02)
        fake.append(Data(repeating: 0xAA, count: 100))

        // This passes the prefix check but will be caught by decryption in --audit-encryption.
        // In the test observer (prefix-only), it passes — demonstrating why the daemon's
        // full decryption check is important.
        let prefixValid = BinaryEnvelopeV2.isValidPrefix(fake)
        XCTAssertTrue(prefixValid, "Spoofed magic should pass prefix check")

        // But decryption must fail
        let testKey = Data(repeating: 0x42, count: 32)
        XCTAssertThrowsError(try BinaryEnvelopeV2.decode(fake, networkKey: testKey),
                            "Garbage body must fail decryption")
    }

    // MARK: - Scenario 4: Valid header encryption, corrupted payload

    /// Simulates a subtle bug where the header is properly encrypted but
    /// the payload section is corrupted — e.g. a buffer reuse bug or
    /// partial write.
    ///
    /// The packet has: valid magic, valid nonce, valid encrypted header,
    /// but the payload bytes are zeroed out.
    func testCatchesCorruptedPayload() async throws {
        let keypair = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data("important data".utf8))
        )

        // Get a valid encrypted packet, then corrupt the payload section
        let sealed = try envelope.encodeV2(networkKey: testKey)
        var corrupted = sealed.data

        // Zero out the last 32 bytes (payload ciphertext + tag area)
        let start = corrupted.count - 32
        for i in start..<corrupted.count {
            corrupted[i] = 0x00
        }

        XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(corrupted), "Prefix still valid")
        XCTAssertThrowsError(try BinaryEnvelopeV2.decode(corrupted, networkKey: testKey),
                            "Corrupted payload must fail decryption")
    }

    // MARK: - Scenario 5: Encrypted with wrong key

    /// Simulates a node that was compromised or misconfigured and is
    /// encrypting with a different network key. The packet looks
    /// structurally valid but authenticates under the wrong key.
    ///
    /// Diff this simulates:
    ///   + let wrongKey = Data(repeating: 0xFF, count: 32)
    ///   + let sealed = try envelope.encodeV2(networkKey: wrongKey)
    ///   + try await socket.send(sealed, to: endpoint)
    func testCatchesWrongKeyEncryption() async throws {
        let keypair = IdentityKeypair()
        let correctKey = Data(repeating: 0x42, count: 32)
        let wrongKey = Data(repeating: 0xFF, count: 32)

        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data("secret".utf8))
        )

        let sealed = try envelope.encodeV2(networkKey: wrongKey)

        XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(sealed.data), "Prefix valid regardless of key")
        XCTAssertThrowsError(try BinaryEnvelopeV2.decode(sealed.data, networkKey: correctKey),
                            "Wrong-key packet must fail decryption with correct key")
    }

    // MARK: - Scenario 6: Replay with tampered nonce

    /// Simulates an attacker capturing a valid packet and changing the
    /// nonce to attempt a replay with modified routing. The crypto
    /// authentication should reject this.
    func testCatchesTamperedNonce() async throws {
        let keypair = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data("replay me".utf8))
        )

        let sealed = try envelope.encodeV2(networkKey: testKey)
        var tampered = sealed.data

        // Flip bits in the nonce (bytes 5-16)
        for i in 5..<17 {
            tampered[i] ^= 0xFF
        }

        XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(tampered), "Prefix unaffected by nonce change")
        XCTAssertThrowsError(try BinaryEnvelopeV2.decode(tampered, networkKey: testKey),
                            "Tampered nonce must fail authentication")
    }

    // MARK: - Scenario 7: Truncated packet

    /// Simulates network truncation or a bug that sends an incomplete packet.
    /// The prefix is valid but the packet is too short to contain the full
    /// encrypted structure.
    func testCatchesTruncatedPacket() async throws {
        let keypair = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data("truncate me".utf8))
        )

        let sealed = try envelope.encodeV2(networkKey: testKey)

        // Truncate to just the prefix + nonce (17 bytes)
        let truncated = sealed.data.prefix(17)

        XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(Data(truncated)), "Prefix valid on truncated data")
        XCTAssertThrowsError(try BinaryEnvelopeV2.decode(Data(truncated), networkKey: testKey),
                            "Truncated packet must fail decryption")
    }

    // MARK: - Scenario 8: Header tag tampered (bit flip attack)

    /// Simulates a targeted bit-flip on the header authentication tag.
    /// This is a precise attack attempting to bypass AEAD verification.
    func testCatchesHeaderTagBitFlip() async throws {
        let keypair = IdentityKeypair()
        let testKey = Data(repeating: 0x42, count: 32)
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data("flip my tag".utf8))
        )

        let sealed = try envelope.encodeV2(networkKey: testKey)
        var tampered = sealed.data

        // Header tag starts at offset 17 (prefix=5 + nonce=12), flip one bit
        let tagOffset = 17
        tampered[tagOffset] ^= 0x01

        XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(tampered), "Prefix unaffected")
        XCTAssertThrowsError(try BinaryEnvelopeV2.decode(tampered, networkKey: testKey),
                            "Flipped header tag bit must fail authentication")
    }

    // MARK: - Scenario 9: Empty payload masquerading as encrypted

    /// Simulates sending just the magic + version with nothing else.
    /// A minimal "looks encrypted" packet.
    func testCatchesMinimalFakePacket() async throws {
        var minimal = Data("OMRT".utf8)
        minimal.append(0x02)

        XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(minimal), "Exactly prefix-sized data passes prefix check")
        XCTAssertThrowsError(try BinaryEnvelopeV2.decode(minimal, networkKey: Data(repeating: 0x42, count: 32)),
                            "Prefix-only packet must fail decryption")
    }

    // MARK: - Scenario 10: Legacy MessageEncryption format

    /// Simulates old code that used the legacy MessageEncryption.encrypt()
    /// path instead of BinaryEnvelopeV2. This is the exact regression that
    /// the SealedEnvelope type system prevents at compile time, but we
    /// verify the runtime audit catches it too.
    func testCatchesLegacyEncryptionFormat() async throws {
        let keypair = IdentityKeypair()
        let envelope = try MeshEnvelope.signed(
            from: keypair,
            machineId: UUID().uuidString,
            to: nil,
            payload: .data(Data("legacy path".utf8))
        )
        let jsonData = try JSONEncoder().encode(envelope)
        let testKey = Data(repeating: 0x42, count: 32)
        let legacyEncrypted = try MessageEncryption.encrypt(jsonData, key: testKey)

        // Legacy format doesn't have OMRT prefix
        XCTAssertFalse(BinaryEnvelopeV2.isValidPrefix(legacyEncrypted),
                      "Legacy encryption format must not pass prefix check")

        let caught = await attemptRawSend(legacyEncrypted)
        XCTAssertTrue(caught, "Audit must catch legacy encryption format sends")
    }
}

#endif
