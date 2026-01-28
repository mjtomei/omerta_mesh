// EncryptionEnforcementTests.swift - Verify all network traffic is encrypted

import XCTest
import NIOPosix
import NIOCore
@testable import OmertaMesh

final class EncryptionEnforcementTests: XCTestCase {

    override func tearDown() {
        super.tearDown()
        #if DEBUG
        UDPSocket.captureHook = nil
        #endif
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
        var captured: [Data] = []
        let lock = NSLock()
        UDPSocket.captureHook = { data, _ in
            lock.lock()
            captured.append(data)
            lock.unlock()
        }

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

        lock.lock()
        let packets = captured
        lock.unlock()

        XCTAssertFalse(packets.isEmpty, "Should have captured at least one packet")

        for (i, packet) in packets.enumerated() {
            XCTAssertTrue(BinaryEnvelopeV2.isValidPrefix(packet),
                         "Packet \(i) missing encrypted prefix: \(packet.prefix(8).map { String(format: "%02x", $0) }.joined())")
        }
    }
    #endif
}
