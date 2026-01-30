// TunnelSessionBatchingTests.swift - Tests for TunnelSession batching behavior

import XCTest
@testable import OmertaTunnel
@testable import OmertaMesh

/// A mock ChannelProvider that tracks sendOnChannel calls for batching tests.
private actor BatchTestProvider: ChannelProvider {
    let peerId: PeerId = "batch-test-peer"

    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]
    private(set) var sendCalls: [(to: String, channel: String, data: Data)] = []

    var sendCallCount: Int { sendCalls.count }

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func onChannel(_ channel: String, batchConfig: BatchConfig?, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        try await onChannel(channel, handler: handler)
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        sendCalls.append((to: peerId, channel: channel, data: data))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        sendCalls.append((to: machineId, channel: channel, data: data))
    }

    func sendOnChannelBuffered(_ data: Data, to peerId: PeerId, channel: String) async throws {
        try await sendOnChannel(data, to: peerId, channel: channel)
    }

    func sendOnChannelBuffered(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        try await sendOnChannel(data, toMachine: machineId, channel: channel)
    }

    func flushChannel(_ channel: String) async throws {}

    func clearCalls() {
        sendCalls.removeAll()
    }
}

final class TunnelSessionBatchingTests: XCTestCase {

    // MARK: - Helpers

    /// Create an activated session with the given batch config.
    private func makeActiveSession(
        provider: BatchTestProvider,
        batchConfig: BatchConfig = BatchConfig(maxFlushDelay: .milliseconds(50), maxBufferSize: 0)
    ) async -> TunnelSession {
        let session = TunnelSession(
            remoteMachineId: "remote-machine",
            channel: "data",
            provider: provider,
            batchConfig: batchConfig
        )
        await session.activate()
        return session
    }

    // MARK: - Tests

    /// 1. send() accumulates data in the buffer without calling the provider.
    func testSendBuffers() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(
            provider: provider,
            batchConfig: BatchConfig(maxFlushDelay: .seconds(10), maxBufferSize: 0)
        )

        try await session.send(Data([1, 2, 3]))
        try await session.send(Data([4, 5, 6]))

        // Provider should NOT have been called — data is buffered
        let callCount = await provider.sendCallCount
        XCTAssertEqual(callCount, 0, "send() should buffer without calling provider")

        await session.close()
    }

    /// 2. flush() sends all buffered packets to the provider as a single batch payload.
    func testFlushSendsToProvider() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(
            provider: provider,
            batchConfig: BatchConfig(maxFlushDelay: .seconds(10), maxBufferSize: 0)
        )

        try await session.send(Data([1, 2]))
        try await session.send(Data([3, 4]))
        try await session.flush()

        let calls = await provider.sendCalls
        XCTAssertEqual(calls.count, 1, "flush() should result in exactly one sendOnChannel call")

        // The payload should be a batch (tag 0x02) containing both packets
        let wireData = calls[0].data
        XCTAssertEqual(wireData.first, BatchWireFormat.batchTag)

        let unpacked = BatchWireFormat.unpack(wireData)
        XCTAssertEqual(unpacked.count, 2)
        XCTAssertEqual(unpacked[0], Data([1, 2]))
        XCTAssertEqual(unpacked[1], Data([3, 4]))

        await session.close()
    }

    /// 3. sendAndFlush() sends immediately via the provider without buffering.
    func testSendAndFlushImmediate() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(provider: provider)

        try await session.sendAndFlush(Data([0xAA, 0xBB]))

        let calls = await provider.sendCalls
        XCTAssertEqual(calls.count, 1, "sendAndFlush() should call provider immediately")

        // Should be a single-packet wire format (tag 0x01)
        let wireData = calls[0].data
        XCTAssertEqual(wireData.first, BatchWireFormat.singleTag)

        let unpacked = BatchWireFormat.unpack(wireData)
        XCTAssertEqual(unpacked, [Data([0xAA, 0xBB])])

        await session.close()
    }

    /// 4. Buffered data auto-flushes after the configured delay.
    func testAutoFlushTimer() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(
            provider: provider,
            batchConfig: BatchConfig(maxFlushDelay: .milliseconds(50), maxBufferSize: 0)
        )

        try await session.send(Data([10, 20, 30]))

        // Immediately after send, provider should not have been called
        let countBefore = await provider.sendCallCount
        XCTAssertEqual(countBefore, 0)

        // Wait for auto-flush to fire (50ms delay + margin)
        try await Task.sleep(for: .milliseconds(200))

        let countAfter = await provider.sendCallCount
        XCTAssertEqual(countAfter, 1, "Auto-flush timer should have sent buffered data")

        // Verify payload contains our packet (single packet => packSingle tag 0x01)
        let calls = await provider.sendCalls
        let unpacked = BatchWireFormat.unpack(calls[0].data)
        XCTAssertEqual(unpacked, [Data([10, 20, 30])])

        await session.close()
    }

    /// 5. deliverIncoming with batch-tagged data delivers each packet separately to the receive handler.
    func testDeliverIncomingUnpacksBatch() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(provider: provider)

        var receivedPackets: [Data] = []
        await session.onReceive { data in
            receivedPackets.append(data)
        }

        // Deliver a batch containing three packets
        let batchData = BatchWireFormat.packBatch([
            Data([1]),
            Data([2, 3]),
            Data([4, 5, 6])
        ])
        await session.deliverIncoming(batchData)

        XCTAssertEqual(receivedPackets.count, 3)
        XCTAssertEqual(receivedPackets[0], Data([1]))
        XCTAssertEqual(receivedPackets[1], Data([2, 3]))
        XCTAssertEqual(receivedPackets[2], Data([4, 5, 6]))

        await session.close()
    }

    /// 6. deliverIncoming with single-tagged data delivers exactly one packet.
    func testDeliverIncomingSinglePacket() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(provider: provider)

        var receivedPackets: [Data] = []
        await session.onReceive { data in
            receivedPackets.append(data)
        }

        let singleData = BatchWireFormat.packSingle(Data([0xFF, 0xFE]))
        await session.deliverIncoming(singleData)

        XCTAssertEqual(receivedPackets.count, 1)
        XCTAssertEqual(receivedPackets[0], Data([0xFF, 0xFE]))

        await session.close()
    }

    /// 7. Sending data beyond maxDatagramPayload triggers auto-flush.
    func testUDPSizeLimitTriggersFlush() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(
            provider: provider,
            batchConfig: BatchConfig(maxFlushDelay: .seconds(60), maxBufferSize: 0)
        )

        let maxPayload = TunnelSession.maxDatagramPayload
        // Send enough data to exceed the limit — each packet is 1000 bytes
        let packetSize = 1000
        let packetsNeeded = (maxPayload / packetSize) + 1
        let packet = Data(repeating: 0xDD, count: packetSize)

        for _ in 0..<packetsNeeded {
            try await session.send(packet)
        }

        // At least one flush should have been triggered by the size limit
        let callCount = await provider.sendCallCount
        XCTAssertGreaterThanOrEqual(callCount, 1,
            "Sending \(packetsNeeded) x \(packetSize) bytes should trigger auto-flush at UDP limit")

        await session.close()
    }

    /// 8. User-configured maxBufferSize is capped by the UDP datagram limit.
    func testUserBufferSizeCappedByUDPLimit() async throws {
        let provider = BatchTestProvider()
        // Configure maxBufferSize larger than the UDP limit
        let session = await makeActiveSession(
            provider: provider,
            batchConfig: BatchConfig(maxFlushDelay: .seconds(60), maxBufferSize: 100_000)
        )

        let maxPayload = TunnelSession.maxDatagramPayload
        let packetSize = 1000
        let packetsNeeded = (maxPayload / packetSize) + 1
        let packet = Data(repeating: 0xEE, count: packetSize)

        for _ in 0..<packetsNeeded {
            try await session.send(packet)
        }

        // Should have flushed at UDP limit, not at the user's 100_000
        let callCount = await provider.sendCallCount
        XCTAssertGreaterThanOrEqual(callCount, 1,
            "UDP limit should override user's maxBufferSize when it is larger")

        await session.close()
    }

    /// 9. User-configured maxBufferSize smaller than UDP limit is respected.
    func testSmallUserBufferSizeRespected() async throws {
        let provider = BatchTestProvider()
        let session = await makeActiveSession(
            provider: provider,
            batchConfig: BatchConfig(maxFlushDelay: .seconds(60), maxBufferSize: 500)
        )

        // Send 600 bytes total (two 300-byte packets) — exceeds the 500-byte user limit
        try await session.send(Data(repeating: 0xAA, count: 300))
        try await session.send(Data(repeating: 0xBB, count: 300))

        let callCount = await provider.sendCallCount
        XCTAssertGreaterThanOrEqual(callCount, 1,
            "User maxBufferSize of 500 should trigger flush before UDP limit")

        await session.close()
    }

    /// 10. flush() on a non-active session throws TunnelError.notConnected.
    func testFlushWhileNotActive() async throws {
        let provider = BatchTestProvider()
        // Create session but do NOT activate it — state remains .connecting
        let session = TunnelSession(
            remoteMachineId: "remote-machine",
            channel: "data",
            provider: provider
        )

        do {
            try await session.flush()
            XCTFail("Expected TunnelError.notConnected")
        } catch {
            XCTAssertEqual(error as? TunnelError, .notConnected)
        }
    }
}
