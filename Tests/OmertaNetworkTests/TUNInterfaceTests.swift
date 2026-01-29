// TUNInterfaceTests.swift - Tests for Linux TUN interface implementation
//
// All tests require root and Linux. They create temporary TUN devices in the
// 10.99.x.x range to avoid conflicting with real interfaces.

#if os(Linux)
import XCTest
import Foundation
import Glibc
@testable import OmertaNetwork

final class TUNInterfaceTests: XCTestCase {

    private func skipUnlessTUNAvailable() throws {
        guard Glibc.geteuid() == 0 else {
            throw XCTSkip("Requires root")
        }
        guard Glibc.access("/dev/net/tun", F_OK) == 0 else {
            throw XCTSkip("/dev/net/tun not available (container or VM without TUN support)")
        }
    }

    // MARK: - Preflight

    func testPreflightRejectsNonRoot() throws {
        guard Glibc.geteuid() != 0 else {
            throw XCTSkip("Test only runs as non-root")
        }
        do {
            try TUNInterface.preflight()
            XCTFail("preflight should throw for non-root")
        } catch let error as InterfaceError {
            guard case .preflightFailed(let msg) = error else {
                XCTFail("Expected preflightFailed, got \(error)")
                return
            }
            XCTAssertTrue(msg.contains("root"), "Message should mention root: \(msg)")
        }
    }

    func testPreflightRejectsMissingTUN() throws {
        guard Glibc.access("/dev/net/tun", F_OK) != 0 else {
            throw XCTSkip("/dev/net/tun is available — cannot test missing device")
        }
        // If we're also non-root, the root check fires first.
        // That's fine — we just verify preflight throws preflightFailed.
        do {
            try TUNInterface.preflight()
            XCTFail("preflight should throw when /dev/net/tun is missing")
        } catch let error as InterfaceError {
            guard case .preflightFailed = error else {
                XCTFail("Expected preflightFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Lifecycle

    func testTUNCreation() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t0", ip: "10.99.0.1")
        try await tun.start()

        // Verify interface exists and has correct IP
        let (output, status) = ipCommand(["addr", "show", "omerta-t0"])
        XCTAssertEqual(status, 0)
        XCTAssertTrue(output.contains("10.99.0.1"))

        await tun.stop()
    }

    func testTUNStartStop() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t1", ip: "10.99.1.1")
        try await tun.start()
        await tun.stop()

        // Interface should be gone
        let (_, status) = ipCommand(["link", "show", "omerta-t1"])
        XCTAssertNotEqual(status, 0)
    }

    func testTUNDoubleStartThrows() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t2", ip: "10.99.2.1")
        try await tun.start()
        defer { Task { await tun.stop() } }

        do {
            try await tun.start()
            XCTFail("Second start should throw")
        } catch is InterfaceError {
            // expected
        }
    }

    // MARK: - Packet I/O

    func testTUNWriteAndReadLoopback() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t3", ip: "10.99.3.1")
        try await tun.start()
        defer { Task { await tun.stop() } }

        // Ping the TUN interface's own IP to generate traffic
        let pingProc = Process()
        pingProc.executableURL = URL(fileURLWithPath: "/bin/ping")
        pingProc.arguments = ["-c", "1", "-W", "2", "10.99.3.1"]
        pingProc.standardOutput = FileHandle.nullDevice
        pingProc.standardError = FileHandle.nullDevice

        // Start reading before ping so we don't miss packets
        let readTask = Task<Data?, Never> {
            try? await withTimeout(seconds: 3) {
                try await tun.readPacket()
            }
        }

        try pingProc.run()
        pingProc.waitUntilExit()

        let packet = await readTask.value
        XCTAssertNotNil(packet)
        if let packet {
            XCTAssertGreaterThan(packet.count, 20, "Should be at least an IP header")
        }
    }

    // MARK: - DispatchSource (event-driven)

    func testTUNDispatchSourceNotBlocking() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t4", ip: "10.99.4.1")
        try await tun.start()
        defer { Task { await tun.stop() } }

        // readPacket suspends via AsyncStream — the actor should remain responsive
        let readTask = Task {
            try await tun.readPacket()
        }

        // The actor should still respond while readTask is waiting
        let ip = await tun.localIP
        XCTAssertEqual(ip, "10.99.4.1")

        readTask.cancel()
    }

    func testTUNCallbackMode() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t5", ip: "10.99.5.1")

        let expectation = XCTestExpectation(description: "packet via callback")
        await tun.setPacketCallback { _ in
            expectation.fulfill()
        }

        try await tun.start()
        defer { Task { await tun.stop() } }

        // Ping ourselves to generate traffic
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/ping")
        proc.arguments = ["-c", "1", "-W", "2", "10.99.5.1"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        proc.waitUntilExit()

        await fulfillment(of: [expectation], timeout: 3)
    }

    // MARK: - TUNBridgeAdapter

    func testTUNBridgeAdapterConforms() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t6", ip: "10.99.6.1")
        let bridge = TUNBridgeAdapter(tun: tun)

        let expectation = XCTestExpectation(description: "return callback fired")
        await bridge.setReturnCallback { _ in
            expectation.fulfill()
        }

        try await bridge.start()
        defer { Task { await bridge.stop() } }

        // Inject an ICMP packet — kernel processes it and sends reply back through TUN
        let icmpPacket = Self.buildICMPEchoRequest(src: "10.99.6.2", dst: "10.99.6.1")
        try await bridge.injectPacket(icmpPacket)

        await fulfillment(of: [expectation], timeout: 3)
    }

    func testTUNBridgeInjectPacket() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t7", ip: "10.99.7.1")
        let bridge = TUNBridgeAdapter(tun: tun)

        let expectation = XCTestExpectation(description: "ICMP reply via callback")
        await bridge.setReturnCallback { packet in
            // ICMP protocol number is 1, at byte offset 9 in IPv4 header
            if packet.count >= 20 && packet[9] == 1 {
                expectation.fulfill()
            }
        }

        try await bridge.start()
        defer { Task { await bridge.stop() } }

        // Build and inject a minimal ICMP echo request
        let icmpPacket = Self.buildICMPEchoRequest(src: "10.99.7.2", dst: "10.99.7.1")
        try await bridge.injectPacket(icmpPacket)

        await fulfillment(of: [expectation], timeout: 3)
    }

    func testTUNBridgeDialTCPThrows() async throws {
        try skipUnlessTUNAvailable()

        let tun = TUNInterface(name: "omerta-t8", ip: "10.99.8.1")
        let bridge = TUNBridgeAdapter(tun: tun)
        try await bridge.start()
        defer { Task { await bridge.stop() } }

        do {
            _ = try await bridge.dialTCP(host: "1.2.3.4", port: 80)
            XCTFail("dialTCP should throw notSupported")
        } catch InterfaceError.notSupported {
            // expected
        }
    }

    // MARK: - KernelNetworking

    func testKernelForwardingToggle() async throws {
        try skipUnlessTUNAvailable()

        let path = "/proc/sys/net/ipv4/ip_forward"

        // Read using POSIX since Foundation doesn't handle procfs well
        let fd = Glibc.open(path, O_RDONLY)
        guard fd >= 0 else {
            throw XCTSkip("No \(path) (container or custom kernel)")
        }
        var buf = [UInt8](repeating: 0, count: 16)
        let n = Glibc.read(fd, &buf, buf.count)
        Glibc.close(fd)
        let original = n > 0 ? String(bytes: buf[..<n], encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "0" : "0"

        defer {
            let wfd = Glibc.open(path, O_WRONLY)
            if wfd >= 0 {
                _ = original.withCString { Glibc.write(wfd, $0, original.utf8.count) }
                Glibc.close(wfd)
            }
        }

        try KernelNetworking.enableForwarding()

        let rfd = Glibc.open(path, O_RDONLY)
        guard rfd >= 0 else {
            XCTFail("Could not read ip_forward after enable")
            return
        }
        var vbuf = [UInt8](repeating: 0, count: 16)
        let vn = Glibc.read(rfd, &vbuf, vbuf.count)
        Glibc.close(rfd)
        let value = vn > 0 ? String(bytes: vbuf[..<vn], encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) : nil
        XCTAssertEqual(value, "1")
    }

    // MARK: - Helpers

    private func ipCommand(_ args: [String]) -> (String, Int32) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/ip")
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (String(data: data, encoding: .utf8) ?? "", proc.terminationStatus)
    }

    /// Build a minimal IPv4 ICMP echo request packet
    static func buildICMPEchoRequest(src: String, dst: String) -> Data {
        var packet = Data(count: 28) // 20-byte IP header + 8-byte ICMP

        // IPv4 header
        packet[0] = 0x45  // version 4, IHL 5
        packet[1] = 0     // DSCP/ECN
        let totalLen = UInt16(28)
        packet[2] = UInt8(totalLen >> 8)
        packet[3] = UInt8(totalLen & 0xFF)
        packet[4] = 0; packet[5] = 1    // identification
        packet[6] = 0; packet[7] = 0    // flags/fragment
        packet[8] = 64                   // TTL
        packet[9] = 1                    // ICMP protocol
        packet[10] = 0; packet[11] = 0  // checksum (filled below)

        // Source IP
        let srcParts = src.split(separator: ".").compactMap { UInt8($0) }
        let dstParts = dst.split(separator: ".").compactMap { UInt8($0) }
        for i in 0..<4 { packet[12 + i] = srcParts[i] }
        for i in 0..<4 { packet[16 + i] = dstParts[i] }

        // IP header checksum
        var sum: UInt32 = 0
        for i in stride(from: 0, to: 20, by: 2) {
            sum += UInt32(packet[i]) << 8 | UInt32(packet[i + 1])
        }
        while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
        let ipCksum = ~UInt16(sum)
        packet[10] = UInt8(ipCksum >> 8)
        packet[11] = UInt8(ipCksum & 0xFF)

        // ICMP echo request
        packet[20] = 8    // type: echo request
        packet[21] = 0    // code
        packet[22] = 0; packet[23] = 0  // checksum (filled below)
        packet[24] = 0; packet[25] = 1  // identifier
        packet[26] = 0; packet[27] = 1  // sequence

        // ICMP checksum
        var icmpSum: UInt32 = 0
        for i in stride(from: 20, to: 28, by: 2) {
            icmpSum += UInt32(packet[i]) << 8 | UInt32(packet[i + 1])
        }
        while icmpSum > 0xFFFF { icmpSum = (icmpSum & 0xFFFF) + (icmpSum >> 16) }
        let icmpCksum = ~UInt16(icmpSum)
        packet[22] = UInt8(icmpCksum >> 8)
        packet[23] = UInt8(icmpCksum & 0xFF)

        return packet
    }
}

/// Timeout helper for async operations
func withTimeout<T>(seconds: Double, operation: @escaping () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw CancellationError()
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

#endif
