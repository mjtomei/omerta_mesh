import XCTest
import Foundation
import NIOCore
import NIOPosix
@testable import OmertaNetwork

final class SOCKSProxyTests: XCTestCase {

    private var mockInterface: MockNetworkInterface!
    private var proxy: SOCKSProxy!

    override func setUp() async throws {
        mockInterface = MockNetworkInterface(localIP: "10.0.0.1")
        try await mockInterface.start()
        proxy = SOCKSProxy(port: 0, interface: mockInterface)
        try await proxy.start()
    }

    override func tearDown() async throws {
        await proxy.stop()
        await mockInterface.stop()
    }

    // MARK: - Helpers

    private func connect() async throws -> (NIOAsyncChannel<ByteBuffer, ByteBuffer>)? {
        // Use raw NIO to connect
        return nil // We'll use a simpler approach
    }

    private func connectRaw() async throws -> Channel {
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let port = await proxy.actualPort
        let bootstrap = ClientBootstrap(group: elg)
        let channel = try await bootstrap.connect(host: "127.0.0.1", port: Int(port)).get()
        return channel
    }

    private func connectSocket() async throws -> SocketHelper {
        let port = await proxy.actualPort
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        XCTAssertGreaterThan(fd, 0)

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Foundation.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        XCTAssertEqual(result, 0, "connect failed: \(errno)")

        return SocketHelper(fd: fd)
    }

    // MARK: - Tests

    func testSOCKS5Greeting() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        // Send greeting: version 5, 1 method, no-auth (0x00)
        sock.send([0x05, 0x01, 0x00])

        let reply = try sock.recv(count: 2, timeout: 2.0)
        XCTAssertEqual(reply, Data([0x05, 0x00]))
    }

    func testSOCKS5ConnectIPv4() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        // Greeting
        sock.send([0x05, 0x01, 0x00])
        _ = try sock.recv(count: 2, timeout: 2.0)

        // Connect to 10.0.0.100:22
        sock.send([
            0x05, 0x01, 0x00, 0x01,  // ver, cmd=connect, rsv, atyp=IPv4
            10, 0, 0, 100,            // address
            0x00, 0x16                 // port 22
        ])

        let reply = try sock.recv(count: 10, timeout: 2.0)
        XCTAssertEqual(reply[0], 0x05) // version
        XCTAssertEqual(reply[1], 0x00) // success

        // Verify dialTCP was called correctly
        let dialed = await mockInterface.getDialedConnections()
        XCTAssertEqual(dialed.count, 1)
        XCTAssertEqual(dialed[0].host, "10.0.0.100")
        XCTAssertEqual(dialed[0].port, 22)
    }

    func testSOCKS5ConnectDomain() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        // Greeting
        sock.send([0x05, 0x01, 0x00])
        _ = try sock.recv(count: 2, timeout: 2.0)

        // Connect with domain name "example.mesh"
        let domain = "example.mesh"
        let domainBytes = Array(domain.utf8)
        var request: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(domainBytes.count)]
        request.append(contentsOf: domainBytes)
        request.append(contentsOf: [0x00, 0x50]) // port 80
        sock.send(request)

        let reply = try sock.recv(count: 10, timeout: 2.0)
        XCTAssertEqual(reply[0], 0x05)
        XCTAssertEqual(reply[1], 0x00) // success

        let dialed = await mockInterface.getDialedConnections()
        XCTAssertEqual(dialed.count, 1)
        XCTAssertEqual(dialed[0].host, "example.mesh")
        XCTAssertEqual(dialed[0].port, 80)
    }

    func testSOCKS5DataRelay() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        // Full handshake
        sock.send([0x05, 0x01, 0x00])
        _ = try sock.recv(count: 2, timeout: 2.0)

        sock.send([
            0x05, 0x01, 0x00, 0x01,
            10, 0, 0, 100,
            0x00, 0x16
        ])
        _ = try sock.recv(count: 10, timeout: 2.0)

        // Send data through the proxy
        let testData = Data("Hello, mesh!".utf8)
        sock.send(Array(testData))

        // Wait for data to arrive at mock connection
        try await Task.sleep(for: .milliseconds(200))

        let mockConn = await mockInterface.getMockConnection(host: "10.0.0.100", port: 22)
        XCTAssertNotNil(mockConn)

        let written = await mockConn!.getWrittenData()
        let combined = written.reduce(Data(), +)
        XCTAssertEqual(combined, testData)

        // Send data back from the mock connection
        let responseData = Data("Hi from mesh!".utf8)
        await mockConn!.simulateIncoming(responseData)

        let received = try sock.recv(count: responseData.count, timeout: 2.0)
        XCTAssertEqual(received, responseData)
    }

    func testSOCKS5UnsupportedAuthRejected() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        // Send greeting with only username/password auth (0x02), no no-auth
        sock.send([0x05, 0x01, 0x02])

        let reply = try sock.recv(count: 2, timeout: 2.0)
        XCTAssertEqual(reply, Data([0x05, 0xFF]))
    }

    func testSOCKS5ConnectFailure() async throws {
        await mockInterface.setShouldFailDial(true)

        let sock = try await connectSocket()
        defer { sock.close() }

        // Greeting
        sock.send([0x05, 0x01, 0x00])
        _ = try sock.recv(count: 2, timeout: 2.0)

        // Connect request
        sock.send([
            0x05, 0x01, 0x00, 0x01,
            10, 0, 0, 100,
            0x00, 0x16
        ])

        let reply = try sock.recv(count: 10, timeout: 2.0)
        XCTAssertEqual(reply[0], 0x05)
        XCTAssertNotEqual(reply[1], 0x00) // Should be a failure code
    }
}

// MARK: - Socket Helper

private class SocketHelper {
    let fd: Int32

    init(fd: Int32) {
        self.fd = fd
        // Set non-blocking isn't needed; we use poll-based recv with timeout
    }

    func send(_ bytes: [UInt8]) {
        bytes.withUnsafeBufferPointer { ptr in
            _ = Foundation.send(fd, ptr.baseAddress!, ptr.count, 0)
        }
    }

    func recv(count: Int, timeout: TimeInterval) throws -> Data {
        var pollFd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        var collected = Data()
        let deadline = Date().addingTimeInterval(timeout)

        while collected.count < count {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else {
                if collected.isEmpty {
                    throw NSError(domain: "SOCKSTest", code: -1, userInfo: [NSLocalizedDescriptionKey: "recv timeout"])
                }
                return collected
            }

            let ms = Int32(remaining * 1000)
            let ret = poll(&pollFd, 1, ms)
            guard ret > 0 else { continue }

            var buf = [UInt8](repeating: 0, count: count - collected.count)
            let n = Foundation.recv(fd, &buf, buf.count, 0)
            if n <= 0 { break }
            collected.append(contentsOf: buf[0..<n])
        }

        return collected
    }

    func close() {
        Foundation.close(fd)
    }
}
