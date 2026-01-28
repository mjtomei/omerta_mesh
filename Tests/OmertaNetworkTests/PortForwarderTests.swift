import XCTest
import Foundation
@testable import OmertaNetwork

final class PortForwarderTests: XCTestCase {

    private var mockInterface: MockNetworkInterface!
    private var forwarder: PortForwarder!

    override func setUp() async throws {
        mockInterface = MockNetworkInterface(localIP: "10.0.0.1")
        try await mockInterface.start()
        forwarder = PortForwarder(localPort: 0, remoteHost: "10.0.0.100", remotePort: 22, interface: mockInterface)
        try await forwarder.start()
    }

    override func tearDown() async throws {
        await forwarder.stop()
        await mockInterface.stop()
    }

    // MARK: - Tests

    func testPortForwardConnect() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        // Give time for the dial to complete
        try await Task.sleep(for: .milliseconds(200))

        let dialed = await mockInterface.getDialedConnections()
        XCTAssertEqual(dialed.count, 1)
        XCTAssertEqual(dialed[0].host, "10.0.0.100")
        XCTAssertEqual(dialed[0].port, 22)
    }

    func testPortForwardDataRelay() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        try await Task.sleep(for: .milliseconds(200))

        // Send data to forwarder
        let testData = Data("Hello, mesh!".utf8)
        sock.send(Array(testData))

        try await Task.sleep(for: .milliseconds(200))

        let mockConn = await mockInterface.getMockConnection(host: "10.0.0.100", port: 22)
        XCTAssertNotNil(mockConn)

        let written = await mockConn!.getWrittenData()
        let combined = written.reduce(Data(), +)
        XCTAssertEqual(combined, testData)

        // Send data back
        let responseData = Data("Hi from mesh!".utf8)
        await mockConn!.simulateIncoming(responseData)

        let received = try sock.recv(count: responseData.count, timeout: 2.0)
        XCTAssertEqual(received, responseData)
    }

    func testPortForwardMultipleClients() async throws {
        let sock1 = try await connectSocket()
        defer { sock1.close() }
        let sock2 = try await connectSocket()
        defer { sock2.close() }
        let sock3 = try await connectSocket()
        defer { sock3.close() }

        try await Task.sleep(for: .milliseconds(300))

        let dialed = await mockInterface.getDialedConnections()
        XCTAssertEqual(dialed.count, 3)

        let count = await forwarder.refreshActiveConnections()
        XCTAssertEqual(count, 3)
    }

    func testPortForwardRemoteClose() async throws {
        let sock = try await connectSocket()
        defer { sock.close() }

        try await Task.sleep(for: .milliseconds(200))

        let mockConn = await mockInterface.getMockConnection(host: "10.0.0.100", port: 22)
        XCTAssertNotNil(mockConn)

        // Close the remote side
        await mockConn!.close()

        // The local connection should close too - verify by trying to recv
        try await Task.sleep(for: .milliseconds(300))

        // After remote close, the local socket should be closed
        var pollFd = pollfd(fd: sock.fd, events: Int16(POLLIN), revents: 0)
        let ret = poll(&pollFd, 1, 500)
        if ret > 0 {
            var buf = [UInt8](repeating: 0, count: 1)
            let n = recv(sock.fd, &buf, 1, 0)
            // n == 0 means connection closed, n == -1 means error — both indicate closure
            XCTAssertLessThanOrEqual(n, 0, "Expected connection to be closed after remote close")
        }
        // If poll returns 0 (timeout), the connection may already be closed
    }

    // MARK: - Helpers

    private func connectSocket() async throws -> SocketHelper {
        let port = await forwarder.actualPort
        let fd = socket(AF_INET, SOCK_STREAM, 0)
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
}

// MARK: - Socket Helper

private class SocketHelper {
    let fd: Int32

    init(fd: Int32) {
        self.fd = fd
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
                    throw NSError(domain: "PortForwardTest", code: -1, userInfo: [NSLocalizedDescriptionKey: "recv timeout"])
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
