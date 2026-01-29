// DemoSOCKSSmokeTest.swift - End-to-end smoke test for the DemoSOCKSGateway stack
//
// Sets up the full SOCKS gateway stack in-process (peer netstack + SOCKS proxy +
// mesh relay + gateway netstack), connects through the SOCKS proxy, makes a real
// HTTP request to example.com, and validates the response.

import XCTest
import Foundation
@testable import OmertaNetwork
@testable import OmertaTunnel
@testable import OmertaMesh

#if canImport(Glibc)
private let SOCK_STREAM_VALUE = Int32(SOCK_STREAM.rawValue)
#else
private let SOCK_STREAM_VALUE = SOCK_STREAM
#endif

final class DemoSOCKSSmokeTest: XCTestCase {

    func testSOCKSGatewayEndToEnd() async throws {
        // --- 1. Create netstack bridges ---

        let peerBridge: NetstackBridge
        let gatewayBridge: NetstackBridge
        do {
            peerBridge = try NetstackBridge(config: .init(gatewayIP: "10.0.0.100"))
            gatewayBridge = try NetstackBridge(config: .init(gatewayIP: "10.200.0.1"))
        } catch {
            throw XCTSkip("NetstackBridge unavailable (libnetstack.a not built?): \(error)")
        }

        // --- 2. Peer node: NetstackInterface + SOCKS proxy ---

        let peerInterface = NetstackInterface(localIP: "10.0.0.100", bridge: peerBridge)
        let peerProvider = E2EChannelProvider(machineId: "peer")
        let peerVNet = VirtualNetwork(localMachineId: "peer")
        await peerVNet.setLocalAddress("10.0.0.100")
        await peerVNet.setGateway(machineId: "gw", ip: "10.0.0.1")

        let peerTunnelManager = TunnelManager(provider: peerProvider)
        try await peerTunnelManager.start()

        let peerRouter = PacketRouter(
            localInterface: peerInterface,
            virtualNetwork: peerVNet,
            tunnelManager: peerTunnelManager
        )

        let socksProxy = SOCKSProxy(port: 0, interface: peerInterface)

        // --- 3. Gateway node ---

        let gwProvider = E2EChannelProvider(machineId: "gw")
        let gwVNet = VirtualNetwork(localMachineId: "gw")
        await gwVNet.setLocalAddress("10.0.0.1")
        await gwVNet.setGateway(machineId: "gw", ip: "10.0.0.1")
        await gwVNet.registerAddress(ip: "10.0.0.100", machineId: "peer")

        let gatewayService = GatewayService(bridge: gatewayBridge)

        let gwTunnelManager = TunnelManager(provider: gwProvider)
        try await gwTunnelManager.start()

        let gwRouter = PacketRouter(
            localInterface: NetstackInterface(localIP: "10.0.0.1", bridge: StubNetstackBridge()),
            virtualNetwork: gwVNet,
            tunnelManager: gwTunnelManager,
            gatewayService: gatewayService
        )

        // --- 4. Wire mesh relay ---

        let relay = E2ERelay()
        await relay.register(machineId: "peer", provider: peerProvider)
        await relay.register(machineId: "gw", provider: gwProvider)
        await relay.startRelay()

        // --- 5. Start everything ---

        try await gatewayService.start()
        try await peerRouter.start()
        try await gwRouter.start()
        try await socksProxy.start()

        let proxyPort = await socksProxy.actualPort
        XCTAssertGreaterThan(proxyPort, 0, "SOCKS proxy should have bound to a port")

        // Allow services to settle
        try await Task.sleep(for: .milliseconds(100))

        // --- 6. Connect to SOCKS proxy and make HTTP request ---

        let httpResponse: String
        do {
            httpResponse = try await withThrowingTaskGroup(of: String.self) { group in
            group.addTask {
                try await self.socksHTTPRequest(
                    proxyHost: "127.0.0.1",
                    proxyPort: proxyPort,
                    targetHost: "example.com",
                    targetPort: 80
                )
            }

            group.addTask {
                try await Task.sleep(for: .seconds(15))
                throw TimeoutError()
            }

            let result = try await group.next()!
            group.cancelAll()
            return result
        }
        } catch {
            // Cleanup on failure
            await socksProxy.stop()
            await peerRouter.stop()
            await gwRouter.stop()
            await gatewayService.stop()
            await peerTunnelManager.stop()
            await gwTunnelManager.stop()
            await relay.stopRelay()
            throw error
        }

        // --- 7. Validate response ---

        XCTAssertTrue(httpResponse.contains("200"), "Response should contain HTTP 200 status")
        XCTAssertTrue(httpResponse.contains("Example Domain"), "Response should contain 'Example Domain'")

        // --- 8. Verify router stats ---

        let peerStats = await peerRouter.getStats()
        XCTAssertGreaterThan(peerStats.packetsToGateway, 0, "Peer should have sent packets to gateway")

        let gwStats = await gwRouter.getStats()
        XCTAssertGreaterThan(gwStats.packetsFromPeers, 0, "Gateway should have received packets from peer")

        // --- 9. Cleanup ---

        await socksProxy.stop()
        await peerRouter.stop()
        await gwRouter.stop()
        await gatewayService.stop()
        await peerTunnelManager.stop()
        await gwTunnelManager.stop()
        await relay.stopRelay()
    }

    // MARK: - SOCKS5 + HTTP Helper

    /// Connects to a SOCKS5 proxy, performs a DOMAINNAME connect, sends an HTTP/1.0 GET,
    /// and returns the full response as a string.
    private func socksHTTPRequest(
        proxyHost: String,
        proxyPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) async throws -> String {
        let sock = try SocketHelper(connectingTo: proxyPort)
        defer { sock.close() }

        // SOCKS5 greeting: version 5, 1 auth method (no auth)
        sock.send([0x05, 0x01, 0x00])

        // Server response: version 5, method 0 (no auth)
        let greetResp = try sock.recv(count: 2, timeout: 5.0)
        guard greetResp.count == 2, greetResp[0] == 0x05, greetResp[1] == 0x00 else {
            throw SOCKSError(message: "SOCKS5 greeting failed: \(Array(greetResp))")
        }

        // SOCKS5 CONNECT request with DOMAINNAME (type 0x03)
        var connectReq: [UInt8] = [
            0x05,                           // version
            0x01,                           // CMD: CONNECT
            0x00,                           // reserved
            0x03,                           // ATYP: DOMAINNAME
            UInt8(targetHost.utf8.count),    // domain length
        ]
        connectReq.append(contentsOf: targetHost.utf8)
        connectReq.append(UInt8(targetPort >> 8))
        connectReq.append(UInt8(targetPort & 0xFF))
        sock.send(connectReq)

        // CONNECT response: at least 10 bytes for IPv4 reply (ver + rep + rsv + atyp + 4 addr + 2 port)
        let connResp = try sock.recv(count: 10, timeout: 10.0)
        guard connResp.count >= 4, connResp[0] == 0x05, connResp[1] == 0x00 else {
            throw SOCKSError(message: "SOCKS5 CONNECT failed with reply: \(Array(connResp))")
        }

        // Send HTTP/1.0 request (connection-close semantics)
        let httpReq = "GET / HTTP/1.0\r\nHost: \(targetHost)\r\n\r\n"
        sock.send(Array(httpReq.utf8))

        // Read full response until EOF
        var responseData = Data()
        while true {
            guard let chunk = try? sock.recv(count: 4096, timeout: 10.0), !chunk.isEmpty else { break }
            responseData.append(chunk)
        }

        return String(data: responseData, encoding: .utf8) ?? ""
    }
}

// MARK: - Socket Helper

private class SocketHelper {
    let fd: Int32

    init(connectingTo port: UInt16) throws {
        fd = socket(AF_INET, SOCK_STREAM_VALUE, 0)
        guard fd >= 0 else { throw SOCKSError(message: "socket: \(errno)") }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Foundation.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            Foundation.close(fd)
            throw SOCKSError(message: "connect: \(errno)")
        }
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
                    throw SOCKSError(message: "recv timeout")
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

// MARK: - Helpers

private struct SOCKSError: Error, CustomStringConvertible {
    let message: String
    var description: String { message }
}

private struct TimeoutError: Error {}

// MARK: - Test Infrastructure (duplicated from RealNetstackIntegrationTests since they're private)

private actor E2EChannelProvider: ChannelProvider {
    let _machineId: MachineId
    private var handlers: [String: @Sendable (MachineId, Data) async -> Void] = [:]
    private(set) var sentMessages: [(data: Data, target: MachineId, channel: String)] = []

    init(machineId: MachineId) {
        self._machineId = machineId
    }

    var peerId: PeerId {
        get async { "peer-\(_machineId)" }
    }

    func onChannel(_ channel: String, handler: @escaping @Sendable (MachineId, Data) async -> Void) async throws {
        handlers[channel] = handler
    }

    func offChannel(_ channel: String) async {
        handlers.removeValue(forKey: channel)
    }

    func sendOnChannel(_ data: Data, to peerId: PeerId, channel: String) async throws {
        let machineId = peerId.hasPrefix("peer-") ? String(peerId.dropFirst(5)) : peerId
        sentMessages.append((data, machineId, channel))
    }

    func sendOnChannel(_ data: Data, toMachine machineId: MachineId, channel: String) async throws {
        sentMessages.append((data, machineId, channel))
    }

    func deliverMessage(_ data: Data, from senderMachineId: MachineId, on channel: String) async {
        if let handler = handlers[channel] {
            await handler(senderMachineId, data)
        }
    }

    func drainSentMessages() -> [(data: Data, target: MachineId, channel: String)] {
        let msgs = sentMessages
        sentMessages.removeAll()
        return msgs
    }

    func clearSentMessages() {
        sentMessages.removeAll()
    }
}

private actor E2ERelay {
    private var providers: [MachineId: E2EChannelProvider] = [:]
    private var relayTask: Task<Void, Never>?

    func register(machineId: MachineId, provider: E2EChannelProvider) {
        providers[machineId] = provider
    }

    func startRelay() {
        relayTask = Task {
            while !Task.isCancelled {
                await relayMessages()
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
    }

    func stopRelay() {
        relayTask?.cancel()
        relayTask = nil
    }

    private func relayMessages() async {
        var pending: [(from: MachineId, to: MachineId, data: Data, channel: String)] = []
        for (machineId, provider) in providers {
            for msg in await provider.drainSentMessages() {
                pending.append((machineId, msg.target, msg.data, msg.channel))
            }
        }
        for msg in pending {
            if let target = providers[msg.to] {
                await target.deliverMessage(msg.data, from: msg.from, on: msg.channel)
            }
        }
    }
}
