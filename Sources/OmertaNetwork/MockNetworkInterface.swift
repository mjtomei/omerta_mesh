// MockNetworkInterface.swift - Mock implementation for testing
//
// Provides a fully controllable network interface for unit tests.
// Test code can inject packets and verify what was sent/received.

import Foundation

/// Mock TCP connection for testing
public actor MockTCPConnection: TCPConnection {
    public let remoteHost: String
    public let remotePort: UInt16

    private var readQueue: [Data] = []
    private var writeQueue: [Data] = []
    private var isClosed = false

    public init(host: String, port: UInt16) {
        self.remoteHost = host
        self.remotePort = port
    }

    public func read() async throws -> Data {
        guard !isClosed else {
            throw InterfaceError.closed
        }
        while readQueue.isEmpty {
            if isClosed { throw InterfaceError.closed }
            try await Task.sleep(for: .milliseconds(10))
        }
        return readQueue.removeFirst()
    }

    public func write(_ data: Data) async throws {
        guard !isClosed else {
            throw InterfaceError.closed
        }
        writeQueue.append(data)
    }

    public func close() async {
        isClosed = true
    }

    // Test helpers
    public func simulateIncoming(_ data: Data) {
        readQueue.append(data)
    }

    public func getWrittenData() -> [Data] {
        let data = writeQueue
        writeQueue = []
        return data
    }
}

/// Mock network interface for testing packet routing
public actor MockNetworkInterface: NetworkInterface {
    public let localIP: String

    private var outboundQueue: [Data] = []
    private var inboundQueue: [Data] = []
    private var isRunning = false

    // For dialTCP tracking
    private var connections: [(host: String, port: UInt16, connection: MockTCPConnection)] = []

    // Continuation for async packet reading
    private var readContinuation: CheckedContinuation<Data, Error>?

    public init(localIP: String) {
        self.localIP = localIP
    }

    public func start() async throws {
        guard !isRunning else {
            throw InterfaceError.alreadyStarted
        }
        isRunning = true
    }

    public func stop() async {
        isRunning = false
        readContinuation?.resume(throwing: InterfaceError.closed)
        readContinuation = nil
    }

    public func readPacket() async throws -> Data {
        guard isRunning else {
            throw InterfaceError.notStarted
        }

        // Return immediately if packet available
        if !outboundQueue.isEmpty {
            return outboundQueue.removeFirst()
        }

        // Wait for a packet
        return try await withCheckedThrowingContinuation { continuation in
            self.readContinuation = continuation
        }
    }

    public func writePacket(_ packet: Data) async throws {
        guard isRunning else {
            throw InterfaceError.notStarted
        }
        inboundQueue.append(packet)
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection? {
        let conn = MockTCPConnection(host: host, port: port)
        connections.append((host, port, conn))
        return conn
    }

    // MARK: - Test Helpers

    /// Simulate an app sending a packet (for outbound testing)
    public func simulateAppSend(_ packet: Data) {
        outboundQueue.append(packet)

        // Resume waiting reader if any
        if let continuation = readContinuation {
            readContinuation = nil
            continuation.resume(returning: outboundQueue.removeFirst())
        }
    }

    /// Get packets delivered to apps (for inbound testing)
    public func getAppReceived() -> Data? {
        inboundQueue.isEmpty ? nil : inboundQueue.removeFirst()
    }

    /// Get all packets delivered to apps
    public func getAllAppReceived() -> [Data] {
        let data = inboundQueue
        inboundQueue = []
        return data
    }

    /// Get the number of packets waiting to be read
    public func pendingOutboundCount() -> Int {
        outboundQueue.count
    }

    /// Get the number of packets delivered to apps
    public func receivedInboundCount() -> Int {
        inboundQueue.count
    }

    /// Get all TCP connections that were dialed
    public func getDialedConnections() -> [(host: String, port: UInt16)] {
        connections.map { ($0.host, $0.port) }
    }

    /// Get a specific mock connection for test control
    public func getMockConnection(host: String, port: UInt16) -> MockTCPConnection? {
        connections.first { $0.host == host && $0.port == port }?.connection
    }

    /// Clear all queues and connections
    public func reset() {
        outboundQueue = []
        inboundQueue = []
        connections = []
    }
}
