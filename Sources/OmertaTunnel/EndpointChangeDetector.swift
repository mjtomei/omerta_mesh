// EndpointChangeDetector.swift - OS-level network change monitoring
//
// Monitors network interface changes and emits EndpointChange events.
// Uses NWPathMonitor on Darwin and netlink sockets on Linux.

import Foundation
#if canImport(Network)
import Network
#endif
#if canImport(Glibc)
import Glibc
#endif

/// Reason for an endpoint change
public enum ChangeReason: Sendable {
    case networkSwitch
    case ipChange
    case interfaceDown
    case interfaceUp
}

/// Represents a detected network endpoint change
public struct EndpointChange: Sendable {
    public let oldEndpoint: String?
    public let newEndpoint: String?
    public let reason: ChangeReason
    public let timestamp: ContinuousClock.Instant

    public init(oldEndpoint: String?, newEndpoint: String?, reason: ChangeReason, timestamp: ContinuousClock.Instant = .now) {
        self.oldEndpoint = oldEndpoint
        self.newEndpoint = newEndpoint
        self.reason = reason
        self.timestamp = timestamp
    }
}

public actor EndpointChangeDetector {
    private var isRunning = false
    private var continuation: AsyncStream<EndpointChange>.Continuation?
    private var _changes: AsyncStream<EndpointChange>?
    private var monitorTask: Task<Void, Never>?
    private var lastEndpoint: String?

    public init() {}

    public var changes: AsyncStream<EndpointChange> {
        if let existing = _changes {
            return existing
        }
        let (stream, continuation) = AsyncStream<EndpointChange>.makeStream()
        self.continuation = continuation
        self._changes = stream
        return stream
    }

    public func start() async {
        guard !isRunning else { return }
        isRunning = true

        // Ensure stream is set up
        _ = changes

        monitorTask = Task { [weak self] in
            await self?.platformMonitor()
        }
    }

    public func stop() async {
        guard isRunning else { return }
        isRunning = false
        monitorTask?.cancel()
        monitorTask = nil
        continuation?.finish()
        continuation = nil
        _changes = nil
    }

    /// Emit a change event (also used for testing)
    func emit(_ change: EndpointChange) {
        continuation?.yield(change)
    }

    // MARK: - Platform-specific monitoring

    private func platformMonitor() async {
        #if canImport(Network)
        await darwinMonitor()
        #elseif os(Linux)
        await linuxMonitor()
        #endif
    }

    #if canImport(Network)
    private func darwinMonitor() async {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "io.omerta.endpoint-change")

        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            var resumed = false
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                Task {
                    await self.handlePathUpdate(path)
                    if !resumed {
                        resumed = true
                        cont.resume()
                    }
                }
            }
            monitor.start(queue: queue)

            Task {
                try? await Task.sleep(for: .milliseconds(100))
                if !resumed {
                    resumed = true
                    cont.resume()
                }
            }
        }

        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(1))
        }
        monitor.cancel()
    }

    private func handlePathUpdate(_ path: NWPath) {
        let newEndpoint: String?
        if path.status == .satisfied {
            newEndpoint = path.availableInterfaces.first?.name
        } else {
            newEndpoint = nil
        }

        let old = lastEndpoint
        lastEndpoint = newEndpoint

        let reason: ChangeReason
        if old == nil && newEndpoint != nil {
            reason = .interfaceUp
        } else if old != nil && newEndpoint == nil {
            reason = .interfaceDown
        } else if old != newEndpoint {
            reason = .networkSwitch
        } else {
            return
        }

        emit(EndpointChange(oldEndpoint: old, newEndpoint: newEndpoint, reason: reason))
    }
    #endif

    #if os(Linux)
    private func linuxMonitor() async {
        // Poll interface addresses for changes
        lastEndpoint = linuxGetPrimaryAddress()
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { break }

            let newEndpoint = linuxGetPrimaryAddress()
            let old = lastEndpoint

            if old != newEndpoint {
                lastEndpoint = newEndpoint
                let reason: ChangeReason
                if old == nil && newEndpoint != nil {
                    reason = .interfaceUp
                } else if old != nil && newEndpoint == nil {
                    reason = .interfaceDown
                } else {
                    reason = .ipChange
                }
                emit(EndpointChange(oldEndpoint: old, newEndpoint: newEndpoint, reason: reason))
            }
        }
    }

    private nonisolated func linuxGetPrimaryAddress() -> String? {
        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0, let first = addrs else { return nil }
        defer { freeifaddrs(first) }

        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = current {
            let name = String(cString: ifa.pointee.ifa_name)
            if name != "lo", let addr = ifa.pointee.ifa_addr, addr.pointee.sa_family == UInt16(AF_INET) {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                getnameinfo(addr, socklen_t(MemoryLayout<sockaddr_in>.size),
                           &hostname, socklen_t(hostname.count),
                           nil, 0, NI_NUMERICHOST)
                return String(cString: hostname)
            }
            current = ifa.pointee.ifa_next.map { UnsafeMutablePointer($0) }
        }
        return nil
    }
    #endif
}
