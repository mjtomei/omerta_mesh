import Foundation
import OmertaMesh

// MARK: - IP Protocol

public enum IPProtocol: Equatable, Hashable, Sendable {
    case tcp
    case udp
    case other(UInt8)

    init(rawValue: UInt8) {
        switch rawValue {
        case 6: self = .tcp
        case 17: self = .udp
        default: self = .other(rawValue)
        }
    }

    var rawValue: UInt8 {
        switch self {
        case .tcp: return 6
        case .udp: return 17
        case .other(let v): return v
        }
    }
}

// MARK: - NAT Key & Entry

public struct NATKey: Hashable, Sendable {
    public let srcIP: UInt32
    public let srcPort: UInt16
    public let dstIP: UInt32
    public let dstPort: UInt16
    public let proto: IPProtocol

    public func reversed() -> NATKey {
        NATKey(srcIP: dstIP, srcPort: dstPort, dstIP: srcIP, dstPort: srcPort, proto: proto)
    }
}

public struct NATEntry: Sendable {
    public let machineId: MachineId
    public let createdAt: Date
}

// MARK: - GatewayService

public actor GatewayService {
    private let bridge: any NetstackBridgeProtocol
    private let natTimeout: TimeInterval
    private var natTable: [NATKey: NATEntry] = [:]
    private var returnHandler: (@Sendable (Data, MachineId) async -> Void)?
    private var running = false

    public init(bridge: any NetstackBridgeProtocol, natTimeout: TimeInterval = 120) {
        self.bridge = bridge
        self.natTimeout = natTimeout
    }

    public func start() async throws {
        running = true
        await bridge.setReturnCallback { [weak self] packet in
            guard let self else { return }
            Task { await self.handleReturnPacket(packet) }
        }
        try await bridge.start()
    }

    public func stop() async {
        running = false
        await bridge.stop()
    }

    public func setReturnHandler(_ handler: @escaping @Sendable (Data, MachineId) async -> Void) {
        self.returnHandler = handler
    }

    public func forwardToInternet(_ packet: Data, from machineId: MachineId) async {
        guard running else { return }
        guard let key = Self.extractNATKey(from: packet) else { return }

        switch key.proto {
        case .tcp, .udp:
            natTable[key] = NATEntry(machineId: machineId, createdAt: Date())
        case .other:
            break
        }

        try? await bridge.injectPacket(packet)
    }

    public func natEntryCount() -> Int {
        natTable.count
    }

    public func cleanupExpiredEntries() {
        let cutoff = Date().addingTimeInterval(-natTimeout)
        natTable = natTable.filter { $0.value.createdAt > cutoff }
    }

    // MARK: - Private

    private func handleReturnPacket(_ packet: Data) async {
        guard let key = Self.extractNATKey(from: packet) else { return }
        let reverseKey = key.reversed()

        guard let entry = natTable[reverseKey] else { return }
        await returnHandler?(packet, entry.machineId)
    }

    // MARK: - Packet Parsing

    static func extractNATKey(from packet: Data) -> NATKey? {
        guard packet.count >= 20 else { return nil }
        let versionIHL = packet[packet.startIndex]
        guard (versionIHL >> 4) == 4 else { return nil }

        let ihl = Int(versionIHL & 0x0F) * 4
        let proto = IPProtocol(rawValue: packet[packet.startIndex + 9])

        let srcIP = readUInt32(packet, offset: 12)
        let dstIP = readUInt32(packet, offset: 16)

        switch proto {
        case .tcp, .udp:
            guard packet.count >= ihl + 4 else { return nil }
            let srcPort = readUInt16(packet, offset: ihl)
            let dstPort = readUInt16(packet, offset: ihl + 2)
            return NATKey(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: proto)
        case .other:
            return NATKey(srcIP: srcIP, srcPort: 0, dstIP: dstIP, dstPort: 0, proto: proto)
        }
    }

    private static func readUInt32(_ data: Data, offset: Int) -> UInt32 {
        let base = data.startIndex + offset
        return UInt32(data[base]) << 24
             | UInt32(data[base + 1]) << 16
             | UInt32(data[base + 2]) << 8
             | UInt32(data[base + 3])
    }

    private static func readUInt16(_ data: Data, offset: Int) -> UInt16 {
        let base = data.startIndex + offset
        return UInt16(data[base]) << 8 | UInt16(data[base + 1])
    }
}
