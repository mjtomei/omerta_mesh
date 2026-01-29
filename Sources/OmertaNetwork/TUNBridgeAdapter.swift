// TUNBridgeAdapter.swift - Adapts TUNInterface to NetstackBridgeProtocol
//
// Wraps a TUNInterface so GatewayService can use a TUN device as its internet
// exit instead of a gVisor netstack. No read loop needed — packets flow directly
// from TUNInterface's DispatchSource to GatewayService via the onPacket callback.

#if os(Linux)
import Foundation

public actor TUNBridgeAdapter: NetstackBridgeProtocol {
    private let tun: TUNInterface

    public init(tun: TUNInterface) {
        self.tun = tun
    }

    public func start() async throws {
        try await tun.start()
    }

    public func stop() async {
        await tun.stop()
    }

    public func injectPacket(_ packet: Data) async throws {
        try await tun.writePacket(packet)
    }

    public func setReturnCallback(_ callback: @escaping @Sendable (Data) -> Void) async {
        await tun.setPacketCallback(callback)
    }

    public func dialTCP(host: String, port: UInt16) async throws -> TCPConnection {
        throw InterfaceError.notSupported
    }
}
#endif
