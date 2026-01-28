// VirtualNetwork.swift - IP-to-machineId mapping and routing decisions
//
// VirtualNetwork manages the address space for a mesh-based virtual network.
// It maps IP addresses to machine IDs and makes routing decisions for packets.

import Foundation
import OmertaMesh

/// Virtual network layer that handles IP address mapping and routing decisions.
///
/// Usage:
/// ```swift
/// let vnet = VirtualNetwork(localMachineId: myMachineId)
/// await vnet.setLocalAddress("10.0.0.5")
/// await vnet.registerAddress(ip: "10.0.0.10", machineId: peerMachineId)
///
/// let decision = await vnet.route(destinationIP: "10.0.0.10")
/// // decision == .peer(peerMachineId)
/// ```
public actor VirtualNetwork {
    private let localMachineId: MachineId
    private let config: VirtualNetworkConfig

    private var localIP: String?
    private var addressMap: [String: MachineId] = [:]   // IP -> MachineId
    private var reverseMap: [MachineId: String] = [:]    // MachineId -> IP
    private var gatewayMachineId: MachineId?

    public init(localMachineId: MachineId, config: VirtualNetworkConfig = .default) {
        self.localMachineId = localMachineId
        self.config = config
    }

    /// Set our local IP address
    public func setLocalAddress(_ ip: String) {
        localIP = ip
        addressMap[ip] = localMachineId
        reverseMap[localMachineId] = ip
    }

    /// Register another machine's address (from DHCP or gossip)
    public func registerAddress(ip: String, machineId: MachineId) {
        addressMap[ip] = machineId
        reverseMap[machineId] = ip
    }

    /// Remove a machine's address mapping
    public func removeAddress(machineId: MachineId) {
        if let ip = reverseMap.removeValue(forKey: machineId) {
            addressMap.removeValue(forKey: ip)
        }
    }

    /// Set the gateway machine
    public func setGateway(machineId: MachineId, ip: String) {
        gatewayMachineId = machineId
        registerAddress(ip: ip, machineId: machineId)
    }

    /// Determine where to route a packet
    public func route(destinationIP: String) -> RouteDecision {
        // Is it for us?
        if destinationIP == localIP {
            return .local
        }

        // Do we know this IP?
        if let machineId = addressMap[destinationIP] {
            return .peer(machineId)
        }

        // Is it in our subnet but unknown?
        if isInSubnet(destinationIP) {
            return .drop("Unknown address in subnet: \(destinationIP)")
        }

        // External IP - route to gateway if we have one
        if gatewayMachineId != nil {
            return .gateway
        }

        return .drop("No route to \(destinationIP) (no gateway)")
    }

    /// Lookup machine by IP
    public func lookupMachine(ip: String) -> MachineId? {
        addressMap[ip]
    }

    /// Lookup IP by machine
    public func lookupIP(machineId: MachineId) -> String? {
        reverseMap[machineId]
    }

    /// Get the local IP address
    public func getLocalIP() -> String? {
        localIP
    }

    /// Get the number of registered addresses
    public func addressCount() -> Int {
        addressMap.count
    }

    private func isInSubnet(_ ip: String) -> Bool {
        // Parse subnet and netmask to do proper comparison
        let subnetOctets = parseIPv4(config.subnet)
        let maskOctets = parseIPv4(config.netmask)
        let ipOctets = parseIPv4(ip)

        guard subnetOctets.count == 4, maskOctets.count == 4, ipOctets.count == 4 else {
            return false
        }

        for i in 0..<4 {
            if (ipOctets[i] & maskOctets[i]) != (subnetOctets[i] & maskOctets[i]) {
                return false
            }
        }
        return true
    }

    private func parseIPv4(_ ip: String) -> [UInt8] {
        ip.split(separator: ".").compactMap { UInt8($0) }
    }
}
