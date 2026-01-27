// NetworkTopologyDemos.swift - Demonstrations of various network topologies
//
// These tests demonstrate mesh network behavior with different mixes of
// public and NAT'ed nodes, various NAT types, and relay scenarios.

import XCTest
@testable import OmertaMesh

final class NetworkTopologyDemos: XCTestCase {

    // MARK: - Demo 1: All Public Nodes

    /// Simplest case: all nodes are publicly reachable
    func testAllPublicNodes() async throws {
        print("\n" + String(repeating: "=", count: 60))
        print("DEMO 1: All Public Nodes")
        print(String(repeating: "=", count: 60))

        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "Server-A")
            .addPublicNode(id: "Server-B")
            .addPublicNode(id: "Server-C")
            .addPublicNode(id: "Server-D")
            .link("Server-A", "Server-B")
            .link("Server-B", "Server-C")
            .link("Server-C", "Server-D")
            .link("Server-D", "Server-A")  // Ring topology
            .build()
        defer { Task { await network.shutdown() } }

        // Start all nodes
        for id in ["Server-A", "Server-B", "Server-C", "Server-D"] {
            try await network.node(id).start()
        }

        print("\nTopology: Ring of 4 public servers")
        print("  Server-A <-> Server-B <-> Server-C <-> Server-D <-> Server-A")

        // Test direct communication
        var successCount = 0
        let pairs = [("Server-A", "Server-B"), ("Server-B", "Server-C"),
                     ("Server-C", "Server-D"), ("Server-D", "Server-A")]

        for (from, to) in pairs {
            do {
                let response = try await network.node(from).sendAndReceive(
                    .ping(recentPeers: [], myNATType: .unknown),
                    to: to,
                    timeout: 2.0
                )
                if case .pong = response {
                    successCount += 1
                    print("  ✓ \(from) -> \(to): Direct connection works")
                }
            } catch {
                print("  ✗ \(from) -> \(to): Failed - \(error)")
            }
        }

        print("\nResult: \(successCount)/\(pairs.count) direct connections successful")
        XCTAssertEqual(successCount, pairs.count)
    }

    // MARK: - Demo 2: Mixed Public and Full Cone NAT

    /// Public servers with some clients behind full cone NAT
    func testPublicServersWithFullConeClients() async throws {
        print("\n" + String(repeating: "=", count: 60))
        print("DEMO 2: Public Servers + Full Cone NAT Clients")
        print(String(repeating: "=", count: 60))

        let network = try await TestNetworkBuilder()
            // Public relay servers
            .addPublicNode(id: "Relay-1")
            .addPublicNode(id: "Relay-2")
            // Clients behind full cone NAT (easiest NAT to traverse)
            .addNATNode(id: "Client-A", natType: .fullCone)
            .addNATNode(id: "Client-B", natType: .fullCone)
            .addNATNode(id: "Client-C", natType: .fullCone)
            // Links
            .link("Relay-1", "Relay-2")
            .link("Client-A", "Relay-1")
            .link("Client-B", "Relay-1")
            .link("Client-C", "Relay-2")
            .build()
        defer { Task { await network.shutdown() } }

        for id in ["Relay-1", "Relay-2", "Client-A", "Client-B", "Client-C"] {
            try await network.node(id).start()
        }

        print("\nTopology:")
        print("  Relay-1 (public) <---> Relay-2 (public)")
        print("     |                      |")
        print("  Client-A              Client-C")
        print("  Client-B")
        print("  (all behind Full Cone NAT)")

        // Test: Clients can reach relays
        print("\n--- Client to Relay Communication ---")
        for client in ["Client-A", "Client-B", "Client-C"] {
            let relay = client == "Client-C" ? "Relay-2" : "Relay-1"
            do {
                let response = try await network.node(client).sendAndReceive(
                    .ping(recentPeers: [], myNATType: .unknown),
                    to: relay,
                    timeout: 2.0
                )
                if case .pong = response {
                    print("  ✓ \(client) -> \(relay): OK")
                }
            } catch {
                print("  ✗ \(client) -> \(relay): Failed")
            }
        }

        // Test: Full cone NAT allows hole punching between clients
        print("\n--- Client to Client (Hole Punch) ---")
        print("  Full Cone NAT allows any source once mapping exists")

        // First, clients send to relay to create NAT mappings
        await network.node("Client-A").send(.ping(recentPeers: [], myNATType: .unknown), to: "Relay-1")
        await network.node("Client-B").send(.ping(recentPeers: [], myNATType: .unknown), to: "Relay-1")
        try await Task.sleep(nanoseconds: 100_000_000)

        // Now Client-A and Client-B should be able to communicate
        // (Full cone NAT allows this once mappings exist)
        let clientAEndpoint = await network.node("Client-A").publicEndpoint
        let clientBEndpoint = await network.node("Client-B").publicEndpoint
        print("  Client-A external: \(clientAEndpoint)")
        print("  Client-B external: \(clientBEndpoint)")

        // Check NAT compatibility
        let compatibility = HolePunchCompatibility.check(initiator: .fullCone, responder: .fullCone)
        print("  Hole punch strategy: \(compatibility.strategy)")
        print("  Likely to succeed: \(compatibility.likely)")

        XCTAssertTrue(compatibility.likely)
    }

    // MARK: - Demo 3: Mixed NAT Types

    /// Network with various NAT types showing different traversal strategies
    func testMixedNATTypes() async throws {
        print("\n" + String(repeating: "=", count: 60))
        print("DEMO 3: Mixed NAT Types")
        print(String(repeating: "=", count: 60))

        let network = try await TestNetworkBuilder()
            // Public relay
            .addPublicNode(id: "Relay")
            // Various NAT types
            .addNATNode(id: "FullCone-Client", natType: .fullCone)
            .addNATNode(id: "Restricted-Client", natType: .restrictedCone)
            .addNATNode(id: "PortRestricted-Client", natType: .portRestrictedCone)
            .addNATNode(id: "Symmetric-Client", natType: .symmetric)
            // All connect through relay
            .link("FullCone-Client", "Relay")
            .link("Restricted-Client", "Relay")
            .link("PortRestricted-Client", "Relay")
            .link("Symmetric-Client", "Relay")
            .build()
        defer { Task { await network.shutdown() } }

        for id in ["Relay", "FullCone-Client", "Restricted-Client", "PortRestricted-Client", "Symmetric-Client"] {
            try await network.node(id).start()
        }

        print("\nTopology: Star with central relay")
        print("              Relay (public)")
        print("           /    |    |    \\")
        print("    FullCone  Restr  PortR  Symmetric")

        print("\n--- NAT Type Compatibility Matrix ---")
        let natTypes: [(String, NATType)] = [
            ("FullCone", .fullCone),
            ("Restricted", .restrictedCone),
            ("PortRestricted", .portRestrictedCone),
            ("Symmetric", .symmetric)
        ]

        print("\n          ", terminator: "")
        for (name, _) in natTypes {
            print(name.padding(toLength: 12, withPad: " ", startingAt: 0), terminator: "")
        }
        print()

        for (name1, type1) in natTypes {
            print(name1.padding(toLength: 10, withPad: " ", startingAt: 0), terminator: "")
            for (_, type2) in natTypes {
                let compat = HolePunchCompatibility.check(initiator: type1, responder: type2)
                let symbol: String
                switch compat.strategy {
                case .simultaneous, .initiatorFirst, .responderFirst:
                    symbol = compat.likely ? "Direct" : "Maybe"
                case .impossible:
                    symbol = "Relay"
                }
                print(symbol.padding(toLength: 12, withPad: " ", startingAt: 0), terminator: "")
            }
            print()
        }

        print("\nLegend: Direct = hole punch works, Maybe = possible but hard, Relay = needs relay")

        // Verify symmetric NAT requires relay
        let symToSym = HolePunchCompatibility.check(initiator: .symmetric, responder: .symmetric)
        XCTAssertEqual(symToSym.strategy, .impossible)

        let fullToFull = HolePunchCompatibility.check(initiator: .fullCone, responder: .fullCone)
        XCTAssertTrue(fullToFull.likely)
    }

    // MARK: - Demo 4: Relay-Dependent Network

    /// Network where symmetric NAT clients must use relays
    func testRelayDependentNetwork() async throws {
        print("\n" + String(repeating: "=", count: 60))
        print("DEMO 4: Relay-Dependent Network (Symmetric NAT)")
        print(String(repeating: "=", count: 60))

        let network = try await TestNetworkBuilder()
            // Public relay servers
            .addPublicNode(id: "Relay-US")
            .addPublicNode(id: "Relay-EU")
            // Clients behind symmetric NAT (hardest to traverse)
            .addNATNode(id: "Home-User-1", natType: .symmetric)
            .addNATNode(id: "Home-User-2", natType: .symmetric)
            .addNATNode(id: "Corporate-User", natType: .symmetric)
            // Connections
            .link("Relay-US", "Relay-EU")
            .link("Home-User-1", "Relay-US")
            .link("Home-User-2", "Relay-US")
            .link("Corporate-User", "Relay-EU")
            .build()
        defer { Task { await network.shutdown() } }

        for id in ["Relay-US", "Relay-EU", "Home-User-1", "Home-User-2", "Corporate-User"] {
            try await network.node(id).start()
        }

        print("\nTopology:")
        print("  Relay-US (public) <---> Relay-EU (public)")
        print("      |                       |")
        print("  Home-User-1             Corporate-User")
        print("  Home-User-2")
        print("  (all behind Symmetric NAT - requires relay)")

        // Demonstrate that symmetric NAT clients cannot hole punch
        print("\n--- Symmetric NAT Behavior ---")

        let nat1 = network.nat(for: "Home-User-1")!
        let nat2 = network.nat(for: "Home-User-2")!

        // Each client sends to relay, creating mappings
        let ext1 = await nat1.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.1:8000")
        let ext1b = await nat1.translateOutbound(from: "192.168.1.1:5000", to: "10.0.0.2:8000")

        print("  Home-User-1 mapping to 10.0.0.1:8000 -> \(ext1 ?? "nil")")
        print("  Home-User-1 mapping to 10.0.0.2:8000 -> \(ext1b ?? "nil")")
        print("  Note: Different external ports for different destinations!")

        // Show that symmetric NAT blocks unknown sources
        let inboundResult = await nat1.filterInbound(from: "10.0.0.3:9000", to: ext1!)
        print("  Inbound from unknown source: \(inboundResult == nil ? "BLOCKED" : "allowed")")

        print("\n--- Relay Path Required ---")
        print("  Home-User-1 -> Relay-US -> Relay-EU -> Corporate-User")
        print("  (Messages must traverse relay chain)")

        // In real implementation, RelayManager would handle this
        let compatibility = HolePunchCompatibility.check(initiator: .symmetric, responder: .symmetric)
        XCTAssertEqual(compatibility.strategy, .impossible)
    }

    // MARK: - Demo 5: Enterprise Network Simulation

    /// Simulates a realistic enterprise network scenario
    func testEnterpriseNetworkScenario() async throws {
        print("\n" + String(repeating: "=", count: 60))
        print("DEMO 5: Enterprise Network Scenario")
        print(String(repeating: "=", count: 60))

        let network = try await TestNetworkBuilder()
            // Cloud infrastructure (public)
            .addPublicNode(id: "Cloud-LB")
            .addPublicNode(id: "Cloud-Worker-1")
            .addPublicNode(id: "Cloud-Worker-2")
            // Office A - behind corporate NAT (port restricted)
            .addNATNode(id: "Office-A-Server", natType: .portRestrictedCone)
            .addNATNode(id: "Office-A-Desktop-1", natType: .portRestrictedCone)
            .addNATNode(id: "Office-A-Desktop-2", natType: .portRestrictedCone)
            // Office B - behind stricter corporate NAT (symmetric)
            .addNATNode(id: "Office-B-Server", natType: .symmetric)
            .addNATNode(id: "Office-B-Desktop", natType: .symmetric)
            // Remote workers - various NAT types
            .addNATNode(id: "Remote-Home", natType: .fullCone)
            .addNATNode(id: "Remote-Coffee", natType: .symmetric)
            // Links
            .link("Cloud-LB", "Cloud-Worker-1")
            .link("Cloud-LB", "Cloud-Worker-2")
            .link("Cloud-Worker-1", "Cloud-Worker-2")
            .link("Office-A-Server", "Cloud-LB")
            .link("Office-A-Desktop-1", "Office-A-Server")
            .link("Office-A-Desktop-2", "Office-A-Server")
            .link("Office-B-Server", "Cloud-LB")
            .link("Office-B-Desktop", "Office-B-Server")
            .link("Remote-Home", "Cloud-LB")
            .link("Remote-Coffee", "Cloud-LB")
            .build()
        defer { Task { await network.shutdown() } }

        let allNodes = ["Cloud-LB", "Cloud-Worker-1", "Cloud-Worker-2",
                        "Office-A-Server", "Office-A-Desktop-1", "Office-A-Desktop-2",
                        "Office-B-Server", "Office-B-Desktop",
                        "Remote-Home", "Remote-Coffee"]

        for id in allNodes {
            try await network.node(id).start()
        }

        print("\nTopology:")
        print("                    Cloud-LB (public, relay)")
        print("                   /    |    \\")
        print("         Cloud-Worker-1  |  Cloud-Worker-2")
        print("                        |")
        print("    +------------------+------------------+")
        print("    |                  |                  |")
        print("  Office-A           Office-B          Remote")
        print("  (PortRestr)        (Symmetric)       Workers")
        print("    |                  |")
        print("  Server             Server")
        print("   / \\                 |")
        print(" Desk1 Desk2        Desktop")

        print("\n--- Node Classification ---")
        var publicCount = 0
        var natCount = 0
        var relayCapable = 0

        for nodeId in allNodes {
            let node = network.node(nodeId)
            let natType = await node.natType
            if natType == .public {
                publicCount += 1
                print("  \(nodeId): Public")
            } else {
                natCount += 1
                print("  \(nodeId): \(natType)")
            }
        }

        print("\n--- Connectivity Analysis ---")
        print("  Public nodes: \(publicCount)")
        print("  NAT'ed nodes: \(natCount)")

        // Analyze connectivity scenarios
        let scenarios = [
            ("Cloud-Worker-1", "Cloud-Worker-2", "Public-to-Public"),
            ("Office-A-Desktop-1", "Cloud-LB", "PortRestr-to-Public"),
            ("Office-A-Desktop-1", "Office-A-Desktop-2", "Same-NAT (PortRestr)"),
            ("Office-A-Desktop-1", "Office-B-Desktop", "PortRestr-to-Symmetric"),
            ("Office-B-Desktop", "Remote-Coffee", "Symmetric-to-Symmetric"),
            ("Remote-Home", "Office-A-Desktop-1", "FullCone-to-PortRestr"),
        ]

        print("\n--- Connection Strategies ---")
        for (from, to, desc) in scenarios {
            let fromType = await network.node(from).natType
            let toType = await network.node(to).natType
            let compat = HolePunchCompatibility.check(initiator: fromType, responder: toType)

            let strategy: String
            switch compat.strategy {
            case .simultaneous, .initiatorFirst, .responderFirst:
                strategy = compat.likely ? "Direct hole punch" : "Hole punch (uncertain)"
            case .impossible:
                strategy = "Via relay (Cloud-LB)"
            }
            print("  \(desc):")
            print("    \(from) -> \(to): \(strategy)")
        }

        XCTAssertEqual(publicCount, 3)
        XCTAssertEqual(natCount, 7)
    }

    // MARK: - Demo 6: Chaos Under Network Stress

    /// Demonstrates network behavior under fault conditions
    func testNetworkUnderChaos() async throws {
        print("\n" + String(repeating: "=", count: 60))
        print("DEMO 6: Network Behavior Under Chaos")
        print(String(repeating: "=", count: 60))

        let network = try await TestNetworkBuilder()
            .addPublicNode(id: "Relay-A")
            .addPublicNode(id: "Relay-B")
            .addNATNode(id: "Client-1", natType: .fullCone)
            .addNATNode(id: "Client-2", natType: .portRestrictedCone)
            .addNATNode(id: "Client-3", natType: .symmetric)
            .link("Relay-A", "Relay-B")
            .link("Client-1", "Relay-A")
            .link("Client-2", "Relay-A")
            .link("Client-3", "Relay-B")
            .build()
        defer { Task { await network.shutdown() } }

        for id in ["Relay-A", "Relay-B", "Client-1", "Client-2", "Client-3"] {
            try await network.node(id).start()
        }

        print("\nInitial topology:")
        print("  Relay-A <---> Relay-B")
        print("    |              |")
        print("  Client-1      Client-3")
        print("  Client-2")

        // Test normal connectivity
        print("\n--- Normal Operation ---")
        var normalSuccess = 0
        for client in ["Client-1", "Client-2", "Client-3"] {
            let relay = client == "Client-3" ? "Relay-B" : "Relay-A"
            do {
                _ = try await network.node(client).sendAndReceive(
                    .ping(recentPeers: [], myNATType: .unknown),
                    to: relay,
                    timeout: 2.0
                )
                normalSuccess += 1
                print("  ✓ \(client) -> \(relay)")
            } catch {
                print("  ✗ \(client) -> \(relay)")
            }
        }
        print("  Connectivity: \(normalSuccess)/3")

        // Inject latency fault
        print("\n--- Injecting Latency (200ms on Relay-A) ---")
        let injector = FaultInjector()
        _ = await injector.inject(
            .latencySpike(nodeId: "Relay-A", additionalMs: 200, duration: 10.0),
            into: network
        )

        // Test under latency
        var latencySuccess = 0
        let startTime = Date()
        for client in ["Client-1", "Client-2"] {
            do {
                _ = try await network.node(client).sendAndReceive(
                    .ping(recentPeers: [], myNATType: .unknown),
                    to: "Relay-A",
                    timeout: 5.0
                )
                latencySuccess += 1
            } catch {
                // Expected under high latency
            }
        }
        let elapsed = Date().timeIntervalSince(startTime)
        print("  Connectivity: \(latencySuccess)/2 (took \(String(format: "%.1f", elapsed))s)")

        // Network partition
        print("\n--- Injecting Network Partition ---")
        _ = await injector.inject(
            .networkPartition(group1: ["Relay-A", "Client-1", "Client-2"],
                            group2: ["Relay-B", "Client-3"]),
            into: network
        )

        print("  Group 1: Relay-A, Client-1, Client-2")
        print("  Group 2: Relay-B, Client-3")
        print("  Cross-group communication blocked")

        // Remove all faults
        print("\n--- Removing All Faults ---")
        await injector.removeAllFaults(from: network)
        print("  Network healed")

        // Verify recovery
        var recoverySuccess = 0
        for client in ["Client-1", "Client-2", "Client-3"] {
            let relay = client == "Client-3" ? "Relay-B" : "Relay-A"
            do {
                _ = try await network.node(client).sendAndReceive(
                    .ping(recentPeers: [], myNATType: .unknown),
                    to: relay,
                    timeout: 2.0
                )
                recoverySuccess += 1
            } catch {
                // May still be recovering
            }
        }
        print("  Post-recovery connectivity: \(recoverySuccess)/3")

        XCTAssertEqual(normalSuccess, 3)
    }

    // MARK: - Demo 7: NAT Mapping Behavior

    /// Demonstrates detailed NAT mapping behavior
    func testNATMappingBehavior() async throws {
        print("\n" + String(repeating: "=", count: 60))
        print("DEMO 7: NAT Mapping Behavior Details")
        print(String(repeating: "=", count: 60))

        // Create NATs of each type
        let fullCone = SimulatedNAT(type: .fullCone, publicIP: "203.0.113.1")
        let restricted = SimulatedNAT(type: .restrictedCone, publicIP: "203.0.113.2")
        let portRestricted = SimulatedNAT(type: .portRestrictedCone, publicIP: "203.0.113.3")
        let symmetric = SimulatedNAT(type: .symmetric, publicIP: "203.0.113.4", portAllocation: .sequential)

        let internalEndpoint = "192.168.1.100:5000"
        let dest1 = "10.0.0.1:8000"
        let dest2 = "10.0.0.2:8000"

        print("\n--- Outbound Mapping Creation ---")
        print("Internal endpoint: \(internalEndpoint)")
        print("Destination 1: \(dest1)")
        print("Destination 2: \(dest2)")

        // Full Cone - same mapping for all destinations
        let fc1 = await fullCone.translateOutbound(from: internalEndpoint, to: dest1)
        let fc2 = await fullCone.translateOutbound(from: internalEndpoint, to: dest2)
        print("\nFull Cone NAT:")
        print("  To \(dest1): \(fc1 ?? "nil")")
        print("  To \(dest2): \(fc2 ?? "nil")")
        print("  Same mapping: \(fc1 == fc2 ? "YES" : "NO")")

        // Restricted - same mapping, but tracks allowed IPs
        let rc1 = await restricted.translateOutbound(from: internalEndpoint, to: dest1)
        let rc2 = await restricted.translateOutbound(from: internalEndpoint, to: dest2)
        print("\nRestricted Cone NAT:")
        print("  To \(dest1): \(rc1 ?? "nil")")
        print("  To \(dest2): \(rc2 ?? "nil")")
        print("  Same mapping: \(rc1 == rc2 ? "YES" : "NO")")

        // Port Restricted - same mapping, tracks allowed IP:port pairs
        let prc1 = await portRestricted.translateOutbound(from: internalEndpoint, to: dest1)
        let prc2 = await portRestricted.translateOutbound(from: internalEndpoint, to: dest2)
        print("\nPort Restricted Cone NAT:")
        print("  To \(dest1): \(prc1 ?? "nil")")
        print("  To \(dest2): \(prc2 ?? "nil")")
        print("  Same mapping: \(prc1 == prc2 ? "YES" : "NO")")

        // Symmetric - different mapping per destination!
        let sym1 = await symmetric.translateOutbound(from: internalEndpoint, to: dest1)
        let sym2 = await symmetric.translateOutbound(from: internalEndpoint, to: dest2)
        print("\nSymmetric NAT:")
        print("  To \(dest1): \(sym1 ?? "nil")")
        print("  To \(dest2): \(sym2 ?? "nil")")
        print("  Same mapping: \(sym1 == sym2 ? "YES" : "NO") <- Different ports!")

        // Inbound filtering test
        print("\n--- Inbound Filtering ---")
        let unknownSource = "10.0.0.99:9999"
        let knownSource = "10.0.0.1:8000"
        let knownIP = "10.0.0.1:9999"  // Same IP, different port

        print("\nFrom unknown source (\(unknownSource)):")
        print("  Full Cone: \(await fullCone.filterInbound(from: unknownSource, to: fc1!) != nil ? "ALLOWED" : "blocked")")
        print("  Restricted: \(await restricted.filterInbound(from: unknownSource, to: rc1!) != nil ? "allowed" : "BLOCKED")")
        print("  Port Restricted: \(await portRestricted.filterInbound(from: unknownSource, to: prc1!) != nil ? "allowed" : "BLOCKED")")
        print("  Symmetric: \(await symmetric.filterInbound(from: unknownSource, to: sym1!) != nil ? "allowed" : "BLOCKED")")

        print("\nFrom known IP, different port (\(knownIP)):")
        print("  Full Cone: \(await fullCone.filterInbound(from: knownIP, to: fc1!) != nil ? "ALLOWED" : "blocked")")
        print("  Restricted: \(await restricted.filterInbound(from: knownIP, to: rc1!) != nil ? "ALLOWED" : "blocked")")
        print("  Port Restricted: \(await portRestricted.filterInbound(from: knownIP, to: prc1!) != nil ? "allowed" : "BLOCKED")")
        print("  Symmetric: \(await symmetric.filterInbound(from: knownIP, to: sym1!) != nil ? "allowed" : "BLOCKED")")

        print("\nFrom exact known source (\(knownSource)):")
        print("  Full Cone: \(await fullCone.filterInbound(from: knownSource, to: fc1!) != nil ? "ALLOWED" : "blocked")")
        print("  Restricted: \(await restricted.filterInbound(from: knownSource, to: rc1!) != nil ? "ALLOWED" : "blocked")")
        print("  Port Restricted: \(await portRestricted.filterInbound(from: knownSource, to: prc1!) != nil ? "ALLOWED" : "blocked")")
        print("  Symmetric: \(await symmetric.filterInbound(from: knownSource, to: sym1!) != nil ? "ALLOWED" : "blocked")")

        // Verify symmetric creates different mappings
        XCTAssertNotEqual(sym1, sym2)
        // Verify others create same mapping
        XCTAssertEqual(fc1, fc2)
        XCTAssertEqual(rc1, rc2)
        XCTAssertEqual(prc1, prc2)
    }
}
