# Virtual Network Upgrade

Fresh plan covering: real DHCP, TunnelProvider protocol, VPN/mesh daemon
separation, shared IPC types, and control socket notifications. Later phases
from VIRTUAL_NETWORK_REWORK.md will be ported after this is approved.

## Phase 1: RFC 2131 DHCP

Replace the JSON-over-mesh-channel DHCP with real RFC 2131 DHCP packets that
travel as normal IP/UDP traffic through PacketRouter. This lets real nodes
(kernel TUN with system DHCP clients) and our own DHCPClient coexist.

### 1a: DHCP packet builder/parser

**`Sources/OmertaNetwork/DHCPPacket.swift`** (new) — RFC 2131 packet handling:
- Parse and build DHCP packets (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE)
- Standard UDP port 67 (server) / 68 (client)
- BOOTP header (fixed 236 bytes): op, htype (1=Ethernet), hlen (6), hops,
  xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr (16 bytes,
  zero-padded), sname (64 bytes), file (128 bytes)
- Magic cookie `0x63825363` marks start of options field
- DHCP options (TLV format): message type (53), subnet mask (1), router (3),
  DNS (6), lease time (51), server identifier (54), requested IP (50),
  end marker (255). Minimum 312 bytes options field per RFC.
- Use machine ID hash as chaddr — first 6 bytes of SHA256(machineId),
  zero-padded to 16 bytes (hlen=6 tells server only first 6 are significant)
- Track xid (transaction ID) per exchange for response matching
- DISCOVER uses src IP `0.0.0.0`, dst `255.255.255.255` (broadcast flag set)

Delete `DHCPMessages.swift` — the JSON envelope types are no longer needed
with real RFC 2131 packets. DHCPService/DHCPClient work directly with
DHCPPacket.

### API changes (OmertaNetwork)

DHCPService and DHCPClient currently consume `ChannelProvider` (see `API.md`
§ChannelProvider Protocol). After this phase they no longer use channels at
all — they are pure packet processors wired into PacketRouter.

**DHCPService** — old vs new:
```swift
// Old (channel-based):
public actor DHCPService {
    init(channelProvider: any ChannelProvider, config: DHCPServerConfig)
    func start() async throws   // registers on "dhcp" channel
    func stop() async           // unregisters channel
}

// New (packet-based):
public actor DHCPService {
    init(config: DHCPServerConfig)
    func handlePacket(_ packet: Data) async -> Data?  // called by PacketRouter
    func leases() async -> [DHCPLease]
}
```

**DHCPClient** — old vs new:
```swift
// Old (channel-based):
public actor DHCPClient {
    init(channelProvider: any ChannelProvider, machineId: MachineId, config: DHCPClientConfig)
    func requestAddress() async throws -> DHCPResponse
    func release() async throws
}

// New (packet-based):
public actor DHCPClient {
    init(machineId: MachineId, config: DHCPClientConfig)
    func buildDiscover() -> Data
    func buildRequest(serverIP: String, offeredIP: String) -> Data
    func buildRelease() -> Data
    func handlePacket(_ packet: Data) async -> DHCPClientAction?
    var state: DHCPClientState { get }
}

public enum DHCPClientAction {
    case sendRequest(Data)
    case configured(ip: String, gateway: String, dns: [String], leaseTime: UInt32)
    case renew(Data)
}

public enum DHCPClientState {
    case initial, discovering, requesting, bound, renewing, rebinding
}
```

**PacketRouter** — init signature change:
```swift
// Old:
public init(/* existing params */)

// New — adds optional DHCP:
public init(/* existing params */,
            dhcpService: DHCPService? = nil,
            dhcpClient: DHCPClient? = nil)
```

The `"dhcp"` channel (see `API.md` §Channels and Messaging, reserved channel
table) is freed. DHCP traffic now flows as standard IP/UDP through
PacketRouter like all other traffic.

### 1b: Rewrite DHCPService to speak RFC 2131

**`Sources/OmertaNetwork/DHCPService.swift`** — rewrite:
- Remove `ChannelProvider` dependency
- New interface: `func handlePacket(_ packet: Data) async -> Data?`
  - Takes raw IP/UDP/DHCP packet, returns response packet (or nil)
  - PacketRouter calls this when it sees UDP destined for port 67
- Internal logic stays the same (lease pool, allocation, renewal, expiry)
- Builds RFC 2131 response packets using DHCPPacket

### 1c: Rewrite DHCPClient to speak RFC 2131

**`Sources/OmertaNetwork/DHCPClient.swift`** — rewrite:
- Remove `ChannelProvider` dependency
- New interface:
  - `init(machineId:, config:)`
  - `func buildDiscover() -> Data` — returns raw IP/UDP DHCP DISCOVER packet
  - `func handlePacket(_ packet: Data) async -> DHCPClientAction?` — processes
    OFFER/ACK, returns action (e.g., `.sendRequest(Data)`, `.configured(ip, gateway, dns)`)
  - `func buildRequest(serverIP:, offeredIP:) -> Data` — REQUEST packet
  - `func buildRelease() -> Data` — RELEASE packet
- State machine: init → discovering → requesting → bound → renewing → rebinding
- Track xid for matching responses to requests
- T1 renewal timer at 50% of lease time (unicast REQUEST to server)
- T2 rebinding timer at 87.5% of lease time (broadcast REQUEST)
- PacketRouter feeds it inbound UDP port 68 packets, sends outbound packets
  it produces

### 1d: Integrate DHCP into PacketRouter

**`Sources/OmertaNetwork/PacketRouter.swift`** — add DHCP routing:
- Add optional `dhcpService: DHCPService?` and `dhcpClient: DHCPClient?` to init
- In `routeOutbound()`: if packet is UDP to port 67 (broadcast `255.255.255.255`
  or gateway IP) and we are gateway, pass to `dhcpService.handlePacket()`,
  send response back to interface. Must handle src `0.0.0.0` (DISCOVER/REQUEST
  before client has IP).
- In `handleInboundPacket()`: if packet is UDP to port 68, pass to
  `dhcpClient.handlePacket()`, act on returned action
- For TUN mode with system DHCP: `dhcpClient` is nil, DHCP packets route
  normally through the tunnel to the gateway which handles them in its
  DHCPService

### 1e: Remove mesh channel DHCP

- **`Sources/OmertaNetwork/DHCPMessages.swift`** — delete entirely (JSON
  envelope types replaced by RFC 2131 DHCPPacket)
- Remove `DHCPService.channelName` and all `ChannelProvider` usage
- Remove `import OmertaMesh` from DHCPService and DHCPClient
- Update demo binaries to use new DHCP integration through PacketRouter

### Files

| File | Action |
|------|--------|
| `Sources/OmertaNetwork/DHCPPacket.swift` | New — RFC 2131 parser/builder |
| `Sources/OmertaNetwork/DHCPService.swift` | Rewrite — packet-based, no ChannelProvider |
| `Sources/OmertaNetwork/DHCPClient.swift` | Rewrite — packet-based state machine |
| `Sources/OmertaNetwork/DHCPClientConfig.swift` | Update — remove ChannelProvider references if any |
| `Sources/OmertaNetwork/DHCPServerConfig.swift` | Update — remove ChannelProvider references if any |
| `Sources/OmertaNetwork/DHCPServerManager.swift` | Update or delete — depends on whether it wraps DHCPService |
| `Sources/OmertaNetwork/DHCPMessages.swift` | Delete — replaced by DHCPPacket |
| `Sources/OmertaNetwork/PacketRouter.swift` | Add DHCP routing (port 67/68) |
| `Sources/DemoSOCKSGateway/main.swift` | Update — pass DHCPService/DHCPClient to PacketRouter |
| `Sources/DemoTUNGateway/main.swift` | Update — pass DHCPService/DHCPClient to PacketRouter |

### Tests

| File | Action |
|------|--------|
| `Tests/OmertaNetworkTests/DHCPPacketTests.swift` | New — parse/build round-trip, magic cookie, options encoding, malformed input |
| `Tests/OmertaNetworkTests/DHCPTests.swift` | Rewrite — update to test new packet-based DHCPService/DHCPClient APIs |
| `Tests/OmertaNetworkTests/DHCPIntegrationTests.swift` | Rewrite — test DHCP flow through PacketRouter (no ChannelProvider) |
| `Tests/OmertaNetworkTests/NativeDHCPTests.swift` | Update or delete — depends on current content vs new design |
| `Tests/OmertaNetworkTests/PacketRouterTests.swift` | Update — add tests for UDP port 67/68 DHCP routing |
| `Tests/OmertaNetworkTests/DemoSOCKSSmokeTest.swift` | Update — remove ChannelProvider-based DHCP wiring, use PacketRouter DHCP |
| `Tests/OmertaNetworkTests/MultiNodeIntegrationTests.swift` | Update if it uses DHCP channels |
| `Tests/OmertaNetworkTests/DHCPClientVsDnsmasqTests.swift` | New — integration: our client vs real dnsmasq (Linux, root) |
| `Tests/OmertaNetworkTests/DHCPServiceVsDhclientTests.swift` | New — integration: our server vs real dhclient (Linux, root) |

### Integration tests (Linux, requires root)

Both tests use a veth pair to exchange real DHCP packets with a known-good
counterpart. Skip in CI if veth/dnsmasq/dhclient unavailable.

**Test our client against dnsmasq (real server):**
1. Create veth pair `veth-srv` / `veth-cli`
2. Assign `10.99.0.1/24` to `veth-srv`, start dnsmasq with pool `10.99.0.100-200`
3. Our DHCPClient builds DISCOVER, write raw packet to `veth-cli`
4. Read OFFER from `veth-cli`, verify RFC 2131 fields (xid match, yiaddr in
   range, options: subnet mask, router, lease time, server identifier)
5. Client builds REQUEST, write to `veth-cli`
6. Read ACK, verify assigned IP matches OFFER's yiaddr
7. Verify client state machine reached `bound`
8. Teardown: kill dnsmasq, delete veth pair

**Test our server against dhclient (real client):**
1. Create veth pair `veth-srv` / `veth-cli`
2. Assign `10.99.0.1/24` to `veth-srv`, start our DHCPService listening on
   `veth-srv` (read raw packets, pass to `handlePacket()`, write responses)
3. Run `dhclient -1 -v veth-cli` (single attempt, verbose)
4. Verify dhclient obtains an IP in our configured pool range
5. Verify our DHCPService recorded a lease for the assigned IP
6. Teardown: `dhclient -r veth-cli`, delete veth pair

## Phase 2: TunnelProvider protocol

Extract a protocol so PacketRouter can work with TunnelManager directly
(demos, mesh daemon in-process) or via IPC proxy (VPN daemon).

### Files

| File | Action |
|------|--------|
| `Sources/OmertaTunnel/TunnelProvider.swift` | New — TunnelProvider + TunnelSessionHandle protocols |
| `Sources/OmertaTunnel/TunnelManager.swift` | Conform to TunnelProvider |
| `Sources/OmertaTunnel/TunnelSession.swift` | Conform to TunnelSessionHandle |
| `Sources/OmertaNetwork/PacketRouter.swift` | Change `tunnelManager: TunnelManager` → `tunnelProvider: any TunnelProvider` |

### TunnelProvider protocol

```swift
public protocol TunnelProvider: Sendable {
    func getSession(machineId: MachineId, channel: String) async throws -> any TunnelSessionHandle
    func getExistingSession(key: TunnelSessionKey) async -> (any TunnelSessionHandle)?
    func setSessionEstablishedHandler(
        _ handler: @escaping @Sendable (any TunnelSessionHandle) async -> Void) async
    func closeSession(key: TunnelSessionKey) async
    func closeAllSessions(to machineId: MachineId) async
    var sessionCount: Int { get async }
}

public protocol TunnelSessionHandle: Sendable {
    var key: TunnelSessionKey { get async }
    var remoteMachineId: MachineId { get async }
    var channel: String { get async }
    var state: TunnelState { get async }
    func send(_ data: Data) async throws
    func onReceive(_ handler: @escaping @Sendable (Data) async -> Void) async
    func close() async
}
```

### API changes (OmertaTunnel)

This introduces two new protocols that abstract the existing concrete
`TunnelManager` and `TunnelSession` APIs documented in `API.md`
§Tunnel Sessions (OmertaTunnel).

**New protocols** (see code block above for full definition):
- `TunnelProvider` — abstracts `TunnelManager` (§TunnelManager API)
- `TunnelSessionHandle` — abstracts `TunnelSession` (§TunnelSession API)

**Conformance changes:**
- `TunnelManager` conforms to `TunnelProvider` — no method signature changes
  needed, the protocol is extracted from its existing public API
- `TunnelSession` conforms to `TunnelSessionHandle` — same

**Consumer changes:**
- `PacketRouter` changes its stored property from concrete `TunnelManager` to
  `any TunnelProvider`. This is the only consumer that changes in this phase.
- All call sites remain the same — the protocol methods match the existing API

The `API.md` §TunnelManager API and §TunnelSession API sections should be
updated to show the protocol definitions and note that `TunnelManager`/
`TunnelSession` are the concrete implementations.

### Tests

| File | Action |
|------|--------|
| `Tests/OmertaTunnelTests/TunnelManagerTests.swift` | Update — use `any TunnelProvider` where applicable |
| `Tests/OmertaTunnelTests/TunnelIntegrationTests.swift` | Update — use protocol types |
| `Tests/OmertaNetworkTests/PacketRouterTests.swift` | Update — inject `any TunnelProvider` instead of concrete TunnelManager |

No new test files needed — this is a pure refactor. Existing tests must pass
unchanged after updating types.

### Verification

```bash
swift build
swift test
# Demo binaries should still work — TunnelManager conforms to TunnelProvider
./demo-socks-gateway.sh
./demo-tun-gateway.sh
```

## Phase 3: Control socket notification support

Add push notifications to the control socket so the mesh daemon can push
tunnel session events and channel messages to connected clients (the VPN daemon).

### Files

| File | Action |
|------|--------|
| `Sources/OmertaMesh/Daemon/ControlSocketClient.swift` | Add notification receive loop + handler |
| `Sources/OmertaMesh/Daemon/ControlSocketServer.swift` | Add notification push to client |

### Design

Add 1-byte type prefix to frames:
- `0x00` + `[4-byte length] [JSON]` = response (existing behavior)
- `0x01` + `[4-byte length] [JSON]` = notification (new)

Client changes:
- Background receive loop distinguishes responses from notifications
- Responses matched to pending request continuations
- Notifications dispatched to registered handler

Server changes:
- `sendNotification(_ data: Data, to client: ClientConnection)` method
- ChannelBridge uses this instead of inline socket writes

### API changes (OmertaMesh)

**ControlSocketServer** — new method:
```swift
// Existing (unchanged):
func send(_ response: Data, to client: ClientConnection) async throws

// New:
func sendNotification(_ data: Data, to client: ClientConnection) async throws
```

**ControlSocketClient** — new API:
```swift
// Existing (unchanged):
func send<Request: Encodable, Response: Decodable>(_ request: Request) async throws -> Response

// New:
func setNotificationHandler(_ handler: @escaping @Sendable (Data) async -> Void) async
```

The client's internal receive loop changes from synchronous request-response
to a background loop that demuxes by the 1-byte type prefix. This is a
wire-format change — both client and server must be updated together, but the
0x00 prefix for responses makes existing CLI binaries forward-compatible
(old servers don't send 0x01 frames, old clients ignore the prefix byte since
it's part of the length field's leading zero).

### Tests

| File | Action |
|------|--------|
| `Tests/OmertaMeshTests/DaemonTests/ControlSocketTests.swift` | Update — test 0x00/0x01 type prefix framing |
| `Tests/OmertaMeshTests/DaemonTests/FramingTests.swift` | Update — add type-prefixed frame tests |
| `Tests/OmertaMeshTests/DaemonTests/NotificationTests.swift` | New — test notification dispatch, response/notification demux, handler registration |
| `Tests/OmertaMeshTests/DaemonTests/ChannelBridgeTests.swift` | Update — verify bridge uses sendNotification |

### Verification

```bash
swift build
swift test
# Existing CLI commands still work (responses unchanged with 0x00 prefix)
```

## Phase 4: Integrate TunnelManager into mesh daemon

Move tunnel session management into the mesh daemon. Replace the incomplete
`createTunnel`/`closeTunnel` stubs with real TunnelManager and expose session
operations over IPC.

### Files

| File | Action |
|------|--------|
| `Sources/OmertaMeshDaemon/MeshDaemon.swift` | Add TunnelManager, replace tunnel stubs |
| `Sources/OmertaMeshDaemon/MeshDaemonProtocol.swift` | Update tunnel IPC commands |
| `Package.swift` | Add `OmertaTunnel` dependency to `OmertaMeshDaemon` |

### IPC command changes

```swift
// Remove:
case createTunnel(peerId: String, tunnelId: String)
case closeTunnel(tunnelId: String)

// Add:
case tunnelOpen(machineId: String, channel: String)
case tunnelClose(machineId: String, channel: String)
case tunnelCloseAll(machineId: String)
case tunnelList
```

### API changes (MeshDaemonProtocol IPC)

The IPC command enum in `MeshDaemonProtocol.swift` is updated. This is the
mesh daemon's IPC protocol — not a public Swift API, but used by `omerta-mesh`
CLI and will be used by `omerta-vpnd`.

```swift
// Remove (incomplete stubs):
case createTunnel(peerId: String, tunnelId: String)
case closeTunnel(tunnelId: String)

// Add:
case tunnelOpen(machineId: String, channel: String)
case tunnelClose(machineId: String, channel: String)
case tunnelCloseAll(machineId: String)
case tunnelList
```

**New IPC responses:**
```swift
case tunnelOpened(sessionUUID: UUID, machineId: String, channel: String)
case tunnelClosed
case tunnelListResult(sessions: [TunnelSessionInfo])
```

**New notification types** (pushed via Phase 3's notification support):
```swift
enum MeshDaemonNotification: Codable {
    case tunnelSessionEstablished(sessionUUID: UUID, machineId: String, channel: String)
    case tunnelSessionClosed(sessionUUID: UUID)
    case tunnelData(sessionUUID: UUID)  // signals data available on data socket
}
```

The `omerta-mesh` CLI (`Sources/OmertaMeshCLI/main.swift`) must update its
duplicated `MeshDaemonCommand` enum to match. (Phase 5 eliminates the
duplication.)

MeshDaemon creates `TunnelManager(provider: meshNetwork)` at startup.
IPC commands delegate to TunnelManager. Inbound session data forwarded to
VPN daemon clients via data socket. Session-established events pushed as
notifications via Phase 3's notification support.

### Data socket

Keep existing framing: `[16-byte UUID] [2-byte length] [packet data]`.
Mesh daemon assigns a UUID to each tunnel session and communicates the
mapping (session key ↔ UUID) to the VPN daemon via control socket responses.

### Tests

| File | Action |
|------|--------|
| `Tests/OmertaMeshTests/DaemonTests/DaemonIntegrationTests.swift` | Update — test tunnelOpen/tunnelClose/tunnelList IPC commands |
| `Tests/OmertaMeshTests/DaemonTests/DaemonProtocolTests.swift` | Update — add new tunnel command encoding/decoding tests |
| `Tests/OmertaMeshTests/DaemonTests/TunnelIPCTests.swift` | New — test tunnel IPC round-trip: open session, send data, receive notification, close |

### Verification

```bash
swift build
swift test
omerta-meshd start <network-id>
# Tunnel IPC commands work via omerta-mesh CLI
```

## Phase 5: Extract shared IPC protocol types

Move `MeshDaemonProtocol.swift` into `OmertaMesh` library. Remove duplicated
types from CLI.

### Files

| File | Action |
|------|--------|
| `Sources/OmertaMesh/Daemon/MeshDaemonProtocol.swift` | New (moved from daemon) |
| `Sources/OmertaMeshDaemon/MeshDaemonProtocol.swift` | Delete |
| `Sources/OmertaMeshCLI/main.swift` | Remove duplicated types, use shared imports |

### API changes (OmertaMesh)

`MeshDaemonCommand`, `MeshDaemonResponse`, and `MeshDaemonNotification` move
from `OmertaMeshDaemon` (internal to daemon binary) to `OmertaMesh` library
(public). This means:

- `OmertaMeshCLI` imports them from `OmertaMesh` instead of duplicating them.
  The CLI currently has its own copy of `MeshDaemonCommand` and
  `MeshDaemonResponse` at `Sources/OmertaMeshCLI/main.swift:143-180` — these
  are deleted.
- `OmertaMeshDaemon` imports them from `OmertaMesh` instead of defining them.
- Future consumers (e.g., `OmertaVPNDaemon`) can import from `OmertaMesh`
  directly.

No behavioral change — just making the types available from the library.

### Tests

| File | Action |
|------|--------|
| `Tests/OmertaMeshTests/DaemonTests/DaemonProtocolTests.swift` | Update — import from `OmertaMesh` instead of duplicated types |

No new test files — this is a code move. Existing tests must compile and
pass with the new import paths.

### Verification

```bash
swift build
swift test
# CLI commands still work
```

## Phase 6: TunnelProxy — TunnelProvider over IPC

Implements `TunnelProvider` for the VPN daemon, communicating with the mesh
daemon's TunnelManager via control + data sockets.

### Files

| File | Action |
|------|--------|
| `Sources/OmertaNetwork/TunnelProxy.swift` | New — TunnelProxy (actor, TunnelProvider) + TunnelSessionProxy (TunnelSessionHandle) |

```swift
public actor TunnelProxy: TunnelProvider {
    private let controlClient: ControlSocketClient
    private let dataClient: DataSocketClient

    // TunnelProvider methods → IPC commands to mesh daemon
    // getSession → tunnelOpen IPC, returns TunnelSessionProxy
    // TunnelSessionProxy.send → data socket write
    // TunnelSessionProxy.onReceive → data socket read callback
    // Session-established notifications → dispatched to handler
}
```

### Tests

| File | Action |
|------|--------|
| `Tests/OmertaNetworkTests/TunnelProxyTests.swift` | New — mock control/data socket, test TunnelProvider conformance |
| `Tests/OmertaNetworkTests/TunnelProxyIntegrationTests.swift` | New — TunnelProxy ↔ real mesh daemon with TunnelManager, end-to-end IPC |

### Verification

```bash
swift build
swift test
```

## Phase 7: VPN daemon (`omerta-vpnd`) and CLI (`omerta-vpn`)

### Files

| File | Action |
|------|--------|
| `Sources/OmertaVPNDaemon/VPNDaemonMain.swift` | New — entry point |
| `Sources/OmertaVPNDaemon/VPNDaemon.swift` | New — daemon actor |
| `Sources/OmertaVPNDaemon/VPNDaemonProtocol.swift` | New — IPC for CLI |
| `Sources/OmertaVPNCLI/main.swift` | New — CLI |
| `Package.swift` | Add 2 targets |

VPN daemon connects to mesh daemon, creates TunnelProxy, wires up:
- VirtualNetwork, PacketRouter, NetworkInterface
- GatewayService (gateway mode)
- DHCPService/DHCPClient (integrated via PacketRouter)

CLI: `omerta-vpn start/stop/status/leases`

### API changes (VPNDaemonProtocol IPC — new)

New IPC protocol between `omerta-vpn` CLI and `omerta-vpnd`:
```swift
public enum VPNDaemonCommand: Codable, Sendable {
    case start(networkId: String, gateway: Bool, gatewayMachine: String?)
    case stop(networkId: String)
    case status(networkId: String)
    case leases(networkId: String)
}

public enum VPNDaemonResponse: Codable, Sendable {
    case started(ip: String, subnet: String, gateway: String)
    case stopped
    case status(VPNStatus)
    case leases([DHCPLease])
    case error(String)
}

public struct VPNStatus: Codable, Sendable {
    public let ip: String
    public let gateway: String
    public let isGateway: Bool
    public let tunnelCount: Int
    public let uptime: TimeInterval
}
```

VPN daemon also uses the mesh daemon's IPC (from `OmertaMesh` after Phase 5)
to communicate with `omerta-meshd` via `ControlSocketClient` and
`DataSocketClient`.

### Tests

| File | Action |
|------|--------|
| `Tests/OmertaVPNDaemonTests/VPNDaemonTests.swift` | New — test daemon lifecycle (start, stop, status reporting) |
| `Tests/OmertaVPNDaemonTests/VPNDaemonProtocolTests.swift` | New — IPC command encoding/decoding |
| `Tests/OmertaVPNDaemonTests/VPNDaemonIntegrationTests.swift` | New — VPN daemon ↔ mesh daemon: start VPN, verify DHCP lease, stop |

### Verification

```bash
swift build
omerta-meshd start <network-id>
omerta-vpn start <network-id> --gateway
omerta-vpn status <network-id>
omerta-vpn stop <network-id>
```

## Phase 8: Two-machine test

Test full stack between two physical machines. (Ported from old Phase 10.)

### Verification

```bash
# Machine 1 (gateway):
omerta-meshd start <network-id>
omerta-vpn start <network-id> --gateway

# Machine 2 (peer):
omerta-meshd start <network-id> --bootstrap <peer>@<host>:<port>
omerta-vpn start <network-id> --gateway-machine <gw-machine-id>

# Verify:
omerta-vpn status <network-id>  # shows DHCP-assigned IP
omerta-vpn leases <network-id>  # on gateway, shows peer lease
# Ping / curl through VPN
```

## Implementation order

1. Phase 1 — RFC 2131 DHCP (self-contained, testable with demos)
2. Phase 2 — TunnelProvider protocol (refactor, no behavior change)
3. Phase 3 — Control socket notifications (mesh infra)
4. Phase 4 — TunnelManager in mesh daemon (mesh infra)
5. Phase 5 — Shared IPC types (cleanup)
6. Phase 6 — TunnelProxy (bridge layer)
7. Phase 7 — VPN daemon + CLI (new binaries)
8. Phase 8 — Two-machine test

## API documentation updates (`API.md`)

After all phases, update `API.md` to reflect the changes:

| Section | Change |
|---------|--------|
| §ChannelProvider Protocol | Note that DHCP no longer uses channels — remove any DHCP channel references |
| §Tunnel Sessions (OmertaTunnel) | Add `TunnelProvider` and `TunnelSessionHandle` protocol definitions; note `TunnelManager`/`TunnelSession` are concrete implementations |
| §TunnelManager API | Show protocol conformance; add `TunnelProxy` as the IPC-based implementation |
| §API Reference Summary | Add TunnelProvider, TunnelProxy, VPNDaemon IPC commands |
| New §VPN Daemon IPC | Document `VPNDaemonCommand`/`VPNDaemonResponse` protocol |
| New §Mesh Daemon Tunnel IPC | Document `tunnelOpen`/`tunnelClose`/`tunnelList` commands and `MeshDaemonNotification` types |
| §Reserved channel IDs | Remove DHCP from channel table if listed |

## Risks

- **RFC 2131 complexity**: Fixed 236-byte header + variable options with magic cookie, TLV encoding, and end marker. chaddr is 16 bytes (not 6). Need solid parser/builder with tests.
- **System DHCP client timing**: On TUN mode, the system DHCP client may timeout before the tunnel to gateway is established. May need to delay interface-up or use a fallback.
- **Data socket session mapping**: UUID ↔ TunnelSessionKey mapping must be consistent between mesh daemon and VPN daemon.
- **Notification ordering**: Session-established notifications must arrive before inbound data on data socket.
