# Mesh Relay Network

A decentralized P2P overlay network where any public node can act as a relay for NAT-bound peers.

This document covers the conceptual model for NAT traversal, connection establishment, endpoint discovery protocols, and how peers help each other establish connections.

---

## Architecture

### Network Topology

```
                        Public Nodes (can receive incoming connections)
                    ┌───────────────────────────────────────────┐
                    │                                           │
                ┌───┴───┐       ┌───────┐       ┌───────┐       │
                │   A   │◄─────►│   B   │◄─────►│   C   │       │
                │public │       │public │       │public │       │
                └───┬───┘       └───┬───┘       └───┬───┘       │
                    │               │               │           │
                    └───────────────┴───────────────┘           │
                                                                │
    ════════════════════════════════════════════════════════════╪════
                                                                │
                    NAT Nodes (can only initiate outgoing)      │
                    │               │               │           │
                ┌───┴───┐       ┌───┴───┐       ┌───┴───┐       │
                │   E   │       │   F   │       │   G   │       │
                │  NAT  │       │  NAT  │       │  NAT  │       │
                └───────┘       └───────┘       └───────┘
```

### Initial State: Relay Connections

Each NAT node maintains connections to one or more public nodes as relays:

```
                ┌───────┐       ┌───────┐       ┌───────┐
                │   A   │       │   B   │       │   C   │
                └───┬───┘       └───┬───┘       └───┬───┘
                    ║               ║ ║             ║
                    ║               ║ ║             ║
                    ▼               ▼ ▼             ▼
                ┌───────┐       ┌───────┐       ┌───────┐
                │   E   │       │   F   │       │   G   │
                └───────┘       └───────┘       └───────┘

                E's relay: A          F's relays: B, C      G's relay: C
```

### Hole Punch Coordination

When E wants to reach F, relay B coordinates the hole punch:

```
    1. E asks B: "Help me reach F"

                    ┌───────┐
                    │   B   │  (coordinator)
                    └───┬───┘
                   ╱         ╲
                  ╱           ╲
                 ▼             ▼
            ┌───────┐     ┌───────┐
            │   E   │     │   F   │
            └───────┘     └───────┘

    2. B tells BOTH E and F: "Send to each other NOW"
       (bidirectional coordination - both parties receive execute)

    3. E and F simultaneously send packets to each other's endpoints
       (punching holes in their respective NATs)

            ┌───────┐ · · · · · · · ┌───────┐
            │   E   │──────────────►│   F   │
            │       │◄──────────────│       │
            └───────┘               └───────┘
              198.51.100.20:45678     203.0.113.50:34567
```

### After Hole Punch: Direct Connection

```
                ┌───────┐       ┌───────┐       ┌───────┐
                │   A   │       │   B   │       │   C   │
                └───┬───┘       └───────┘       └───┬───┘
                    ║                               ║
                    ║   (relay no longer needed     ║
                    ▼    for E↔F traffic)           ▼
                ┌───────┐                       ┌───────┐
                │   E   │◄─────────────────────►│   F   │
                └───────┘    direct connection  └───────┘
                     ╲                             ╱
                      ╲         ┌───────┐         ╱
                       ╲        │   G   │        ╱
                        ╲       └───────┘       ╱
                         ╲          │          ╱
                          ╲         │         ╱
                           (G can also hole-punch to E or F)
```

### Legend

```
────►  Direct UDP connection (after hole punch or to public node)
════►  Relay connection (maintained for coordination)
· · ·  Hole punch attempt (simultaneous packets)
```

### Key Points

- **Any public node can be a relay** - no dedicated relay infrastructure needed
- **Hole punching works for most NAT types** - except symmetric NAT
- **Symmetric NAT falls back to relay** - messages routed through public nodes
- **Direct connections are preferred** - relay only when hole punch fails

---

## Peer vs Machine Distinction

A **peer** is an identity (public key). A **machine** is a physical device running the software. One peer can have multiple machines (e.g., laptop and phone), and each machine has its own endpoint(s).

Throughout this document and the codebase:
- Endpoints are tracked per **machine**, not per peer
- Gossip shares `MachineEndpointInfo` (machineId + endpoint + natType)
- When we say "contact X", we mean "contact one of X's machines"
- A peer is reachable if ANY of their machines is reachable

---

## Part 1: Two Endpoint Properties

Every endpoint has two independent properties:

| Property | Question | Depends On |
|----------|----------|------------|
| **Works for me** | Can I reach them with this endpoint? | My recent contact with them |
| **Works for others** | Can someone else use this endpoint? | Target's NAT type |

### Works for Me

| Status | Action |
|--------|--------|
| Yes | Direct send |
| No | Need help from contacts |

This is the only property that matters when *I* need to reach someone. It applies uniformly regardless of NAT type - a public IP can go offline, a NAT endpoint can expire, or an endpoint can simply be wrong.

### Works for Others

| Target NAT Type | Shareable? | Why |
|-----------------|------------|-----|
| Public | Yes | Anyone can reach them |
| Shared Endpoint | Yes (if fresh) | Same endpoint works for everyone |
| Per-Peer Endpoint | No | Target must send to requester first |

This property matters when *someone asks me* for help reaching a peer. Even if I have a working endpoint for X, I can only share it if X's NAT type allows reuse.

---

## Part 2: Asking For and Providing Help

### Asking for Help (I need to reach X)

When my endpoint for X doesn't work, target's NAT type determines what kind of help I need:

| Target NAT Type | What I Need | Who Can Help |
|-----------------|-------------|--------------|
| **Public or Shared** | Fresh endpoint | Any first-hand contact |
| **Per-Peer** | Hole punch coordination | Only first-hand contacts |

**Query routing preference:** When choosing who to ask, prefer contacts who are NOT behind Per-Peer NAT:
1. Public/Shared contacts first (reliable communication)
2. Per-Peer contacts only if no other option (may have connectivity issues)

### Providing Help (Someone asks me about X)

When someone asks me for help reaching X, I need to check both endpoint properties:

| Do I have working endpoint for X? | Is X's endpoint shareable? | What I can do |
|-----------------------------------|----------------------------|---------------|
| Yes | Yes (X is Public/Shared) | Share the endpoint |
| Yes | No (X is Per-Peer) | Coordinate: tell X to contact requester |
| No | - | Forward query to my contacts (with TTL) |

### NAT Type Reference

| Category | Behavior | Endpoint Shareable? |
|----------|----------|---------------------|
| **Public** | Always reachable (no NAT) | Yes |
| **Shared Endpoint** | Same endpoint works for everyone (Full Cone NAT) | Yes (if fresh) |
| **Per-Peer Endpoint** | Each peer needs their own endpoint (Restricted/Symmetric NAT) | No |

### Special Case: Both Peers are Per-Peer Endpoint

When both requester and target are behind Per-Peer NAT, behavior depends on their NAT subtype:

| Requester NAT | Target NAT | Can Hole Punch? | Action |
|---------------|------------|-----------------|--------|
| Restricted (fixed port) | Restricted (fixed port) | Yes | Simultaneous send |
| Restricted | Symmetric | No | Must relay |
| Symmetric | Restricted | No | Must relay |
| Symmetric | Symmetric | No | Must relay |

**Why symmetric NAT breaks hole punching:** Symmetric NAT uses a different external port for each destination. When A sends to B, A's NAT creates mapping `A:portX → B`. When B sends to A, B's NAT creates mapping `B:portY → A`. But A is expecting traffic on `portX`, not the port B is sending to. The ports don't match, so packets are dropped.

**Restricted cone works** because the external port stays the same regardless of destination. Both sides can predict each other's external endpoint.

**Protocol when hole punch is possible:**
1. Coordinator has first-hand contact with both peers
2. Coordinator tells BOTH: "Send to each other NOW" (always bidirectional)
3. Simultaneous sends create NAT mappings on both sides
4. Direct communication established

**When hole punch is not possible:** Must relay all messages through a mutual contact.

**Code:** `HolePunchCoordinator` - HolePunch/HolePunchCoordinator.swift

---

## Part 3: Endpoint Information Flow

This section documents all the ways endpoint information moves between peers.

### 3.1 Bootstrap Connection

**When:** Node startup
**Direction:** Us → Bootstrap peers (known addresses)

**Information exchanged:**
- We send: `ping(recentMachines=[], myNATType, requestFullList=true)`
- They respond: `pong(recentMachines=[...], yourEndpoint="1.2.3.4:5678", myNATType)`

**Code:**
```
MeshNetwork.start()
  → MeshNetwork.connectToBootstrapPeers()  [Public/MeshNetwork.swift]
    → MeshNode.sendPing()                   [MeshNode.swift]
```

**Result:**
- We learn our public endpoint (for NAT type detection)
- We learn about other machines from their `recentMachines`
- Bootstrap learns about us

---

### 3.2 Gossip via Ping/Pong

**When:** Every ping/pong exchange
**Direction:** Bidirectional

**Information exchanged:**
```swift
ping(recentMachines: [MachineEndpointInfo], myNATType: NATType, requestFullList: Bool)
pong(recentMachines: [MachineEndpointInfo], yourEndpoint: String, myNATType: NATType)

struct MachineEndpointInfo {
    peerId: PeerId
    machineId: MachineId
    endpoint: String
    natType: NATType
    isFirstHand: Bool  // sender has direct contact with this machine
}
```

**Code:**
- Message types: Types/MeshMessage.swift
- Handling ping: MeshNode.swift (`handleDefaultMessage` case `.ping`)
- Handling pong: MeshNode.swift (`handleDefaultMessage` case `.pong`)

**What we learn:**
- Endpoints of machines the sender knows
- NAT types of those machines
- Whether sender has first-hand contact (can actually help us reach them)
- Who knows who (sender knows the machines they gossip about)

---

### 3.3 "Who Knows Who" Tracking

**When:** Receiving gossip about any machine
**Purpose:** Know who to ask when we need to reach a machine

**Logic:**
- When A gossips about X, record: "A knows X" with first-hand indicator
- Later, if we can't reach X:
  1. Try first-hand contacts first (they can actually help)
  2. Fall back to second-hand contacts if no first-hand available

**Code:**
```swift
// MeshNode.swift
struct KnownContact {
    let contactMachineId: MachineId
    let contactPeerId: PeerId
    let lastSeen: Date
    let isFirstHand: Bool
}

// Track contacts for ALL machines (not just symmetric NAT)
private var knownContacts: [MachineId: [KnownContact]] = [:]

func recordKnownContact(for targetMachineId: MachineId, ..., isFirstHand: Bool)
func getContactsForMachine(_ machineId: MachineId) async -> [KnownContact]
```

**Contact selection priority:**
1. First-hand contacts behind Public/Shared NAT
2. First-hand contacts behind Per-Peer NAT
3. Second-hand contacts behind Public/Shared NAT
4. Second-hand contacts behind Per-Peer NAT (last resort)

---

### 3.4 Propagation Queue (New/Changed Machines)

**When:** Learning about a new machine OR a machine whose endpoint changed
**Purpose:** Spread information about new/changed machines

**Logic:**
1. Receive gossip about machine X
2. Add to propagation queue if:
   - X is completely new (never seen before), OR
   - X's endpoint has changed since we last saw it
3. Do NOT propagate just because we haven't heard from X in a while (10 min absence alone is not enough)
4. Include in our next `recentMachines` with fanout limit

**Threshold:** 10 minutes absence is used for "reconnecting" detection, but only triggers propagation if endpoint also changed.

**Code:**
```
MeshNode.handleDefaultMessage() case .ping   [MeshNode.swift]
  → isNew = !hasEndpoints
  → endpointChanged = newEndpoint != previousEndpoint
  → if isNew || endpointChanged: add to propagationQueue
```

---

### 3.5 Machine List in Pong Responses

**Default behavior:** Send only changes since last contact with this machine
- Track what we've previously sent to each machine
- Only include machines that are new or have changed endpoints
- Reduces bandwidth and avoids redundant gossip

**Full list request:** Support explicit request for complete machine list
- Ping message includes optional `requestFullList: Bool` flag
- If true, pong includes ALL known machines
- Used for:
  - Initial bootstrap (new nodes)
  - Manual CLI pings (default behavior, can be disabled with `--no-full-list`)
  - Reconnecting peers (10+ minute absence)

**Logic:**
```swift
if ping.requestFullList || isNewMachine(sender) || isReconnecting(sender) {
    response = buildFullMachineList()
} else {
    response = buildDeltaMachineList(excluding: sender)
}
```

**CLI behavior:**
- `omerta ping <peer>` → uses default (delta)
- `omerta ping <peer> --request-full-list` → requests full list

---

### 3.6 Observed Endpoint Updates (NAT Type Detection)

**When:** Receiving pong with `yourEndpoint`
**Purpose:** Determine our own NAT type

**Logic:**
- Collect `yourEndpoint` from multiple peers
- Same endpoint from all → Public or Shared Endpoint
- Different endpoints → Per-Peer Endpoint

**Code:**
```
MeshNode.updateObservedEndpoint()   [MeshNode.swift]
  → NATPredictor.recordObservation()   [NAT/NATPredictor.swift]
  → predictNATType() based on observations
```

---

### 3.7 Hole Punch Coordination Messages

**When:** Any peer needs to reach a Per-Peer Endpoint machine
**Flow:** Initiator ↔ Coordinator ↔ Target

**Key principle:** Coordinator ALWAYS tells both parties to contact each other simultaneously, regardless of initiator's NAT type. This:
- Handles the case where both are restricted cone (simultaneous sends work)
- Simplifies the protocol (one flow for all cases)
- If initiator is Public/Shared, their send is just a normal ping that happens to be timed

**Messages:**
```swift
// Initiator → Coordinator
holePunchRequest(targetMachineId, myEndpoint, myNATType)

// Coordinator → BOTH parties (always bidirectional)
holePunchExecute(targetEndpoint, peerEndpoint, simultaneousSend: true)

// Either → Coordinator
holePunchResult(targetMachineId, success, establishedEndpoint)
```

**Code:**
- `HolePunchManager.establishDirectConnection()` - HolePunch/HolePunchManager.swift
- `HolePunchCoordinator.handleRequest()` - HolePunch/HolePunchCoordinator.swift

---

### 3.8 Relay Forward Messages (for Symmetric NAT targets)

**When:** Cannot establish direct connection (both peers are symmetric NAT or hole punch failed)
**Flow:** Us → Relay → Target

**Messages:**
```swift
relayForward(targetMachineId, payload: Data)
relayForwardResult(targetMachineId, success: Bool)
```

**Code:**
- `MeshNode.sendViaRelay()` - MeshNode.swift
- `MeshNode.handleRelayForward()` - MeshNode.swift

**Note:** Relay works because the relay has an active mapping with the target (target has sent to relay recently). This is the fallback when hole punch coordination (3.7) cannot succeed.

---

## Part 4: Identified Gaps

### Gap 1: No endpoint query protocol

**Current:** We only get endpoints via passive gossip
**Needed:** Active query: "Do you have a working endpoint for X? Can you ping them and share it?"

**Proposed messages:**
```swift
endpointQuery(targetPeerId, queryId, originPeerId, ttl)
endpointResponse(targetPeerId, queryId, endpoint?, natType?, isFirstHand?)
```

### Gap 2: No optimistic direct send before coordination

**Current:** `establishDirectConnection()` goes straight to coordinator
**Needed:** Try gossiped endpoint first (especially for Shared Endpoint targets)

### Gap 3: Coordinator selection uses callback, not gossip data

**Current:** `getCoordinatorPeerId()` callback returns fixed coordinator
**Needed:** Select from `knownContacts[target]` - prioritize **first-hand** contacts

### Gap 4: No recursive endpoint query

**Current:** If our contacts can't reach target, we give up
**Needed:** Contacts should forward query to their contacts (with TTL limit)

---

## Part 5: Quick Reference

### Two Endpoint Properties

| Property | Question | When It Matters |
|----------|----------|-----------------|
| **Works for me** | Can I reach them? | When I need to send |
| **Works for others** | Can I share this endpoint? | When someone asks me for help |

### Asking for Help (I need to reach X)

| My endpoint works? | Action |
|--------------------|--------|
| Yes | Direct send |
| No | Ask contacts for help |

**Who to ask (in order of preference):**
1. First-hand contacts behind Public/Shared NAT
2. First-hand contacts behind Per-Peer NAT
3. Second-hand contacts behind Public/Shared NAT
4. Second-hand contacts behind Per-Peer NAT (last resort)

### Providing Help (Someone asks me about X)

| I can reach X? | X is shareable? | Action |
|----------------|-----------------|--------|
| Yes | Yes (Public/Shared) | Share endpoint |
| Yes | No (Per-Peer) | Tell X to contact requester |
| No | - | Forward query (with TTL) |

### NAT Type → Shareability

| Target NAT Type | Endpoint Shareable? |
|-----------------|---------------------|
| Public | Yes |
| Shared Endpoint | Yes (if fresh) |
| Per-Peer Endpoint | No |

### Contact Tracking Requirements

| What to Track | Why |
|---------------|-----|
| Who gossiped about X | Know who to ask for help reaching X |
| First-hand vs second-hand | Only first-hand can help with Per-Peer targets |
| Contact's NAT type | Prefer Public/Shared contacts for queries |

---

## References

- [RFC 5389 - STUN](https://tools.ietf.org/html/rfc5389)
- [RFC 5766 - TURN](https://tools.ietf.org/html/rfc5766)
- [RFC 8445 - ICE](https://tools.ietf.org/html/rfc8445)
- [libp2p Circuit Relay](https://docs.libp2p.io/concepts/circuit-relay/)
- [Kademlia DHT Paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
