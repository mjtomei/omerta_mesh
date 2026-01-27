# OmertaMesh Protocol Test Plan

This document defines comprehensive tests for the mesh networking protocol, covering network topologies, NAT configurations, fault injection, and performance benchmarks.

## Test Infrastructure

### VM-Based Test Environment

```
┌─────────────────────────────────────────────────────────────────┐
│                    Linux Host (Test Controller)                  │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │   VM-A   │  │   VM-B   │  │   VM-C   │  │   VM-D   │        │
│  │ (Relay)  │  │  (Peer)  │  │  (Peer)  │  │  (Peer)  │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │                │
│  ┌────┴─────────────┴─────────────┴─────────────┴────┐          │
│  │              Virtual Network Bridge                │          │
│  │         (configurable topology/latency)            │          │
│  └────────────────────────────────────────────────────┘          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Test Controller                         │   │
│  │  - Topology configuration                                │   │
│  │  - Fault injection (tc, iptables)                       │   │
│  │  - Metrics collection                                   │   │
│  │  - Test orchestration                                   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Physical Test Environment

```
┌───────────────┐         ┌───────────────┐
│  Linux Host   │◄───────►│   Mac Host    │
│  (Relay)      │   LAN   │   (Peer)      │
└───────────────┘         └───────────────┘
```

---

## Part 1: Network Topologies

### 1.1 Basic Topologies

#### Test T1.1: Point-to-Point Direct
```
[Peer A] ◄──────────────► [Peer B]
         Direct Connection
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T1.1.1 | Two peers on same LAN | Direct connection established, <10ms RTT |
| T1.1.2 | Bidirectional messaging | Both peers send/receive 100 messages |
| T1.1.3 | High-throughput transfer | >100 Mbps sustained transfer |
| T1.1.4 | Connection recovery | Reconnects after 5s network interruption |

#### Test T1.2: Star Topology (Relay Hub)
```
        [Peer B]
            │
            ▼
[Peer A] ► [Relay] ◄ [Peer C]
            ▲
            │
        [Peer D]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T1.2.1 | All peers discover relay | All 4 peers connect within 10s |
| T1.2.2 | Peer-to-peer via relay | A→C message delivered <100ms |
| T1.2.3 | Relay handles 10 peers | All connections maintained |
| T1.2.4 | Relay failure recovery | Peers reconnect to backup relay |

#### Test T1.3: Linear Chain (Multi-Hop)
```
[Peer A] ──► [Peer B] ──► [Peer C] ──► [Peer D]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T1.3.1 | 3-hop message delivery | A→D delivered within 500ms |
| T1.3.2 | TTL enforcement | Message with TTL=2 doesn't reach D |
| T1.3.3 | Intermediate node failure | Route recovers around B failure |
| T1.3.4 | Loop prevention | No message duplication in loops |

#### Test T1.4: Mesh Topology
```
    [A] ──── [B]
    │ \    / │
    │  \  /  │
    │   \/   │
    │   /\   │
    │  /  \  │
    │ /    \ │
    [C] ──── [D]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T1.4.1 | Full mesh connectivity | All 6 direct connections established |
| T1.4.2 | Optimal path selection | A→D uses direct path, not via B or C |
| T1.4.3 | Graceful degradation | Remove A-D link, traffic routes via B |
| T1.4.4 | Broadcast efficiency | Broadcast reaches all once, no floods |

#### Test T1.5: Hierarchical Topology
```
              [Super Relay]
             /      |      \
      [Relay A]  [Relay B]  [Relay C]
       /    \      |   \       |
    [P1]  [P2]  [P3]  [P4]   [P5]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T1.5.1 | Cross-region discovery | P1 discovers P5 via super relay |
| T1.5.2 | Relay hierarchy routing | P1→P5 routes through minimum hops |
| T1.5.3 | Sub-relay failure | P1-P2 traffic routes through other relay |
| T1.5.4 | Super relay failure | Local traffic continues, cross fails |

### 1.2 Scale Tests

| Test ID | Topology | Nodes | Success Criteria |
|---------|----------|-------|------------------|
| T1.S.1 | Star | 50 | All connected, <5s convergence |
| T1.S.2 | Star | 100 | All connected, <10s convergence |
| T1.S.3 | Mesh | 20 | Full mesh (190 connections) |
| T1.S.4 | Hierarchical | 500 | 5 relays, 100 peers each |

---

## Part 2: NAT Configurations

### 2.1 NAT Types

```
┌────────────────────────────────────────────────────────────────────┐
│ NAT Type          │ External Mapping      │ Hole Punch Success    │
├────────────────────────────────────────────────────────────────────┤
│ No NAT            │ Public IP             │ N/A (always works)    │
│ Full Cone         │ Fixed port            │ High                  │
│ Address-Restricted│ Fixed, src IP checked │ High                  │
│ Port-Restricted   │ Fixed, src IP:port    │ Medium                │
│ Symmetric         │ Random per dest       │ Low (needs relay)     │
└────────────────────────────────────────────────────────────────────┘
```

### 2.2 NAT Traversal Tests

#### Test T2.1: Full Cone NAT
```
[Peer A]──[Full Cone NAT]──Internet──[Peer B (Public)]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T2.1.1 | NAT type detection | Correctly identifies as Full Cone |
| T2.1.2 | Hole punch to public | Direct connection established |
| T2.1.3 | Hole punch to Full Cone | Direct connection established |
| T2.1.4 | Connection persistence | Survives NAT mapping timeout |

#### Test T2.2: Address-Restricted Cone NAT
```
[Peer A]──[Addr-Restricted NAT]──Internet──[Peer B (Public)]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T2.2.1 | NAT type detection | Correctly identifies as Address-Restricted |
| T2.2.2 | Hole punch requires outbound | B cannot reach A without A sending first |
| T2.2.3 | Coordinated hole punch | Both peers punch simultaneously, connects |
| T2.2.4 | Source IP validation | Different source IP blocked |

#### Test T2.3: Port-Restricted Cone NAT
```
[Peer A]──[Port-Restricted NAT]──Internet──[Peer B (Public)]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T2.3.1 | NAT type detection | Correctly identifies as Port-Restricted |
| T2.3.2 | Same port requirement | B must reply from exact port |
| T2.3.3 | Coordinated hole punch | Requires simultaneous + correct ports |
| T2.3.4 | Different port rejected | Reply from different port blocked |

#### Test T2.4: Symmetric NAT
```
[Peer A]──[Symmetric NAT]──Internet──[Peer B]──[Symmetric NAT]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T2.4.1 | NAT type detection | Correctly identifies as Symmetric |
| T2.4.2 | Port prediction failure | Random ports, prediction fails |
| T2.4.3 | Relay fallback | Automatically falls back to relay |
| T2.4.4 | Relay performance | <100ms added latency via relay |

#### Test T2.5: Double NAT (Carrier-Grade NAT)
```
[Peer A]──[Home NAT]──[ISP CGNAT]──Internet──[Peer B]
```

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T2.5.1 | Double NAT detection | Detected via STUN mismatch |
| T2.5.2 | Hole punch attempt | May succeed depending on CGNAT type |
| T2.5.3 | Relay fallback | Works reliably through CGNAT |
| T2.5.4 | STUN server reachability | STUN works through double NAT |

### 2.3 NAT Combination Matrix

Test hole punching between all NAT type combinations:

| Initiator \ Responder | None | Full Cone | Addr-Restr | Port-Restr | Symmetric |
|-----------------------|------|-----------|------------|------------|-----------|
| None (Public)         | T2.M.1 | T2.M.2 | T2.M.3 | T2.M.4 | T2.M.5 |
| Full Cone             | T2.M.6 | T2.M.7 | T2.M.8 | T2.M.9 | T2.M.10 |
| Address-Restricted    | T2.M.11 | T2.M.12 | T2.M.13 | T2.M.14 | T2.M.15 |
| Port-Restricted       | T2.M.16 | T2.M.17 | T2.M.18 | T2.M.19 | T2.M.20 |
| Symmetric             | T2.M.21 | T2.M.22 | T2.M.23 | T2.M.24 | T2.M.25 |

Expected outcomes:
- Green (Direct): None-*, Full Cone-*, *-None, *-Full Cone
- Yellow (Maybe): Addr-Restr↔Addr-Restr, Addr-Restr↔Port-Restr, Port-Restr↔Port-Restr
- Red (Relay): Any Symmetric combination

---

## Part 3: Fault Injection

### 3.1 Packet-Level Faults

#### Test T3.1: Packet Loss
```bash
# Simulate on Linux with tc
tc qdisc add dev eth0 root netem loss 10%
```

| Test ID | Loss Rate | Duration | Success Criteria |
|---------|-----------|----------|------------------|
| T3.1.1 | 1% | 60s | <5% message loss, no disconnects |
| T3.1.2 | 5% | 60s | <10% message loss, recovers |
| T3.1.3 | 10% | 60s | <20% message loss, reconnects |
| T3.1.4 | 25% | 60s | Falls back to relay if needed |
| T3.1.5 | Bursty 50% for 5s | 60s | Recovers within 10s |

#### Test T3.2: Latency/Jitter
```bash
tc qdisc add dev eth0 root netem delay 100ms 50ms distribution normal
```

| Test ID | Base Latency | Jitter | Success Criteria |
|---------|--------------|--------|------------------|
| T3.2.1 | 50ms | 10ms | Normal operation, adjusted timeouts |
| T3.2.2 | 200ms | 50ms | Hole punch succeeds with retries |
| T3.2.3 | 500ms | 100ms | May need relay assistance |
| T3.2.4 | Variable 10-500ms | High | Adaptive timeout works |
| T3.2.5 | Sudden spike 10ms→1s | - | Doesn't trigger false disconnect |

#### Test T3.3: Bandwidth Constraints
```bash
tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms
```

| Test ID | Bandwidth | Success Criteria |
|---------|-----------|------------------|
| T3.3.1 | 10 Mbps | Full throughput utilized |
| T3.3.2 | 1 Mbps | Control messages prioritized |
| T3.3.3 | 100 Kbps | Basic connectivity maintained |
| T3.3.4 | Asymmetric 10M/1M | Bidirectional works with different rates |

#### Test T3.4: Packet Reordering
```bash
tc qdisc add dev eth0 root netem delay 10ms reorder 25% 50%
```

| Test ID | Reorder Rate | Success Criteria |
|---------|--------------|------------------|
| T3.4.1 | 5% | Message ordering preserved |
| T3.4.2 | 25% | Reassembly works correctly |
| T3.4.3 | 50% | Performance degrades gracefully |

#### Test T3.5: Packet Duplication
```bash
tc qdisc add dev eth0 root netem duplicate 10%
```

| Test ID | Duplicate Rate | Success Criteria |
|---------|----------------|------------------|
| T3.5.1 | 5% | Deduplication works |
| T3.5.2 | 25% | No double processing |
| T3.5.3 | 50% | Performance impact <20% |

### 3.2 Node-Level Faults

#### Test T3.6: Node Crashes
| Test ID | Scenario | Success Criteria |
|---------|----------|------------------|
| T3.6.1 | Single peer crash | Other peers detect within 30s |
| T3.6.2 | Relay crash | Peers failover to backup relay |
| T3.6.3 | Coordinator crash | New coordinator elected |
| T3.6.4 | Rapid crash/restart | Reconnects without duplicate state |
| T3.6.5 | 50% of nodes crash | Remaining network continues |

#### Test T3.7: Graceful Shutdown
| Test ID | Scenario | Success Criteria |
|---------|----------|------------------|
| T3.7.1 | Peer announces shutdown | Routes updated before disconnect |
| T3.7.2 | Relay announces shutdown | Peers migrate before disconnect |
| T3.7.3 | Shutdown during transfer | Transfer completes or cleanly fails |

### 3.3 Network Partitions

#### Test T3.8: Network Splits
```
Before:  [A]──[B]──[C]──[D]
After:   [A]──[B]  |  [C]──[D]
         Partition ─┘
```

| Test ID | Partition Type | Success Criteria |
|---------|----------------|------------------|
| T3.8.1 | Clean split (2+2) | Each partition continues operating |
| T3.8.2 | Asymmetric (3+1) | Isolated node tries to reconnect |
| T3.8.3 | Intermittent (flapping) | No state corruption |
| T3.8.4 | Heal after 60s | Network reconverges, no duplicates |
| T3.8.5 | Partial partition | Some paths work, others don't |

### 3.4 Clock/Timing Faults

#### Test T3.9: Clock Skew
| Test ID | Skew Amount | Success Criteria |
|---------|-------------|------------------|
| T3.9.1 | +/- 5 seconds | Normal operation |
| T3.9.2 | +/- 60 seconds | Freshness checks still work |
| T3.9.3 | +/- 5 minutes | Graceful degradation |
| T3.9.4 | Clock jump mid-connection | Connection survives |

---

## Part 4: Protocol Tests

### 4.1 Bootstrap & Discovery

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T4.1.1 | Bootstrap from single peer | Discovers full network |
| T4.1.2 | Bootstrap from list | Uses fastest responder |
| T4.1.3 | Bootstrap peer offline | Tries next, eventually succeeds |
| T4.1.4 | All bootstrap offline | Reports error, retries |
| T4.1.5 | Malicious bootstrap | Ignores invalid peer lists |
| T4.1.6 | Peer rediscovery | Periodic refresh updates stale info |

### 4.2 Hole Punching

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T4.2.1 | Simultaneous punch | Both sides punch at same time |
| T4.2.2 | Sequential punch | Initiator then responder |
| T4.2.3 | Punch timeout | Falls back to relay after timeout |
| T4.2.4 | Punch retry | Retries with backoff on failure |
| T4.2.5 | Coordinator selection | Uses appropriate coordinator |
| T4.2.6 | Coordinator fallback | Switches coordinator on failure |

### 4.3 Relay Operations

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T4.3.1 | Relay registration | Peer registers with relay |
| T4.3.2 | Relay message forwarding | Messages delivered via relay |
| T4.3.3 | Relay capacity limits | Graceful rejection at capacity |
| T4.3.4 | Relay selection | Chooses best relay by latency |
| T4.3.5 | Relay rotation | Switches to better relay |
| T4.3.6 | Multiple relays | Load balanced across relays |

### 4.4 Message Handling

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T4.4.1 | Small message | <100 bytes delivered correctly |
| T4.4.2 | Large message | >1MB delivered correctly |
| T4.4.3 | Binary message | Non-text data preserved |
| T4.4.4 | Rapid messages | 1000 msg/s handled |
| T4.4.5 | Message ordering | Order preserved per sender |
| T4.4.6 | Duplicate detection | Same message ID rejected |

### 4.5 Freshness & Staleness

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T4.5.1 | Fresh peer info | Recent contact used directly |
| T4.5.2 | Stale peer info | Triggers revalidation |
| T4.5.3 | Dead peer detection | Removed after timeout |
| T4.5.4 | Path freshness query | Updates stale routes |
| T4.5.5 | Freshness propagation | Updates spread through mesh |

### 4.6 Keepalive & Network Health

**Current Implementation:**
- `ConnectionKeepalive` sends periodic pings to actively connected peers
- Ping/pong includes `recentPeers` dictionary for gossip
- Bootstrap connection is one-shot (connect, discover, done)

**Planned Improvements:**

| Feature | Description | Priority |
|---------|-------------|----------|
| Bootstrap keepalive | Maintain persistent connection to bootstrap node(s) | High |
| Proactive gossip | Periodically ping random known peers to spread updates | Medium |
| Minimum connections | Maintain N connections for network resilience | Medium |
| Adaptive ping interval | Increase frequency when network is changing | Low |

**Keepalive Tests:**

| Test ID | Description | Success Criteria |
|---------|-------------|------------------|
| T4.6.1 | Bootstrap persistence | Connection to bootstrap stays alive for duration |
| T4.6.2 | Gossip propagation | New peer info reaches all nodes within 30s |
| T4.6.3 | Peer rediscovery | Reconnects to lost peer within 60s via gossip |
| T4.6.4 | NAT mapping refresh | Keepalive prevents NAT timeout (typ. 30-120s) |
| T4.6.5 | Minimum connections | Node maintains at least N healthy connections |
| T4.6.6 | Idle network health | Mesh stays connected when no app traffic for 5min |
| T4.6.7 | Keepalive under load | Keepalive continues during high throughput |
| T4.6.8 | Asymmetric keepalive | Works when one side has stricter NAT |

**Implementation Plan:**

1. **Bootstrap keepalive** (High priority)
   - After initial bootstrap, don't disconnect
   - Send periodic pings (every 15-30s) to bootstrap node(s)
   - If bootstrap dies, try to reconnect or use discovered peers as new bootstrap

2. **Proactive gossip** (Medium priority)
   - Every 60s, pick a random known peer and ping them
   - This spreads peer info even without active connections
   - Helps discover when peers come/go

3. **Minimum connections** (Medium priority)
   - Config option: `minimumConnections: Int = 3`
   - If below threshold, proactively connect to known peers
   - Ensures network resilience even when idle

---

## Part 5: Performance Benchmarks

### 5.1 Latency Benchmarks

| Test ID | Scenario | Target p50 | Target p99 |
|---------|----------|------------|------------|
| T5.1.1 | Direct LAN | <5ms | <20ms |
| T5.1.2 | Direct WAN (same region) | <30ms | <100ms |
| T5.1.3 | Via relay (same region) | <50ms | <150ms |
| T5.1.4 | Via relay (cross-region) | <100ms | <300ms |
| T5.1.5 | 3-hop mesh | <100ms | <300ms |

### 5.2 Throughput Benchmarks

| Test ID | Scenario | Target |
|---------|----------|--------|
| T5.2.1 | Direct connection (small pkts) | >50K pps |
| T5.2.2 | Direct connection (large pkts) | >500 Mbps |
| T5.2.3 | Via relay (small pkts) | >20K pps |
| T5.2.4 | Via relay (large pkts) | >200 Mbps |
| T5.2.5 | Sustained 10 minutes | Stable, no degradation |

### 5.3 Convergence Benchmarks

| Test ID | Scenario | Target |
|---------|----------|--------|
| T5.3.1 | New peer joins | <5s to discover network |
| T5.3.2 | Peer failure detection | <30s |
| T5.3.3 | Route reconvergence | <10s after failure |
| T5.3.4 | Network partition heal | <30s to reconverge |

### 5.4 Resource Benchmarks

| Test ID | Scenario | Target |
|---------|----------|--------|
| T5.4.1 | Memory per peer | <5MB per connection |
| T5.4.2 | CPU at idle | <1% |
| T5.4.3 | CPU at max throughput | <50% one core |
| T5.4.4 | File descriptors | <10 per peer |

---

## Part 6: Test Execution

### 6.1 VM Setup Commands

```bash
# Start test VMs with network namespace
./scripts/start-test-vm.sh --name vm-a --ip 10.0.0.1 --nat full-cone
./scripts/start-test-vm.sh --name vm-b --ip 10.0.0.2 --nat symmetric
./scripts/start-test-vm.sh --name vm-relay --ip 10.0.0.100 --relay

# Configure network conditions
./scripts/set-network-conditions.sh --vm vm-a --latency 50ms --loss 5%

# Run test suite
./scripts/run-mesh-tests.sh --topology star --duration 300
```

### 6.2 Test Matrix Execution Order

1. **Phase 1: Basic Functionality** (T1.1, T4.1-T4.4)
   - Direct connections work
   - Bootstrap and discovery work
   - Message delivery works

2. **Phase 2: NAT Traversal** (T2.*)
   - Each NAT type detected correctly
   - Hole punching works where possible
   - Relay fallback works

3. **Phase 3: Fault Tolerance** (T3.*)
   - Network impairments handled
   - Node failures detected and recovered
   - Partitions handled correctly

4. **Phase 4: Scale & Performance** (T1.S.*, T5.*)
   - Performance targets met
   - Scale targets achieved
   - Resource usage acceptable

### 6.3 Metrics Collection

```swift
struct MeshTestMetrics {
    // Latency
    var pingLatencyP50: Duration
    var pingLatencyP99: Duration

    // Throughput
    var messagesPerSecond: Double
    var bytesPerSecond: Double

    // Reliability
    var messageDeliveryRate: Double
    var connectionSuccessRate: Double

    // Discovery
    var peerDiscoveryTime: Duration
    var holePunchSuccessRate: Double

    // Resources
    var memoryUsage: Int
    var cpuUsage: Double
}
```

---

## Appendix: NAT Simulation with iptables

### Full Cone NAT
```bash
# Map internal IP to single external port
iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source $EXT_IP
```

### Address-Restricted Cone NAT
```bash
# Only allow responses from IPs we've contacted
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -j DROP
```

### Port-Restricted Cone NAT
```bash
# Only allow responses from exact IP:port we contacted
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -j DROP
```

### Symmetric NAT
```bash
# Random source port for each destination
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random
```

---

## References

- [RFC 5389 - STUN](https://tools.ietf.org/html/rfc5389)
- [RFC 5245 - ICE](https://tools.ietf.org/html/rfc5245)
- [RFC 6886 - NAT-PMP](https://tools.ietf.org/html/rfc6886)
- [NAT Traversal Techniques](https://bford.info/pub/net/p2pnat/)
