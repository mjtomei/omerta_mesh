# OmertaSSH: SSH Client with Mosh-like Features

## Overview

Build a custom SSH client that connects to VMs through the mesh tunnel (via netstack) with mosh-like local echo for responsive typing even with latency.

## Architecture

```
User Terminal
     │
     ▼
┌─────────────────────────────────────┐
│  OmertaSSH Client                   │
│  ├── RawTerminal (termios)          │
│  ├── LocalEchoEngine (speculation)  │
│  ├── SSH Protocol (Citadel)         │
│  └── NetstackTCPClient              │
└─────────────────────────────────────┘
     │
     ▼ (TCP over netstack)
┌─────────────────────────────────────┐
│  TunnelSession (trafficSource)      │
│  └── tunnel-traffic channel         │
└─────────────────────────────────────┘
     │
     ▼ (mesh network)
┌─────────────────────────────────────┐
│  Provider TunnelSession (trafficExit)│
│  └── NetstackBridge                 │
└─────────────────────────────────────┘
     │
     ▼ (real TCP)
┌─────────────────────────────────────┐
│  VM sshd (standard, no changes)     │
└─────────────────────────────────────┘
```

## Key Components

### 1. Expose Netstack Dial to Swift

Netstack (gVisor) already supports `gonet.DialTCP()` for application-level connections. We just need to expose this to Swift.

**How it works:** When we dial 10.x.x.2:22, netstack:
1. Creates TCP endpoint, generates SYN packet
2. Sends packet out its NIC callback (already wired to tunnel-return)
3. Provider receives packet, injects into VM
4. VM's SYN-ACK comes back via tunnel-traffic
5. Netstack completes handshake - we have a TCP connection

No new packet routing needed - just expose the dial API.

**Files:**
- `Sources/OmertaTunnel/Netstack/tunnel_netstack.go` - Add `DialTCP` wrapper around gonet
- `Sources/OmertaTunnel/NetstackBridge.swift` - Swift wrapper

```go
// New exports in tunnel_netstack.go
//export NetstackDialTCP
func NetstackDialTCP(handle uint64, host *C.char, port C.uint16_t) C.uint64_t
// Uses gonet.DialTCP internally - packets flow through existing NIC callback

//export NetstackConnRead
func NetstackConnRead(connHandle uint64, buf *C.uint8_t, maxLen C.size_t) C.int

//export NetstackConnWrite
func NetstackConnWrite(connHandle uint64, buf *C.uint8_t, len C.size_t) C.int
```

### 2. SSH Protocol (Citadel library)

Use [Citadel](https://github.com/orlandos-nl/Citadel) - Pure Swift SSH built on NIO:

```swift
// Package.swift addition
.package(url: "https://github.com/orlandos-nl/Citadel.git", from: "0.7.0")
```

Citadel provides:
- SSH transport, key exchange, encryption
- Channel multiplexing
- PTY allocation
- Works with custom NIO channels (our netstack)

### 3. Terminal Layer (New)

**RawTerminal.swift** - Low-level terminal control:
```swift
public final class RawTerminal {
    func enterRawMode() throws      // Disable line buffering, echo
    func exitRawMode()              // Restore settings
    func readByte() -> UInt8?       // Single byte input
    func write(_ bytes: [UInt8])    // Output
    func getSize() -> (rows, cols)  // Terminal dimensions
    func onResize(handler)          // SIGWINCH handling
}
```

### 4. Local Echo Engine (New)

**LocalEchoEngine.swift** - Speculative rendering:
```swift
public actor LocalEchoEngine {
    // When user types:
    func processInput(_ byte: UInt8) async {
        predictionBuffer.add(byte)
        displaySpeculative(byte)  // Show immediately with underline
    }

    // When server responds:
    func processServerOutput(_ data: Data) async {
        if reconciler.confirms(data, predictions: predictionBuffer) {
            clearSpeculativeMarkers()  // Remove underline
        } else {
            redrawFromServer()  // Mismatch - use server state
        }
    }
}
```

**Echo decision table:**
| Input | Action |
|-------|--------|
| Printable chars | Echo with underline |
| Backspace | Echo, update prediction |
| Arrow keys | Don't echo (app handles) |
| Tab | Echo predicted spaces |
| Enter | Echo newline |
| Ctrl+C/Z | Don't echo (signals) |

### 5. Module Structure

```
Sources/OmertaSSH/
├── SSHClient.swift              # Main orchestrator
├── Transport/
│   ├── NetstackTCPClient.swift  # TCP dial via netstack
│   └── MeshSSHChannel.swift     # NIO channel for Citadel
├── Terminal/
│   ├── RawTerminal.swift        # termios, raw mode
│   └── TerminalState.swift      # VT100 state tracking
└── LocalEcho/
    ├── LocalEchoEngine.swift    # Speculation engine
    ├── PredictionBuffer.swift   # Unconfirmed chars
    └── Reconciler.swift         # Match server output
```

### 6. CLI Integration

```swift
// In OmertaCLI/main.swift
struct SSHCommand: AsyncParsableCommand {
    @Argument var target: String  // VM ID or IP
    @Option var identity: String = "~/.omerta/ssh/id_ed25519"
    @Option var user: String = "omerta"
    @Flag var noLocalEcho: Bool = false

    func run() async throws {
        let vm = try await resolveTarget(target)
        let tunnel = try await getTunnelSession(for: vm)
        let client = SSHClient(localEchoEnabled: !noLocalEcho)
        try await client.connect(tunnel: tunnel, vmIP: vm.vmIP, user: user)
        try await client.runInteractive()
    }
}
```

## Implementation Phases

### Phase 1: SSH over Netstack (MVP)
- Expose netstack's `gonet.DialTCP` to Swift (packets already flow correctly via tunnel-return)
- Add `NetstackTCPClient` Swift wrapper
- Add Citadel dependency
- Basic SSH connection (no local echo yet)
- `omerta ssh` command

**Deliverable:** SSH to VM through mesh works like regular ssh

### Phase 2: Terminal Layer
- `RawTerminal` with termios handling
- Window resize (SIGWINCH → SSH window-change)
- Proper signal handling

**Deliverable:** Full terminal support with resize

### Phase 3: Local Echo
- `TerminalState` for cursor tracking
- `PredictionBuffer` for unconfirmed input
- `LocalEchoEngine` with speculative display
- Visual marker (underline) for unconfirmed

**Deliverable:** Responsive typing with latency

### Phase 4: Resilience
- Detect mesh disconnection
- Maintain TCP state in netstack
- Auto-reconnect when mesh recovers
- "Reconnecting..." indicator

**Deliverable:** Sessions survive brief outages

## Files to Modify

| File | Change |
|------|--------|
| `Package.swift` | Add Citadel, new OmertaSSH module |
| `Sources/OmertaTunnel/Netstack/tunnel_netstack.go` | Add DialTCP, conn management |
| `Sources/OmertaTunnel/Netstack/libnetstack.h` | New C exports |
| `Sources/OmertaTunnel/NetstackBridge.swift` | Swift dialTCP wrapper |
| `Sources/OmertaCLI/main.swift` | Add SSHCommand |

## Files to Create

| File | Purpose |
|------|---------|
| `Sources/OmertaSSH/SSHClient.swift` | Main client actor |
| `Sources/OmertaSSH/Transport/NetstackTCPClient.swift` | TCP over netstack |
| `Sources/OmertaSSH/Transport/MeshSSHChannel.swift` | NIO channel adapter |
| `Sources/OmertaSSH/Terminal/RawTerminal.swift` | termios handling |
| `Sources/OmertaSSH/Terminal/TerminalState.swift` | VT100 state |
| `Sources/OmertaSSH/LocalEcho/LocalEchoEngine.swift` | Speculation |
| `Sources/OmertaSSH/LocalEcho/PredictionBuffer.swift` | Buffer |
| `Sources/OmertaSSH/LocalEcho/Reconciler.swift` | Match output |

## Verification

### Phase 1 Test

**Step 1: Verify TCP dial through netstack (before Citadel)**
```bash
# Start provider daemon on Mac
ssh mac "omertad start"

# Request VM
omerta vm request --wait
# Note the VM IP (e.g., 10.118.119.2)

# Test raw TCP connection via netstack dial
# (New test command or integration test)
omerta tunnel tcp-test 10.118.119.2:22
# Should output: "Connected to 10.118.119.2:22, received SSH banner: SSH-2.0-OpenSSH_..."

# Or via unit test:
swift test --filter NetstackDialTests
```

**Step 2: Verify full SSH works**
```bash
# SSH through mesh
omerta ssh <vm-id>

# Should get shell prompt
whoami  # → omerta
```

### Phase 3 Test
```bash
# Add artificial latency
sudo tc qdisc add dev eth0 root netem delay 200ms

# SSH should feel responsive despite latency
omerta ssh <vm-id>
# Type quickly - chars appear immediately (underlined)
# After 200ms delay, underline disappears as server confirms
```

### Phase 4 Test
```bash
# SSH into VM
omerta ssh <vm-id>

# Kill mesh connection briefly
# In another terminal:
pkill -STOP omertad; sleep 5; pkill -CONT omertad

# Session should show "reconnecting" then resume
```
