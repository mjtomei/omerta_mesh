# OmertaMesh

A standalone P2P mesh networking library in Swift, providing secure peer-to-peer communication with NAT traversal, hole punching, and relay support.

## Features

- **End-to-end encrypted messaging** using ChaCha20-Poly1305
- **NAT traversal and relay support**
- **Link health monitoring and automated gossip protocol** 
- **Virtual network** with userspace server support
- **Encryption enforcement audit** (`--audit-encryption`)
- **Cross-platform** (macOS 13+, Linux)

## Modules

| Module | Description |
|--------|-------------|
| **OmertaMesh** | Core mesh networking library |
| **OmertaNetwork** | Virtual networking: DHCP, TUN interfaces, packet routing, subnet selection |
| **OmertaTunnel** | TCP/UDP tunnels over mesh connections |
| **OmertaSSH** | SSH client over mesh tunnels |
| **OmertaMeshDaemon** | `omerta-meshd` daemon with IPC |
| **OmertaMeshCLI** | CLI for testing and debugging |
| **DemoSOCKSGateway** | SOCKS5 proxy with DNS through gateway netstack |
| **DemoTUNGateway** | TUN interface gateway demo |
| **HealthTestRunner** | Multi-phase cross-machine health monitoring test |
| **CNetstack** | C bridge for gVisor netstack |

## Building

```bash
swift build
```

## Testing

```bash
swift test
```

## CLI Usage

Run a mesh node:

```bash
swift run omerta_mesh --port 18002
```

Connect to a bootstrap peer:

```bash
swift run omerta_mesh --port 18003 --bootstrap "<peerId>@192.168.1.100:18002"
```

Run as a relay node:

```bash
swift run omerta_mesh --port 18002 --relay
```

## Using as a Dependency

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/mjtomei/omerta_mesh.git", from: "1.0.0"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "OmertaMesh", package: "omerta_mesh"),
            .product(name: "OmertaTunnel", package: "omerta_mesh"),
        ]
    ),
]
```

## Documentation

- [API Reference](API.md) - Public API documentation for all modules
- [Cryptography](CRYPTOGRAPHY.md) - Encryption, key exchange, and security details

### Plans

Working documents for development are in [plans/](plans/):

- NAT traversal design and implementation
- Cryptography details
- Migration guides
- Code structure

## Development Status

See [plans/notes.txt](../plans/notes.txt) for the latest human-managed TODO list.

### Accomplished

- [x] End-to-end encrypted messaging using ChaCha20-Poly1305
- [x] X25519 key exchange and Ed25519 signatures
- [x] NAT traversal with automatic type detection
- [x] Relay support for peers behind symmetric NAT
- [x] Gossip-based peer discovery
- [x] TCP/UDP tunneling via gVisor netstack
- [x] Cross-platform support (macOS 13+, Linux)
- [x] Separated into standalone library with clean API
- [x] OmertaNetwork module (virtual networking, DHCP, packet routing, TUN)
- [x] Health monitoring and endpoint change detection
- [x] SOCKS5 proxy and TCP port forwarder
- [x] Security hardening: encryption enforcement, SealedEnvelope, audit mode
- [x] Multi-phase cross-machine health test runner
- [x] SPM build plugins

### LOC

~30,000 implementation / ~27,000 tests

### TODO

- [ ] Fix IPv6 NAT detection and add contact request message for NAT hole punching
- [ ] Test relay functionality with artificial constraints on peer nodes
- [ ] Handle diverse cases where inbound traffic isn't allowed (IPv4 and IPv6)
- [ ] Add reasonable rate limiting to UDP socket wrapper
- [ ] Implement mosh-clone SSH client for use with mesh tunnel
- [ ] macOS kernel networking for TUN interfaces
- [ ] Implement VPN functionality using Tunnel utility for internet connections
- [ ] Multi-radio support and connection prioritization
- [ ] Traffic shaping and bandwidth splitting
- [ ] Padding to reduce traffic analysis data leakage
- [ ] Kernel/DPU/FPGA accelerated mesh nodes
- [ ] WireGuard connection migration

## Third-Party Dependencies

OmertaMesh uses the following notable third-party libraries:

- **[gVisor netstack](https://gvisor.dev/)** (Apache-2.0) - Userspace TCP/IP stack for the OmertaTunnel module
- **[Swift NIO](https://github.com/apple/swift-nio)** (Apache-2.0) - Non-blocking I/O
- **[Swift Crypto](https://github.com/apple/swift-crypto)** (Apache-2.0) - Cryptographic operations

See [licenses/](licenses/) for complete license information.

## License

Proprietary - All rights reserved.
