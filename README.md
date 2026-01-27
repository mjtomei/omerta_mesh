# OmertaMesh

A standalone P2P mesh networking library in Swift, providing secure peer-to-peer communication with NAT traversal, hole punching, and relay support.

## Features

- **End-to-end encrypted messaging** using ChaCha20-Poly1305
- **NAT traversal** with automatic type detection and hole punching
- **Relay support** for peers behind symmetric NAT
- **Gossip-based peer discovery** for decentralized networking
- **TCP/UDP tunneling** over mesh connections via netstack
- **Cross-platform** (macOS 13+, Linux)

## Modules

| Module | Description |
|--------|-------------|
| **OmertaMesh** | Core mesh networking library |
| **OmertaTunnel** | TCP/UDP tunnels over mesh connections |
| **OmertaSSH** | SSH client over mesh tunnels |
| **OmertaMeshCLI** | CLI for testing and debugging |

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
    .package(url: "https://github.com/your-org/omerta_mesh.git", from: "1.0.0"),
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

## Third-Party Dependencies

OmertaMesh uses the following notable third-party libraries:

- **[gVisor netstack](https://gvisor.dev/)** (Apache-2.0) - Userspace TCP/IP stack for the OmertaTunnel module
- **[Swift NIO](https://github.com/apple/swift-nio)** (Apache-2.0) - Non-blocking I/O
- **[Swift Crypto](https://github.com/apple/swift-crypto)** (Apache-2.0) - Cryptographic operations

See [licenses/](licenses/) for complete license information.

## License

Proprietary - All rights reserved.
