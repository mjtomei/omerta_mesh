# Netstack - Userspace TCP/IP Stack

This directory contains a Go-based userspace TCP/IP stack using gVisor's netstack.
It's compiled as a C archive (`libnetstack.a`) for integration with Swift.

## Prerequisites

- Go 1.21 or later
- Make

### Installing Go

**macOS:**
```bash
brew install go
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install golang-go
# Or use the official installer from https://go.dev/dl/
```

**Linux (Arch):**
```bash
sudo pacman -S go
```

## Building

```bash
cd Sources/OmertaTunnel/Netstack

# Download dependencies
go mod tidy

# Run tests
go test -v ./...

# Build C archive
make

# Install to CNetstack directory
make install
```

This produces:
- `libnetstack.a` - Static library
- `libnetstack.h` - C header file

## Architecture

```
Swift (OmertaTunnel)
    │
    │ (calls C functions)
    ▼
CNetstack (module map)
    │
    │ (links libnetstack.a)
    ▼
Go netstack (exports.go)
    │
    │ (uses cgo)
    ▼
gVisor netstack (TCP/IP stack)
```

## API

The C API (defined in `libnetstack.h`):

```c
// Create a netstack instance
uint64_t NetstackCreate(const char* gatewayIP, uint32_t mtu);

// Set callback for returned packets
void NetstackSetCallback(uint64_t handle, ReturnPacketCallback callback, void* context);

// Start processing
int NetstackStart(uint64_t handle);

// Stop and destroy
void NetstackStop(uint64_t handle);

// Inject a raw IP packet
int NetstackInjectPacket(uint64_t handle, const uint8_t* data, size_t len);

// Get statistics
int NetstackGetStats(uint64_t handle, uint32_t* tcpConns, uint32_t* udpConns);
```

## How It Works

1. **Packet Injection**: Raw IP packets are injected via `NetstackInjectPacket()`
2. **TCP/UDP Processing**: netstack processes the packet, establishing real connections
3. **Forwarding**: Traffic is forwarded to/from real internet sockets
4. **Return Packets**: Responses are sent back via the callback

## Testing

```bash
# Run Go tests
go test -v ./...

# Run benchmarks
go test -bench=. -benchmem ./...
```

## Troubleshooting

### Build fails with "gvisor.dev/gvisor: module lookup disabled"

Run `go mod tidy` to download dependencies.

### Swift build fails with "library not found for -lnetstack"

Run `make install` to copy the library to `Sources/CNetstack/`.

### Runtime crash on packet injection

Ensure `NetstackStart()` was called before injecting packets.
