#!/usr/bin/env bash
#
# Demo: SOCKS5 Gateway over Userspace Mesh VPN
#
# What this tests:
#   A single-process demo that runs a complete mesh VPN data path in-process:
#
#   1. A SOCKS5 proxy on localhost:1080
#   2. A "peer" node with a real gVisor userspace TCP/IP stack (NetstackInterface)
#   3. A "gateway" node with GatewayService + real gVisor netstack for internet access
#   4. A mock in-process mesh relay connecting the two nodes
#
#   Traffic flow:
#     curl --> SOCKS5 proxy --> peer netstack dialTCPByName()
#       --> DNS query through gVisor UDP --> PacketRouter --> mesh relay
#       --> gateway PacketRouter --> GatewayService --> gateway netstack
#       --> real DNS server (8.8.8.8) --> response back through full chain
#       --> peer resolves IP --> TCP SYN through same path
#       --> gateway netstack dials real destination --> HTTP response back
#
#   This exercises the full packet pipeline: netstack packet generation,
#   PacketRouter routing decisions, VirtualNetwork address mapping,
#   TunnelManager session creation, GatewayService NAT tracking,
#   and netstack TCP/UDP forwarding -- all without a real tunnel or TUN device.
#
# Prerequisites:
#   - Swift toolchain
#   - libnetstack.a pre-built in Sources/CNetstack/ (requires Go to rebuild)
#
# Stats:
#   The demo prints packet counters every 5 seconds showing traffic through
#   each component: router packet counts, netstack connection counts, and
#   NAT table entries.
#
# Usage:
#   ./demo-socks-gateway.sh
#
#   Then in another terminal:
#     curl -v -x socks5h://127.0.0.1:1080 http://example.com
#     curl -L -x socks5h://127.0.0.1:1080 https://google.com
#
#   Press Ctrl+C to stop.

set -e

echo "Building DemoSOCKSGateway..."
swift build --target DemoSOCKSGateway

echo ""
echo "Starting demo..."
swift run DemoSOCKSGateway
