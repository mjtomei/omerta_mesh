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
# Usage:
#   ./demo-socks-gateway.sh
#
#   The script builds, starts the server, runs a curl test, and reports PASS/FAIL.

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

TMPLOG=$(mktemp /tmp/demo-socks-gw.XXXXXX)
SERVER_PID=""

print_kernel_state() {
    local label="$1"
    echo "  Kernel state ($label): ip_forward=$(cat /proc/sys/net/ipv4/ip_forward) rp_filter=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)"
}

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$TMPLOG"
}
trap cleanup EXIT

# Build
echo "Building DemoSOCKSGateway..."
swift build --product DemoSOCKSGateway 2>&1 | grep -E '^\[|^Build |error:'
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    echo "Build failed."
    exit 1
fi

print_kernel_state "before"

# Start server in background
echo "Starting DemoSOCKSGateway..."
.build/debug/DemoSOCKSGateway > "$TMPLOG" 2>&1 &
SERVER_PID=$!

# Wait for readiness
READY=false
for i in $(seq 1 30); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Server process died unexpectedly."
        cat "$TMPLOG"
        exit 1
    fi
    if grep -q "SOCKS5 Gateway Demo Running" "$TMPLOG" 2>/dev/null; then
        READY=true
        break
    fi
    sleep 0.5
done

if [ "$READY" != "true" ]; then
    echo "Timed out waiting for server to start (15s)."
    cat "$TMPLOG"
    exit 1
fi

echo "Server ready."

# Test
echo "Running curl test..."
RESULT=$(curl -s --max-time 15 -x socks5h://127.0.0.1:1080 http://example.com 2>&1) || true

# Wait for stats to be logged, then print packet counts
sleep 6
echo "  Packet counts:"
grep "Stats" "$TMPLOG" | tail -1 | sed 's/.*--- Stats --- //' \
    | sed 's/ | /\n/g' | sed 's/GW /Gateway /g' | sed 's/^/    /' || true

# Kill server
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

print_kernel_state "after"

# Report
echo ""
if echo "$RESULT" | grep -q "Example Domain"; then
    echo -e "${GREEN}${BOLD}PASS${RESET} — SOCKS5 gateway returned Example Domain"
    exit 0
else
    echo -e "${RED}${BOLD}FAIL${RESET} — did not find 'Example Domain' in response"
    echo "Response was:"
    echo "$RESULT" | head -20
    exit 1
fi
