#!/usr/bin/env bash
#
# Demo: TUN-Based Gateway over Mesh VPN
#
# What this tests:
#   A single-process demo using real Linux TUN interfaces instead of userspace
#   gVisor netstack. Linux only — macOS kernel networking (utun) is not yet
#   implemented. Requires Linux and sudo access.
#
#   Mode "tun":
#     Peer: TUNInterface (omerta0, kernel networking)
#     Gateway: NetstackBridge (userspace)
#     Test: curl --interface omerta0 http://example.com
#
#   Mode "socks-tun":
#     Peer: NetstackBridge (userspace) + SOCKS5 proxy on localhost:1080
#     Gateway: TUNInterface (omerta-gw0) + kernel ip_forward + MASQUERADE
#     Test: curl -x socks5h://127.0.0.1:1080 http://example.com
#
# Prerequisites:
#   - Linux with sudo access
#   - Swift toolchain
#   - libnetstack.a pre-built in Sources/CNetstack/ (requires Go to rebuild)
#
# Usage:
#   ./demo-tun-gateway.sh
#
#   The script builds, runs both tun and socks-tun modes, and reports PASS/FAIL.

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

TMPLOG=$(mktemp /tmp/demo-tun-gw.XXXXXX)
SYSCTL_SAVE="/tmp/demo-tun-gw-sysctl-saved"
SERVER_PID=""

print_kernel_state() {
    local label="$1"
    echo "  Kernel state ($label): ip_forward=$(cat /proc/sys/net/ipv4/ip_forward) rp_filter=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)"
}

# Save original sysctl values so we can restore them after the test.
# If the save file already exists (from a previous killed run), don't overwrite —
# it contains the true original values.
save_sysctl() {
    if [ -f "$SYSCTL_SAVE" ]; then
        echo "  (sysctl save file exists from previous run, keeping original values)"
        return
    fi
    cat > "$SYSCTL_SAVE" <<-EOF
	ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
	rp_filter_all=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)
	EOF
    echo "  Saved sysctl state to $SYSCTL_SAVE"
}

restore_sysctl() {
    if [ ! -f "$SYSCTL_SAVE" ]; then
        return
    fi
    # Read values for the log message before the binary deletes the file
    # shellcheck source=/dev/null
    source "$SYSCTL_SAVE" 2>/dev/null || true
    sudo .build/debug/DemoTUNGateway --restore-sysctl "$SYSCTL_SAVE" 2>/dev/null || true
    rm -f "$SYSCTL_SAVE" 2>/dev/null || true
    echo "  Restored sysctl state (ip_forward=${ip_forward:-?}, rp_filter=${rp_filter_all:-?})"
}

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    restore_sysctl
    rm -f "$TMPLOG"
}
trap cleanup EXIT

# Build (no root needed)
echo "Building DemoTUNGateway..."
swift build --product DemoTUNGateway 2>&1 | grep -E '^\[|^Build '

# Verify sudo access for this binary
if ! sudo -n -l "$(pwd)/.build/debug/DemoTUNGateway" >/dev/null 2>&1; then
    echo "ERROR: This demo requires root to create and configure TUN interfaces."
    echo "Please run with sudo or ensure your user has sudo access for .build/debug/DemoTUNGateway."
    exit 1
fi

# Save sysctl values before the binary modifies them
save_sysctl

run_mode() {
    local MODE="$1"
    local READY_STRING="$2"
    local CURL_CMD="$3"

    echo ""
    echo "=== Testing mode: $MODE ==="
    print_kernel_state "before"

    # Start server (binary kills stale instances on its own)
    > "$TMPLOG"
    sudo .build/debug/DemoTUNGateway "$MODE" > "$TMPLOG" 2>&1 &
    SERVER_PID=$!

    # Wait for readiness
    local READY=false
    for i in $(seq 1 30); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "Server process died. Check log:"
            cat "$TMPLOG"
            SERVER_PID=""
            return 1
        fi
        if grep -q "$READY_STRING" "$TMPLOG" 2>/dev/null; then
            READY=true
            break
        fi
        sleep 0.5
    done

    if [ "$READY" != "true" ]; then
        echo "Timed out waiting for server (15s)."
        cat "$TMPLOG"
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        return 1
    fi

    echo "Server ready ($MODE), PID=$SERVER_PID."

    # Run curl test
    echo "Running curl test..."
    local RESULT
    RESULT=$(eval "$CURL_CMD" 2>&1) || true

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

    # Check result
    if echo "$RESULT" | grep -q "Example Domain"; then
        echo -e "${GREEN}${BOLD}PASS${RESET} — $MODE mode returned Example Domain"
        return 0
    else
        echo -e "${RED}${BOLD}FAIL${RESET} — $MODE mode did not find 'Example Domain'"
        echo "Response was:"
        echo "$RESULT" | head -20
        return 1
    fi
}

# Run both modes sequentially
EXIT_CODE=0

run_mode "tun" \
    "TUN Gateway Demo Running (mode: tun)" \
    "curl -s --max-time 15 --interface omerta0 http://example.com" \
    || EXIT_CODE=1

run_mode "socks-tun" \
    "TUN Gateway Demo Running (mode: socks-tun)" \
    "curl -s --max-time 15 -x socks5h://127.0.0.1:1080 http://example.com" \
    || EXIT_CODE=1

# Summary
echo ""
if [ "$EXIT_CODE" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All TUN gateway tests passed.${RESET}"
else
    echo -e "${RED}${BOLD}Some TUN gateway tests failed.${RESET}"
fi
exit "$EXIT_CODE"
