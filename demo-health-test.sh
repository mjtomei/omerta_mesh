#!/bin/bash
#
# demo-health-test.sh — Build and run the cross-machine health monitoring test
#
# Usage:
#   ./demo-health-test.sh <ssh-host> <remote-path>
#
# Arguments:
#   ssh-host     SSH destination for the remote machine (e.g. "mac", "user@host")
#   remote-path  Absolute path on the remote machine to clone the repo into.
#                Must not already exist (the script clones fresh and cleans up).
#
# Prerequisites:
#   - Passwordless SSH access to the remote machine
#   - Passwordless sudo on both machines (sudo -n)
#   - Swift toolchain on both machines
#   - Git remote accessible from both machines (the script pushes before cloning)
#
# The script starts Node B (remote) first, then Node A (local, orchestrator).
# Results are printed at the end. Exit code 0 = all passed.

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <ssh-host> <remote-path> [--phase N]"
    echo ""
    echo "  ssh-host     SSH destination (e.g. 'mac', 'user@192.0.2.10')"
    echo "  remote-path  Absolute path on remote to clone into (must not exist)"
    echo "  --phase N    Only run phases starting from N (skip earlier phases)"
    exit 1
fi

REMOTE_HOST="$1"
REMOTE_PATH="$2"
shift 2
PHASE_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --phase)
            PHASE_ARG="--phase $2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Validate remote-path is absolute
if [[ "$REMOTE_PATH" != /* ]]; then
    echo "ERROR: remote-path must be an absolute path (got: $REMOTE_PATH)"
    exit 1
fi

# Fail if remote path already exists
if ssh "$REMOTE_HOST" "test -e '$REMOTE_PATH'" 2>/dev/null; then
    echo "ERROR: Remote path already exists: $REMOTE_HOST:$REMOTE_PATH"
    echo "  Remove it first or choose a different path."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$SCRIPT_DIR"
PRODUCT="HealthTestRunner"
LOCAL_BIN="$HOME/.local/bin/$PRODUCT"
PORT=18020

LOGDIR="$(mktemp -d)"
NODE_A_LOG="$LOGDIR/nodeA.out"
NODE_B_LOG="$LOGDIR/nodeB.out"

# Resolve LAN IP addresses for --remote-host flags
# Strategy: collect all private IPs from both machines, find a matching subnet.
get_private_ips() {
    # Works on both Linux and macOS
    ssh "$1" "
        if command -v ip >/dev/null 2>&1; then
            ip -4 addr show | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1
        else
            ifconfig -a | grep 'inet ' | awk '{print \$2}'
        fi
    " 2>/dev/null | grep -E '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
}

# Get local private IPs (no ssh needed)
if command -v ip >/dev/null 2>&1; then
    LOCAL_PRIVATE_IPS="$(ip -4 addr show | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | grep -E '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)' || true)"
else
    LOCAL_PRIVATE_IPS="$(ifconfig -a | grep 'inet ' | awk '{print $2}' | grep -E '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)' || true)"
fi
REMOTE_PRIVATE_IPS="$(get_private_ips "$REMOTE_HOST")"

# Find matching /24 subnet
LOCAL_IP=""
REMOTE_IP=""
for local_ip in $LOCAL_PRIVATE_IPS; do
    local_subnet="${local_ip%.*}"
    for remote_ip in $REMOTE_PRIVATE_IPS; do
        remote_subnet="${remote_ip%.*}"
        if [ "$local_subnet" = "$remote_subnet" ]; then
            LOCAL_IP="$local_ip"
            REMOTE_IP="$remote_ip"
            break 2
        fi
    done
done

if [ -z "$LOCAL_IP" ] || [ -z "$REMOTE_IP" ]; then
    echo "ERROR: Could not determine IP addresses."
    echo "  Local IP:  ${LOCAL_IP:-unknown}"
    echo "  Remote IP: ${REMOTE_IP:-unknown}"
    exit 1
fi

# Get the git remote URL to clone from
GIT_REMOTE="$(git -C "$REPO_DIR" remote get-url origin)"
GIT_BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD)"

echo "=== Health Test Runner ==="
echo "Local:   $(hostname) ($LOCAL_IP)"
echo "Remote:  $REMOTE_HOST ($REMOTE_IP)"
echo "Clone:   $GIT_REMOTE @ $GIT_BRANCH -> $REMOTE_HOST:$REMOTE_PATH"
echo "Logs:    $LOGDIR"
echo ""

NODE_B_PID=""
NODE_A_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$NODE_B_PID" ] && kill "$NODE_B_PID" 2>/dev/null || true
    [ -n "$NODE_A_PID" ] && kill "$NODE_A_PID" 2>/dev/null || true
    [ -n "$NODE_B_PID" ] && wait "$NODE_B_PID" 2>/dev/null || true
    [ -n "$NODE_A_PID" ] && wait "$NODE_A_PID" 2>/dev/null || true
    # Clean up remote clone
    echo "Removing remote clone at $REMOTE_HOST:$REMOTE_PATH..."
    ssh "$REMOTE_HOST" "rm -rf '$REMOTE_PATH'" 2>/dev/null || true
}
trap cleanup EXIT

# --- Step 1: Build on Linux ---
echo "[1/7] Building locally..."
cd "$REPO_DIR"
swift build --product "$PRODUCT" 2>&1 | tail -3

# --- Step 2: Deploy to local sudoers path ---
echo "[2/7] Deploying to $LOCAL_BIN..."
mkdir -p "$(dirname "$LOCAL_BIN")"
rm -f "$LOCAL_BIN"
cp ".build/debug/$PRODUCT" "$LOCAL_BIN"

# --- Step 3: Push and clone on remote ---
echo "[3/7] Pushing to remote and cloning on $REMOTE_HOST..."
git push 2>&1 | tail -3
ssh "$REMOTE_HOST" "git clone --branch '$GIT_BRANCH' '$GIT_REMOTE' '$REMOTE_PATH'" 2>&1 | tail -3

# --- Step 4: Build on remote ---
echo "[4/7] Building on $REMOTE_HOST..."
ssh "$REMOTE_HOST" "cd '$REMOTE_PATH' && swift build --disable-sandbox --product $PRODUCT" 2>&1 | tail -3

# --- Step 5: Deploy on remote ---
echo "[5/7] Deploying on $REMOTE_HOST..."
REMOTE_BIN="~/.local/bin/$PRODUCT"
ssh "$REMOTE_HOST" "mkdir -p ~/.local/bin && rm -f $REMOTE_BIN && cp '$REMOTE_PATH/.build/debug/$PRODUCT' $REMOTE_BIN" 2>&1
# codesign on macOS if available
ssh "$REMOTE_HOST" "command -v codesign >/dev/null 2>&1 && codesign -s - --force $REMOTE_BIN" 2>&1 || true

# --- Step 6: Start Node B (remote) ---
echo "[6/7] Starting Node B on $REMOTE_HOST..."
ssh "$REMOTE_HOST" "sudo -n $REMOTE_BIN --role nodeB --port $PORT --lan --remote-host $LOCAL_IP $PHASE_ARG" > "$NODE_B_LOG" 2>&1 &
NODE_B_PID=$!
sleep 3

# Verify Node B started
if ! kill -0 "$NODE_B_PID" 2>/dev/null; then
    echo "ERROR: Node B failed to start. Log:"
    cat "$NODE_B_LOG"
    exit 1
fi
echo "  Node B running (PID $NODE_B_PID)"

# --- Step 7: Start Node A (local, orchestrator) ---
echo "[7/7] Starting Node A locally..."
sudo -n "$LOCAL_BIN" --role nodeA --port "$PORT" --lan --remote-host "$REMOTE_IP" $PHASE_ARG > "$NODE_A_LOG" 2>&1 &
NODE_A_PID=$!

# Wait for Node A to finish (it's the orchestrator)
echo ""
echo "Test running... (tail -f $NODE_A_LOG to watch)"
echo ""
wait "$NODE_A_PID"
NODE_A_EXIT=$?

# Wait for Node B to finish
sleep 5
kill "$NODE_B_PID" 2>/dev/null || true
wait "$NODE_B_PID" 2>/dev/null || true

# --- Print results ---
echo ""
echo "=== Node A Results ==="
grep -E '\[(PASS|FAIL)\]|Total:|ALL TESTS|SOME TESTS' "$NODE_A_LOG"

echo ""
echo "Full logs: $LOGDIR"

exit "$NODE_A_EXIT"
