#!/bin/bash
#
# run-health-test.sh — Build and run the cross-machine health monitoring test
#
# Prerequisites:
#   - Linux host at 192.168.12.121 with sudoers entry for ~/.local/bin/HealthTestRunner
#   - Mac host at 192.168.12.209 (ssh alias "mac") with same sudoers entry
#   - Both machines have the omerta_mesh repo cloned
#   - State files from previous runs are cleaned automatically
#
# Usage:
#   ./scripts/run-health-test.sh
#
# The script starts Node B (Mac) first, then Node A (Linux, orchestrator).
# Results are printed at the end. Exit code 0 = all passed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MAC_HOST="mac"
MAC_REPO="~/omerta_mesh"
PRODUCT="HealthTestRunner"
LOCAL_BIN="$HOME/.local/bin/$PRODUCT"
PORT=18020

LOGDIR="$(mktemp -d /tmp/health-test-XXXXXX)"
NODE_A_LOG="$LOGDIR/nodeA.out"
NODE_B_LOG="$LOGDIR/nodeB.out"
NODE_A_PID=""
NODE_B_PID=""

echo "=== Health Test Runner ==="
echo "Logs: $LOGDIR"
echo ""

cleanup() {
    echo ""
    echo "Cleaning up..."
    # Kill background jobs
    [ -n "$NODE_B_PID" ] && kill "$NODE_B_PID" 2>/dev/null || true
    [ -n "$NODE_A_PID" ] && kill "$NODE_A_PID" 2>/dev/null || true
    [ -n "$NODE_B_PID" ] && wait "$NODE_B_PID" 2>/dev/null || true
    [ -n "$NODE_A_PID" ] && wait "$NODE_A_PID" 2>/dev/null || true
}
trap cleanup EXIT

# --- Step 1: Build on Linux ---
echo "[1/6] Building on Linux..."
cd "$REPO_DIR"
swift build --product "$PRODUCT" 2>&1 | tail -3

# --- Step 2: Deploy to local sudoers path ---
echo "[2/6] Deploying to $LOCAL_BIN..."
mkdir -p "$(dirname "$LOCAL_BIN")"
rm -f "$LOCAL_BIN"
cp ".build/debug/$PRODUCT" "$LOCAL_BIN"

# --- Step 3: Push and build on Mac ---
echo "[3/6] Pushing to remote and building on Mac..."
git push 2>&1 | tail -3
ssh "$MAC_HOST" "cd $MAC_REPO && git pull && swift build --disable-sandbox --product $PRODUCT" 2>&1 | tail -3

# --- Step 4: Deploy on Mac ---
echo "[4/6] Deploying on Mac..."
ssh "$MAC_HOST" "mkdir -p ~/.local/bin && rm -f ~/.local/bin/$PRODUCT && cp $MAC_REPO/.build/debug/$PRODUCT ~/.local/bin/$PRODUCT && codesign -s - --force ~/.local/bin/$PRODUCT" 2>&1

# --- Step 5: Start Node B (Mac) ---
echo "[5/6] Starting Node B on Mac..."
ssh "$MAC_HOST" "sudo -n ~/.local/bin/$PRODUCT --role nodeB --port $PORT --lan --remote-host 192.168.12.121" > "$NODE_B_LOG" 2>&1 &
NODE_B_PID=$!
sleep 3

# Verify Node B started
if ! kill -0 "$NODE_B_PID" 2>/dev/null; then
    echo "ERROR: Node B failed to start. Log:"
    cat "$NODE_B_LOG"
    exit 1
fi
echo "  Node B running (PID $NODE_B_PID)"

# --- Step 6: Start Node A (Linux, orchestrator) ---
echo "[6/6] Starting Node A on Linux..."
sudo -n "$LOCAL_BIN" --role nodeA --port "$PORT" --lan --remote-host 192.168.12.209 > "$NODE_A_LOG" 2>&1 &
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
