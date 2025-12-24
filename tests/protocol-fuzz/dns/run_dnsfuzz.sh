#!/bin/bash
#
# run_dnsfuzz.sh - Run dns-fuzz-server against the DNS resolver harness
#
# Prerequisites:
#   - dns-fuzz-server: https://github.com/sischkg/dns-fuzz-server
#   - Build: cmake . && make
#
# Usage:
#   ./run_dnsfuzz.sh [iterations]
#
# The script will:
#   1. Build dns-fuzz-server if needed
#   2. Start the fuzz server
#   3. Run our resolver harness against it

set -e

ITERATIONS=${1:-1000}
FUZZ_PORT=10053
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
HARNESS="$BUILD_DIR/dns_resolver_harness"
FUZZ_SERVER_DIR="$HOME/.local/share/dns-fuzz-server"
FUZZ_SERVER="$FUZZ_SERVER_DIR/dns-fuzz-server"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== DNS Protocol Fuzzing ===${NC}"
echo ""

# Check/install dns-fuzz-server
install_dns_fuzz_server() {
    echo -e "${YELLOW}Installing dns-fuzz-server...${NC}"

    mkdir -p "$FUZZ_SERVER_DIR"
    cd "$FUZZ_SERVER_DIR"

    if [ ! -d ".git" ]; then
        git clone https://github.com/sischkg/dns-fuzz-server.git .
    fi

    cmake . -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)

    cd "$SCRIPT_DIR"
}

if [ ! -x "$FUZZ_SERVER" ]; then
    install_dns_fuzz_server
fi

# Check if our harness exists
if [ ! -x "$HARNESS" ]; then
    echo -e "${YELLOW}Harness not found. Building...${NC}"

    cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" \
        -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON \
        -DCMAKE_BUILD_TYPE=Debug

    cmake --build "$BUILD_DIR" --target dns_resolver_harness -j$(nproc)
fi

# Start dns-fuzz-server in background
echo -e "${GREEN}Starting dns-fuzz-server on port $FUZZ_PORT...${NC}"
"$FUZZ_SERVER" \
    --address 127.0.0.1 \
    --port $FUZZ_PORT \
    --fuzz-type random \
    2>&1 | sed 's/^/[fuzz-server] /' &
FUZZ_PID=$!

sleep 2

if ! kill -0 $FUZZ_PID 2>/dev/null; then
    echo -e "${RED}Error: dns-fuzz-server failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}dns-fuzz-server running with PID $FUZZ_PID${NC}"
echo ""

# Cleanup
cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping dns-fuzz-server...${NC}"
    kill $FUZZ_PID 2>/dev/null || true
    wait $FUZZ_PID 2>/dev/null || true
}
trap cleanup EXIT

# Run our resolver harness
echo -e "${GREEN}Running DNS resolver harness...${NC}"
echo "  Server: 127.0.0.1:$FUZZ_PORT"
echo "  Iterations: $ITERATIONS"
echo ""

"$HARNESS" \
    --server 127.0.0.1 \
    --port $FUZZ_PORT \
    --iterations $ITERATIONS

echo ""
echo -e "${GREEN}DNS fuzzing complete${NC}"
