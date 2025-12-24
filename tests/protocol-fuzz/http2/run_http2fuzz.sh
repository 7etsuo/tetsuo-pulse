#!/bin/bash
#
# run_http2fuzz.sh - Run http2fuzz against the HTTP/2 server harness
#
# Prerequisites:
#   - Go installed
#   - http2fuzz installed: go install github.com/c0nrad/http2fuzz@latest
#
# Usage:
#   ./run_http2fuzz.sh [port]

set -e

PORT=${1:-8443}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
HARNESS="$BUILD_DIR/http2_server_harness"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== HTTP/2 Protocol Fuzzing ===${NC}"
echo ""

# Check if http2fuzz is installed
if ! command -v http2fuzz &> /dev/null; then
    echo -e "${YELLOW}http2fuzz not found. Installing...${NC}"
    if command -v go &> /dev/null; then
        go install github.com/c0nrad/http2fuzz@latest
        export PATH="$PATH:$(go env GOPATH)/bin"
    else
        echo -e "${RED}Error: Go is not installed. Please install Go first.${NC}"
        echo "  Ubuntu/Debian: sudo apt install golang-go"
        echo "  macOS: brew install go"
        exit 1
    fi
fi

# Check if harness exists
if [ ! -x "$HARNESS" ]; then
    echo -e "${YELLOW}Harness not found. Building...${NC}"

    # Build with TLS support
    cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" \
        -DENABLE_TLS=ON \
        -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON \
        -DCMAKE_BUILD_TYPE=Debug

    cmake --build "$BUILD_DIR" --target http2_server_harness -j$(nproc)
fi

# Start the harness in background
echo -e "${GREEN}Starting HTTP/2 server harness on port $PORT...${NC}"
"$HARNESS" "$PORT" &
HARNESS_PID=$!

# Wait for server to start
sleep 1

# Check if harness is running
if ! kill -0 $HARNESS_PID 2>/dev/null; then
    echo -e "${RED}Error: Harness failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}Harness running with PID $HARNESS_PID${NC}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping harness...${NC}"
    kill $HARNESS_PID 2>/dev/null || true
    wait $HARNESS_PID 2>/dev/null || true
}
trap cleanup EXIT

# Run http2fuzz
echo -e "${GREEN}Running http2fuzz...${NC}"
echo "  Target: localhost:$PORT"
echo "  Duration: 60 seconds (Ctrl+C to stop early)"
echo ""

http2fuzz \
    -target="localhost:$PORT" \
    -fuzz-delay=50 \
    -restart-delay=5 \
    2>&1 | head -100

echo ""
echo -e "${GREEN}Fuzzing complete${NC}"
