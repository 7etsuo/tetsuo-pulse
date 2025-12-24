#!/bin/bash
#
# run_tlsfuzzer.sh - Run tlsfuzzer tests against the TLS server harness
#
# Prerequisites:
#   - Python 3 with pip
#   - tlsfuzzer installed: pip install tlsfuzzer tlslite-ng
#
# Usage:
#   ./run_tlsfuzzer.sh [port] [test-script]
#
# Examples:
#   ./run_tlsfuzzer.sh                        # Run all basic tests
#   ./run_tlsfuzzer.sh 4433 test-tls-version  # Run specific test

set -e

PORT=${1:-4433}
TEST_SCRIPT=${2:-""}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
HARNESS="$BUILD_DIR/tls_server_harness"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== TLS Protocol Fuzzing with tlsfuzzer ===${NC}"
echo ""

# Check Python and tlsfuzzer
check_tlsfuzzer() {
    if python3 -c "import tlsfuzzer" 2>/dev/null; then
        return 0
    fi
    return 1
}

if ! check_tlsfuzzer; then
    echo -e "${YELLOW}tlsfuzzer not found. Installing...${NC}"
    pip3 install --user tlsfuzzer tlslite-ng
    export PATH="$PATH:$HOME/.local/bin"
fi

# Check if harness exists
if [ ! -x "$HARNESS" ]; then
    echo -e "${YELLOW}Harness not found. Building...${NC}"

    cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" \
        -DENABLE_TLS=ON \
        -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON \
        -DCMAKE_BUILD_TYPE=Debug

    cmake --build "$BUILD_DIR" --target tls_server_harness -j$(nproc)
fi

# Start harness in background
echo -e "${GREEN}Starting TLS server harness on port $PORT...${NC}"
"$HARNESS" "$PORT" &
HARNESS_PID=$!

sleep 1

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

# Common tlsfuzzer test scripts
BASIC_TESTS=(
    "test-tls13-conversation"
    "test-tls13-finished"
    "test-tls13-record-layer-limits"
    "test-tls13-version-negotiation"
    "test-tls12-conversation"
    "test-record-layer-fragmentation"
    "test-invalid-compression-methods"
    "test-client-hello-padding"
    "test-sessionID-resumption"
    "test-early-application-data"
)

# Run specific test or all tests
run_test() {
    local test_name=$1
    echo -e "${GREEN}Running: $test_name${NC}"

    # Find the script in tlsfuzzer
    python3 -m tlsfuzzer.scripts.$test_name \
        -h localhost \
        -p $PORT \
        --no-ssl2 \
        2>&1 || {
        echo -e "${YELLOW}Test $test_name failed or not available${NC}"
        return 1
    }
}

if [ -n "$TEST_SCRIPT" ]; then
    # Run specific test
    run_test "$TEST_SCRIPT"
else
    # Run all basic tests
    echo -e "${GREEN}Running basic TLS conformance tests...${NC}"
    echo ""

    passed=0
    failed=0
    skipped=0

    for test in "${BASIC_TESTS[@]}"; do
        if run_test "$test"; then
            ((passed++))
        else
            ((failed++))
        fi
        echo ""
    done

    echo ""
    echo -e "${GREEN}=== Summary ===${NC}"
    echo -e "  Passed:  $passed"
    echo -e "  Failed:  $failed"
fi

echo ""
echo -e "${GREEN}Fuzzing complete${NC}"
