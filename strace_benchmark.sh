#!/bin/bash
#
# strace_benchmark.sh - Run benchmark with strace syscall monitoring
#
# This script runs the HTTP benchmark under strace to prove it's making
# real network syscalls (connect, read, write, etc.).
#
# Usage:
#   ./strace_benchmark.sh                     # Run tetsuo benchmark with strace
#   ./strace_benchmark.sh --curl              # Run curl benchmark with strace
#   ./strace_benchmark.sh --summary           # Show syscall counts only
#   ./strace_benchmark.sh --output trace.log  # Save full trace to file
#
# Output shows proof of real network I/O:
#   - socket() calls creating TCP sockets
#   - connect() establishing connections to server
#   - write()/send() sending HTTP requests
#   - read()/recv() receiving HTTP responses
#   - close() closing connections

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
BENCHMARK="tetsuo"
SUMMARY_MODE=0
OUTPUT_FILE=""
URL="http://127.0.0.1:8080/small"
THREADS=2
REQS=50

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use release build if available
if [ -d "$SCRIPT_DIR/build-release" ]; then
    BUILD_DIR="$SCRIPT_DIR/build-release"
else
    BUILD_DIR="$SCRIPT_DIR/build"
fi

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Run HTTP benchmark under strace to prove real network I/O."
    echo ""
    echo "Options:"
    echo "  --tetsuo             Run tetsuo-socket benchmark (default)"
    echo "  --curl               Run libcurl benchmark"
    echo "  --summary            Show syscall count summary"
    echo "  --output <file>      Save full strace output to file"
    echo "  --url <url>          Target URL (default: http://127.0.0.1:8080/small)"
    echo "  --threads <n>        Thread count (default: 2)"
    echo "  --reqs <n>           Requests per thread (default: 50)"
    echo "  -h, --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                           # Quick trace of tetsuo benchmark"
    echo "  $0 --summary                 # Show syscall counts"
    echo "  $0 --curl --summary          # Compare curl syscalls"
    echo "  $0 --output trace.log        # Save full trace for analysis"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tetsuo)
            BENCHMARK="tetsuo"
            shift
            ;;
        --curl)
            BENCHMARK="curl"
            shift
            ;;
        --summary)
            SUMMARY_MODE=1
            shift
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --reqs)
            REQS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Check strace is available
if ! command -v strace &> /dev/null; then
    echo -e "${RED}Error: strace not installed${NC}"
    echo "Install with: sudo apt install strace"
    exit 1
fi

# Determine benchmark binary
if [ "$BENCHMARK" = "tetsuo" ]; then
    BENCH_BIN="$BUILD_DIR/benchmark_http_tetsuo"
    BENCH_NAME="tetsuo-socket"
else
    BENCH_BIN="$BUILD_DIR/benchmark_http_curl"
    BENCH_NAME="libcurl"
fi

# Check benchmark exists
if [ ! -f "$BENCH_BIN" ]; then
    echo -e "${RED}Error: $BENCH_BIN not found${NC}"
    echo "Build with: cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DBUILD_HTTP_BENCHMARKS=ON && cmake --build build-release"
    exit 1
fi

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Strace Benchmark Monitor${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Benchmark: $BENCH_NAME"
echo "URL: $URL"
echo "Threads: $THREADS"
echo "Requests per thread: $REQS"
echo ""

# Syscalls to trace
SYSCALLS="socket,connect,accept,accept4,bind,listen,read,write,send,recv,sendto,recvfrom,sendmsg,recvmsg,close,shutdown,poll,epoll_wait,epoll_ctl"

if [ $SUMMARY_MODE -eq 1 ]; then
    echo -e "${CYAN}Running with syscall summary...${NC}"
    echo ""

    # Run with -c for summary
    strace -f -c -e trace=$SYSCALLS -- "$BENCH_BIN" \
        --url="$URL" \
        --threads=$THREADS \
        --requests=$REQS \
        --http1 2>&1 | tee /tmp/strace_summary.txt

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Syscall Analysis${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    # Extract key syscall counts
    # strace -c format: % time | seconds | usecs/call | calls | [errors] | syscall
    echo "Key network syscalls from benchmark:"
    echo ""

    # Use awk to find syscall lines and extract call count (4th field)
    socket_count=$(awk '/socket$/{print $4}' /tmp/strace_summary.txt 2>/dev/null || echo "0")
    connect_count=$(awk '/connect$/{print $4}' /tmp/strace_summary.txt 2>/dev/null || echo "0")
    write_count=$(awk '/write$/{print $4}' /tmp/strace_summary.txt 2>/dev/null || echo "0")
    sendto_count=$(awk '/sendto$/{print $4}' /tmp/strace_summary.txt 2>/dev/null || echo "0")
    read_count=$(awk '/[^f]read$/{print $4}' /tmp/strace_summary.txt 2>/dev/null || echo "0")
    recvfrom_count=$(awk '/recvfrom$/{print $4}' /tmp/strace_summary.txt 2>/dev/null || echo "0")
    close_count=$(awk '/close$/{print $4}' /tmp/strace_summary.txt 2>/dev/null || echo "0")

    # Default to 0 if empty
    socket_count=${socket_count:-0}
    connect_count=${connect_count:-0}
    write_count=${write_count:-0}
    sendto_count=${sendto_count:-0}
    read_count=${read_count:-0}
    recvfrom_count=${recvfrom_count:-0}
    close_count=${close_count:-0}

    echo -e "  ${GREEN}socket()${NC}:   $socket_count  (TCP sockets created)"
    echo -e "  ${GREEN}connect()${NC}:  $connect_count  (connections established)"
    echo -e "  ${YELLOW}write()${NC}:    $write_count  (data sent via write)"
    echo -e "  ${YELLOW}sendto()${NC}:   $sendto_count  (data sent via sendto)"
    echo -e "  ${CYAN}read()${NC}:     $read_count  (data received via read)"
    echo -e "  ${CYAN}recvfrom()${NC}: $recvfrom_count  (data received via recvfrom)"
    echo -e "  ${RED}close()${NC}:    $close_count  (connections closed)"
    echo ""

    total_sends=$((write_count + sendto_count))
    total_recvs=$((read_count + recvfrom_count))
    expected_reqs=$((THREADS * REQS))

    echo "Summary:"
    echo "  Expected requests: $expected_reqs"
    echo "  Total send syscalls: $total_sends"
    echo "  Total recv syscalls: $total_recvs"
    echo ""

    if [ "$connect_count" -gt 0 ] && [ "$total_sends" -gt 0 ] && [ "$total_recvs" -gt 0 ]; then
        echo -e "${GREEN}VERIFIED: Benchmark made real network syscalls${NC}"
    else
        echo -e "${RED}WARNING: Unexpected syscall counts${NC}"
    fi

elif [ -n "$OUTPUT_FILE" ]; then
    echo -e "${CYAN}Running with full trace output to: $OUTPUT_FILE${NC}"
    echo ""

    strace -f -tt -e trace=$SYSCALLS -o "$OUTPUT_FILE" -- "$BENCH_BIN" \
        --url="$URL" \
        --threads=$THREADS \
        --requests=$REQS \
        --http1

    echo ""
    echo -e "${GREEN}Trace saved to: $OUTPUT_FILE${NC}"
    echo ""
    echo "Sample of trace (first 20 network calls):"
    grep -E "(connect|write|read|send|recv)" "$OUTPUT_FILE" | head -20

else
    echo -e "${CYAN}Running with live trace output...${NC}"
    echo ""
    echo "Format: [PID] TIMESTAMP syscall(args) = result"
    echo "---------------------------------------------------"
    echo ""

    # Run with filtered output, hide poll/epoll spam
    strace -f -tt -e trace=$SYSCALLS -- "$BENCH_BIN" \
        --url="$URL" \
        --threads=$THREADS \
        --requests=$REQS \
        --http1 2>&1 | grep -vE "(poll|epoll)" | head -100

    echo ""
    echo "(output truncated to 100 lines, use --output for full trace)"
fi

echo ""
