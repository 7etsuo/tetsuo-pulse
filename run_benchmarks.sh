#!/bin/bash
set -e

echo "=========================================="
echo "  Socket Library Benchmark Suite"
echo "=========================================="

# Parse arguments
REBUILD_FLAG=""
REQS=10000
THREADS=4

for arg in "$@"; do
    case $arg in
        --rebuild)
            REBUILD_FLAG="--rebuild"
            shift
            ;;
        --reqs=*)
            REQS="${arg#*=}"
            shift
            ;;
        --threads=*)
            THREADS="${arg#*=}"
            shift
            ;;
        *)
            # Assume positional: reqs threads
            if [[ "$arg" =~ ^[0-9]+$ ]]; then
                if [ -z "$REQS_SET" ]; then
                    REQS="$arg"
                    REQS_SET=1
                else
                    THREADS="$arg"
                fi
            fi
            ;;
    esac
done

echo "Configuration:"
echo "  Requests: $REQS"
echo "  Threads: $THREADS"
if [ -n "$REBUILD_FLAG" ]; then
    echo "  Rebuild: Yes"
fi
echo ""

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# Step 1: Clean up ports
echo "=== Step 1: Cleaning up ports ==="
sudo lsof -ti:8080,8081,8082 | xargs -r kill -9 2>/dev/null || true
sleep 1

# Step 2: Rebuild if needed
echo "=== Step 2: Rebuilding (if needed) ==="
cd "$BUILD_DIR"
if [ -n "$REBUILD_FLAG" ] || [ ! -f "benchmark_server" ]; then
    echo "Rebuilding..."
    rm -rf *
    cmake ..
    make -j$(nproc)
    echo "Build complete!"
else
    echo "Skipping rebuild (use --rebuild to force)"
fi
echo ""

# Function to run benchmark against a server
run_benchmark() {
    local SERVER_NAME=$1
    local SERVER_CMD=$2
    local PORT=$3
    
    echo "=========================================="
    echo "  Benchmarking: $SERVER_NAME"
    echo "=========================================="
    
    # Start server
    echo "Starting $SERVER_NAME on port $PORT..."
    $SERVER_CMD &
    SERVER_PID=$!
    sleep 3
    
    # Check if server is running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: $SERVER_NAME crashed on startup!"
        return 1
    fi
    
    # Run client with timeout (calculate timeout: 2 seconds per 1000 requests, minimum 30 seconds)
    local TIMEOUT=$((REQS / 1000 * 2))
    if [ $TIMEOUT -lt 30 ]; then
        TIMEOUT=30
    fi
    if [ $TIMEOUT -gt 300 ]; then
        TIMEOUT=300  # Cap at 5 minutes
    fi
    
    echo "Running benchmark client (timeout: ${TIMEOUT}s)..."
    timeout ${TIMEOUT}s ./benchmark_client --reqs=$REQS --threads=$THREADS --port=$PORT || {
        echo "WARNING: Benchmark client timed out or failed after ${TIMEOUT}s"
        echo "This may indicate the server is slow or unresponsive"
    }
    
    # Cleanup
    kill $SERVER_PID 2>/dev/null || true
    sleep 1
    sudo lsof -ti:$PORT | xargs -r kill -9 2>/dev/null || true
    
    echo ""
    sleep 2
}

# Benchmark 1: Socket Library (port 8080)
run_benchmark "Socket Library" "./benchmark_server" 8080

# Benchmark 2: Raw epoll (port 8081)
run_benchmark "Raw epoll" "./benchmark_raw" 8081

# Benchmark 3: libevent (port 8082)
if [ -f "./benchmark_libevent" ]; then
    run_benchmark "libevent" "./benchmark_libevent" 8082
else
    echo "=========================================="
    echo "  Skipping libevent benchmark"
    echo "=========================================="
    echo "libevent not built (install libevent-dev to enable)"
    echo ""
fi

# Final cleanup
echo "=== Final cleanup ==="
sudo lsof -ti:8080,8081,8082 | xargs -r kill -9 2>/dev/null || true

echo ""
echo "=========================================="
echo "  Benchmark Suite Complete!"
echo "=========================================="
echo ""
echo "Usage examples:"
echo "  ./run_benchmarks.sh                    # Default: 10000 reqs, 4 threads"
echo "  ./run_benchmarks.sh 50000 8            # 50000 reqs, 8 threads"
echo "  ./run_benchmarks.sh --rebuild          # Rebuild and run defaults"
echo "  ./run_benchmarks.sh --reqs=100000 --threads=10  # Named parameters"

