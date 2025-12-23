#!/bin/bash
#
# HTTP Client Benchmark Suite: tetsuo-socket vs libcurl
#
# Compares HTTP client performance against nginx reference server.
#
# Prerequisites:
#   - nginx installed and configured with test endpoints
#   - libcurl-dev installed for curl benchmark
#   - Build with: cmake -B build -DBUILD_HTTP_BENCHMARKS=ON
#
# Usage:
#   ./run_http_benchmarks.sh              # Run all scenarios
#   ./run_http_benchmarks.sh --http1      # HTTP/1.1 only
#   ./run_http_benchmarks.sh --http2      # HTTP/2 only
#   ./run_http_benchmarks.sh --rebuild    # Rebuild before running

set -e

echo "=========================================="
echo "  HTTP Client Benchmark Suite"
echo "  tetsuo-socket vs libcurl"
echo "=========================================="
echo ""

# Parse arguments
# Note: Keep total requests low (<2000) until issue #119 (HTTP client memory
# corruption) is fixed
REBUILD_FLAG=""
REQS=100
THREADS=4
HTTP_VERSION="both"
NGINX_PORT=8080
NGINX_TLS_PORT=8443
OUTPUT_DIR="benchmark_results"

for arg in "$@"; do
    case $arg in
        --rebuild)
            REBUILD_FLAG="1"
            ;;
        --http1)
            HTTP_VERSION="http1"
            ;;
        --http2)
            HTTP_VERSION="http2"
            ;;
        --reqs=*)
            REQS="${arg#*=}"
            ;;
        --threads=*)
            THREADS="${arg#*=}"
            ;;
        --port=*)
            NGINX_PORT="${arg#*=}"
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --rebuild          Rebuild benchmarks before running"
            echo "  --http1            Run HTTP/1.1 benchmarks only"
            echo "  --http2            Run HTTP/2 benchmarks only"
            echo "  --reqs=N           Requests per thread (default: 10000)"
            echo "  --threads=N        Number of threads (default: 4)"
            echo "  --port=N           nginx HTTP port (default: 8080)"
            echo ""
            echo "Prerequisites:"
            echo "  1. nginx running with test endpoints:"
            echo "     - GET /small (100 byte response)"
            echo "     - GET /medium (4KB response)"
            echo "     - GET /large (1MB response)"
            echo ""
            echo "  2. Build benchmarks:"
            echo "     cmake -B build -DBUILD_HTTP_BENCHMARKS=ON"
            echo "     cmake --build build"
            exit 0
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use build-release for performance benchmarks (no sanitizers)
# Fall back to build/ if build-release doesn't exist
if [ -d "$SCRIPT_DIR/build-release" ]; then
    BUILD_DIR="$SCRIPT_DIR/build-release"
else
    BUILD_DIR="$SCRIPT_DIR/build"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Configuration:"
echo "  Requests per thread: $REQS"
echo "  Threads: $THREADS"
echo "  HTTP version: $HTTP_VERSION"
echo "  nginx port: $NGINX_PORT"
echo "  Output directory: $OUTPUT_DIR"
echo ""

# Check nginx is running
check_nginx() {
    local url="http://127.0.0.1:$NGINX_PORT/small"
    if curl -s --max-time 2 "$url" > /dev/null 2>&1; then
        echo "nginx is running on port $NGINX_PORT"
        return 0
    else
        echo "ERROR: nginx not responding on port $NGINX_PORT"
        echo ""
        echo "Please start nginx with test endpoints. Example config:"
        echo ""
        echo "  server {"
        echo "      listen $NGINX_PORT;"
        echo "      location /small { return 200 'x{100}'; }"
        echo "      location /medium { alias /tmp/bench_4k.txt; }"
        echo "      location /large { alias /tmp/bench_1m.txt; }"
        echo "  }"
        echo ""
        echo "Or create test files:"
        echo "  head -c 100 /dev/zero | tr '\\0' 'x' > /tmp/bench_100.txt"
        echo "  head -c 4096 /dev/zero | tr '\\0' 'x' > /tmp/bench_4k.txt"
        echo "  head -c 1048576 /dev/zero | tr '\\0' 'x' > /tmp/bench_1m.txt"
        return 1
    fi
}

# Rebuild if needed - always use Release mode for benchmarks
if [ -n "$REBUILD_FLAG" ] || [ ! -f "$BUILD_DIR/benchmark_http_tetsuo" ]; then
    echo "=== Building benchmarks (Release mode) ==="

    # Create build-release directory if it doesn't exist
    if [ ! -d "$SCRIPT_DIR/build-release" ]; then
        mkdir -p "$SCRIPT_DIR/build-release"
        BUILD_DIR="$SCRIPT_DIR/build-release"
    fi

    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_HTTP_BENCHMARKS=ON -DENABLE_SANITIZERS=OFF
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu) benchmark_http_tetsuo benchmark_http_curl 2>/dev/null || \
        make benchmark_http_tetsuo  # curl benchmark may not be available
    cd "$SCRIPT_DIR"
    echo ""
fi

# Check benchmarks exist
if [ ! -f "$BUILD_DIR/benchmark_http_tetsuo" ]; then
    echo "ERROR: benchmark_http_tetsuo not found"
    echo "Build with: cmake -B build -DBUILD_HTTP_BENCHMARKS=ON && cmake --build build"
    exit 1
fi

HAVE_CURL=0
if [ -f "$BUILD_DIR/benchmark_http_curl" ]; then
    HAVE_CURL=1
else
    echo "WARNING: benchmark_http_curl not found (libcurl not installed?)"
    echo "Install libcurl-dev and rebuild to enable curl benchmark"
    echo ""
fi

# Check nginx
check_nginx || exit 1
echo ""

# Run a single benchmark scenario
run_scenario() {
    local name="$1"
    local http_flag="$2"
    local url="$3"
    local tetsuo_output="$OUTPUT_DIR/tetsuo_${name}.json"
    local curl_output="$OUTPUT_DIR/curl_${name}.json"

    echo "=========================================="
    echo "  Scenario: $name"
    echo "=========================================="
    echo "URL: $url"
    echo ""

    # Run tetsuo-socket benchmark
    echo "--- tetsuo-socket ---"
    "$BUILD_DIR/benchmark_http_tetsuo" \
        --url="$url" \
        --threads=$THREADS \
        --requests=$REQS \
        $http_flag \
        --output="$tetsuo_output"

    # Run libcurl benchmark if available
    if [ $HAVE_CURL -eq 1 ]; then
        echo "--- libcurl ---"
        "$BUILD_DIR/benchmark_http_curl" \
            --url="$url" \
            --threads=$THREADS \
            --requests=$REQS \
            $http_flag \
            --output="$curl_output"
    fi

    echo ""
}

# Run HTTP/1.1 scenarios
if [ "$HTTP_VERSION" = "both" ] || [ "$HTTP_VERSION" = "http1" ]; then
    echo ""
    echo "############################################"
    echo "#           HTTP/1.1 Benchmarks           #"
    echo "############################################"
    echo ""

    run_scenario "http1_small" "--http1" "http://127.0.0.1:$NGINX_PORT/small"
    run_scenario "http1_concurrent" "--http1" "http://127.0.0.1:$NGINX_PORT/small"
fi

# Run HTTP/2 scenarios
if [ "$HTTP_VERSION" = "both" ] || [ "$HTTP_VERSION" = "http2" ]; then
    echo ""
    echo "############################################"
    echo "#            HTTP/2 Benchmarks            #"
    echo "############################################"
    echo ""

    run_scenario "http2_small" "--http2" "http://127.0.0.1:$NGINX_PORT/small"
    run_scenario "http2_concurrent" "--http2" "http://127.0.0.1:$NGINX_PORT/small"
fi

# Generate comparison summary
echo ""
echo "=========================================="
echo "  Benchmark Summary"
echo "=========================================="
echo ""
echo "Results saved to: $OUTPUT_DIR/"
echo ""

# Print comparison table if both benchmarks ran
if [ $HAVE_CURL -eq 1 ]; then
    echo "Comparison (requests/sec):"
    echo "--------------------------"
    printf "%-20s %15s %15s %10s\n" "Scenario" "tetsuo-socket" "libcurl" "Winner"
    echo "-----------------------------------------------------------"

    for f in "$OUTPUT_DIR"/tetsuo_*.json; do
        if [ -f "$f" ]; then
            scenario=$(basename "$f" .json | sed 's/tetsuo_//')
            curl_file="$OUTPUT_DIR/curl_${scenario}.json"

            if [ -f "$curl_file" ]; then
                tetsuo_rps=$(grep -o '"requests_per_sec": [0-9.]*' "$f" | grep -o '[0-9.]*')
                curl_rps=$(grep -o '"requests_per_sec": [0-9.]*' "$curl_file" | grep -o '[0-9.]*')

                # Determine winner
                winner="tie"
                if command -v bc &> /dev/null; then
                    if [ "$(echo "$tetsuo_rps > $curl_rps" | bc)" -eq 1 ]; then
                        winner="tetsuo"
                    elif [ "$(echo "$curl_rps > $tetsuo_rps" | bc)" -eq 1 ]; then
                        winner="libcurl"
                    fi
                fi

                printf "%-20s %15.2f %15.2f %10s\n" "$scenario" "$tetsuo_rps" "$curl_rps" "$winner"
            fi
        fi
    done
    echo ""
fi

echo "=========================================="
echo "  Benchmark Suite Complete!"
echo "=========================================="
echo ""
echo "To analyze results:"
echo "  cat $OUTPUT_DIR/*.json | jq ."
echo ""
echo "To run individual benchmarks:"
echo "  $BUILD_DIR/benchmark_http_tetsuo --url=http://127.0.0.1:8080/small --threads=4"
echo "  $BUILD_DIR/benchmark_http_curl --url=http://127.0.0.1:8080/small --threads=4"
