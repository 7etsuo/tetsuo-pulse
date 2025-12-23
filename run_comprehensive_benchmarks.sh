#!/bin/bash
#
# Comprehensive HTTP Client Benchmark Suite
#
# Compares tetsuo-socket performance against libcurl, libevent, and Boost.Beast.
# Outputs detailed metrics and comparison tables.
#
# Usage:
#   ./run_comprehensive_benchmarks.sh                  # Full suite
#   ./run_comprehensive_benchmarks.sh --quick          # Quick test (fewer requests)
#   ./run_comprehensive_benchmarks.sh --trace          # Enable function tracing
#   ./run_comprehensive_benchmarks.sh --markdown       # Output as markdown table
#   ./run_comprehensive_benchmarks.sh --suite=http1    # Run specific suite
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build-release"
BUILD_TRACE_DIR="$SCRIPT_DIR/build-trace"
OUTPUT_DIR="$SCRIPT_DIR/benchmark_results"
NGINX_PORT=8080
NGINX_TLS_PORT=8443

# Default test parameters
THREADS=4
QUICK_REQS=100
FULL_REQS=10000
REQS=$FULL_REQS
TRACE_MODE=0
MARKDOWN_OUTPUT=0
REBUILD=0
SUITE="all"  # all, http1, tls, concurrency, payloads, connections

# Available libraries (populated during check)
HAVE_TETSUO=0
HAVE_CURL=0
HAVE_LIBEVENT=0
HAVE_BEAST=0

# Parse arguments
for arg in "$@"; do
    case $arg in
        --quick)
            REQS=$QUICK_REQS
            ;;
        --trace)
            TRACE_MODE=1
            ;;
        --markdown)
            MARKDOWN_OUTPUT=1
            ;;
        --rebuild)
            REBUILD=1
            ;;
        --threads=*)
            THREADS="${arg#*=}"
            ;;
        --reqs=*)
            REQS="${arg#*=}"
            ;;
        --suite=*)
            SUITE="${arg#*=}"
            ;;
        --help|-h)
            echo "Comprehensive HTTP Benchmark Suite"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --quick         Run quick tests (100 requests vs 10000)"
            echo "  --trace         Enable function tracing (slower but shows call graph)"
            echo "  --markdown      Output results as markdown table"
            echo "  --rebuild       Force rebuild of benchmarks"
            echo "  --threads=N     Number of threads for multi-threaded tests (default: 4)"
            echo "  --reqs=N        Requests per thread (default: 10000)"
            echo "  --suite=NAME    Run specific suite: all, http1, tls, concurrency, payloads, connections"
            echo ""
            echo "Libraries benchmarked:"
            echo "  - tetsuo-socket (always available)"
            echo "  - libcurl (requires libcurl-dev)"
            echo "  - libevent (requires libevent-dev)"
            echo "  - Boost.Beast (requires libboost-all-dev)"
            echo ""
            exit 0
            ;;
    esac
done

# Print header
print_header() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║                      Comprehensive HTTP Benchmark Suite                              ║${NC}"
    echo -e "${BOLD}║              tetsuo-socket vs libcurl vs libevent vs Boost.Beast                     ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Print section
print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Print subsection
print_subsection() {
    echo ""
    echo -e "${CYAN}  ── $1 ──${NC}"
}

# Check nginx endpoints (verify 200 status and correct size)
check_endpoint() {
    local url="$1"
    local name="$2"
    local expected_size="$3"  # Optional expected size

    local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null)
    if [ "$status" = "200" ]; then
        if [ -n "$expected_size" ]; then
            local actual_size=$(curl -s --max-time 2 "$url" 2>/dev/null | wc -c)
            if [ "$actual_size" -ge "$expected_size" ]; then
                echo -e "  ${GREEN}✓${NC} $name (${actual_size} bytes)"
                return 0
            else
                echo -e "  ${YELLOW}✗${NC} $name (wrong size: ${actual_size}B, expected ~${expected_size}B)"
                return 1
            fi
        else
            echo -e "  ${GREEN}✓${NC} $name"
            return 0
        fi
    else
        echo -e "  ${YELLOW}✗${NC} $name (HTTP $status)"
        return 1
    fi
}

# Check nginx is running and detect available endpoints
check_nginx() {
    echo -e "${BOLD}Checking endpoints...${NC}"

    local have_basic=0

    # Basic endpoints with size verification
    if check_endpoint "http://127.0.0.1:$NGINX_PORT/small" "/small" 100; then
        have_basic=1
    fi

    # Size variants with expected sizes
    check_endpoint "http://127.0.0.1:$NGINX_PORT/medium" "/medium" 4000 || true
    check_endpoint "http://127.0.0.1:$NGINX_PORT/large" "/large" 1000000 || true

    # TLS endpoint
    if curl -sk --max-time 2 "https://127.0.0.1:$NGINX_TLS_PORT/small" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} HTTPS on port $NGINX_TLS_PORT"
        HAVE_TLS=1
    else
        echo -e "  ${YELLOW}✗${NC} HTTPS on port $NGINX_TLS_PORT (not available)"
        HAVE_TLS=0
    fi

    if [ $have_basic -eq 0 ]; then
        echo ""
        echo -e "${RED}ERROR: nginx not responding on port $NGINX_PORT${NC}"
        exit 1
    fi
}

# Build benchmarks
build_benchmarks() {
    local build_dir="$1"
    local trace_flag="$2"

    if [ ! -d "$build_dir" ] || [ $REBUILD -eq 1 ]; then
        echo -e "${YELLOW}Building benchmarks in $build_dir...${NC}"
        mkdir -p "$build_dir"
        cd "$build_dir"

        cmake_flags="-DCMAKE_BUILD_TYPE=Release -DBUILD_HTTP_BENCHMARKS=ON -DENABLE_SANITIZERS=OFF"
        if [ -n "$trace_flag" ]; then
            cmake_flags="$cmake_flags -DENABLE_TRACING=ON"
        fi

        cmake .. $cmake_flags > /dev/null 2>&1
        make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu) \
            benchmark_http_tetsuo \
            benchmark_http_curl \
            benchmark_http_libevent \
            benchmark_http_beast 2>/dev/null || true
        cd "$SCRIPT_DIR"
    fi

    # Check which benchmarks are available
    if [ -f "$build_dir/benchmark_http_tetsuo" ]; then
        HAVE_TETSUO=1
        echo -e "${GREEN}✓${NC} tetsuo-socket benchmark"
    fi
    if [ -f "$build_dir/benchmark_http_curl" ]; then
        HAVE_CURL=1
        echo -e "${GREEN}✓${NC} libcurl benchmark"
    else
        echo -e "${YELLOW}✗${NC} libcurl benchmark (install libcurl-dev)"
    fi
    if [ -f "$build_dir/benchmark_http_libevent" ]; then
        HAVE_LIBEVENT=1
        echo -e "${GREEN}✓${NC} libevent benchmark"
    else
        echo -e "${YELLOW}✗${NC} libevent benchmark (install libevent-dev)"
    fi
    if [ -f "$build_dir/benchmark_http_beast" ]; then
        HAVE_BEAST=1
        echo -e "${GREEN}✓${NC} Boost.Beast benchmark"
    else
        echo -e "${YELLOW}✗${NC} Boost.Beast benchmark (install libboost-all-dev)"
    fi

    if [ $HAVE_TETSUO -eq 0 ]; then
        echo -e "${RED}ERROR: Failed to build tetsuo-socket benchmark${NC}"
        exit 1
    fi
}

# Run a single benchmark and extract metrics
run_single_benchmark() {
    local binary="$1"
    local url="$2"
    local extra_flags="$3"
    local threads="$4"
    local reqs="$5"
    local output_file="$6"

    # Run benchmark, suppress console output
    "$binary" \
        --url="$url" \
        --threads=$threads \
        --requests=$reqs \
        $extra_flags \
        --output="$output_file" > /dev/null 2>&1 || true

    # Extract metrics from JSON file
    if [ -f "$output_file" ]; then
        local rps=$(command grep '"requests_per_sec"' "$output_file" | sed 's/.*: *\([0-9.]*\).*/\1/')
        local p50=$(command grep '"p50"' "$output_file" | sed 's/.*: *\([0-9.]*\).*/\1/')
        [ -z "$rps" ] && rps=0
        [ -z "$p50" ] && p50=0
        echo "$rps,$p50"
    else
        echo "0,0"
    fi
}

# Helper: Check if endpoint has valid content (not 404 page)
endpoint_valid() {
    local url="$1"
    local min_size="$2"
    local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null)
    if [ "$status" != "200" ]; then
        return 1
    fi
    local size=$(curl -s --max-time 2 "$url" 2>/dev/null | wc -c)
    [ "$size" -ge "$min_size" ]
}

# Format number with commas (handle decimals)
format_num() {
    local num="${1%.*}"
    [ -z "$num" ] && num=0
    printf "%'d" "$num" 2>/dev/null || printf "%d" "$num"
}

# Calculate speedup safely
calc_speedup() {
    local a="$1"
    local b="$2"
    if command -v bc &> /dev/null; then
        if [ -n "$b" ] && [ "$b" != "0" ] && [ "$(echo "$b > 0" | bc 2>/dev/null)" = "1" ]; then
            echo "scale=2; $a / $b" | bc 2>/dev/null
        else
            echo "-"
        fi
    else
        echo "-"
    fi
}

# Print 4-library table header
print_table_header() {
    echo ""
    if [ $MARKDOWN_OUTPUT -eq 1 ]; then
        echo "| Scenario | tetsuo | curl | libevent | beast | Best |"
        echo "|----------|--------|------|----------|-------|------|"
    else
        echo -e "                              ${BOLD}Throughput (requests/sec)${NC}"
        echo "  ┌───────────────────────┬────────────┬────────────┬────────────┬────────────┬────────┐"
        echo -e "  │ ${BOLD}Scenario${NC}              │ ${BOLD}    tetsuo${NC} │ ${BOLD}      curl${NC} │ ${BOLD}  libevent${NC} │ ${BOLD}     beast${NC} │ ${BOLD}  Best${NC} │"
        echo "  ├───────────────────────┼────────────┼────────────┼────────────┼────────────┼────────┤"
    fi
}

# Print table footer
print_table_footer() {
    if [ $MARKDOWN_OUTPUT -ne 1 ]; then
        echo "  └───────────────────────┴────────────┴────────────┴────────────┴────────────┴────────┘"
    fi
}

# Arrays to store all results for summary
declare -a ALL_TETSUO_RPS ALL_CURL_RPS ALL_LIBEVENT_RPS ALL_BEAST_RPS ALL_SCENARIOS

# Run a test scenario with all available libraries
run_scenario() {
    local name="$1"
    local url="$2"
    local extra_flags="$3"
    local threads="${4:-$THREADS}"
    local reqs="${5:-$REQS}"

    # Run each available benchmark
    local t_rps=0 t_p50=0
    local c_rps=0 c_p50=0
    local e_rps=0 e_p50=0
    local b_rps=0 b_p50=0

    if [ $HAVE_TETSUO -eq 1 ]; then
        local result=$(run_single_benchmark "$BENCH_DIR/benchmark_http_tetsuo" "$url" "$extra_flags" "$threads" "$reqs" "$OUTPUT_DIR/tetsuo_${name}.json")
        IFS=',' read -r t_rps t_p50 <<< "$result"
    fi
    if [ $HAVE_CURL -eq 1 ]; then
        local result=$(run_single_benchmark "$BENCH_DIR/benchmark_http_curl" "$url" "$extra_flags" "$threads" "$reqs" "$OUTPUT_DIR/curl_${name}.json")
        IFS=',' read -r c_rps c_p50 <<< "$result"
    fi
    if [ $HAVE_LIBEVENT -eq 1 ]; then
        local result=$(run_single_benchmark "$BENCH_DIR/benchmark_http_libevent" "$url" "$extra_flags" "$threads" "$reqs" "$OUTPUT_DIR/libevent_${name}.json")
        IFS=',' read -r e_rps e_p50 <<< "$result"
    fi
    if [ $HAVE_BEAST -eq 1 ]; then
        local result=$(run_single_benchmark "$BENCH_DIR/benchmark_http_beast" "$url" "$extra_flags" "$threads" "$reqs" "$OUTPUT_DIR/beast_${name}.json")
        IFS=',' read -r b_rps b_p50 <<< "$result"
    fi

    # Store for summary
    ALL_SCENARIOS+=("$name")
    ALL_TETSUO_RPS+=("$t_rps")
    ALL_CURL_RPS+=("$c_rps")
    ALL_LIBEVENT_RPS+=("$e_rps")
    ALL_BEAST_RPS+=("$b_rps")

    # Find best performer
    local best="tetsuo"
    local best_rps="$t_rps"
    if command -v bc &> /dev/null; then
        [ "$(echo "$c_rps > $best_rps" | bc 2>/dev/null)" = "1" ] && best="curl" && best_rps="$c_rps"
        [ "$(echo "$e_rps > $best_rps" | bc 2>/dev/null)" = "1" ] && best="libevent" && best_rps="$e_rps"
        [ "$(echo "$b_rps > $best_rps" | bc 2>/dev/null)" = "1" ] && best="beast" && best_rps="$b_rps"
    fi

    # Print row
    if [ $MARKDOWN_OUTPUT -eq 1 ]; then
        printf "| %-22s | %10.0f | %10.0f | %10.0f | %10.0f | %s |\n" \
            "$name" "$t_rps" "$c_rps" "$e_rps" "$b_rps" "$best"
    else
        # Highlight the winner in green
        local t_str=$(printf "%'10.0f" "$t_rps")
        local c_str=$(printf "%'10.0f" "$c_rps")
        local e_str=$(printf "%'10.0f" "$e_rps")
        local b_str=$(printf "%'10.0f" "$b_rps")

        [ "$best" = "tetsuo" ] && t_str="${GREEN}${t_str}${NC}"
        [ "$best" = "curl" ] && c_str="${GREEN}${c_str}${NC}"
        [ "$best" = "libevent" ] && e_str="${GREEN}${e_str}${NC}"
        [ "$best" = "beast" ] && b_str="${GREEN}${b_str}${NC}"

        printf "  │ %-21s │ ${t_str} │ ${c_str} │ ${e_str} │ ${b_str} │ %6s │\n" \
            "$name" "$best"
    fi
}

# Suite: HTTP/1.1 Basic Tests
run_suite_http1() {
    print_subsection "HTTP/1.1 Basic Tests"
    print_table_header

    run_scenario "http1_small_100B" "http://127.0.0.1:$NGINX_PORT/small" "--http1"

    if endpoint_valid "http://127.0.0.1:$NGINX_PORT/medium" 4000; then
        run_scenario "http1_medium_4KB" "http://127.0.0.1:$NGINX_PORT/medium" "--http1"
    fi

    if endpoint_valid "http://127.0.0.1:$NGINX_PORT/large" 1000000; then
        run_scenario "http1_large_1MB" "http://127.0.0.1:$NGINX_PORT/large" "--http1"
    fi

    print_table_footer
}

# Suite: Payload Size Scaling
run_suite_payloads() {
    print_subsection "Payload Size Scaling (HTTP/1.1)"

    local endpoints=()
    if endpoint_valid "http://127.0.0.1:$NGINX_PORT/small" 100; then
        endpoints+=("small:100B")
    fi
    if endpoint_valid "http://127.0.0.1:$NGINX_PORT/medium" 4000; then
        endpoints+=("medium:4KB")
    fi
    if endpoint_valid "http://127.0.0.1:$NGINX_PORT/large" 1000000; then
        endpoints+=("large:1MB")
    fi

    if [ ${#endpoints[@]} -lt 2 ]; then
        echo -e "  ${YELLOW}Skipping: Need at least 2 valid payload endpoints${NC}"
        return
    fi

    print_table_header

    for ep in "${endpoints[@]}"; do
        local path="${ep%:*}"
        local label="${ep#*:}"
        run_scenario "payload_${label}" "http://127.0.0.1:$NGINX_PORT/$path" "--http1"
    done

    print_table_footer
}

# Suite: Concurrency Scaling
run_suite_concurrency() {
    print_subsection "Concurrency Scaling (HTTP/1.1, 100B payload)"
    print_table_header

    local total_reqs=$((THREADS * REQS))

    for threads in 1 2 4 8; do
        local per_thread=$((total_reqs / threads))
        [ $per_thread -lt 10 ] && per_thread=10
        run_scenario "concurrency_${threads}t" "http://127.0.0.1:$NGINX_PORT/small" "--http1" "$threads" "$per_thread"
    done

    print_table_footer
}

# Suite: Connection Behavior
run_suite_connections() {
    print_subsection "Connection Behavior (HTTP/1.1, 100B)"
    print_table_header

    run_scenario "keepalive_enabled" "http://127.0.0.1:$NGINX_PORT/small" "--http1"
    run_scenario "keepalive_disabled" "http://127.0.0.1:$NGINX_PORT/small" "--http1 --no-keepalive"

    print_table_footer
}

# Suite: TLS/HTTPS Tests
run_suite_tls() {
    if [ "$HAVE_TLS" != "1" ]; then
        echo ""
        echo -e "  ${YELLOW}Skipping TLS suite: HTTPS not available on port $NGINX_TLS_PORT${NC}"
        return
    fi

    print_subsection "TLS/HTTPS Tests"
    print_table_header

    run_scenario "https_small" "https://127.0.0.1:$NGINX_TLS_PORT/small" ""

    print_table_footer
}

# Print summary
print_summary() {
    print_section "Summary"
    echo ""

    if [ ${#ALL_TETSUO_RPS[@]} -eq 0 ]; then
        echo "  No results to summarize."
        return
    fi

    # Count wins
    local wins_tetsuo=0 wins_curl=0 wins_libevent=0 wins_beast=0
    local total_tetsuo=0 total_curl=0 total_libevent=0 total_beast=0
    local count=0

    for i in "${!ALL_TETSUO_RPS[@]}"; do
        if command -v bc &> /dev/null; then
            local t="${ALL_TETSUO_RPS[$i]:-0}"
            local c="${ALL_CURL_RPS[$i]:-0}"
            local e="${ALL_LIBEVENT_RPS[$i]:-0}"
            local b="${ALL_BEAST_RPS[$i]:-0}"

            total_tetsuo=$(echo "$total_tetsuo + $t" | bc)
            total_curl=$(echo "$total_curl + $c" | bc)
            total_libevent=$(echo "$total_libevent + $e" | bc)
            total_beast=$(echo "$total_beast + $b" | bc)

            # Find winner
            local best="$t"
            local winner="tetsuo"
            [ "$(echo "$c > $best" | bc)" = "1" ] && best="$c" && winner="curl"
            [ "$(echo "$e > $best" | bc)" = "1" ] && best="$e" && winner="libevent"
            [ "$(echo "$b > $best" | bc)" = "1" ] && best="$b" && winner="beast"

            case "$winner" in
                tetsuo) wins_tetsuo=$((wins_tetsuo + 1)) ;;
                curl) wins_curl=$((wins_curl + 1)) ;;
                libevent) wins_libevent=$((wins_libevent + 1)) ;;
                beast) wins_beast=$((wins_beast + 1)) ;;
            esac
        fi
        count=$((count + 1))
    done

    echo -e "  ${BOLD}Scenarios tested: $count${NC}"
    echo ""
    echo -e "  ${BOLD}Wins by library:${NC}"
    printf "    tetsuo-socket: %s%d%s\n" "$([ $wins_tetsuo -gt 0 ] && echo -e ${GREEN})" "$wins_tetsuo" "$([ $wins_tetsuo -gt 0 ] && echo -e ${NC})"
    [ $HAVE_CURL -eq 1 ] && printf "    libcurl:       %d\n" "$wins_curl"
    [ $HAVE_LIBEVENT -eq 1 ] && printf "    libevent:      %d\n" "$wins_libevent"
    [ $HAVE_BEAST -eq 1 ] && printf "    Boost.Beast:   %d\n" "$wins_beast"

    if command -v bc &> /dev/null && [ $count -gt 0 ]; then
        echo ""
        echo -e "  ${BOLD}Average throughput:${NC}"
        printf "    tetsuo-socket: ${GREEN}%s req/sec${NC}\n" "$(format_num $(echo "scale=0; $total_tetsuo / $count" | bc))"
        [ $HAVE_CURL -eq 1 ] && printf "    libcurl:       %s req/sec\n" "$(format_num $(echo "scale=0; $total_curl / $count" | bc))"
        [ $HAVE_LIBEVENT -eq 1 ] && printf "    libevent:      %s req/sec\n" "$(format_num $(echo "scale=0; $total_libevent / $count" | bc))"
        [ $HAVE_BEAST -eq 1 ] && printf "    Boost.Beast:   %s req/sec\n" "$(format_num $(echo "scale=0; $total_beast / $count" | bc))"
    fi

    echo ""
    echo -e "  Results saved to: ${BLUE}$OUTPUT_DIR/${NC}"
}

# Main execution
print_header

echo -e "${BOLD}Configuration:${NC}"
echo "  Threads:         $THREADS"
echo "  Requests/thread: $REQS"
echo "  Total requests:  $((THREADS * REQS))"
echo "  Suite:           $SUITE"
echo "  Trace mode:      $([ $TRACE_MODE -eq 1 ] && echo 'enabled' || echo 'disabled')"
echo ""

# Check prerequisites
print_section "Prerequisites"
check_nginx
echo ""

# Build
echo -e "${BOLD}Building benchmarks...${NC}"
if [ $TRACE_MODE -eq 1 ]; then
    build_benchmarks "$BUILD_TRACE_DIR" "trace"
    BENCH_DIR="$BUILD_TRACE_DIR"
else
    build_benchmarks "$BUILD_DIR" ""
    BENCH_DIR="$BUILD_DIR"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run benchmarks
print_section "Running Benchmarks"

case "$SUITE" in
    all)
        run_suite_http1
        run_suite_payloads
        run_suite_concurrency
        run_suite_connections
        run_suite_tls
        ;;
    http1)
        run_suite_http1
        ;;
    payloads)
        run_suite_payloads
        ;;
    concurrency)
        run_suite_concurrency
        ;;
    connections)
        run_suite_connections
        ;;
    tls)
        run_suite_tls
        ;;
    *)
        echo -e "${RED}Unknown suite: $SUITE${NC}"
        exit 1
        ;;
esac

# Summary
print_summary

# Trace mode hint
if [ $TRACE_MODE -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}Function tracing was enabled. Check stderr for call traces.${NC}"
fi

print_section "Done"
echo ""
