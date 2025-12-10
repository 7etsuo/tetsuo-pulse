#!/bin/bash
#
# run_fuzz_parallel.sh - Launch all fuzzers with parallel execution
#
# Part of the Socket Library Fuzzing Suite
#
# Optimized for 64-core / 1TB RAM systems. Runs multiple fuzzer targets
# simultaneously with aggressive parallelism. Default: 2 jobs per target
# (32 targets * 2 jobs = 64 cores total).
#
# Usage:
#   ./scripts/run_fuzz_parallel.sh [OPTIONS]
#
# Options:
#   -j JOBS     Jobs per target (default: 2, total = JOBS * targets)
#   -t TIME     Total time in seconds (default: 3600 = 1 hour)
#   -m MAXLEN   Maximum input length (default: 4096)
#   -g GROUPS   Fuzzer groups to run (comma-separated, default: all)
#               Groups: all, core, crypto, utf8, socket, dns, tls, dtls,
#                       http, http1, hpack, http2
#   -r          Use ramdisk corpus (/mnt/fuzz_corpus)
#   -c          Continue from existing corpus (don't reset)
#   -q          Quick mode: 5 minutes, 4 jobs per target
#   -h          Show help

set -e

# Default configuration
JOBS_PER_TARGET=2  # Optimized for 64 cores: 32 targets * 2 jobs = 64 cores
TOTAL_TIME=3600
MAX_LEN=4096
USE_RAMDISK=0
CONTINUE=0
BUILD_DIR="build-fuzz"
CORPUS_BASE="src/fuzz/corpus"
FUZZ_GROUPS="all"

# Fuzzer targets by group
TARGETS_CORE=(
    fuzz_arena
    fuzz_exception
    fuzz_timer
    fuzz_ratelimit
    fuzz_iptracker
    fuzz_synprotect
    fuzz_pool_dos
)

TARGETS_CRYPTO=(
    fuzz_base64_decode
    fuzz_hex_decode
)

TARGETS_UTF8=(
    fuzz_utf8
    fuzz_utf8_validate
    fuzz_utf8_incremental
)

TARGETS_SOCKET=(
    fuzz_socketbuf
    fuzz_socketbuf_stress
    fuzz_socketio
    fuzz_socketpoll
    fuzz_socketpool
    fuzz_socketdgram
    fuzz_unix_path
)

TARGETS_DNS=(
    fuzz_ip_parse
    fuzz_cidr_parse
    fuzz_dns_validate
    fuzz_dns_inj
    fuzz_address_parse
    fuzz_connect
    fuzz_happy_eyeballs
    fuzz_reconnect
    fuzz_async
)

TARGETS_TLS=(
    fuzz_tls_alpn
    fuzz_tls_session
    fuzz_tls_certs
    fuzz_tls_io
    fuzz_tls_sni
    fuzz_tls_verify
    fuzz_tls_ct
    fuzz_tls_context  # TLS Context Management (Section 2.1-2.3)
    fuzz_cert_pinning
)

TARGETS_DTLS=(
    fuzz_dtls_context
    fuzz_dtls_cookie
    fuzz_dtls_handshake
    fuzz_dtls_io
)

TARGETS_PROXY=(
    fuzz_proxy_url
    fuzz_proxy_http
    fuzz_proxy_socks4
    fuzz_proxy_socks5
)

TARGETS_WS=(
    fuzz_ws_frame
    fuzz_ws_frames
    fuzz_ws_handshake
    fuzz_ws_deflate
    fuzz_websocket_handshake
)

TARGETS_HTTP=(
    fuzz_uri_parse
    fuzz_http_date
    fuzz_http_core
    fuzz_http_headers_collection
    fuzz_http_cookies
    fuzz_http_cookies_simple
    fuzz_http_auth
    fuzz_http_content_type
    fuzz_http_smuggling
    fuzz_http_client
)

TARGETS_HTTP1=(
    fuzz_http1_request
    fuzz_http1_response
    fuzz_http1_chunked
    fuzz_http1_headers
    fuzz_http1_serialize
    fuzz_http1_compression
)

TARGETS_HPACK=(
    fuzz_hpack
    fuzz_hpack_decode
    fuzz_hpack_encode
    fuzz_hpack_huffman
    fuzz_hpack_integer
)

TARGETS_HTTP2=(
    fuzz_http2_frames
    fuzz_http2_frames_full
    fuzz_http2_headers
    fuzz_http2_settings
)

# Build target list from selected groups
build_target_list() {
    TARGETS=()
    IFS=',' read -ra GROUP_LIST <<< "$FUZZ_GROUPS"
    for group in "${GROUP_LIST[@]}"; do
        case "$group" in
            all)
                TARGETS+=("${TARGETS_CORE[@]}" "${TARGETS_CRYPTO[@]}" "${TARGETS_UTF8[@]}" "${TARGETS_SOCKET[@]}" "${TARGETS_DNS[@]}" "${TARGETS_TLS[@]}" "${TARGETS_DTLS[@]}" "${TARGETS_PROXY[@]}" "${TARGETS_WS[@]}" "${TARGETS_HTTP[@]}" "${TARGETS_HTTP1[@]}" "${TARGETS_HPACK[@]}" "${TARGETS_HTTP2[@]}")
                ;;
            core)
                TARGETS+=("${TARGETS_CORE[@]}")
                ;;
            crypto)
                TARGETS+=("${TARGETS_CRYPTO[@]}")
                ;;
            utf8)
                TARGETS+=("${TARGETS_UTF8[@]}")
                ;;
            socket)
                TARGETS+=("${TARGETS_SOCKET[@]}")
                ;;
            dns|network)
                TARGETS+=("${TARGETS_DNS[@]}")
                ;;
            tls)
                TARGETS+=("${TARGETS_TLS[@]}")
                ;;
            dtls)
                TARGETS+=("${TARGETS_DTLS[@]}")
                ;;
            proxy)
                TARGETS+=("${TARGETS_PROXY[@]}")
                ;;
            ws|websocket)
                TARGETS+=("${TARGETS_WS[@]}")
                ;;
            http)
                TARGETS+=("${TARGETS_HTTP[@]}")
                ;;
            http1)
                TARGETS+=("${TARGETS_HTTP1[@]}")
                ;;
            hpack)
                TARGETS+=("${TARGETS_HPACK[@]}")
                ;;
            http2)
                TARGETS+=("${TARGETS_HTTP2[@]}")
                ;;
            *)
                log_error "Unknown group: $group"
                log_info "Valid groups: all, core, crypto, utf8, socket, dns, tls, dtls, proxy, ws, http, http1, hpack, http2"
                exit 1
                ;;
        esac
    done
}

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Launch all fuzzers with parallel execution optimized for 64 cores."
    echo ""
    echo "Options:"
    echo "  -j JOBS     Jobs per target (default: $JOBS_PER_TARGET, optimized for 64 cores)"
    echo "  -t TIME     Total time in seconds (default: $TOTAL_TIME)"
    echo "  -m MAXLEN   Maximum input length (default: $MAX_LEN)"
    echo "  -g GROUPS   Fuzzer groups to run, comma-separated (default: all)"
    echo "              Groups: all, core, crypto, utf8, socket, dns, tls, dtls,"
    echo "                      proxy, ws, http, http1, hpack, http2"
    echo "  -r          Use ramdisk corpus (/mnt/fuzz_corpus)"
    echo "  -c          Continue from existing corpus"
    echo "  -q          Quick mode: 5 min, 4 jobs/target"
    echo "  -h          Show this help"
    echo ""
    echo "Fuzzer Groups:"
    echo "  core   - Arena, exception, timer, rate limit, IP tracker, SYN protect, pool DoS"
    echo "  crypto - Base64, hex encoding/decoding"
    echo "  utf8   - UTF-8 validation (one-shot and incremental)"
    echo "  socket - Socket buffer, I/O, poll, pool, dgram, Unix path"
    echo "  dns    - IP/CIDR parsing, DNS validation/injection, connect, Happy Eyeballs"
    echo "  tls    - TLS ALPN, session, certs, I/O, SNI, verify, CT, cert pinning"
    echo "  dtls   - DTLS context, cookie, handshake, I/O"
    echo "  proxy  - Proxy URL, HTTP proxy, SOCKS4, SOCKS5"
    echo "  ws     - WebSocket frame, frames, handshake, deflate"
    echo "  http   - URI, date, core, headers, cookies, auth, content-type, smuggling, client"
    echo "  http1  - HTTP/1.1 request, response, chunked, headers, serialize, compression"
    echo "  hpack  - HPACK encode/decode, Huffman, integer coding"
    echo "  http2  - HTTP/2 frames, frames_full, headers, settings"
    echo ""
    echo "Examples:"
    echo "  $0                    # Default: all groups, 2 jobs/target"
    echo "  $0 -g http2           # Only HTTP/2 fuzzers (4 targets)"
    echo "  $0 -g http,http1,http2 # All HTTP fuzzers (20 targets)"
    echo "  $0 -g hpack,http2     # HPACK + HTTP/2 (9 targets)"
    echo "  $0 -g tls,dtls        # TLS + DTLS fuzzers (12 targets)"
    echo "  $0 -g ws              # WebSocket fuzzers (5 targets)"
    echo "  $0 -g proxy           # Proxy fuzzers (4 targets)"
    echo "  $0 -g core -j 10      # Core fuzzers with 10 jobs each"
    echo "  $0 -j 32 -t 86400     # 32 jobs/target, 24 hours"
    echo "  $0 -r -j 16 -t 3600   # Use ramdisk, 16 jobs, 1 hour"
    echo "  $0 -q                 # Quick 5-minute smoke test"
}

# Parse arguments
while getopts "j:t:m:g:rcqh" opt; do
    case $opt in
        j) JOBS_PER_TARGET=$OPTARG ;;
        t) TOTAL_TIME=$OPTARG ;;
        m) MAX_LEN=$OPTARG ;;
        g) FUZZ_GROUPS=$OPTARG ;;
        r) USE_RAMDISK=1 ;;
        c) CONTINUE=1 ;;
        q) JOBS_PER_TARGET=4; TOTAL_TIME=300 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

# Build target list from selected groups
build_target_list

# Determine corpus location
if [[ $USE_RAMDISK -eq 1 ]]; then
    if mountpoint -q /mnt/fuzz_corpus 2>/dev/null; then
        CORPUS_BASE="/mnt/fuzz_corpus"
        log_info "Using ramdisk corpus at $CORPUS_BASE"
    else
        log_error "Ramdisk not mounted. Run: sudo ./scripts/setup_ramdisk.sh"
        exit 1
    fi
fi

# Check build directory
if [[ ! -d "$BUILD_DIR" ]]; then
    log_error "Build directory '$BUILD_DIR' not found."
    log_info "Build fuzzers with:"
    echo "  mkdir $BUILD_DIR && cd $BUILD_DIR"
    echo "  CC=clang cmake .. -DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug"
    echo "  make fuzzers"
    exit 1
fi

# Check if fuzzers exist
AVAILABLE_TARGETS=()
for target in "${TARGETS[@]}"; do
    if [[ -x "$BUILD_DIR/$target" ]]; then
        AVAILABLE_TARGETS+=("$target")
    else
        log_warn "Fuzzer not found: $BUILD_DIR/$target (skipping)"
    fi
done

if [[ ${#AVAILABLE_TARGETS[@]} -eq 0 ]]; then
    log_error "No fuzzers found in $BUILD_DIR"
    exit 1
fi

# Calculate totals
TOTAL_JOBS=$((JOBS_PER_TARGET * ${#AVAILABLE_TARGETS[@]}))
NPROC=$(nproc)

log_section "Fuzzing Configuration"
echo "  Groups:         $FUZZ_GROUPS"
echo "  Targets:        ${#AVAILABLE_TARGETS[@]} (${AVAILABLE_TARGETS[*]})"
echo "  Jobs/target:    $JOBS_PER_TARGET"
echo "  Total jobs:     $TOTAL_JOBS"
echo "  Available CPUs: $NPROC"
echo "  Max input len:  $MAX_LEN"
echo "  Duration:       $TOTAL_TIME seconds"
echo "  Corpus base:    $CORPUS_BASE"

if [[ $TOTAL_JOBS -gt $NPROC ]]; then
    log_warn "Total jobs ($TOTAL_JOBS) exceeds CPU count ($NPROC)"
fi

# Create/prepare corpus directories
log_section "Preparing Corpus"
for target in "${AVAILABLE_TARGETS[@]}"; do
    # Strip "fuzz_" prefix to get corpus directory name
    corpus_name="${target#fuzz_}"
    corpus_dir="$CORPUS_BASE/$corpus_name"
    mkdir -p "$corpus_dir"
    
    # Copy seed corpus if starting fresh
    if [[ $CONTINUE -eq 0 && -d "src/fuzz/corpus/$corpus_name" ]]; then
        cp -n src/fuzz/corpus/$corpus_name/* "$corpus_dir/" 2>/dev/null || true
    fi
    
    count=$(ls -1 "$corpus_dir" 2>/dev/null | wc -l)
    log_info "$target ($corpus_name): $count seed inputs"
done

# Create output directories
FINDINGS_DIR="$(pwd)/fuzz_findings_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$FINDINGS_DIR"
log_info "Findings will be saved to: $FINDINGS_DIR"

# Start fuzzers
log_section "Starting Fuzzers"

# Array to track PIDs
declare -a PIDS

cleanup() {
    log_warn "Stopping fuzzers..."
    for pid in "${PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    wait
    log_info "All fuzzers stopped"
}

trap cleanup EXIT INT TERM

for target in "${AVAILABLE_TARGETS[@]}"; do
    # Strip "fuzz_" prefix to get corpus directory name
    corpus_name="${target#fuzz_}"
    corpus_dir="$CORPUS_BASE/$corpus_name"
    log_file="$FINDINGS_DIR/${target}.log"
    
    log_info "Starting $target with $JOBS_PER_TARGET parallel jobs"
    log_info "  Corpus: $corpus_dir/"
    log_info "  Artifacts: $FINDINGS_DIR/${target}_"

    "$BUILD_DIR/$target" "$corpus_dir/" \
        -fork=$JOBS_PER_TARGET \
        -max_len=$MAX_LEN \
        -max_total_time=$TOTAL_TIME \
        -artifact_prefix="$FINDINGS_DIR/${target}_" \
        -print_final_stats=1 \
        -rss_limit_mb=4096 \
        > "$log_file" 2>&1 &
    
    PIDS+=($!)
    log_info "  PID: ${PIDS[-1]}, Log: $log_file"
done

log_section "Fuzzers Running"
echo "  Monitor progress: tail -f $FINDINGS_DIR/*.log"
echo "  Stop early:       Ctrl+C"
echo ""

# Wait for all fuzzers
wait

# Summary
log_section "Fuzzing Complete"

echo ""
echo "Results saved to: $FINDINGS_DIR/"
echo ""

# Check for crashes in artifact files and logs
CRASHES=$(ls -1 "$FINDINGS_DIR"/*crash* 2>/dev/null | wc -l)
TIMEOUTS=$(ls -1 "$FINDINGS_DIR"/*timeout* 2>/dev/null | wc -l)
OOM=$(ls -1 "$FINDINGS_DIR"/*oom* 2>/dev/null | wc -l)

# Also check log files for crash indicators (in case artifacts aren't saved)
LOG_CRASHES=$(grep -l "ERROR: AddressSanitizer\|ERROR: UndefinedBehaviorSanitizer\|Test unit written to\|SUMMARY:.*ABORTING" "$FINDINGS_DIR"/*.log 2>/dev/null | wc -l)

TOTAL_CRASHES=$((CRASHES + LOG_CRASHES))

if [[ $TOTAL_CRASHES -gt 0 ]]; then
    log_error "CRASHES FOUND: $TOTAL_CRASHES ($CRASHES artifacts, $LOG_CRASHES in logs)"
    if [[ $CRASHES -gt 0 ]]; then
        ls -la "$FINDINGS_DIR"/*crash* 2>/dev/null
    fi
    if [[ $LOG_CRASHES -gt 0 ]]; then
        echo "Crashes detected in logs:"
        grep -l "ERROR: AddressSanitizer\|ERROR: UndefinedBehaviorSanitizer\|Test unit written to\|SUMMARY:.*ABORTING" "$FINDINGS_DIR"/*.log 2>/dev/null
    fi
fi

if [[ $TIMEOUTS -gt 0 ]]; then
    log_warn "Timeouts: $TIMEOUTS"
fi

if [[ $OOM -gt 0 ]]; then
    log_warn "OOM errors: $OOM"
fi

if [[ $TOTAL_CRASHES -eq 0 && $TIMEOUTS -eq 0 && $OOM -eq 0 ]]; then
    log_info "No crashes, timeouts, or OOM errors found!"
fi

# Print final stats from logs
log_section "Final Statistics"
for target in "${AVAILABLE_TARGETS[@]}"; do
    echo ""
    echo "=== $target ==="
    grep -E "(cov:|ft:|corp:|exec/s:|NEW|BINGO)" "$FINDINGS_DIR/${target}.log" 2>/dev/null | tail -10 || true
done

# Show all artifact files found
log_section "Artifact Summary"
echo "Findings directory: $FINDINGS_DIR"
echo ""
echo "Crash artifacts:"
ls -1 "$FINDINGS_DIR"/*crash* 2>/dev/null || echo "  None found"
echo ""
echo "Timeout artifacts:"
ls -1 "$FINDINGS_DIR"/*timeout* 2>/dev/null || echo "  None found"
echo ""
echo "OOM artifacts:"
ls -1 "$FINDINGS_DIR"/*oom* 2>/dev/null || echo "  None found"
echo ""
echo "All artifacts:"
ls -1 "$FINDINGS_DIR"/* 2>/dev/null | grep -v "\.log$" | head -20 || echo "  None found"

