#!/bin/bash
#
# run_fuzz_parallel.sh - Launch all fuzzers with parallel execution
#
# Part of the Socket Library Fuzzing Suite
#
# Optimized for 64-core / 1TB RAM systems. Runs multiple fuzzer targets
# simultaneously with aggressive parallelism.
#
# Usage:
#   ./scripts/run_fuzz_parallel.sh [OPTIONS]
#
# Options:
#   -j JOBS     Jobs per target (default: 16, total = JOBS * 4 targets)
#   -t TIME     Total time in seconds (default: 3600 = 1 hour)
#   -m MAXLEN   Maximum input length (default: 4096)
#   -r          Use ramdisk corpus (/mnt/fuzz_corpus)
#   -c          Continue from existing corpus (don't reset)
#   -q          Quick mode: 5 minutes, 8 jobs per target
#   -h          Show help

set -e

# Default configuration
JOBS_PER_TARGET=16
TOTAL_TIME=3600
MAX_LEN=4096
USE_RAMDISK=0
CONTINUE=0
BUILD_DIR="build-fuzz"
CORPUS_BASE="src/fuzz/corpus"

# Fuzzer targets
TARGETS=(fuzz_socketbuf fuzz_arena fuzz_ip_parse fuzz_dns_validate fuzz_socketbuf_stress)

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
    echo "Launch all fuzzers with parallel execution."
    echo ""
    echo "Options:"
    echo "  -j JOBS     Jobs per target (default: $JOBS_PER_TARGET)"
    echo "  -t TIME     Total time in seconds (default: $TOTAL_TIME)"
    echo "  -m MAXLEN   Maximum input length (default: $MAX_LEN)"
    echo "  -r          Use ramdisk corpus (/mnt/fuzz_corpus)"
    echo "  -c          Continue from existing corpus"
    echo "  -q          Quick mode: 5 min, 8 jobs/target"
    echo "  -h          Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                    # Default: 16 jobs/target, 1 hour"
    echo "  $0 -j 32 -t 86400     # 32 jobs/target, 24 hours"
    echo "  $0 -r -j 16 -t 3600   # Use ramdisk, 16 jobs, 1 hour"
    echo "  $0 -q                 # Quick 5-minute smoke test"
}

# Parse arguments
while getopts "j:t:m:rcqh" opt; do
    case $opt in
        j) JOBS_PER_TARGET=$OPTARG ;;
        t) TOTAL_TIME=$OPTARG ;;
        m) MAX_LEN=$OPTARG ;;
        r) USE_RAMDISK=1 ;;
        c) CONTINUE=1 ;;
        q) JOBS_PER_TARGET=8; TOTAL_TIME=300 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

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
echo "  Targets:        ${AVAILABLE_TARGETS[*]}"
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
FINDINGS_DIR="fuzz_findings_$(date +%Y%m%d_%H%M%S)"
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

# Check for crashes
CRASHES=$(ls -1 "$FINDINGS_DIR"/*crash* 2>/dev/null | wc -l)
TIMEOUTS=$(ls -1 "$FINDINGS_DIR"/*timeout* 2>/dev/null | wc -l)
OOM=$(ls -1 "$FINDINGS_DIR"/*oom* 2>/dev/null | wc -l)

if [[ $CRASHES -gt 0 ]]; then
    log_error "CRASHES FOUND: $CRASHES"
    ls -la "$FINDINGS_DIR"/*crash* 2>/dev/null
fi

if [[ $TIMEOUTS -gt 0 ]]; then
    log_warn "Timeouts: $TIMEOUTS"
fi

if [[ $OOM -gt 0 ]]; then
    log_warn "OOM errors: $OOM"
fi

if [[ $CRASHES -eq 0 && $TIMEOUTS -eq 0 && $OOM -eq 0 ]]; then
    log_info "No crashes, timeouts, or OOM errors found!"
fi

# Print final stats from logs
log_section "Final Statistics"
for target in "${AVAILABLE_TARGETS[@]}"; do
    echo ""
    echo "=== $target ==="
    grep -E "(cov:|ft:|corp:|exec/s:|NEW|BINGO)" "$FINDINGS_DIR/${target}.log" 2>/dev/null | tail -10 || true
done

