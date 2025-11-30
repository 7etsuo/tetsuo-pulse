#!/bin/bash
#
# build_fuzz.sh - Build fuzzers with libFuzzer (requires Clang)
#
# Usage:
#   ./scripts/build_fuzz.sh [OPTIONS]
#
# Options:
#   -c          Clean build (remove build-fuzz first)
#   -j JOBS     Parallel jobs for make (default: nproc)
#   -s          Enable sanitizers (ASan + UBSan)
#   -h          Show help

set -e

# Get project root (script is in scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

BUILD_DIR="build-fuzz"
CLEAN=0
JOBS=$(nproc)
SANITIZERS=0

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build fuzzers with libFuzzer (requires Clang)."
    echo ""
    echo "Options:"
    echo "  -c          Clean build (remove $BUILD_DIR first)"
    echo "  -j JOBS     Parallel jobs for make (default: $JOBS)"
    echo "  -s          Enable sanitizers (ASan + UBSan)"
    echo "  -h          Show this help"
}

while getopts "cj:sh" opt; do
    case $opt in
        c) CLEAN=1 ;;
        j) JOBS=$OPTARG ;;
        s) SANITIZERS=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

# Check for clang
if ! command -v clang &> /dev/null; then
    log_error "Clang not found. Install with: sudo apt install clang"
    exit 1
fi

CLANG_VERSION=$(clang --version | head -1)
log_info "Using: $CLANG_VERSION"

# Clean if requested
if [[ $CLEAN -eq 1 && -d "$BUILD_DIR" ]]; then
    log_info "Removing existing $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure
log_info "Configuring with CMake..."
CMAKE_OPTS="-DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug"

if [[ $SANITIZERS -eq 1 ]]; then
    CMAKE_OPTS="$CMAKE_OPTS -DENABLE_SANITIZERS=ON"
    log_info "Sanitizers enabled (ASan + UBSan)"
fi

CC=clang cmake .. $CMAKE_OPTS

# Build
log_info "Building with $JOBS parallel jobs..."
make -j"$JOBS"

# Count fuzzers
FUZZ_COUNT=$(ls -1 fuzz_* 2>/dev/null | wc -l)

log_info "Build complete!"
log_info "Fuzzers built: $FUZZ_COUNT"
echo ""
echo "Run fuzzers with:"
echo "  ./scripts/run_fuzz_parallel.sh -g dtls     # DTLS only"
echo "  ./scripts/run_fuzz_parallel.sh -g all -q   # Quick smoke test"
echo "  ./scripts/run_fuzz_parallel.sh             # Full run (1 hour)"

