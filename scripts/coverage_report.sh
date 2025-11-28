#!/bin/bash
# Generate LLVM Coverage Report
# Usage: ./scripts/coverage_report.sh [--open]

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build-coverage"

echo "=== Socket Library Coverage Report Generator ==="
echo ""

# Check if build exists
if [ ! -f "$BUILD_DIR/libsocket.so" ]; then
    echo "Building with coverage instrumentation..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake "$PROJECT_ROOT" \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping -g -O1" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_TLS=ON
    make -j$(nproc)
fi

cd "$BUILD_DIR"

# Clean old profiles
rm -f *.profraw coverage.profdata

echo "Running tests to gather coverage..."
export LLVM_PROFILE_FILE="coverage-%p.profraw"

for test in ./test_*; do
    if [ -x "$test" ]; then
        echo "  Running $(basename $test)..."
        timeout 60 "$test" > /dev/null 2>&1 || true
    fi
done

echo ""
echo "Merging profiles..."
llvm-profdata merge -sparse coverage-*.profraw -o coverage.profdata

echo "Generating HTML report..."
llvm-cov show \
    ./libsocket.so \
    -instr-profile=coverage.profdata \
    -format=html \
    -output-dir=coverage_report \
    -show-line-counts-or-regions \
    -show-branches=count \
    -ignore-filename-regex='test/.*'

echo ""
echo "=== Coverage Summary ==="
llvm-cov report ./libsocket.so -instr-profile=coverage.profdata \
    -ignore-filename-regex='test/.*' 2>/dev/null | tail -5

echo ""
echo "Report: file://$BUILD_DIR/coverage_report/index.html"

# Open in browser if requested
if [ "$1" = "--open" ]; then
    xdg-open "$BUILD_DIR/coverage_report/index.html" 2>/dev/null || \
    open "$BUILD_DIR/coverage_report/index.html" 2>/dev/null || \
    echo "Open manually: $BUILD_DIR/coverage_report/index.html"
fi

