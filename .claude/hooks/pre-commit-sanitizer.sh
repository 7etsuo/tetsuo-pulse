#!/bin/bash
#
# Pre-commit hook: Run sanitizer tests before allowing git commits
# Exit 0 = allow, Exit 2 = block
#

set -e

# Parse JSON input from stdin
input_json=$(cat)
command=$(echo "$input_json" | jq -r '.tool_input.command // empty' 2>/dev/null)

# Only intercept git commit commands
if [[ ! "$command" =~ "git commit" ]]; then
    exit 0
fi

cd "$CLAUDE_PROJECT_DIR" || exit 0

# Check if build directory exists
if [[ ! -d build ]]; then
    echo "No build directory found. Run cmake first." >&2
    exit 0  # Warning only, don't block
fi

echo "Running sanitizer tests before commit..." >&2

# Reconfigure with sanitizers if needed
if ! grep -q "ENABLE_SANITIZERS:BOOL=ON" build/CMakeCache.txt 2>/dev/null; then
    echo "Configuring with sanitizers..." >&2
    cmake -B build -DENABLE_SANITIZERS=ON >/dev/null 2>&1 || {
        echo "CMake configuration failed" >&2
        exit 2
    }
    cmake --build build -j >/dev/null 2>&1 || {
        echo "Build failed" >&2
        exit 2
    }
fi

# Run tests with sanitizers
# Exclude flaky network-dependent tests that may timeout in CI environments
cd build
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest --output-on-failure -j4 -E "test_dns_over_https" 2>&1 | tail -20

if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    echo "" >&2
    echo "BLOCKED: Tests failed with sanitizers. Fix failures before committing." >&2
    exit 2
fi

echo "All tests passed. Commit allowed." >&2
exit 0
