#!/bin/bash
#
# Post-edit hook: Quick syntax check after C file edits
# Uses gcc -fsyntax-only for fast validation
#

# Parse JSON input
input_json=$(cat)
file_path=$(echo "$input_json" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

# Only check C source files
if [[ ! "$file_path" =~ \.(c|h)$ ]]; then
    exit 0
fi

# Skip if file doesn't exist
if [[ ! -f "$file_path" ]]; then
    exit 0
fi

cd "$CLAUDE_PROJECT_DIR" || exit 0

# Determine include paths based on file location
include_dirs="-I$CLAUDE_PROJECT_DIR/include"

# Add OpenSSL includes if available
if pkg-config --exists openssl 2>/dev/null; then
    include_dirs="$include_dirs $(pkg-config --cflags openssl)"
fi

# Quick syntax check
errors=$(gcc -fsyntax-only -Wall $include_dirs "$file_path" 2>&1)

if [[ $? -ne 0 ]]; then
    echo "" >&2
    echo "=== Syntax Check Failed ===" >&2
    echo "$errors" | head -10 >&2
    echo "" >&2
    # Exit 0 = warning only. Change to exit 2 to block.
    exit 0
fi

exit 0
