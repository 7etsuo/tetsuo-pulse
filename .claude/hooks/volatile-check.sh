#!/bin/bash
#
# Post-edit hook: Warn about exception safety issues
# Checks for common TRY/EXCEPT mistakes
#

# Parse JSON input
input_json=$(cat)
file_path=$(echo "$input_json" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
content=$(echo "$input_json" | jq -r '.tool_input.content // .tool_input.new_string // empty' 2>/dev/null)

# Only check C source files
if [[ ! "$file_path" =~ \.(c|h)$ ]]; then
    exit 0
fi

# If we have content from the tool input, check it
# Otherwise, read the file
if [[ -z "$content" ]] && [[ -f "$file_path" ]]; then
    content=$(cat "$file_path")
fi

if [[ -z "$content" ]]; then
    exit 0
fi

warnings=()

# Check 1: Non-volatile variables assigned in TRY blocks
# Pattern: variable = something inside TRY block without volatile
if echo "$content" | grep -Pzo 'TRY\s*\{[^}]*(?<!volatile\s)\w+_T\s+\w+\s*=[^}]*\}' >/dev/null 2>&1; then
    warnings+=("EXCEPTION SAFETY: Possible non-volatile variable in TRY block.")
    warnings+=("  Variables modified in TRY should be declared volatile before TRY.")
fi

# Check 2: Deeply nested TRY blocks (more than 2 levels)
depth=$(echo "$content" | grep -o 'TRY' | wc -l)
end_depth=$(echo "$content" | grep -o 'END_TRY' | wc -l)
if [[ $depth -gt 2 ]] && [[ $depth -eq $end_depth ]]; then
    # Check if they're nested (simplistic check)
    if echo "$content" | grep -Pzo 'TRY\s*\{[^}]*TRY\s*\{[^}]*TRY' >/dev/null 2>&1; then
        warnings+=("EXCEPTION SAFETY: Deeply nested TRY blocks (>2 levels) detected.")
        warnings+=("  This can corrupt the exception stack. Refactor to helper functions.")
    fi
fi

# Check 3: return inside TRY block (should use RETURN macro)
if echo "$content" | grep -Pzo 'TRY\s*\{[^}]*\breturn\b[^}]*\}' >/dev/null 2>&1; then
    # Make sure it's not the RETURN macro
    if ! echo "$content" | grep -Pzo 'TRY\s*\{[^}]*\bRETURN\b[^}]*\}' >/dev/null 2>&1; then
        warnings+=("EXCEPTION SAFETY: Bare 'return' inside TRY block detected.")
        warnings+=("  Use RETURN macro instead to properly clean up exception stack.")
    fi
fi

# Check 4: Resource allocation inside TRY without matching FINALLY cleanup
if echo "$content" | grep -Pzo 'TRY\s*\{[^}]*(_new|_alloc|malloc|calloc)\s*\([^}]*\}[^}]*END_TRY' >/dev/null 2>&1; then
    if ! echo "$content" | grep -Pzo 'FINALLY\s*\{[^}]*(_free|_dispose|free)\s*\(' >/dev/null 2>&1; then
        warnings+=("EXCEPTION SAFETY: Resource allocated in TRY without FINALLY cleanup.")
        warnings+=("  Ensure all resources are freed in FINALLY block.")
    fi
fi

# Output warnings
if [[ ${#warnings[@]} -gt 0 ]]; then
    echo "" >&2
    echo "=== Exception Safety Warnings ===" >&2
    for warning in "${warnings[@]}"; do
        echo "$warning" >&2
    done
    echo "" >&2
fi

# Always exit 0 (warnings only, don't block)
exit 0
