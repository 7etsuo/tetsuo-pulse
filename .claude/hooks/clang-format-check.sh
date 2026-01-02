#!/bin/bash
# Auto-format C/H files after editing
# Runs clang-format -i on the edited file if it's a C or header file

set -euo pipefail

# Get the file path from the tool input
FILE_PATH=$(echo "$CLAUDE_TOOL_INPUT" | jq -r '.file_path // empty')

if [[ -z "$FILE_PATH" ]]; then
    exit 0
fi

# Only format C and header files
case "$FILE_PATH" in
    *.c|*.h)
        if [[ -f "$FILE_PATH" ]] && command -v clang-format &>/dev/null; then
            clang-format -i "$FILE_PATH"
            echo "Auto-formatted: $FILE_PATH"
        fi
        ;;
esac

exit 0
