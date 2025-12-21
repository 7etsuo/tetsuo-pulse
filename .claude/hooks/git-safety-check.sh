#!/bin/bash
# Git safety hook - prevents dangerous operations
# Blocks: direct commits to main, force push to main

set -e

input=$(cat)
command=$(echo "$input" | jq -r '.tool_input.command // ""')

# Skip if not a git command
if ! echo "$command" | grep -q '^git '; then
    exit 0
fi

# Block force push to main/master
if echo "$command" | grep -qE 'git\s+push.*--force.*\b(main|master)\b'; then
    echo '{"error": "Force push to main/master is not allowed. Use a feature branch."}' >&2
    exit 2
fi

if echo "$command" | grep -qE 'git\s+push.*\b(main|master)\b.*--force'; then
    echo '{"error": "Force push to main/master is not allowed. Use a feature branch."}' >&2
    exit 2
fi

# Block direct commits to main (should use feature branch)
current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [ "$current_branch" = "main" ] || [ "$current_branch" = "master" ]; then
    if echo "$command" | grep -qE 'git\s+commit'; then
        echo '{"error": "Cannot commit directly to main. Create a feature branch first: git checkout -b issue-<num>-<description>"}' >&2
        exit 2
    fi
fi

# Block hard reset on main
if [ "$current_branch" = "main" ] || [ "$current_branch" = "master" ]; then
    if echo "$command" | grep -qE 'git\s+reset\s+--hard'; then
        echo '{"error": "Hard reset on main is not allowed."}' >&2
        exit 2
    fi
fi

exit 0
