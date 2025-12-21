#!/bin/bash
# UserPromptSubmit hook - injects git workflow reminders as context
# For UserPromptSubmit, stdout plain text is automatically added to context

set -e

input=$(cat)
prompt=$(echo "$input" | jq -r '.prompt // ""' | tr '[:upper:]' '[:lower:]')

# Keywords that suggest starting new work
new_work_patterns=(
    "add a"
    "add the"
    "implement"
    "create a"
    "write a"
    "add support"
    "add new"
    "new feature"
)

# Keywords that suggest finishing work (commit/PR)
finish_patterns=(
    "commit"
    "push"
    "create pr"
    "pull request"
    "squash"
    "finish"
    "done with"
)

# Keywords that suggest fixing/updating
fix_patterns=(
    "fix the"
    "fix a"
    "update the"
    "change the"
    "modify"
    "refactor"
    "remove the"
    "delete the"
    "rename"
    "move the"
    "bug fix"
    "patch"
)

# Check for new work patterns
for pattern in "${new_work_patterns[@]}"; do
    if echo "$prompt" | grep -qi "$pattern"; then
        cat << 'EOF'
GIT WORKFLOW REQUIRED: This is new work. Use the /git-workflow skill to set up proper git workflow before making changes. The skill will create a GitHub issue and ensure you're on a feature branch. Do NOT work directly on main.
EOF
        exit 0
    fi
done

# Check for finish patterns
for pattern in "${finish_patterns[@]}"; do
    if echo "$prompt" | grep -qi "$pattern"; then
        cat << 'EOF'
GIT WORKFLOW: Use /git-workflow skill for proper commit/PR formatting. Commit messages must include type prefix (feat/fix/refactor), reference the issue with "Fixes #N", and include the Claude Code footer.
EOF
        exit 0
    fi
done

# Check for fix patterns
for pattern in "${fix_patterns[@]}"; do
    if echo "$prompt" | grep -qi "$pattern"; then
        cat << 'EOF'
GIT WORKFLOW: This involves code changes. Verify you're on a feature branch (not main). If on main, use /git-workflow to create an issue and branch first.
EOF
        exit 0
    fi
done

# No reminder needed
exit 0
