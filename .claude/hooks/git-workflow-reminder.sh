#!/bin/bash
# UserPromptSubmit hook - reminds Claude to use git workflow for code changes

set -e

input=$(cat)
prompt=$(echo "$input" | jq -r '.prompt // ""' | tr '[:upper:]' '[:lower:]')

# Keywords that suggest code changes
code_change_patterns=(
    "add a"
    "add the"
    "implement"
    "create a"
    "write a"
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
    "add support"
    "add new"
    "new feature"
    "bug fix"
    "patch"
)

# Check if prompt matches any code change pattern
for pattern in "${code_change_patterns[@]}"; do
    if echo "$prompt" | grep -qi "$pattern"; then
        # Return reminder as additional context
        cat << 'EOF'
{
  "addToPrompt": "\n\n<system-reminder>\nThis request appears to involve codebase changes. Follow the git workflow:\n1. Create GitHub issue: `gh issue create`\n2. Create branch from main: `git checkout main && git pull && git checkout -b issue-<num>-<description>`\n3. Make the changes\n4. Squash commits and create PR: `gh pr create`\n\nDo NOT commit directly to main. The git-safety-check hook will block you if you try.\n</system-reminder>"
}
EOF
        exit 0
    fi
done

# No code change detected, no reminder needed
exit 0
