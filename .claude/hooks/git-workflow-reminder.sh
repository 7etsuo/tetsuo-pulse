#!/bin/bash
# UserPromptSubmit hook - triggers git-workflow agent for code changes

set -e

input=$(cat)
prompt=$(echo "$input" | jq -r '.prompt // ""' | tr '[:upper:]' '[:lower:]')

# Keywords that suggest starting new work (need full git workflow)
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

# Keywords that suggest fixing/updating (may need branch)
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

# Check for new work patterns - need worktree/branch setup
for pattern in "${new_work_patterns[@]}"; do
    if echo "$prompt" | grep -qi "$pattern"; then
        cat << 'EOF'
{
  "addToPrompt": "\n\n<system-reminder>\n**IMPORTANT: Use the git-workflow agent for this task.**\n\nThis appears to be new work. You MUST:\n1. Use Task tool with subagent_type='git-workflow' to set up proper workflow\n2. The agent will create a GitHub issue and worktree (or branch)\n3. Only start coding after the agent confirms setup\n\nPrefer worktrees for isolation: `git worktree add ../tetsuo-socket-red -b issue-N-desc origin/main`\n\nDo NOT commit directly to main. The git-safety-check hook will block you.\n</system-reminder>"
}
EOF
        exit 0
    fi
done

# Check for finish patterns - need commit/PR help
for pattern in "${finish_patterns[@]}"; do
    if echo "$prompt" | grep -qi "$pattern"; then
        cat << 'EOF'
{
  "addToPrompt": "\n\n<system-reminder>\n**Use /git-workflow to finalize changes.**\n\nFor commits, use this format:\n```\ngit commit -m \"$(cat <<'COMMIT'\n<type>: <description>\n\n<body>\n\nFixes #<issue>\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>\nCOMMIT\n)\"\n```\n\nFor PRs: `gh pr create --title \"<type>: desc\" --body \"...\"`\n</system-reminder>"
}
EOF
        exit 0
    fi
done

# Check for fix patterns - may need branch if on main
for pattern in "${fix_patterns[@]}"; do
    if echo "$prompt" | grep -qi "$pattern"; then
        cat << 'EOF'
{
  "addToPrompt": "\n\n<system-reminder>\nThis appears to involve code changes. Check your current branch:\n- If on main: Use git-workflow agent to create issue + worktree/branch first\n- If on feature branch: Proceed with changes\n\nPrefer worktrees for parallel work: `git worktree add ../tetsuo-socket-red -b issue-N-desc origin/main`\n\nRun `git branch` to verify you're not on main before making changes.\n</system-reminder>"
}
EOF
        exit 0
    fi
done

# No code change detected, no reminder needed
exit 0
