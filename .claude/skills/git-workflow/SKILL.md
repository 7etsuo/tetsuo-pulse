---
name: git-workflow
description: Git workflow best practices, commit message templates, and PR description formats. Use when working with git, creating commits, or preparing pull requests.
user-invocable: true
allowed-tools: Bash, Read, Grep, Glob
---

# Git Workflow with Worktrees

When invoked, guide the user through the git workflow. **Prefer worktrees for parallel development**.

## Quick Commands

### Start New Feature (Worktree)
```bash
# 1. Create issue
gh issue create --title "feat: description" --body "Details"

# 2. Create worktree (use color or issue naming)
git fetch origin
git worktree add ../tetsuo-socket-red -b issue-<NUM>-<desc> origin/main

# 3. Navigate and start working
cd ../tetsuo-socket-red
```

### Start New Feature (Standard Branch)
```bash
git checkout main && git pull origin main
gh issue create --title "feat: description" --body "Details"
git checkout -b issue-<NUM>-<desc>
```

### Commit Changes
```bash
git add -A
git commit -m "$(cat <<'EOF'
<type>: <description>

<body explaining WHY>

Fixes #<issue-number>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```

### Create PR
```bash
git push -u origin HEAD
gh pr create --title "<type>: <description>" --body "$(cat <<'EOF'
## Summary
- Brief description

Fixes #<issue-number>

## Test plan
- [ ] Tests pass with sanitizers
- [ ] Manual testing done

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

### Cleanup Worktree
```bash
cd /home/tetsuo/git/tetsuo-socket
git worktree remove ../tetsuo-socket-red
git worktree prune
```

## Worktree Naming Patterns

| Style | Directory | Use Case |
|-------|-----------|----------|
| Color | `../project-red` | Multiple parallel sessions |
| Issue | `../project-issue-42-auth` | Single focused task |
| Task | `../project-refactor-dns` | Descriptive for long-lived work |

## Parallel Development Setup

For running multiple Claude sessions on different features:

```bash
# Main repo stays on main (or current work)
/home/tetsuo/git/tetsuo-socket

# Worktrees for parallel work
/home/tetsuo/git/tetsuo-socket-red     → issue-42-feature-a
/home/tetsuo/git/tetsuo-socket-blue    → issue-43-feature-b
/home/tetsuo/git/tetsuo-socket-purple  → issue-44-bugfix
```

Each directory gets its own Claude session with full isolation.

## Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `issue-<num>-<desc>` | `issue-42-add-websocket-timeout` |
| Fix | `issue-<num>-fix-<desc>` | `issue-15-fix-memory-leak` |
| Refactor | `issue-<num>-refactor-<desc>` | `issue-8-refactor-dns-cache` |

## Commit Types

- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code change (no behavior change)
- `docs`: Documentation only
- `test`: Adding/updating tests
- `chore`: Build, deps, tooling
- `perf`: Performance improvement

## Safety Rules

- NEVER commit directly to main
- NEVER force push to main
- ALWAYS create issue first
- ALWAYS work on feature branch/worktree
- ALWAYS reference issue in commits/PR

## Workflow Checklist

### Before Starting
- [ ] On latest main: `git fetch origin`
- [ ] Issue created with clear description
- [ ] Worktree or branch created from main

### Before PR
- [ ] All tests pass (especially with sanitizers)
- [ ] Commits squashed to logical units
- [ ] Commit message follows convention
- [ ] Branch rebased on latest main if needed

### PR Description
- [ ] Links to issue with "Fixes #N"
- [ ] Describes WHY, not just WHAT
- [ ] Includes test plan

## Post-PR Cleanup

After creating a PR, ALWAYS show cleanup instructions:

```
PR created: <URL>

After PR is merged, clean up this worktree:
  cd /home/tetsuo/git/tetsuo-socket
  git worktree remove $(pwd)
  git worktree prune
  git branch -d <branch-name>
```

Skip worktree cleanup if working in main repo (not a worktree).
