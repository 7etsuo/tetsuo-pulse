---
name: worktree
description: Manage git worktrees for parallel development. Use when setting up, listing, or cleaning up worktrees for multiple Claude sessions.
user-invocable: true
allowed-tools: Bash, Read
---

# Git Worktree Management

Manage worktrees for parallel Claude Code sessions.

## When Invoked

1. **List current worktrees**: `git worktree list`
2. **Show available actions** based on context
3. **Execute requested operation**

## Quick Actions

### List Worktrees
```bash
git worktree list
```

### Create New Worktree (with issue)

```bash
# First, create the issue
gh issue create --title "feat: <description>" --body "<details>"

# Then create worktree (pick a naming style)
git fetch origin

# Option 1: Color naming (for parallel sessions)
git worktree add ../tetsuo-socket-red -b issue-<NUM>-<desc> origin/main

# Option 2: Issue naming (descriptive)
git worktree add ../tetsuo-socket-issue-<NUM>-<desc> -b issue-<NUM>-<desc> origin/main
```

### Create Quick Worktree (existing issue)

```bash
git fetch origin
git worktree add ../tetsuo-socket-<color> -b issue-<NUM>-<desc> origin/main
cd ../tetsuo-socket-<color>
```

### Remove Worktree

```bash
# From main repo
cd /home/tetsuo/git/tetsuo-socket
git worktree remove ../tetsuo-socket-<name>
git worktree prune
```

### Clean All Stale Worktrees

```bash
git worktree prune
git worktree list
```

## Naming Convention

| Color | Suggested Use |
|-------|---------------|
| `red` | Primary feature work |
| `blue` | Secondary feature |
| `purple` | Bug fixes |
| `green` | Experiments/spikes |
| `orange` | Refactoring |

Or use issue-based: `../tetsuo-socket-issue-42-auth`

## Parallel Session Setup

For running multiple Claude instances:

```bash
# Terminal 1 - Main repo
cd /home/tetsuo/git/tetsuo-socket
claude

# Terminal 2 - Feature A
cd /home/tetsuo/git/tetsuo-socket-red
claude

# Terminal 3 - Feature B
cd /home/tetsuo/git/tetsuo-socket-blue
claude
```

Each session is fully isolated with its own:
- Working directory
- Branch
- Staged changes
- Claude conversation

## Troubleshooting

### Worktree locked
```bash
git worktree unlock ../tetsuo-socket-<name>
```

### Branch already checked out
```bash
# Check where it's checked out
git worktree list
# Remove that worktree first, or use a different branch name
```

### Stale worktree references
```bash
git worktree prune
```
