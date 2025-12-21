# Git Operations Command

Quick git operations. For full workflow (issue → branch → PR), use `/git-workflow`.

## Quick Status
```bash
git status --short
git branch -vv
git worktree list
```

## Staging Files

Stage source files only (skip build artifacts):
```bash
git add *.c *.h
# Or specific files
git add src/socket/SocketBuf.c include/socket/SocketBuf.h
```

Never auto-stage:
- `.o`, `.swp`, `.swo` files
- `build/`, `Testing/`, `.cursor/` directories
- `.env`, credentials, secrets

## Commit Format

```bash
git commit -m "$(cat <<'EOF'
<type>: <description>

<body explaining WHY>

Fixes #<issue-number>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`

## Worktree Operations

```bash
# List worktrees
git worktree list

# Create new worktree with branch
git worktree add ../tetsuo-socket-red -b issue-42-feature origin/main

# Remove worktree
git worktree remove ../tetsuo-socket-red
git worktree prune
```

## Common Operations

```bash
# Squash commits before PR
git rebase -i main

# Push new branch
git push -u origin HEAD

# Create PR
gh pr create --title "<type>: desc" --body "..."

# Sync with main
git fetch origin
git rebase origin/main
```

## Error Handling

| Issue | Solution |
|-------|----------|
| Merge conflicts | Resolve manually, then `git add` and `git rebase --continue` |
| Upstream diverged | `git pull --rebase origin main` |
| Wrong branch | `git stash && git checkout correct-branch && git stash pop` |
| Undo last commit | `git reset --soft HEAD~1` (keeps changes staged) |

## Safety Rules

- NEVER commit to main directly
- NEVER force push to main
- ALWAYS work on feature branch or worktree
- ALWAYS reference issue number in commits
