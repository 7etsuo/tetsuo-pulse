---
name: git-workflow
description: Git workflow best practices, commit message templates, and PR description formats. Use when working with git, creating commits, or preparing pull requests.
allowed-tools: Read, Grep, Glob
---

# Git Workflow Best Practices

## Branch Naming Convention

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `issue-<num>-<description>` | `issue-42-add-websocket-timeout` |
| Fix | `issue-<num>-fix-<description>` | `issue-15-fix-memory-leak` |
| Refactor | `issue-<num>-refactor-<description>` | `issue-8-refactor-dns-cache` |

## Commit Message Template

```
<type>: <concise description>

<optional body explaining WHY, not WHAT>

Fixes #<issue-number>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

### Commit Types

- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `docs`: Documentation only
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, tooling
- `perf`: Performance improvement

### Good Commit Messages

```
feat: add connection timeout for WebSocket handshake

Without a timeout, hung connections would block the event loop
indefinitely. This adds a configurable timeout (default 30s).

Fixes #42
```

### Bad Commit Messages

```
fixed stuff          # Too vague
WIP                  # Not descriptive
Update Socket.c      # Describes WHAT, not WHY
```

## Pull Request Template

```markdown
## Summary
- One-line description of what this PR does
- Key implementation decisions

Fixes #<issue-number>

## Changes
- List of specific changes made
- Any breaking changes noted

## Test plan
- [ ] `ctest --output-on-failure` passes
- [ ] Sanitizers pass: `ASAN_OPTIONS=detect_leaks=1 ctest`
- [ ] Manual testing: <describe how to test>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## Squashing Commits

Before creating a PR, squash related commits:

```bash
# Interactive rebase against main
git rebase -i main

# In editor: mark commits as 'squash' or 's' to combine
# First commit stays as 'pick', rest become 'squash'

# Force push after squashing (only on feature branch!)
git push --force-with-lease
```

## Workflow Checklist

### Before Starting Work
- [ ] On latest main: `git checkout main && git pull`
- [ ] Issue created with clear description
- [ ] Feature branch created from main

### Before Creating PR
- [ ] All tests pass
- [ ] Commits squashed to logical units
- [ ] Commit message follows convention
- [ ] Branch rebased on latest main

### PR Description
- [ ] Links to issue with "Fixes #N"
- [ ] Describes the WHY, not just WHAT
- [ ] Includes test plan
