---
name: issue-processor
description: Parallel issue implementation pipeline. Fetches GitHub issues, builds dependency graph, spawns parallel agents to implement multiple issues simultaneously. File-based state survives context exhaustion.
allowed-tools: Bash,Read,Task
---

# Parallel Issue Implementation Pipeline

Implement multiple GitHub issues in parallel with unlimited scaling through checkpointing.

## Activation

This skill activates when:
- User mentions "process issues", "implement backlog", or "parallel issues"
- User wants to implement multiple GitHub issues
- User asks to "work on ready issues" or "unblocked issues"
- User says "continue" (to resume interrupted processing)

## CRITICAL: Context Efficiency

This skill uses an ultra-thin architecture:

1. **Python scripts** do all deterministic work (zero context)
2. **ONE coordinator** is spawned (background, 10min timeout)
3. **File polling** monitors progress (NOT TaskOutput)
4. **Coordinator respawns** on checkpoint (fresh context)

**NEVER use TaskOutput in this skill.** Poll files instead.

## Architecture

```
This Skill (ultra-thin) ──▶ Coordinator Agent ──▶ Implementation Agents (parallel)
        │                          │                        │
        │                          ▼                        ▼
        │                    manifest.json             results/*.json
        │                    (checkpoint)              (written by agents)
        │                          │
        └──────────────────────────┴──── Poll status.txt (via script)
```

**Context usage**: ~2KB constant (scripts do the heavy lifting)

## Workflow

### Step 1: Check for Existing Run

```bash
ls -d .claude/issue-state/run-* 2>/dev/null | tail -1
```

If found and not completed, ask user: "Resume or start fresh?"

### Step 2: Setup (Run Python Script)

```bash
RUN_ID="run-$(date +%Y%m%d-%H%M%S)"
STATE_DIR=".claude/issue-state/${RUN_ID}"

python3 .claude/skills/issue-processor/scripts/setup.py \
  --repo {REPOSITORY} \
  --label {LABEL} \
  --max {MAX} \
  --state-dir "${STATE_DIR}"
```

Script output tells you ready/blocked count. Creates:
- `manifest.json` - checkpoint state
- `graph.json` - dependency graph
- `frontier.json` - ready/blocked lists
- `issues/*.json` - issue details

### Step 3: Spawn Coordinator (Fire and Forget)

```
Task tool:
  subagent_type: "issue-impl-coordinator"
  description: "Coordinate issue implementation"
  prompt: |
    STATE_DIR: {STATE_DIR}
    REPOSITORY: {REPOSITORY}
    RESUME: false
    BATCH_SIZE: {BATCH_SIZE}

    Process all ready issues. Spawn implementation agents in parallel.
    Poll for result files using poll_results.py (NOT TaskOutput).
    Write CHECKPOINT if context gets low.
  run_in_background: true
  timeout: 600000
```

**IMPORTANT**: After spawning, IGNORE the returned task_id. Do not use TaskOutput.

### Step 4: Monitor Status (via Script)

Loop every 30 seconds:

```bash
python3 .claude/skills/issue-processor/scripts/check_status.py --state-dir {STATE_DIR}
```

**Status meanings:**

| Status | Action |
|--------|--------|
| `READY:N/M` | Coordinator hasn't started yet |
| `RUNNING:N/M` | In progress, report to user |
| `COMPLETED:N/M:X_success:Y_failed` | Done, go to summary |
| `ERROR:message` | Report error |

**IMPORTANT**: Do NOT use TaskOutput to check coordinator status. Only read status.txt.

For coordinator respawn on context exhaustion, check manifest.json for in_progress issues.

### Step 5: Handle Resume

If there are in_progress issues in manifest.json but no active coordinator:

```
Task tool:
  subagent_type: "issue-impl-coordinator"
  prompt: |
    STATE_DIR: {STATE_DIR}
    REPOSITORY: {REPOSITORY}
    RESUME: true
    BATCH_SIZE: {BATCH_SIZE}

    Continue from previous state. Read manifest.json for progress.
  run_in_background: true
  timeout: 600000
```

Then continue monitoring (Step 4).

### Step 5b: Get Next Batch

Use `next_batch.py` to get the next batch of ready issues with optional worktree creation:

```bash
python3 .claude/skills/issue-processor/scripts/next_batch.py \
  --state-dir {STATE_DIR} \
  --batch-size 5 \
  --create-worktrees
```

This returns JSON with worktree paths for parallel development.

### Step 6: Generate Summary

When status is `COMPLETED`:

```bash
python3 .claude/skills/issue-processor/scripts/summarize.py --state-dir {STATE_DIR}
```

Script outputs markdown summary of PRs and failures.

## User Options

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--repo` | Repository (owner/repo) | 7etsuo/tetsuo-socket |
| `--label` | Filter by label | none |
| `--max` | Maximum issues to process | 50 |
| `--batch-size` | Parallel agents per batch | 10 |
| `--dry-run` | Show frontier without implementing | false |

### Dry Run Mode

Just run setup and report:

```bash
python3 .claude/skills/issue-processor/scripts/setup.py --repo OWNER/REPO --state-dir /tmp/dry-run
cat /tmp/dry-run/frontier.json
```

Report ready/blocked without spawning agents.

## Resume Support

If user says "continue":

1. Find latest run: `ls -d .claude/issue-state/run-* | tail -1`
2. Check status: `python3 scripts/check_status.py --state-dir {DIR}`
3. If not COMPLETED: spawn coordinator with RESUME=true
4. Continue monitoring

## State Files

```
.claude/issue-state/run-{timestamp}/
├── manifest.json    # Checkpoint with progress
├── status.txt       # Simple status for polling
├── graph.json       # Dependency graph
├── frontier.json    # Ready/blocked lists
├── worktrees.json   # Worktree paths (if --create-worktrees used)
├── issues/          # Issue details
│   └── 391.json
└── results/         # Implementation results
    └── 391.json
```

## Result Format

See `scripts/RESULT_FORMAT.md` for the expected JSON structure when writing result files.

## What NOT to Do

❌ `TaskOutput(task_id: "abc123")` - FORBIDDEN
❌ Reading coordinator output directly - Only poll status.txt
❌ Waiting for agents synchronously - Fire and forget
❌ Parsing agent returns - Only read result files

## What TO Do

✅ Run setup.py to create state directory
✅ Spawn coordinator with `run_in_background: true`
✅ Poll status.txt using check_status.py
✅ Spawn new coordinator on CHECKPOINT
✅ Run summarize.py when COMPLETED

## Example Usage

```
User: /issue-processor --label quic --max 10

Skill:
  [1] Setup: "Fetched 15 issues. Ready: 8, Blocked: 7"
  [2] Spawning coordinator (fire and forget)...
  [3] Monitoring status.txt...
      Status: RUNNING:0/8
      Status: RUNNING:5/8
      Status: COMPLETED:8/8:7_success:1_failed

  ## Results

  | Issue | Title | PR |
  |-------|-------|-----|
  | #391 | NEW_TOKEN frame | #420 |
  | #392 | STREAM frame | #421 |
  ...

  ### Failures
  | #398 | Build failed: undefined reference |

  ### Next Wave
  - #393 (was blocked by #392)
  ...
```

## Benefits

| Aspect | Value |
|--------|-------|
| Context usage | ~2KB constant |
| Max issues | Unlimited (coordinator respawns) |
| State persistence | Files survive /compact |
| Parallelism | 10+ agents per batch |
| Resume | Automatic from checkpoint |
