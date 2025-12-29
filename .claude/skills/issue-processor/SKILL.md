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

This skill uses a direct architecture:

1. **Python scripts** do all deterministic work (zero context)
2. **Skill spawns implementers directly** (no coordinator layer)
3. **File polling** monitors progress (NOT TaskOutput)
4. **Batched spawning** prevents context exhaustion
5. **Centralized locking** - skill claims/releases, agents just implement

**NEVER use TaskOutput in this skill.** Poll files instead.

**Locking Architecture**: The skill owns ALL claim/release logic:
- `start_batch.py` claims issues with `wip:claude-*` labels BEFORE spawning agents
- Agents do NOT claim - they trust the skill already claimed for them
- `finish_batch.py` releases all claims AFTER agents complete
- This prevents race conditions where agents try to re-claim already-claimed issues

## Architecture

```
This Skill ──▶ Implementation Agents (parallel, up to BATCH_SIZE)
     │                      │
     │                      ▼
     │                 results/*.json
     │                 (written by agents)
     │
     └──── Poll status.txt (via script)
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

### Step 3: Spawn Implementers Directly (Fire and Forget)

**Claim the batch first** using `start_batch.py` (updates manifest with `current_batch`):

```bash
BATCH=$(python3 .claude/skills/issue-processor/scripts/start_batch.py \
  --state-dir {STATE_DIR} \
  --batch-size 10 \
  --fail-mode fail-safe)

# Update status
echo "RUNNING:0/$(echo $BATCH | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')" > {STATE_DIR}/status.txt
```

**Fail modes** (for API error handling):
- `fail-safe` (default): Skip entire batch on API error (prevents duplicates)
- `fail-open`: Include all candidates on API error (risks duplicates)
- `error`: Exit with error on API failure

This enables visibility - other terminals can see which issues are being worked on.

Spawn ALL agents in ONE message with MULTIPLE Task calls:

**IMPORTANT**: Include the CRITICAL OVERRIDE instruction to tell agents NOT to claim (the skill already claimed for them):

```
Task(
  subagent_type: "issue-implementer"
  description: "Implement #391"
  prompt: |
    **CRITICAL OVERRIDE**: DO NOT call claim_issue.py --action claim. The orchestrator has already claimed this issue. Skip claiming entirely and go directly to Setup Worktree.

    STATE_DIR: {STATE_DIR}
    REPOSITORY: {REPOSITORY}
    ISSUE_NUMBER: 391
  run_in_background: true
)
Task(
  subagent_type: "issue-implementer"
  description: "Implement #392"
  prompt: |
    **CRITICAL OVERRIDE**: DO NOT call claim_issue.py --action claim. The orchestrator has already claimed this issue. Skip claiming entirely and go directly to Setup Worktree.

    STATE_DIR: {STATE_DIR}
    REPOSITORY: {REPOSITORY}
    ISSUE_NUMBER: 392
  run_in_background: true
)
... (spawn up to BATCH_SIZE at once)
```

**IMPORTANT**: After spawning, IGNORE the returned task_ids. Do not use TaskOutput.

### Step 4: Monitor Status (via Script)

Poll every 10 seconds until batch completes (default):

```bash
python3 .claude/skills/issue-processor/scripts/poll_results.py \
  --state-dir {STATE_DIR} \
  --expected {comma_separated_issue_numbers} \
  --timeout 600 \
  --poll-interval 10 \
  --stall-threshold 120
```

Arguments:
- `--poll-interval N`: Seconds between polls (default: 10)
- `--stall-threshold N`: Seconds without progress before STALLED warning (default: 120)
- `--timeout N`: Total timeout in seconds (default: 600)

The script monitors `results/*.json` files and updates status.txt.

Also check status with:

```bash
python3 .claude/skills/issue-processor/scripts/check_status.py --state-dir {STATE_DIR}
```

**Status meanings:**

| Status | Action |
|--------|--------|
| `RUNNING:N/M` | In progress, report to user |
| `STALLED:N/M:no_progress_for_Xs` | No results for 120+ seconds - agents may have failed |
| `COMPLETED:N/M:X_success:Y_failed` | Batch done, check for more |
| `ERROR:message` | Report error |

**STALLED handling**: If you see STALLED, check:
1. `started/` directory - which agents wrote started markers
2. `wip:*` labels on issues - which are claimed but not progressing
3. Release stuck claims and retry

### Step 5: Finish Batch and Process Next

After a batch completes, finalize it and check for more:

```bash
python3 .claude/skills/issue-processor/scripts/finish_batch.py --state-dir {STATE_DIR}
```

This clears `current_batch` and updates `completed`/`failed` lists in the manifest.

Then check for remaining issues:
1. Read `manifest.json` - check `completed`, `failed`, `ready` lists
2. If more ready issues exist, go back to Step 3 with next batch
3. If all done, go to Step 6 (Summary)

### Step 5b: Get Next Batch

Use `next_batch.py` to get the next batch of ready issues with optional worktree creation:

```bash
python3 .claude/skills/issue-processor/scripts/next_batch.py \
  --state-dir {STATE_DIR} \
  --batch-size 5 \
  --create-worktrees \
  --fail-mode fail-safe
```

This returns JSON with worktree paths for parallel development. The `--fail-mode` option
works the same as in `start_batch.py`.

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
3. Read manifest.json to find remaining ready issues (excluding completed/failed)
4. Spawn next batch of implementers directly
5. Continue polling and batching until done

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
├── started/         # Agent start markers (for debugging)
│   └── 391.json
└── results/         # Implementation results
    └── 391.json
```

## Result Format

See `scripts/RESULT_FORMAT.md` for the expected JSON structure when writing result files.

## What NOT to Do

❌ `TaskOutput(task_id: "abc123")` - FORBIDDEN
❌ Reading agent output directly - Only poll result files
❌ Waiting for agents synchronously - Fire and forget
❌ Using a coordinator subagent - Spawn implementers directly

## What TO Do

✅ Run setup.py to create state directory
✅ Spawn implementers directly with `run_in_background: true`
✅ Poll status.txt using check_status.py or poll_results.py
✅ Process batches sequentially (spawn batch, wait, spawn next)
✅ Run summarize.py when COMPLETED

## Example Usage

```
User: /issue-processor --label quic --max 10

Skill:
  [1] Setup: "Fetched 15 issues. Ready: 8, Blocked: 7"
  [2] Spawning 8 implementer agents directly...
  [3] Polling for results...
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

## Checking Available Issues (for Manual Work)

When issue-processor is running in one terminal and you want to work on issues
manually in another terminal, use `list_available.py`:

```bash
python3 .claude/skills/issue-processor/scripts/list_available.py \
  --repo 7etsuo/tetsuo-socket \
  --state-dir .claude/issue-state/run-xxx
```

Output shows:
- **CLAIMED**: Issues currently being worked on by agents (have `wip:*` labels)
- **CURRENT BATCH**: Issues in the active batch (from manifest)
- **AVAILABLE**: Issues safe to work on manually

Options:
- `--limit N`: Show first N available issues (default: 20)
- `--json`: Output as JSON for scripting

For quick status with batch details:
```bash
python3 .claude/skills/issue-processor/scripts/check_status.py \
  --state-dir .claude/issue-state/run-xxx \
  --verbose
```

## Multi-Instance Coordination

Multiple Claude instances can safely run `/issue-processor` simultaneously without conflicts.

### How It Works

1. **Setup filtering**: `setup.py` skips issues with `wip:*` labels (already claimed)
2. **Batch re-validation**: `start_batch.py` and `next_batch.py` **query GitHub before each batch**
   to filter out issues that are:
   - Already CLOSED (completed by other instances)
   - Have `wip:*` labels (claimed by other instances)
   - Already have open PRs linked
3. **Claim on start**: Each implementer adds a `wip:claude-{timestamp}-{pid}` label before working
4. **Release on finish**: Label is removed after success or failure
5. **Race detection**: If two instances try to claim the same issue, the second one backs off

### Why Re-Validation Prevents Duplicates

Without re-validation:
```
Instance A: setup → ready=[1-50] → works on [1-10]
Instance B: setup → ready=[11-60] → finishes [11-20]
Instance A: finishes [1-10] → grabs [11-20] from stale manifest
         ❌ Creates duplicate PRs for [11-20]!
```

With re-validation:
```
Instance A: setup → ready=[1-50] → works on [1-10]
Instance B: setup → ready=[11-60] → finishes [11-20]
Instance A: finishes [1-10] → start_batch.py checks GitHub
         ✅ Sees [11-20] are closed → skips them → no duplicates
```

### Label Protocol

| Label | Meaning |
|-------|---------|
| `wip:claude-1703847234-12345` | Claimed by instance at timestamp 1703847234, PID 12345 |
| No `wip:*` label | Available for claiming |

### Manual Claim Management

```bash
# Check if issue is claimed
python3 .claude/skills/issue-processor/scripts/claim_issue.py \
  --repo 7etsuo/tetsuo-socket --issue 391 --action check

# Manually release a stuck claim (e.g., after crash)
python3 .claude/skills/issue-processor/scripts/claim_issue.py \
  --repo 7etsuo/tetsuo-socket --issue 391 --action release
```

### Recovery from Crashes

If an instance crashes mid-implementation:
1. The `wip:*` label remains on the issue
2. Other instances will skip it
3. Manually release with `--action release` or remove the label in GitHub UI
4. The issue becomes available for the next run

## Troubleshooting

### STALLED Status

When `poll_results.py` reports `STALLED`, agents may have failed silently.

**Diagnosis steps:**

1. Check which agents started:
   ```bash
   ls {STATE_DIR}/started/
   ```

2. Check which agents wrote results:
   ```bash
   ls {STATE_DIR}/results/
   ```

3. Find agents that started but didn't finish:
   ```bash
   # Compare started vs results
   comm -23 <(ls {STATE_DIR}/started/ | sort) <(ls {STATE_DIR}/results/ | sort)
   ```

4. Check GitHub for stuck claims:
   ```bash
   python3 .claude/skills/issue-processor/scripts/list_available.py \
     --repo OWNER/REPO --state-dir {STATE_DIR} --json | jq '.claimed'
   ```

**Resolution:**

- Release stuck claims manually:
  ```bash
  python3 .claude/skills/issue-processor/scripts/claim_issue.py \
    --repo OWNER/REPO --issue {NUM} --action release
  ```

- Re-run the batch for failed issues

### API Rate Limits

The GitHub GraphQL API has complexity limits that may cause batch validation to fail.

**Symptoms:**
- `GitHub API error` messages during batch claiming
- Empty batches returned despite ready issues

**Resolution:**
- The default `--fail-mode fail-safe` will skip batches on API errors
- Wait and retry - rate limits reset over time
- Reduce `--batch-size` to check fewer issues per API call

### Duplicate PRs

If duplicate PRs are created, check:

1. **Are you using the latest scripts?** Re-validation was added to prevent this.

2. **Is fail-mode set correctly?** Use `fail-safe` (default) not `fail-open`.

3. **Are GitHub labels working?** Check that `wip:*` labels are being applied:
   ```bash
   gh issue view {NUM} --repo OWNER/REPO --json labels
   ```

### Result File Format Errors

If `poll_results.py` can't parse result files:

1. Check the result file format matches `scripts/RESULT_FORMAT.md`
2. Ensure JSON is valid:
   ```bash
   python3 -m json.tool {STATE_DIR}/results/{NUM}.json
   ```

3. Valid status values are: `success`, `failed`, `already_resolved`

## Benefits

| Aspect | Value |
|--------|-------|
| Context usage | ~2KB constant |
| Max issues | Unlimited (batched spawning) |
| State persistence | Files survive /compact |
| Parallelism | 10+ agents per batch |
| Resume | Automatic from manifest state |
| Multi-instance | Safe coordination via GitHub labels |
