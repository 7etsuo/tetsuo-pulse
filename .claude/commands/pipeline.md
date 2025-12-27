# Code Analysis Pipeline

Multi-agent code analysis pipeline for C codebases. Spawns per-file pipeline agents that independently analyze, verify findings, and create GitHub issues for confirmed problems.

## Usage

```
/pipeline <directory>
```

Examples:
```
/pipeline src/socket/
/pipeline src/http/
/pipeline src/
```

## Pipeline Architecture

```
Phase 1: Discovery
    │
    ▼
Phase 2: Per-File Pipeline (parallel agents)
    │ ┌──────────────────────────────────────────────────────┐
    │ │ per-file-pipeline-agent (file1.c)                   │
    │ │   ├── Analyze file → finds issues                    │
    │ │   ├── Spawn issue-verifier-agent per finding        │
    │ │   └── Spawn pipeline-issue-writer for verified      │
    │ ├──────────────────────────────────────────────────────┤
    │ │ per-file-pipeline-agent (file2.c)                   │
    │ │   ├── Analyze file → finds issues                    │
    │ │   ├── Spawn issue-verifier-agent per finding        │
    │ │   └── Spawn pipeline-issue-writer for verified      │
    │ ├──────────────────────────────────────────────────────┤
    │ │ per-file-pipeline-agent (file3.c)                   │ All run in parallel
    │ │   └── ...                                            │
    │ └──────────────────────────────────────────────────────┘
    ▼
Phase 3: Report
```

Each per-file agent owns its complete workflow:
1. Analyze the file for security/redundancy/refactor issues
2. Spawn verification agents to double-check each finding
3. Create GitHub issues for verified problems
4. Return summary of actions taken

---

## PHASE 1: Discovery

**Goal**: Scan the target directory and identify all source files.

### Steps

1. **Scan directory recursively** for `.c` and `.h` files:
   ```
   Use Glob tool with patterns:
   - <directory>/**/*.c
   - <directory>/**/*.h
   ```

2. **List files found** with count

3. **CHECKPOINT**: Display file list and ask user to confirm analysis targets

### Output

```markdown
## Phase 1: Discovery Complete

Found [N] source files in <directory>:

### C Files ([count])
- path/to/file1.c
- path/to/file2.c
...

### Header Files ([count])
- path/to/file1.h
- path/to/file2.h
...

**Proceed with per-file analysis?** ([N] per-file-pipeline-agents will be spawned)
```

---

## PHASE 2: Per-File Pipeline Agents

**Goal**: Spawn independent agents that own the complete analysis→verification→issue workflow for each file.

### CRITICAL: Parallel Execution

**Spawn one `per-file-pipeline-agent` per source file, ALL IN A SINGLE MESSAGE.**

Do NOT:
- Process files sequentially
- Run agents one at a time
- Analyze files yourself without agents

DO:
- Send ONE message with N Task tool invocations (one per file)
- Run all agents in background
- Collect all results when complete

### Task Invocations

For each file, spawn:

```
Task:
  subagent_type: per-file-pipeline-agent
  run_in_background: true
  prompt: |
    Run complete analysis pipeline for this file:

    File: [FILEPATH]
    Repository: 7etsuo/tetsuo-socket

    Your workflow:
    1. Analyze the file for security, redundancy, and refactoring issues
    2. For EACH finding, spawn an issue-verifier-agent to verify it
    3. For each VERIFIED finding, spawn a pipeline-issue-writer to create a GitHub issue
    4. Return a summary of:
       - Issues found
       - Issues verified vs rejected (false positives)
       - GitHub issues created (with URLs)
       - Findings needing manual review
```

### Batching Strategy

If more than 20 files:
1. Split into batches of 15-20 files
2. Run each batch, wait for completion
3. Aggregate results across batches

### Collecting Results

Wait for all agents to complete using `TaskOutput` with blocking.

Each agent returns:
- Count of issues found
- Count verified vs rejected
- GitHub issue URLs created
- Any manual review items

---

## PHASE 3: Report Generation

**Goal**: Aggregate results from all per-file agents into a comprehensive report.

### Report Location

Save to: `<directory>/PIPELINE_ANALYSIS.md`

### Aggregation Steps

1. **Collect all agent outputs**
2. **Aggregate statistics**:
   - Total files analyzed
   - Total issues found across all files
   - Total verified / rejected / needs review
   - Total GitHub issues created
3. **Group created issues by category**:
   - Security issues
   - Redundancy issues
   - Refactoring issues
4. **List manual review items**

### Report Template

```markdown
# Pipeline Analysis Report

**Generated**: [timestamp]
**Directory**: <directory>
**Files Analyzed**: [count]

## Executive Summary

- **Files Analyzed**: [count]
- **Issues Found**: [count]
- **Verified Issues**: [count]
- **False Positives Filtered**: [count]
- **GitHub Issues Created**: [count]
- **Needs Manual Review**: [count]

## Issues Created by Category

### Security ([count])

| Issue # | File | Pattern | Severity |
|---------|------|---------|----------|
| #142 | file1.c:42 | UNSAFE_STRCPY | CRITICAL |
| #143 | file2.c:100 | MALLOC_OVERFLOW | HIGH |

### Redundancy ([count])

| Issue # | File | Pattern | Severity |
|---------|------|---------|----------|
| #144 | file3.c:55 | MANUAL_DJB2 | CRITICAL |

### Refactoring ([count])

| Issue # | File | Pattern | Severity |
|---------|------|---------|----------|
| #145 | file4.c:200 | LONG_FUNCTION_100 | HIGH |

## Per-File Breakdown

| File | Found | Verified | Rejected | Issues Created |
|------|-------|----------|----------|----------------|
| file1.c | 3 | 2 | 1 | #142 |
| file2.c | 2 | 1 | 1 | #143 |
| file3.c | 1 | 1 | 0 | #144 |

## Needs Manual Review

These findings require human judgment:

| File | Line | Pattern | Reason |
|------|------|---------|--------|
| file5.c | 100 | DEEP_NESTING | Switch statement, may be intentional |

## False Positives Filtered

| File | Line | Pattern | Reason |
|------|------|---------|--------|
| file1.c | 50 | MISSING_NULL | Already checked earlier |

---
*Report generated by /pipeline command*
```

### Final Output

```markdown
## Phase 3: Report Complete

Analysis report saved to: <directory>/PIPELINE_ANALYSIS.md

### Summary
- Files analyzed: [N]
- GitHub issues created: [N]
- False positives filtered: [N]
- Needs manual review: [N]

### Issue Links

- #142: fix(security): Replace unsafe strcpy in file1.c
- #143: fix(security): Check malloc overflow in file2.c
- #144: refactor(socket): Use socket_util_hash_djb2 in file3.c
- #145: refactor(http): Split long function in file4.c

**Pipeline complete.**
```

---

## Error Handling

- **Agent timeout**: If any agent takes >5 minutes, report partial results
- **Parse errors**: If agent output doesn't match expected format, include raw output
- **Issue creation failure**: Log error, continue with remaining files
- **Empty file**: Skip files with no code (only comments/whitespace)

---

## Example Session

```
User: /pipeline src/socket/

Claude: [Executes Phase 1 - Discovery]

## Phase 1: Discovery Complete

Found 12 source files in src/socket/:

### C Files (10)
- src/socket/Socket.c
- src/socket/SocketBuf.c
- src/socket/SocketCommon.c
...

### Header Files (2)
- include/socket/Socket.h
- include/socket/SocketBuf.h

**Proceed with per-file analysis?** (12 per-file-pipeline-agents will be spawned)

User: Yes

Claude: [Spawns 12 per-file-pipeline-agent tasks IN PARALLEL in background]
        [Each agent independently:]
        [  - Analyzes its file]
        [  - Spawns verifiers for each finding]
        [  - Creates issues for verified findings]
        [  - Returns summary]

        [Waits for all to complete]

## Pipeline Results

All 12 agents completed.

### Summary
- Files analyzed: 12
- Issues found: 18
- Verified: 14
- Rejected (false positives): 4
- GitHub issues created: 14
- Needs manual review: 2

### Issues Created

Security:
- #150: fix(security): Replace sprintf with snprintf in SocketBuf.c
- #151: fix(security): Add NULL check in Socket.c:142

Redundancy:
- #152: refactor(socket): Use socket_util_hash_djb2 instead of manual hash
- #153: refactor(socket): Define SOCKET_BUFFER_SIZE constant

Refactoring:
- #154: refactor(socket): Split Socket_connect function (>100 lines)

**Generate report?**

User: Yes

Claude: [Executes Phase 3 - Report]

Analysis report saved to: src/socket/PIPELINE_ANALYSIS.md

**Pipeline complete.**
```

---

## Key Design Principles

1. **Per-file ownership**: Each file gets its own agent that owns the complete workflow
2. **Parallel execution**: All per-file agents run simultaneously
3. **Verification before issues**: Every finding is verified before creating issues
4. **Independent issue creation**: Issues are created per-file, not grouped across files
5. **Comprehensive reporting**: Final report aggregates all agent results

## Notes

- Each per-file agent spawns its own verification and issue-writing sub-agents
- This creates more issues (one per finding per file) vs grouped issues
- But provides better isolation and clearer responsibility
- False positive filtering happens at the verification stage within each file's pipeline
