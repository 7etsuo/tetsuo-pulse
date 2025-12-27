# Code Analysis Pipeline

Multi-agent code analysis pipeline for C codebases. Spawns per-file analysis agents, verifies findings, and creates GitHub issues for confirmed problems.

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
Phase 2: Per-File Analysis (parallel agents)
    │ ┌──────────────────────────────────┐
    │ │ file-analyzer-agent (file1.c)   │──┐
    │ │ file-analyzer-agent (file2.c)   │──┼── All run in parallel
    │ │ file-analyzer-agent (file3.c)   │──┤
    │ │ ...                              │──┘
    │ └──────────────────────────────────┘
    ▼
Phase 3: Group & Aggregate
    │
    ▼
Phase 4: Verification (parallel agents)
    │ ┌──────────────────────────────────┐
    │ │ issue-verifier-agent (pattern1) │──┐
    │ │ issue-verifier-agent (pattern2) │──┼── Verify each pattern
    │ │ issue-verifier-agent (pattern3) │──┤
    │ └──────────────────────────────────┘
    ▼
Phase 5: Issue Creation
    │ ┌──────────────────────────────────┐
    │ │ pipeline-issue-writer            │── Create GitHub issues
    │ └──────────────────────────────────┘
    ▼
Phase 6: Report
```

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

**Proceed with per-file analysis?** ([N] agents will be spawned in parallel)
```

---

## PHASE 2: Per-File Analysis

**Goal**: Analyze each file independently using parallel agents.

### CRITICAL: Parallel Execution

**Spawn one `file-analyzer-agent` per source file, ALL IN A SINGLE MESSAGE.**

Do NOT:
- Analyze files sequentially
- Run agents one at a time
- Analyze files yourself without agents

DO:
- Send ONE message with N Task tool invocations (one per file)
- Run all agents in background if >10 files
- Collect all results when complete

### Task Invocations

For each file, spawn:

```
Task:
  subagent_type: file-analyzer-agent
  run_in_background: true  (if many files)
  prompt: |
    Analyze this C source file for security, redundancy, and refactoring issues:

    File: [FILEPATH]

    Return structured findings with:
    - Pattern IDs for grouping
    - Exact line numbers
    - Severity levels
    - Specific recommendations

    Reference .claude/references/module-apis.md for existing utilities.
```

### Batching Strategy

If more than 20 files:
1. Split into batches of 15-20 files
2. Run each batch, wait for completion
3. Aggregate results across batches

### Collecting Results

Wait for all agents to complete using `TaskOutput` with blocking.

---

## PHASE 3: Group & Aggregate

**Goal**: Combine per-file findings into grouped patterns.

### Steps

1. **Parse all agent outputs** into structured findings

2. **Group by Pattern ID**:
   - Collect all instances of `UNSAFE_STRCPY` across files
   - Collect all instances of `MAGIC_BUFFER_4096` across files
   - etc.

3. **Create pattern groups**:
   ```
   Pattern: UNSAFE_STRCPY
   Category: security
   Severity: CRITICAL
   Locations:
     - file1.c:42
     - file2.c:100
     - file3.c:55
   ```

4. **Prioritize patterns**:
   - CRITICAL security issues first
   - HIGH issues next
   - Group by category within severity

5. **CHECKPOINT**: Display grouped findings summary

### Output

```markdown
## Phase 3: Grouping Complete

### Patterns Found

| Pattern ID | Category | Severity | Locations |
|------------|----------|----------|-----------|
| UNSAFE_STRCPY | security | CRITICAL | 5 files |
| MAGIC_BUFFER_4096 | redundancy | HIGH | 8 files |
| LONG_FUNCTION_100 | refactor | HIGH | 3 files |
| STYLE_RETURN_LINE | refactor | MEDIUM | 12 files |

**Total Patterns**: [N]
**Total Findings**: [M across all files]

**Proceed with verification?** ([N] verification agents will be spawned)
```

---

## PHASE 4: Verification

**Goal**: Verify each pattern group to filter false positives.

### CRITICAL: Parallel Execution

**Spawn one `issue-verifier-agent` per pattern group, ALL IN A SINGLE MESSAGE.**

### Task Invocations

For each pattern group:

```
Task:
  subagent_type: issue-verifier-agent
  run_in_background: true
  prompt: |
    Verify this code analysis finding:

    Pattern ID: [PATTERN_ID]
    Category: [category]
    Severity: [severity]

    Locations to verify:
    - [file1.c:line1] - [code snippet]
    - [file2.c:line2] - [code snippet]
    - [file3.c:line3] - [code snippet]

    Original Issue: [description]
    Recommendation: [recommendation]

    For each location:
    1. Read the code at that line
    2. Confirm the issue exists (not a false positive)
    3. Validate the recommendation is applicable

    Return VERIFIED, REJECTED, or NEEDS_MANUAL_REVIEW for each location.
```

### Collecting Results

Wait for all verification agents. Aggregate into:
- **Verified patterns** (at least one valid location)
- **Rejected patterns** (all locations were false positives)
- **Uncertain patterns** (needs manual review)

---

## PHASE 5: Issue Creation

**Goal**: Create GitHub issues for verified findings.

### Steps

1. **For each verified pattern**, spawn issue writer:

```
Task:
  subagent_type: pipeline-issue-writer
  prompt: |
    Create a GitHub issue for this verified finding:

    Pattern: [PATTERN_ID]
    Category: [category]
    Severity: [severity]

    Verified Locations:
    - [file1.c:42] - Confirmed: [reason]
    - [file2.c:100] - Confirmed: [reason]

    Issue: [description]
    Recommendation: [fix]

    Repository: 7etsuo/tetsuo-socket

    Create ONE issue grouping all locations.
    Apply appropriate labels.
    Return the issue URL when done.
```

2. **Collect issue URLs** as they're created

3. **For UNCERTAIN patterns**, note for manual review

### Output

```markdown
## Phase 5: Issues Created

### Created Issues

| Issue | Pattern | Severity | Files |
|-------|---------|----------|-------|
| #142 | UNSAFE_STRCPY | CRITICAL | 5 |
| #143 | MAGIC_BUFFER_4096 | HIGH | 8 |
| #144 | LONG_FUNCTION_100 | HIGH | 3 |

### Needs Manual Review

| Pattern | Locations | Reason |
|---------|-----------|--------|
| STYLE_RETURN_LINE | 12 files | Uncertain if intentional |

**Continue with report generation?**
```

---

## PHASE 6: Report Generation

**Goal**: Generate comprehensive analysis report.

### Report Location

Save to: `<directory>/PIPELINE_ANALYSIS.md`

### Report Template

```markdown
# Pipeline Analysis Report

**Generated**: [timestamp]
**Directory**: <directory>
**Files Analyzed**: [count]

## Executive Summary

- **Patterns Identified**: [count]
- **Findings Total**: [count across all files]
- **Verified Issues**: [count]
- **Issues Created**: [count]
- **False Positives Filtered**: [count]
- **Needs Manual Review**: [count]

## Issues Created

| Issue # | Title | Severity | Files Affected |
|---------|-------|----------|----------------|
| #142 | [title] | CRITICAL | 5 |
| #143 | [title] | HIGH | 8 |

## Analysis by Category

### Security ([count] issues)

[List security issues with brief descriptions]

### Redundancy ([count] issues)

[List redundancy issues with brief descriptions]

### Refactoring ([count] issues)

[List refactoring issues with brief descriptions]

## Needs Manual Review

These patterns require human judgment:

| Pattern | Files | Reason |
|---------|-------|--------|
| [pattern] | [count] | [reason verification was uncertain] |

## Files Analyzed

| File | Issues Found | Patterns |
|------|--------------|----------|
| path/file1.c | 3 | UNSAFE_STRCPY, MAGIC_BUFFER_4096 |
| path/file2.c | 1 | LONG_FUNCTION_100 |

## False Positives Filtered

These findings were rejected during verification:

| Pattern | Location | Reason |
|---------|----------|--------|
| [pattern] | [file:line] | [why it was a false positive] |

---
*Report generated by /pipeline command*
```

### Final Output

```markdown
## Phase 6: Report Complete

Analysis report saved to: <directory>/PIPELINE_ANALYSIS.md

### Summary
- Files analyzed: [N]
- Patterns identified: [N]
- Issues created: [N]
- False positives filtered: [N]
- Needs manual review: [N]

### Issue Links
- #142: fix(security): Replace unsafe strcpy calls
- #143: refactor(socket): Define SOCKET_BUFFER_SIZE constant
- #144: refactor(http): Split long parse_request function

**Pipeline complete.**
```

---

## Error Handling

- **Agent timeout**: If any agent takes >5 minutes, report partial results
- **Parse errors**: If agent output doesn't match expected format, include raw output
- **Issue creation failure**: Log error, continue with remaining issues
- **All locations rejected**: Don't create issue, note pattern was fully filtered

---

## Example Session

```
User: /pipeline src/socket/

Claude: [Executes Phase 1 - Discovery]

## Phase 1: Discovery Complete

Found 15 source files in src/socket/:

### C Files (12)
- src/socket/Socket.c
- src/socket/SocketBuf.c
- src/socket/SocketCommon.c
...

### Header Files (3)
- include/socket/Socket.h
- include/socket/SocketBuf.h
...

**Proceed with per-file analysis?** (12 agents will be spawned)

User: Yes

Claude: [Spawns 12 file-analyzer-agent tasks IN PARALLEL]
        [Waits for all to complete]
        [Executes Phase 3 - Grouping]

## Phase 3: Grouping Complete

### Patterns Found

| Pattern ID | Category | Severity | Locations |
|------------|----------|----------|-----------|
| UNSAFE_SPRINTF | security | CRITICAL | 3 files |
| MAGIC_BUFFER_4096 | redundancy | HIGH | 5 files |
| MANUAL_DJB2 | redundancy | CRITICAL | 2 files |

**Proceed with verification?**

User: Yes

Claude: [Spawns 3 issue-verifier-agent tasks IN PARALLEL]
        [Waits for all to complete]

## Phase 4: Verification Complete

### Verified: 2 patterns
- UNSAFE_SPRINTF: 3/3 locations confirmed
- MANUAL_DJB2: 2/2 locations confirmed

### Filtered: 1 pattern
- MAGIC_BUFFER_4096: All 5 locations were protocol constants

**Create issues for verified findings?**

User: Yes

Claude: [Spawns pipeline-issue-writer]
        [Creates 2 GitHub issues]

## Phase 5: Issues Created

- #150: fix(security): Replace sprintf with snprintf in socket code
- #151: refactor(socket): Use socket_util_hash_djb2 instead of manual implementation

**Generate report?**

User: Yes

Claude: [Executes Phase 6 - Report]

Analysis report saved to: src/socket/PIPELINE_ANALYSIS.md

**Pipeline complete.**
```

---

## Notes

- Each file gets its own analyzer agent for thorough per-file analysis
- Pattern grouping enables consolidated issues (one issue per pattern, not per file)
- Full verification filters false positives before issue creation
- Interactive checkpoints let user control the process
- Parallel execution maximizes performance
