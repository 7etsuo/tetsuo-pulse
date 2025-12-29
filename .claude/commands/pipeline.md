# Code Analysis Pipeline

Multi-agent code analysis pipeline for C codebases. Supports three modes:
1. **Code Analysis Mode** (default) - Security, redundancy, and refactoring analysis
2. **TODO Mode** - Scan for TODO/FIXME/HACK/XXX/NOTE comments and create issues
3. **Refactor Mode** - Focus on flattening nested ifs and identifying single-use subroutines

## Usage

```
/pipeline <directory>           # Code analysis mode (default)
/pipeline <directory> todo      # TODO scanning mode
/pipeline <file|directory> refactor  # Readability refactoring mode
```

Examples:
```
/pipeline src/socket/           # Analyze socket module for issues
/pipeline src/http/ todo        # Scan http module for TODO comments
/pipeline src/                  # Analyze entire src directory
/pipeline src/http/SocketHTTP2.c refactor  # Refactor analysis on single file
/pipeline src/socket/ refactor  # Refactor analysis on directory
```

---

# MODE DETECTION

Check the second argument to determine which mode to run:

- If second argument is `todo` → Run **TODO Mode** (see TODO MODE section below)
- If second argument is `refactor` → Run **Refactor Mode** (see REFACTOR MODE section below)
- Otherwise → Run **Code Analysis Mode** (see PHASE 1-3 sections below)

---

# TODO MODE

Scan for TODO/FIXME/HACK/XXX/NOTE comments and create GitHub issues for each one.

## TODO Mode Architecture

```
/pipeline src/socket/ todo
    │
    ▼
Phase T1: Discovery
    │ Grep for TODO/FIXME/HACK/XXX/NOTE patterns
    │ Extract: file, line, pattern, comment text
    ▼
Phase T2: Per-TODO Processing (parallel)
    │ ┌──────────────────────────────────────────┐
    │ │ todo-scanner-agent (TODO at file1.c:42)  │
    │ │   ├── Check for duplicate issue          │
    │ │   └── Create issue if not duplicate      │
    │ ├──────────────────────────────────────────┤
    │ │ todo-scanner-agent (FIXME at file2.c:100)│
    │ │   └── ...                                 │
    │ └──────────────────────────────────────────┘
    ▼
Phase T3: Report
    │ Aggregate results
    │ Write <folder>/TODO_ANALYSIS.md
    ▼
Done
```

## PHASE T1: TODO Discovery

**Goal**: Find all TODO/FIXME/HACK/XXX/NOTE comments in the target directory.

### Steps

1. **Scan for TODO patterns** using Bash with `rg`:
   ```bash
   rg "(TODO|FIXME|HACK|XXX|NOTE)" <directory> -n -g "*.c" -g "*.h"
   ```

   This is more reliable than the Grep tool which may fail on certain directories.

2. **Parse results** into structured findings:
   - File path
   - Line number
   - Pattern type (TODO, FIXME, HACK, XXX, NOTE)
   - Comment text (everything after the pattern)

3. **CHECKPOINT**: Display findings and ask user to confirm:
   ```markdown
   ## Phase T1: TODO Discovery Complete

   Found [N] TODO comments in <directory>:

   | Pattern | Count |
   |---------|-------|
   | TODO    | 5     |
   | FIXME   | 3     |
   | HACK    | 1     |
   | XXX     | 0     |
   | NOTE    | 2     |

   **Total**: 11 TODOs found

   **Proceed with issue creation?** ([N] issues will be created after deduplication)
   ```

## PHASE T2: Per-TODO Processing

**Goal**: Spawn agents to check for duplicates and create issues.

### CRITICAL: Parallel Execution

**Spawn one `todo-scanner-agent` per TODO finding, ALL IN A SINGLE MESSAGE.**

### Task Invocations

For each TODO finding, spawn:

```
Task:
  subagent_type: todo-scanner-agent
  run_in_background: true
  prompt: |
    Process this TODO comment and create a GitHub issue if not duplicate:

    File: [FILEPATH]
    Line: [LINE_NUMBER]
    Pattern: [TODO|FIXME|HACK|XXX|NOTE]
    Comment: [COMMENT_TEXT]
    Repository: 7etsuo/tetsuo-socket

    Your workflow:
    1. Read surrounding context (5 lines before/after)
    2. Check for duplicate issues using: gh issue list --search "FILEPATH:LINE or COMMENT_TEXT"
    3. If duplicate found, return SKIPPED with existing issue number
    4. If no duplicate, create the issue directly using gh issue create
    5. Return result: CREATED (with URL) or SKIPPED (with reason)
```

### Batching Strategy

If more than 50 TODOs found:
1. Split into batches of 20
2. Ask user: "Found [N] TODOs. Process in batches of 20?"
3. Run each batch, wait for completion
4. Aggregate results across batches

### Collecting Results

Wait for all agents to complete using `TaskOutput` with blocking.

Each agent returns:
- Status: CREATED or SKIPPED
- Issue URL (if created)
- Existing issue # (if duplicate)
- Pattern type and file location

## PHASE T3: TODO Report Generation

**Goal**: Aggregate results into a comprehensive TODO report.

### Report Location

Save to: `<directory>/TODO_ANALYSIS.md`

### Report Template

```markdown
# TODO Analysis Report

**Generated**: [timestamp]
**Directory**: <directory>
**TODOs Found**: [count]

## Summary

| Pattern | Found | Created | Duplicates |
|---------|-------|---------|------------|
| TODO    | 5     | 4       | 1          |
| FIXME   | 3     | 3       | 0          |
| HACK    | 1     | 0       | 1          |
| XXX     | 0     | 0       | 0          |
| NOTE    | 2     | 2       | 0          |
| **Total** | **11** | **9** | **2**     |

## Issues Created

| Issue # | Pattern | File:Line | Description |
|---------|---------|-----------|-------------|
| #500 | TODO | socket.c:42 | implement feature X |
| #501 | FIXME | buf.c:100 | broken parsing |
| #502 | NOTE | dns.c:200 | edge case handling |

## Duplicates Skipped

| Pattern | File:Line | Existing Issue | Comment |
|---------|-----------|----------------|---------|
| TODO | socket.c:200 | #123 | old feature request |
| HACK | dns.c:50 | #456 | known workaround |

---
*Report generated by /pipeline todo*
```

### Final Output

```markdown
## Phase T3: TODO Report Complete

Report saved to: <directory>/TODO_ANALYSIS.md

### Summary
- TODOs found: [N]
- Issues created: [N]
- Duplicates skipped: [N]

### Issue Links

- #500: todo(socket): implement feature X
- #501: fixme(http): broken parsing
- #502: note(dns): edge case handling

**TODO pipeline complete.**
```

---

# REFACTOR MODE

Analyze code for readability improvements focusing on:
1. **Nested if statements** that should be flattened to guard clauses
2. **Single-use subroutines** that are candidates for inlining

**Creates GitHub issues for all verified findings.**

## Refactor Mode Architecture

```
/pipeline src/socket/SocketHTTP2.c refactor
    │
    ▼
Phase R1: Discovery
    │ Identify target files (.c/.h)
    │ Can be single file or directory
    ▼
Phase R2: Per-File Pipeline (parallel agents)
    │ ┌──────────────────────────────────────────────────────┐
    │ │ per-file-pipeline-agent (file1.c)                   │
    │ │   ├── Analyze file for readability issues            │
    │ │   ├── Spawn issue-verifier-agent per finding        │
    │ │   └── Spawn pipeline-issue-writer for verified      │
    │ ├──────────────────────────────────────────────────────┤
    │ │ per-file-pipeline-agent (file2.c)                   │
    │ │   └── ...                                            │
    │ └──────────────────────────────────────────────────────┘
    ▼
Phase R3: Report
    │ Aggregate findings
    │ List created GitHub issues
    ▼
Done
```

## PHASE R1: Discovery

**Goal**: Identify files to analyze for readability issues.

### Steps

1. **Check if input is file or directory**:
   - If file: analyze that single file
   - If directory: scan for all .c files recursively

2. **For directories, use Glob**:
   ```
   Glob pattern: <directory>/**/*.c
   ```

3. **CHECKPOINT**: Display files and confirm:
   ```markdown
   ## Phase R1: Discovery Complete

   Target: <path>
   Files to analyze: [N]

   - src/http/SocketHTTP2.c (1500 lines)
   - src/http/SocketHTTP2-frames.c (800 lines)
   ...

   **Proceed with readability analysis?** ([N] per-file-pipeline-agents will be spawned)
   ```

## PHASE R2: Per-File Pipeline Agents

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
    Run READABILITY-FOCUSED analysis pipeline for this file:

    File: [FILEPATH]
    Repository: 7etsuo/tetsuo-socket
    Analysis Type: REFACTOR (readability issues only)

    Focus ONLY on these two issue types:

    1. NESTED IF STATEMENTS (3+ depth)
       - Find deeply nested conditionals (if/else chains)
       - Severity: CRITICAL (5+ depth), HIGH (4 depth), MEDIUM (3 depth)
       - Pattern: DEEP_NESTING_[depth]
       - Recommendation: Flatten with guard clauses/early returns

    2. SINGLE-USE SUBROUTINES
       - Find static functions called exactly once
       - Severity: HIGH (<30 lines, inline candidate), MEDIUM (30-100 lines, review needed)
       - Pattern: SINGLE_USE_INLINE or SINGLE_USE_REVIEW
       - Recommendation: Inline small functions, document justification for larger ones

    Your workflow:
    1. Analyze the file for ONLY the above readability issues
    2. For EACH finding, spawn an issue-verifier-agent to verify it
    3. For each VERIFIED finding, spawn a pipeline-issue-writer to create a GitHub issue
       - Issue title format: "refactor(<module>): <description>"
       - Label: "refactor", "readability"
    4. Return a summary of:
       - Issues found (nested ifs + single-use functions)
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
- Count of readability issues found
- Count verified vs rejected
- GitHub issue URLs created
- Any manual review items

## PHASE R3: Report Generation

**Goal**: Aggregate results from all per-file agents into a comprehensive report.

### Report Location

Save to: `<target>/REFACTOR_ANALYSIS.md`

### Report Template

```markdown
# Refactor Analysis Report

**Generated**: [timestamp]
**Target**: <path>
**Files Analyzed**: [count]

## Executive Summary

- **Files Analyzed**: [count]
- **Readability Issues Found**: [count]
- **Verified Issues**: [count]
- **False Positives Filtered**: [count]
- **GitHub Issues Created**: [count]

## Issues Created by Category

### Nested If Statements ([count])

| Issue # | File:Lines | Depth | Severity |
|---------|------------|-------|----------|
| #200 | SocketHTTP2.c:100-180 | 5 | CRITICAL |
| #201 | SocketHTTP2.c:300-350 | 4 | HIGH |

### Single-Use Subroutines ([count])

| Issue # | File | Function | Lines | Severity |
|---------|------|----------|-------|----------|
| #202 | SocketHTTP2.c | parse_value | 12 | HIGH (inline) |
| #203 | SocketHTTP2.c | process_block | 45 | MEDIUM (review) |

## Per-File Breakdown

| File | Found | Verified | Rejected | Issues Created |
|------|-------|----------|----------|----------------|
| SocketHTTP2.c | 5 | 4 | 1 | #200, #201, #202 |
| SocketHTTP2-frame.c | 2 | 2 | 0 | #203, #204 |

## False Positives Filtered

| File | Line | Pattern | Reason |
|------|------|---------|--------|
| file.c | 100 | DEEP_NESTING | Switch statement, intentional |

---
*Report generated by /pipeline refactor*
```

### Final Output

```markdown
## Phase R3: Report Complete

Analysis report saved to: <target>/REFACTOR_ANALYSIS.md

### Summary
- Files analyzed: [N]
- GitHub issues created: [N]
- False positives filtered: [N]

### Issue Links

- #200: refactor(http2): Flatten 5-level nesting in process_frame
- #201: refactor(http2): Flatten 4-level nesting in validate_headers
- #202: refactor(http2): Inline single-use parse_value function

**Refactor pipeline complete.**
```

---

# CODE ANALYSIS MODE (Default)

The original multi-agent code analysis pipeline for security, redundancy, and refactoring issues.

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
