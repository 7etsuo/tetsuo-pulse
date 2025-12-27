# Code Analysis Pipeline

Multi-agent code analysis pipeline for C codebases. Orchestrates parallel security, redundancy, and refactoring analysis with consolidation and fix application.

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

## Pipeline Phases

This pipeline executes in 5 phases with checkpoints for user confirmation.

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

3. **Batch if needed**: If more than 30 files, split into batches of 10-15 files each for analysis

4. **CHECKPOINT**: Display file list and ask user to confirm analysis targets

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

**Proceed with analysis?** (Files will be analyzed in [N] batch(es))
```

---

## PHASE 2: Parallel Analysis

**Goal**: Run security, redundancy, and refactoring analysis IN PARALLEL.

### CRITICAL: Parallel Execution

**YOU MUST spawn all 3 agents in a SINGLE message with 3 Task tool calls.**

Do NOT:
- Run agents sequentially
- Analyze files yourself without agents
- Call one Task, wait, then call another

DO:
- Send one message with exactly 3 Task tool invocations
- Wait for all 3 to complete
- Collect results from each

### Task Invocations

In a single message, invoke these 3 tasks:

```
Task 1 (security-agent):
  subagent_type: security-agent
  prompt: |
    Analyze these C source files for security vulnerabilities:

    Files:
    [list all .c and .h files]

    Focus on:
    - Buffer overflows and unsafe functions
    - Integer overflows in allocations
    - Input validation gaps
    - Injection risks
    - Race conditions
    - Memory safety issues

    Return structured findings in the format specified in your instructions.

Task 2 (redundancy-agent):
  subagent_type: redundancy-agent
  prompt: |
    Find code duplication in these C source files:

    Files:
    [list all .c and .h files]

    Focus on:
    - Re-implemented helper functions (check against SocketUtil, SocketCrypto, etc.)
    - Duplicate code blocks across files
    - Repeated magic numbers
    - Copy-pasted patterns

    Return structured findings in the format specified in your instructions.

Task 3 (refactor-agent):
  subagent_type: refactor-agent
  prompt: |
    Identify refactoring opportunities in these C source files:

    Files:
    [list all .c and .h files]

    Focus on:
    - Long functions (>50 lines)
    - Magic numbers needing constants
    - Style violations
    - Naming issues
    - Missing error handling
    - Complex conditionals

    Return structured findings in the format specified in your instructions.
```

### Collecting Results

After all 3 tasks complete, collect their outputs. Each agent returns markdown-formatted findings.

---

## PHASE 3: Consolidation

**Goal**: Analyze cross-file patterns and determine extraction candidates.

### Steps

1. **Parse all agent outputs** into structured findings

2. **Cross-reference findings**:
   - Security issues that redundancy also flagged (duplicated unsafe code)
   - Magic numbers appearing in redundancy AND refactor findings
   - Patterns that multiple agents identified

3. **Apply consolidation skill logic**:
   - Use the decision framework from `.claude/skills/consolidation/SKILL.md`
   - Determine what to extract vs keep inline
   - Identify target locations for extracted code

4. **Generate consolidated plan**:
   - Group findings by file
   - Prioritize by severity
   - Create actionable fix list

5. **CHECKPOINT**: Present consolidated findings and extraction plan

### Output

```markdown
## Phase 3: Consolidation Complete

### Cross-File Patterns Identified

1. **[Pattern Name]**
   - Files: [list]
   - Type: constant/function/pattern
   - Recommendation: Extract to [location]

### Fixes by File

#### path/to/file1.c
| Priority | Category | Issue | Fix |
|----------|----------|-------|-----|
| CRITICAL | Security | Buffer overflow at line 42 | Use strncpy with bounds |
| HIGH | Redundancy | Magic number 4096 | Use SOCKET_BUFFER_SIZE constant |

#### path/to/file2.c
...

### Extraction Plan

| Target | New Location | Files Affected |
|--------|--------------|----------------|
| BUFFER_SIZE = 4096 | SocketConfig.h | file1.c, file2.c, file3.c |
| validate_port() | SocketCommon.h | file1.c, file4.c |

**Proceed with applying fixes?**
```

---

## PHASE 4: Apply Fixes

**Goal**: Apply fixes to each file with user confirmation.

### Steps

1. **For each file** with fixes:

   a. **Show proposed changes**:
      ```markdown
      ### Fixing: path/to/file.c

      **Changes to apply:**
      1. Line 42: Replace `strcpy(dst, src)` with `strncpy(dst, src, sizeof(dst)-1)`
      2. Line 100: Replace `4096` with `SOCKET_BUFFER_SIZE`
      3. Line 150: Add include for SocketConfig.h

      **Apply these changes?** [Yes/No/Skip file]
      ```

   b. **Wait for user confirmation**

   c. **Apply using Edit tool** if approved

   d. **Hooks auto-run**: `build-check.sh` verifies syntax, `volatile-check.sh` checks exception safety

2. **For extracted code** (new constants/functions):

   a. Show what will be added to target files (SocketConfig.h, etc.)
   b. Get confirmation
   c. Apply additions

3. **Track results**:
   - Files modified
   - Changes applied
   - Changes skipped

---

## PHASE 5: Report Generation

**Goal**: Generate comprehensive analysis report.

### Report Location

Save to: `<directory>/ANALYSIS_REPORT.md`

### Report Template

```markdown
# Code Analysis Report

**Generated**: [timestamp]
**Directory**: <directory>
**Files Analyzed**: [count]

## Executive Summary

- **Security Issues**: [count] (CRITICAL: X, HIGH: Y, MEDIUM: Z)
- **Redundancies**: [count] (estimated [N] lines saveable)
- **Refactoring Opportunities**: [count]
- **Fixes Applied**: [count]
- **Fixes Skipped**: [count]

## Security Analysis

### Critical Issues
[findings from security-agent, CRITICAL severity]

### High Priority Issues
[findings from security-agent, HIGH severity]

### Other Issues
[remaining security findings]

## Redundancy Analysis

### Code Duplication
[findings from redundancy-agent]

### Consolidation Actions Taken
[what was extracted, where]

## Refactoring Analysis

### Priority Improvements
[HIGH priority findings from refactor-agent]

### Style and Naming
[MEDIUM/LOW findings]

## Changes Applied

### Files Modified
| File | Changes |
|------|---------|
| path/file.c | [list of changes] |

### Code Extracted
| Item | Location |
|------|----------|
| BUFFER_SIZE constant | SocketConfig.h |

## Remaining Items

### Not Applied (User Skipped)
[list of skipped fixes with reasons]

### Manual Review Recommended
[issues that need human judgment]

---
*Report generated by /pipeline command*
```

### Final Output

```markdown
## Phase 5: Report Complete

Analysis report saved to: <directory>/ANALYSIS_REPORT.md

### Summary
- Files analyzed: [N]
- Issues found: [N]
- Fixes applied: [N]
- Fixes skipped: [N]

**Pipeline complete.**
```

---

## Batching Strategy

When analyzing >30 files:

1. **Split files into batches** of 10-15 files each
2. **Run Phase 2 for each batch** (3 parallel agents per batch)
3. **Accumulate results** across batches
4. **Single Phase 3-5** consolidation and fix application

This prevents context overflow while maintaining parallelism within batches.

---

## Error Handling

- **Agent timeout**: If any agent takes >5 minutes, report partial results and continue
- **Parse errors**: If agent output doesn't match expected format, include raw output in report
- **Fix failures**: If Edit tool fails (syntax check), rollback and note in report
- **Missing files**: If referenced file doesn't exist, skip and note

---

## Example Session

```
User: /pipeline src/core/

Claude: [Executes Phase 1 - Discovery]

## Phase 1: Discovery Complete

Found 12 source files in src/core/:

### C Files (8)
- src/core/Arena.c
- src/core/Except.c
- src/core/SocketCrypto.c
- src/core/SocketRateLimit.c
- src/core/SocketTimer.c
- src/core/SocketUTF8.c
- src/core/SocketUtil.c
- src/core/SocketSecurity.c

### Header Files (4)
- include/core/Arena.h
- include/core/Except.h
- include/core/SocketConfig.h
- include/core/SocketUtil.h

**Proceed with analysis?** (Files will be analyzed in 1 batch)

User: Yes

Claude: [Spawns 3 Task agents IN PARALLEL - security-agent, redundancy-agent, refactor-agent]
        [Waits for all 3 to complete]
        [Executes Phase 3 - Consolidation]
        [Presents consolidated findings]
        [Asks for fix confirmation]

User: Apply all

Claude: [Executes Phase 4 - Applies fixes with Edit tool]
        [Executes Phase 5 - Generates report]

Analysis report saved to: src/core/ANALYSIS_REPORT.md
```

---

## Notes

- This command orchestrates multiple specialized agents
- Each agent focuses on one dimension of code quality
- Parallel execution significantly speeds up analysis
- Interactive confirmation prevents unwanted changes
- The consolidation skill provides extraction decision logic
- Existing hooks (build-check.sh, volatile-check.sh) validate changes