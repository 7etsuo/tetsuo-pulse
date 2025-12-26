---
name: issue-processor
description: Dependency-Aware Parallel Issue Processor. Scans issue backlog, builds dependency graph, identifies ready frontier, and spawns parallel agents to implement unblocked issues. Breadth-first fork-join pattern.
---

# Dependency-Aware Parallel Issue Processor

Process GitHub issues in dependency-aware parallel batches using breadth-first execution.

## Activation

This skill activates when:
- User mentions "process issues", "implement backlog", or "parallel issues"
- User wants to implement multiple GitHub issues
- User asks to "work on ready issues" or "unblocked issues"
- User mentions "issue frontier" or "dependency wave"

## Concepts

| Term | Description |
|------|-------------|
| **Dependency Graph** | DAG where edges represent "blocks" relationships |
| **Ready Frontier** | Issues with all dependencies resolved (closed/merged) |
| **Breadth-First** | Only process current depth level per run |
| **Fork-Join** | Spawn parallel workers, await completion, repeat |

## Pipeline Overview

```
Issue Backlog → Fetch Issues → Build DAG → Find Frontier → Parallel Implement
      ↓              ↓            ↓             ↓               ↓
   GitHub API   Parse bodies   Add edges   Filter ready    Spawn agents
               for "blocked by"           (deps closed)    (max 10)
```

## Phase 1: Fetch Issues

Fetch all open issues from the repository with their body text.

### GraphQL Query

Use `gh api graphql` to fetch issues efficiently:

```bash
gh api graphql -f query='
query($owner: String!, $repo: String!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    issues(first: 100, states: OPEN, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        title
        body
        labels(first: 10) { nodes { name } }
        state
      }
    }
  }
}' -f owner=7etsuo -f repo=tetsuo-socket
```

### Pagination

If `hasNextPage` is true, fetch more with the `endCursor`:
```bash
-f cursor="<endCursor>"
```

### Output: Issue List

```json
{
  "issues": [
    {
      "number": 391,
      "title": "feat(quic): implement NEW_TOKEN frame",
      "body": "...\n\n## Dependencies\n- Blocked by #388\n...",
      "labels": ["enhancement", "quic"],
      "state": "OPEN"
    }
  ]
}
```

## Phase 2: Build Dependency Graph

Parse issue bodies to extract dependency relationships.

### Dependency Patterns

Look for these patterns in issue bodies (case-insensitive):

| Pattern | Meaning |
|---------|---------|
| `Blocked by #N` | This issue depends on #N |
| `Depends on #N` | This issue depends on #N |
| `Requires #N` | This issue depends on #N |
| `After #N` | This issue depends on #N |
| `- [ ] #N` (in Dependencies section) | This issue depends on #N |

### Parsing Algorithm

```
for each issue:
    dependencies = []

    # Pattern 1: "Blocked by #N, #M"
    match = regex("blocked by #(\\d+)", body, case_insensitive)
    dependencies.extend(match.groups)

    # Pattern 2: "Depends on #N"
    match = regex("depends on #(\\d+)", body, case_insensitive)
    dependencies.extend(match.groups)

    # Pattern 3: Dependencies section with checkboxes
    if "## Dependencies" in body:
        section = extract_section("Dependencies", body)
        match = regex("- \\[[ x]\\] #(\\d+)", section)
        dependencies.extend(match.groups)

    graph[issue.number] = dependencies
```

### Verify Dependencies Exist

For each dependency:
1. Check if it's a valid issue number (exists)
2. Check its state (OPEN or CLOSED)
3. Track closed dependencies as "satisfied"

```bash
# Check if issue is closed
gh issue view N --json state --jq '.state'
```

### Output: Dependency Graph

```json
{
  "graph": {
    "391": {"deps": [388], "satisfied": [388]},
    "392": {"deps": [388], "satisfied": [388]},
    "393": {"deps": [392], "satisfied": []},
    "394": {"deps": [], "satisfied": []}
  },
  "closed_issues": [388, 389, 390]
}
```

## Phase 3: Identify Ready Frontier

The ready frontier contains issues where ALL dependencies are satisfied.

### Algorithm

```
ready_frontier = []

for issue_num, deps_info in graph:
    unsatisfied = deps_info.deps - deps_info.satisfied
    if unsatisfied is empty:
        ready_frontier.append(issue_num)
    else:
        # Log what's blocking this issue
        log(f"Issue #{issue_num} blocked by: {unsatisfied}")

sort(ready_frontier, by=issue_number)  # Process in order
```

### Example

```
Graph state:
  #388 (closed)
   ├── #391 (open, deps: [388]) → deps satisfied → READY
   ├── #392 (open, deps: [388]) → deps satisfied → READY
   └── #393 (open, deps: [392]) → deps NOT satisfied → BLOCKED

Ready frontier: [#391, #392]
Next wave (after #392 closes): [#393]
```

### Output

```json
{
  "ready": [391, 392, 394, 398, 399, 400, 401],
  "blocked": {
    "393": [392],
    "395": [394],
    "396": [395]
  }
}
```

## Phase 4: Parallel Implementation

Spawn agents to implement ready issues. Use fork-join pattern.

### Batching Strategy

- Maximum 5 concurrent agents (to avoid overwhelming the system)
- Process ready frontier in batches
- Wait for batch completion before reporting

### Spawning Implementation Agents

For each ready issue, use the Task tool:

```
Task tool:
  subagent_type: "general-purpose"
  description: "Implement issue #391"
  prompt: |
    You are implementing GitHub issue #391 for the tetsuo-socket C library.

    ## Issue Details

    **Title**: feat(quic): implement NEW_TOKEN frame (RFC 9000 §19.7)
    **Number**: 391
    **Repository**: 7etsuo/tetsuo-socket

    **Body**:
    """
    [full issue body here]
    """

    ## Instructions

    1. First, invoke /git-workflow to set up proper branch for this issue
    2. Read the related RFC section and existing code patterns
    3. Implement the feature following project conventions:
       - Arena-based memory management
       - Exception-based error handling (TRY/EXCEPT/FINALLY)
       - Functions under 20 lines
       - Doxygen documentation
    4. Add tests in src/test/
    5. Ensure build passes with sanitizers
    6. Commit with proper message format
    7. Create PR linking to issue #391

    Return the PR URL when complete, or a summary of what was done.
  run_in_background: true
```

### Collect Results

Use TaskOutput to collect all agent results:

```
TaskOutput tool:
  task_id: [from Task result]
  block: true
```

### Aggregate Results

```json
{
  "completed": [
    {"issue": 391, "pr": "https://github.com/7etsuo/tetsuo-socket/pull/420"},
    {"issue": 392, "pr": "https://github.com/7etsuo/tetsuo-socket/pull/421"}
  ],
  "failed": [
    {"issue": 394, "error": "Build failed with sanitizer errors"}
  ]
}
```

## Phase 5: Report Results

After all agents complete, summarize:

### Success Report

```
## Issue Processing Complete

### Ready Frontier: 7 issues
### Processed: 5 issues
### Remaining: 2 issues (hit batch limit)

### Results

| Issue | Title | Status | PR |
|-------|-------|--------|-----|
| #391 | NEW_TOKEN frame | Completed | #420 |
| #392 | STREAM frame | Completed | #421 |
| #394 | BLOCKED frames | Failed | - |

### Failures

#394 failed: Build error - test_quic_frame.c:45: undefined reference to 'Frame_encode'

### Next Steps

Run this skill again after merging PRs #420, #421 to process the next wave:
- #393 (unblocked by #392)
- #395 (unblocked by #394 - fix needed first)
```

## User Interaction

### Before Processing

Confirm with user:
1. Repository to process (default: 7etsuo/tetsuo-socket)
2. Label filter (e.g., "quic" to only process QUIC issues)
3. Maximum issues to process per run (default: 5)
4. Dry-run mode (show frontier without implementing)

### Dry-Run Mode

```
User: Process QUIC issues in dry-run mode
Assistant: Analyzing issue dependencies...

Ready Frontier (7 issues):
  #391 - NEW_TOKEN frame (no deps)
  #392 - STREAM frame (no deps)
  #394 - BLOCKED frames (no deps)
  #398 - HANDSHAKE_DONE frame (no deps)
  #399 - Stream States (no deps)
  #400 - Flow Control (no deps)
  #401 - Connection ID Operations (no deps)

Blocked (12 issues):
  #393 - MAX frames (blocked by #392)
  #395 - Connection ID frames (blocked by #394)
  ...

Run without --dry-run to implement ready issues.
```

### Label Filtering

```bash
# Fetch only issues with specific label
gh api graphql -f query='
query($owner: String!, $repo: String!, $label: String!) {
  repository(owner: $owner, name: $repo) {
    issues(first: 100, states: OPEN, labels: [$label]) {
      nodes { number title body labels { nodes { name } } }
    }
  }
}' -f owner=7etsuo -f repo=tetsuo-socket -f label=quic
```

## Error Handling

### No Ready Issues

If frontier is empty but open issues exist:
```
All open issues have unsatisfied dependencies.

Blocking chains:
  #393 ← #392 ← #391 ← #388 (OPEN - root blocker!)

Root blockers (must be closed first):
  #388 - implement Frame Format
```

### Cycle Detection

If dependency graph has cycles:
```
Dependency cycle detected!
  #100 → #101 → #102 → #100

Please resolve by editing issue bodies to break the cycle.
```

### Agent Failures

If an implementation agent fails:
1. Log the failure reason
2. Continue with other issues
3. Report failures at end
4. Suggest fixes for common issues

## Worktree Strategy

For parallel agents, each should use a separate worktree:

```
Agent for #391 → ../tetsuo-socket-issue-391
Agent for #392 → ../tetsuo-socket-issue-392
```

Instruct agents to:
1. Create worktree from origin/main
2. Implement in isolation
3. Push and create PR
4. Clean up worktree after PR created

## Example Session

```
User: /issue-processor --label quic --max 3
Assistant: I will process QUIC issues with a maximum of 3 parallel agents.

[Phase 1: Fetching 20 open QUIC issues...]
[Phase 2: Building dependency graph...]
[Phase 3: Identifying ready frontier...]

Ready Frontier: 7 issues (processing first 3)
  #391 - NEW_TOKEN frame
  #392 - STREAM frame
  #394 - BLOCKED frames

Spawning 3 implementation agents...

[Agent 1: Implementing #391...]
[Agent 2: Implementing #392...]
[Agent 3: Implementing #394...]

[Waiting for agents to complete...]

## Results

| Issue | Status | PR |
|-------|--------|-----|
| #391 | Completed | #420 |
| #392 | Completed | #421 |
| #394 | Completed | #422 |

All 3 issues implemented successfully\!

Next wave (4 issues now unblocked):
  #393 - MAX frames (was blocked by #392)
  #395 - Connection ID frames (was blocked by #394)
  ...

Run /issue-processor again after merging PRs to process the next wave.
```

## Tips for Success

1. **Start with dry-run** - Always preview the frontier before implementing
2. **Use label filters** - Focus on one component at a time (e.g., "quic")
3. **Small batches** - Start with max 2-3 until confident in the process
4. **Review PRs promptly** - Unblocks the next wave faster
5. **Fix failures early** - Failed issues may block dependents

