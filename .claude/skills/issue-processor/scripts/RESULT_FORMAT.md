# Result File Format

This document describes the JSON format for issue implementation results.

## Location

Results are written to: `{state_dir}/results/{issue_number}.json`

## Success Format

```json
{
    "issue": 391,
    "status": "success",
    "pr_url": "https://github.com/owner/repo/pull/123",
    "pr_number": 123,
    "branch": "issue-391-feature-name",
    "commits": 3,
    "files_changed": 5,
    "completed_at": "2025-01-15T10:30:00Z"
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `issue` | int | The GitHub issue number |
| `status` | string | Must be `"success"` |
| `pr_url` | string | Full URL to the created pull request |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `pr_number` | int | PR number (extracted from URL if not provided) |
| `branch` | string | Branch name used for the implementation |
| `commits` | int | Number of commits in the PR |
| `files_changed` | int | Number of files modified |
| `completed_at` | string | ISO 8601 timestamp |

## Already Resolved Format

Use this when you discover the issue doesn't need implementation (feature already exists,
issue is stale, etc.):

```json
{
    "issue": 393,
    "status": "already_resolved",
    "resolution": "Feature already implemented in src/quic/frame.c at line 245"
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `issue` | int | The GitHub issue number |
| `status` | string | Must be `"already_resolved"` |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `resolution` | string | Explanation of why no action was needed |

This status is treated as "completed" (not failed) in the pipeline.

## Failure Format

```json
{
    "issue": 392,
    "status": "failed",
    "error": "Build failed: undefined reference to SocketPool_drain",
    "stage": "build",
    "branch": "issue-392-fix-pool",
    "failed_at": "2025-01-15T10:35:00Z"
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `issue` | int | The GitHub issue number |
| `status` | string | Must be `"failed"` |
| `error` | string | Human-readable error description (max 100 chars recommended) |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `stage` | string | Where failure occurred: `checkout`, `implement`, `build`, `test`, `commit`, `push`, `pr` |
| `branch` | string | Branch name (for cleanup) |
| `failed_at` | string | ISO 8601 timestamp |

## Writing Results

The issue-implementer agent should write results atomically:

```python
import json
from pathlib import Path

def write_result(state_dir: Path, issue_num: int, result: dict):
    result_file = state_dir / "results" / f"{issue_num}.json"
    tmp_file = result_file.with_suffix('.tmp')

    with open(tmp_file, 'w') as f:
        json.dump(result, f, indent=2)
    tmp_file.rename(result_file)
```

## Example: Minimal Success

```json
{
    "issue": 400,
    "status": "success",
    "pr_url": "https://github.com/7etsuo/tetsuo-socket/pull/450"
}
```

## Example: Minimal Failure

```json
{
    "issue": 401,
    "status": "failed",
    "error": "Tests timeout after 5 minutes"
}
```
