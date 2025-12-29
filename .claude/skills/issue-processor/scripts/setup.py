#!/usr/bin/env python3
"""
Fetch issues from GitHub, parse dependencies, build graph, find ready frontier.

Usage:
    python setup.py --repo OWNER/REPO [--label LABEL] [--max N] [--state-dir DIR]

Outputs:
    - manifest.json: Checkpoint file with run metadata
    - graph.json: Dependency graph
    - frontier.json: Ready and blocked issues
    - issues/*.json: Individual issue details
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from utils import (
    run_gh as utils_run_gh,
    run_git,
    save_json,
    validate_repo_format,
    log_info,
    log_warning,
    log_error,
    GitHubAPIError,
    ValidationError,
)


def run_gh(args: list[str]) -> dict:
    """Run gh CLI command and return parsed JSON."""
    try:
        success, output = utils_run_gh(args, check=False)
        if not success:
            log_error(f"gh {' '.join(args[:2])}: {output}")
            sys.exit(1)
        return json.loads(output) if output.strip() else {}
    except json.JSONDecodeError:
        # Some commands return non-JSON output
        return {"_raw": output}


def fetch_issues(owner: str, repo: str, label: str | None = None) -> list[dict]:
    """Fetch all open issues from repository."""
    issues = []
    cursor = None

    while True:
        # Build GraphQL query
        label_filter = f', labels: ["{label}"]' if label else ""
        cursor_arg = f', after: "{cursor}"' if cursor else ""

        query = f'''
        query {{
          repository(owner: "{owner}", name: "{repo}") {{
            issues(first: 100, states: OPEN{label_filter}{cursor_arg}) {{
              pageInfo {{ hasNextPage endCursor }}
              nodes {{
                number
                title
                body
                labels(first: 10) {{ nodes {{ name }} }}
                state
              }}
            }}
          }}
        }}
        '''

        result = run_gh(["api", "graphql", "-f", f"query={query}"])

        page = result.get("data", {}).get("repository", {}).get("issues", {})
        nodes = page.get("nodes", [])

        for node in nodes:
            issues.append({
                "number": node["number"],
                "title": node["title"],
                "body": node.get("body") or "",
                "labels": [l["name"] for l in node.get("labels", {}).get("nodes", [])],
                "state": node["state"]
            })

        if not page.get("pageInfo", {}).get("hasNextPage"):
            break
        cursor = page["pageInfo"]["endCursor"]

    return issues


def fetch_closed_issues(owner: str, repo: str, issue_numbers: set[int]) -> set[int]:
    """Check which issue numbers are closed."""
    if not issue_numbers:
        return set()

    closed = set()

    # Batch check in groups of 20
    numbers_list = list(issue_numbers)
    for i in range(0, len(numbers_list), 20):
        batch = numbers_list[i:i+20]

        # Build query to check multiple issues at once
        queries = []
        for num in batch:
            queries.append(f'issue{num}: issue(number: {num}) {{ number state }}')

        query = f'''
        query {{
          repository(owner: "{owner}", name: "{repo}") {{
            {" ".join(queries)}
          }}
        }}
        '''

        try:
            result = run_gh(["api", "graphql", "-f", f"query={query}"])
            repo_data = result.get("data", {}).get("repository", {})

            for key, value in repo_data.items():
                if value and value.get("state") == "CLOSED":
                    closed.add(value["number"])
        except Exception as e:
            # If batch fails, check individually using REST API
            log_warning(f"Batch query failed ({e}), checking issues individually")
            for num in batch:
                try:
                    # Use REST API to get issue state
                    result = run_gh(["api", f"repos/{owner}/{repo}/issues/{num}"])
                    # result is a dict with "state" field
                    if result.get("state") == "closed":
                        closed.add(num)
                except Exception:
                    # Issue might not exist or API error - skip silently
                    pass

    return closed


def parse_dependencies(body: str) -> list[int]:
    """Extract issue dependencies from body text."""
    deps = set()

    # Pattern 1: "Blocked by #N" or "Blocked by: #N"
    for match in re.finditer(r'blocked\s+by[:\s]+#(\d+)', body, re.IGNORECASE):
        deps.add(int(match.group(1)))

    # Pattern 2: "Depends on #N"
    for match in re.finditer(r'depends\s+on[:\s]+#(\d+)', body, re.IGNORECASE):
        deps.add(int(match.group(1)))

    # Pattern 3: "Requires #N"
    for match in re.finditer(r'requires[:\s]+#(\d+)', body, re.IGNORECASE):
        deps.add(int(match.group(1)))

    # Pattern 4: "After #N"
    for match in re.finditer(r'after[:\s]+#(\d+)', body, re.IGNORECASE):
        deps.add(int(match.group(1)))

    # Pattern 5: Dependencies section with checkboxes "- [ ] #N" or "- [x] #N"
    deps_section = re.search(r'##\s*Dependencies(.*?)(?=##|$)', body, re.IGNORECASE | re.DOTALL)
    if deps_section:
        for match in re.finditer(r'-\s*\[[x ]\]\s*#(\d+)', deps_section.group(1), re.IGNORECASE):
            deps.add(int(match.group(1)))

    # Pattern 6: Simple "#N" references in a "Blocked by" line
    for line in body.split('\n'):
        if re.search(r'blocked|depends|requires', line, re.IGNORECASE):
            for match in re.finditer(r'#(\d+)', line):
                deps.add(int(match.group(1)))

    return sorted(deps)


def build_graph(issues: list[dict], closed_issues: set[int]) -> dict:
    """Build dependency graph from issues."""
    graph = {}
    all_deps = set()

    for issue in issues:
        deps = parse_dependencies(issue["body"])
        all_deps.update(deps)

        # Determine which deps are satisfied (closed)
        satisfied = [d for d in deps if d in closed_issues]
        unsatisfied = [d for d in deps if d not in closed_issues]

        graph[issue["number"]] = {
            "deps": deps,
            "satisfied": satisfied,
            "unsatisfied": unsatisfied
        }

    return graph


def find_frontier(graph: dict) -> tuple[list[int], dict[int, list[int]]]:
    """Find ready frontier (no unsatisfied deps) and blocked issues."""
    ready = []
    blocked = {}

    for issue_num, info in graph.items():
        if not info["unsatisfied"]:
            ready.append(issue_num)
        else:
            blocked[issue_num] = info["unsatisfied"]

    return sorted(ready), blocked


def has_wip_label(issue: dict) -> bool:
    """Check if issue has a work-in-progress label (wip:*)."""
    for label in issue.get("labels", []):
        if label.startswith("wip:"):
            return True
    return False


def filter_claimed_issues(issues: list[dict], ready: list[int]) -> tuple[list[int], list[int]]:
    """
    Filter out issues that are already claimed by another instance.

    Args:
        issues: List of issue dicts with labels
        ready: List of issue numbers that are ready

    Returns:
        Tuple of (available issues, claimed issues)
    """
    issue_map = {i["number"]: i for i in issues}
    available = []
    claimed = []

    for num in ready:
        issue = issue_map.get(num)
        if issue and has_wip_label(issue):
            claimed.append(num)
        else:
            available.append(num)

    return available, claimed


def run_git(args: list[str], cwd: str | None = None) -> tuple[bool, str]:
    """Run git command and return (success, output)."""
    result = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        cwd=cwd
    )
    return result.returncode == 0, result.stdout.strip() or result.stderr.strip()


def get_repo_root() -> Path:
    """Get the git repository root directory."""
    success, output = run_git(["rev-parse", "--show-toplevel"])
    if not success:
        return None
    return Path(output)


def create_worktrees(ready_issues: list[int], state_dir: Path) -> dict[int, str]:
    """
    Create git worktrees for parallel issue implementation.

    Args:
        ready_issues: List of issue numbers ready for implementation
        state_dir: State directory for storing worktree info

    Returns:
        Dict mapping issue number to worktree path
    """
    repo_root = get_repo_root()
    if not repo_root:
        print("Warning: Not in a git repository, skipping worktree creation", file=sys.stderr)
        return {}

    worktrees = {}

    # Fetch latest from origin
    run_git(["fetch", "origin"], cwd=str(repo_root))

    for issue_num in ready_issues:
        branch_name = f"issue-{issue_num}"
        worktree_dir = repo_root.parent / f"{repo_root.name}-issue-{issue_num}"

        # Skip if worktree already exists
        if worktree_dir.exists():
            worktrees[issue_num] = str(worktree_dir)
            continue

        # Create worktree with new branch from origin/main
        success, output = run_git(
            ["worktree", "add", str(worktree_dir), "-b", branch_name, "origin/main"],
            cwd=str(repo_root)
        )

        if not success:
            # Branch might already exist, try without -b
            success, output = run_git(
                ["worktree", "add", str(worktree_dir), branch_name],
                cwd=str(repo_root)
            )

        if success:
            worktrees[issue_num] = str(worktree_dir)
            print(f"Created worktree for #{issue_num}: {worktree_dir}", file=sys.stderr)
        else:
            print(f"Warning: Failed to create worktree for #{issue_num}: {output}", file=sys.stderr)

    # Save worktree mapping (atomic write)
    save_json(state_dir / "worktrees.json", worktrees)

    return worktrees


def main():
    parser = argparse.ArgumentParser(description="Setup issue processing pipeline")
    parser.add_argument("--repo", required=True, help="Repository (owner/repo)")
    parser.add_argument("--label", help="Filter by label")
    parser.add_argument("--max", type=int, help="Maximum issues to process")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--create-worktrees", action="store_true",
                        help="Create git worktrees for ready issues")
    args = parser.parse_args()

    # Validate repo format
    try:
        owner, repo = validate_repo_format(args.repo)
    except ValidationError as e:
        log_error(str(e))
        sys.exit(1)

    state_dir = Path(args.state_dir)

    # Create directories
    (state_dir / "issues").mkdir(parents=True, exist_ok=True)
    (state_dir / "results").mkdir(parents=True, exist_ok=True)

    print(f"Fetching issues from {args.repo}...", file=sys.stderr)

    # Fetch issues
    issues = fetch_issues(owner, repo, args.label)

    if not issues:
        print("No open issues found.", file=sys.stderr)
        sys.exit(0)

    print(f"Found {len(issues)} open issues", file=sys.stderr)

    # Collect all referenced dependencies
    all_deps = set()
    for issue in issues:
        deps = parse_dependencies(issue["body"])
        all_deps.update(deps)

    # Check which dependencies are satisfied (closed)
    # A dependency is satisfied when the referenced issue is CLOSED
    open_issue_nums = {i["number"] for i in issues}
    deps_to_check = all_deps - open_issue_nums  # Only check deps not in our open set

    print(f"Checking {len(deps_to_check)} external dependency references...", file=sys.stderr)
    closed_issues = fetch_closed_issues(owner, repo, deps_to_check)

    # Build graph
    graph = build_graph(issues, closed_issues)

    # Find frontier
    ready, blocked = find_frontier(graph)

    # Filter out issues already claimed by other instances (have wip:* label)
    ready, claimed = filter_claimed_issues(issues, ready)
    if claimed:
        print(f"Skipping {len(claimed)} issues claimed by other instances: {claimed}", file=sys.stderr)

    # Apply max limit to ready
    if args.max and len(ready) > args.max:
        ready = ready[:args.max]

    # Write individual issue files (using atomic writes)
    for issue in issues:
        issue_file = state_dir / "issues" / f"{issue['number']}.json"
        issue["dependencies"] = parse_dependencies(issue["body"])
        save_json(issue_file, issue)

    # Write graph
    save_json(state_dir / "graph.json", {
        "graph": {str(k): v for k, v in graph.items()},
        "closed_issues": sorted(closed_issues)
    })

    # Write frontier
    save_json(state_dir / "frontier.json", {
        "ready": ready,
        "blocked": {str(k): v for k, v in blocked.items()}
    })

    # Write manifest
    run_id = state_dir.name
    manifest = {
        "version": 1,
        "run_id": run_id,
        "repository": args.repo,
        "label_filter": args.label,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_issues": len(issues),
        "ready": ready,
        "claimed_by_others": claimed,
        "completed": [],
        "failed": [],
        "in_progress": []
    }
    save_json(state_dir / "manifest.json", manifest)

    # Write initial status
    (state_dir / "status.txt").write_text(f"READY:{len(ready)}/{len(issues)}\n")

    # Create worktrees if requested
    worktrees = {}
    if args.create_worktrees and ready:
        print(f"Creating worktrees for {len(ready)} ready issues...", file=sys.stderr)
        worktrees = create_worktrees(ready, state_dir)

    # Print summary (this is what the skill sees)
    print(f"Ready: {len(ready)} issues")
    print(f"Blocked: {len(blocked)} issues")
    if claimed:
        print(f"Claimed by others: {len(claimed)} issues")
    if ready:
        print(f"First ready: #{ready[0]}")
    if blocked:
        first_blocked = list(blocked.keys())[0]
        print(f"First blocked: #{first_blocked} (by {blocked[first_blocked]})")


if __name__ == "__main__":
    main()
