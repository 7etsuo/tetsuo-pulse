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
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_gh(args: list[str]) -> dict:
    """Run gh CLI command and return parsed JSON."""
    result = subprocess.run(
        ["gh"] + args,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"Error running gh: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout) if result.stdout.strip() else {}


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
        except Exception:
            # If batch fails, check individually
            for num in batch:
                try:
                    result = run_gh(["api", f"repos/{owner}/{repo}/issues/{num}", "--jq", ".state"])
                    if "closed" in str(result).lower():
                        closed.add(num)
                except Exception:
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


def main():
    parser = argparse.ArgumentParser(description="Setup issue processing pipeline")
    parser.add_argument("--repo", required=True, help="Repository (owner/repo)")
    parser.add_argument("--label", help="Filter by label")
    parser.add_argument("--max", type=int, help="Maximum issues to process")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    args = parser.parse_args()

    owner, repo = args.repo.split("/")
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

    # Check which dependencies are closed
    print(f"Checking {len(all_deps)} dependency references...", file=sys.stderr)
    open_issue_nums = {i["number"] for i in issues}
    deps_to_check = all_deps - open_issue_nums  # Only check deps that aren't in our open set
    closed_issues = fetch_closed_issues(owner, repo, deps_to_check)
    # Issues in our open set are obviously not closed
    # Issues that are closed
    closed_issues.update(deps_to_check - closed_issues)  # Wait, this is wrong

    # Actually: check which deps are satisfied
    # A dep is satisfied if it's closed
    closed_issues = fetch_closed_issues(owner, repo, all_deps)

    # Build graph
    graph = build_graph(issues, closed_issues)

    # Find frontier
    ready, blocked = find_frontier(graph)

    # Apply max limit to ready
    if args.max and len(ready) > args.max:
        ready = ready[:args.max]

    # Write individual issue files
    for issue in issues:
        issue_file = state_dir / "issues" / f"{issue['number']}.json"
        issue["dependencies"] = parse_dependencies(issue["body"])
        with open(issue_file, "w") as f:
            json.dump(issue, f, indent=2)

    # Write graph
    with open(state_dir / "graph.json", "w") as f:
        json.dump({
            "graph": {str(k): v for k, v in graph.items()},
            "closed_issues": sorted(closed_issues)
        }, f, indent=2)

    # Write frontier
    with open(state_dir / "frontier.json", "w") as f:
        json.dump({
            "ready": ready,
            "blocked": {str(k): v for k, v in blocked.items()}
        }, f, indent=2)

    # Write manifest
    run_id = state_dir.name
    manifest = {
        "version": 1,
        "run_id": run_id,
        "repository": args.repo,
        "label_filter": args.label,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "total_issues": len(issues),
        "ready": ready,
        "completed": [],
        "failed": [],
        "in_progress": []
    }
    with open(state_dir / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    # Write initial status
    with open(state_dir / "status.txt", "w") as f:
        f.write(f"READY:{len(ready)}/{len(issues)}\n")

    # Print summary (this is what the skill sees)
    print(f"Ready: {len(ready)} issues")
    print(f"Blocked: {len(blocked)} issues")
    if ready:
        print(f"First ready: #{ready[0]}")
    if blocked:
        first_blocked = list(blocked.keys())[0]
        print(f"First blocked: #{first_blocked} (by {blocked[first_blocked]})")


if __name__ == "__main__":
    main()
