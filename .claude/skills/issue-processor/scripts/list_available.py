#!/usr/bin/env python3
"""
List issues that are available for manual work vs currently claimed by agents.

This helps when running issue-processor in one terminal and wanting to work
on issues manually in another terminal without conflicts.

Usage:
    python list_available.py --repo OWNER/REPO [--state-dir DIR] [--limit N]

Output:
    Shows currently claimed issues (with wip:* labels) and available issues
    that are safe to work on manually.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from utils import (
    run_gh,
    load_json,
    validate_repo_format,
    log_error,
    ValidationError,
)


def fetch_open_issues(owner: str, repo: str) -> list[dict]:
    """Fetch all open issues with their labels."""
    issues = []
    cursor = None

    while True:
        cursor_arg = f', after: "{cursor}"' if cursor else ""

        query = f'''
        query {{
          repository(owner: "{owner}", name: "{repo}") {{
            issues(first: 100, states: OPEN{cursor_arg}) {{
              pageInfo {{ hasNextPage endCursor }}
              nodes {{
                number
                title
                labels(first: 10) {{ nodes {{ name }} }}
              }}
            }}
          }}
        }}
        '''

        success, output = run_gh(["api", "graphql", "-f", f"query={query}"], check=False)
        if not success:
            log_error(f"Fetching issues: {output}")
            sys.exit(1)

        try:
            result = json.loads(output)
        except json.JSONDecodeError as e:
            log_error(f"Failed to parse GitHub API response: {e}")
            log_error(f"Response was: {output[:500]}")
            sys.exit(1)
        page = result.get("data", {}).get("repository", {}).get("issues", {})
        nodes = page.get("nodes", [])

        for node in nodes:
            labels = [l["name"] for l in node.get("labels", {}).get("nodes", [])]
            wip_label = next((l for l in labels if l.startswith("wip:")), None)
            issues.append({
                "number": node["number"],
                "title": node["title"],
                "labels": labels,
                "wip_label": wip_label,
                "claimed": wip_label is not None
            })

        if not page.get("pageInfo", {}).get("hasNextPage"):
            break
        cursor = page["pageInfo"]["endCursor"]

    return issues


def main():
    parser = argparse.ArgumentParser(
        description="List available issues vs claimed issues"
    )
    parser.add_argument("--repo", required=True, help="Repository (owner/repo)")
    parser.add_argument("--state-dir", help="State directory to check for completed issues")
    parser.add_argument("--limit", type=int, default=20, help="Max available issues to show")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    try:
        owner, repo = validate_repo_format(args.repo)
    except ValidationError as e:
        log_error(str(e))
        sys.exit(1)

    # Fetch all open issues
    print("Fetching open issues...", file=sys.stderr)
    issues = fetch_open_issues(owner, repo)

    # Separate claimed vs available
    claimed = [i for i in issues if i["claimed"]]
    available = [i for i in issues if not i["claimed"]]

    # Check manifest for completed/failed issues
    completed_nums = set()
    failed_nums = set()
    current_batch = []

    if args.state_dir:
        state_dir = Path(args.state_dir)
        manifest_file = state_dir / "manifest.json"
        if manifest_file.exists():
            try:
                manifest = load_json(manifest_file)
                completed_nums = set(manifest.get("completed", []))
                failed_nums = set(manifest.get("failed", []))
                current_batch = manifest.get("current_batch", [])
            except json.JSONDecodeError as e:
                log_error(f"Failed to parse manifest.json: {e}")
                log_error(f"File: {manifest_file}")
                # Continue without manifest data

            # Filter out completed/failed/current_batch from available
            current_batch_set = set(current_batch)
            available = [i for i in available
                         if i["number"] not in completed_nums
                         and i["number"] not in failed_nums
                         and i["number"] not in current_batch_set]

    if args.json:
        output = {
            "claimed": [{"number": i["number"], "title": i["title"], "wip_label": i["wip_label"]}
                        for i in claimed],
            "available": [{"number": i["number"], "title": i["title"]}
                          for i in available[:args.limit]],
            "completed": list(completed_nums),
            "failed": list(failed_nums),
            "current_batch": current_batch,
            "stats": {
                "total_open": len(issues),
                "claimed": len(claimed),
                "available": len(available),
                "completed": len(completed_nums),
                "failed": len(failed_nums)
            }
        }
        print(json.dumps(output, indent=2))
        return

    # Pretty print
    print()
    print("=" * 70)
    print(f"ISSUE STATUS FOR {owner}/{repo}")
    print("=" * 70)

    # Show claimed issues
    print()
    if claimed:
        print(f"CLAIMED ({len(claimed)} issues being worked on by agents):")
        print("-" * 50)
        for issue in sorted(claimed, key=lambda x: x["number"]):
            label = issue["wip_label"]
            # Extract timestamp from label like wip:claude-1703847234-12345
            parts = label.split("-")
            if len(parts) >= 2:
                try:
                    timestamp = int(parts[1])
                    claimed_at = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
                    print(f"  #{issue['number']:4d}  {issue['title'][:45]:<45}  (since {claimed_at})")
                except (ValueError, IndexError):
                    print(f"  #{issue['number']:4d}  {issue['title'][:45]:<45}  ({label})")
            else:
                print(f"  #{issue['number']:4d}  {issue['title'][:45]:<45}  ({label})")
    else:
        print("CLAIMED: None")

    # Show current batch if available
    if current_batch:
        print()
        print(f"CURRENT BATCH ({len(current_batch)} issues in this batch):")
        print("-" * 50)
        for num in current_batch:
            issue = next((i for i in issues if i["number"] == num), None)
            if issue:
                status = "claimed" if issue["claimed"] else "pending"
                print(f"  #{num:4d}  {issue['title'][:50]:<50}  [{status}]")
            else:
                print(f"  #{num:4d}  (issue not found)")

    # Show stats
    print()
    print("SUMMARY:")
    print("-" * 50)
    print(f"  Total open issues:  {len(issues)}")
    print(f"  Claimed by agents:  {len(claimed)}")
    print(f"  Completed:          {len(completed_nums)}")
    print(f"  Failed:             {len(failed_nums)}")
    print(f"  Available:          {len(available)}")

    # Show available issues
    print()
    print(f"AVAILABLE FOR MANUAL WORK (showing first {args.limit}):")
    print("-" * 50)
    if available:
        for issue in sorted(available, key=lambda x: x["number"])[:args.limit]:
            print(f"  #{issue['number']:4d}  {issue['title'][:60]}")
    else:
        print("  (none available)")

    print()
    print("=" * 70)
    print("Issues marked 'AVAILABLE' can be safely worked on in another terminal.")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
