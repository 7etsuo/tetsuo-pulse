#!/usr/bin/env python3
"""
Generate summary of pipeline results.
Reads results/*.json and produces a markdown summary.

Usage:
    python summarize.py --state-dir DIR

Output:
    Markdown table with PRs created, failures, and next wave.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Summarize pipeline results")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    results_dir = state_dir / "results"

    # Read manifest
    manifest_file = state_dir / "manifest.json"
    if not manifest_file.exists():
        print("ERROR: manifest.json not found", file=sys.stderr)
        sys.exit(1)

    with open(manifest_file) as f:
        manifest = json.load(f)

    # Read frontier for next wave info
    frontier_file = state_dir / "frontier.json"
    frontier = {}
    if frontier_file.exists():
        with open(frontier_file) as f:
            frontier = json.load(f)

    # Collect results
    successes = []
    failures = []

    if results_dir.exists():
        for result_file in sorted(results_dir.glob("*.json")):
            with open(result_file) as f:
                result = json.load(f)

            if result.get("status") == "success":
                successes.append(result)
            else:
                failures.append(result)

    # Print summary
    print("## Issue Processing Results\n")

    total = len(successes) + len(failures)
    print(f"**Total processed**: {total}")
    print(f"**Successful**: {len(successes)}")
    print(f"**Failed**: {len(failures)}")
    print()

    if successes:
        print("### Pull Requests Created\n")
        print("| Issue | Title | PR |")
        print("|-------|-------|-----|")
        for s in successes:
            issue_num = s.get("issue", "?")
            pr_url = s.get("pr_url", "")

            # Extract PR number from URL if not provided directly
            pr_num = s.get("pr_number")
            if not pr_num and pr_url:
                # URL format: https://github.com/owner/repo/pull/123
                match = re.search(r'/pull/(\d+)', pr_url)
                if match:
                    pr_num = match.group(1)
            if not pr_num:
                pr_num = "?"

            # Try to get title from issue file
            issue_file = state_dir / "issues" / f"{issue_num}.json"
            title = "—"
            if issue_file.exists():
                with open(issue_file) as f:
                    issue_data = json.load(f)
                    title = issue_data.get("title", "—")
                    # Truncate long titles
                    if len(title) > 50:
                        title = title[:47] + "..."

            if pr_url:
                print(f"| #{issue_num} | {title} | [#{pr_num}]({pr_url}) |")
            else:
                print(f"| #{issue_num} | {title} | #{pr_num} |")
        print()

    if failures:
        print("### Failures\n")
        print("| Issue | Error |")
        print("|-------|-------|")
        for f_result in failures:
            issue_num = f_result.get("issue", "?")
            error = f_result.get("error", "Unknown error")
            # Truncate long errors
            if len(error) > 60:
                error = error[:57] + "..."
            print(f"| #{issue_num} | {error} |")
        print()

    # Calculate next wave (issues that were blocked but whose blockers are now done)
    completed_issues = set(manifest.get("completed", []))
    blocked = frontier.get("blocked", {})

    next_wave = []
    for issue_str, blockers in blocked.items():
        issue_num = int(issue_str)
        # Check if all blockers are now completed
        if all(b in completed_issues for b in blockers):
            next_wave.append(issue_num)

    if next_wave:
        print("### Next Wave\n")
        print("These issues are now unblocked and ready to implement:\n")
        for issue_num in sorted(next_wave)[:10]:  # Show first 10
            issue_file = state_dir / "issues" / f"{issue_num}.json"
            title = ""
            if issue_file.exists():
                with open(issue_file) as f:
                    issue_data = json.load(f)
                    title = issue_data.get("title", "")
            print(f"- #{issue_num} {title}")
        if len(next_wave) > 10:
            print(f"- ... and {len(next_wave) - 10} more")
        print()
        print("Run `/issue-processor` again to process the next wave.")


if __name__ == "__main__":
    main()
