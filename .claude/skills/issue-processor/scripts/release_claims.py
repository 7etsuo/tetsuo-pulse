#!/usr/bin/env python3
"""
Manually release wip label claims from issues.

Use this after verifying that PRs are merged and issues can be closed.

Usage:
    python release_claims.py --repo OWNER/REPO --label wip:claude-XXXX
    python release_claims.py --repo OWNER/REPO --all-wip

Options:
    --label LABEL   Remove a specific wip label from all issues that have it
    --all-wip       Remove ALL wip:* labels from all issues (nuclear option)
    --dry-run       Show what would be done without making changes
"""

import argparse
import json
import sys

from utils import (
    run_gh,
    validate_repo_format,
    log_info,
    log_warning,
    log_error,
    ValidationError,
)


def get_issues_with_label(owner: str, repo: str, label: str) -> list[int]:
    """Get all issue numbers that have a specific label."""
    success, output = run_gh([
        "issue", "list",
        "--repo", f"{owner}/{repo}",
        "--label", label,
        "--state", "all",
        "--json", "number",
        "--limit", "500"
    ], check=False)

    if not success:
        log_error(f"Failed to list issues: {output}")
        return []

    try:
        issues = json.loads(output)
        return [i["number"] for i in issues]
    except json.JSONDecodeError:
        log_error(f"Failed to parse issue list: {output}")
        return []


def get_all_wip_labels(owner: str, repo: str) -> list[str]:
    """Get all wip:* labels in the repository."""
    success, output = run_gh([
        "label", "list",
        "--repo", f"{owner}/{repo}",
        "--json", "name",
        "--limit", "500"
    ], check=False)

    if not success:
        log_error(f"Failed to list labels: {output}")
        return []

    try:
        labels = json.loads(output)
        return [l["name"] for l in labels if l["name"].startswith("wip:")]
    except json.JSONDecodeError:
        log_error(f"Failed to parse label list: {output}")
        return []


def remove_label_from_issue(owner: str, repo: str, issue_num: int, label: str) -> bool:
    """Remove a label from an issue."""
    success, output = run_gh([
        "issue", "edit", str(issue_num),
        "--repo", f"{owner}/{repo}",
        "--remove-label", label
    ], check=False)

    return success


def main():
    parser = argparse.ArgumentParser(
        description="Manually release wip label claims from issues"
    )
    parser.add_argument("--repo", required=True, help="Repository (owner/repo)")
    parser.add_argument("--label", help="Specific wip label to remove")
    parser.add_argument("--all-wip", action="store_true",
                        help="Remove ALL wip:* labels")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without making changes")
    args = parser.parse_args()

    if not args.label and not args.all_wip:
        log_error("Must specify either --label or --all-wip")
        sys.exit(1)

    try:
        owner, repo = validate_repo_format(args.repo)
    except ValidationError as e:
        log_error(str(e))
        sys.exit(1)

    # Determine which labels to process
    if args.all_wip:
        labels = get_all_wip_labels(owner, repo)
        if not labels:
            print("No wip:* labels found in repository")
            sys.exit(0)
        log_info(f"Found {len(labels)} wip labels: {', '.join(labels)}")
    else:
        labels = [args.label]

    # Process each label
    total_removed = 0
    for label in labels:
        issues = get_issues_with_label(owner, repo, label)
        if not issues:
            log_info(f"No issues with label '{label}'")
            continue

        log_info(f"Found {len(issues)} issues with label '{label}'")

        for issue_num in issues:
            if args.dry_run:
                print(f"  Would remove '{label}' from #{issue_num}")
            else:
                if remove_label_from_issue(owner, repo, issue_num, label):
                    print(f"  Removed '{label}' from #{issue_num}")
                    total_removed += 1
                else:
                    log_warning(f"  Failed to remove '{label}' from #{issue_num}")

    if args.dry_run:
        print(f"\nDry run complete. Would have removed labels from {total_removed} issues.")
    else:
        print(f"\nDone. Removed labels from {total_removed} issues.")


if __name__ == "__main__":
    main()
