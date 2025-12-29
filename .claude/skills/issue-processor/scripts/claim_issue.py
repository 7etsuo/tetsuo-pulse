#!/usr/bin/env python3
"""
Claim or release GitHub issues using labels for multi-instance coordination.

Uses 'wip:claude-{timestamp}' labels as distributed locks to prevent multiple
Claude instances from working on the same issue simultaneously.

Usage:
    python claim_issue.py --repo OWNER/REPO --issue NUM --action claim
    python claim_issue.py --repo OWNER/REPO --issue NUM --action release
    python claim_issue.py --repo OWNER/REPO --issue NUM --action check

Exit codes:
    0: Success (claimed, released, or not claimed)
    1: Already claimed by another instance
    2: Error (API failure, etc.)
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse


def run_gh(args: list[str], check: bool = True) -> tuple[bool, str]:
    """Run gh CLI command and return (success, output)."""
    result = subprocess.run(
        ["gh"] + args,
        capture_output=True,
        text=True
    )
    if check and result.returncode != 0:
        return False, result.stderr.strip()
    return True, result.stdout.strip()


def get_issue_labels(owner: str, repo: str, issue_num: int) -> list[str]:
    """Get all labels on an issue."""
    success, output = run_gh([
        "api", f"repos/{owner}/{repo}/issues/{issue_num}",
        "--jq", ".labels[].name"
    ])
    if not success:
        return []
    return [l.strip() for l in output.split("\n") if l.strip()]


def get_wip_label(labels: list[str]) -> str | None:
    """Find the wip:* label if present."""
    for label in labels:
        if label.startswith("wip:"):
            return label
    return None


def ensure_label_exists(owner: str, repo: str, label_name: str) -> bool:
    """Ensure the label exists in the repository, create if not."""
    # URL-encode the label name for the API path
    encoded_name = urllib.parse.quote(label_name, safe='')

    # Try to get the label
    result = subprocess.run(
        ["gh", "api", f"repos/{owner}/{repo}/labels/{encoded_name}"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        return True

    # Create the label
    success, output = run_gh([
        "api", f"repos/{owner}/{repo}/labels",
        "-X", "POST",
        "-f", f"name={label_name}",
        "-f", "color=FFA500",  # Orange color for WIP
        "-f", "description=Work in progress - claimed by Claude instance"
    ], check=False)

    if not success and "already_exists" not in output.lower():
        print(f"Warning: Could not create label: {output}", file=sys.stderr)
        return False

    return True


def add_label(owner: str, repo: str, issue_num: int, label: str) -> bool:
    """Add a label to an issue."""
    success, output = run_gh([
        "issue", "edit", str(issue_num),
        "--repo", f"{owner}/{repo}",
        "--add-label", label
    ], check=False)

    if not success:
        print(f"Error adding label: {output}", file=sys.stderr)
        return False
    return True


def remove_label(owner: str, repo: str, issue_num: int, label: str) -> bool:
    """Remove a label from an issue."""
    success, output = run_gh([
        "issue", "edit", str(issue_num),
        "--repo", f"{owner}/{repo}",
        "--remove-label", label
    ], check=False)

    if not success:
        print(f"Error removing label: {output}", file=sys.stderr)
        return False
    return True


def generate_claim_label() -> str:
    """Generate a unique claim label for this instance."""
    timestamp = int(time.time())
    pid = os.getpid()
    return f"wip:claude-{timestamp}-{pid}"


def claim_issue(owner: str, repo: str, issue_num: int) -> tuple[bool, str]:
    """
    Attempt to claim an issue by adding a wip: label.

    Returns:
        (success, message) where success is False if already claimed
    """
    # Check current labels
    labels = get_issue_labels(owner, repo, issue_num)
    existing_wip = get_wip_label(labels)

    if existing_wip:
        return False, f"Already claimed: {existing_wip}"

    # Generate our claim label
    claim_label = generate_claim_label()

    # Ensure label exists in repo
    ensure_label_exists(owner, repo, claim_label)

    # Add the label
    if not add_label(owner, repo, issue_num, claim_label):
        return False, "Failed to add claim label"

    # Verify we got the claim (race condition check)
    labels = get_issue_labels(owner, repo, issue_num)
    wip_labels = [l for l in labels if l.startswith("wip:")]

    if len(wip_labels) > 1:
        # Race condition - multiple claims, we lose
        remove_label(owner, repo, issue_num, claim_label)
        other_labels = [l for l in wip_labels if l != claim_label]
        return False, f"Lost race to: {other_labels[0]}"

    if claim_label not in labels:
        return False, "Claim label not applied"

    return True, claim_label


def release_issue(owner: str, repo: str, issue_num: int) -> tuple[bool, str]:
    """
    Release a claimed issue by removing the wip: label.

    Returns:
        (success, message)
    """
    labels = get_issue_labels(owner, repo, issue_num)
    wip_label = get_wip_label(labels)

    if not wip_label:
        return True, "No claim to release"

    if not remove_label(owner, repo, issue_num, wip_label):
        return False, f"Failed to remove label: {wip_label}"

    return True, f"Released: {wip_label}"


def check_issue(owner: str, repo: str, issue_num: int) -> tuple[bool, str]:
    """
    Check if an issue is claimed.

    Returns:
        (is_available, message)
    """
    labels = get_issue_labels(owner, repo, issue_num)
    wip_label = get_wip_label(labels)

    if wip_label:
        return False, f"Claimed: {wip_label}"
    return True, "Available"


def main():
    parser = argparse.ArgumentParser(description="Claim/release GitHub issues using labels")
    parser.add_argument("--repo", required=True, help="Repository (owner/repo)")
    parser.add_argument("--issue", type=int, required=True, help="Issue number")
    parser.add_argument("--action", required=True, choices=["claim", "release", "check"],
                        help="Action to perform")
    args = parser.parse_args()

    owner, repo = args.repo.split("/")

    if args.action == "claim":
        success, message = claim_issue(owner, repo, args.issue)
        print(message)
        sys.exit(0 if success else 1)

    elif args.action == "release":
        success, message = release_issue(owner, repo, args.issue)
        print(message)
        sys.exit(0 if success else 2)

    elif args.action == "check":
        available, message = check_issue(owner, repo, args.issue)
        print(message)
        sys.exit(0 if available else 1)


if __name__ == "__main__":
    main()
