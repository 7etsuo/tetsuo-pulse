#!/usr/bin/env python3
"""
Claim a batch of issues for processing and update the manifest.

This script should be called by the skill before spawning agents to track
which issues are currently being worked on. This enables visibility when
running list_available.py or check_status.py --verbose.

IMPORTANT: This script re-validates issues against GitHub before claiming
to prevent duplicate work when multiple instances are running.

Usage:
    python start_batch.py --state-dir DIR --batch-size N [--repo OWNER/REPO] [--fail-mode MODE]

Fail modes:
    fail-safe (default): Skip entire batch on API error (prevents duplicates)
    fail-open: Include all candidates on API error (risks duplicates)
    error: Exit with error on API failure

Output:
    JSON list of issue numbers in the claimed batch.

Example:
    $ python start_batch.py --state-dir .claude/issue-state/run-xxx --batch-size 10
    [1298, 1299, 1300, 1301, 1302, 1303, 1304, 1305, 1306, 1307]
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from utils import (
    run_gh,
    load_json,
    save_json,
    validate_repo_format,
    log_info,
    log_warning,
    log_error,
    GitHubAPIError,
    ValidationError,
)


class APIValidationError(Exception):
    """Raised when GitHub API validation fails."""
    pass


def generate_wip_label() -> str:
    """Generate a unique wip label for this instance."""
    return f"wip:claude-{int(time.time())}-{os.getpid()}"


def claim_issue(owner: str, repo: str, issue_num: int, wip_label: str) -> bool:
    """Atomically claim an issue by adding a wip label. Returns True if successful."""
    # Create label if needed
    run_gh(["label", "create", wip_label, "--repo", f"{owner}/{repo}",
            "--description", "Work in progress - claimed by Claude instance",
            "--color", "FFA500"], check=False)

    # Add label to issue
    success, output = run_gh(["issue", "edit", str(issue_num), "--repo", f"{owner}/{repo}",
                              "--add-label", wip_label], check=False)
    if not success:
        return False

    # Verify we won the race
    success, output = run_gh(["issue", "view", str(issue_num), "--repo", f"{owner}/{repo}",
                              "--json", "labels"], check=False)
    if not success:
        run_gh(["issue", "edit", str(issue_num), "--repo", f"{owner}/{repo}",
                "--remove-label", wip_label], check=False)
        return False

    try:
        data = json.loads(output)
        wip_labels = [l["name"] for l in data.get("labels", []) if l["name"].startswith("wip:")]
        if len(wip_labels) > 1:
            our_ts = int(wip_label.split("-")[1])
            for other in wip_labels:
                if other != wip_label:
                    try:
                        if int(other.split("-")[1]) < our_ts:
                            run_gh(["issue", "edit", str(issue_num), "--repo", f"{owner}/{repo}",
                                    "--remove-label", wip_label], check=False)
                            return False
                    except (IndexError, ValueError):
                        pass
        return True
    except (json.JSONDecodeError, KeyError):
        run_gh(["issue", "edit", str(issue_num), "--repo", f"{owner}/{repo}",
                "--remove-label", wip_label], check=False)
        return False


def validate_issues_against_github(
    owner: str,
    repo: str,
    issue_nums: list[int],
    fail_mode: str = "fail-safe"
) -> dict:
    """
    Check GitHub for current state of issues.

    Args:
        owner: Repository owner
        repo: Repository name
        issue_nums: List of issue numbers to validate
        fail_mode: How to handle API errors ("fail-safe", "fail-open", "error")

    Returns:
        dict with:
            - valid: issues that are OPEN and have no wip:* label
            - closed: issues that are CLOSED
            - claimed: issues with wip:* labels (claimed by other instances)
            - has_pr: issues that already have linked PRs

    Raises:
        APIValidationError: If fail_mode is "error" and API call fails
    """
    if not issue_nums:
        return {"valid": [], "closed": [], "claimed": [], "has_pr": []}

    valid = []
    closed = []
    claimed = []
    has_pr = []

    # Batch check in groups of 20 to avoid GraphQL query complexity limits
    for i in range(0, len(issue_nums), 20):
        batch = issue_nums[i:i+20]

        # Build GraphQL query to check multiple issues at once
        queries = []
        for num in batch:
            queries.append(f'''
                issue{num}: issue(number: {num}) {{
                    number
                    state
                    labels(first: 10) {{ nodes {{ name }} }}
                    timelineItems(itemTypes: [CONNECTED_EVENT, CROSS_REFERENCED_EVENT], first: 10) {{
                        nodes {{
                            ... on ConnectedEvent {{
                                subject {{ ... on PullRequest {{ number state }} }}
                            }}
                            ... on CrossReferencedEvent {{
                                source {{ ... on PullRequest {{ number state }} }}
                            }}
                        }}
                    }}
                }}
            ''')

        query = f'''
        query {{
            repository(owner: "{owner}", name: "{repo}") {{
                {" ".join(queries)}
            }}
        }}
        '''

        success, output = run_gh(["api", "graphql", "-f", f"query={query}"], check=False)

        if not success:
            error_msg = f"GitHub API error: {output}"

            if fail_mode == "error":
                raise APIValidationError(error_msg)
            elif fail_mode == "fail-safe":
                log_warning(f"{error_msg} - skipping batch (fail-safe mode)")
                # Return empty valid list - skip this batch entirely
                return {"valid": [], "closed": [], "claimed": [], "has_pr": [], "api_error": True}
            else:  # fail-open
                log_warning(f"{error_msg} - including all candidates (fail-open mode)")
                return {"valid": issue_nums, "closed": [], "claimed": [], "has_pr": []}

        try:
            result = json.loads(output)
            repo_data = result.get("data", {}).get("repository", {})

            for num in batch:
                issue_data = repo_data.get(f"issue{num}")
                if not issue_data:
                    # Issue doesn't exist or was deleted
                    closed.append(num)
                    continue

                # Check if closed
                if issue_data.get("state") == "CLOSED":
                    closed.append(num)
                    continue

                # Check for wip:* labels
                labels = [l["name"] for l in issue_data.get("labels", {}).get("nodes", [])]
                wip_labels = [l for l in labels if l.startswith("wip:")]
                if wip_labels:
                    claimed.append(num)
                    log_info(f"#{num}: claimed by {wip_labels[0]}")
                    continue

                # Check for linked PRs (open ones mean work in progress)
                timeline = issue_data.get("timelineItems", {}).get("nodes", [])
                has_open_pr = False
                for item in timeline:
                    pr = item.get("subject") or item.get("source")
                    if pr and pr.get("state") == "OPEN":
                        has_open_pr = True
                        break

                if has_open_pr:
                    has_pr.append(num)
                    log_info(f"#{num}: already has open PR")
                    continue

                # Issue is valid - open, unclaimed, no PR
                valid.append(num)

        except (json.JSONDecodeError, KeyError) as e:
            error_msg = f"Failed to parse GitHub response: {e}"

            if fail_mode == "error":
                raise APIValidationError(error_msg)
            elif fail_mode == "fail-safe":
                log_warning(f"{error_msg} - skipping batch (fail-safe mode)")
                return {"valid": [], "closed": [], "claimed": [], "has_pr": [], "api_error": True}
            else:  # fail-open
                log_warning(f"{error_msg} - including batch candidates (fail-open mode)")
                valid.extend(batch)

    return {"valid": valid, "closed": closed, "claimed": claimed, "has_pr": has_pr}


def main():
    parser = argparse.ArgumentParser(
        description="Claim a batch of issues and update manifest"
    )
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--batch-size", type=int, default=10,
                        help="Number of issues to claim")
    parser.add_argument("--repo", help="Repository (owner/repo) - read from manifest if not provided")
    parser.add_argument("--fail-mode", choices=["fail-safe", "fail-open", "error"],
                        default="fail-safe",
                        help="How to handle GitHub API errors (default: fail-safe)")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    manifest_file = state_dir / "manifest.json"

    if not manifest_file.exists():
        log_error("manifest.json not found")
        sys.exit(1)

    # Load manifest
    try:
        manifest = load_json(manifest_file)
    except Exception as e:
        log_error(f"Failed to load manifest: {e}")
        sys.exit(1)

    # Get repo from args or manifest
    repo_full = args.repo or manifest.get("repository")
    if not repo_full:
        log_error("No repository specified")
        sys.exit(1)

    try:
        owner, repo = validate_repo_format(repo_full)
    except ValidationError as e:
        log_error(str(e))
        sys.exit(1)

    # Get lists from local manifest
    ready = manifest.get("ready", [])
    completed = set(manifest.get("completed", []))
    failed = set(manifest.get("failed", []))
    claimed_by_others = set(manifest.get("claimed_by_others", []))

    # Filter ready list to exclude already processed issues (local check)
    candidates = [n for n in ready
                  if n not in completed
                  and n not in failed
                  and n not in claimed_by_others]

    if not candidates:
        print("[]")  # Empty batch
        sys.exit(0)

    # Take more candidates than batch_size for validation.
    # Rationale: Some candidates will be filtered out by GitHub validation
    # (closed, claimed, has PR). By fetching 2x, we're more likely to end up
    # with a full batch after filtering. This is a heuristic - in practice,
    # most issues won't be filtered, so 2x is usually sufficient.
    candidates_to_check = candidates[:args.batch_size * 2]

    # RE-VALIDATE against GitHub to catch:
    # - Issues closed by other instances
    # - Issues claimed by other instances (wip:* labels)
    # - Issues that already have PRs
    log_info(f"Validating {len(candidates_to_check)} candidate issues against GitHub...")

    try:
        validation = validate_issues_against_github(
            owner, repo, candidates_to_check, args.fail_mode
        )
    except APIValidationError as e:
        log_error(str(e))
        sys.exit(1)

    # Check for API error in fail-safe mode (returns empty valid list)
    if validation.get("api_error"):
        log_warning("Skipping batch due to API error")
        print("[]")
        sys.exit(0)

    # Log what was filtered
    if validation["closed"]:
        log_info(f"Filtered {len(validation['closed'])} closed issues: {validation['closed']}")
        # Update manifest with newly discovered closed issues
        completed.update(validation["closed"])
        manifest["completed"] = list(completed)

    if validation["claimed"]:
        log_info(f"Filtered {len(validation['claimed'])} claimed issues")
        claimed_by_others.update(validation["claimed"])
        manifest["claimed_by_others"] = list(claimed_by_others)

    if validation["has_pr"]:
        log_info(f"Filtered {len(validation['has_pr'])} issues with existing PRs")
        # Treat issues with PRs as completed
        completed.update(validation["has_pr"])
        manifest["completed"] = list(completed)

    available = validation["valid"]

    if not available:
        print("[]")  # Empty batch after validation
        # Still save manifest with updated completed/claimed lists
        save_json(manifest_file, manifest)
        sys.exit(0)

    # Take batch candidates and atomically claim each
    candidates = available[:args.batch_size]
    wip_label = generate_wip_label()
    log_info(f"Attempting to claim {len(candidates)} issues with {wip_label}")

    claimed = []
    for num in candidates:
        if claim_issue(owner, repo, num, wip_label):
            claimed.append(num)
            log_info(f"#{num}: claimed")
        else:
            log_info(f"#{num}: claim failed")

    if not claimed:
        log_warning("No issues could be claimed")
        print("[]")
        sys.exit(0)

    log_info(f"Successfully claimed {len(claimed)} issues: {claimed}")

    # Update manifest with current batch and wip label
    manifest["current_batch"] = claimed
    manifest["current_wip_label"] = wip_label
    manifest["batch_started_at"] = datetime.now(timezone.utc).isoformat()

    save_json(manifest_file, manifest)
    print(json.dumps(claimed))


if __name__ == "__main__":
    main()
