#!/usr/bin/env python3
"""
Get the next batch of issues to process with their worktree paths.

Reads manifest.json to find ready issues that haven't been completed,
failed, or are in progress. Creates git worktrees for parallel development.

IMPORTANT: This script re-validates issues against GitHub before returning
to prevent duplicate work when multiple instances are running.

Usage:
    python next_batch.py --state-dir DIR --batch-size N [--create-worktrees] [--fail-mode MODE]

Fail modes:
    fail-safe (default): Skip entire batch on API error (prevents duplicates)
    fail-open: Include all candidates on API error (risks duplicates)
    error: Exit with error on API failure

Output (JSON):
    {
        "batch": [
            {"issue": 391, "worktree": "/path/to/repo-issue-391"},
            {"issue": 392, "worktree": "/path/to/repo-issue-392"}
        ],
        "remaining": 5
    }
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

from utils import (
    run_git,
    run_gh,
    load_json,
    save_json,
    log_info,
    log_warning,
    log_error,
    validate_repo_format,
    GitHubAPIError,
    ValidationError,
)


class APIValidationError(Exception):
    """Raised when GitHub API validation fails."""
    pass


def generate_wip_label() -> str:
    """Generate a unique wip label for this instance."""
    timestamp = int(time.time())
    pid = os.getpid()
    return f"wip:claude-{timestamp}-{pid}"


def claim_issue(owner: str, repo: str, issue_num: int, wip_label: str) -> bool:
    """Atomically claim an issue. Returns True if successful."""
    # Create label if needed
    run_gh([
        "label", "create", wip_label,
        "--repo", f"{owner}/{repo}",
        "--description", "Work in progress - claimed by Claude instance",
        "--color", "FFA500"
    ], check=False)

    # Add label to issue
    success, output = run_gh([
        "issue", "edit", str(issue_num),
        "--repo", f"{owner}/{repo}",
        "--add-label", wip_label
    ], check=False)

    if not success:
        return False

    # Verify we won the race
    success, output = run_gh([
        "issue", "view", str(issue_num),
        "--repo", f"{owner}/{repo}",
        "--json", "labels"
    ], check=False)

    if not success:
        run_gh(["issue", "edit", str(issue_num), "--repo", f"{owner}/{repo}",
                "--remove-label", wip_label], check=False)
        return False

    try:
        data = json.loads(output)
        labels = [l["name"] for l in data.get("labels", [])]
        wip_labels = [l for l in labels if l.startswith("wip:")]

        if len(wip_labels) > 1:
            our_timestamp = int(wip_label.split("-")[1])
            for other in wip_labels:
                if other == wip_label:
                    continue
                try:
                    other_ts = int(other.split("-")[1])
                    if other_ts < our_timestamp:
                        run_gh(["issue", "edit", str(issue_num), "--repo", f"{owner}/{repo}",
                                "--remove-label", wip_label], check=False)
                        return False
                except (IndexError, ValueError):
                    continue
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
            - claimed: issues with wip:* labels
            - has_pr: issues with linked open PRs

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
                    closed.append(num)
                    continue

                if issue_data.get("state") == "CLOSED":
                    closed.append(num)
                    continue

                labels = [l["name"] for l in issue_data.get("labels", {}).get("nodes", [])]
                wip_labels = [l for l in labels if l.startswith("wip:")]
                if wip_labels:
                    claimed.append(num)
                    log_info(f"#{num}: claimed by {wip_labels[0]}")
                    continue

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


def get_repo_root() -> Path:
    """Get the git repository root directory."""
    success, output = run_git(["rev-parse", "--show-toplevel"])
    if not success:
        log_error("Not in a git repository")
        sys.exit(1)
    return Path(output)


def create_worktree(repo_root: Path, issue_num: int, branch_name: str) -> Path | None:
    """Create a git worktree for an issue, return worktree path or None on failure."""
    worktree_dir = repo_root.parent / f"{repo_root.name}-issue-{issue_num}"

    # Check if worktree already exists
    if worktree_dir.exists():
        # Verify it's a valid worktree
        success, worktree_list = run_git(["worktree", "list", "--porcelain"], cwd=str(repo_root))
        if success and str(worktree_dir) in worktree_list:
            return worktree_dir
        # Directory exists but not a worktree - remove it
        shutil.rmtree(worktree_dir, ignore_errors=True)

    # Fetch latest from origin
    run_git(["fetch", "origin"], cwd=str(repo_root))

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
        return worktree_dir

    log_warning(f"Failed to create worktree for #{issue_num}: {output}")
    return None


def main():
    parser = argparse.ArgumentParser(description="Get next batch of issues with worktree paths")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--batch-size", type=int, default=5, help="Maximum issues in batch")
    parser.add_argument("--create-worktrees", action="store_true",
                        help="Create git worktrees for each issue")
    parser.add_argument("--fail-mode", choices=["fail-safe", "fail-open", "error"],
                        default="fail-safe",
                        help="How to handle GitHub API errors (default: fail-safe)")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)

    # Load manifest
    manifest_path = state_dir / "manifest.json"
    if not manifest_path.exists():
        print(json.dumps({"error": "manifest_not_found", "batch": [], "remaining": 0}))
        sys.exit(1)

    manifest = load_json(manifest_path)

    # Get repo info
    repo_full = manifest.get("repository", "")
    try:
        owner, repo_name = validate_repo_format(repo_full)
    except ValidationError as e:
        print(json.dumps({"error": str(e), "batch": [], "remaining": 0}))
        sys.exit(1)

    # Get sets of processed issues (local state)
    completed = set(manifest.get("completed", []))
    failed = set(manifest.get("failed", []))
    in_progress = set(manifest.get("in_progress", []))
    claimed_by_others = set(manifest.get("claimed_by_others", []))
    processed = completed | failed | in_progress | claimed_by_others

    # Get ready issues that haven't been processed (local filter)
    candidates = [i for i in manifest.get("ready", []) if i not in processed]

    if not candidates:
        print(json.dumps({"batch": [], "remaining": 0, "completed": len(completed), "failed": len(failed)}))
        sys.exit(0)

    # Take more candidates than batch_size for validation.
    # Rationale: Some candidates will be filtered out by GitHub validation
    # (closed, claimed, has PR). By fetching 2x, we're more likely to end up
    # with a full batch after filtering. This is a heuristic - in practice,
    # most issues won't be filtered, so 2x is usually sufficient.
    candidates_to_check = candidates[:args.batch_size * 2]

    # RE-VALIDATE against GitHub to prevent duplicates
    log_info(f"Validating {len(candidates_to_check)} candidates against GitHub...")

    try:
        validation = validate_issues_against_github(
            owner, repo_name, candidates_to_check, args.fail_mode
        )
    except APIValidationError as e:
        log_error(str(e))
        print(json.dumps({"error": str(e), "batch": [], "remaining": 0}))
        sys.exit(1)

    # Check for API error in fail-safe mode
    if validation.get("api_error"):
        log_warning("Skipping batch due to API error")
        print(json.dumps({"batch": [], "remaining": 0, "api_error": True}))
        sys.exit(0)

    # Update manifest with discovered state
    if validation["closed"]:
        log_info(f"Filtered {len(validation['closed'])} closed issues: {validation['closed']}")
        completed.update(validation["closed"])
        manifest["completed"] = list(completed)

    if validation["claimed"]:
        log_info(f"Filtered {len(validation['claimed'])} claimed issues")
        claimed_by_others.update(validation["claimed"])
        manifest["claimed_by_others"] = list(claimed_by_others)

    if validation["has_pr"]:
        log_info(f"Filtered {len(validation['has_pr'])} issues with PRs")
        completed.update(validation["has_pr"])
        manifest["completed"] = list(completed)

    valid_issues = validation["valid"]

    if not valid_issues:
        # Save updated manifest
        save_json(manifest_path, manifest)
        print(json.dumps({"batch": [], "remaining": 0, "completed": len(completed), "failed": len(failed)}))
        sys.exit(0)

    # Take batch candidates from validated issues
    batch_candidates = valid_issues[:args.batch_size]

    log_info(f"Attempting to claim {len(batch_candidates)} issues: {batch_candidates}")

    # Generate unique wip label and atomically claim each issue
    wip_label = generate_wip_label()
    log_info(f"Using claim label: {wip_label}")

    batch_issues = []
    for issue_num in batch_candidates:
        if claim_issue(owner, repo_name, issue_num, wip_label):
            batch_issues.append(issue_num)
            log_info(f"#{issue_num}: claimed successfully")
        else:
            log_info(f"#{issue_num}: claim failed, skipping")

    if not batch_issues:
        log_warning("No issues could be claimed")
        save_json(manifest_path, manifest)
        print(json.dumps({"batch": [], "remaining": 0, "completed": len(completed), "failed": len(failed)}))
        sys.exit(0)

    remaining = len(valid_issues) - len(batch_issues)
    log_info(f"Successfully claimed {len(batch_issues)} issues: {batch_issues}")

    # Get repo root for worktree creation
    repo_root = get_repo_root()

    # Build batch with worktree paths
    batch = []
    for issue_num in batch_issues:
        branch_name = f"issue-{issue_num}"

        if args.create_worktrees:
            worktree_path = create_worktree(repo_root, issue_num, branch_name)
            if worktree_path:
                batch.append({
                    "issue": issue_num,
                    "worktree": str(worktree_path),
                    "branch": branch_name
                })
            else:
                # Fallback to main repo if worktree creation fails
                batch.append({
                    "issue": issue_num,
                    "worktree": str(repo_root),
                    "branch": branch_name,
                    "worktree_failed": True
                })
        else:
            # Just return issue info without creating worktrees
            worktree_path = repo_root.parent / f"{repo_root.name}-issue-{issue_num}"
            batch.append({
                "issue": issue_num,
                "worktree": str(worktree_path),
                "branch": branch_name
            })

    # Update manifest with in_progress, current_batch, and wip_label
    manifest["in_progress"] = list(in_progress | set(batch_issues))
    manifest["current_batch"] = batch_issues
    manifest["current_wip_label"] = wip_label  # For finish_batch.py to release claims
    save_json(manifest_path, manifest)

    # Output result
    result = {
        "batch": batch,
        "remaining": remaining,
        "total_ready": len(manifest.get("ready", [])),
        "completed": len(completed),
        "failed": len(failed),
        "filtered": {
            "closed": len(validation["closed"]),
            "claimed": len(validation["claimed"]),
            "has_pr": len(validation["has_pr"])
        }
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
