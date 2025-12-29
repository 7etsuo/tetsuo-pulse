#!/usr/bin/env python3
"""
Mark the current batch as complete and clear it from the manifest.

This script should be called by the skill after a batch completes (all agents
have written results). It clears current_batch and updates completed/failed
lists based on result files.

Usage:
    python finish_batch.py --state-dir DIR

Output:
    Summary of batch completion status.

Note: Issues without result files are marked as failed (agent crashed).
"""

import argparse
import sys
from pathlib import Path

from utils import (
    run_gh,
    load_json,
    save_json,
    validate_repo_format,
    log_info,
    log_warning,
)


def release_claim(owner: str, repo: str, issue_num: int, wip_label: str) -> None:
    """Remove the wip label from an issue to release the claim."""
    run_gh(["issue", "edit", str(issue_num), "--repo", f"{owner}/{repo}",
            "--remove-label", wip_label], check=False)


def main():
    parser = argparse.ArgumentParser(
        description="Mark current batch as complete"
    )
    parser.add_argument("--state-dir", required=True, help="State directory path")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    manifest_file = state_dir / "manifest.json"
    results_dir = state_dir / "results"

    if not manifest_file.exists():
        log_warning("manifest.json not found")
        sys.exit(1)

    # Load manifest
    manifest = load_json(manifest_file)

    current_batch = manifest.get("current_batch", [])
    if not current_batch:
        print("No current batch to finish")
        sys.exit(0)

    # Get wip label and repo for releasing claims
    wip_label = manifest.get("current_wip_label")
    repo_full = manifest.get("repository")
    owner, repo = None, None
    if repo_full:
        try:
            owner, repo = validate_repo_format(repo_full)
        except Exception:
            pass

    completed = set(manifest.get("completed", []))
    failed = set(manifest.get("failed", []))

    # Check result files for each issue in batch
    new_completed = 0
    new_already_resolved = 0
    new_failed = 0

    for issue_num in current_batch:
        result_file = results_dir / f"{issue_num}.json"
        if result_file.exists():
            result = load_json(result_file)
            status = result.get("status")

            if status == "success":
                completed.add(issue_num)
                new_completed += 1
            elif status == "already_resolved":
                # Treat already_resolved as completed (issue doesn't need work)
                completed.add(issue_num)
                new_already_resolved += 1
            else:
                failed.add(issue_num)
                new_failed += 1
        else:
            # No result file - assume failed (agent crashed without writing)
            log_warning(f"No result file for #{issue_num} - marking as failed")
            failed.add(issue_num)
            new_failed += 1

    # NOTE: We no longer auto-release wip labels. User must manually remove them
    # after verifying PRs are merged. This prevents issues from appearing
    # "available" while their PRs are still pending review.
    # To release claims manually, use: gh issue edit <num> --remove-label <wip-label>
    if wip_label:
        log_info(f"Keeping wip label '{wip_label}' on issues (manual removal required)")

    # Update manifest
    manifest["completed"] = list(completed)
    manifest["failed"] = list(failed)
    manifest["current_batch"] = []
    manifest.pop("batch_started_at", None)
    manifest.pop("current_wip_label", None)

    save_json(manifest_file, manifest)

    # Output summary
    log_info(f"Batch complete: {new_completed} succeeded, {new_already_resolved} already resolved, {new_failed} failed")
    log_info(f"Total: {len(completed)} completed, {len(failed)} failed")

    # Return counts for skill to parse
    print(f"BATCH_DONE:{new_completed + new_already_resolved}:{new_failed}")


if __name__ == "__main__":
    main()
