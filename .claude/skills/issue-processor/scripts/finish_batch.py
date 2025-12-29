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
"""

import argparse
import json
import sys
from pathlib import Path


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
        print("ERROR: manifest.json not found", file=sys.stderr)
        sys.exit(1)

    # Load manifest
    with open(manifest_file) as f:
        manifest = json.load(f)

    current_batch = manifest.get("current_batch", [])
    if not current_batch:
        print("No current batch to finish")
        sys.exit(0)

    completed = set(manifest.get("completed", []))
    failed = set(manifest.get("failed", []))

    # Check result files for each issue in batch
    new_completed = 0
    new_failed = 0

    for issue_num in current_batch:
        result_file = results_dir / f"{issue_num}.json"
        if result_file.exists():
            with open(result_file) as f:
                result = json.load(f)

            if result.get("status") == "success":
                completed.add(issue_num)
                new_completed += 1
            else:
                failed.add(issue_num)
                new_failed += 1
        else:
            # No result file - assume failed (agent crashed without writing)
            failed.add(issue_num)
            new_failed += 1

    # Update manifest
    manifest["completed"] = list(completed)
    manifest["failed"] = list(failed)
    manifest["current_batch"] = []  # Clear the batch
    manifest.pop("batch_started_at", None)

    # Save manifest
    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)

    # Output summary
    print(f"Batch complete: {new_completed} succeeded, {new_failed} failed")
    print(f"Total: {len(completed)} completed, {len(failed)} failed")


if __name__ == "__main__":
    main()
