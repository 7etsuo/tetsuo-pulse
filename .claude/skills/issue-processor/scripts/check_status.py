#!/usr/bin/env python3
"""
Check pipeline status by reading status.txt and manifest.json.
Prints a simple status line for the skill to parse.

Usage:
    python check_status.py --state-dir DIR [--verbose]

Output (one of):
    READY:5/20                              - Setup complete, ready to start
    RUNNING:5/20                            - Processing in progress
    STALLED:3/20:no_progress_for_120s       - No results for 120+ seconds
    COMPLETED:20/20:18_success:2_fail       - All issues processed
    ERROR:message                           - Error occurred

With --verbose, also shows:
    - Current batch issue numbers
    - Completed issue numbers
    - Failed issue numbers

Note: STALLED indicates agents may have failed without writing result files.
Check agent logs or manually inspect issues with wip:* labels.
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Check pipeline status")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed batch information")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)

    # Check if state directory exists
    if not state_dir.exists():
        print("ERROR:state_directory_not_found")
        sys.exit(1)

    # Read status.txt if it exists
    status_file = state_dir / "status.txt"
    status_line = None
    if status_file.exists():
        status_line = status_file.read_text().strip()
        if not args.verbose:
            print(status_line)
            sys.exit(0)

    # Read manifest for details
    manifest_file = state_dir / "manifest.json"
    if not manifest_file.exists():
        print("ERROR:manifest_not_found")
        sys.exit(1)

    with open(manifest_file) as f:
        manifest = json.load(f)

    total = manifest.get("total_issues", 0)
    completed = manifest.get("completed", [])
    failed = manifest.get("failed", [])
    in_progress = manifest.get("in_progress", [])
    current_batch = manifest.get("current_batch", [])
    ready = manifest.get("ready", [])

    # Determine status if we don't have status.txt
    if not status_line:
        if len(completed) + len(failed) == total and total > 0:
            status_line = f"COMPLETED:{total}/{total}:{len(completed)}_success:{len(failed)}_failed"
        elif len(in_progress) > 0 or len(current_batch) > 0:
            done = len(completed) + len(failed)
            status_line = f"RUNNING:{done}/{total}"
        else:
            status_line = f"READY:{len(ready)}/{total}"

    if not args.verbose:
        print(status_line)
        sys.exit(0)

    # Verbose output
    print(f"Status: {status_line}")
    print(f"Run ID: {manifest.get('run_id', 'unknown')}")
    print(f"Repository: {manifest.get('repository', 'unknown')}")
    print()

    if current_batch:
        print(f"Current batch ({len(current_batch)} issues):")
        print(f"  {', '.join(f'#{n}' for n in sorted(current_batch))}")
        print()

    if completed:
        print(f"Completed ({len(completed)} issues):")
        # Show in groups of 10
        sorted_completed = sorted(completed)
        for i in range(0, len(sorted_completed), 10):
            chunk = sorted_completed[i:i+10]
            print(f"  {', '.join(f'#{n}' for n in chunk)}")
        print()

    if failed:
        print(f"Failed ({len(failed)} issues):")
        print(f"  {', '.join(f'#{n}' for n in sorted(failed))}")
        print()

    remaining_ready = [n for n in ready if n not in completed and n not in failed and n not in current_batch]
    if remaining_ready:
        print(f"Remaining ready ({len(remaining_ready)} issues):")
        print(f"  First 10: {', '.join(f'#{n}' for n in sorted(remaining_ready)[:10])}")
        if len(remaining_ready) > 10:
            print(f"  ... and {len(remaining_ready) - 10} more")


if __name__ == "__main__":
    main()
