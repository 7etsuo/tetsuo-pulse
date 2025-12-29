#!/usr/bin/env python3
"""
Check pipeline status by reading status.txt and manifest.json.
Prints a simple status line for the skill to parse.

Usage:
    python check_status.py --state-dir DIR

Output (one of):
    READY:5/20                              - Setup complete, ready to start
    RUNNING:5/20                            - Processing in progress
    STALLED:3/20:no_progress_for_120s       - No results for 120+ seconds
    COMPLETED:20/20:18_success:2_fail       - All issues processed
    ERROR:message                           - Error occurred

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
    args = parser.parse_args()

    state_dir = Path(args.state_dir)

    # Check if state directory exists
    if not state_dir.exists():
        print("ERROR:state_directory_not_found")
        sys.exit(1)

    # Read status.txt if it exists
    status_file = state_dir / "status.txt"
    if status_file.exists():
        status = status_file.read_text().strip()
        print(status)
        sys.exit(0)

    # Fall back to reading manifest
    manifest_file = state_dir / "manifest.json"
    if not manifest_file.exists():
        print("ERROR:manifest_not_found")
        sys.exit(1)

    with open(manifest_file) as f:
        manifest = json.load(f)

    total = manifest.get("total_issues", 0)
    completed = len(manifest.get("completed", []))
    failed = len(manifest.get("failed", []))
    in_progress = len(manifest.get("in_progress", []))

    if completed + failed == total and total > 0:
        print(f"COMPLETED:{total}/{total}:{completed}_success:{failed}_failed")
    elif in_progress > 0:
        done = completed + failed
        print(f"RUNNING:{done}/{total}")
    else:
        ready = len(manifest.get("ready", []))
        print(f"READY:{ready}/{total}")


if __name__ == "__main__":
    main()
