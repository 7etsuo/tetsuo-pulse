#!/usr/bin/env python3
"""
Claim a batch of issues for processing and update the manifest.

This script should be called by the skill before spawning agents to track
which issues are currently being worked on. This enables visibility when
running list_available.py or check_status.py --verbose.

Usage:
    python start_batch.py --state-dir DIR --batch-size N

Output:
    JSON list of issue numbers in the claimed batch.

Example:
    $ python start_batch.py --state-dir .claude/issue-state/run-xxx --batch-size 10
    [1298, 1299, 1300, 1301, 1302, 1303, 1304, 1305, 1306, 1307]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Claim a batch of issues and update manifest"
    )
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--batch-size", type=int, default=10,
                        help="Number of issues to claim")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    manifest_file = state_dir / "manifest.json"

    if not manifest_file.exists():
        print("ERROR: manifest.json not found", file=sys.stderr)
        sys.exit(1)

    # Load manifest
    with open(manifest_file) as f:
        manifest = json.load(f)

    # Get lists
    ready = manifest.get("ready", [])
    completed = set(manifest.get("completed", []))
    failed = set(manifest.get("failed", []))
    claimed_by_others = set(manifest.get("claimed_by_others", []))

    # Filter ready list to exclude already processed issues
    available = [n for n in ready
                 if n not in completed
                 and n not in failed
                 and n not in claimed_by_others]

    if not available:
        print("[]")  # Empty batch
        sys.exit(0)

    # Take the batch
    batch = available[:args.batch_size]

    # Update manifest with current batch
    manifest["current_batch"] = batch
    manifest["batch_started_at"] = datetime.now(timezone.utc).isoformat()

    # Save manifest
    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)

    # Output the batch
    print(json.dumps(batch))


if __name__ == "__main__":
    main()
