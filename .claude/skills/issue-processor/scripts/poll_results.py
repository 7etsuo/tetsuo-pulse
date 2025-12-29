#!/usr/bin/env python3
"""
Poll for implementation results and update manifest.

This script is the key to context efficiency - it runs as a subprocess,
monitors result files, and updates state WITHOUT consuming agent context.

Usage:
    python poll_results.py --state-dir DIR --expected 391,392,393 --timeout 600

Output:
    DONE:10/10:8_success:2_failed
    or
    TIMEOUT:7/10:5_success:2_failed
"""

import argparse
import json
import sys
import time
from pathlib import Path


def load_json(path: Path) -> dict:
    """Load JSON file, return empty dict if missing."""
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def save_json(path: Path, data: dict):
    """Save JSON file atomically."""
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    tmp.rename(path)


def main():
    parser = argparse.ArgumentParser(description="Poll for implementation results")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--expected", required=True, help="Comma-separated issue numbers")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    parser.add_argument("--poll-interval", type=int, default=10, help="Poll interval in seconds")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    results_dir = state_dir / "results"
    manifest_path = state_dir / "manifest.json"
    status_path = state_dir / "status.txt"

    # Parse expected issues
    expected = set(int(x.strip()) for x in args.expected.split(",") if x.strip())
    total = len(expected)

    if total == 0:
        print("ERROR:no_expected_issues")
        sys.exit(1)

    # Track completed issues
    completed = set()
    failed = set()

    start_time = time.time()
    last_progress_time = start_time
    last_done_count = 0
    stall_warning_shown = False
    STALL_THRESHOLD = 120  # seconds without progress before warning

    while True:
        # Check for result files
        if results_dir.exists():
            for result_file in results_dir.glob("*.json"):
                try:
                    issue_num = int(result_file.stem)
                except ValueError:
                    continue

                if issue_num not in expected:
                    continue
                if issue_num in completed or issue_num in failed:
                    continue

                # Read result
                try:
                    result = load_json(result_file)
                    if result.get("status") == "success":
                        completed.add(issue_num)
                    else:
                        failed.add(issue_num)
                except Exception:
                    # File might be partially written, retry next iteration
                    continue

        done_count = len(completed) + len(failed)

        # Track progress for stall detection
        if done_count > last_done_count:
            last_progress_time = time.time()
            last_done_count = done_count
            stall_warning_shown = False

        # Update manifest
        manifest = load_json(manifest_path)
        manifest["completed"] = list(set(manifest.get("completed", [])) | completed)
        manifest["failed"] = list(set(manifest.get("failed", [])) | failed)
        manifest["in_progress"] = [i for i in expected if i not in completed and i not in failed]
        save_json(manifest_path, manifest)

        # Update status with stall indicator if needed
        time_since_progress = time.time() - last_progress_time
        if time_since_progress > STALL_THRESHOLD and not stall_warning_shown:
            status_path.write_text(f"STALLED:{done_count}/{total}:no_progress_for_{int(time_since_progress)}s\n")
            stall_warning_shown = True
            print(f"WARNING: No progress for {int(time_since_progress)}s. Agents may have failed.", file=sys.stderr)

            # List which issues are still pending
            pending = [i for i in expected if i not in completed and i not in failed]
            print(f"Pending issues: {pending}", file=sys.stderr)

            # Check which agents have started (wrote started marker)
            started_dir = state_dir / "started"
            if started_dir.exists():
                started_issues = set()
                for started_file in started_dir.glob("*.json"):
                    try:
                        started_issues.add(int(started_file.stem))
                    except ValueError:
                        continue

                started_but_pending = started_issues & set(pending)
                not_started = set(pending) - started_issues

                if started_but_pending:
                    print(f"Started but no result: {sorted(started_but_pending)}", file=sys.stderr)
                if not_started:
                    print(f"Never started: {sorted(not_started)}", file=sys.stderr)
        else:
            status_path.write_text(f"RUNNING:{done_count}/{total}\n")

        # Check if all done
        if done_count >= total:
            final_status = f"DONE:{total}/{total}:{len(completed)}_success:{len(failed)}_failed"
            status_path.write_text(f"COMPLETED:{total}/{total}:{len(completed)}_success:{len(failed)}_failed\n")
            print(final_status)
            sys.exit(0)

        # Check timeout
        elapsed = time.time() - start_time
        if elapsed >= args.timeout:
            final_status = f"TIMEOUT:{done_count}/{total}:{len(completed)}_success:{len(failed)}_failed"
            print(final_status)
            sys.exit(1)

        # Progress output (for visibility)
        remaining = total - done_count
        print(f"[{int(elapsed)}s] Waiting for {remaining} results... ({done_count}/{total} done)", file=sys.stderr)

        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
