#!/usr/bin/env python3
"""
Poll for implementation results and update manifest.

This script is the key to context efficiency - it runs as a subprocess,
monitors result files, and updates state WITHOUT consuming agent context.

Usage:
    python poll_results.py --state-dir DIR --expected 391,392,393 --timeout 600

Options:
    --stall-threshold N    Seconds without progress before STALLED warning (default: 120)
    --poll-interval N      Seconds between polls (default: 10)
    --timeout N            Total timeout in seconds (default: 600)

Output:
    DONE:10/10:8_success:2_failed
    or
    TIMEOUT:7/10:5_success:2_failed

Status file (status.txt) values:
    RUNNING:done/total     - Active processing
    STALLED:done/total:... - No progress for stall-threshold seconds
    COMPLETED:done/total:... - All issues finished
"""

import argparse
import sys
import time
from pathlib import Path

from utils import (
    load_json,
    save_json,
    log_info,
    log_warning,
    STATUS_RUNNING,
    STATUS_STALLED,
    STATUS_COMPLETED,
)


def main():
    parser = argparse.ArgumentParser(description="Poll for implementation results")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--expected", required=True, help="Comma-separated issue numbers")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    parser.add_argument("--poll-interval", type=int, default=10,
                        help="Poll interval in seconds (default: 10)")
    parser.add_argument("--stall-threshold", type=int, default=120,
                        help="Seconds without progress before STALLED warning (default: 120)")
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
    already_resolved = set()

    start_time = time.time()
    last_progress_time = start_time
    last_done_count = 0
    stall_warning_shown = False

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
                if issue_num in completed or issue_num in failed or issue_num in already_resolved:
                    continue

                # Read result
                try:
                    result = load_json(result_file)
                    status = result.get("status")
                    if status == "success":
                        completed.add(issue_num)
                    elif status == "already_resolved":
                        already_resolved.add(issue_num)
                    else:
                        failed.add(issue_num)
                except Exception:
                    # File might be partially written, retry next iteration
                    continue

        done_count = len(completed) + len(failed) + len(already_resolved)

        # Track progress for stall detection
        if done_count > last_done_count:
            last_progress_time = time.time()
            last_done_count = done_count
            stall_warning_shown = False

        # Update manifest
        manifest = load_json(manifest_path)
        manifest["completed"] = list(set(manifest.get("completed", [])) | completed | already_resolved)
        manifest["failed"] = list(set(manifest.get("failed", [])) | failed)
        manifest["in_progress"] = [i for i in expected if i not in completed
                                    and i not in failed and i not in already_resolved]
        save_json(manifest_path, manifest)

        # Update status with stall indicator if needed
        time_since_progress = time.time() - last_progress_time
        if time_since_progress > args.stall_threshold and not stall_warning_shown:
            status_path.write_text(
                f"{STATUS_STALLED}:{done_count}/{total}:no_progress_for_{int(time_since_progress)}s\n"
            )
            stall_warning_shown = True
            log_warning(f"No progress for {int(time_since_progress)}s. Agents may have failed.")

            # List which issues are still pending
            pending = [i for i in expected if i not in completed
                       and i not in failed and i not in already_resolved]
            log_info(f"Pending issues: {pending}")

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
                    log_info(f"Started but no result: {sorted(started_but_pending)}")
                if not_started:
                    log_info(f"Never started: {sorted(not_started)}")
        else:
            status_path.write_text(f"{STATUS_RUNNING}:{done_count}/{total}\n")

        # Check if all done
        if done_count >= total:
            success_count = len(completed) + len(already_resolved)
            final_status = f"COMPLETED:{total}/{total}:{success_count}_success:{len(failed)}_failed"
            status_path.write_text(f"{STATUS_COMPLETED}:{total}/{total}:{success_count}_success:{len(failed)}_failed\n")
            print(final_status)
            sys.exit(0)

        # Check timeout
        elapsed = time.time() - start_time
        if elapsed >= args.timeout:
            success_count = len(completed) + len(already_resolved)
            final_status = f"TIMEOUT:{done_count}/{total}:{success_count}_success:{len(failed)}_failed"
            print(final_status)
            sys.exit(1)

        # Progress output (for visibility)
        remaining = total - done_count
        log_info(f"[{int(elapsed)}s] Waiting for {remaining} results... ({done_count}/{total} done)")

        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
