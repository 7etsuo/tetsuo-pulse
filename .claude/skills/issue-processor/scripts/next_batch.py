#!/usr/bin/env python3
"""
Get the next batch of issues to process with their worktree paths.

Reads manifest.json to find ready issues that haven't been completed,
failed, or are in progress. Creates git worktrees for parallel development.

Usage:
    python next_batch.py --state-dir DIR --batch-size N [--create-worktrees]

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
import subprocess
import sys
from pathlib import Path


def run_git(args: list[str], cwd: str | None = None) -> tuple[bool, str]:
    """Run git command and return (success, output)."""
    result = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        cwd=cwd
    )
    return result.returncode == 0, result.stdout.strip() or result.stderr.strip()


def get_repo_root() -> Path:
    """Get the git repository root directory."""
    success, output = run_git(["rev-parse", "--show-toplevel"])
    if not success:
        print("ERROR: Not in a git repository", file=sys.stderr)
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
        import shutil
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

    print(f"Warning: Failed to create worktree for #{issue_num}: {output}", file=sys.stderr)
    return None


def main():
    parser = argparse.ArgumentParser(description="Get next batch of issues with worktree paths")
    parser.add_argument("--state-dir", required=True, help="State directory path")
    parser.add_argument("--batch-size", type=int, default=5, help="Maximum issues in batch")
    parser.add_argument("--create-worktrees", action="store_true",
                        help="Create git worktrees for each issue")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)

    # Load manifest
    manifest_path = state_dir / "manifest.json"
    if not manifest_path.exists():
        print(json.dumps({"error": "manifest_not_found", "batch": [], "remaining": 0}))
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    # Get sets of processed issues
    completed = set(manifest.get("completed", []))
    failed = set(manifest.get("failed", []))
    in_progress = set(manifest.get("in_progress", []))
    processed = completed | failed | in_progress

    # Get ready issues that haven't been processed
    ready = [i for i in manifest.get("ready", []) if i not in processed]

    # Take batch
    batch_issues = ready[:args.batch_size]
    remaining = len(ready) - len(batch_issues)

    # Get repo root for worktree creation
    repo_root = get_repo_root()
    repo_name = manifest.get("repository", "unknown/repo").split("/")[-1]

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

    # Update manifest with in_progress
    manifest["in_progress"] = list(in_progress | set(batch_issues))
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # Output result
    result = {
        "batch": batch,
        "remaining": remaining,
        "total_ready": len(manifest.get("ready", [])),
        "completed": len(completed),
        "failed": len(failed)
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
