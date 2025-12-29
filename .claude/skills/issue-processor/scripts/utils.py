#!/usr/bin/env python3
"""
Shared utilities for issue-processor scripts.

This module provides consistent implementations of common operations:
- GitHub CLI (gh) wrapper with proper error handling
- Git command wrapper
- Atomic JSON file operations
- Input validation

All scripts should import from this module instead of implementing their own.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class GitHubAPIError(Exception):
    """Raised when GitHub API call fails."""
    pass


class GitError(Exception):
    """Raised when git command fails."""
    pass


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def run_gh(
    args: list[str],
    check: bool = True,
    capture_output: bool = True
) -> tuple[bool, str]:
    """
    Run gh CLI command with consistent error handling.

    Args:
        args: Arguments to pass to gh command
        check: If True, raise GitHubAPIError on failure
        capture_output: If True, capture stdout/stderr

    Returns:
        Tuple of (success: bool, output: str)

    Raises:
        GitHubAPIError: If check=True and command fails
    """
    result = subprocess.run(
        ["gh"] + args,
        capture_output=capture_output,
        text=True
    )

    output = result.stdout.strip() if result.stdout else ""
    error = result.stderr.strip() if result.stderr else ""

    if result.returncode != 0:
        if check:
            raise GitHubAPIError(f"gh {' '.join(args[:2])}: {error or output}")
        return False, error or output

    return True, output


def run_git(
    args: list[str],
    cwd: str | Path | None = None,
    check: bool = False
) -> tuple[bool, str]:
    """
    Run git command with consistent error handling.

    Args:
        args: Arguments to pass to git command
        cwd: Working directory for command
        check: If True, raise GitError on failure

    Returns:
        Tuple of (success: bool, output: str)

    Raises:
        GitError: If check=True and command fails
    """
    result = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None
    )

    output = result.stdout.strip() or result.stderr.strip()

    if result.returncode != 0:
        if check:
            raise GitError(f"git {args[0]}: {output}")
        return False, output

    return True, output


def load_json(path: Path, default: Any = None) -> Any:
    """
    Load JSON file with error handling.

    Args:
        path: Path to JSON file
        default: Value to return if file doesn't exist (None raises error)

    Returns:
        Parsed JSON data

    Raises:
        FileNotFoundError: If file doesn't exist and no default provided
        json.JSONDecodeError: If file contains invalid JSON
    """
    if not path.exists():
        if default is not None:
            return default
        raise FileNotFoundError(f"JSON file not found: {path}")

    with open(path) as f:
        return json.load(f)


def save_json(path: Path, data: Any, indent: int = 2) -> None:
    """
    Save JSON file atomically using tmp file + rename pattern.

    This ensures the file is never partially written, which could
    cause corruption if the process is interrupted.

    Args:
        path: Destination path for JSON file
        data: Data to serialize as JSON
        indent: Indentation level for pretty printing
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write to temporary file first
    tmp_path = path.with_suffix('.tmp')
    with open(tmp_path, 'w') as f:
        json.dump(data, f, indent=indent)

    # Atomic rename
    tmp_path.rename(path)


def validate_repo_format(repo: str) -> tuple[str, str]:
    """
    Validate and parse repository format.

    Args:
        repo: Repository string in "owner/name" format

    Returns:
        Tuple of (owner, repo_name)

    Raises:
        ValidationError: If format is invalid
    """
    if not repo or "/" not in repo:
        raise ValidationError(
            f"Invalid repository format: '{repo}'. Expected 'owner/repo'"
        )

    parts = repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValidationError(
            f"Invalid repository format: '{repo}'. Expected 'owner/repo'"
        )

    return parts[0], parts[1]


def get_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def get_repo_root() -> Path | None:
    """
    Get the git repository root directory.

    Returns:
        Path to repo root, or None if not in a git repo
    """
    success, output = run_git(["rev-parse", "--show-toplevel"])
    if not success:
        return None
    return Path(output)


def format_issue_list(issues: list[int], max_display: int = 10) -> str:
    """
    Format a list of issue numbers for display.

    Args:
        issues: List of issue numbers
        max_display: Maximum issues to show before truncating

    Returns:
        Formatted string like "#1, #2, #3, ... and 5 more"
    """
    if not issues:
        return "(none)"

    sorted_issues = sorted(issues)

    if len(sorted_issues) <= max_display:
        return ", ".join(f"#{n}" for n in sorted_issues)

    shown = sorted_issues[:max_display]
    remaining = len(sorted_issues) - max_display
    return f"{', '.join(f'#{n}' for n in shown)}, ... and {remaining} more"


def log_info(message: str) -> None:
    """Log info message to stderr."""
    print(f"[INFO] {message}", file=sys.stderr)


def log_warning(message: str) -> None:
    """Log warning message to stderr."""
    print(f"[WARN] {message}", file=sys.stderr)


def log_error(message: str) -> None:
    """Log error message to stderr."""
    print(f"[ERROR] {message}", file=sys.stderr)


# Status constants for consistency across scripts
STATUS_READY = "READY"
STATUS_RUNNING = "RUNNING"
STATUS_STALLED = "STALLED"
STATUS_COMPLETED = "COMPLETED"
STATUS_ERROR = "ERROR"


def format_status(
    status: str,
    done: int,
    total: int,
    extra: str | None = None
) -> str:
    """
    Format status string consistently.

    Args:
        status: One of STATUS_* constants
        done: Number of completed items
        total: Total number of items
        extra: Optional extra info (e.g., "5_success:2_failed")

    Returns:
        Formatted status string like "COMPLETED:7/10:5_success:2_failed"
    """
    base = f"{status}:{done}/{total}"
    if extra:
        return f"{base}:{extra}"
    return base
