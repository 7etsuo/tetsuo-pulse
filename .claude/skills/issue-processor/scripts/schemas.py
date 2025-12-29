#!/usr/bin/env python3
"""
JSON schema validation for issue-processor data files.

Provides validation functions for:
- Result files (results/{issue}.json)
- Manifest files (manifest.json)
- Frontier files (frontier.json)

Uses simple validation (no external dependencies) with clear error messages.
"""

from typing import Any


class SchemaValidationError(Exception):
    """Raised when data doesn't match expected schema."""
    pass


def _check_type(data: Any, expected_type: type, field_name: str) -> None:
    """Check that data is of expected type."""
    if not isinstance(data, expected_type):
        actual = type(data).__name__
        expected = expected_type.__name__
        raise SchemaValidationError(
            f"Field '{field_name}' expected {expected}, got {actual}"
        )


def _check_required(data: dict, field_name: str) -> Any:
    """Check that required field exists and return its value."""
    if field_name not in data:
        raise SchemaValidationError(f"Missing required field: '{field_name}'")
    return data[field_name]


def _check_one_of(value: Any, allowed: list, field_name: str) -> None:
    """Check that value is one of allowed values."""
    if value not in allowed:
        raise SchemaValidationError(
            f"Field '{field_name}' must be one of {allowed}, got '{value}'"
        )


def validate_result(data: Any, issue_num: int | None = None) -> dict:
    """
    Validate a result file (results/{issue}.json).

    Required fields:
        - issue: int
        - status: "success" | "failed" | "already_resolved"

    For status="success":
        - pr_url: str (required)
        - pr_number: int (optional)
        - branch: str (optional)
        - files_changed: list[str] (optional)
        - tests_passed: bool (optional)
        - commit_sha: str (optional)
        - completed_at: str (optional)

    For status="failed":
        - error: str (required, max 200 chars recommended)
        - stage: str (optional)
        - details: str (optional)
        - partial_work: dict (optional)
        - failed_at: str (optional)

    For status="already_resolved":
        - resolution: str (optional)

    Args:
        data: Parsed JSON data to validate
        issue_num: Expected issue number (optional, for cross-validation)

    Returns:
        Validated data dict

    Raises:
        SchemaValidationError: If validation fails
    """
    _check_type(data, dict, "result")

    # Required fields
    issue = _check_required(data, "issue")
    _check_type(issue, int, "issue")

    status = _check_required(data, "status")
    _check_type(status, str, "status")
    _check_one_of(status, ["success", "failed", "already_resolved"], "status")

    # Cross-validation
    if issue_num is not None and issue != issue_num:
        raise SchemaValidationError(
            f"Issue number mismatch: file says {issue}, expected {issue_num}"
        )

    # Status-specific validation
    if status == "success":
        pr_url = _check_required(data, "pr_url")
        _check_type(pr_url, str, "pr_url")
        if not pr_url.startswith("https://"):
            raise SchemaValidationError(
                f"Field 'pr_url' must be a valid URL, got '{pr_url}'"
            )

    elif status == "failed":
        error = _check_required(data, "error")
        _check_type(error, str, "error")
        if len(error) > 500:
            # Warning, not error - just truncate for display
            data["error"] = error[:497] + "..."

    # already_resolved has no required fields beyond issue and status

    return data


def validate_manifest(data: Any) -> dict:
    """
    Validate a manifest file (manifest.json).

    Required fields:
        - run_id: str
        - repository: str (owner/repo format)
        - ready: list[int]

    Optional fields:
        - version: int
        - label_filter: str | None
        - created_at: str
        - total_issues: int
        - blocked: dict[str, list[int]]
        - completed: list[int]
        - failed: list[int]
        - in_progress: list[int]
        - current_batch: list[int]
        - batch_started_at: str
        - claimed_by_others: list[int]

    Args:
        data: Parsed JSON data to validate

    Returns:
        Validated data dict with defaults filled in

    Raises:
        SchemaValidationError: If validation fails
    """
    _check_type(data, dict, "manifest")

    # Required fields
    run_id = _check_required(data, "run_id")
    _check_type(run_id, str, "run_id")

    repository = _check_required(data, "repository")
    _check_type(repository, str, "repository")
    if "/" not in repository:
        raise SchemaValidationError(
            f"Field 'repository' must be 'owner/repo' format, got '{repository}'"
        )

    ready = _check_required(data, "ready")
    _check_type(ready, list, "ready")
    for i, item in enumerate(ready):
        if not isinstance(item, int):
            raise SchemaValidationError(
                f"Field 'ready[{i}]' must be int, got {type(item).__name__}"
            )

    # Validate optional list[int] fields
    for field in ["completed", "failed", "in_progress", "current_batch", "claimed_by_others"]:
        if field in data:
            _check_type(data[field], list, field)
            for i, item in enumerate(data[field]):
                if not isinstance(item, int):
                    raise SchemaValidationError(
                        f"Field '{field}[{i}]' must be int, got {type(item).__name__}"
                    )

    # Fill in defaults for optional fields
    data.setdefault("completed", [])
    data.setdefault("failed", [])
    data.setdefault("in_progress", [])
    data.setdefault("current_batch", [])
    data.setdefault("claimed_by_others", [])

    return data


def validate_frontier(data: Any) -> dict:
    """
    Validate a frontier file (frontier.json).

    Required fields:
        - ready: list[int]
        - blocked: dict[str, list[int]]

    Args:
        data: Parsed JSON data to validate

    Returns:
        Validated data dict

    Raises:
        SchemaValidationError: If validation fails
    """
    _check_type(data, dict, "frontier")

    # Ready list
    ready = _check_required(data, "ready")
    _check_type(ready, list, "ready")
    for i, item in enumerate(ready):
        if not isinstance(item, int):
            raise SchemaValidationError(
                f"Field 'ready[{i}]' must be int, got {type(item).__name__}"
            )

    # Blocked dict
    blocked = _check_required(data, "blocked")
    _check_type(blocked, dict, "blocked")
    for key, deps in blocked.items():
        # Keys are string representations of issue numbers
        try:
            int(key)
        except ValueError:
            raise SchemaValidationError(
                f"Field 'blocked' key must be numeric string, got '{key}'"
            )

        if not isinstance(deps, list):
            raise SchemaValidationError(
                f"Field 'blocked[{key}]' must be list, got {type(deps).__name__}"
            )

        for i, dep in enumerate(deps):
            if not isinstance(dep, int):
                raise SchemaValidationError(
                    f"Field 'blocked[{key}][{i}]' must be int, got {type(dep).__name__}"
                )

    return data


def validate_issue(data: Any) -> dict:
    """
    Validate an issue file (issues/{num}.json).

    Required fields:
        - number: int
        - title: str

    Optional fields:
        - body: str
        - labels: list[str]
        - state: str
        - dependencies: list[int]

    Args:
        data: Parsed JSON data to validate

    Returns:
        Validated data dict

    Raises:
        SchemaValidationError: If validation fails
    """
    _check_type(data, dict, "issue")

    # Required fields
    number = _check_required(data, "number")
    _check_type(number, int, "number")

    title = _check_required(data, "title")
    _check_type(title, str, "title")

    # Optional fields with type validation
    if "body" in data:
        _check_type(data["body"], str, "body")

    if "labels" in data:
        _check_type(data["labels"], list, "labels")
        for i, label in enumerate(data["labels"]):
            if not isinstance(label, str):
                raise SchemaValidationError(
                    f"Field 'labels[{i}]' must be str, got {type(label).__name__}"
                )

    if "dependencies" in data:
        _check_type(data["dependencies"], list, "dependencies")
        for i, dep in enumerate(data["dependencies"]):
            if not isinstance(dep, int):
                raise SchemaValidationError(
                    f"Field 'dependencies[{i}]' must be int, got {type(dep).__name__}"
                )

    # Fill defaults
    data.setdefault("body", "")
    data.setdefault("labels", [])
    data.setdefault("dependencies", [])

    return data
