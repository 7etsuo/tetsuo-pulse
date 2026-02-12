#!/usr/bin/env python3
"""Run a gRPC interop/conformance matrix and emit machine-readable results."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Tuple

DEFAULT_SKIP_PATTERNS = ["[SKIP]", "[SKIPPED]"]
MAX_CAPTURE_CHARS = 12000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run gRPC interop matrix")
    parser.add_argument("--matrix", required=True, help="Path to matrix JSON")
    parser.add_argument(
        "--build-dir",
        default="build",
        help="CMake build directory used by ctest commands",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root for script execution context",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output report JSON path (default: <build-dir>/grpc-interop-report.json)",
    )
    parser.add_argument(
        "--strict-optional",
        action="store_true",
        help="Fail overall run if optional cases fail",
    )
    return parser.parse_args()


def load_matrix(path: Path, stack: Tuple[Path, ...] = ()) -> Dict[str, Any]:
    resolved = path.resolve()
    if resolved in stack:
        chain = " -> ".join(str(p) for p in (stack + (resolved,)))
        raise ValueError(f"Matrix include cycle detected: {chain}")

    with resolved.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Matrix must be an object: {resolved}")

    if "extends" not in data:
        matrix = copy.deepcopy(data)
        matrix["_path"] = str(resolved)
        return matrix

    parent_ref = data.get("extends")
    if not isinstance(parent_ref, str) or not parent_ref:
        raise ValueError(f"Invalid extends field in {resolved}")

    parent = load_matrix(resolved.parent / parent_ref, stack + (resolved,))
    child = copy.deepcopy(data)
    child.pop("extends", None)

    merged = copy.deepcopy(parent)
    parent_cases = list(parent.get("cases", []))
    child_cases = list(child.pop("cases", []))

    for key, value in child.items():
        merged[key] = value

    merged["cases"] = parent_cases + child_cases
    merged["_path"] = str(resolved)
    return merged


def replace_tokens(value: str, tokens: Dict[str, str]) -> str:
    out = value
    for key, token_value in tokens.items():
        out = out.replace("{" + key + "}", token_value)
    return out


def capture_excerpt(text: str) -> str:
    if len(text) <= MAX_CAPTURE_CHARS:
        return text
    return text[:MAX_CAPTURE_CHARS] + "\n...[truncated]"


def case_timeout_seconds(case: Dict[str, Any], default_seconds: int = 300) -> int:
    raw = case.get("timeout_seconds", default_seconds)
    if not isinstance(raw, int) or raw <= 0:
        return default_seconds
    return raw


def find_missing_tools(required_tools: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for tool in required_tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def command_has_skip(output: str, skip_patterns: Iterable[str]) -> bool:
    for pattern in skip_patterns:
        if pattern in output:
            return True
    return False


def run_case(
    case: Dict[str, Any],
    tokens: Dict[str, str],
    repo_root: Path,
    default_skip_patterns: List[str],
) -> Dict[str, Any]:
    case_id = str(case.get("id", ""))
    description = str(case.get("description", ""))
    requirement = str(case.get("requirement", ""))
    optional = bool(case.get("optional", False))
    required_tools = list(case.get("required_tools", []))
    skip_patterns = list(case.get("skip_patterns", default_skip_patterns))

    command = case.get("command")
    if not isinstance(command, list) or not command:
        return {
            "id": case_id,
            "requirement": requirement,
            "description": description,
            "optional": optional,
            "status": "fail",
            "reason": "Invalid or empty command",
            "returncode": None,
            "duration_seconds": 0.0,
            "command": command,
            "stdout": "",
            "stderr": "",
        }

    expanded_cmd = [replace_tokens(str(item), tokens) for item in command]

    missing_tools = find_missing_tools(required_tools)
    if missing_tools:
        return {
            "id": case_id,
            "requirement": requirement,
            "description": description,
            "optional": optional,
            "status": "skipped",
            "reason": "Missing required tools: " + ", ".join(missing_tools),
            "returncode": None,
            "duration_seconds": 0.0,
            "command": expanded_cmd,
            "stdout": "",
            "stderr": "",
        }

    env = os.environ.copy()
    env_overrides = case.get("env", {})
    if isinstance(env_overrides, dict):
        for key, value in env_overrides.items():
            env[str(key)] = replace_tokens(str(value), tokens)

    timeout_seconds = case_timeout_seconds(case)
    started = time.time()

    try:
        proc = subprocess.run(
            expanded_cmd,
            cwd=str(repo_root),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration = time.time() - started
    except subprocess.TimeoutExpired as exc:
        duration = time.time() - started
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return {
            "id": case_id,
            "requirement": requirement,
            "description": description,
            "optional": optional,
            "status": "fail",
            "reason": f"Timed out after {timeout_seconds}s",
            "returncode": None,
            "duration_seconds": round(duration, 3),
            "command": expanded_cmd,
            "stdout": capture_excerpt(stdout),
            "stderr": capture_excerpt(stderr),
        }

    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        status = "fail"
        reason = f"Command exited with code {proc.returncode}"
    elif command_has_skip(combined, skip_patterns):
        status = "skipped"
        reason = "Skip pattern matched"
    else:
        status = "pass"
        reason = "Command exited successfully"

    return {
        "id": case_id,
        "requirement": requirement,
        "description": description,
        "optional": optional,
        "status": status,
        "reason": reason,
        "returncode": proc.returncode,
        "duration_seconds": round(duration, 3),
        "command": expanded_cmd,
        "stdout": capture_excerpt(proc.stdout or ""),
        "stderr": capture_excerpt(proc.stderr or ""),
    }


def main() -> int:
    args = parse_args()

    repo_root = Path(args.repo_root).resolve()
    build_dir = Path(args.build_dir).resolve()
    matrix_path = Path(args.matrix).resolve()

    if args.output:
        output_path = Path(args.output).resolve()
    else:
        output_path = build_dir / "grpc-interop-report.json"

    matrix = load_matrix(matrix_path)
    cases = matrix.get("cases", [])
    if not isinstance(cases, list):
        raise ValueError("Matrix cases must be a list")

    tokens = {
        "repo_root": str(repo_root),
        "build_dir": str(build_dir),
    }

    skip_patterns = list(matrix.get("skip_patterns", DEFAULT_SKIP_PATTERNS))
    started = time.time()
    results: List[Dict[str, Any]] = []

    print(f"Interop profile: {matrix.get('profile', 'unknown')}")
    print(f"Matrix: {matrix_path}")

    for case in cases:
        if not isinstance(case, dict):
            results.append(
                {
                    "id": "<invalid>",
                    "requirement": "",
                    "description": "",
                    "optional": False,
                    "status": "fail",
                    "reason": "Matrix case is not an object",
                    "returncode": None,
                    "duration_seconds": 0.0,
                    "command": [],
                    "stdout": "",
                    "stderr": "",
                }
            )
            print("[FAIL] <invalid> matrix case is not an object")
            continue

        case_result = run_case(case, tokens, repo_root, skip_patterns)
        results.append(case_result)

        status = case_result["status"].upper()
        case_id = case_result.get("id", "<unknown>")
        optional_suffix = " (optional)" if case_result.get("optional") else ""
        reason = case_result.get("reason", "")
        print(f"[{status}] {case_id}{optional_suffix} :: {reason}")

    elapsed = time.time() - started

    pass_count = sum(1 for r in results if r["status"] == "pass")
    fail_count = sum(1 for r in results if r["status"] == "fail")
    skip_count = sum(1 for r in results if r["status"] == "skipped")
    required_fail_count = sum(
        1 for r in results if r["status"] == "fail" and not r.get("optional", False)
    )
    optional_fail_count = sum(
        1 for r in results if r["status"] == "fail" and r.get("optional", False)
    )

    report = {
        "profile": matrix.get("profile", "unknown"),
        "description": matrix.get("description", ""),
        "matrix_path": str(matrix_path),
        "generated_at_unix": int(time.time()),
        "duration_seconds": round(elapsed, 3),
        "summary": {
            "total": len(results),
            "passed": pass_count,
            "failed": fail_count,
            "skipped": skip_count,
            "required_failed": required_fail_count,
            "optional_failed": optional_fail_count,
            "strict_optional": bool(args.strict_optional),
        },
        "cases": results,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    print(
        "Summary: "
        f"pass={pass_count} fail={fail_count} skip={skip_count} "
        f"required_fail={required_fail_count} optional_fail={optional_fail_count}"
    )
    print(f"Report: {output_path}")

    if required_fail_count > 0:
        return 1
    if args.strict_optional and optional_fail_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Fatal: {exc}", file=sys.stderr)
        raise SystemExit(2)
