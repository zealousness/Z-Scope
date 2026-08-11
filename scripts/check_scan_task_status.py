#!/usr/bin/env python3
"""Check whether a Z-SCOPE scan task has reached a terminal log marker."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Sequence


COMPLETE_MARKERS = (
    "Batch Analysis Complete.",
    "Analysis Complete.",
)
FAILED_MARKERS = (
    "Analysis failed:",
    "Traceback (most recent call last):",
)
INTERRUPTED_MARKERS = (
    "[!] Exiting immediately due to prior interrupt.",
    "Use --resume to continue from the last checkpoint.",
    "Interrupted entries: unknown",
)

EXIT_CODES = {
    "complete": 0,
    "running": 1,
    "failed": 2,
    "interrupted": 3,
    "not_found": 4,
    "missing_log": 5,
}


def detect_scan_status(log_text: str, *, task_id: str = "") -> dict[str, Any]:
    text = str(log_text or "")
    task = str(task_id or "").strip()
    if task and f"Task ID: {task}" not in text:
        return {
            "status": "not_found",
            "done": False,
            "task_id": task,
            "reason": "task_id marker not found in log",
        }

    interrupted = any(marker in text for marker in INTERRUPTED_MARKERS)
    if interrupted and "Interrupted entries: none." not in text:
        return _result("interrupted", True, task, "interrupted marker found")

    if any(marker in text for marker in FAILED_MARKERS):
        return _result("failed", True, task, "failure marker found")

    if any(marker in text for marker in COMPLETE_MARKERS):
        return _result("complete", True, task, "completion marker found")

    return _result("running", False, task, "no terminal marker found")


def _result(status: str, done: bool, task_id: str, reason: str) -> dict[str, Any]:
    return {
        "status": status,
        "done": done,
        "task_id": task_id,
        "reason": reason,
    }


def _read_log(path: Path) -> tuple[str, dict[str, Any] | None]:
    try:
        return path.read_text(encoding="utf-8", errors="replace"), None
    except FileNotFoundError:
        return "", {
            "status": "missing_log",
            "done": False,
            "task_id": "",
            "reason": f"log file not found: {path}",
        }


def check_log(path: Path, *, task_id: str = "") -> dict[str, Any]:
    text, error = _read_log(path)
    if error is not None:
        error["task_id"] = str(task_id or "").strip()
        return error
    return detect_scan_status(text, task_id=task_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="Z-SCOPE scan log path.")
    parser.add_argument("--task-id", default="", help="Optional task ID marker to match in the log.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--watch", action="store_true", help="Poll until a terminal status or timeout.")
    parser.add_argument("--interval", type=float, default=5.0, help="Watch polling interval in seconds.")
    parser.add_argument("--timeout", type=float, default=0.0, help="Watch timeout in seconds; 0 means no timeout.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    started = time.monotonic()

    while True:
        result = check_log(args.log, task_id=args.task_id)
        if result["done"] or not args.watch:
            return _emit(result, json_output=args.json)
        if args.timeout and time.monotonic() - started >= args.timeout:
            result = dict(result)
            result["reason"] = f"{result['reason']}; watch timeout reached"
            return _emit(result, json_output=args.json)
        time.sleep(max(0.1, float(args.interval or 0.1)))


def _emit(result: dict[str, Any], *, json_output: bool) -> int:
    status = str(result.get("status") or "running")
    if json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"status={status} done={str(bool(result.get('done'))).lower()} reason={result.get('reason', '')}")
    return EXIT_CODES.get(status, 1)


if __name__ == "__main__":
    raise SystemExit(main())
