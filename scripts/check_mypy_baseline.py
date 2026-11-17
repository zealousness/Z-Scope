#!/usr/bin/env python3
"""Fail when mypy introduces errors outside the reviewed legacy baseline."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Counter as CounterType

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "requirements" / "mypy-baseline.json"
ERROR_RE = re.compile(r"^(.*?):\d+(?::\d+)?: error: (.*)$")


def _collect() -> tuple[int, CounterType[str], str]:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "zscope",
            "--no-error-summary",
            "--show-error-codes",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    errors: CounterType[str] = Counter()
    for line in completed.stdout.splitlines():
        match = ERROR_RE.match(line)
        if match:
            path, message = match.groups()
            message = re.sub(r"\bline \d+\b", "line <N>", message)
            errors[f"{path.replace(chr(92), '/')} :: {message}"] += 1
    return completed.returncode, errors, completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="accept the current reviewed debt")
    args = parser.parse_args()

    returncode, current, output = _collect()
    if returncode not in {0, 1}:
        print(output, file=sys.stderr)
        return returncode

    if args.update:
        payload = {
            "schema_version": "zscope.mypy-debt-baseline.v1",
            "python_target": "3.9",
            "error_count": sum(current.values()),
            "errors": dict(sorted(current.items())),
        }
        BASELINE.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"updated {BASELINE.relative_to(ROOT)} with {sum(current.values())} errors")
        return 0

    payload = json.loads(BASELINE.read_text(encoding="utf-8"))
    accepted: CounterType[str] = Counter(payload["errors"])
    additions = current - accepted
    if additions:
        print("mypy introduced errors outside the reviewed baseline:", file=sys.stderr)
        for message, count in sorted(additions.items()):
            print(f"  {count}x {message}", file=sys.stderr)
        return 1

    resolved = sum(accepted.values()) - sum(current.values())
    print(
        f"mypy debt gate passed: {sum(current.values())} accepted errors"
        + (f", {resolved} baseline occurrences resolved" if resolved else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
