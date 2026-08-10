#!/usr/bin/env python3
"""Require new Python files to be formatted and lock legacy formatting debt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "requirements" / "black-baseline.json"
SCOPES = ("zscope", "scripts", "test", "tests", "tools")
REFORMAT_RE = re.compile(r"^would reformat (.+)$")


def _digest(path: Path) -> str:
    # GitHub checks out repository text with LF; normalize Windows worktrees so
    # the reviewed debt hash is stable across runner operating systems.
    content = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def _collect() -> tuple[int, dict[str, str], str]:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "black",
            "--check",
            "--target-version",
            "py39",
            *SCOPES,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    unformatted: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        match = REFORMAT_RE.match(line.strip())
        if not match:
            continue
        path = Path(match.group(1)).resolve()
        relative = path.relative_to(ROOT).as_posix()
        unformatted[relative] = _digest(path)
    return completed.returncode, unformatted, completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="accept current legacy file hashes")
    args = parser.parse_args()

    returncode, current, output = _collect()
    if returncode not in {0, 1}:
        print(output, file=sys.stderr)
        return returncode

    if args.update:
        payload = {
            "schema_version": "zscope.black-debt-baseline.v1",
            "target_version": "py39",
            "unformatted_files": dict(sorted(current.items())),
        }
        BASELINE.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"updated {BASELINE.relative_to(ROOT)} with {len(current)} legacy files")
        return 0

    payload = json.loads(BASELINE.read_text(encoding="utf-8"))
    accepted = payload["unformatted_files"]
    violations = {
        path: digest
        for path, digest in current.items()
        if path not in accepted or accepted[path] != digest
    }
    if violations:
        print("Black formatting debt changed or was introduced:", file=sys.stderr)
        for path in sorted(violations):
            reason = "new file" if path not in accepted else "modified legacy file"
            print(f"  {path} ({reason})", file=sys.stderr)
        print(
            "Run Black on the listed files; do not expand the baseline for routine changes.",
            file=sys.stderr,
        )
        return 1

    resolved = len(set(accepted) - set(current))
    print(
        f"Black debt gate passed: {len(current)} unchanged legacy files"
        + (f", {resolved} files resolved" if resolved else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
