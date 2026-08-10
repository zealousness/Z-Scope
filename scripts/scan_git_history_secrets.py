#!/usr/bin/env python3
"""High-confidence secret/private-endpoint scan without printing secret values."""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, Tuple

PATTERNS: Dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "openai_style_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "private_ipv4_endpoint": re.compile(
        r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)"
    ),
}


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(
        marker in lowered
        for marker in (
            "example",
            "your",
            "placeholder",
            "dummy",
            "fake",
            "test",
            "benchmark",
            "xxxx",
        )
    ):
        return True
    if not value:
        return True
    counts = {char: value.count(char) for char in set(value)}
    entropy = -sum(
        (count / len(value)) * math.log2(count / len(value)) for count in counts.values()
    )
    return entropy < 3.5


def _is_finding(kind: str, pattern: re.Pattern[str], text: str) -> bool:
    match = pattern.search(text)
    if not match:
        return False
    if kind == "private_key":
        return text.strip() == match.group(0)
    if kind in {"openai_style_key", "github_token"}:
        return not _looks_like_placeholder(match.group(0))
    return True


def _lines(commit: str) -> Iterable[Tuple[str, int, str]]:
    command = ["git", "grep", "-I", "-n", "-E", "BEGIN |AKIA|gh[pousr]_|sk-|https?://"]
    if commit:
        command.append(commit)
    else:
        command.insert(2, "--untracked")
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or f"git grep failed for {commit}")
    for raw in proc.stdout.splitlines():
        parts = raw.split(":", 3 if commit else 2)
        if commit and len(parts) == 4 and parts[2].isdigit():
            yield parts[1], int(parts[2]), parts[3]
        elif not commit and len(parts) == 3 and parts[1].isdigit():
            yield parts[0], int(parts[1]), parts[2]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current-only", action="store_true")
    args = parser.parse_args()
    commits = (
        [""]
        if args.current_only
        else subprocess.check_output(
            ["git", "rev-list", "--all"], text=True, encoding="utf-8"
        ).splitlines()
    )
    findings = set()
    seen_trees = set()
    for commit in commits:
        tree = (
            "WORKTREE"
            if not commit
            else subprocess.check_output(
                ["git", "rev-parse", f"{commit}^{{tree}}"], text=True
            ).strip()
        )
        if tree in seen_trees:
            continue
        seen_trees.add(tree)
        for path, line_number, text in _lines(commit):
            for kind, pattern in PATTERNS.items():
                if kind == "private_ipv4_endpoint" and not args.current_only:
                    continue
                if _is_finding(kind, pattern, text):
                    match = pattern.search(text)
                    assert match is not None
                    fingerprint = hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()[:16]
                    findings.add(
                        (
                            kind,
                            fingerprint,
                            commit[:12] or "WORKTREE",
                            Path(path).as_posix(),
                            line_number,
                        )
                    )
    grouped: Dict[Tuple[str, str], list] = {}
    for kind, fingerprint, commit, path, line_number in sorted(findings):
        grouped.setdefault((kind, fingerprint), []).append((commit, path, line_number))
    for (kind, fingerprint), occurrences in sorted(grouped.items()):
        commit, path, line_number = occurrences[0]
        paths = len({item[1] for item in occurrences})
        print(
            f"{kind}\tfingerprint={fingerprint}\toccurrences={len(occurrences)}\t"
            f"paths={paths}\tsample={commit}:{path}:{line_number}"
        )
    if findings:
        raise SystemExit(f"secret scan found {len(findings)} high-confidence occurrence(s)")
    print(f"secret scan passed: {len(seen_trees)} unique Git trees")


if __name__ == "__main__":
    main()
