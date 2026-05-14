#!/usr/bin/env python3
"""Preflight-check range benchmark entry coverage.

The benchmark uses a fixed batch entry list instead of automatic discovery.
This script keeps that contract explicit: every scored finding must be reachable
from at least one configured entry function, and entry names must resolve
unambiguously in the fixture source tree.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


FUNC_DEF_RE = re.compile(
    r"(?m)^[A-Za-z_][\w\s\*\(\),]*\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return data


def resolve_entry_list(config_path: Path) -> Path | None:
    if not config_path.exists():
        return None
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("entry_functions_list:"):
            value = stripped.split(":", 1)[1].strip().strip("'\"")
            return (config_path.parent / value).resolve()
    return None


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in ("src", "include", "internal"):
        base = root / rel
        if base.exists():
            files.extend(base.rglob("*.c"))
            files.extend(base.rglob("*.h"))
            files.extend(base.rglob("*.ph"))
    return sorted(files)


def find_function_defs(root: Path) -> dict[str, list[str]]:
    defs: dict[str, list[str]] = {}
    for path in source_files(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in FUNC_DEF_RE.finditer(text):
            name = match.group(1)
            rel = path.relative_to(root).as_posix()
            defs.setdefault(name, []).append(rel)
    return defs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("test/range"))
    parser.add_argument("--config", type=Path, default=Path("test/range/zscope.benchmark.yaml"))
    parser.add_argument("--entries", type=Path, default=None)
    parser.add_argument("--truth", type=Path, default=Path("test/range/benchmark/ground_truth.json"))
    parser.add_argument(
        "--require-all-functions",
        action="store_true",
        help="Require both primary and secondary truth functions to be explicit entries.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    entries_path = args.entries.resolve() if args.entries else resolve_entry_list(args.config)
    if entries_path is None:
        raise SystemExit(f"Cannot resolve entry_functions_list from {args.config}")

    entries_data = load_json(entries_path)
    truth_data = load_json(args.truth)
    entries = entries_data.get("functions", [])
    vulns = truth_data.get("vulnerabilities", [])
    if not isinstance(entries, list):
        raise SystemExit(f"{entries_path} field 'functions' must be an array")
    if not isinstance(vulns, list):
        raise SystemExit(f"{args.truth} field 'vulnerabilities' must be an array")

    entry_names = [str(item.get("function_name") or "") for item in entries if isinstance(item, dict)]
    entry_set = {name for name in entry_names if name}
    duplicates = sorted({name for name in entry_names if entry_names.count(name) > 1})

    missing_truth: list[str] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        funcs = [
            str(vuln.get("function") or ""),
            str(vuln.get("secondary_function") or ""),
        ]
        funcs = [name for name in funcs if name]
        if args.require_all_functions:
            missing = [name for name in funcs if name not in entry_set]
            if missing:
                missing_truth.append(f"{vuln.get('id')}: missing {', '.join(missing)}")
        elif not any(name in entry_set for name in funcs):
            missing_truth.append(f"{vuln.get('id')}: none of {', '.join(funcs)}")

    defs = find_function_defs(root)
    missing_defs = sorted(name for name in entry_set if name not in defs)
    duplicate_defs = sorted(name for name in entry_set if len(defs.get(name, [])) > 1)

    print(
        json.dumps(
            {
                "entries": len(entry_set),
                "ground_truth": len(vulns),
                "missing_truth_entry": missing_truth,
                "duplicate_entry_names": duplicates,
                "missing_entry_definitions": missing_defs,
                "duplicate_entry_definitions": {
                    name: defs.get(name, []) for name in duplicate_defs
                },
                "mode": "require_all_functions" if args.require_all_functions else "reachable_from_any_truth_function",
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    if missing_truth or duplicates or missing_defs or duplicate_defs:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
