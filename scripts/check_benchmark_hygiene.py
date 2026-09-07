#!/usr/bin/env python3
"""Fail closed when benchmark fixtures regain ambiguous or leaking assets."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from zscope.benchmarking.runner import SPECS, copy_scan_input  # noqa: E402


FORBIDDEN_SUFFIXES = {".log", ".db", ".sqlite", ".sarif"}
FORBIDDEN_NAMES = {
    "GROUND_TRUTH.md",
    "entry_functions_list.json",
    "zscope.local.env",
    "zscope.local.yaml",
}
DEPRECATED_TEXT = (
    "run_auto_unified_wsl.sh",
    "run_zscope_scan.sh",
    "scripts/run_formal_benchmark.py",
    "--build-cpg",
)
PERSONAL_PATH = re.compile(r"(?:/home/(?:zeal|jager)/|/mnt/c/Users/|[A-Za-z]:\\Users\\)")
_RANGE_V16_PACKET_RE = re.compile(
    r"^test/range/benchmark/v16/review-packets/[A-Za-z0-9][A-Za-z0-9_.-]*\.json$"
)
_RANGE_V16_PAIR_RE = re.compile(
    r"^test/range/benchmark/v16/pairs/[A-Za-z0-9][A-Za-z0-9_.-]*/"
    r"(?:manifest\.json|vulnerable/case\.c|fixed_or_near_miss/case\.c)$"
)
_RANGE_V16_EXACT = {
    "test/range/benchmark/v16/ground_truth.json",
    "test/range/benchmark/v16/review-packet-catalog.json",
    "test/range/benchmark/v16/reviews/normalized-decisions.json",
    "test/range/benchmark/v16/safe-pair-manifest.json",
    "test/range/benchmark/v16/safe-pair-v1.schema.json",
    "test/range/benchmark/v16/truth-manifest.json",
    "test/range/benchmark/v16/truth-v16.schema.json",
}


def _tracked_test_files() -> List[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "test"],
        cwd=str(ROOT),
        stderr=subprocess.DEVNULL,
    ).decode("utf-8")
    return [ROOT / item for item in output.split("\0") if item and (ROOT / item).is_file()]


def _allowed(relative: Path) -> bool:
    value = relative.as_posix()
    if (
        value in _RANGE_V16_EXACT
        or _RANGE_V16_PACKET_RE.fullmatch(value)
        or _RANGE_V16_PAIR_RE.fullmatch(value)
    ):
        return True
    if value.startswith("test/range/src/") or value.startswith("test/range/include/"):
        return True
    if value.startswith("test/range/internal/"):
        return True
    if value in {
        "test/range/README.md",
        "test/range/CMakeLists.txt",
        "test/range/zscope.benchmark.yaml",
        "test/range/benchmark/README.md",
        "test/range/benchmark/ground_truth.json",
        "test/range/benchmark/deterministic_entries.json",
        "test/range/benchmark/check_entry_coverage.py",
        "test/range/benchmark/fp_audit_rules.py",
        "test/range/benchmark/maintenance/README.md",
    }:
        return True
    if value.startswith("test/java_range/src/"):
        return True
    return value in {
        "test/java_range/README.md",
        "test/java_range/pom.xml",
        "test/java_range/zscope.benchmark.yaml",
        "test/java_range/benchmark/README.md",
        "test/java_range/benchmark/entries.json",
        "test/java_range/benchmark/ground_truth.json",
        "test/java_range/benchmark/structural_baseline.json",
        "test/java_range/benchmark/maintenance/entry_rule_coverage.json",
    }


def _truth_errors(path: Path) -> List[str]:
    errors = []
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("vulnerabilities")
    if not isinstance(payload.get("version"), int) or payload["version"] < 1:
        errors.append(f"{path}: version must be a positive integer")
    if not isinstance(rows, list):
        return [f"{path}: vulnerabilities must be a list"]
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or any(not isinstance(item, str) or not item for item in ids):
        errors.append(f"{path}: every vulnerability must have a non-empty string id")
    if len(set(ids)) != len(ids):
        errors.append(f"{path}: vulnerability ids are not unique")
    declared = payload.get("total_vulnerabilities")
    if declared is not None and declared != len(rows):
        errors.append(f"{path}: total_vulnerabilities does not match array length")
    return errors


def _java_entry_errors() -> List[str]:
    root = SPECS["java"].fixture_root
    entries = json.loads((root / "benchmark/entries.json").read_text(encoding="utf-8"))
    mapping = json.loads(
        (root / "benchmark/maintenance/entry_rule_coverage.json").read_text(encoding="utf-8")
    )
    rows = entries.get("functions", [])
    forbidden = {"covers_rule_ids", "cwe", "cwes", "truth_id", "truth_ids", "audit_prompt"}
    errors = []
    for index, row in enumerate(rows):
        leaked = forbidden.intersection(row) if isinstance(row, dict) else forbidden
        if leaked:
            errors.append(f"Java entries[{index}] contains answer metadata: {sorted(leaked)}")
    runtime_names = [
        str(row["function_name"])
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("function_name"), str)
    ]
    mapping_names = [
        str(row["function_name"])
        for row in mapping.get("entries", [])
        if isinstance(row, dict) and isinstance(row.get("function_name"), str)
    ]
    if len(runtime_names) != len(set(runtime_names)):
        errors.append("Java runtime entry function names are not unique")
    if sorted(runtime_names) != sorted(mapping_names):
        errors.append("Java maintenance coverage does not map one-to-one to runtime entries")
    return errors


def _active_text_errors(paths: Iterable[Path]) -> List[str]:
    errors = []
    for path in paths:
        if path.suffix.lower() not in {".py", ".sh", ".yaml", ".yml", ".md"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if PERSONAL_PATH.search(text):
            errors.append(f"personal absolute path in active benchmark asset: {path}")
        for token in DEPRECATED_TEXT:
            if token in text:
                errors.append(f"deprecated benchmark entry {token!r} in {path}")
    return errors


def _ignored_errors() -> List[str]:
    samples = [
        "test/range/entry_functions_list.json",
        "test/range/entry_functions_diff.local.json",
        "test/range/.zscope_bc/cache.bc",
        "test/range/.zscope_joern/cpg.bin",
        "test/range/.zscope_knowledge-next/db.sqlite",
        "test/java_range/.zscope_snapshots-next/state.json",
        "benchmark-artifacts/example/output.json",
        ".mypy_cache/example.json",
        ".ruff_cache/example",
    ]
    errors = []
    for sample in samples:
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", "--", sample],
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            errors.append(f"expected generated path to be ignored: {sample}")
    return errors


def check_hygiene() -> List[str]:
    tracked = _tracked_test_files()
    errors = [
        f"unexpected tracked benchmark asset: {path.relative_to(ROOT).as_posix()}"
        for path in tracked
        if not _allowed(path.relative_to(ROOT))
    ]
    for path in tracked:
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden tracked benchmark output: {path.relative_to(ROOT)}")
    for spec in SPECS.values():
        yaml_files = list(spec.fixture_root.glob("*.yaml")) + list(spec.fixture_root.glob("*.yml"))
        if yaml_files != [spec.config_path]:
            errors.append(
                f"{spec.fixture_root}: expected exactly one zscope.benchmark.yaml, got {yaml_files}"
            )
        errors.extend(_truth_errors(spec.truth_path))
    range_truth = json.loads(SPECS["c_cpp"].truth_path.read_text(encoding="utf-8"))
    if range_truth.get("version") != 15 or range_truth.get("total_vulnerabilities") != 136:
        errors.append("Range canonical truth must remain version 15 with 136 records")
    errors.extend(_java_entry_errors())
    active = [
        ROOT / "zscope/benchmarking/runner.py",
        ROOT / "zscope/cli/benchmark.py",
        *tracked,
    ]
    errors.extend(_active_text_errors(active))
    errors.extend(_ignored_errors())
    with tempfile.TemporaryDirectory(prefix="zscope-hygiene-") as temporary:
        base = Path(temporary)
        for language, spec in SPECS.items():
            destination = base / language
            manifest = copy_scan_input(spec.fixture_root, destination, language)
            for row in manifest["files"]:
                manifest_path = str(row["path"])
                if "ground_truth" in manifest_path.lower() or manifest_path.startswith(
                    "benchmark/"
                ):
                    errors.append(
                        f"truth/maintenance leak in {language} scan input: {manifest_path}"
                    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = check_hygiene()
    if args.json:
        print(json.dumps({"passed": not errors, "errors": errors}, ensure_ascii=False, indent=2))
    elif errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    else:
        print("benchmark hygiene passed")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
