#!/usr/bin/env python3
"""Fail closed when removed P1 runtime components remain importable or packaged."""

from __future__ import annotations

import argparse
import ast
import sys
import zipfile
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
REMOVED_MODULES = (
    "zscope.agents.deep_worker",
    "zscope.agents.issue_reconciler",
    "zscope.agents.vulnerability_analyzer",
    "zscope.orchestration.subagents",
)
REMOVED_WHEEL_FRAGMENTS = tuple(value.replace(".", "/") for value in REMOVED_MODULES)
REQUIRED_WHEEL_ENTRIES = (
    "zscope/agents/active_discovery/AGENT.md",
    "zscope/agents/history_maintenance/AGENT.md",
    "zscope/agents/history_maintenance/agent.py",
    "zscope/compat/__init__.py",
    "zscope/compat/config.py",
    "zscope/compat/reports.py",
    "zscope/compat/usage.py",
)
COMPAT_DENIED_IMPORTS = (
    "zscope.agents",
    "zscope.framework.llm_client",
    "zscope.orchestration.parallel_analyzer",
    "zscope.orchestration.workflow_executor",
    "zscope.core.validation",
)


def _imports(source: str, *, module: str) -> Iterable[str]:
    tree = ast.parse(source, filename=module)
    package = module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                imported = f"{base}.{node.module}" if node.module else base
            else:
                imported = node.module or ""
            yield imported


def source_import_errors(repo_root: Path) -> list[str]:
    errors: list[str] = []
    source_root = repo_root / "zscope"
    for path in sorted(source_root.rglob("*.py")):
        relative = path.relative_to(repo_root).with_suffix("")
        module = ".".join(relative.parts)
        for imported in _imports(path.read_text(encoding="utf-8"), module=module):
            if imported.startswith(REMOVED_MODULES):
                errors.append(f"{relative.as_posix()}: imports removed module {imported}")
            if relative.parts[:2] == ("zscope", "compat") and imported.startswith(
                COMPAT_DENIED_IMPORTS
            ):
                errors.append(f"{relative.as_posix()}: compat imports live runtime {imported}")
    return errors


def wheel_errors(wheel_path: Path) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(wheel_path) as archive:
        names = set(archive.namelist())
        for fragment in REMOVED_WHEEL_FRAGMENTS:
            matches = sorted(name for name in names if name.startswith(fragment))
            if matches:
                errors.append(f"wheel contains removed component {fragment}: {matches}")
        for required in REQUIRED_WHEEL_ENTRIES:
            if required not in names:
                errors.append(f"wheel is missing required runtime entry {required}")
        for name in sorted(names):
            if not name.startswith("zscope/") or not name.endswith(".py"):
                continue
            module = name[:-3].replace("/", ".")
            source = archive.read(name).decode("utf-8")
            for imported in _imports(source, module=module):
                if imported.startswith(REMOVED_MODULES):
                    errors.append(f"{name}: imports removed module {imported}")
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--wheel", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = source_import_errors(args.repo_root.resolve())
    errors.extend(wheel_errors(args.wheel.resolve()))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(
        "P1 runtime reachability gate passed: removed modules absent from source imports and wheel"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
