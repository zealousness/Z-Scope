#!/usr/bin/env python3
"""Fail closed when removed P1/P5 runtime components remain reachable."""

from __future__ import annotations

import argparse
import ast
import sys
import zipfile
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
REMOVED_MODULES = (
    "zscope.agents.active_discovery",
    "zscope.agents.deep_worker",
    "zscope.agents.issue_reconciler",
    "zscope.agents.global_modeler",
    "zscope.agents.semantic_modeler",
    "zscope.agents.validator_agent",
    "zscope.agents.vulnerability_analyzer",
    "zscope.orchestration.active_discovery",
    "zscope.orchestration.global_modeler",
    "zscope.orchestration.subagents",
    "zscope.semantics.security_specs.shadow",
)
REMOVED_WHEEL_FRAGMENTS = tuple(value.replace(".", "/") for value in REMOVED_MODULES)
REQUIRED_WHEEL_ENTRIES = (
    "zscope/agents/history_maintenance/AGENT.md",
    "zscope/agents/history_maintenance/agent.py",
    "zscope/agents/hypothesis_hunter/AGENT.md",
    "zscope/agents/proof_engine/AGENT.md",
    "zscope/agents/proof_engine/agent.py",
    "zscope/compat/__init__.py",
    "zscope/compat/config.py",
    "zscope/compat/reports.py",
    "zscope/compat/usage.py",
    "zscope/orchestration/runtime_authority.py",
    "zscope/orchestration/schemas/runtime-authority-manifest-v1.schema.json",
    "zscope/semantics/security_specs/runtime.py",
)
COMPAT_DENIED_IMPORTS = (
    "zscope.agents",
    "zscope.framework.llm_client",
    "zscope.orchestration.parallel_analyzer",
    "zscope.orchestration.workflow_executor",
    "zscope.core.validation",
)
LIVE_DENIED_IMPORTS = ("zscope.benchmarking", "zscope.compat")
LIVE_IMPORT_EXEMPT_PREFIXES = (
    "zscope.benchmarking",
    "zscope.compat",
    "zscope.cli.benchmark",
    "zscope.cli.config_cli",
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
            if not module.startswith(LIVE_IMPORT_EXEMPT_PREFIXES) and imported.startswith(
                LIVE_DENIED_IMPORTS
            ):
                errors.append(
                    f"{relative.as_posix()}: live runtime imports isolated package {imported}"
                )
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
                if not module.startswith(LIVE_IMPORT_EXEMPT_PREFIXES) and imported.startswith(
                    LIVE_DENIED_IMPORTS
                ):
                    errors.append(f"{name}: live runtime imports isolated package {imported}")
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
    print("P5 runtime reachability gate passed: legacy actors absent and live imports isolated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
