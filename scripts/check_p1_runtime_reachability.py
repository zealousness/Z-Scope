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
GOVERNANCE_ONLY_LIVE_IMPORT_EXEMPT_MODULES = frozenset(
    {
        "zscope.orchestration.successor_review_evidence",
        "zscope.orchestration.successor_review_integration",
    }
)


def _live_import_denied(*, module: str, imported: str) -> bool:
    """Keep benchmark imports isolated except for exact offline projectors."""

    return (
        imported.startswith(LIVE_DENIED_IMPORTS)
        and not module.startswith(LIVE_IMPORT_EXEMPT_PREFIXES)
        and module not in GOVERNANCE_ONLY_LIVE_IMPORT_EXEMPT_MODULES
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


def _governance_projector_imports(source: str, *, module: str) -> Iterable[str]:
    """Resolve exact projector imports, including constant dynamic imports."""

    tree = ast.parse(source, filename=module)
    package = module.rpartition(".")[0]
    imported_projectors: set[str] = set()
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()
    for node in ast.walk(tree):
        candidates: list[str] = []
        if isinstance(node, ast.Import):
            candidates.extend(alias.name for alias in node.names)
            importlib_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "importlib"
            )
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                imported = f"{base}.{node.module}" if node.module else base
            else:
                imported = node.module or ""
            candidates.append(imported)
            candidates.extend(
                f"{imported}.{alias.name}" if imported else alias.name
                for alias in node.names
                if alias.name != "*"
            )
            if imported == "importlib":
                import_module_aliases.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "import_module"
                )
        elif (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            function = node.func
            if (
                isinstance(function, ast.Name)
                and function.id in {"__import__", *import_module_aliases}
            ) or (
                isinstance(function, ast.Attribute)
                and function.attr == "import_module"
                and isinstance(function.value, ast.Name)
                and function.value.id in importlib_aliases
            ):
                candidates.append(node.args[0].value)
        imported_projectors.update(
            candidate
            for candidate in candidates
            if candidate in GOVERNANCE_ONLY_LIVE_IMPORT_EXEMPT_MODULES
        )
    yield from sorted(imported_projectors)


def source_import_errors(repo_root: Path) -> list[str]:
    errors: list[str] = []
    source_root = repo_root / "zscope"
    for path in sorted(source_root.rglob("*.py")):
        relative = path.relative_to(repo_root).with_suffix("")
        module = ".".join(relative.parts)
        source = path.read_text(encoding="utf-8")
        for imported in _imports(source, module=module):
            if imported.startswith(REMOVED_MODULES):
                errors.append(f"{relative.as_posix()}: imports removed module {imported}")
            if relative.parts[:2] == ("zscope", "compat") and imported.startswith(
                COMPAT_DENIED_IMPORTS
            ):
                errors.append(f"{relative.as_posix()}: compat imports live runtime {imported}")
            if _live_import_denied(module=module, imported=imported):
                errors.append(
                    f"{relative.as_posix()}: live runtime imports isolated package {imported}"
                )
        if module not in GOVERNANCE_ONLY_LIVE_IMPORT_EXEMPT_MODULES:
            for imported in _governance_projector_imports(source, module=module):
                errors.append(
                    f"{relative.as_posix()}: imports governance-only projector {imported}"
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
                if _live_import_denied(module=module, imported=imported):
                    errors.append(f"{name}: live runtime imports isolated package {imported}")
            if module not in GOVERNANCE_ONLY_LIVE_IMPORT_EXEMPT_MODULES:
                for imported in _governance_projector_imports(source, module=module):
                    errors.append(f"{name}: imports governance-only projector {imported}")
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
