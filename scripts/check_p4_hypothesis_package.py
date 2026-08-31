#!/usr/bin/env python3
"""Verify P4 modules, prompt, schemas, and qualification in a wheel."""

from __future__ import annotations

import argparse
import ast
import zipfile
from pathlib import Path
from typing import Optional, Sequence


PREFIX = "zscope/orchestration/hypothesis_hunter/"
REQUIRED_MODULES = {
    PREFIX + name
    for name in (
        "__init__.py",
        "agent.py",
        "blind.py",
        "catalog.py",
        "lifecycle.py",
        "models.py",
        "planner.py",
        "qualification.py",
        "runtime.py",
        "store.py",
    )
}
REQUIRED_SCHEMAS = {
    "attack-surface-audit-unit-v2.schema.json",
    "hypothesis-coverage-observation-v1.schema.json",
    "hypothesis-hunt-report-v2.schema.json",
    "hypothesis-offer-v2.schema.json",
    "localized-coverage-key-v2.schema.json",
    "security-hypothesis-v2.schema.json",
}
REQUIRED_PROMPT = "zscope/agents/hypothesis_hunter/AGENT.md"
REQUIRED_QUALIFICATIONS = {
    PREFIX + "qualification/qualification-artifact.json",
    PREFIX + "qualification/qualification-artifact.v2.json",
}
FORBIDDEN_IMPORTS = (
    "zscope.benchmarking",
    "zscope.core.validation.runner",
    "zscope.reporting",
)


def wheel_errors(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            sources = {
                name: archive.read(name).decode("utf-8")
                for name in names
                if name.startswith(PREFIX) and name.endswith(".py")
            }
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"cannot read wheel: {exc}"]
    errors = [f"wheel missing P4 module: {name}" for name in sorted(REQUIRED_MODULES - names)]
    if REQUIRED_PROMPT not in names:
        errors.append("wheel missing Hypothesis Hunter prompt")
    errors.extend(
        f"wheel missing P4 qualification artifact: {name}"
        for name in sorted(REQUIRED_QUALIFICATIONS - names)
    )
    schema_prefix = PREFIX + "schemas/"
    present = {name.removeprefix(schema_prefix) for name in names if name.startswith(schema_prefix)}
    errors.extend(f"wheel missing P4 schema: {name}" for name in sorted(REQUIRED_SCHEMAS - present))
    for name, source in sources.items():
        lowered = source.lower()
        if name != PREFIX + "blind.py" and any(
            value in lowered for value in ("ground_truth", "truth_id", "scorer")
        ):
            errors.append(f"P4 contains forbidden Benchmark vocabulary: {name}")
        tree = ast.parse(source, filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports = [value.name for value in node.names]
            elif isinstance(node, ast.ImportFrom):
                imports = [str(node.module or "")]
            else:
                continue
            for imported in imports:
                if imported.startswith(FORBIDDEN_IMPORTS):
                    errors.append(f"P4 imports forbidden authority dependency: {name}")
    return sorted(set(errors))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args(argv)
    errors = wheel_errors(args.wheel)
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P4 Hypothesis Hunter wheel gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
