#!/usr/bin/env python3
"""Verify P3 SecuritySpec modules and schemas in a built wheel."""

from __future__ import annotations

import argparse
import ast
import zipfile
from pathlib import Path
from typing import Optional, Sequence


PREFIX = "zscope/semantics/security_specs/"
REQUIRED_MODULES = {
    PREFIX + name
    for name in (
        "__init__.py",
        "archive.py",
        "canonical.py",
        "compiler.py",
        "lifecycle.py",
        "manifest.py",
        "miner.py",
        "models.py",
        "qualification.py",
        "registry.py",
        "shadow.py",
        "store.py",
    )
}
REQUIRED_SCHEMAS = {
    "compiled-security-spec-v2.schema.json",
    "security-spec-archive-v2.schema.json",
    "security-spec-qualification-v1.schema.json",
    "security-spec-review-event-v2.schema.json",
    "security-spec-v2.schema.json",
}
REQUIRED_QUALIFICATION = PREFIX + "qualification/p3-security-spec-qualification.json"
FORBIDDEN_IMPORTS = (
    "zscope.benchmarking",
    "zscope.core.candidates",
    "zscope.core.validation",
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
    errors = [
        f"wheel missing SecuritySpec module: {name}" for name in sorted(REQUIRED_MODULES - names)
    ]
    if REQUIRED_QUALIFICATION not in names:
        errors.append("wheel missing built-in SecuritySpec qualification artifact")
    schema_prefix = PREFIX + "schemas/"
    present = {name.removeprefix(schema_prefix) for name in names if name.startswith(schema_prefix)}
    errors.extend(
        f"wheel missing SecuritySpec schema: {name}" for name in sorted(REQUIRED_SCHEMAS - present)
    )
    for name, source in sources.items():
        lowered = source.lower()
        if any(value in lowered for value in ("ground_truth", "truth_id", "scorer")):
            errors.append(f"SecuritySpec contains forbidden Benchmark vocabulary: {name}")
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
                    errors.append(f"SecuritySpec imports forbidden authority dependency: {name}")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args(argv)
    errors = wheel_errors(args.wheel)
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P3 SecuritySpec wheel gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
