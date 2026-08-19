#!/usr/bin/env python3
"""Verify that a built wheel contains the P2 kernel and strict schemas."""

from __future__ import annotations

import argparse
import ast
import zipfile
from pathlib import Path
from typing import Sequence


REQUIRED_MODULES = {
    "zscope/core/validation/proof_kernel/__init__.py",
    "zscope/core/validation/proof_kernel/canonical.py",
    "zscope/core/validation/proof_kernel/checker.py",
    "zscope/core/validation/proof_kernel/engine.py",
    "zscope/core/validation/proof_kernel/lifecycle.py",
    "zscope/core/validation/proof_kernel/models.py",
    "zscope/core/validation/proof_kernel/provider.py",
    "zscope/core/validation/proof_kernel/registry.py",
    "zscope/core/validation/proof_kernel/store.py",
}
FORBIDDEN_IMPORT_PREFIXES = (
    "zscope.benchmarking",
    "zscope.core.validation.claim_verifier",
    "zscope.core.validation.evidence_completion",
)
REQUIRED_SCHEMAS = {
    "evidence-action-v2.schema.json",
    "evidence-certificate-v2.schema.json",
    "function-security-summary-v2.schema.json",
    "program-proof-ir-v2.schema.json",
    "proof-check-result-v2.schema.json",
    "proof-obligation-v2.schema.json",
}


def wheel_errors(path: Path) -> list[str]:
    errors = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            proof_sources = {
                name: archive.read(name).decode("utf-8")
                for name in names
                if name.startswith("zscope/core/validation/proof_kernel/") and name.endswith(".py")
            }
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"cannot read wheel: {exc}"]
    for name in sorted(REQUIRED_MODULES - names):
        errors.append(f"wheel missing Proof Kernel module: {name}")
    schema_prefix = "zscope/core/validation/proof_kernel/schemas/"
    present_schemas = {
        name.removeprefix(schema_prefix) for name in names if name.startswith(schema_prefix)
    }
    for name in sorted(REQUIRED_SCHEMAS - present_schemas):
        errors.append(f"wheel missing Proof Kernel schema: {name}")
    for name, source in sorted(proof_sources.items()):
        lowered = source.lower()
        if any(value in lowered for value in ("ground_truth", "truth_id", "scorer")):
            errors.append(f"Proof Kernel contains forbidden Benchmark vocabulary: {name}")
        try:
            tree = ast.parse(source, filename=name)
        except SyntaxError as exc:
            errors.append(f"Proof Kernel module is not parseable: {name}: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports = [value.name for value in node.names]
            elif isinstance(node, ast.ImportFrom):
                imports = [str(node.module or "")]
            else:
                continue
            for imported in imports:
                if imported.startswith(FORBIDDEN_IMPORT_PREFIXES):
                    errors.append(
                        "Proof Kernel imports forbidden live authority dependency: "
                        f"{name}: {imported}"
                    )
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args(argv)
    errors = wheel_errors(args.wheel)
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P2 Proof Kernel wheel gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
