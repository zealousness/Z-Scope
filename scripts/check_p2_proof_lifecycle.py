#!/usr/bin/env python3
"""Fail closed unless the P5 Proof Engine authority is hard-wired."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
PROOF_ROOT = ROOT / "zscope" / "core" / "validation" / "proof_kernel"
MANIFEST = ROOT / "docs" / "design" / "zscope-2.0-security-architecture" / "design-manifest.json"


def _python_files(root: Path) -> Iterable[Path]:
    return sorted(root.rglob("*.py"))


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    manifest_path = root / MANIFEST.relative_to(ROOT)
    json.loads(manifest_path.read_text(encoding="utf-8"))
    lifecycle = root / "zscope" / "core" / "validation" / "proof_kernel" / "lifecycle.py"
    tree = ast.parse(lifecycle.read_text(encoding="utf-8"), filename=str(lifecycle))
    mode = ""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == "PROOF_KERNEL_MODE"
                for target in node.targets
            ):
                if isinstance(node.value, ast.Constant):
                    mode = str(node.value.value)
    if mode != "authoritative":
        errors.append("Proof Engine mode must be authoritative during the P5 cutover")

    forbidden_import_roots = {"zscope.benchmarking", "zscope.benchmark", "test.range"}
    proof_root = root / PROOF_ROOT.relative_to(ROOT)
    for path in _python_files(proof_root):
        parsed = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                names = [value.name for value in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [str(node.module or "")]
            else:
                continue
            if any(
                name == forbidden or name.startswith(forbidden + ".")
                for name in names
                for forbidden in forbidden_import_roots
            ):
                errors.append(f"forbidden Benchmark/truth import in {path.relative_to(root)}")
        lowered = path.read_text(encoding="utf-8").lower()
        if "ground_truth" in lowered or "truth_id" in lowered or "scorer" in lowered:
            errors.append(f"forbidden truth/Scorer vocabulary in {path.relative_to(root)}")

    for path in sorted((root / "zscope" / "config").rglob("*")):
        if path.is_file() and path.suffix.lower() in {".py", ".yaml", ".yml", ".json"}:
            if "proof_kernel_mode" in path.read_text(encoding="utf-8", errors="ignore"):
                errors.append(f"user-controllable proof_kernel_mode in {path.relative_to(root)}")
    return sorted(set(errors))


def main() -> int:
    errors = check()
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P5 Proof Engine lifecycle gate passed: mode=authoritative; no user switch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
