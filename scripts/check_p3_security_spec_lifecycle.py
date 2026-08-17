#!/usr/bin/env python3
"""Fail closed if SecuritySpec obtains product authority before P5."""

from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    design = root / "docs/design/zscope-2.0-security-architecture/design-manifest.json"
    manifest = json.loads(design.read_text(encoding="utf-8"))
    p5_complete = (manifest.get("phase_status") or {}).get("P5") == "complete"
    package = root / "zscope/semantics/security_specs"
    lifecycle = package / "lifecycle.py"
    tree = ast.parse(lifecycle.read_text(encoding="utf-8"), filename=str(lifecycle))
    assignments = {
        target.id: str(node.value.value)
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    if not p5_complete and assignments.get("SECURITY_SPEC_MODE") != "shadow":
        errors.append("SecuritySpec mode must remain shadow until P5 is complete")
    if assignments.get("REVIEWER_IDENTITY_MODE") != "unavailable_read_only":
        errors.append("P3 reviewer identity mode must remain unavailable_read_only")

    forbidden_imports = (
        "zscope.benchmarking",
        "zscope.core.candidates",
        "zscope.core.validation",
        "zscope.reporting",
    )
    for path in sorted(package.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        if any(value in lowered for value in ("ground_truth", "truth_id", "scorer")):
            errors.append(f"forbidden Benchmark vocabulary in {path.relative_to(root)}")
        parsed = ast.parse(source, filename=str(path))
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                imports = [value.name for value in node.names]
            elif isinstance(node, ast.ImportFrom):
                imports = [str(node.module or "")]
            else:
                continue
            for imported in imports:
                if imported.startswith(forbidden_imports):
                    errors.append(
                        f"SecuritySpec imports authority dependency in {path.relative_to(root)}: "
                        f"{imported}"
                    )

    config_root = root / "zscope/config"
    for path in sorted(config_root.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".py", ".yaml", ".yml", ".json"}:
            if "security_spec_mode" in path.read_text(encoding="utf-8", errors="ignore"):
                errors.append(f"user-controllable security_spec_mode in {path.relative_to(root)}")
    for relative_root in (
        "zscope/core/candidates",
        "zscope/core/validation",
        "zscope/reporting",
    ):
        live_root = root / relative_root
        for path in sorted(live_root.rglob("*.py")):
            if "security_spec" in path.read_text(encoding="utf-8", errors="ignore").lower():
                errors.append(
                    f"SecuritySpec has a forbidden pre-P5 live data edge in {path.relative_to(root)}"
                )
    parallel_path = root / "zscope/orchestration/parallel_analyzer.py"
    if parallel_path.is_file():
        parallel_source = parallel_path.read_text(encoding="utf-8")
        if '"active_product_effect": "none"' not in parallel_source:
            errors.append(
                "parallel analyzer does not freeze SecuritySpec active_product_effect=none"
            )
    alert_path = root / "zscope/alerts/verifier.py"
    if alert_path.is_file():
        alert_source = alert_path.read_text(encoding="utf-8")
        if "load_shadow_manifest_identity" not in alert_source:
            errors.append("alert-verify does not load the shared frozen SecuritySpec manifest")
    return sorted(set(errors))


def main() -> int:
    errors = check()
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P3 SecuritySpec lifecycle gate passed: mode=shadow; reviews=read-only; authority=P5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
