#!/usr/bin/env python3
"""Fail closed if P4 can reach live authority before P5."""

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
    package = root / "zscope/orchestration/hypothesis_hunter"
    lifecycle = package / "lifecycle.py"
    tree = ast.parse(lifecycle.read_text(encoding="utf-8"), filename=str(lifecycle))
    assignments = {
        target.id: str(node.value.value)
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    if not p5_complete and assignments.get("HYPOTHESIS_HUNTER_MODE") != "shadow":
        errors.append("Hypothesis Hunter mode must remain shadow until P5 is complete")
    if assignments.get("ACTIVE_PRODUCT_EFFECT") != "none":
        errors.append("Hypothesis Hunter active product effect must remain none")

    forbidden_imports = (
        "zscope.benchmarking",
        "zscope.core.validation.runner",
        "zscope.reporting",
    )
    for path in sorted(package.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        if path.name != "blind.py" and any(
            value in lowered for value in ("ground_truth", "truth_id", "scorer")
        ):
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
                        f"Hypothesis Hunter imports live authority in "
                        f"{path.relative_to(root)}: {imported}"
                    )
        if any(
            value in lowered
            for value in (
                "validationrunner",
                "terminalauthority",
                "finding_root",
                "build_report_views",
                "promotion_eligible = true",
            )
        ):
            errors.append(f"forbidden pre-P5 authority edge in {path.relative_to(root)}")

    config_root = root / "zscope/config"
    for path in sorted(config_root.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".py", ".yaml", ".yml", ".json"}:
            if "hypothesis_hunter_mode" in path.read_text(encoding="utf-8", errors="ignore"):
                errors.append(
                    f"user-controllable hypothesis_hunter_mode in {path.relative_to(root)}"
                )

    for relative_root in (
        "zscope/core/candidates",
        "zscope/core/validation",
        "zscope/reporting",
    ):
        live_root = root / relative_root
        for path in sorted(live_root.rglob("*.py")):
            parsed = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(parsed):
                if isinstance(node, ast.ImportFrom) and "hypothesis_hunter" in str(
                    node.module or ""
                ):
                    errors.append(
                        f"live authority imports P4 shadow package in {path.relative_to(root)}"
                    )

    parallel = (root / "zscope/orchestration/parallel_analyzer.py").read_text(encoding="utf-8")
    if '"active_product_effect": "none"' not in parallel:
        errors.append("parallel analyzer does not freeze P4 active_product_effect=none")
    active_call = parallel.find("self._run_active_discovery(entries, discovery_profile)")
    validation_call = parallel.find("self._run_scan_validation_queue()", active_call)
    if (
        active_call < 0
        or validation_call < 0
        or active_call > validation_call
        or "self._run_hypothesis_hunter_shadow(" not in parallel
    ):
        errors.append("P4 shadow runtime is not ordered before live validation queue")
    if 'HypothesisArtifactStore(snapshot_dir / "hypothesis_hunter")' not in parallel:
        errors.append("P4 does not use its independent artifact store")
    alert = (root / "zscope/alerts/verifier.py").read_text(encoding="utf-8")
    if "load_hypothesis_shadow_identity" not in alert:
        errors.append("alert-verify does not replay the frozen P4 manifest")
    return sorted(set(errors))


def main() -> int:
    errors = check()
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P4 Hypothesis Hunter lifecycle gate passed: shadow ledger isolated; authority=P5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
