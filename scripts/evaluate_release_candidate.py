#!/usr/bin/env python3
"""Evaluate benchmark, asset, and offline-smoke evidence for a release candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from scripts.verify_release_assets import ReleaseAssetError, verify_release_assets
    from scripts.verify_release_version import package_version
except ModuleNotFoundError:  # Direct execution sets sys.path[0] to scripts/.
    from verify_release_assets import ReleaseAssetError, verify_release_assets
    from verify_release_version import package_version

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate_candidate(
    provenance_path: Path,
    *,
    release_sha: str,
    version: str,
    tag: str = "",
    asset_dir: Optional[Path] = None,
    smoke_evidence: Optional[Path] = None,
) -> Dict[str, Any]:
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    hard_blockers: List[str] = []
    rc_blockers: List[str] = []
    advisories: List[str] = []
    if provenance.get("package_version") != version:
        hard_blockers.append("package_version_mismatch")
    if not tag:
        hard_blockers.append("release_tag_missing")
    elif tag != f"v{version}":
        hard_blockers.append("tag_package_version_mismatch")
    else:
        try:
            tag_sha = subprocess.check_output(
                ["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
                cwd=str(ROOT),
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            if tag_sha != release_sha:
                hard_blockers.append("release_tag_not_release_sha")
        except subprocess.CalledProcessError:
            hard_blockers.append("release_tag_not_found")

    benchmark_results = []
    for item in provenance.get("benchmarks", []):
        archive_path = (ROOT / str(item["archive"])).resolve()
        archive = json.loads(archive_path.read_text(encoding="utf-8"))
        required = bool(item.get("required_for_release", False))
        language = str(item.get("language"))
        result = {
            "language": language,
            "required_for_release": required,
            "archive": str(item["archive"]),
            "archive_sha256": _sha256(archive_path),
            "benchmark_git_sha": archive.get("benchmark_git_sha"),
            "cold_runs": len(archive.get("runs", [])),
        }
        if archive.get("benchmark_git_sha") != item.get("git_sha"):
            hard_blockers.append(f"{language}:provenance_archive_sha_mismatch")
        if required and archive.get("benchmark_git_sha") != release_sha:
            hard_blockers.append(f"{language}:benchmark_sha_not_release_sha")
        runs = archive.get("runs", [])
        if len(runs) < 5:
            hard_blockers.append(f"{language}:fewer_than_five_runs")
        for run in runs:
            completeness = run.get("completeness", {})
            if not all(
                completeness.get(key) is True
                for key in (
                    "report_present",
                    "score_present",
                    "summary_present",
                    "backend_health_present",
                    "queue_empty",
                    "backend_valid",
                    "source_truth_isolated",
                )
            ):
                hard_blockers.append(f"{language}:run_{run.get('run')}_incomplete")
        gate = archive.get("gate", {})
        if required and gate.get("numeric_gates_passed") is not True:
            hard_blockers.append(f"{language}:numeric_gate_failed")
        if required and language == "cpp":
            limits = {
                "confirmed_tp": (">=", 85.0),
                "confirmed_precision_percent": (">=", 95.0),
                "with_review_tp": (">=", 134.0),
                "with_review_raw_fp": ("<=", 100.0),
                "needs_review": ("<=", 150.0),
                "total_tokens": ("<=", 6_000_000.0),
                "wall_seconds": ("<=", 3600.0),
            }
            for run in runs:
                metrics = run.get("metrics", {})
                for metric, (operator, threshold) in limits.items():
                    try:
                        value = float(metrics[metric])
                    except (KeyError, TypeError, ValueError):
                        hard_blockers.append(f"{language}:run_{run.get('run')}_{metric}_missing")
                        continue
                    failed = (operator == ">=" and value < threshold) or (
                        operator == "<=" and value > threshold
                    )
                    if failed:
                        hard_blockers.append(
                            f"{language}:run_{run.get('run')}_{metric}_gate_failed"
                        )
        if required and gate.get("sealed_set_verified") is not True:
            rc_blockers.append(f"{language}:sealed_set_not_verified")
        if archive.get("performance_analysis", {}).get("outlier_runs"):
            advisories.append(f"{language}:performance_outlier_present")
        benchmark_results.append(result)

    asset_result: Optional[Dict[str, Any]] = None
    if asset_dir is None:
        hard_blockers.append("release_assets_missing")
    else:
        try:
            asset_result = verify_release_assets(asset_dir)
            if asset_result.get("git_sha") != release_sha:
                hard_blockers.append("release_assets_git_sha_not_release_sha")
        except (OSError, ValueError, json.JSONDecodeError, ReleaseAssetError) as exc:
            hard_blockers.append(f"release_assets_invalid:{type(exc).__name__}")

    smoke_result: Optional[Dict[str, Any]] = None
    if smoke_evidence is None:
        hard_blockers.append("production_offline_smoke_missing")
    else:
        smoke_result = json.loads(smoke_evidence.read_text(encoding="utf-8"))
        if smoke_result.get("passed") is not True:
            hard_blockers.append("production_offline_smoke_failed")
        if smoke_result.get("synthetic_payload") is not False:
            hard_blockers.append("production_offline_smoke_is_synthetic")
        if smoke_result.get("network_isolation_confirmed") is not True:
            hard_blockers.append("production_offline_smoke_not_network_isolated")
        if asset_result and smoke_result.get("release_manifest_sha256") != asset_result.get(
            "release_manifest_sha256"
        ):
            hard_blockers.append("offline_smoke_asset_manifest_mismatch")

    hard_blockers = list(dict.fromkeys(hard_blockers))
    rc_blockers = list(dict.fromkeys(rc_blockers))
    if hard_blockers:
        status = "blocked"
    elif rc_blockers:
        status = "rc_only"
    else:
        status = "release_ready"
    return {
        "schema_version": "zscope.release-candidate-audit.v1",
        "status": status,
        "package_version": version,
        "tag": tag or None,
        "release_sha": release_sha,
        "benchmarks": benchmark_results,
        "assets": asset_result,
        "offline_smoke": smoke_result,
        "hard_blockers": hard_blockers,
        "rc_blockers": rc_blockers,
        "advisories": advisories,
        "publishable": status == "release_ready",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--provenance",
        type=Path,
        default=ROOT / "docs/releases/benchmark-provenance.json",
    )
    parser.add_argument("--release-sha", default="")
    parser.add_argument("--package-version", default=package_version())
    parser.add_argument("--tag", default="")
    parser.add_argument("--asset-dir", type=Path)
    parser.add_argument("--offline-smoke-evidence", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    release_sha = (
        args.release_sha
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT), text=True).strip()
    )
    report = evaluate_candidate(
        args.provenance,
        release_sha=release_sha,
        version=args.package_version,
        tag=args.tag,
        asset_dir=args.asset_dir,
        smoke_evidence=args.offline_smoke_evidence,
    )
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not report["publishable"] and not args.allow_incomplete:
        raise SystemExit("release candidate is not publishable")


if __name__ == "__main__":
    main()
