#!/usr/bin/env python3
"""Prepare and verify external qualification campaigns for C/C++ rules.

This tool never creates qualification evidence.  ``prepare`` creates an empty
work plan, ``verify`` derives readiness from strict immutable evidence, and
``assemble`` emits a registry only after every selected current revision has
passed the existing qualification contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from zscope.rules.catalog import RuleCatalog, RuleCatalogError, RuleDescriptor
from zscope.rules.qualification_evidence import (
    load_qualification_evidence,
)


CAMPAIGN_SCHEMA = "zscope.rule-qualification-campaign.v1"
REPORT_SCHEMA = "zscope.rule-qualification-campaign-report.v1"


def _rules() -> list[RuleDescriptor]:
    return [
        rule for rule in RuleCatalog.builtin() if rule.language == "c_cpp" and rule.default_enabled
    ]


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise RuleCatalogError(f"refusing to overwrite existing campaign artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def prepare(root: Path) -> Dict[str, Any]:
    root = Path(root)
    if root.exists() and any(root.iterdir()):
        raise RuleCatalogError(f"campaign directory is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    templates = root / "rules"
    templates.mkdir()
    rows = []
    for descriptor in _rules():
        template_name = f"{descriptor.id}.r{descriptor.revision}.campaign.json"
        _write_new(
            templates / template_name,
            {
                "schema_version": CAMPAIGN_SCHEMA,
                "rule_id": descriptor.id,
                "revision": descriptor.revision,
                "status": "pending_external_evidence",
                "evidence_manifest": None,
                "evidence_sha256": None,
                "requirements": {
                    "minimum_external_projects": 3,
                    "minimum_positive_cases": 10,
                    "minimum_near_miss_negative_cases": 20,
                    "minimum_metamorphic_variants": 3,
                    "requires_vulnerable_fixed_pair": True,
                    "minimum_external_precision": 0.9,
                    "range_ground_truth_forbidden": True,
                },
            },
        )
        rows.append(
            {
                "rule_id": descriptor.id,
                "revision": descriptor.revision,
                "campaign_file": f"rules/{template_name}",
            }
        )
    manifest = {
        "schema_version": CAMPAIGN_SCHEMA,
        "scope": "default_enabled_c_cpp_rules",
        "rule_count": len(rows),
        "rules": rows,
    }
    _write_new(root / "campaign.json", manifest)
    return manifest


def _strict_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuleCatalogError(f"invalid campaign JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuleCatalogError(f"campaign JSON must be an object: {path}")
    return value


def _descriptor_map() -> Dict[tuple[str, int], RuleDescriptor]:
    return {(rule.id, rule.revision): rule for rule in _rules()}


def _campaign_child(root: Path, relative: str) -> Path:
    raw = Path(str(relative or ""))
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise RuleCatalogError(f"invalid campaign-relative path: {relative!r}")
    resolved_root = root.resolve()
    resolved = (resolved_root / raw).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise RuleCatalogError(f"campaign path escapes root: {relative!r}")
    return resolved


def verify(root: Path) -> Dict[str, Any]:
    root = Path(root)
    campaign = _strict_json(root / "campaign.json")
    if campaign.get("schema_version") != CAMPAIGN_SCHEMA:
        raise RuleCatalogError("unsupported qualification campaign schema")
    descriptors = _descriptor_map()
    rows = []
    seen: set[tuple[str, int]] = set()
    for pointer in campaign.get("rules") or []:
        if not isinstance(pointer, Mapping):
            raise RuleCatalogError("campaign rule pointer must be an object")
        key = (str(pointer.get("rule_id") or ""), int(pointer.get("revision") or 0))
        if key in seen:
            raise RuleCatalogError(f"duplicate campaign rule pointer: {key!r}")
        seen.add(key)
        descriptor = descriptors.get(key)
        if descriptor is None:
            rows.append(
                {
                    "rule_id": key[0],
                    "revision": key[1],
                    "status": "stale_rule_revision",
                    "passed": False,
                }
            )
            continue
        campaign_file = _campaign_child(root, str(pointer.get("campaign_file") or ""))
        work = _strict_json(campaign_file)
        manifest_value = work.get("evidence_manifest")
        sha_value = work.get("evidence_sha256")
        if not isinstance(manifest_value, str) or not manifest_value.strip():
            rows.append(
                {
                    "rule_id": descriptor.id,
                    "revision": descriptor.revision,
                    "status": "pending_external_evidence",
                    "passed": False,
                }
            )
            continue
        normalized_manifest = manifest_value.replace("\\", "/")
        if (
            "test/range/" in normalized_manifest.lower()
            or "ground_truth" in normalized_manifest.lower()
        ):
            rows.append(
                {
                    "rule_id": descriptor.id,
                    "revision": descriptor.revision,
                    "status": "range_evidence_forbidden",
                    "passed": False,
                }
            )
            continue
        manifest = _campaign_child(root, normalized_manifest)
        if not isinstance(sha_value, str) or len(sha_value) != 64:
            rows.append(
                {
                    "rule_id": descriptor.id,
                    "revision": descriptor.revision,
                    "status": "evidence_sha256_missing",
                    "passed": False,
                }
            )
            continue
        try:
            summary = load_qualification_evidence(
                manifest,
                descriptor=descriptor,
                expected_sha256=sha_value,
                evidence_root=root,
            )
            gates = {
                "external_projects": summary.external_projects >= 3,
                "positive_cases": summary.positive_cases >= 10,
                "near_miss_negative_cases": summary.near_miss_negative_cases >= 20,
                "metamorphic_variants": summary.metamorphic_variants >= 3,
                "vulnerable_fixed_pair": summary.vulnerable_fixed_pair,
                "external_precision": summary.external_precision >= 0.9,
                "leakage_lint": summary.leakage_lint_passed,
            }
            passed = all(gates.values())
            rows.append(
                {
                    **summary.to_dict(),
                    "status": "qualified" if passed else "evidence_below_threshold",
                    "passed": passed,
                    "gates": gates,
                }
            )
        except RuleCatalogError as exc:
            rows.append(
                {
                    "rule_id": descriptor.id,
                    "revision": descriptor.revision,
                    "status": "invalid_external_evidence",
                    "passed": False,
                    "error": str(exc),
                }
            )
    for rule_id, revision in sorted(set(descriptors) - seen):
        rows.append(
            {
                "rule_id": rule_id,
                "revision": revision,
                "status": "missing_campaign_rule",
                "passed": False,
            }
        )
    passed_count = sum(row.get("passed") is True for row in rows)
    return {
        "schema_version": REPORT_SCHEMA,
        "campaign_sha256": hashlib.sha256((root / "campaign.json").read_bytes()).hexdigest(),
        "rule_count": len(rows),
        "qualified_count": passed_count,
        "pending_or_failed_count": len(rows) - passed_count,
        "complete": bool(rows) and passed_count == len(rows),
        "rules": rows,
    }


def assemble(root: Path, output: Path) -> Dict[str, Any]:
    report = verify(root)
    if not report["complete"]:
        raise RuleCatalogError(
            "qualification campaign is incomplete; registry assembly is forbidden"
        )
    qualifications = []
    for row in report["rules"]:
        qualifications.append(
            {
                "rule_id": row["rule_id"],
                "revision": row["revision"],
                "state": "qualified",
                "evidence_sha256": row["source_sha256"],
                "external_projects": row["external_projects"],
                "positive_cases": row["positive_cases"],
                "near_miss_negative_cases": row["near_miss_negative_cases"],
                "metamorphic_variants": row["metamorphic_variants"],
                "vulnerable_fixed_pair": row["vulnerable_fixed_pair"],
                "external_precision": row["external_precision"],
            }
        )
    registry = {
        "schema_version": "zscope.rule-qualification.v1",
        "legacy_stable_policy": "require_explicit",
        "qualifications": qualifications,
    }
    _write_new(Path(output), registry)
    return registry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)
    verify_parser.add_argument("--output", type=Path)
    assemble_parser = commands.add_parser("assemble")
    assemble_parser.add_argument("--root", type=Path, required=True)
    assemble_parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(args.output)
        elif args.command == "verify":
            result = verify(args.root)
            if args.output:
                _write_new(args.output, result)
        else:
            result = assemble(args.root, args.output)
    except RuleCatalogError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
