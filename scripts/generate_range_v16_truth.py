#!/usr/bin/env python3
"""Normalize protected E0 reviews and build independently bound Range Truth v16.

The ``normalize`` command is intentionally strict: any material difference
between Fable and DeepSeek requires an Opus decision, and the nine frozen
disputed IDs always require Opus.  The ``build`` command consumes only that
normalized adjudication plus independently compiled safe-pair manifests.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from e0_review_governance import (  # noqa: E402
    E0GovernanceError,
    load_json_strict,
    sha256_file,
    sha256_value,
    validate_review_decision,
    validate_review_packet,
)
from run_e0_reviewers import (  # noqa: E402
    DISPUTED_IDS,
    MATERIAL_DECISION_FIELDS,
    _validate_existing_primary,
    validate_decision_against_packet,
)
from validate_range_v16_truth import (  # noqa: E402
    NORMALIZED_SCHEMA_VERSION,
    TRUTH_CONTRACT_SCHEMA_VERSION,
    TRUTH_RECORD_SCHEMA_VERSION,
    range_fixture_manifest_sha,
    validate_normalized_decisions,
    validate_pair_index,
    validate_pair_manifest,
    validate_review_provenance,
    validate_truth_manifest,
    validate_truth_v16,
)


_REVIEW_IDENTITIES = {
    "fable": ("primary_fable", "claude-fable-5"),
    "deepseek": ("primary_deepseek", "deepseek-v4-pro-0813:max"),
    "opus": ("arbiter_opus", "claude-opus-5"),
}


def _json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")


def _mapping(path: Path) -> Mapping[str, Any]:
    value = load_json_strict(path.resolve(strict=True))
    if not isinstance(value, Mapping):
        raise E0GovernanceError(f"JSON artifact must be an object: {path}")
    return value


def _validate_packet_catalog(path: Path, packet_dir: Path) -> tuple[Mapping[str, Any], str]:
    catalog = _mapping(path)
    if (
        set(catalog)
        != {
            "schema_version",
            "source_truth_sha256",
            "record_count",
            "packets",
            "catalog_sha256",
        }
        or catalog.get("schema_version") != "zscope.range-v16-review-packet-catalog.v1"
    ):
        raise E0GovernanceError("review packet catalog fields or schema are invalid")
    records = catalog.get("packets")
    if not isinstance(records, list) or len(records) != 136 or catalog.get("record_count") != 136:
        raise E0GovernanceError("review packet catalog requires exactly 136 records")
    if catalog.get("catalog_sha256") != sha256_value(records):
        raise E0GovernanceError("review packet catalog content hash mismatch")
    seen: set[str] = set()
    for item in records:
        if not isinstance(item, Mapping) or set(item) != {
            "truth_id",
            "packet_uid",
            "packet_sha256",
            "file_sha256",
        }:
            raise E0GovernanceError("review packet catalog record is invalid")
        truth_id = str(item.get("truth_id") or "")
        if not truth_id or truth_id in seen:
            raise E0GovernanceError("review packet catalog truth IDs are duplicate")
        seen.add(truth_id)
        packet_path = packet_dir / f"{truth_id}.json"
        if sha256_file(packet_path.resolve(strict=True)) != item.get("file_sha256"):
            raise E0GovernanceError(f"review packet file hash mismatch: {truth_id}")
        packet = _mapping(packet_path)
        validate_review_packet(packet)
        if packet.get("packet_uid") != item.get("packet_uid") or packet.get(
            "packet_sha256"
        ) != item.get("packet_sha256"):
            raise E0GovernanceError(f"review packet catalog identity mismatch: {truth_id}")
    return catalog, str(catalog["catalog_sha256"])


def _validate_review_bundle(root: Path, manifest_path: Path) -> str:
    manifest = _mapping(manifest_path)
    if (
        set(manifest) != {"schema_version", "files", "file_count", "bundle_sha256"}
        or manifest.get("schema_version") != "zscope.range-v16-review-bundle.v1"
    ):
        raise E0GovernanceError("review bundle manifest fields or schema are invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or manifest.get("file_count") != len(files):
        raise E0GovernanceError("review bundle file count is invalid")
    if manifest.get("bundle_sha256") != sha256_value(files):
        raise E0GovernanceError("review bundle hash mismatch")
    seen: set[str] = set()
    for record in files:
        if not isinstance(record, Mapping) or set(record) != {"path", "size", "sha256"}:
            raise E0GovernanceError("review bundle file binding is invalid")
        relative = str(record.get("path") or "")
        posix_path = PurePosixPath(relative)
        if (
            relative in seen
            or not relative
            or posix_path.is_absolute()
            or posix_path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in posix_path.parts)
            or posix_path.parts[0] not in {"fable", "deepseek", "opus"}
        ):
            raise E0GovernanceError("review bundle paths must be unique")
        seen.add(relative)
        path = (root / relative).resolve(strict=True)
        try:
            path.relative_to(root.resolve(strict=True))
        except ValueError as exc:
            raise E0GovernanceError("review bundle path escapes its root") from exc
        if path.is_symlink() or not path.is_file():
            raise E0GovernanceError("review bundle path must be a regular file")
        if path.stat().st_size != record.get("size") or sha256_file(path) != record.get("sha256"):
            raise E0GovernanceError(f"review bundle file binding mismatch: {relative}")
    manifest_resolved = manifest_path.resolve(strict=True)
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise E0GovernanceError("review bundle cannot contain symlink artifacts")
        if not path.is_file() or path.resolve() == manifest_resolved:
            continue
        actual_files.add(path.relative_to(root).as_posix())
    if actual_files != seen:
        raise E0GovernanceError("review bundle contains unbound or missing files")
    return str(manifest["bundle_sha256"])


def _load_review(
    root: Path,
    truth_id: str,
    *,
    packet: Mapping[str, Any],
    reviewer: str,
) -> tuple[Mapping[str, Any], dict[str, str]]:
    role, model = _REVIEW_IDENTITIES[reviewer]
    decision_path = root / "decisions" / f"{truth_id}.json"
    raw_path = root / "raw" / f"{truth_id}.json"
    _validate_existing_primary(
        packet,
        reviewer=reviewer,
        decision_path=decision_path,
        raw_path=raw_path,
    )
    decision = _mapping(decision_path)
    validate_review_decision(
        decision,
        expected_packet_uid=str(packet["packet_uid"]),
        expected_packet_sha256=str(packet["packet_sha256"]),
        expected_role=role,
    )
    if decision.get("reviewer_model") != model:
        raise E0GovernanceError(f"{reviewer} model identity mismatch for {truth_id}")
    validate_decision_against_packet(
        decision,
        packet,
        require_resolvable_evidence=reviewer == "opus",
    )
    # Raw output remains outside Git, but the normalized record must bind its bytes.
    raw_path = raw_path.resolve(strict=True)
    if raw_path.is_symlink() or not raw_path.is_file():
        raise E0GovernanceError(f"raw review artifact is invalid: {raw_path}")
    return decision, {
        "role": role,
        "model": model,
        "decision_sha256": sha256_file(decision_path.resolve(strict=True)),
        "raw_sha256": sha256_file(raw_path),
    }


def _final_decision(decision: Mapping[str, Any]) -> dict[str, Any]:
    return {field: decision[field] for field in MATERIAL_DECISION_FIELDS}


def normalize_reviews(
    *,
    packet_dir: Path,
    packet_catalog_path: Path,
    review_root: Path,
    review_bundle_manifest: Path,
    provenance_path: Path,
) -> dict[str, Any]:
    catalog, catalog_sha = _validate_packet_catalog(packet_catalog_path, packet_dir)
    review_bundle_sha = _validate_review_bundle(review_root, review_bundle_manifest)
    provenance = _mapping(provenance_path)
    validate_review_provenance(provenance)
    if provenance.get("packet_catalog_sha256") != catalog_sha:
        raise E0GovernanceError("protected provenance packet catalog hash mismatch")
    if provenance.get("review_bundle_sha256") != review_bundle_sha:
        raise E0GovernanceError("protected provenance review bundle hash mismatch")

    records: list[dict[str, Any]] = []
    for catalog_record in catalog["packets"]:
        truth_id = str(catalog_record["truth_id"])
        packet = _mapping(packet_dir / f"{truth_id}.json")
        fable, fable_binding = _load_review(
            review_root / "fable", truth_id, packet=packet, reviewer="fable"
        )
        deepseek, deepseek_binding = _load_review(
            review_root / "deepseek", truth_id, packet=packet, reviewer="deepseek"
        )
        disagreement_fields = sorted(
            field for field in MATERIAL_DECISION_FIELDS if fable.get(field) != deepseek.get(field)
        )
        evidence_deficit = any(
            decision.get("contract_kind") in {"concrete_trigger", "public_api_contract"}
            and not decision.get("evidence_refs")
            for decision in (fable, deepseek)
        )
        opus_required = truth_id in DISPUTED_IDS or bool(disagreement_fields) or evidence_deficit
        opus_binding: dict[str, str] = {}
        selected = fable
        if opus_required:
            selected, opus_binding = _load_review(
                review_root / "opus", truth_id, packet=packet, reviewer="opus"
            )
        validate_decision_against_packet(
            selected,
            packet,
            require_resolvable_evidence=True,
        )
        final = _final_decision(selected)
        if final["disposition"] == "unresolved":
            final["contract_kind"] = "pattern_model"
        if final["disposition"] == "retire":
            final["contract_kind"] = "retired"
        record: dict[str, Any] = {
            "truth_id": truth_id,
            "packet_uid": packet["packet_uid"],
            "packet_sha256": packet["packet_sha256"],
            "primary_reviews": {"fable": fable_binding, "deepseek": deepseek_binding},
            "disagreement_fields": disagreement_fields,
            "opus_required": opus_required,
            "opus_review": opus_binding,
            "final_decision": final,
            "final_decision_sha256": sha256_value(final),
            "normalized_record_sha256": "",
        }
        unsigned = dict(record)
        unsigned.pop("normalized_record_sha256")
        record["normalized_record_sha256"] = sha256_value(unsigned)
        records.append(record)
    payload: dict[str, Any] = {
        "schema_version": NORMALIZED_SCHEMA_VERSION,
        "source_truth_sha256": catalog["source_truth_sha256"],
        "packet_catalog_sha256": catalog_sha,
        "review_bundle_sha256": review_bundle_sha,
        "review_provenance": dict(provenance),
        "record_count": len(records),
        "records": records,
        "content_sha256": "",
    }
    unsigned = dict(payload)
    unsigned.pop("content_sha256")
    payload["content_sha256"] = sha256_value(unsigned)
    validate_normalized_decisions(payload)
    return payload


def _validate_taxonomy_contract(taxonomy: Mapping[str, Any]) -> None:
    if taxonomy.get("schema_version") != "zscope.defect-taxonomy.v1":
        raise E0GovernanceError("defect taxonomy schema is invalid")
    families = taxonomy.get("families")
    if not isinstance(families, Mapping):
        raise E0GovernanceError("defect taxonomy families are missing")
    for values in families.values():
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise E0GovernanceError("defect taxonomy aliases are invalid")


def _apply_anchors(record: dict[str, Any], anchors: Sequence[Mapping[str, Any]]) -> None:
    for field in (
        "secondary_file",
        "secondary_function",
        "secondary_line",
        "secondary_end_line",
        "sibling_file",
        "sibling_function",
        "sibling_line",
        "sibling_end_line",
        "additional_locations",
    ):
        record.pop(field, None)
    primary = next((anchor for anchor in anchors if anchor.get("kind") == "primary"), anchors[0])
    record.update(
        {
            "file": primary["file"],
            "function": primary["function"],
            "line": primary["start_line"],
            "end_line": primary["end_line"],
        }
    )
    secondaries = [anchor for anchor in anchors if anchor.get("kind") == "secondary"]
    if secondaries:
        secondary = secondaries[0]
        record.update(
            {
                "secondary_file": secondary["file"],
                "secondary_function": secondary["function"],
                "secondary_line": secondary["start_line"],
                "secondary_end_line": secondary["end_line"],
            }
        )
    additional = [
        {
            "file": anchor["file"],
            "function": anchor["function"],
            "line": anchor["start_line"],
            "end_line": anchor["end_line"],
        }
        for anchor in anchors
        if anchor is not primary and anchor not in secondaries[:1]
    ]
    if additional:
        record["additional_locations"] = additional


def build_truth_v16(
    *,
    truth_v15: Mapping[str, Any],
    normalized: Mapping[str, Any],
    pair_root: Path,
    taxonomy_path: Path,
    fixture_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_normalized_decisions(normalized)
    records_v15 = truth_v15.get("vulnerabilities")
    if not isinstance(records_v15, list) or len(records_v15) != 136:
        raise E0GovernanceError("source Truth v15 must contain exactly 136 records")
    taxonomy = _mapping(taxonomy_path)
    _validate_taxonomy_contract(taxonomy)
    decisions = {str(item["truth_id"]): item for item in normalized["records"]}
    source_by_id = {
        str(item.get("id") or ""): item for item in records_v15 if isinstance(item, Mapping)
    }
    if set(decisions) != set(source_by_id):
        raise E0GovernanceError("normalized decisions do not exactly cover source Truth v15")
    output_records: list[dict[str, Any]] = []
    pair_index_records: list[dict[str, Any]] = []
    for truth_id in sorted(source_by_id):
        normalized_record = decisions[truth_id]
        decision = normalized_record["final_decision"]
        taxonomy_id = str(decision["defect_taxonomy_id"])
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,127}", taxonomy_id):
            raise E0GovernanceError(f"truth {truth_id} uses invalid taxonomy ID {taxonomy_id}")
        kind = str(decision["contract_kind"])
        disposition = str(decision["disposition"])
        status = (
            "retired"
            if kind == "retired"
            else (
                "corrected"
                if disposition == "correct"
                or any(bool(anchor.get("corrected")) for anchor in decision["structured_anchors"])
                else "accepted"
            )
        )
        anchors = [
            {key: anchor[key] for key in ("kind", "file", "function", "start_line", "end_line")}
            for anchor in decision["structured_anchors"]
        ]
        review_artifacts = {
            "fable_sha256": normalized_record["primary_reviews"]["fable"]["raw_sha256"],
            "deepseek_sha256": normalized_record["primary_reviews"]["deepseek"]["raw_sha256"],
            "normalized_sha256": normalized_record["normalized_record_sha256"],
        }
        if normalized_record["opus_required"]:
            review_artifacts["opus_sha256"] = normalized_record["opus_review"]["raw_sha256"]
        pair_contract: dict[str, Any] = {}
        if kind in {"concrete_trigger", "public_api_contract"}:
            pair_dir = pair_root / truth_id
            pair_manifest_path = pair_dir / "manifest.json"
            pair_manifest = _mapping(pair_manifest_path)
            bound = validate_pair_manifest(pair_manifest, pair_root=pair_dir)
            if pair_manifest.get("truth_id") != truth_id:
                raise E0GovernanceError(f"safe pair truth identity mismatch: {truth_id}")
            if pair_manifest.get("contract_kind") != kind:
                raise E0GovernanceError(f"safe pair contract kind mismatch: {truth_id}")
            if (
                pair_manifest.get("review_decision_sha256")
                != normalized_record["final_decision_sha256"]
            ):
                raise E0GovernanceError(f"safe pair review binding mismatch: {truth_id}")
            pair_contract = {
                "pair_uid": pair_manifest["pair_uid"],
                "manifest_sha256": sha256_file(pair_manifest_path.resolve(strict=True)),
                "vulnerable_sha256": bound["vulnerable"]["sha256"],
                "fixed_or_near_miss_sha256": bound["fixed_or_near_miss"]["sha256"],
            }
            pair_index_records.append(
                {
                    "truth_id": truth_id,
                    **pair_contract,
                    "content_sha256": pair_manifest["content_sha256"],
                }
            )
        record = dict(source_by_id[truth_id])
        record["source_v15_id"] = truth_id
        record["stable_uid"] = f"range-truth:{truth_id}"
        record["category"] = taxonomy_id
        record["cwe_ids"] = list(decision["cwe_ids"])
        record["cwe"] = "/".join(decision["cwe_ids"])
        _apply_anchors(record, anchors)
        record["verification_contract"] = {
            "schema_version": TRUTH_RECORD_SCHEMA_VERSION,
            "kind": kind,
            "adjudication_status": status,
            "defect_taxonomy_id": taxonomy_id,
            "structured_anchors": anchors,
            "trigger": {
                "summary": decision["trigger_summary"],
                "evidence_refs": list(decision["evidence_refs"]),
            },
            "threat_assumptions": list(decision["threat_assumptions"]),
            "required_evidence_clauses": list(decision["required_evidence_clauses"]),
            "review_artifacts": review_artifacts,
            "safe_pair": pair_contract,
            "fixture_sha256": fixture_sha256,
        }
        output_records.append(record)
    canonical = [
        {"truth_id": record["id"], **record["verification_contract"]} for record in output_records
    ]
    truth: dict[str, Any] = {
        "benchmark": str(truth_v15.get("benchmark") or "zscope-range-service-runtime"),
        "version": 16,
        "notes": (
            "Truth v16 is independently adjudicated under zscope.range-truth-contract.v2; "
            "v15 remains historical and v4/v5 scores are not directly comparable."
        ),
        "truth_contract": {
            "schema_version": TRUTH_CONTRACT_SCHEMA_VERSION,
            "manifest_sha256": sha256_value(canonical),
            "review_bundle_sha256": normalized["review_bundle_sha256"],
            "taxonomy_sha256": sha256_file(taxonomy_path.resolve(strict=True)),
            "independent_review_complete": True,
            "review_protocol": "Fable 5 + DSH deepseek/deepseek-v4-pro-0813 Max; Opus 5 mandatory/disagreement arbitration",
            "safe_unit_count": len(pair_index_records),
        },
        "total_vulnerabilities": len(output_records),
        "vulnerabilities": output_records,
    }
    pair_index: dict[str, Any] = {
        "schema_version": "zscope.range-v16-safe-pair-index.v1",
        "record_count": len(pair_index_records),
        "records": pair_index_records,
        "content_sha256": sha256_value(pair_index_records),
    }
    validate_truth_v16(truth, pair_root=pair_root)
    return truth, pair_index


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    normalize = sub.add_parser("normalize")
    normalize.add_argument("--packet-dir", required=True, type=Path)
    normalize.add_argument("--packet-catalog", required=True, type=Path)
    normalize.add_argument("--review-root", required=True, type=Path)
    normalize.add_argument("--review-bundle-manifest", required=True, type=Path)
    normalize.add_argument("--review-provenance", required=True, type=Path)
    normalize.add_argument("--output", required=True, type=Path)
    build = sub.add_parser("build")
    build.add_argument("--truth-v15", required=True, type=Path)
    build.add_argument("--normalized-decisions", required=True, type=Path)
    build.add_argument("--pair-root", required=True, type=Path)
    build.add_argument("--fixture-root", required=True, type=Path)
    build.add_argument("--taxonomy", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--pair-index-output", required=True, type=Path)
    build.add_argument("--truth-manifest-output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "normalize":
            payload = normalize_reviews(
                packet_dir=args.packet_dir.resolve(strict=True),
                packet_catalog_path=args.packet_catalog.resolve(strict=True),
                review_root=args.review_root.resolve(strict=True),
                review_bundle_manifest=args.review_bundle_manifest.resolve(strict=True),
                provenance_path=args.review_provenance.resolve(strict=True),
            )
            _json_dump(args.output, payload)
        else:
            truth = _mapping(args.truth_v15)
            normalized = _mapping(args.normalized_decisions)
            if sha256_file(args.truth_v15.resolve(strict=True)) != normalized.get(
                "source_truth_sha256"
            ):
                raise E0GovernanceError("source Truth v15 byte hash does not match review packets")
            fixture_sha = range_fixture_manifest_sha(args.fixture_root)
            output, pair_index = build_truth_v16(
                truth_v15=truth,
                normalized=normalized,
                pair_root=args.pair_root.resolve(strict=True),
                taxonomy_path=args.taxonomy.resolve(strict=True),
                fixture_sha256=fixture_sha,
            )
            _json_dump(args.output, output)
            _json_dump(args.pair_index_output, pair_index)
            truth_manifest = {
                "schema_version": "zscope.range-v16-truth-manifest.v1",
                "truth_sha256": sha256_file(args.output.resolve(strict=True)),
                "truth_contract_manifest_sha256": output["truth_contract"]["manifest_sha256"],
                "source_v15_sha256": normalized["source_truth_sha256"],
                "normalized_decisions_sha256": sha256_file(
                    args.normalized_decisions.resolve(strict=True)
                ),
                "review_bundle_sha256": normalized["review_bundle_sha256"],
                "packet_catalog_sha256": normalized["packet_catalog_sha256"],
                "taxonomy_sha256": sha256_file(args.taxonomy.resolve(strict=True)),
                "fixture_tree_sha256": fixture_sha,
                "safe_pair_index_sha256": sha256_file(args.pair_index_output.resolve(strict=True)),
                "counts_by_kind": {
                    kind: sum(
                        1
                        for record in output["vulnerabilities"]
                        if record["verification_contract"]["kind"] == kind
                    )
                    for kind in (
                        "concrete_trigger",
                        "public_api_contract",
                        "pattern_model",
                        "retired",
                    )
                },
                "v15_v16_directly_comparable": False,
                "v4_v5_directly_comparable": False,
                "content_sha256": "",
            }
            unsigned = dict(truth_manifest)
            unsigned.pop("content_sha256")
            truth_manifest["content_sha256"] = sha256_value(unsigned)
            _json_dump(args.truth_manifest_output, truth_manifest)
            validate_pair_index(pair_index, pair_root=args.pair_root.resolve(strict=True))
            validate_truth_manifest(
                truth_manifest,
                truth_path=args.output,
                normalized_path=args.normalized_decisions,
                pair_index_path=args.pair_index_output,
                taxonomy_path=args.taxonomy,
                fixture_root=args.fixture_root,
            )
    except (E0GovernanceError, OSError) as exc:
        print(f"Range Truth v16 generation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
