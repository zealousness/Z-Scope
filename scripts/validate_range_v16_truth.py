#!/usr/bin/env python3
"""Validate Range Truth v16 review, pair, and truth artifacts fail closed.

This module belongs to the truth/fixture governance domain.  It deliberately
does not import product reports or the benchmark scorer.  Raw reviewer output
is validated outside Git and is referenced here only by content hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from e0_review_governance import (  # noqa: E402
    CONTRACT_KINDS,
    E0GovernanceError,
    SHA256_RE,
    load_json_strict,
    sha256_file,
    sha256_value,
    validate_review_provenance,
)


NORMALIZED_SCHEMA_VERSION = "zscope.range-v16-normalized-decisions.v1"
PAIR_SCHEMA_VERSION = "zscope.range-v16-safe-pair.v1"
PAIR_INDEX_SCHEMA_VERSION = "zscope.range-v16-safe-pair-index.v1"
TRUTH_MANIFEST_SCHEMA_VERSION = "zscope.range-v16-truth-manifest.v1"
TRUTH_RECORD_SCHEMA_VERSION = "zscope.range-truth-record.v2"
TRUTH_CONTRACT_SCHEMA_VERSION = "zscope.range-truth-contract.v2"
TRUTH_ADJUDICATION_STATUSES = frozenset({"accepted", "corrected", "retired"})
TRUTH_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "adjudication_status",
        "defect_taxonomy_id",
        "structured_anchors",
        "trigger",
        "threat_assumptions",
        "required_evidence_clauses",
        "review_artifacts",
        "safe_pair",
        "fixture_sha256",
    }
)
TRUTH_ENTRY_REQUIRED_FIELDS = frozenset(
    {
        "id",
        "source_v15_id",
        "stable_uid",
        "category",
        "cwe",
        "cwe_ids",
        "file",
        "function",
        "line",
        "end_line",
        "severity",
        "title",
        "keywords",
        "verification_contract",
    }
)
TRUTH_ENTRY_ALLOWED_FIELDS = TRUTH_ENTRY_REQUIRED_FIELDS | frozenset(
    {
        "additional_locations",
        "flow",
        "notes",
        "related_functions",
        "scope",
        "secondary_end_line",
        "secondary_file",
        "secondary_function",
        "secondary_line",
        "source_issue",
        "source_model",
        "subtype",
        "tier",
        "weight",
    }
)
ANCHOR_KINDS = frozenset({"primary", "secondary", "additional"})
CLAUSE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


def _canonical_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise E0GovernanceError(f"{field} must be a canonical POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise E0GovernanceError(f"{field} must be a canonical POSIX path")
    return value


def _strict_sha(value: Any, *, field: str) -> str:
    raw = str(value or "")
    if not SHA256_RE.fullmatch(raw):
        raise E0GovernanceError(f"{field} must be sha256")
    return raw


def _resolve_beneath(root: Path, relative: str, *, field: str) -> Path:
    _canonical_path(relative, field=field)
    root = root.resolve(strict=True)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise E0GovernanceError(f"{field} cannot traverse a symlink")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise E0GovernanceError(f"{field} escapes its artifact root") from exc
    if not resolved.is_file():
        raise E0GovernanceError(f"{field} must identify a regular file")
    return resolved


def directory_manifest_sha(root: Path) -> str:
    root = root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
        if path.is_symlink():
            raise E0GovernanceError("fixture manifest cannot contain symlinks")
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    if not records:
        raise E0GovernanceError("fixture manifest cannot be empty")
    return str(sha256_value(records))


def range_fixture_manifest_sha(root: Path) -> str:
    """Hash only the answer-free Range scan-input allowlist.

    Truth, scorer, review, build, and cache artifacts are deliberately outside
    this identity.  Including ``benchmark/v16`` would create a circular hash in
    which writing Truth v16 invalidates its own fixture binding.
    """

    root = root.resolve(strict=True)
    candidates: list[Path] = []
    for directory_name in ("src", "include", "internal"):
        directory = root / directory_name
        if directory.is_dir() and not directory.is_symlink():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    for file_name in ("CMakeLists.txt", "README.md"):
        path = root / file_name
        if path.is_file():
            candidates.append(path)
    records: list[dict[str, Any]] = []
    for path in sorted(set(candidates), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise E0GovernanceError("Range fixture allowlist cannot traverse symlinks")
        records.append(
            {
                "path": relative.as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    if not records:
        raise E0GovernanceError("Range fixture answer-free allowlist cannot be empty")
    return str(sha256_value(records))


def validate_pair_manifest(value: Mapping[str, Any], *, pair_root: Path) -> dict[str, Any]:
    expected = {
        "schema_version",
        "truth_id",
        "pair_uid",
        "contract_kind",
        "kind",
        "invariant_summary",
        "review_decision_sha256",
        "compiler_contract",
        "vulnerable",
        "fixed_or_near_miss",
        "content_sha256",
    }
    if set(value) != expected or value.get("schema_version") != PAIR_SCHEMA_VERSION:
        raise E0GovernanceError("safe-pair manifest fields or schema are invalid")
    truth_id = str(value.get("truth_id") or "")
    if not truth_id or value.get("pair_uid") != f"range-v16-pair:{truth_id}":
        raise E0GovernanceError("safe-pair identity is invalid")
    if value.get("contract_kind") not in {"concrete_trigger", "public_api_contract"}:
        raise E0GovernanceError("safe pair may bind only confirmable truth")
    if value.get("kind") not in {"fixed", "near_miss"}:
        raise E0GovernanceError("safe-pair kind is invalid")
    if (
        not isinstance(value.get("invariant_summary"), str)
        or not value["invariant_summary"].strip()
    ):
        raise E0GovernanceError("safe-pair invariant is missing")
    _strict_sha(value.get("review_decision_sha256"), field="review decision hash")
    compiler = value.get("compiler_contract")
    if not isinstance(compiler, Mapping) or set(compiler) != {
        "language",
        "standard",
        "compiler",
        "arguments",
    }:
        raise E0GovernanceError("safe-pair compiler contract is invalid")
    if compiler.get("language") != "c" or compiler.get("standard") not in {"c11", "gnu11"}:
        raise E0GovernanceError("safe-pair language contract is invalid")
    if compiler.get("compiler") not in {"cc", "gcc", "clang"}:
        raise E0GovernanceError("safe-pair compiler identity is invalid")
    arguments = compiler.get("arguments")
    if not isinstance(arguments, list) or not all(isinstance(arg, str) for arg in arguments):
        raise E0GovernanceError("safe-pair compiler arguments are invalid")
    forbidden_args = {"-o", "--output", "-include", "-imacros"}
    if any(arg in forbidden_args or arg.startswith("@") for arg in arguments):
        raise E0GovernanceError("safe-pair compiler arguments contain unsafe indirection")

    bound: dict[str, Any] = {}
    for side in ("vulnerable", "fixed_or_near_miss"):
        record = value.get(side)
        if not isinstance(record, Mapping) or set(record) != {"path", "sha256"}:
            raise E0GovernanceError(f"safe-pair {side} binding is invalid")
        relative = _canonical_path(record.get("path"), field=f"safe-pair {side} path")
        if not relative.startswith(f"{side}/") or not relative.endswith(".c"):
            raise E0GovernanceError(f"safe-pair {side} path is outside its side directory")
        source = _resolve_beneath(pair_root, relative, field=f"safe-pair {side} path")
        claimed = _strict_sha(record.get("sha256"), field=f"safe-pair {side} hash")
        if sha256_file(source) != claimed:
            raise E0GovernanceError(f"safe-pair {side} source hash mismatch")
        bound[side] = {"path": relative, "sha256": claimed, "source": source}

    unsigned = dict(value)
    unsigned.pop("content_sha256", None)
    if value.get("content_sha256") != sha256_value(unsigned):
        raise E0GovernanceError("safe-pair manifest content hash mismatch")
    return bound


def compile_pair_manifest(value: Mapping[str, Any], *, pair_root: Path) -> None:
    bound = validate_pair_manifest(value, pair_root=pair_root)
    compiler = value["compiler_contract"]
    for side in ("vulnerable", "fixed_or_near_miss"):
        with tempfile.TemporaryDirectory(prefix="zscope-range-v16-pair-") as raw_temp:
            output = Path(raw_temp) / "case.o"
            command = [
                str(compiler["compiler"]),
                f"-std={compiler['standard']}",
                "-Werror",
                "-Wall",
                "-Wextra",
                *compiler["arguments"],
                "-c",
                str(bound[side]["source"]),
                "-o",
                str(output),
            ]
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if completed.returncode != 0 or not output.is_file():
                raise E0GovernanceError(
                    f"safe-pair {side} does not compile independently: "
                    f"{completed.stderr[-1000:]}"
                )


def validate_pair_index(value: Mapping[str, Any], *, pair_root: Path) -> set[str]:
    if set(value) != {"schema_version", "record_count", "records", "content_sha256"}:
        raise E0GovernanceError("safe-pair index fields are invalid")
    if value.get("schema_version") != PAIR_INDEX_SCHEMA_VERSION:
        raise E0GovernanceError("safe-pair index schema is invalid")
    records = value.get("records")
    if not isinstance(records, list) or value.get("record_count") != len(records):
        raise E0GovernanceError("safe-pair index count is invalid")
    if value.get("content_sha256") != sha256_value(records):
        raise E0GovernanceError("safe-pair index content hash mismatch")
    seen_truth: set[str] = set()
    seen_pair: set[str] = set()
    pair_root = pair_root.resolve(strict=True)
    for record in records:
        expected = {
            "truth_id",
            "pair_uid",
            "manifest_sha256",
            "vulnerable_sha256",
            "fixed_or_near_miss_sha256",
            "content_sha256",
        }
        if not isinstance(record, Mapping) or set(record) != expected:
            raise E0GovernanceError("safe-pair index record fields are invalid")
        truth_id = str(record.get("truth_id") or "")
        pair_uid = str(record.get("pair_uid") or "")
        if not truth_id or truth_id in seen_truth:
            raise E0GovernanceError("safe-pair index truth IDs must be unique")
        if pair_uid != f"range-v16-pair:{truth_id}" or pair_uid in seen_pair:
            raise E0GovernanceError("safe-pair index pair UIDs must be unique and canonical")
        seen_truth.add(truth_id)
        seen_pair.add(pair_uid)
        pair_dir = pair_root / truth_id
        manifest_path = _resolve_beneath(
            pair_root,
            f"{truth_id}/manifest.json",
            field=f"safe-pair index {truth_id} manifest",
        )
        manifest = load_json_strict(manifest_path)
        if not isinstance(manifest, Mapping):
            raise E0GovernanceError("indexed safe-pair manifest must be an object")
        bound = validate_pair_manifest(manifest, pair_root=pair_dir)
        expected_values = {
            "pair_uid": manifest["pair_uid"],
            "manifest_sha256": sha256_file(manifest_path),
            "vulnerable_sha256": bound["vulnerable"]["sha256"],
            "fixed_or_near_miss_sha256": bound["fixed_or_near_miss"]["sha256"],
            "content_sha256": manifest["content_sha256"],
        }
        if any(record.get(field) != expected_value for field, expected_value in expected_values.items()):
            raise E0GovernanceError(f"safe-pair index binding mismatch: {truth_id}")
    manifest_ids = {
        path.parent.name
        for path in pair_root.glob("*/manifest.json")
        if path.is_file() and not path.is_symlink()
    }
    if manifest_ids != seen_truth:
        raise E0GovernanceError("safe-pair index does not exactly cover pair manifests")
    return seen_truth


def validate_truth_manifest(
    value: Mapping[str, Any],
    *,
    truth_path: Path,
    normalized_path: Path,
    pair_index_path: Path,
    taxonomy_path: Path,
    fixture_root: Path,
) -> None:
    expected = {
        "schema_version",
        "truth_sha256",
        "truth_contract_manifest_sha256",
        "source_v15_sha256",
        "normalized_decisions_sha256",
        "review_bundle_sha256",
        "packet_catalog_sha256",
        "taxonomy_sha256",
        "fixture_tree_sha256",
        "safe_pair_index_sha256",
        "counts_by_kind",
        "v15_v16_directly_comparable",
        "v4_v5_directly_comparable",
        "content_sha256",
    }
    if set(value) != expected or value.get("schema_version") != TRUTH_MANIFEST_SCHEMA_VERSION:
        raise E0GovernanceError("Truth v16 manifest fields or schema are invalid")
    for field in expected - {
        "schema_version",
        "counts_by_kind",
        "v15_v16_directly_comparable",
        "v4_v5_directly_comparable",
        "content_sha256",
    }:
        _strict_sha(value.get(field), field=f"Truth v16 manifest {field}")
    if value.get("v15_v16_directly_comparable") is not False or value.get(
        "v4_v5_directly_comparable"
    ) is not False:
        raise E0GovernanceError("Truth v16 manifest must declare historical scores incomparable")

    truth = load_json_strict(truth_path.resolve(strict=True))
    normalized = load_json_strict(normalized_path.resolve(strict=True))
    if not isinstance(truth, Mapping) or not isinstance(normalized, Mapping):
        raise E0GovernanceError("Truth or normalized decision artifact is invalid")
    validate_normalized_decisions(normalized)
    truth_contract = truth.get("truth_contract")
    if not isinstance(truth_contract, Mapping):
        raise E0GovernanceError("Truth v16 manifest cannot bind a missing truth contract")
    bindings = {
        "truth_sha256": sha256_file(truth_path.resolve(strict=True)),
        "truth_contract_manifest_sha256": truth_contract.get("manifest_sha256"),
        "source_v15_sha256": normalized.get("source_truth_sha256"),
        "normalized_decisions_sha256": sha256_file(normalized_path.resolve(strict=True)),
        "review_bundle_sha256": normalized.get("review_bundle_sha256"),
        "packet_catalog_sha256": normalized.get("packet_catalog_sha256"),
        "taxonomy_sha256": sha256_file(taxonomy_path.resolve(strict=True)),
        "fixture_tree_sha256": range_fixture_manifest_sha(fixture_root),
        "safe_pair_index_sha256": sha256_file(pair_index_path.resolve(strict=True)),
    }
    for field, expected_value in bindings.items():
        if value.get(field) != expected_value:
            raise E0GovernanceError(f"Truth v16 manifest binding mismatch: {field}")
    if truth_contract.get("review_bundle_sha256") != bindings["review_bundle_sha256"]:
        raise E0GovernanceError("Truth v16 contract/review bundle binding mismatch")
    if truth_contract.get("taxonomy_sha256") != bindings["taxonomy_sha256"]:
        raise E0GovernanceError("Truth v16 contract/taxonomy binding mismatch")
    fixture_hashes = {
        str(contract.get("fixture_sha256") or "")
        for record in truth.get("vulnerabilities", [])
        if isinstance(record, Mapping)
        for contract in [record.get("verification_contract")]
        if isinstance(contract, Mapping)
    }
    if fixture_hashes != {str(bindings["fixture_tree_sha256"])}:
        raise E0GovernanceError("Truth v16 contract/fixture binding mismatch")
    pair_index = load_json_strict(pair_index_path.resolve(strict=True))
    if not isinstance(pair_index, Mapping) or pair_index.get("record_count") != truth_contract.get(
        "safe_unit_count"
    ):
        raise E0GovernanceError("Truth v16 contract/safe-pair count mismatch")
    counts = value.get("counts_by_kind")
    expected_kinds = set(CONTRACT_KINDS)
    if not isinstance(counts, Mapping) or set(counts) != expected_kinds:
        raise E0GovernanceError("Truth v16 manifest contract counts are invalid")
    actual_counts = {kind: 0 for kind in expected_kinds}
    for record in truth.get("vulnerabilities", []):
        if not isinstance(record, Mapping):
            raise E0GovernanceError("Truth v16 manifest found an invalid truth record")
        contract = record.get("verification_contract")
        kind = contract.get("kind") if isinstance(contract, Mapping) else None
        if kind not in actual_counts:
            raise E0GovernanceError("Truth v16 manifest found an invalid contract kind")
        actual_counts[str(kind)] += 1
    if dict(counts) != actual_counts:
        raise E0GovernanceError("Truth v16 manifest contract counts mismatch")
    unsigned = dict(value)
    supplied = unsigned.pop("content_sha256", None)
    if supplied != sha256_value(unsigned):
        raise E0GovernanceError("Truth v16 manifest content hash mismatch")


def validate_normalized_decisions(value: Mapping[str, Any]) -> None:
    expected = {
        "schema_version",
        "source_truth_sha256",
        "packet_catalog_sha256",
        "review_bundle_sha256",
        "review_provenance",
        "record_count",
        "records",
        "content_sha256",
    }
    if set(value) != expected or value.get("schema_version") != NORMALIZED_SCHEMA_VERSION:
        raise E0GovernanceError("normalized decision fields or schema are invalid")
    for field in ("source_truth_sha256", "packet_catalog_sha256", "review_bundle_sha256"):
        _strict_sha(value.get(field), field=field)
    provenance = value.get("review_provenance")
    if not isinstance(provenance, Mapping):
        raise E0GovernanceError("normalized decisions lack protected provenance")
    validate_review_provenance(provenance)
    if provenance.get("packet_catalog_sha256") != value.get("packet_catalog_sha256"):
        raise E0GovernanceError("normalized packet catalog provenance mismatch")
    if provenance.get("review_bundle_sha256") != value.get("review_bundle_sha256"):
        raise E0GovernanceError("normalized review bundle provenance mismatch")
    records = value.get("records")
    if not isinstance(records, list) or len(records) != 136 or value.get("record_count") != 136:
        raise E0GovernanceError("normalized decisions require exactly 136 records")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise E0GovernanceError("normalized decision record must be an object")
        expected_record = {
            "truth_id",
            "packet_uid",
            "packet_sha256",
            "primary_reviews",
            "disagreement_fields",
            "opus_required",
            "opus_review",
            "final_decision",
            "final_decision_sha256",
            "normalized_record_sha256",
        }
        if set(record) != expected_record:
            raise E0GovernanceError("normalized decision record fields are invalid")
        truth_id = str(record.get("truth_id") or "")
        if not truth_id or truth_id in seen:
            raise E0GovernanceError("normalized truth IDs must be unique")
        seen.add(truth_id)
        if record.get("packet_uid") != f"range-v16:{truth_id}":
            raise E0GovernanceError("normalized packet UID mismatch")
        _strict_sha(record.get("packet_sha256"), field="normalized packet hash")
        reviews = record.get("primary_reviews")
        if not isinstance(reviews, Mapping) or set(reviews) != {"fable", "deepseek"}:
            raise E0GovernanceError("normalized primary review bindings are invalid")
        for reviewer, expected_role in (
            ("fable", "primary_fable"),
            ("deepseek", "primary_deepseek"),
        ):
            binding = reviews[reviewer]
            if not isinstance(binding, Mapping) or set(binding) != {
                "role",
                "model",
                "decision_sha256",
                "raw_sha256",
            }:
                raise E0GovernanceError("normalized primary review binding is invalid")
            if binding.get("role") != expected_role:
                raise E0GovernanceError("normalized primary reviewer role mismatch")
            _strict_sha(binding.get("decision_sha256"), field="review decision hash")
            _strict_sha(binding.get("raw_sha256"), field="raw review hash")
        disagreements = record.get("disagreement_fields")
        if not isinstance(disagreements, list) or not all(
            isinstance(field, str) and field for field in disagreements
        ):
            raise E0GovernanceError("normalized disagreement fields are invalid")
        if len(disagreements) != len(set(disagreements)):
            raise E0GovernanceError("normalized disagreement fields are duplicate")
        opus_required = record.get("opus_required")
        if not isinstance(opus_required, bool):
            raise E0GovernanceError("normalized Opus requirement must be boolean")
        opus = record.get("opus_review")
        if opus_required:
            if not isinstance(opus, Mapping) or set(opus) != {
                "role",
                "model",
                "decision_sha256",
                "raw_sha256",
            }:
                raise E0GovernanceError("required Opus review binding is missing")
            if opus.get("role") != "arbiter_opus":
                raise E0GovernanceError("Opus review role mismatch")
            _strict_sha(opus.get("decision_sha256"), field="Opus decision hash")
            _strict_sha(opus.get("raw_sha256"), field="Opus raw hash")
        elif opus not in ({}, None):
            raise E0GovernanceError("unexpected Opus review binding")
        final = record.get("final_decision")
        if not isinstance(final, Mapping) or final.get("contract_kind") not in CONTRACT_KINDS:
            raise E0GovernanceError("normalized final decision is invalid")
        if record.get("final_decision_sha256") != sha256_value(final):
            raise E0GovernanceError("normalized final decision hash mismatch")
        unsigned = dict(record)
        unsigned.pop("normalized_record_sha256", None)
        if record.get("normalized_record_sha256") != sha256_value(unsigned):
            raise E0GovernanceError("normalized record hash mismatch")
    unsigned = dict(value)
    unsigned.pop("content_sha256", None)
    if value.get("content_sha256") != sha256_value(unsigned):
        raise E0GovernanceError("normalized decisions content hash mismatch")


def _nonempty_string_list(value: Any, *, field: str, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise E0GovernanceError(f"{field} must be a string list")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise E0GovernanceError(f"{field} contains an invalid string")
    if len(value) != len(set(value)):
        raise E0GovernanceError(f"{field} contains duplicate values")
    return value


def _validate_truth_record_contract(
    truth_id: str,
    record: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> tuple[str, Mapping[str, Any]]:
    if set(contract) != TRUTH_RECORD_FIELDS:
        raise E0GovernanceError(f"Truth v16 {truth_id} record contract fields are invalid")
    if contract.get("schema_version") != TRUTH_RECORD_SCHEMA_VERSION:
        raise E0GovernanceError(f"Truth v16 {truth_id} record contract schema is invalid")

    kind = str(contract.get("kind") or "")
    status = str(contract.get("adjudication_status") or "")
    if kind not in CONTRACT_KINDS:
        raise E0GovernanceError(f"Truth v16 {truth_id} contract kind is invalid")
    if status not in TRUTH_ADJUDICATION_STATUSES:
        raise E0GovernanceError(f"Truth v16 {truth_id} adjudication status is invalid")
    if (kind == "retired") != (status == "retired"):
        raise E0GovernanceError(f"Truth v16 {truth_id} retired status is inconsistent")

    taxonomy_id = contract.get("defect_taxonomy_id")
    if not isinstance(taxonomy_id, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{1,127}", taxonomy_id
    ):
        raise E0GovernanceError(f"Truth v16 {truth_id} taxonomy identity is invalid")
    if record.get("category") != taxonomy_id:
        raise E0GovernanceError(f"Truth v16 {truth_id} category/taxonomy identity mismatch")

    anchors = contract.get("structured_anchors")
    if not isinstance(anchors, list) or not anchors:
        raise E0GovernanceError(f"Truth v16 {truth_id} structured anchors are missing")
    primary_anchors: list[Mapping[str, Any]] = []
    anchor_identities: set[tuple[Any, ...]] = set()
    for anchor in anchors:
        expected_anchor = {"kind", "file", "function", "start_line", "end_line"}
        if not isinstance(anchor, Mapping) or set(anchor) != expected_anchor:
            raise E0GovernanceError(f"Truth v16 {truth_id} structured anchor is invalid")
        anchor_kind = anchor.get("kind")
        if anchor_kind not in ANCHOR_KINDS:
            raise E0GovernanceError(f"Truth v16 {truth_id} anchor kind is invalid")
        file_name = _canonical_path(
            anchor.get("file"), field=f"Truth v16 {truth_id} anchor file"
        )
        function = anchor.get("function")
        if not isinstance(function, str) or not function.strip():
            raise E0GovernanceError(f"Truth v16 {truth_id} anchor function is invalid")
        start = anchor.get("start_line")
        end = anchor.get("end_line")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 1
            or end < start
        ):
            raise E0GovernanceError(f"Truth v16 {truth_id} anchor line range is invalid")
        identity = (anchor_kind, file_name, function, start, end)
        if identity in anchor_identities:
            raise E0GovernanceError(f"Truth v16 {truth_id} has duplicate structured anchors")
        anchor_identities.add(identity)
        if anchor_kind == "primary":
            primary_anchors.append(anchor)
    if len(primary_anchors) != 1:
        raise E0GovernanceError(f"Truth v16 {truth_id} requires exactly one primary anchor")
    primary = primary_anchors[0]
    if any(
        record.get(field) != primary.get(contract_field)
        for field, contract_field in (
            ("file", "file"),
            ("function", "function"),
            ("line", "start_line"),
        )
    ):
        raise E0GovernanceError(f"Truth v16 {truth_id} primary anchor projection mismatch")

    trigger = contract.get("trigger")
    if not isinstance(trigger, Mapping) or set(trigger) != {"summary", "evidence_refs"}:
        raise E0GovernanceError(f"Truth v16 {truth_id} trigger contract is invalid")
    if not isinstance(trigger.get("summary"), str) or not trigger["summary"].strip():
        raise E0GovernanceError(f"Truth v16 {truth_id} trigger summary is missing")
    _nonempty_string_list(
        trigger.get("evidence_refs"),
        field=f"Truth v16 {truth_id} trigger evidence refs",
        allow_empty=kind not in {"concrete_trigger", "public_api_contract"},
    )
    _nonempty_string_list(
        contract.get("threat_assumptions"),
        field=f"Truth v16 {truth_id} threat assumptions",
        allow_empty=False,
    )

    clauses = contract.get("required_evidence_clauses")
    if not isinstance(clauses, list) or not clauses:
        raise E0GovernanceError(f"Truth v16 {truth_id} required evidence clauses are missing")
    clause_ids: set[str] = set()
    for clause in clauses:
        if not isinstance(clause, Mapping) or set(clause) != {
            "clause_id",
            "predicate",
            "evidence_refs",
        }:
            raise E0GovernanceError(f"Truth v16 {truth_id} evidence clause is invalid")
        clause_id = clause.get("clause_id")
        if not isinstance(clause_id, str) or not CLAUSE_ID_RE.fullmatch(clause_id):
            raise E0GovernanceError(f"Truth v16 {truth_id} clause identity is invalid")
        if clause_id in clause_ids:
            raise E0GovernanceError(f"Truth v16 {truth_id} clause identities are duplicate")
        clause_ids.add(clause_id)
        if not isinstance(clause.get("predicate"), str) or not clause["predicate"].strip():
            raise E0GovernanceError(f"Truth v16 {truth_id} clause predicate is invalid")
        _nonempty_string_list(
            clause.get("evidence_refs"),
            field=f"Truth v16 {truth_id} clause evidence refs",
        )

    reviews = contract.get("review_artifacts")
    required_reviews = {"fable_sha256", "deepseek_sha256", "normalized_sha256"}
    if not isinstance(reviews, Mapping) or not required_reviews.issubset(reviews):
        raise E0GovernanceError(f"Truth v16 {truth_id} dual review artifacts are missing")
    if set(reviews) - (required_reviews | {"opus_sha256"}):
        raise E0GovernanceError(f"Truth v16 {truth_id} review artifacts contain unknown fields")
    for field, digest in reviews.items():
        _strict_sha(digest, field=f"Truth v16 {truth_id} {field}")

    fixture_sha = _strict_sha(
        contract.get("fixture_sha256"), field=f"Truth v16 {truth_id} fixture hash"
    )
    if not fixture_sha:
        raise E0GovernanceError(f"Truth v16 {truth_id} fixture hash is missing")

    pair = contract.get("safe_pair")
    if not isinstance(pair, Mapping):
        raise E0GovernanceError(f"Truth v16 {truth_id} safe pair contract is invalid")
    if kind in {"concrete_trigger", "public_api_contract"}:
        required_pair = {
            "pair_uid",
            "manifest_sha256",
            "vulnerable_sha256",
            "fixed_or_near_miss_sha256",
        }
        if set(pair) != required_pair:
            raise E0GovernanceError(f"Truth v16 {truth_id} safe pair fields are invalid")
        if pair.get("pair_uid") != f"range-v16-pair:{truth_id}":
            raise E0GovernanceError(f"Truth v16 {truth_id} safe pair UID is invalid")
        for field in required_pair - {"pair_uid"}:
            _strict_sha(pair.get(field), field=f"Truth v16 {truth_id} safe pair {field}")
    elif pair:
        raise E0GovernanceError(f"Truth v16 {truth_id} non-confirmable pair must be empty")
    return kind, pair


def validate_truth_v16(truth: Mapping[str, Any], *, pair_root: Path) -> dict[str, int]:
    expected_top = {
        "benchmark",
        "version",
        "notes",
        "truth_contract",
        "total_vulnerabilities",
        "vulnerabilities",
    }
    if set(truth) != expected_top or truth.get("version") != 16:
        raise E0GovernanceError("Truth v16 top-level fields are invalid")
    records = truth.get("vulnerabilities")
    if not isinstance(records, list) or len(records) != 136:
        raise E0GovernanceError("Truth v16 requires exactly 136 source records")
    if truth.get("total_vulnerabilities") != 136:
        raise E0GovernanceError("Truth v16 total_vulnerabilities is inconsistent")
    manifest = truth.get("truth_contract")
    expected_manifest = {
        "schema_version",
        "manifest_sha256",
        "review_bundle_sha256",
        "taxonomy_sha256",
        "independent_review_complete",
        "review_protocol",
        "safe_unit_count",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != expected_manifest:
        raise E0GovernanceError("Truth v16 contract manifest is invalid")
    if manifest.get("schema_version") != TRUTH_CONTRACT_SCHEMA_VERSION:
        raise E0GovernanceError("Truth v16 contract schema is invalid")
    if manifest.get("independent_review_complete") is not True:
        raise E0GovernanceError("Truth v16 independent review is incomplete")
    for field in ("manifest_sha256", "review_bundle_sha256", "taxonomy_sha256"):
        _strict_sha(manifest.get(field), field=field)
    safe_count = manifest.get("safe_unit_count")
    if isinstance(safe_count, bool) or not isinstance(safe_count, int) or safe_count < 0:
        raise E0GovernanceError("Truth v16 safe unit count is invalid")

    seen: set[str] = set()
    pair_uids: set[str] = set()
    fixture_hashes: set[str] = set()
    counts = {kind: 0 for kind in sorted(CONTRACT_KINDS)}
    canonical_records: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise E0GovernanceError("Truth v16 record must be an object")
        record_fields = set(record)
        if (
            not TRUTH_ENTRY_REQUIRED_FIELDS.issubset(record_fields)
            or not record_fields.issubset(TRUTH_ENTRY_ALLOWED_FIELDS)
        ):
            raise E0GovernanceError("Truth v16 source record fields are invalid")
        truth_id = str(record.get("id") or "")
        if not truth_id or truth_id in seen:
            raise E0GovernanceError("Truth v16 IDs must be unique and non-empty")
        seen.add(truth_id)
        if record.get("source_v15_id") != truth_id:
            raise E0GovernanceError(f"Truth v16 {truth_id} source v15 identity mismatch")
        if record.get("stable_uid") != f"range-truth:{truth_id}":
            raise E0GovernanceError(f"Truth v16 {truth_id} stable UID mismatch")
        cwe_ids = record.get("cwe_ids")
        if (
            not isinstance(cwe_ids, list)
            or not cwe_ids
            or len(cwe_ids) != len(set(cwe_ids))
            or not all(
                isinstance(cwe_id, str) and re.fullmatch(r"CWE-[0-9]+", cwe_id)
                for cwe_id in cwe_ids
            )
            or record.get("cwe") != "/".join(cwe_ids)
        ):
            raise E0GovernanceError(f"Truth v16 {truth_id} CWE identities are invalid")
        contract = record.get("verification_contract")
        if not isinstance(contract, Mapping):
            raise E0GovernanceError(f"Truth v16 {truth_id} record contract is invalid")
        kind, pair = _validate_truth_record_contract(truth_id, record, contract)
        counts[kind] += 1
        fixture_hashes.add(str(contract["fixture_sha256"]))
        if kind in {"concrete_trigger", "public_api_contract"}:
            pair_uid = str(pair.get("pair_uid") or "")
            if pair_uid in pair_uids:
                raise E0GovernanceError("Truth v16 safe-pair UIDs must be unique")
            pair_uids.add(pair_uid)
            pair_dir = pair_root / truth_id
            manifest_path = pair_dir / "manifest.json"
            actual_manifest_sha = sha256_file(manifest_path.resolve(strict=True))
            if pair.get("manifest_sha256") != actual_manifest_sha:
                raise E0GovernanceError(f"Truth v16 {truth_id} pair manifest hash mismatch")
            pair_manifest = load_json_strict(manifest_path)
            if not isinstance(pair_manifest, Mapping):
                raise E0GovernanceError(f"Truth v16 {truth_id} pair manifest must be an object")
            bound = validate_pair_manifest(pair_manifest, pair_root=pair_dir)
            if (
                pair_manifest.get("truth_id") != truth_id
                or pair_manifest.get("pair_uid") != pair_uid
            ):
                raise E0GovernanceError(f"Truth v16 {truth_id} pair identity mismatch")
            if pair.get("vulnerable_sha256") != bound["vulnerable"]["sha256"]:
                raise E0GovernanceError(f"Truth v16 {truth_id} vulnerable pair hash mismatch")
            if pair.get("fixed_or_near_miss_sha256") != bound["fixed_or_near_miss"]["sha256"]:
                raise E0GovernanceError(f"Truth v16 {truth_id} safe pair hash mismatch")
        canonical_records.append({"truth_id": truth_id, **dict(contract)})
    if len(fixture_hashes) != 1:
        raise E0GovernanceError("Truth v16 records do not bind one fixture snapshot")
    if (
        safe_count != len(pair_uids)
        or safe_count < counts["concrete_trigger"] + counts["public_api_contract"]
    ):
        raise E0GovernanceError("Truth v16 safe unit count does not cover confirmable truth")
    if manifest.get("manifest_sha256") != sha256_value(canonical_records):
        raise E0GovernanceError("Truth v16 contract manifest hash mismatch")
    return counts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--pair-root", required=True, type=Path)
    parser.add_argument("--truth-manifest", type=Path)
    parser.add_argument("--normalized-decisions", type=Path)
    parser.add_argument("--pair-index", type=Path)
    parser.add_argument("--taxonomy", type=Path)
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--compile-pairs", action="store_true")
    args = parser.parse_args(argv)
    try:
        truth = load_json_strict(args.truth.resolve(strict=True))
        if not isinstance(truth, Mapping):
            raise E0GovernanceError("Truth v16 must be an object")
        counts = validate_truth_v16(truth, pair_root=args.pair_root.resolve(strict=True))
        optional = {
            "truth_manifest": args.truth_manifest,
            "normalized_decisions": args.normalized_decisions,
            "pair_index": args.pair_index,
            "taxonomy": args.taxonomy,
            "fixture_root": args.fixture_root,
        }
        if any(optional.values()) and not all(optional.values()):
            raise E0GovernanceError(
                "truth manifest verification requires normalized, pair index, taxonomy, and fixture"
            )
        if args.pair_index:
            pair_index = load_json_strict(args.pair_index.resolve(strict=True))
            if not isinstance(pair_index, Mapping):
                raise E0GovernanceError("safe-pair index must be an object")
            validate_pair_index(pair_index, pair_root=args.pair_root.resolve(strict=True))
            truth_manifest = load_json_strict(args.truth_manifest.resolve(strict=True))
            if not isinstance(truth_manifest, Mapping):
                raise E0GovernanceError("Truth v16 manifest must be an object")
            validate_truth_manifest(
                truth_manifest,
                truth_path=args.truth,
                normalized_path=args.normalized_decisions,
                pair_index_path=args.pair_index,
                taxonomy_path=args.taxonomy,
                fixture_root=args.fixture_root,
            )
        if args.compile_pairs:
            for path in sorted(args.pair_root.glob("*/manifest.json")):
                manifest = load_json_strict(path)
                if not isinstance(manifest, Mapping):
                    raise E0GovernanceError(f"safe-pair manifest must be an object: {path}")
                compile_pair_manifest(manifest, pair_root=path.parent)
    except (E0GovernanceError, OSError, subprocess.SubprocessError) as exc:
        print(f"invalid Range Truth v16: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "valid", "counts_by_kind": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
