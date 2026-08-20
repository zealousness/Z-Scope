from __future__ import annotations

import hashlib
import json
import os
import shutil
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.e0_review_governance import sha256_file, sha256_value
from scripts.generate_range_v16_truth import _validate_review_bundle
from scripts.validate_range_v16_truth import (
    NORMALIZED_SCHEMA_VERSION,
    compile_pair_manifest,
    range_fixture_manifest_sha,
    validate_normalized_decisions,
    validate_pair_index,
    validate_pair_manifest,
    validate_review_provenance,
    validate_truth_manifest,
    validate_truth_v16,
)


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _provenance() -> dict:
    return {
        "schema_version": "zscope.range-v16-review-provenance.v1",
        "workflow_path": ".github/workflows/range-v16-review.yml",
        "workflow_run_id": 123,
        "workflow_head_sha": "a" * 40,
        "packet_source_sha": "b" * 40,
        "environment": "sealed-benchmark",
        "artifact_name": f"range-v16-reviewed-{'b' * 40}",
        "artifact_digest": f"sha256:{'a' * 64}",
        "packet_catalog_sha256": "c" * 64,
        "review_bundle_sha256": "d" * 64,
    }


def _normalized_record(index: int) -> dict:
    truth_id = f"T-{index:03d}"
    final = {
        "contract_kind": "pattern_model",
        "disposition": "unresolved",
        "defect_taxonomy_id": "bounds",
        "cwe_ids": ["CWE-125"],
        "structured_anchors": [
            {
                "kind": "primary",
                "corrected": False,
                "file": "src/demo.c",
                "function": "demo",
                "start_line": 1,
                "end_line": 2,
            }
        ],
        "required_evidence_clauses": [
            {"clause_id": "path", "predicate": "path exists", "evidence_refs": []}
        ],
        "evidence_refs": [],
        "trigger_summary": "Insufficient evidence for a concrete trigger.",
        "threat_assumptions": ["A caller contract is required."],
        "safe_pair_recommendation": {
            "kind": "near_miss",
            "invariant_summary": "A bound must dominate the access.",
            "vulnerable_summary": "The access is not dominated.",
            "safe_summary": "The access is dominated.",
            "compile_requirements": ["Compile as C11."],
        },
        "reason_codes": ["INSUFFICIENT_EVIDENCE"],
        "confidence": 0.8,
    }
    record = {
        "truth_id": truth_id,
        "packet_uid": f"range-v16:{truth_id}",
        "packet_sha256": "1" * 64,
        "primary_reviews": {
            "fable": {
                "role": "primary_fable",
                "model": "claude-fable-5",
                "decision_sha256": "2" * 64,
                "raw_sha256": "3" * 64,
            },
            "glm": {
                "role": "primary_glm",
                "model": "zai/glm-5.2:max",
                "decision_sha256": "4" * 64,
                "raw_sha256": "5" * 64,
            },
        },
        "disagreement_fields": [],
        "opus_required": False,
        "opus_review": {},
        "final_decision": final,
        "final_decision_sha256": sha256_value(final),
        "normalized_record_sha256": "",
    }
    unsigned = dict(record)
    unsigned.pop("normalized_record_sha256")
    record["normalized_record_sha256"] = sha256_value(unsigned)
    return record


def _normalized() -> dict:
    records = [_normalized_record(index) for index in range(136)]
    payload = {
        "schema_version": NORMALIZED_SCHEMA_VERSION,
        "source_truth_sha256": "e" * 64,
        "packet_catalog_sha256": "c" * 64,
        "review_bundle_sha256": "d" * 64,
        "review_provenance": _provenance(),
        "record_count": 136,
        "records": records,
        "content_sha256": "",
    }
    unsigned = dict(payload)
    unsigned.pop("content_sha256")
    payload["content_sha256"] = sha256_value(unsigned)
    return payload


def _pair(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "pairs" / "T-001"
    vulnerable = root / "vulnerable" / "case.c"
    safe = root / "fixed_or_near_miss" / "case.c"
    vulnerable.parent.mkdir(parents=True)
    safe.parent.mkdir(parents=True)
    vulnerable.write_text("int f(int n) { return 10 / n; }\n", encoding="utf-8")
    safe.write_text("int f(int n) { return n ? 10 / n : 0; }\n", encoding="utf-8")
    manifest = {
        "schema_version": "zscope.range-v16-safe-pair.v1",
        "truth_id": "T-001",
        "pair_uid": "range-v16-pair:T-001",
        "contract_kind": "concrete_trigger",
        "kind": "fixed",
        "invariant_summary": "The divisor must be non-zero.",
        "review_decision_sha256": "6" * 64,
        "compiler_contract": {
            "language": "c",
            "standard": "c11",
            "compiler": "cc",
            "arguments": [],
        },
        "vulnerable": {
            "path": "vulnerable/case.c",
            "sha256": sha256_file(vulnerable),
        },
        "fixed_or_near_miss": {
            "path": "fixed_or_near_miss/case.c",
            "sha256": sha256_file(safe),
        },
        "content_sha256": "",
    }
    unsigned = dict(manifest)
    unsigned.pop("content_sha256")
    manifest["content_sha256"] = sha256_value(unsigned)
    _write(root / "manifest.json", manifest)
    return root, manifest


def _truth_v16(tmp_path: Path) -> tuple[dict, Path]:
    pair_dir, pair_manifest = _pair(tmp_path)
    records = []
    for index in range(136):
        truth_id = f"T-{index + 1:03d}"
        kind = "concrete_trigger" if index == 0 else "pattern_model"
        line = index + 1
        pair = (
            {
                "pair_uid": pair_manifest["pair_uid"],
                "manifest_sha256": sha256_file(pair_dir / "manifest.json"),
                "vulnerable_sha256": pair_manifest["vulnerable"]["sha256"],
                "fixed_or_near_miss_sha256": pair_manifest["fixed_or_near_miss"]["sha256"],
            }
            if index == 0
            else {}
        )
        contract = {
            "schema_version": "zscope.range-truth-record.v2",
            "kind": kind,
            "adjudication_status": "accepted",
            "defect_taxonomy_id": "arithmetic_error",
            "structured_anchors": [
                {
                    "kind": "primary",
                    "file": "src/demo.c",
                    "function": f"function_{index + 1}",
                    "start_line": line,
                    "end_line": line,
                }
            ],
            "trigger": {
                "summary": "The operation violates its arithmetic precondition.",
                "evidence_refs": [f"src/demo.c:{line}"],
            },
            "threat_assumptions": ["The function can receive an unconstrained value."],
            "required_evidence_clauses": [
                {
                    "clause_id": "unsafe_path",
                    "predicate": "An unsafe arithmetic path reaches the operation.",
                    "evidence_refs": [f"src/demo.c:{line}"],
                }
            ],
            "review_artifacts": {
                "fable_sha256": "1" * 64,
                "glm_sha256": "2" * 64,
                "normalized_sha256": "3" * 64,
            },
            "safe_pair": pair,
            "fixture_sha256": "7" * 64,
        }
        records.append(
            {
                "id": truth_id,
                "source_v15_id": truth_id,
                "stable_uid": f"range-truth:{truth_id}",
                "category": "arithmetic_error",
                "cwe": "CWE-369",
                "cwe_ids": ["CWE-369"],
                "file": "src/demo.c",
                "function": f"function_{index + 1}",
                "line": line,
                "end_line": line,
                "severity": "high",
                "title": "Arithmetic precondition violation",
                "keywords": ["arithmetic"],
                "verification_contract": contract,
            }
        )
    canonical = [
        {"truth_id": record["id"], **record["verification_contract"]} for record in records
    ]
    truth = {
        "benchmark": "unit",
        "version": 16,
        "notes": "unit fixture",
        "truth_contract": {
            "schema_version": "zscope.range-truth-contract.v2",
            "manifest_sha256": sha256_value(canonical),
            "review_bundle_sha256": "d" * 64,
            "taxonomy_sha256": "9" * 64,
            "independent_review_complete": True,
            "review_protocol": "protected dual review and arbitration",
            "safe_unit_count": 1,
        },
        "total_vulnerabilities": 136,
        "vulnerabilities": records,
    }
    return truth, pair_dir.parent


def _pair_index(pair_root: Path) -> dict:
    manifest_path = pair_root / "T-001" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = [
        {
            "truth_id": "T-001",
            "pair_uid": manifest["pair_uid"],
            "manifest_sha256": sha256_file(manifest_path),
            "vulnerable_sha256": manifest["vulnerable"]["sha256"],
            "fixed_or_near_miss_sha256": manifest["fixed_or_near_miss"]["sha256"],
            "content_sha256": manifest["content_sha256"],
        }
    ]
    return {
        "schema_version": "zscope.range-v16-safe-pair-index.v1",
        "record_count": 1,
        "records": records,
        "content_sha256": sha256_value(records),
    }


def test_review_provenance_requires_protected_workflow_identity() -> None:
    validate_review_provenance(_provenance())
    forged = _provenance()
    forged["environment"] = "local"
    with pytest.raises(ValueError, match="environment"):
        validate_review_provenance(forged)


def test_review_bundle_rejects_unbound_files_and_noncanonical_paths(tmp_path: Path) -> None:
    root = tmp_path / "reviews"
    reviewed = root / "fable" / "decisions" / "T-001.json"
    _write(reviewed, {"decision": True})
    records = [
        {
            "path": "fable/decisions/T-001.json",
            "size": reviewed.stat().st_size,
            "sha256": sha256_file(reviewed),
        }
    ]
    manifest_path = root / "review-bundle-manifest.json"
    _write(
        manifest_path,
        {
            "schema_version": "zscope.range-v16-review-bundle.v1",
            "files": records,
            "file_count": 1,
            "bundle_sha256": sha256_value(records),
        },
    )
    _validate_review_bundle(root, manifest_path)

    _write(root / "unbound.json", {"unexpected": True})
    with pytest.raises(ValueError, match="unbound or missing"):
        _validate_review_bundle(root, manifest_path)

    (root / "unbound.json").unlink()
    malformed = json.loads(manifest_path.read_text(encoding="utf-8"))
    malformed["files"][0]["path"] = "fable/../fable/decisions/T-001.json"
    malformed["bundle_sha256"] = sha256_value(malformed["files"])
    _write(manifest_path, malformed)
    with pytest.raises(ValueError, match="paths must be unique"):
        _validate_review_bundle(root, manifest_path)


def test_normalized_decisions_bind_every_record_and_hash() -> None:
    value = _normalized()
    validate_normalized_decisions(value)
    tampered = deepcopy(value)
    tampered["records"][0]["final_decision"]["trigger_summary"] = "changed"
    with pytest.raises(ValueError, match="final decision hash"):
        validate_normalized_decisions(tampered)


def test_safe_pair_binds_sources_and_compiles(tmp_path: Path) -> None:
    root, manifest = _pair(tmp_path)
    validate_pair_manifest(manifest, pair_root=root)
    safe_path = root / "fixed_or_near_miss" / "case.c"
    safe_source = safe_path.read_text(encoding="utf-8")
    safe_path.write_text("int f(int n) { return 1 / n; }\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source hash mismatch"):
        validate_pair_manifest(manifest, pair_root=root)
    safe_path.write_text(safe_source, encoding="utf-8")
    if os.name == "nt":
        pytest.skip("formal safe-pair compilation runs in the Linux benchmark toolchain")
    compile_pair_manifest(manifest, pair_root=root)


def test_safe_pair_rejects_path_escape(tmp_path: Path) -> None:
    root, manifest = _pair(tmp_path)
    escaped = deepcopy(manifest)
    escaped["vulnerable"]["path"] = "../outside.c"
    unsigned = dict(escaped)
    unsigned.pop("content_sha256")
    escaped["content_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="canonical POSIX"):
        validate_pair_manifest(escaped, pair_root=root)


def test_truth_v16_strictly_binds_records_anchors_pairs_and_fixture(tmp_path: Path) -> None:
    truth, pair_root = _truth_v16(tmp_path)
    counts = validate_truth_v16(truth, pair_root=pair_root)
    assert counts["concrete_trigger"] == 1
    assert counts["pattern_model"] == 135

    unknown = deepcopy(truth)
    unknown["vulnerabilities"][0]["verification_contract"]["benchmark_hint"] = "forbidden"
    with pytest.raises(ValueError, match="record contract fields"):
        validate_truth_v16(unknown, pair_root=pair_root)

    unknown_record = deepcopy(truth)
    unknown_record["vulnerabilities"][0]["benchmark_hint"] = "forbidden"
    with pytest.raises(ValueError, match="source record fields"):
        validate_truth_v16(unknown_record, pair_root=pair_root)

    incoherent = deepcopy(truth)
    incoherent["vulnerabilities"][0]["function"] = "unrelated_function"
    with pytest.raises(ValueError, match="primary anchor projection"):
        validate_truth_v16(incoherent, pair_root=pair_root)

    mixed_fixture = deepcopy(truth)
    mixed_fixture["vulnerabilities"][1]["verification_contract"]["fixture_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="one fixture snapshot"):
        validate_truth_v16(mixed_fixture, pair_root=pair_root)

    missing_trigger_evidence = deepcopy(truth)
    missing_trigger_evidence["vulnerabilities"][0]["verification_contract"]["trigger"][
        "evidence_refs"
    ] = []
    with pytest.raises(ValueError, match="trigger evidence refs"):
        validate_truth_v16(missing_trigger_evidence, pair_root=pair_root)


def test_truth_v16_rejects_duplicate_clauses_and_pair_uid(tmp_path: Path) -> None:
    truth, pair_root = _truth_v16(tmp_path)
    duplicate = deepcopy(truth)
    clauses = duplicate["vulnerabilities"][0]["verification_contract"]["required_evidence_clauses"]
    clauses.append(deepcopy(clauses[0]))
    with pytest.raises(ValueError, match="clause identities are duplicate"):
        validate_truth_v16(duplicate, pair_root=pair_root)

    wrong_pair = deepcopy(truth)
    wrong_pair["vulnerabilities"][0]["verification_contract"]["safe_pair"][
        "pair_uid"
    ] = "range-v16-pair:other"
    with pytest.raises(ValueError, match="safe pair UID"):
        validate_truth_v16(wrong_pair, pair_root=pair_root)


def test_truth_v16_requires_independent_safe_pair_sources(tmp_path: Path) -> None:
    truth, pair_root = _truth_v16(tmp_path)
    source_dir = pair_root / "T-001"
    duplicate_dir = pair_root / "T-002"
    shutil.copytree(source_dir, duplicate_dir)
    duplicate_manifest_path = duplicate_dir / "manifest.json"
    duplicate_manifest = json.loads(duplicate_manifest_path.read_text(encoding="utf-8"))
    duplicate_manifest["truth_id"] = "T-002"
    duplicate_manifest["pair_uid"] = "range-v16-pair:T-002"
    unsigned_manifest = dict(duplicate_manifest)
    unsigned_manifest.pop("content_sha256")
    duplicate_manifest["content_sha256"] = sha256_value(unsigned_manifest)
    _write(duplicate_manifest_path, duplicate_manifest)

    duplicate_contract = truth["vulnerabilities"][1]["verification_contract"]
    duplicate_contract["kind"] = "concrete_trigger"
    duplicate_contract["safe_pair"] = {
        "pair_uid": duplicate_manifest["pair_uid"],
        "manifest_sha256": sha256_file(duplicate_manifest_path),
        "vulnerable_sha256": duplicate_manifest["vulnerable"]["sha256"],
        "fixed_or_near_miss_sha256": duplicate_manifest["fixed_or_near_miss"]["sha256"],
    }
    truth["truth_contract"]["safe_unit_count"] = 2
    with pytest.raises(ValueError, match="independent safe-pair sources"):
        validate_truth_v16(truth, pair_root=pair_root)


def test_truth_v16_json_schema_matches_strict_contract(tmp_path: Path) -> None:
    truth, _ = _truth_v16(tmp_path)
    schema_path = Path("test/range/benchmark/v16/truth-v16.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["version"] == {"const": 16}
    assert schema["properties"]["vulnerabilities"]["minItems"] == len(truth["vulnerabilities"])
    contract_schema = schema["$defs"]["verificationContract"]
    assert contract_schema["additionalProperties"] is False
    assert set(contract_schema["required"]) == set(
        truth["vulnerabilities"][0]["verification_contract"]
    )


def test_safe_pair_json_schema_matches_manifest_contract(tmp_path: Path) -> None:
    _, manifest = _pair(tmp_path)
    schema_path = Path("test/range/benchmark/v16/safe-pair-v1.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(manifest)
    assert schema["properties"]["schema_version"] == {"const": "zscope.range-v16-safe-pair.v1"}


def test_pair_index_dereferences_every_manifest_and_rejects_tampering(tmp_path: Path) -> None:
    _, pair_root = _truth_v16(tmp_path)
    index = _pair_index(pair_root)
    assert validate_pair_index(index, pair_root=pair_root) == {"T-001"}

    tampered = deepcopy(index)
    tampered["records"][0]["vulnerable_sha256"] = "f" * 64
    tampered["content_sha256"] = sha256_value(tampered["records"])
    with pytest.raises(ValueError, match="index binding mismatch"):
        validate_pair_index(tampered, pair_root=pair_root)


def test_truth_manifest_cross_binds_all_semantic_artifacts(tmp_path: Path) -> None:
    truth, pair_root = _truth_v16(tmp_path)
    normalized = _normalized()
    fixture_root = tmp_path / "fixture"
    (fixture_root / "src").mkdir(parents=True)
    (fixture_root / "src" / "source.c").write_text(
        "int main(void) { return 0; }\n", encoding="utf-8"
    )
    fixture_sha = range_fixture_manifest_sha(fixture_root)
    taxonomy_path = tmp_path / "taxonomy.json"
    _write(taxonomy_path, {"schema_version": "zscope.defect-taxonomy.v1"})
    taxonomy_sha = sha256_file(taxonomy_path)
    for record in truth["vulnerabilities"]:
        record["verification_contract"]["fixture_sha256"] = fixture_sha
    canonical = [
        {"truth_id": record["id"], **record["verification_contract"]}
        for record in truth["vulnerabilities"]
    ]
    truth["truth_contract"]["manifest_sha256"] = sha256_value(canonical)
    truth["truth_contract"]["taxonomy_sha256"] = taxonomy_sha
    truth_path = tmp_path / "ground_truth.json"
    normalized_path = tmp_path / "normalized.json"
    pair_index_path = tmp_path / "safe-pair-manifest.json"
    _write(truth_path, truth)
    _write(normalized_path, normalized)
    pair_index = _pair_index(pair_root)
    _write(pair_index_path, pair_index)
    counts = {
        "concrete_trigger": 1,
        "public_api_contract": 0,
        "pattern_model": 135,
        "retired": 0,
    }
    manifest = {
        "schema_version": "zscope.range-v16-truth-manifest.v1",
        "truth_sha256": sha256_file(truth_path),
        "truth_contract_manifest_sha256": truth["truth_contract"]["manifest_sha256"],
        "source_v15_sha256": normalized["source_truth_sha256"],
        "normalized_decisions_sha256": sha256_file(normalized_path),
        "review_bundle_sha256": normalized["review_bundle_sha256"],
        "packet_catalog_sha256": normalized["packet_catalog_sha256"],
        "taxonomy_sha256": taxonomy_sha,
        "fixture_tree_sha256": fixture_sha,
        "safe_pair_index_sha256": sha256_file(pair_index_path),
        "counts_by_kind": counts,
        "v15_v16_directly_comparable": False,
        "v4_v5_directly_comparable": False,
        "content_sha256": "",
    }
    unsigned = dict(manifest)
    unsigned.pop("content_sha256")
    manifest["content_sha256"] = sha256_value(unsigned)
    validate_truth_manifest(
        manifest,
        truth_path=truth_path,
        normalized_path=normalized_path,
        pair_index_path=pair_index_path,
        taxonomy_path=taxonomy_path,
        fixture_root=fixture_root,
    )

    tampered = deepcopy(manifest)
    tampered["counts_by_kind"]["pattern_model"] = 134
    unsigned = dict(tampered)
    unsigned.pop("content_sha256")
    tampered["content_sha256"] = sha256_value(unsigned)
    with pytest.raises(ValueError, match="contract counts mismatch"):
        validate_truth_manifest(
            tampered,
            truth_path=truth_path,
            normalized_path=normalized_path,
            pair_index_path=pair_index_path,
            taxonomy_path=taxonomy_path,
            fixture_root=fixture_root,
        )


def test_range_fixture_hash_excludes_truth_and_build_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "range"
    (root / "src").mkdir(parents=True)
    (root / "src" / "case.c").write_text("int value;\n", encoding="utf-8")
    before = range_fixture_manifest_sha(root)
    (root / "benchmark" / "v16").mkdir(parents=True)
    (root / "benchmark" / "v16" / "ground_truth.json").write_text(
        '{"answer": true}\n', encoding="utf-8"
    )
    (root / "build").mkdir()
    (root / "build" / "case.o").write_bytes(b"generated")
    assert range_fixture_manifest_sha(root) == before

    (root / "src" / "case.c").write_text("int changed;\n", encoding="utf-8")
    assert range_fixture_manifest_sha(root) != before
