from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.audit_rule_qualifications import audit, main as audit_main
from zscope.rules.catalog import RuleCatalog, RuleCatalogError, RuleDescriptor
from zscope.rules.qualification import QualificationRegistry


def _descriptor(
    *, legacy: bool = False, status: str = "stable", revision: int = 1
) -> RuleDescriptor:
    return RuleDescriptor(
        id="legacy_rule" if legacy else "zscope.c_cpp.cpp_regex.sample",
        language="c_cpp",
        engine="cpp_regex",
        defect_class="bounds",
        cwe="CWE-125",
        skill="bounds_and_integer",
        default_severity="high",
        revision=revision,
        status=status,
        title="Sample",
        summary="Sample rule.",
        required_capabilities=("source_text",),
        legacy_id=legacy,
        default_enabled=status != "experimental",
    )


def _write(path: Path, rows: list[dict], *, policy: str = "require_explicit") -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": "zscope.rule-qualification.v1",
                "legacy_stable_policy": policy,
                "qualifications": rows,
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_catalog(path: Path, descriptors: list[RuleDescriptor]) -> Path:
    rows = []
    for descriptor in descriptors:
        row = descriptor.as_dict()
        row.pop("source")
        rows.append(row)
    path.write_text(
        json.dumps({"rule_catalog_version": 2, "rules": rows}),
        encoding="utf-8",
    )
    return path


def _write_qualification_evidence(
    root: Path,
    descriptor: RuleDescriptor,
    *,
    transformations: tuple[str, ...] = (
        "identifier_rename",
        "wrapper_rewrite",
        "macro_rewrite",
    ),
) -> str:
    evidence_dir = root / "qualification_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    def write_artifact(relative_path: str, payload: dict) -> str:
        artifact_path = evidence_dir.joinpath(*relative_path.split("/"))
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        raw_artifact = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        artifact_path.write_bytes(raw_artifact)
        return hashlib.sha256(raw_artifact).hexdigest()

    descriptor_payload = json.dumps(
        descriptor.as_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    manifest = {
        "schema_version": "zscope.rule-qualification-evidence.v1",
        "rule_id": descriptor.id,
        "revision": descriptor.revision,
        "catalog_descriptor_sha256": hashlib.sha256(descriptor_payload.encode("utf-8")).hexdigest(),
        "leakage_lint": {
            "passed": True,
            "scanned_product_sha256": "1" * 64,
            "range_token_set_sha256": "2" * 64,
            "artifact_path": "artifacts/leakage-lint.json",
            "artifact_sha256": write_artifact(
                "artifacts/leakage-lint.json",
                {"passed": True, "kind": "structural-leakage-lint"},
            ),
        },
        "metamorphic_cases": [
            {
                "case_id": f"meta-{index}",
                "transformation": transformation,
                "unsafe_detected": True,
                "fixed_not_detected": True,
                "artifact_path": f"artifacts/metamorphic-{index}.json",
                "artifact_sha256": write_artifact(
                    f"artifacts/metamorphic-{index}.json",
                    {
                        "transformation": transformation,
                        "unsafe_detected": True,
                        "fixed_not_detected": True,
                    },
                ),
            }
            for index, transformation in enumerate(transformations)
        ],
        "external_cases": [
            *[
                {
                    "case_id": f"positive-{index}",
                    "project_id": f"project-{index % 3}",
                    "family_id": f"family-{index % 3}",
                    "expectation": "vulnerable",
                    "detected": True,
                    "artifact_path": f"artifacts/external-positive-{index}.json",
                    "artifact_sha256": write_artifact(
                        f"artifacts/external-positive-{index}.json",
                        {"expectation": "vulnerable", "detected": True},
                    ),
                }
                for index in range(10)
            ],
            *[
                {
                    "case_id": f"negative-{index}",
                    "project_id": f"project-{index % 3}",
                    "family_id": f"family-{index % 3}",
                    "expectation": "near_miss_safe",
                    "detected": False,
                    "artifact_path": f"artifacts/external-negative-{index}.json",
                    "artifact_sha256": write_artifact(
                        f"artifacts/external-negative-{index}.json",
                        {"expectation": "near_miss_safe", "detected": False},
                    ),
                }
                for index in range(20)
            ],
        ],
        "vulnerable_fixed_pairs": [
            {
                "pair_id": "pair-1",
                "project_id": "project-0",
                "vulnerable_detected": True,
                "fixed_detected": False,
                "artifact_path": "artifacts/vulnerable-fixed-pair.json",
                "artifact_sha256": write_artifact(
                    "artifacts/vulnerable-fixed-pair.json",
                    {"vulnerable_detected": True, "fixed_detected": False},
                ),
            }
        ],
    }
    path = evidence_dir / f"{descriptor.id}.r{descriptor.revision}.json"
    raw = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _qualified_row(descriptor: RuleDescriptor, evidence_sha256: str) -> dict:
    return {
        "rule_id": descriptor.id,
        "revision": descriptor.revision,
        "state": "qualified",
        "evidence_sha256": evidence_sha256,
        "external_projects": 3,
        "positive_cases": 10,
        "near_miss_negative_cases": 20,
        "metamorphic_variants": 3,
        "vulnerable_fixed_pair": True,
        "external_precision": 1.0,
    }


def _rewrite_evidence_manifest(root: Path, descriptor: RuleDescriptor, payload: dict) -> str:
    path = root / "qualification_evidence" / f"{descriptor.id}.r{descriptor.revision}.json"
    raw = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_packaged_registry_authority_is_yaml_and_migrates_legacy_stable() -> None:
    catalog = RuleCatalog.builtin()
    registry = QualificationRegistry.builtin(catalog=catalog)

    assert registry.source_path.endswith("qualification_registry.yaml")
    assert registry.summary()["inherited_legacy_pending"] > 0
    assert registry.summary()["total"] == sum(
        rule.status == "stable" for rule in catalog
    )


def test_legacy_stable_rules_are_explicitly_synthesized_as_pending(tmp_path: Path) -> None:
    descriptor = _descriptor(legacy=True)
    catalog = RuleCatalog((descriptor,))
    registry = QualificationRegistry.from_path(
        _write(tmp_path / "registry.json", [], policy="legacy_stable_pending"),
        catalog=catalog,
    )

    record = registry.state_for(descriptor.id, descriptor.revision)
    assert record is not None
    assert record.state == "pending"
    assert record.inherited_legacy_pending is True


def test_new_stable_rule_requires_a_qualification_record(tmp_path: Path) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    with pytest.raises(RuleCatalogError, match="has no qualification record"):
        QualificationRegistry.from_path(
            _write(tmp_path / "registry.json", []),
            catalog=catalog,
        )


def test_new_stable_rule_cannot_use_a_pending_promotion_record(tmp_path: Path) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    row = {"rule_id": descriptor.id, "revision": 1, "state": "pending"}
    with pytest.raises(RuleCatalogError, match="qualified promotion record"):
        QualificationRegistry.from_path(
            _write(tmp_path / "registry.json", [row]),
            catalog=catalog,
        )


def test_qualified_record_enforces_promotion_gates(tmp_path: Path) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    evidence_sha256 = _write_qualification_evidence(tmp_path, descriptor)
    row = _qualified_row(descriptor, evidence_sha256)
    registry = QualificationRegistry.from_path(
        _write(tmp_path / "registry.json", [row]),
        catalog=catalog,
    )
    record = registry.state_for(descriptor.id, 1)
    assert record is not None
    assert record.state == "qualified"
    assert record.evidence_verified is True

    row["external_projects"] = 2
    with pytest.raises(RuleCatalogError, match="external_projects>=3"):
        QualificationRegistry.from_path(
            _write(tmp_path / "invalid.json", [row]),
            catalog=catalog,
        )


def test_qualified_record_requires_resolvable_matching_case_evidence(tmp_path: Path) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    row = _qualified_row(descriptor, "d" * 64)

    with pytest.raises(RuleCatalogError, match="qualification evidence cannot be loaded"):
        QualificationRegistry.from_path(
            _write(tmp_path / "missing-evidence.json", [row]),
            catalog=catalog,
        )

    row["evidence_sha256"] = _write_qualification_evidence(
        tmp_path,
        descriptor,
        transformations=("identifier_rename", "identifier_rename", "identifier_rename"),
    )
    with pytest.raises(RuleCatalogError, match="three distinct transformation kinds"):
        QualificationRegistry.from_path(
            _write(tmp_path / "insufficient-evidence.json", [row]),
            catalog=catalog,
        )


def test_qualified_record_rejects_missing_bound_artifact(tmp_path: Path) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    evidence_sha = _write_qualification_evidence(tmp_path, descriptor)
    (tmp_path / "qualification_evidence" / "artifacts" / "external-positive-0.json").unlink()

    with pytest.raises(RuleCatalogError, match="qualification artifact does not exist"):
        QualificationRegistry.from_path(
            _write(tmp_path / "registry.json", [_qualified_row(descriptor, evidence_sha)]),
            catalog=catalog,
        )


def test_qualified_record_rejects_tampered_bound_artifact(tmp_path: Path) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    evidence_sha = _write_qualification_evidence(tmp_path, descriptor)
    artifact_path = tmp_path / "qualification_evidence" / "artifacts" / "external-positive-0.json"
    artifact_path.write_bytes(b"tampered\n")

    with pytest.raises(RuleCatalogError, match="artifact SHA-256 mismatch"):
        QualificationRegistry.from_path(
            _write(tmp_path / "registry.json", [_qualified_row(descriptor, evidence_sha)]),
            catalog=catalog,
        )


@pytest.mark.parametrize(
    "malicious_path",
    ("../outside.json", "/outside.json", "C:/outside.json", "artifacts\\outside.json"),
)
def test_qualified_record_rejects_artifact_path_escape(
    tmp_path: Path,
    malicious_path: str,
) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    _write_qualification_evidence(tmp_path, descriptor)
    manifest_path = (
        tmp_path / "qualification_evidence" / f"{descriptor.id}.r{descriptor.revision}.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    outside = tmp_path / "outside.json"
    outside_bytes = b'{"outside": true}\n'
    outside.write_bytes(outside_bytes)
    manifest["external_cases"][0]["artifact_path"] = malicious_path
    manifest["external_cases"][0]["artifact_sha256"] = hashlib.sha256(outside_bytes).hexdigest()
    evidence_sha = _rewrite_evidence_manifest(tmp_path, descriptor, manifest)

    with pytest.raises(RuleCatalogError, match="canonical relative POSIX path"):
        QualificationRegistry.from_path(
            _write(tmp_path / "registry.json", [_qualified_row(descriptor, evidence_sha)]),
            catalog=catalog,
        )


def test_qualified_record_rejects_symlinked_bound_artifact(tmp_path: Path) -> None:
    descriptor = _descriptor()
    catalog = RuleCatalog((descriptor,))
    evidence_sha = _write_qualification_evidence(tmp_path, descriptor)
    artifact_path = tmp_path / "qualification_evidence" / "artifacts" / "external-positive-0.json"
    outside = tmp_path / "outside-artifact.json"
    outside.write_bytes(artifact_path.read_bytes())
    artifact_path.unlink()
    try:
        artifact_path.symlink_to(outside)
    except OSError:
        pytest.skip("creating a symlink is not permitted in this test environment")

    with pytest.raises(RuleCatalogError, match="symbolic links or reparse points"):
        QualificationRegistry.from_path(
            _write(tmp_path / "registry.json", [_qualified_row(descriptor, evidence_sha)]),
            catalog=catalog,
        )


def test_registry_uses_rule_and_revision_as_unique_key_and_keeps_history(
    tmp_path: Path,
) -> None:
    descriptor = _descriptor(status="experimental", revision=2)
    catalog = RuleCatalog((descriptor,))
    rows = [
        {"rule_id": descriptor.id, "revision": 1, "state": "failed"},
        {"rule_id": descriptor.id, "revision": 2, "state": "pending"},
    ]
    registry = QualificationRegistry.from_path(
        _write(tmp_path / "registry.json", rows),
        catalog=catalog,
    )
    assert registry.state_for(descriptor.id, 1).state == "failed"
    assert registry.state_for(descriptor.id, 2).state == "pending"

    with pytest.raises(RuleCatalogError, match="duplicate qualification"):
        QualificationRegistry.from_path(
            _write(tmp_path / "duplicate.json", [rows[0], rows[0]]),
            catalog=catalog,
        )


@pytest.mark.parametrize(
    "argument",
    ("--benchmark-report", "--benchmark-truth"),
)
def test_rule_qualification_audit_requires_benchmark_inputs_as_a_pair(
    argument: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        audit_main([argument, "benchmark.json"])

    assert exc_info.value.code == 2
    assert (
        "--benchmark-report and --benchmark-truth must be provided together"
        in capsys.readouterr().err
    )


def test_rule_qualification_audit_counts_overlapping_benchmark_tp_rules(
    tmp_path: Path,
) -> None:
    first = replace(
        _descriptor(status="experimental", revision=3),
        aliases=("sample_alias",),
    )
    second = replace(
        _descriptor(status="experimental", revision=2),
        id="zscope.c_cpp.cpp_regex.second",
        title="Second sample",
    )
    catalog_path = _write_catalog(tmp_path / "catalog.json", [first, second])
    registry_path = _write(
        tmp_path / "registry.json",
        [
            {"rule_id": first.id, "revision": first.revision, "state": "pending"},
            {"rule_id": second.id, "revision": second.revision, "state": "pending"},
        ],
    )
    deterministic_issue = {
        "category": "memory_leak",
        "function": "leaky",
        "location": "src/demo.c:10",
        "description": "memory leak on error path",
        "rule_id": ["sample_alias"],
        "evidence_pack": {
            "rule": [second.id],
            "candidate_payload": {"rule_id": ["sample_alias", "third_party.detector"]},
        },
        "attribution": {
            "discovered_by": ["deterministic_rule"],
            "decided_by": "deterministic_proof",
            "decision_level": "V0",
        },
    }
    llm_issue_with_rule_field = {
        "category": "use_after_free",
        "function": "uaf",
        "location": "src/demo.c:40",
        "description": "use after free after cleanup",
        "rule": first.id,
        "attribution": {
            "discovered_by": ["llm_active_discovery"],
            "decided_by": "validator_llm",
            "decision_level": "V1",
        },
    }
    review_deterministic_issue = {
        "category": "buffer_overflow",
        "function": "overflow",
        "location": "src/demo.c:70",
        "description": "write exceeds destination bounds",
        "candidate_payload": {"rule": [first.id]},
        "attribution": {
            "discovered_by": ["deterministic_rule", "backend_signal"],
            "decided_by": "unresolved",
            "decision_level": "none",
        },
    }
    report = {
        "issues": [deterministic_issue, llm_issue_with_rule_field],
        "report_views": {
            "default": {
                "issues": [deterministic_issue, llm_issue_with_rule_field],
            },
            "with_needs_review": {
                "issues": [
                    deterministic_issue,
                    llm_issue_with_rule_field,
                    review_deterministic_issue,
                ],
            },
        },
    }
    truth = {
        "benchmark": "rule-audit-unit",
        "suite": "unit",
        "vulnerabilities": [
            {
                "id": "BUG-1",
                "category": "memory_leak",
                "function": "leaky",
                "file": "src/demo.c",
                "line": 10,
            },
            {
                "id": "BUG-2",
                "category": "use_after_free",
                "function": "uaf",
                "file": "src/demo.c",
                "line": 40,
            },
            {
                "id": "BUG-3",
                "category": "buffer_overflow",
                "function": "overflow",
                "file": "src/demo.c",
                "line": 70,
            },
        ],
    }
    report_path = tmp_path / "report.json"
    truth_path = tmp_path / "truth.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    truth_path.write_text(json.dumps(truth), encoding="utf-8")

    without_benchmark = audit(
        catalog_path=catalog_path,
        registry_path=registry_path,
    )
    assert "benchmark_tp_participation" not in without_benchmark

    result = audit(
        catalog_path=catalog_path,
        registry_path=registry_path,
        benchmark_report_path=report_path,
        benchmark_truth_path=truth_path,
        view="with_needs_review",
    )["benchmark_tp_participation"]

    assert result["selected_view_true_positives"] == 3
    assert result["deterministic_rule_tp_issue_count"] == 2
    assert result["participating_rule_ids"] == [first.id, second.id]
    by_rule = {row["rule_id"]: row for row in result["participating_rules"]}
    assert by_rule[first.id] == {
        "rule_id": first.id,
        "tp_count": 2,
        "truth_ids": ["BUG-1", "BUG-3"],
        "current_revision": 3,
        "qualification_state": "pending",
        "evidence_verified": False,
        "default_enabled": False,
        "observed_detector_ids": sorted([first.id, "sample_alias"]),
    }
    assert by_rule[second.id]["tp_count"] == 1
    assert by_rule[second.id]["truth_ids"] == ["BUG-1"]
    assert result["unknown_detectors"] == [
        {
            "detector_id": "third_party.detector",
            "tp_count": 1,
            "truth_ids": ["BUG-1"],
        }
    ]
    assert result["per_rule_tp_count_sum"] == 3
    assert result["per_rule_counts_overlap"] is True
    assert "MUST NOT be summed" in result["counting_contract"]
