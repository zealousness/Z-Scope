from __future__ import annotations

from typing import Any

from zscope.reporting.finding_roots import (
    FINDING_ROOT_VERSION,
    project_finding_roots,
)


def _outcome(
    uid: str,
    *,
    candidate_uid: str | None = None,
    cluster_uid: str | None = None,
    family: str = "memory_leak",
    file_path: str = "src\\owner.c",
    function: str = "destroy_owner",
    shape: str = "source_centric",
    subject: str = "owner.member",
    region: str = "REGION_cfg_exit_42",
    sink: dict[str, Any] | None = None,
    code_hash: str = "code-a",
    disposition: str = "confirmed",
    complete_proof: bool = True,
    blocking_negative_evidence: bool = False,
    missing_fact_kinds: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "candidate_uid": candidate_uid or f"CAND_{uid}",
        "validation_cluster_uid": cluster_uid or f"VAL_{uid}",
        "occurrence_uid": f"OCC_{uid}",
        "candidate_disposition": disposition,
        "defect_class": family,
        "file_path": file_path,
        "function": function,
        "obligation_shape": shape,
        "code_hash": code_hash,
        "blocking_negative_evidence": blocking_negative_evidence,
        "security_obligation": {
            "defect_family": family,
            "obligation_shape": shape,
            "subject_uid": subject,
            "decision_region_uid": region,
        },
        "attribution": {
            "schema_version": "zscope.finding-attribution.v1",
            "discovered_by": ["deterministic_rule"],
            "discovery_details": [{"detector": f"detector-{uid}"}],
            "decided_by": "deterministic_proof" if complete_proof else "unresolved",
            "decision_level": "V0" if complete_proof else "V3",
        },
        "evidence_refs": [f"evidence:{uid}"],
    }
    if sink is not None:
        result["security_obligation"]["sink_uid"] = sink
    if complete_proof:
        result["decision_proof"] = {
            "outcome": "confirm",
            "proof_kind": "missing_cleanup_path",
            "proof_version": "zscope.decision-proof.v4",
            "producer_engine": "cfg",
            "fact_ids": [f"fact:{uid}"],
            "cfg_nodes": ["42"],
            "subject_identity": subject,
            "code_hash": code_hash,
            "scope": "complete cleanup path",
            "completeness": "complete",
        }
    if disposition == "needs_review":
        result.pop("decision_proof", None)
        result["obligation_required_fact_kinds"] = ["cleanup_coverage", "ownership"]
        result["missing_fact_kinds"] = missing_fact_kinds or ["ownership"]
        result["model_verdict"] = "uncertain"
        result["candidate_promotion_reason"] = "missing_promotion_fact"
    return result


def _display(outcomes: tuple[dict[str, Any], ...], disposition: str) -> list[dict[str, Any]]:
    return [item for item in outcomes if item.get("candidate_disposition") == disposition]


def test_same_candidate_different_validation_clusters_merge() -> None:
    projection = project_finding_roots(
        [
            _outcome("a", candidate_uid="CAND_shared", cluster_uid="VAL_a"),
            _outcome("b", candidate_uid="CAND_shared", cluster_uid="VAL_b"),
        ]
    )

    primary = _display(projection.outcomes, "confirmed")
    aliases = _display(projection.outcomes, "deduplicated_alias")
    assert len(primary) == 1
    assert len(aliases) == 1
    assert primary[0]["finding_root_merge_contract"] == "same_candidate_uid"
    assert primary[0]["member_validation_cluster_uids"] == ["VAL_a", "VAL_b"]
    assert primary[0]["finding_root_alias_uids"] == ["VAL_b"]
    assert aliases[0]["finding_root_uid"] == primary[0]["finding_root_uid"]


def test_different_detectors_with_same_structured_sink_merge() -> None:
    sink = {
        "file": "src/owner.c",
        "line": 77,
        "operation": "release(owner->member)",
    }
    projection = project_finding_roots(
        [
            _outcome("graph", region="REGION_graph", sink=sink),
            _outcome("clang", region="REGION_clang", sink=sink),
        ]
    )

    primary = _display(projection.outcomes, "confirmed")[0]
    assert projection.finding_root_count == 1
    assert projection.finding_root_alias_count == 1
    assert primary["finding_root_merge_contract"] == "same_structured_sink"
    assert len(primary["finding_root_member_attributions"]) == 2


def test_multi_sink_writes_in_same_subject_and_decision_region_merge() -> None:
    outcomes = [
        _outcome(
            str(line),
            sink={
                "file": "src/runtime.c",
                "line": line,
                "operation": f"segment->{field} = value",
            },
            file_path="src/runtime.c",
            function="_runtime_stream_compact_segments",
            family="state_consistency",
            subject="segment",
            region="REGION_compaction_commit",
        )
        for line, field in ((101, "start"), (102, "length"), (103, "flags"), (104, "next"))
    ]

    projection = project_finding_roots(outcomes)

    primary = _display(projection.outcomes, "confirmed")[0]
    assert projection.finding_root_count == 1
    assert projection.finding_root_alias_count == 3
    assert primary["finding_root_merge_contract"] == "same_decision_region_subject"
    assert len(primary["member_candidate_uids"]) == 4


def test_family_function_subject_region_or_counterproof_prevents_merge() -> None:
    blocked = _outcome("blocked", blocking_negative_evidence=True)
    projection = project_finding_roots(
        [
            _outcome("base"),
            _outcome("family", family="use_after_free"),
            _outcome("function", function="destroy_other"),
            _outcome("subject", subject="owner.other"),
            _outcome("region", region="REGION_cfg_exit_43"),
            blocked,
        ]
    )

    assert projection.finding_root_count == 6
    assert projection.finding_root_alias_count == 0


def test_dependency_code_hash_is_not_finding_root_identity() -> None:
    projection = project_finding_roots(
        [_outcome("a", code_hash="code-a"), _outcome("b", code_hash="code-b")]
    )

    assert projection.finding_root_count == 1
    assert projection.finding_root_alias_count == 1
    assert projection.summary["counts_by_merge_contract"] == {"same_decision_region_subject": 1}


def test_needs_review_merges_only_when_unresolved_contract_matches() -> None:
    projection = project_finding_roots(
        [
            _outcome("a", disposition="needs_review"),
            _outcome("b", disposition="needs_review"),
            _outcome(
                "c",
                disposition="needs_review",
                missing_fact_kinds=["cleanup_coverage"],
            ),
        ]
    )

    assert len(_display(projection.outcomes, "needs_review")) == 2
    assert projection.finding_root_alias_count == 1


def test_confirmed_attaches_review_only_with_complete_proof_and_no_conflict() -> None:
    attached = project_finding_roots(
        [_outcome("confirmed"), _outcome("review", disposition="needs_review")]
    )
    no_proof = project_finding_roots(
        [
            _outcome("confirmed", complete_proof=False),
            _outcome("review", disposition="needs_review"),
        ]
    )
    blocked = project_finding_roots(
        [
            _outcome("confirmed"),
            _outcome(
                "review",
                disposition="needs_review",
                blocking_negative_evidence=True,
            ),
        ]
    )

    assert len(_display(attached.outcomes, "confirmed")) == 1
    assert len(_display(attached.outcomes, "needs_review")) == 0
    assert attached.finding_root_alias_count == 1
    assert (
        _display(attached.outcomes, "deduplicated_alias")[0]["finding_root_original_disposition"]
        == "needs_review"
    )
    assert no_proof.finding_root_count == 2
    assert no_proof.finding_root_alias_count == 0
    assert blocked.finding_root_count == 2
    assert blocked.finding_root_alias_count == 0


def test_alias_preserves_member_evidence_sources_and_terminal_records() -> None:
    projection = project_finding_roots([_outcome("a"), _outcome("b")])

    primary = _display(projection.outcomes, "confirmed")[0]
    alias = _display(projection.outcomes, "deduplicated_alias")[0]
    assert primary["finding_root_version"] == FINDING_ROOT_VERSION
    assert primary["occurrence_uids"] == ["OCC_a", "OCC_b"]
    assert {row["candidate_uid"] for row in primary["finding_root_member_attributions"]} == {
        "CAND_a",
        "CAND_b",
    }
    assert alias["evidence_refs"] in (["evidence:a"], ["evidence:b"])
    assert alias["attribution"]["discovery_details"]
    assert len(projection.outcomes) == 2


def test_missing_root_fields_emit_explicit_skip_reason() -> None:
    incomplete = _outcome("missing")
    incomplete["security_obligation"].pop("subject_uid")
    incomplete["decision_proof"].pop("subject_identity")

    projection = project_finding_roots([incomplete])

    primary = _display(projection.outcomes, "confirmed")[0]
    assert "finding_root_uid" not in primary
    assert primary["finding_root_projection_skip_reason"] == "missing_root_fields:subject"
    assert projection.summary["unprojectable_count"] == 1
    assert projection.summary["unprojectable_by_reason"] == {"missing_root_fields:subject": 1}
