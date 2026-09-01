from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from typing import Any

from scripts.p2_proof_corpus import build_case
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.proof_kernel import ProofKernelEngine
from zscope.core.validation.proof_kernel.canonical import seal_mapping
from zscope.reporting.finding_roots import (
    FINDING_ROOT_VERSION,
    project_finding_roots,
)


@lru_cache(maxsize=64)
def _confirmed_v4_bundle(
    *,
    family: str,
    subject: str,
    region: str,
    cluster_uid: str,
) -> dict[str, Any]:
    case = build_case("concurrency", 0)
    body = dict(case["proof_obligation"])
    body.pop("obligation_uid")
    body.pop("content_sha256")
    body.update(
        {
            "validation_cluster_uid": cluster_uid,
            "defect_family": family,
            "subject_uid": subject,
            "decision_region_uid": region,
        }
    )
    obligation = seal_mapping(body, uid_field="obligation_uid", prefix="POBL_")
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=case["program_proof_ir"],
        obligation=obligation,
    )
    carrier: dict[str, Any] = {}
    evaluation.apply_to_issue(carrier)
    carrier["proof_kernel_root_manifest_sha256"] = evaluation.root_manifest_sha256
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    return carrier


@lru_cache(maxsize=64)
def _review_v4_bundle(
    *,
    family: str,
    subject: str,
    region: str,
    cluster_uid: str,
) -> dict[str, Any]:
    case = build_case("concurrency", 10)
    body = dict(case["proof_obligation"])
    body.pop("obligation_uid")
    body.pop("content_sha256")
    body.update(
        {
            "validation_cluster_uid": cluster_uid,
            "defect_family": family,
            "subject_uid": subject,
            "decision_region_uid": region,
        }
    )
    obligation = seal_mapping(body, uid_field="obligation_uid", prefix="POBL_")
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=case["program_proof_ir"],
        obligation=obligation,
    )
    carrier: dict[str, Any] = {}
    evaluation.apply_to_issue(carrier)
    carrier["proof_kernel_root_manifest_sha256"] = evaluation.root_manifest_sha256
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    return carrier


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
    v4_promotion: bool = False,
    v4_review: bool = False,
    blocking_negative_evidence: bool = False,
    missing_fact_kinds: list[str] | None = None,
    call_path: list[str] | None = None,
) -> dict[str, Any]:
    resolved_cluster_uid = cluster_uid or f"VAL_{uid}"
    result: dict[str, Any] = {
        "candidate_uid": candidate_uid or f"CAND_{uid}",
        "validation_cluster_uid": resolved_cluster_uid,
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
    if call_path is not None:
        result["call_path"] = list(call_path)
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
        if v4_review:
            result.update(
                deepcopy(
                    _review_v4_bundle(
                        family=family,
                        subject=subject,
                        region=region,
                        cluster_uid=resolved_cluster_uid,
                    )
                )
            )
    elif v4_promotion:
        result.update(
            deepcopy(
                _confirmed_v4_bundle(
                    family=family,
                    subject=subject,
                    region=region,
                    cluster_uid=resolved_cluster_uid,
                )
            )
        )
    return result


def _display(outcomes: tuple[dict[str, Any], ...], disposition: str) -> list[dict[str, Any]]:
    return [item for item in outcomes if item.get("candidate_disposition") == disposition]


def test_same_candidate_different_validation_clusters_do_not_merge() -> None:
    projection = project_finding_roots(
        [
            _outcome("a", candidate_uid="CAND_shared", cluster_uid="VAL_a"),
            _outcome("b", candidate_uid="CAND_shared", cluster_uid="VAL_b"),
        ]
    )

    assert len(_display(projection.outcomes, "confirmed")) == 2
    assert len(_display(projection.outcomes, "deduplicated_alias")) == 0


def test_different_detectors_with_same_structured_sink_merge() -> None:
    sink = {
        "file": "src/owner.c",
        "line": 77,
        "operation": "release(owner->member)",
    }
    projection = project_finding_roots(
        [
            _outcome(
                "graph",
                cluster_uid="VAL_shared_sink",
                region="REGION_shared_sink",
                sink=sink,
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "clang",
                cluster_uid="VAL_shared_sink",
                region="REGION_shared_sink",
                sink=sink,
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
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
            cluster_uid="VAL_compaction_commit",
            v4_promotion=True,
            call_path=["entry", "compact", "commit"],
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
        [
            _outcome(
                "a",
                code_hash="code-a",
                cluster_uid="VAL_shared_code",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "b",
                code_hash="code-b",
                cluster_uid="VAL_shared_code",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
        ]
    )

    assert projection.finding_root_count == 1
    assert projection.finding_root_alias_count == 1
    assert projection.summary["counts_by_merge_contract"] == {"same_decision_region_subject": 1}


def test_needs_review_merges_only_when_unresolved_contract_matches() -> None:
    projection = project_finding_roots(
        [
            _outcome(
                "a",
                disposition="needs_review",
                cluster_uid="VAL_shared_review",
                v4_review=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "b",
                disposition="needs_review",
                cluster_uid="VAL_shared_review",
                v4_review=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "c",
                disposition="needs_review",
                cluster_uid="VAL_shared_review",
                v4_review=True,
                call_path=["entry", "sink"],
                missing_fact_kinds=["cleanup_coverage"],
            ),
        ]
    )

    assert len(_display(projection.outcomes, "needs_review")) == 2
    assert projection.finding_root_alias_count == 1


def test_confirmed_never_attaches_a_different_incomplete_proof_root() -> None:
    attached = project_finding_roots(
        [
            _outcome(
                "confirmed",
                cluster_uid="VAL_attachment",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "review",
                cluster_uid="VAL_attachment",
                disposition="needs_review",
                v4_review=True,
                call_path=["entry", "sink"],
            ),
        ]
    )
    no_proof = project_finding_roots(
        [
            _outcome("confirmed", complete_proof=False),
            _outcome("review", disposition="needs_review"),
        ]
    )
    blocked = project_finding_roots(
        [
            _outcome("confirmed", v4_promotion=True),
            _outcome(
                "review",
                disposition="needs_review",
                blocking_negative_evidence=True,
            ),
        ]
    )

    assert len(_display(attached.outcomes, "confirmed")) == 1
    assert len(_display(attached.outcomes, "needs_review")) == 1
    assert attached.finding_root_alias_count == 0
    assert no_proof.finding_root_count == 2
    assert no_proof.finding_root_alias_count == 0
    assert blocked.finding_root_count == 2
    assert blocked.finding_root_alias_count == 0


def test_legacy_decision_proof_or_v3_materialization_cannot_authorize_attachment() -> None:
    review = _outcome("review", disposition="needs_review")
    legacy_only = project_finding_roots([_outcome("legacy"), review])
    with_v3 = _outcome("v3", v4_promotion=True)
    with_v3["terminal_authority_decision"] = {
        "schema_version": "zscope.terminal-authority-decision.v3",
        "disposition": "confirmed",
    }
    v3_materialized = project_finding_roots([with_v3, review])

    assert legacy_only.finding_root_count == 2
    assert legacy_only.finding_root_alias_count == 0
    assert v3_materialized.finding_root_count == 2
    assert v3_materialized.finding_root_alias_count == 0


def test_legacy_confirmed_rows_with_same_region_and_subject_do_not_merge() -> None:
    projection = project_finding_roots(
        [
            _outcome(
                "legacy_a",
                subject="owner.member",
                region="REGION_shared_exit",
            ),
            _outcome(
                "legacy_b",
                subject="owner.member",
                region="REGION_shared_exit",
            ),
        ]
    )

    assert len(_display(projection.outcomes, "confirmed")) == 2
    assert len(_display(projection.outcomes, "deduplicated_alias")) == 0
    assert projection.finding_root_count == 2
    assert projection.finding_root_alias_count == 0


def test_tampered_v4_promotion_cannot_authorize_attachment() -> None:
    confirmed = _outcome("confirmed", v4_promotion=True)
    confirmed["proof_kernel_promotion_certificate"]["subject_uid"] = "other.object"

    projection = project_finding_roots([confirmed, _outcome("review", disposition="needs_review")])

    assert projection.finding_root_count == 2
    assert projection.finding_root_alias_count == 0


def test_same_candidate_different_subject_region_or_call_path_never_merges() -> None:
    variants = (
        (
            _outcome(
                "a",
                candidate_uid="CAND_shared",
                cluster_uid="VAL_shared_subject",
                subject="owner.left",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "b",
                candidate_uid="CAND_shared",
                cluster_uid="VAL_shared_subject",
                subject="owner.right",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
        ),
        (
            _outcome(
                "a",
                candidate_uid="CAND_shared",
                cluster_uid="VAL_shared_region",
                region="REGION_left",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "b",
                candidate_uid="CAND_shared",
                cluster_uid="VAL_shared_region",
                region="REGION_right",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
        ),
        (
            _outcome(
                "a",
                candidate_uid="CAND_shared",
                cluster_uid="VAL_shared_path",
                v4_promotion=True,
                call_path=["entry", "left", "sink"],
            ),
            _outcome(
                "b",
                candidate_uid="CAND_shared",
                cluster_uid="VAL_shared_path",
                v4_promotion=True,
                call_path=["entry", "right", "sink"],
            ),
        ),
    )

    for outcomes in variants:
        projection = project_finding_roots(list(outcomes))
        assert projection.finding_root_count == 2
        assert projection.finding_root_alias_count == 0


def test_alias_preserves_member_evidence_sources_and_terminal_records() -> None:
    projection = project_finding_roots(
        [
            _outcome(
                "a",
                cluster_uid="VAL_alias",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
            _outcome(
                "b",
                cluster_uid="VAL_alias",
                v4_promotion=True,
                call_path=["entry", "sink"],
            ),
        ]
    )

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
