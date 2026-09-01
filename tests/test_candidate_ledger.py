from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.p2_proof_corpus import build_case
from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.decision_facts import (
    DECISION_CONTEXT_V33,
    DecisionFactGraphCache,
)
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.proof_kernel import (
    ProofKernelEngine,
    build_proof_clause,
    build_proof_obligation,
)
from zscope.core.validation.proof_kernel.canonical import seal_mapping
from zscope.orchestration.candidates import CandidateLedger, CandidateTicket


def _ticket(*, priority=90, negative=None):
    return CandidateTicket(
        id="RULE_1",
        skill="bounds_and_integer",
        task="check bounds",
        trigger="memcpy",
        line=12,
        context_slice="memcpy(dst, src, len);",
        priority_score=priority,
        origin="src/demo.c:10",
        sink="src/demo.c:12",
        resource_kind="memory",
        evidence={
            "candidate_id": "RULE_1",
            "defect_class": "bounds",
            "positive_evidence": ["len reaches memcpy"],
            "negative_evidence": list(negative or []),
        },
    )


def _terminal_v4_issue(cluster_uid: str, *, disposition: str = "confirmed") -> dict:
    case = build_case("concurrency", 0)
    obligation_body = deepcopy(case["proof_obligation"])
    obligation_body.pop("obligation_uid")
    obligation_body.pop("content_sha256")
    obligation_body["validation_cluster_uid"] = cluster_uid
    if disposition == "confirmed":
        obligation = seal_mapping(
            obligation_body,
            uid_field="obligation_uid",
            prefix="POBL_",
        )
    elif disposition == "rejected_with_proof":
        confirmation = obligation_body["confirmation_clauses"][0]
        counterproof = build_proof_clause(
            role="counterproof",
            provider_family=confirmation["provider_family"],
            predicate_id=confirmation["predicate_id"],
            fact_kind=confirmation["fact_kind"],
            quantifier=confirmation["quantifier"],
            expected_value=confirmation["expected_value"],
            parameters=confirmation["parameters"],
        )
        obligation = build_proof_obligation(
            validation_cluster_uid=cluster_uid,
            defect_family=obligation_body["defect_family"],
            subject_uid=obligation_body["subject_uid"],
            decision_region_uid=obligation_body["decision_region_uid"],
            confirmation_clauses=(),
            counterproof_clauses=(counterproof,),
            dependency_hashes=obligation_body["dependency_hashes"],
        )
    else:  # pragma: no cover - test helper contract
        raise ValueError("unsupported_terminal_disposition")
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=case["program_proof_ir"],
        obligation=obligation,
    )
    assert evaluation.decision == disposition
    issue: dict = {
        "validation_cluster_uid": cluster_uid,
        "candidate_disposition": disposition,
    }
    evaluation.apply_to_issue(issue)
    authority = TerminalAuthorityEvaluator().evaluate(issue, operation="live").to_dict()
    issue["proof_kernel_terminal_authority_decision"] = authority
    issue["terminal_authority_decision"] = deepcopy(authority)
    return issue


def _confirmed_v4_issue(cluster_uid: str) -> dict:
    return _terminal_v4_issue(cluster_uid)


def test_investigator_report_cannot_confirm_candidate() -> None:
    ledger = CandidateLedger()
    record, _ = ledger.add(
        _ticket(negative=["a guard may bound len"]),
        source="local_rule:entry",
        call_path=["entry", "sink"],
    )

    ledger.mark_reported(
        [
            {
                "ticket": {"id": record.candidate_id},
                "status": "analyzed",
                "validation_status": "confirmed",
            }
        ]
    )

    assert record.status == "investigated"
    assert record.record_role == "triage_lead"
    assert record.disposition == ""


@pytest.mark.parametrize("forged_disposition", ["confirmed", "rejected_with_proof"])
def test_main_validation_cannot_backfill_proof_terminal_without_exact_v4_authority(
    forged_disposition: str,
) -> None:
    ledger = CandidateLedger()
    record, _ = ledger.add(
        _ticket(negative=["a guard may bound len"]),
        source="local_rule:entry",
        call_path=["entry", "sink"],
    )

    updated = ledger.mark_issue_terminal(
        {
            "candidate_uid": record.candidate_uid,
            "evidence_hash": record.evidence_hash,
            "context_signature": record.context_signature,
            "candidate_disposition": forged_disposition,
            "validation_status": "validated",
        },
        disposition=forged_disposition,
        status="validated",
    )

    assert updated == 1
    assert record.status == "needs_review"
    assert record.disposition == "needs_review"
    assert record.terminal_issue["candidate_terminal_authority_failure_class"] == (
        "terminal_authority_binding_invalid"
    )


def test_main_validation_accepts_exact_v4_terminal_authority() -> None:
    ledger = CandidateLedger()
    ticket = _ticket(negative=["a guard may bound len"])
    ticket.evidence["validation_cluster_uid"] = "VAL_exact_v4"
    record, _ = ledger.add(
        ticket,
        source="local_rule:entry",
        call_path=["entry", "sink"],
    )
    issue = _confirmed_v4_issue(record.validation_cluster_uid)

    assert (
        ledger.mark_issue_terminal(
            issue,
            disposition="confirmed",
            status="validated",
        )
        == 1
    )
    assert record.status == "validated"
    assert record.disposition == "confirmed"


def test_main_validation_accepts_exact_v4_counterproof_terminal_authority() -> None:
    ledger = CandidateLedger()
    ticket = _ticket(negative=["the path may be unreachable"])
    ticket.evidence["validation_cluster_uid"] = "VAL_exact_v4_counterproof"
    record, _ = ledger.add(
        ticket,
        source="local_rule:entry",
        call_path=["entry", "sink"],
    )
    issue = _terminal_v4_issue(
        record.validation_cluster_uid,
        disposition="rejected_with_proof",
    )

    assert (
        ledger.mark_issue_terminal(
            issue,
            disposition="rejected_with_proof",
            status="rejected",
        )
        == 1
    )
    assert record.status == "rejected"
    assert record.disposition == "rejected_with_proof"


@pytest.mark.parametrize("failure_kind", ["legacy", "stale", "cross_obligation", "forged"])
def test_proof_terminal_lineage_mismatch_fails_closed(failure_kind: str) -> None:
    ledger = CandidateLedger()
    ticket = _ticket()
    ticket.evidence["validation_cluster_uid"] = "VAL_current"
    record, _ = ledger.add(
        ticket,
        source="local_rule:entry",
        call_path=["entry", "sink"],
    )
    issue = _confirmed_v4_issue(record.validation_cluster_uid)
    if failure_kind == "legacy":
        issue["proof_kernel_terminal_authority_decision"] = {
            "schema_version": "zscope.terminal-authority-decision.v3",
            "terminal": True,
            "disposition": "confirmed",
        }
    elif failure_kind == "stale":
        issue["terminal_authority_decision"] = {
            **issue["terminal_authority_decision"],
            "reason_code": "STALE",
        }
    elif failure_kind == "cross_obligation":
        issue = _confirmed_v4_issue("VAL_other")
        issue["validation_cluster_uid"] = record.validation_cluster_uid
    else:
        issue["proof_kernel_promotion_certificate"] = {
            **issue["proof_kernel_promotion_certificate"],
            "subject_uid": "forged-subject",
        }

    assert (
        ledger.mark_issue_terminal(
            issue,
            disposition="confirmed",
            status="validated",
        )
        == 1
    )
    assert record.disposition == "needs_review"
    assert record.terminal_issue["terminal_authority_decision"]["disposition"] == "needs_review"


def test_investigator_completion_cannot_close_validation_obligation() -> None:
    ledger = CandidateLedger()
    record, _ = ledger.add(
        _ticket(),
        source="local_rule:entry",
        call_path=["entry", "sink"],
        record_role="validation_obligation",
    )

    ledger.mark_reported([{"ticket": {"id": record.candidate_id}, "status": "analyzed"}])

    assert record.status == "queued"
    assert record.disposition == ""
    assert record.evidence_completion_status == "evidence_collected"


def test_candidate_uid_includes_revision_but_history_key_does_not() -> None:
    first = CandidateLedger(project_id=r"C:\work\demo", revision="rev-a")
    second = CandidateLedger(project_id="/mnt/build/demo", revision="rev-b")

    first_record, _ = first.add(
        _ticket(),
        source="local",
        call_path=["entry", "sink"],
    )
    second_record, _ = second.add(
        _ticket(),
        source="local",
        call_path=["entry", "sink"],
    )

    assert first_record.candidate_uid != second_record.candidate_uid
    assert first_record.history_key == second_record.history_key


def test_candidate_ledger_shares_validation_across_equivalent_entry_wrappers() -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")

    first, first_is_new = ledger.add(
        _ticket(),
        source="local",
        call_path=["entry_a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_a",
    )
    second, second_is_new = ledger.add(
        _ticket(),
        source="local",
        call_path=["entry_b", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_b",
    )

    assert first_is_new is True
    assert second_is_new is False
    assert first is second
    assert first.candidate_uid == second.candidate_uid
    assert first.validation_cluster_uid == second.validation_cluster_uid
    assert len(first.occurrence_uids) == 2
    assert {item.entry_identity for item in first.occurrences} == {
        "entry_a",
        "entry_b",
    }


def test_analyzer_propagates_stable_v33_identity_into_scan_ledger() -> None:
    """The ledger, rather than the transient issue, owns report identity."""

    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            project_id="demo",
            project_root=Path("."),
        ),
        analysis=SimpleNamespace(
            decision_fact_graph_v1=True,
            security_obligation_v1=True,
            decision_context_v31=True,
        ),
    )
    analyzer.decision_fact_cache = DecisionFactGraphCache()
    ledger = CandidateLedger(project_id="demo", revision="rev")
    state = {
        "candidate_ledger": ledger,
        "entry_identity": "src/demo.c::entry(void)",
        "run_id": "run",
    }
    issue = {
        "id": "RULE_1",
        "function": "entry",
        "location": "src/demo.c:12",
        "category": "bounds",
        "source": "len",
        "sink": "memcpy(dst, src, len)",
        "impact_level": "high",
        "evidence_pack": {
            "dependency_code_hash": "code-v1",
            "path": {"function": "entry", "complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "signed_io_result", "line": 10},
                    {"kind": "signed_to_unsigned_cast", "line": 11},
                    {"kind": "unsigned_length_sink", "line": 12},
                ]
            },
        },
    }

    analyzer._register_candidate_issues(state, [issue], source="clang_ast_cfg")

    record = ledger.records()[0]
    assert record.decision_context_version == DECISION_CONTEXT_V33
    assert record.ticket.evidence["decision_context_version"] == DECISION_CONTEXT_V33
    assert record.ticket.evidence["decision_fact_version"]


def test_repeated_display_id_across_entries_cannot_cross_update_terminal_state() -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")
    first, _ = ledger.add(
        _ticket(),
        source="local",
        call_path=["entry_a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_a",
    )
    second, _ = ledger.add(
        _ticket(),
        source="local",
        call_path=["entry_b", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_b",
    )

    assert (
        ledger.mark_issue_terminal(
            {"id": "ISSUE_1", "candidate_id": "ISSUE_1"},
            disposition="confirmed",
            status="validated",
        )
        == 0
    )
    # Queue state is not a security disposition; only a closed validation
    # group may become confirmed/rejected/review.
    assert first.disposition == ""
    assert second.disposition == ""

    assert (
        ledger.mark_issue_terminal(
            {"occurrence_uid": first.occurrence_uids[0], "id": "ISSUE_1"},
            disposition="confirmed",
            status="validated",
        )
        == 1
    )
    assert first.disposition == "needs_review"
    assert second.disposition == "needs_review"


def test_same_candidate_and_context_keep_distinct_evidence_validation_records() -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")
    first, first_is_new = ledger.add(
        _ticket(negative=["guard is after the sink"]),
        source="local",
        call_path=["entry", "sink"],
        record_role="validation_obligation",
    )
    second, second_is_new = ledger.add(
        _ticket(negative=["guard dominates the sink"]),
        source="local",
        call_path=["entry", "sink"],
        record_role="validation_obligation",
    )

    assert first_is_new is True
    assert second_is_new is True
    assert first is not second
    assert first.candidate_uid == second.candidate_uid
    assert first.context_signature == second.context_signature
    assert first.evidence_hash != second.evidence_hash

    assert (
        ledger.mark_issue_terminal(
            {
                # Both evidence records describe the same occurrence.  The exact
                # validation identity must take precedence over that broader UID.
                "occurrence_uid": first.occurrence_uids[0],
                "candidate_uid": first.candidate_uid,
                "evidence_hash": first.evidence_hash,
                "context_signature": first.context_signature,
            },
            disposition="needs_review",
            status="needs_review",
        )
        == 1
    )
    assert first.disposition == "needs_review"
    assert second.disposition == ""


def test_lifecycle_snapshot_filters_entry_and_excludes_triage_leads() -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")
    ledger.add(
        _ticket(),
        source="source_rule",
        call_path=["entry_a", "sink"],
        entry_identity="entry_a",
    )
    obligation, _ = ledger.add(
        _ticket(negative=["guard is absent"]),
        source="clang_ast_cfg",
        call_path=["entry_a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_a",
    )
    ledger.add(
        _ticket(negative=["guard is absent"]),
        source="clang_ast_cfg",
        call_path=["entry_b", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_b",
    )

    snapshot = ledger.lifecycle_snapshot(entry_identity="entry_a")

    assert snapshot["candidate_schema_version"] == "zscope.candidate.v3.3"
    assert len(snapshot["records"]) == 1
    assert snapshot["records"][0]["validation_cluster_uid"] == (obligation.validation_cluster_uid)
    assert snapshot["records"][0]["entry_count"] == 1
    assert snapshot["records"][0]["entries"] == ["entry_a"]
    assert snapshot["summary"]["triage_lead_count"] == 1


def test_frozen_candidate_ledger_rejects_late_discovery() -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")
    ledger.add(_ticket(), source="source_rule")

    snapshot = ledger.freeze()

    assert snapshot["summary"]["total"] == 1
    with pytest.raises(RuntimeError, match="frozen"):
        ledger.add(_ticket(), source="late")


def test_validation_group_outcome_is_the_only_reportable_terminal_projection() -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")
    first, _ = ledger.add(
        _ticket(),
        source="clang_ast_cfg",
        call_path=["entry_b", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_b",
    )
    ledger.add(
        _ticket(),
        source="graph_rule",
        call_path=["entry_a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry_a",
    )

    # A queued group is diagnostic state, not an actionable review row.
    assert ledger.lifecycle_snapshot()["outcomes"] == []
    confirmed = _confirmed_v4_issue(first.validation_cluster_uid)
    confirmed["description"] = "confirmed"
    assert ledger.mark_issue_terminal(confirmed, disposition="confirmed", status="validated") == 1

    outcome = ledger.freeze()["outcomes"]
    assert len(outcome) == 1
    assert outcome[0]["candidate_disposition"] == "confirmed"
    assert outcome[0]["primary_occurrence_uid"] == min(first.occurrence_uids)
    assert len(outcome[0]["occurrence_uids"]) == 2
    assert outcome[0]["issue"]["candidate_uid"] == first.candidate_uid
    assert outcome[0]["issue"]["validation_cluster_uid"] == first.validation_cluster_uid
    assert ledger.summary()["nonterminal_validation_count"] == 0


def test_frozen_nonterminal_validation_group_marks_scan_incomplete() -> None:
    ledger = CandidateLedger(project_id="demo", revision="rev")
    ledger.add(
        _ticket(),
        source="clang_ast_cfg",
        call_path=["entry", "sink"],
        record_role="validation_obligation",
    )

    snapshot = ledger.freeze()

    assert snapshot["outcomes"] == []
    assert snapshot["summary"]["nonterminal_validation_count"] == 1
    assert snapshot["summary"]["incomplete"] is True
