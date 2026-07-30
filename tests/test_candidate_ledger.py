from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.candidates import CandidateLedger
from zscope.orchestration.subagents import SubAgentTicket
import pytest


def _ticket(*, priority=90, negative=None):
    return SubAgentTicket(
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


def test_main_validation_backfills_candidate_terminal_state() -> None:
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
            "candidate_disposition": "confirmed",
            "validation_status": "validated",
        },
        disposition="confirmed",
        status="validated",
    )

    assert updated == 1
    assert record.status == "validated"
    assert record.disposition == "confirmed"


def test_deep_investigator_requires_high_risk_conflicting_evidence() -> None:
    assert Analyzer._is_high_risk_conflicting_ticket(
        _ticket(negative=["a dominating guard may bound len"])
    )
    assert not Analyzer._is_high_risk_conflicting_ticket(
        _ticket(priority=40, negative=["a guard may bound len"])
    )
    assert not Analyzer._is_high_risk_conflicting_ticket(_ticket())


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

    assert ledger.mark_issue_terminal(
        {"id": "ISSUE_1", "candidate_id": "ISSUE_1"},
        disposition="confirmed",
        status="validated",
    ) == 0
    assert first.disposition == "needs_review"
    assert second.disposition == "needs_review"

    assert ledger.mark_issue_terminal(
        {"occurrence_uid": first.occurrence_uids[0], "id": "ISSUE_1"},
        disposition="confirmed",
        status="validated",
    ) == 1
    assert first.disposition == "confirmed"
    assert second.disposition == "confirmed"


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

    assert ledger.mark_issue_terminal(
        {
            # Both evidence records describe the same occurrence.  The exact
            # validation identity must take precedence over that broader UID.
            "occurrence_uid": first.occurrence_uids[0],
            "candidate_uid": first.candidate_uid,
            "evidence_hash": first.evidence_hash,
            "context_signature": first.context_signature,
        },
        disposition="rejected_with_proof",
        status="rejected",
    ) == 1
    assert first.disposition == "rejected_with_proof"
    assert second.disposition == "needs_review"


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

    assert snapshot["candidate_schema_version"] == "zscope.candidate.v3"
    assert len(snapshot["records"]) == 1
    assert snapshot["records"][0]["validation_cluster_uid"] == (
        obligation.validation_cluster_uid
    )
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
