"""Plan acceptance gates; no network calls, scan execution or benchmark input.

These tests deliberately retain failures until the implementation satisfies
the agreed contracts. Do not skip or loosen them to obtain a green suite.
"""

from copy import deepcopy

import pytest

from zscope.review_memory.extractor import proposal_from_record
from zscope.review_memory.lifecycle import qualify_for_advisory
from zscope.review_memory.matcher import match_patterns
from zscope.review_memory.projector import project_hints
from zscope.review_memory.schema import validate_pattern, validate_registered, validate_review_record
from zscope.review_memory.store import ReviewMemoryStore
from zscope.review_memory.identity import review_subject_id
from zscope.config.user_config_store import UserConfigStore
from zscope.web.services import ReportFeedbackService
from types import SimpleNamespace
import json


def _record():
    return {
        "schema_version": "zscope.review-record.v1",
        "review_id": "review_acceptance",
        "project_id": "project_acceptance",
        "finding": {
            "rule": "example_rule",
            "category": "double_free",
            "stable_fingerprint": "issue_identity_unchanged",
        },
        "source_context": {"source_context_fingerprint": "source_original"},
        "user_rebuttal": "Check the current guard independently.",
        "status": "pending_extraction",
    }


def _pattern():
    pattern = proposal_from_record(_record())
    pattern["required_checks"] = ["Verify the guard in current code."]
    pattern["status"] = "advisory"
    return pattern


def test_zero_pattern_limit_never_injects_a_hint():
    assert match_patterns(
        _record()["finding"], [_pattern()], project_id="project_acceptance", limit=0
    ) == []


def test_zero_token_budget_never_injects_a_hint():
    projection = project_hints([{"pattern_id": "fp_example", "summary": "hint"}], token_budget=0)
    assert projection["hints"] == []
    assert projection["selection"]["selected_count"] == 0


def test_source_identity_is_not_replaced_by_issue_identity():
    pattern = proposal_from_record(_record())
    assert "source_original" in pattern["source_fingerprints"]
    assert "issue_identity_unchanged" not in pattern["source_fingerprints"]


def test_record_identity_rejects_path_traversal_before_any_write():
    record = _record()
    record["review_id"] = "../../outside"
    with pytest.raises(ValueError):
        validate_review_record(record)


def test_pattern_schema_rejects_unknown_lifecycle_state():
    pattern = _pattern()
    pattern["status"] = "arbitrary_active_state"
    with pytest.raises(ValueError):
        validate_pattern(pattern)


def test_review_memory_registry_is_independent_and_runtime_validated():
    pattern = _pattern()
    assert validate_registered(pattern)["schema_version"] == "zscope.false-positive-pattern-proposal.v1"
    with pytest.raises(ValueError, match="unregistered"):
        validate_registered({"schema_version": "zscope.wiki.constraint.v1"})


def test_qualification_requires_resolvable_source_evidence():
    pattern = _pattern()
    pattern["status"] = "proposed"
    pattern["evidence_refs"] = []
    assert not qualify_for_advisory(pattern)


def test_original_rebuttal_cannot_be_overwritten_under_same_review_id(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    original = _record()
    store.save_record(original)
    replacement = deepcopy(original)
    replacement["user_rebuttal"] = "Changed feedback must become a new review event."
    try:
        store.save_record(replacement)
    except ValueError:
        pass
    assert store.get_record(original["review_id"])["user_rebuttal"] == original["user_rebuttal"]


def test_missing_record_file_is_recreated_even_when_stale_sqlite_row_exists(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    original = _record()
    store.save_record(original)
    record_path = tmp_path / ".zscope/review-memory/records" / f"{original['review_id']}.json"
    record_path.unlink()

    recreated = deepcopy(original)
    recreated["status"] = "pending_extraction"
    recreated["created_at"] = "2026-09-14T00:00:01Z"
    store.save_record(recreated)

    assert record_path.is_file()
    assert store.get_record(original["review_id"])["status"] == "pending_extraction"
    assert any(
        json.loads(line).get("event") == "review_record_created"
        and json.loads(line).get("recreated_missing_file") is True
        for line in (tmp_path / ".zscope/review-memory/audits/events.jsonl").read_text().splitlines()
    )


def test_same_finding_uses_one_subject_but_retains_distinct_rebuttal_events(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    first = _record()
    second = deepcopy(first)
    second["review_id"] = "review_acceptance_second"
    second["user_rebuttal"] = "A later, more precise explanation."
    first["review_subject_id"] = review_subject_id(first)
    second["review_subject_id"] = review_subject_id(second)
    store.save_record(first)
    store.save_record(second)
    assert first["review_subject_id"] == second["review_subject_id"]
    assert len(store.list_records()) == 2


def test_rejected_feedback_archives_review_record_without_llm(tmp_path):
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"issues": [{"id": "I1", "function": "f", "location": "a.c:1", "category": "C"}]}), encoding="utf-8")
    project = SimpleNamespace(
        project_root=tmp_path,
        project_id="project_acceptance",
        review_memory=SimpleNamespace(mode="archive", state_dir=".zscope/review-memory"),
    )
    service = ReportFeedbackService(
        UserConfigStore(tmp_path / "user_config.xlsx"),
        report_filename=str(report_path),
        project_config=project,
    )
    result = service.save_validation_feedback([{
        "id": "I1", "function": "f", "location": "a.c:1", "category": "C",
        "validation_status": "rejected", "user_rebuttal": "guard is unreachable",
    }])
    assert result["review_memory"]["recorded"] is True
    assert result["review_memory"]["items"][0]["review_id"]
    assert result["review_memory"]["items"][0]["extraction_status"] == "pending_extraction"
    assert result["review_memory"]["review_id"] == result["review_memory"]["items"][0]["review_id"]
    assert result["review_memory"]["extraction_status"] == "pending_extraction"
    records = ReviewMemoryStore(tmp_path).list_records()
    assert records[0]["user_rebuttal"] == "guard is unreachable"


def test_validated_feedback_supersedes_record_and_proposal_without_deleting_history(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    record = _record()
    record["finding"]["candidate_id"] = "CAND-1"
    record["status"] = "extracted"
    record["review_subject_id"] = review_subject_id(record)
    store.save_record(record)
    pattern = _pattern()
    pattern["origin_review_ids"] = [record["review_id"]]
    pattern["review_subject_id"] = record["review_subject_id"]
    store.save_proposal(pattern)

    result = store.supersede_for_finding({"candidate_id": "CAND-1"})

    assert result["review_ids"] == [record["review_id"]]
    assert result["pattern_ids"] == [pattern["pattern_id"]]
    assert len(store.list_records()) == 1
    assert store.get_record(record["review_id"])["status"] == "superseded"
    assert store.get_proposal(pattern["pattern_id"])["status"] == "deprecated"


def test_store_publishes_active_digest_and_hash_chained_audit(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    pattern = _pattern()
    pattern["status"] = "proposed"
    store.save_proposal(pattern)
    assert store.active_pointer()["pattern_ids"] == []
    pattern["status"] = "advisory"
    store.save_proposal(pattern)
    active = store.active_pointer()
    assert active["pattern_ids"] == [pattern["pattern_id"]]
    assert active["digest"]
    assert store.verify_audit_integrity()["valid"] is True


def test_store_persists_pattern_match_and_exports_it(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    match = store.save_match({
        "schema_version": "zscope.review-pattern-match.v1",
        "pattern_id": "pattern_1",
        "scan_id": "scan_1",
        "issue_identity": {"issue_id": "issue_1"},
        "match_basis": ["ast"],
        "source_compatible": True,
        "injected": True,
    })
    assert match["created_at"]
    assert store.list_matches(scan_id="scan_1")[0]["pattern_id"] == "pattern_1"
    assert store.export_json()["matches"][0]["issue_identity"]["issue_id"] == "issue_1"


def test_extraction_job_is_persistent_and_audited(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    job = store.create_extraction_job(["review_a", "review_b"])
    assert job["status"] == "pending"
    running = store.update_extraction_job(job, status="running")
    assert running["attempts"] == 1
    completed = store.update_extraction_job(running, status="completed")
    assert completed["status"] == "completed"
    persisted = store.list_extraction_jobs()[0]
    assert persisted["review_ids"] == ["review_a", "review_b"]
    assert store.verify_audit_integrity()["valid"] is True


def test_export_includes_jobs_and_replay_output_is_atomic(tmp_path):
    store = ReviewMemoryStore(tmp_path)
    store.create_extraction_job([])
    assert store.export_json()["jobs"][0]["operation"] == "extraction_job"
