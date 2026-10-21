"""Actual S01-independent Stage boundaries, with controlled ledger state only."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from zscope.common.cancellation import CancellationError
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.candidates import CandidateLedger
from zscope.orchestration.jobs.instance_results import InstanceKey
from zscope.orchestration.jobs.scan_work import InstanceWorkHandlers
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.orchestration.subagents import SubAgentTicket
from zscope.retrieval.instance_index import InstanceScope


def collector():
    analyzer = Analyzer.__new__(Analyzer)
    analyzer._instance_collection = {"stages": {}, "unsupported_stages": {}}
    return analyzer


@pytest.mark.parametrize(
    "error",
    [
        CancellationError("window stopped"),
        ValueError("input changed"),
        RuntimeError("detector failed"),
    ],
)
def test_collection_preserves_original_failure_and_records_final_disposition(error):
    analyzer = collector()

    def fail():
        raise error

    with pytest.raises(type(error)) as raised:
        analyzer._observe_instance_collection("local", fail)
    assert raised.value is error
    assert analyzer._instance_collection["stages"]["local"] == {
        "disposition": "cancelled" if isinstance(error, CancellationError) else "error",
        "reason": f"{type(error).__name__}: {error}",
    }


def test_currentness_failure_is_preserved_and_operation_is_never_started(monkeypatch):
    analyzer = collector()
    error = ValueError("current input was revoked")
    entered = []

    def revoked():
        raise error

    monkeypatch.setattr(analyzer, "_require_instance_semantics_current", revoked)
    with pytest.raises(ValueError) as raised:
        analyzer._observe_instance_collection("graph", lambda: entered.append(True))
    assert raised.value is error and entered == []
    assert analyzer._instance_collection["stages"]["graph"]["disposition"] == "error"


def test_invalid_detector_payload_keeps_its_actual_error():
    analyzer = collector()
    with pytest.raises(ValueError, match="instance_collection_invalid_detector_output"):
        analyzer._observe_instance_collection("backend", lambda: [object()])
    assert analyzer._instance_collection["stages"]["backend"]["disposition"] == "error"


def test_successful_collection_retains_payload_and_unsupported_status():
    analyzer = collector()
    payload = [{"rule": "controlled_detector_result"}]
    assert analyzer._observe_instance_collection("local", lambda: payload) is payload
    assert analyzer._instance_collection["stages"]["local"] == {
        "disposition": "complete",
        "reason": "",
    }
    analyzer._instance_collection["unsupported_stages"][
        "persist"
    ] = "scoped_raw_knowledge_db_unavailable"
    assert analyzer._observe_instance_collection("persist", lambda: None) is None
    assert analyzer._instance_collection["stages"]["persist"] == {
        "disposition": "unsupported",
        "reason": "scoped_raw_knowledge_db_unavailable",
    }


def closed_work(summary):
    work = InstanceWorkHandlers.__new__(InstanceWorkHandlers)
    work._batch = None
    work._closed_recovery_summary = summary
    return work


def test_closed_recovery_summary_is_detached_and_preserves_json_normalization():
    saved = {
        "restored_identities": ("instance-a",),
        "restored_instance_runs": {"instance-a": "run-a"},
    }
    work = closed_work(saved)
    actual = work.recovery_summary
    assert actual == json.loads(json.dumps(saved))
    actual["restored_identities"].append("caller mutation")
    actual["restored_instance_runs"]["instance-a"] = "other run"
    assert saved == {
        "restored_identities": ("instance-a",),
        "restored_instance_runs": {"instance-a": "run-a"},
    }
    assert work.recovery_summary == json.loads(json.dumps(saved))
    assert closed_work({}).recovery_summary == {}


@pytest.mark.parametrize("corrupt", [[], "invalid summary", 7])
def test_closed_recovery_summary_rejects_non_mapping_root(corrupt):
    with pytest.raises(ValueError, match="instance_recovery_summary_not_mapping"):
        _ = closed_work(corrupt).recovery_summary


def pending_ledger():
    ledger = CandidateLedger(project_id="quality-unit")
    ticket = SubAgentTicket(
        id="RULE_QUALITY_UNIT",
        skill="bounds_and_integer",
        task="check bounds",
        trigger="memcpy",
        line=12,
        context_slice="memcpy(dst, src, len);",
        priority_score=90,
        origin="src/demo.c:10",
        sink="src/demo.c:12",
        resource_kind="memory",
        evidence={
            "build_context_id": "build-a",
            "defect_class": "bounds",
            "entry_identity": "entry-a",
        },
    )
    record, _ = ledger.add(
        ticket,
        source="quality-unit",
        call_path=["entry-a", "sink"],
        record_role="validation_obligation",
        entry_identity="entry-a",
    )
    key = InstanceKey("instance-a", "build-a", "c:@F@entry-a", "/controlled/src/demo.c")
    return ledger, record, key


def test_pending_snapshot_preserves_typed_owner_membership_and_live_ledger():
    ledger, record, key = pending_ledger()
    before = deepcopy(record.to_dict(include_context=True))
    snapshot = ledger.pending_instance_snapshot(
        instance=key, entry_instances={("entry-a", "build-a"): key}
    )
    assert len(snapshot.records) == 1
    detached = snapshot.records[0]
    assert detached.owner_instances == (key,)
    assert detached.candidate_uid == record.candidate_uid
    assert detached.status == "queued" and detached.record_role == "validation_obligation"
    assert json.loads(snapshot.manifest_json)["record_count"] == 1
    wire = json.loads(detached.record_json)
    wire["ticket"]["task"] = "caller mutation"
    assert record.to_dict(include_context=True) == before


def test_unknown_owner_and_terminal_record_cannot_be_exported_as_pending():
    ledger, record, key = pending_ledger()
    with pytest.raises(ValueError, match="pending_record_entry_binding_unknown"):
        ledger.pending_instance_snapshot(instance=key, entry_instances={})
    record.status = "validated"
    with pytest.raises(ValueError, match="pending_record_not_neutral"):
        ledger.pending_instance_snapshot(
            instance=key, entry_instances={("entry-a", "build-a"): key}
        )


def scoped_router():
    ledger, record, key = pending_ledger()
    selected = InstanceScope(key.build_context_id, key.usr, key.identity, key.source)
    other = InstanceScope(key.build_context_id, "c:@F@other", "other-instance", key.source)
    analyzer = ParallelAnalyzer.__new__(ParallelAnalyzer)
    analyzer._candidate_ledger = ledger
    analyzer._instance_scopes_by_build = {key.build_context_id: [other, selected]}
    analyzer._instance_entry_owners = {("entry-a", key.build_context_id): key}
    issue = {
        "build_context_id": key.build_context_id,
        "validation_cluster_uid": record.validation_cluster_uid,
        "context_signature": record.context_signature,
    }
    return analyzer, record, key, selected, issue


def test_pending_issue_selects_exact_owner_instead_of_first_scope():
    analyzer, _record, _key, selected, issue = scoped_router()
    assert analyzer._scope_for_pending_issue(issue) is selected
    assert analyzer._scope_for_pending_issue({**issue, "context_signature": "different"}) is None


def test_missing_or_shared_owner_remains_unvalidated():
    analyzer, record, key, _selected, issue = scoped_router()
    analyzer._instance_entry_owners = {("unrelated", key.build_context_id): key}
    assert analyzer._scope_for_pending_issue(issue) is None
    second = InstanceKey("instance-b", key.build_context_id, "c:@F@other", key.source)
    analyzer._instance_entry_owners = {
        ("entry-a", key.build_context_id): key,
        ("entry-b", key.build_context_id): second,
    }
    record.occurrences.append(replace(record.occurrences[0], entry_identity="entry-b"))
    assert analyzer._scope_for_pending_issue(issue) is None
