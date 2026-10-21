"""Offline A01 boundary: provider data never becomes an executable capability."""

import hashlib
import json
from dataclasses import replace

import pytest

from test_investigation_evidence import case, report
from zscope.common.cancellation import CancellationToken
from zscope.orchestration.external_investigation import (
    ExternalInvestigationTask,
    OfflineImportError,
    SCHEMA,
    run_external_investigation,
)


def task_for(case, session, **options):
    return ExternalInvestigationTask.from_session(
        session,
        case.unit,
        case.projection,
        proposition="The observed copy may exceed the destination capacity.",
        missing_facts=("destination_capacity",),
        **options,
    )


def read_intent(line=3):
    return {
        "action": "query",
        "tool": "read_code",
        "function_uid": "FUNC_copy",
        "arguments": {"file_path": "src/demo.c", "start_line": line, "end_line": line},
    }


def document(task, decisions, **updates):
    payload = {
        "schema_version": SCHEMA,
        "provider": {"kind": "offline", "name": "test-fixture", "version": "1"},
        "task_id": task.task_id,
        "task_fingerprint": task.fingerprint,
        "decisions": decisions,
    }
    payload.update(updates)
    return json.dumps(payload)


def finish(case, refs=None, **options):
    return {
        "action": "finish",
        "report": report(case, refs or ["@evidence:1"], **options).to_dict(),
    }


def tree(root):
    return {
        str(path.relative_to(root)): (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            path.stat().st_mtime_ns,
        )
        for path in root.rglob("*")
        if path.is_file()
    }


def test_offline_queries_register_program_refs_and_return_partial_typed_report(case):
    session = case.session()
    task = task_for(case, session)
    before = tree(case.root)
    outcome = run_external_investigation(
        task,
        document(task, [read_intent(2), read_intent(3), finish(case, ["@evidence:2"])]),
        session,
    )
    assert outcome.status == "completed"
    assert outcome.report.coverage_status == "partial"
    assert len(outcome.evidence) == 2
    assert outcome.report.hypotheses[0].positive_evidence_refs == (
        outcome.evidence[1]["evidence_ref"],
    )
    assert outcome.provenance["origin"] == "external_offline_investigation"
    assert outcome.provenance["independent_blind_discovery"] is False
    assert outcome.provenance["real_provider_executed"] is False
    assert outcome.usage == {"status": "unknown", "physical_attempts": None, "tokens": None}
    assert not outcome.proof_authority
    assert all(not item["proof_authority"] for item in outcome.evidence)
    assert tree(case.root) == before
    session.validate_current()  # Borrowed owner retains the session.


def test_exported_task_contains_enforced_readonly_boundaries(case):
    task = task_for(case, case.session())
    exported = task.to_dict()
    assert exported["network"] == "none"
    assert exported["write_paths"] == []
    assert exported["shell"] is exported["scan"] is False
    assert exported["max_child_depth"] == exported["parent_depth"] == 0
    assert {scope["file_path"] for scope in exported["allowed_scopes"]} == {"src/demo.c"}
    exported["allowed_scopes"][0]["file_path"] = "private.c"
    assert task.to_dict()["allowed_scopes"][0]["file_path"] == "src/demo.c"


@pytest.mark.parametrize("field", ["schema_version", "task_id", "task_fingerprint"])
def test_import_version_mismatch_executes_nothing(case, field):
    session = case.session(execute_tool=lambda *_: pytest.fail("version mismatch executed"))
    task = task_for(case, session)
    out = run_external_investigation(
        task, document(task, [read_intent()], **{field: "stale"}), session
    )
    assert out.status == "rejected" and out.report is None and not out.evidence


@pytest.mark.parametrize(
    "field", ["revision", "build_context", "tool_version", "model_identity", "tool_policy"]
)
def test_current_identity_change_rejects_before_tools(case, field):
    session = case.session(execute_tool=lambda *_: pytest.fail("stale identity executed"))
    task = task_for(case, session)
    case.current[0] = replace(case.identity, **{field: "changed"})
    out = run_external_investigation(task, document(task, [read_intent()]), session)
    assert out.status == "rejected" and not out.evidence


@pytest.mark.parametrize(
    "tool",
    [
        "shell",
        "exec",
        "scan.run",
        "get_static_findings",
        "write_file",
        "network",
        "external_adapter",
    ],
)
def test_forbidden_tools_cannot_reach_program_executor(case, tool):
    session = case.session(execute_tool=lambda *_: pytest.fail("forbidden tool executed"))
    task = task_for(case, session)
    intent = {**read_intent(), "tool": tool}
    out = run_external_investigation(task, document(task, [intent]), session)
    assert out.status == "rejected" and not out.evidence


@pytest.mark.parametrize(
    "path", ["../private.c", "/home/private/.env", "GROUND_TRUTH.md", ".env", "src/other.c"]
)
def test_private_and_ungranted_paths_are_never_executed_or_echoed(case, path):
    session = case.session(execute_tool=lambda *_: pytest.fail("private path executed"))
    task = task_for(case, session)
    intent = read_intent()
    intent["arguments"]["file_path"] = path
    out = run_external_investigation(task, document(task, [intent]), session)
    assert not out.evidence and not out.report.hypotheses
    assert path not in json.dumps(out.trace)
    assert path not in out.stop_reason


def test_report_scope_cannot_expand_program_grant(case):
    session = case.session()
    task = task_for(case, session)
    intent = {**read_intent(), "function_uid": "FUNC_private"}
    out = run_external_investigation(task, document(task, [intent]), session)
    assert out.status == "rejected" and not out.evidence


@pytest.mark.parametrize(
    "field,value",
    [
        ("command", ["touch", "private"]),
        ("callback", "module:run"),
        ("write_paths", ["src"]),
        ("network", "allow"),
        ("environment", {"SECRET": "private"}),
        ("cwd", "/private"),
        ("proof_authority", True),
    ],
)
def test_import_cannot_inject_executable_or_authority_fields(case, field, value):
    session = case.session(execute_tool=lambda *_: pytest.fail("invalid import executed"))
    task = task_for(case, session)
    out = run_external_investigation(
        task, document(task, [read_intent()], **{field: value}), session
    )
    assert out.status == "rejected" and out.report is None


def test_callable_is_not_an_offline_document(case):
    session = case.session()
    task = task_for(case, session)
    out = run_external_investigation(task, lambda: pytest.fail("callback invoked"), session)
    assert out.status == "rejected"


@pytest.mark.parametrize("kind,version", [("sdk", "1"), ("cli", "1"), ("offline", "2")])
def test_real_or_unknown_provider_is_unsupported_without_session_work(
    case, monkeypatch, kind, version
):
    session = case.session()
    task = task_for(case, session)
    monkeypatch.setattr(
        session, "manifest", lambda: pytest.fail("unsupported provider touched session")
    )
    out = run_external_investigation(
        task,
        document(
            task,
            [read_intent()],
            provider={
                "kind": kind,
                "name": "not-loaded",
                "version": version,
            },
        ),
        session,
    )
    assert out.status == "unsupported"
    assert out.stop_reason == "provider_permissions_unenforced"
    assert out.provenance["provider"]["kind"] == kind
    assert out.provenance["execution"] == "not_run"


def test_imported_manifest_and_proof_claims_are_not_capabilities(case):
    session = case.session()
    task = task_for(case, session)
    intent = finish(case, ["investigation:serialized_old_session:1"])
    out = run_external_investigation(task, document(task, [intent]), session)
    assert out.status == "rejected" and not out.report.hypotheses
    intent = finish(case, ["source:src/demo.c:3"])
    intent["report"]["proof_authority"] = True
    out = run_external_investigation(task, document(task, [intent]), session)
    assert out.status == "rejected" and not out.report.hypotheses


def test_old_ref_cannot_be_replayed_in_another_session(case):
    first = case.session()
    first_task = task_for(case, first)
    accepted = run_external_investigation(first_task, document(first_task, [read_intent()]), first)
    old_ref = accepted.evidence[0]["evidence_ref"]
    first.close()
    second = case.session()
    second_task = task_for(case, second)
    out = run_external_investigation(
        second_task, document(second_task, [finish(case, [old_ref])]), second
    )
    assert out.status == "rejected" and not out.report.hypotheses


@pytest.mark.parametrize("refs", [["@evidence:0"], ["@evidence:2"], ["@evidence:evil"]])
def test_only_current_program_registered_slots_can_bind_report(case, refs):
    session = case.session()
    task = task_for(case, session)
    out = run_external_investigation(
        task, document(task, [read_intent(), finish(case, refs)]), session
    )
    assert out.status == "rejected" and not out.report.hypotheses
    assert len(out.evidence) == len(out.report.tool_evidence_refs) == 1


@pytest.mark.parametrize(
    "options",
    [
        {"coverage": "complete"},
        {"function": "FUNC_other"},
        {"location": "src/other.c:3"},
        {"location": "src/demo.c:100"},
    ],
)
def test_imported_report_cannot_claim_complete_or_outside_scope(case, options):
    session = case.session()
    task = task_for(case, session)
    out = run_external_investigation(
        task, document(task, [read_intent(), finish(case, **options)]), session
    )
    assert out.status == "rejected" and out.report.coverage_status == "partial"
    assert not out.report.hypotheses


def test_cancel_after_tool_preserves_receipt_and_only_cancels_owned_operation(case):
    parent, unrelated = CancellationToken(), CancellationToken()

    def execute(name, args):
        value = case.runtime.execute_tool(name, args)
        parent.cancel("fixture cancellation")
        return value

    session = case.session(execute_tool=execute)
    task = task_for(case, session)
    out = run_external_investigation(
        task, document(task, [read_intent(), read_intent(2)]), session, cancellation=parent
    )
    assert out.status == "interrupted" and len(out.evidence) == 1
    assert len(out.report.tool_evidence_refs) == 1 and not unrelated.is_cancelled()
    session.validate_current()


def test_local_deadline_keeps_parent_and_borrowed_session_live(case, monkeypatch):
    import zscope.common.cancellation as module

    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    parent = CancellationToken()

    def execute(name, args):
        value = case.runtime.execute_tool(name, args)
        now[0] = 2.0
        return value

    session = case.session(execute_tool=execute)
    task = task_for(case, session, timeout_seconds=1)
    out = run_external_investigation(
        task, document(task, [read_intent()]), session, cancellation=parent
    )
    assert out.status == "interrupted" and len(out.evidence) == 1
    assert not parent.is_cancelled()
    session.validate_current()


def test_pre_cancelled_import_starts_no_tools(case):
    session = case.session(execute_tool=lambda *_: pytest.fail("cancelled work executed"))
    task = task_for(case, session)
    parent = CancellationToken()
    parent.cancel()
    out = run_external_investigation(
        task, document(task, [read_intent()]), session, cancellation=parent
    )
    assert out.status == "interrupted" and not out.evidence


def test_nested_adapter_is_rejected_without_poisoning_outer_or_later_run(case):
    nested = []
    task = None
    session = None

    def execute(name, args):
        nested.append(run_external_investigation(task, document(task, [read_intent()]), session))
        return case.runtime.execute_tool(name, args)

    session = case.session(execute_tool=execute)
    task = task_for(case, session)
    out = run_external_investigation(task, document(task, [read_intent()]), session)
    assert len(out.evidence) == 1
    assert nested[0].stop_reason == "recursive_adapter_denied"
    later = run_external_investigation(task, document(task, [{"action": "unknown"}]), session)
    assert later.stop_reason == "provider_unknown"


def test_source_change_revokes_report_but_keeps_receipt_for_audit(case):
    def execute(name, args):
        value = case.runtime.execute_tool(name, args)
        case.path.write_text("changed\n", encoding="utf-8")
        return value

    session = case.session(execute_tool=execute)
    task = task_for(case, session)
    out = run_external_investigation(task, document(task, [read_intent()]), session)
    assert out.status == "rejected" and out.report is None


def test_tool_failure_can_recover_and_error_text_is_not_echoed(case):
    calls = []

    def execute(name, args):
        calls.append(args)
        if len(calls) == 1:
            raise RuntimeError("SECRET_PROVIDER_EXCEPTION")
        return case.runtime.execute_tool(name, args)

    session = case.session(execute_tool=execute)
    task = task_for(case, session)
    out = run_external_investigation(
        task, document(task, [read_intent(2), read_intent(3), finish(case)]), session
    )
    assert out.status == "completed" and len(out.evidence) == 1
    assert "SECRET" not in json.dumps(out.trace)
    failed = run_external_investigation(task, "{bad", session)
    assert failed.status == "rejected"
    again = run_external_investigation(task, document(task, [read_intent(), finish(case)]), session)
    assert again.status == "completed"


def test_repeated_query_and_step_budget_do_not_launch_more_work(case):
    session = case.session()
    task = task_for(case, session)
    out = run_external_investigation(task, document(task, [read_intent(), read_intent()]), session)
    assert out.stop_reason == "repeated_query_no_gain" and len(out.evidence) == 1
    bounded = task_for(case, session, max_steps=1)
    out = run_external_investigation(
        bounded, document(bounded, [read_intent(2), read_intent(4)]), session
    )
    assert out.stop_reason == "step_budget" and len(out.evidence) == 1


@pytest.mark.parametrize("text", ['{"provider": {}, "provider": {}}', "{}", "NaN", "[]"])
def test_malformed_or_duplicate_json_is_rejected(case, text):
    session = case.session(execute_tool=lambda *_: pytest.fail("invalid JSON executed"))
    out = run_external_investigation(task_for(case, session), text, session)
    assert out.status == "rejected"


@pytest.mark.parametrize(
    "changes",
    [
        {"max_steps": 0},
        {"max_steps": 5},
        {"max_steps": True},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": 121},
        {"parent_depth": 1},
        {"allowed_tools": ("shell",)},
    ],
)
def test_task_cannot_enlarge_fixed_execution_boundary(case, changes):
    task = task_for(case, case.session())
    with pytest.raises(OfflineImportError):
        replace(task, **changes)


def test_caller_can_narrow_tools_but_intents_cannot_widen_them(case):
    session = case.session(execute_tool=lambda *_: pytest.fail("broadened tool policy"))
    task = task_for(case, session, allowed_tools=frozenset({"search_code"}))
    out = run_external_investigation(task, document(task, [read_intent()]), session)
    assert out.status == "rejected"


def test_decision_callback_is_data_rejected_before_tools(case):
    session = case.session(execute_tool=lambda *_: pytest.fail("callback intent executed"))
    task = task_for(case, session)
    intent = {**read_intent(), "callback": "execute_private_code"}
    out = run_external_investigation(task, document(task, [intent]), session)
    assert out.status == "rejected" and not out.evidence


def test_later_version_change_preserves_only_stale_audit_and_no_report(case):
    calls = []

    def execute(name, args):
        calls.append(name)
        value = case.runtime.execute_tool(name, args)
        if len(calls) == 2:
            case.current[0] = replace(case.identity, revision="new")
        return value

    session = case.session(execute_tool=execute)
    task = task_for(case, session)
    out = run_external_investigation(
        task, document(task, [read_intent(2), read_intent(3)]), session
    )
    assert out.status == "rejected" and out.report is None
    assert len(out.evidence) == 1
    assert out.provenance["evidence_validity"] == "stale_or_unavailable"


def test_oversized_import_is_rejected_without_tool_work(case):
    session = case.session(execute_tool=lambda *_: pytest.fail("oversized intent executed"))
    task = task_for(case, session)
    out = run_external_investigation(task, " " * (2 * 1024 * 1024 + 1), session)
    assert out.status == "rejected"
