"""Scoped human declarations, native replay and selective feedback invalidation."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from test_lifecycle_paths import paths_project
from test_protocol_assessment import assessed
from test_validation_runner import _runner, _state
from zscope.config.protocol_feedback import ProtocolAnswerConflict
from zscope.config.user_config_store import UserConfigStore
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.semantics.business_assumptions import assumption_key, feedback_reuse_problem


@pytest.fixture
def store(tmp_path):
    return UserConfigStore(tmp_path / "config")


def answer(store, assumption, value="yes", note="项目接口约定第 3 节", revision=0):
    return store.save_protocol_answers(
        [
            {
                "assumption": assumption,
                "answer": value,
                "source_note": note,
                "expected_revision": revision,
            }
        ]
    )


def validate(project, store, issue):
    runner = _runner(None, enabled=False, code_index=project[0])
    runner.get_contract_registry = lambda: project[2]
    runner.validation_pipeline = ValidationPipeline(store)
    state = _state(issue)
    runner.run(state)
    return state


def test_explicit_scope_plus_current_native_path_can_confirm(paths_project, store):
    issue = assessed(paths_project)
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    answer(store, assumption)
    state = validate(paths_project, store, issue)
    assert len(state["issues"]) == 1 and not state["observations"]
    assert issue["candidate_disposition"] == "confirmed"
    assert (
        issue["decision_proof"]["proof_kind"]
        == "checked_object_protocol_with_business_declarations"
    )
    assert not issue["missing_fact_kinds"]
    assert issue["security_obligation"]["decision_fact_slice"]["coverage"] == "complete"
    assert deterministic_decision_proof(deepcopy(issue), outcome="confirm") is not None
    assert deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm") is None
    assert not store.is_false_positive("", "", "")


def test_failure_needs_both_norm_and_responsibility_endpoint(paths_project, store):
    issue = assessed(paths_project, "failure_unreleased")
    assumptions = issue["protocol_assessment"]["assumptions"]
    answer(store, assumptions[0])
    state = validate(paths_project, store, issue)
    assert not state["issues"]
    assert issue["needs_review_sub_state"] == "business_conditional"
    assert issue["missing_fact_kinds"] == [assumptions[1]["fact_kind"]]
    answer(store, assumptions[1])
    assert validate(paths_project, store, issue)["issues"]


def test_answer_never_supplies_later_access_or_other_objects(paths_project, store):
    retained = assessed(paths_project, "stale_retained")
    answer(store, retained["protocol_assessment"]["assumptions"][0])
    assert not validate(paths_project, store, retained)["issues"]
    assert "event:later_slot_access" in retained["missing_fact_kinds"]
    other = assessed(paths_project, "cancel_stale")
    assert not validate(paths_project, store, other)["issues"]
    assert other["protocol_assessment"]["assumptions"][0]["status"] == "unconfirmed"


@pytest.mark.parametrize("value", ["no", "unknown"])
def test_withdrawal_revokes_live_proof_and_reopens_business_facts(paths_project, store, value):
    issue = assessed(paths_project)
    assumption = issue["protocol_assessment"]["assumptions"][0]
    answer(store, assumption)
    validate(paths_project, store, issue)
    old = deepcopy(issue)
    answer(store, assumption, value, "接口约定修订，旧约定不再适用", revision=1)
    assert deterministic_decision_proof(old, outcome="confirm") is None
    assert feedback_reuse_problem(old, store) == "business_feedback_changed"
    state = validate(paths_project, store, issue)
    assert not state["issues"] and state["observations"]
    assert issue["policy_disposition"] == "needs_review"
    assert not issue.get("decision_proof")
    assert "event:business_release_requirement" in issue["missing_fact_kinds"]
    assert not any(
        f.get("provider") == "protocol_business_feedback"
        for f in issue["decision_fact_slice"]["facts"]
    )
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_revision_history_atomic_conflicts_and_idempotent_retry(paths_project, store):
    assumptions = assessed(paths_project, "failure_unreleased")["protocol_assessment"][
        "assumptions"
    ]
    first = answer(store, assumptions[0])
    assert answer(store, assumptions[0]) == first
    with pytest.raises(ProtocolAnswerConflict):
        store.save_protocol_answers(
            [
                {
                    "assumption": assumptions[1],
                    "answer": "yes",
                    "source_note": "new",
                    "expected_revision": 0,
                },
                {
                    "assumption": assumptions[0],
                    "answer": "no",
                    "source_note": "old writer",
                    "expected_revision": 0,
                },
            ]
        )
    assert store.protocol_answer_revisions([assumption_key(assumptions[1])]) == {
        assumption_key(assumptions[1]): 0
    }
    answer(store, assumptions[0], "unknown", "需重新核实", revision=1)
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM protocol_assumption_answers").fetchone()[0] == 2
    assert UserConfigStore(store.workbook.path).protocol_answer_revisions(list(first)) == {
        next(iter(first)): 2
    }


def test_feedback_reuse_is_dependency_scoped_and_old_history_revalidates(paths_project, store):
    from zscope.core.analysis.analyzer import Analyzer
    from zscope.reporting.schema import report_reuse_blockers

    left, right = assessed(paths_project, "cancel_stale"), assessed(paths_project, "other_pool")
    for issue in (left, right):
        answer(store, issue["protocol_assessment"]["assumptions"][0])
        validate(paths_project, store, issue)
    answer(store, left["protocol_assessment"]["assumptions"][0], "no", "允许重复归还", revision=1)
    assert feedback_reuse_problem(left, store) == "business_feedback_changed"
    assert feedback_reuse_problem(right, store) == ""
    report = {"report_views": {"default": {"issues": [left]}}}
    assert "business_feedback_changed" in report_reuse_blockers(report, business_answer_store=store)
    assert "business_feedback_unavailable" in report_reuse_blockers(report)
    state = {"history_loaded": True, "is_code_unchanged": True, "valid_hist_issues": [left, right]}
    from zscope.orchestration.candidates import CandidateLedger

    analyzer = Analyzer.__new__(Analyzer)
    analyzer.user_config = store
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            entry_function="cancel_stale",
            project_root=paths_project[1].parent,
            project_id="protocol-test",
        )
    )
    state["candidate_ledger"] = CandidateLedger(project_root=str(paths_project[1].parent))
    Analyzer._reconcile_changed_issues(analyzer, state)
    assert state["verified_hist_issues"] == [right]
    assert len(state["pending_new_issues"]) == 1
    assert state["pending_new_issues"][0]["candidate_disposition"] == "needs_review"
    reopened = state["pending_new_issues"][0]
    runner = _runner(None, enabled=False, code_index=paths_project[0])
    runner.validation_pipeline = ValidationPipeline(store)
    runner.get_contract_registry = lambda: paths_project[2]
    validation_state = {**_state(reopened), "candidate_ledger": state["candidate_ledger"]}
    runner.run(validation_state)
    records = state["candidate_ledger"].lifecycle_snapshot()["records"]
    assert records and all(r["candidate_disposition"] == "needs_review" for r in records)


def test_web_acceptance_only_writes_server_owned_assumptions(
    paths_project, store, tmp_path, monkeypatch
):
    from zscope.web.review_reports import ReportReviewService
    from zscope.web.services import ReportFeedbackService

    issue = assessed(paths_project)
    validate(paths_project, store, issue)
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps(
            {
                "observations": [issue],
                "report_views": {
                    "default": {"issues": []},
                    "with_needs_review": {"issues": [issue]},
                },
            }
        ),
        encoding="utf-8",
    )
    original = path.read_bytes()
    service = ReportReviewService(ReportFeedbackService(store, report_filename=str(path)))
    _, _, catalog, _, _ = service.catalog()
    key = next(iter(catalog))
    review = service.issue_report(key)["business_review"]
    q = review["questions"][0]
    payload = {k: review[k] for k in ("report_id", "issue_id", "base_revision")}
    payload["answers"] = [
        {"id": q["id"], "answer": "yes", "source_note": "接口规范", "expected_revision": 0}
    ]
    result = service.save_business_review(payload)
    assert result["revalidation_required"]
    assert result["business_review"]["questions"][0]["expected_revision"] == 1
    assert path.read_bytes() == original
    assert not store.get_finding_baseline(issue["dedup_key"])
    bad = deepcopy(payload)
    bad["answers"][0]["scope"] = {"entry_usr": "another-entry"}
    with pytest.raises(ValueError):
        service.save_business_review(bad)
    bad = deepcopy(payload)
    bad["answers"][0]["id"] = "foreign-assumption"
    with pytest.raises(ValueError):
        service.save_business_review(bad)
    bad = deepcopy(payload)
    bad["answers"][0].update(answer="no", source_note="过期页面")
    with pytest.raises(ProtocolAnswerConflict):
        service.save_business_review(bad)
    from io import BytesIO
    from zscope.web import server

    monkeypatch.setattr(server, "_report_feedback_service", service.feedback)
    handler = object.__new__(server.ZScopeHandler)
    handler.path = "/api/business_review"
    encoded = json.dumps(bad).encode("utf-8")
    handler.headers = {"Content-Length": str(len(encoded))}
    handler.rfile = BytesIO(encoded)
    sent = []
    handler._send_json = lambda value, status=200: sent.append((status, value))
    handler.do_POST()
    assert sent[0][0] == 409
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    "change", ["empty_source", "invalid_answer", "boolean_revision", "duplicate"]
)
def test_invalid_answer_batches_do_not_write(paths_project, store, change):
    a = assessed(paths_project)["protocol_assessment"]["assumptions"][0]
    update = {"assumption": a, "answer": "yes", "source_note": "spec", "expected_revision": 0}
    if change == "empty_source":
        update["source_note"] = "  "
    elif change == "invalid_answer":
        update["answer"] = ["yes"]
    elif change == "boolean_revision":
        update["expected_revision"] = False
    batch = [update, update] if change == "duplicate" else [update]
    with pytest.raises(ValueError):
        store.save_protocol_answers(batch)
    assert store.protocol_answer_revisions([assumption_key(a)]) == {assumption_key(a): 0}


@pytest.mark.parametrize("value,confirmed", [("yes", True), ("no", False)])
def test_feedback_changed_while_model_runs_is_rechecked(paths_project, store, value, confirmed):
    from zscope.framework.base import AgentResponse

    issue = assessed(paths_project, "failure_unreleased")
    first, endpoint = issue["protocol_assessment"]["assumptions"]
    answer(store, first)

    class Agent:
        def run(self, data):
            answer(store, endpoint, value)
            return AgentResponse(
                success=True, data={"verdict": "verified", "confidence_score": 1.0}
            )

    runner = _runner(Agent(), code_index=paths_project[0])
    runner.get_contract_registry = lambda: paths_project[2]
    runner.validation_pipeline = ValidationPipeline(store)
    state = _state(issue)
    runner.run(state)
    assert bool(state["issues"]) == confirmed
    if not confirmed:
        assert "business_premise_denied" in issue["protocol_assessment"]["technical_gaps"]
        assert "event:responsibility_endpoint" in issue["missing_fact_kinds"]
