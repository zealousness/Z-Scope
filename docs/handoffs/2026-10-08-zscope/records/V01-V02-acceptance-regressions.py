"""Independent acceptance checks, 2026-10-09. Expected invariants, not xfails.

Run explicitly with pytest. Kept in records so failed acceptance evidence does
not silently alter the repository's normal test suite. No vulnerable C is run.
"""

import dataclasses
import json
import runpy
from pathlib import Path

import pytest

from zscope.core.validation import dynamic_reproduction as d
from zscope.core.validation.proofs import deterministic_decision_proof


ROOT = Path(__file__).resolve().parents[4]
H = runpy.run_path(str(ROOT / "tests/test_dynamic_reproduction.py"))


@pytest.fixture(autouse=True)
def clear_authority():
    d.witness_authority_clear()
    yield
    d.witness_authority_clear()


def qualified_issue():
    issue = H["_issue"]()
    plan, record, replay = H["_record_and_replay"](issue)
    outcome = d.register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=H["_policy"]()
    )
    assert outcome.proof_attached
    return issue, plan, record, replay


def test_wrong_named_object_at_same_site_is_not_a_match():
    binding = d.bind_candidate(H["_issue"](resource_identity="other_buffer"))
    finding = dataclasses.replace(H["_finding"](), object_ref="actual_buffer")
    ok, facts, _ = d.match_witness_to_candidate(binding, finding)
    assert not ok and not facts["candidate_object_matched"]


@pytest.mark.parametrize("key,value", [
    ("resource_identity", "other_buffer"),
    ("location", "other.c:200"),
    ("defect_class", "double_free"),
    ("build_configuration", "another-build"),
    ("toolchain_id", "another-toolchain"),
])
def test_registration_rechecks_entire_candidate_binding(key, value):
    issue = H["_issue"]()
    plan, record, replay = H["_record_and_replay"](issue)
    issue[key] = value
    try:
        outcome = d.register_dynamic_reproduction(
            issue, plan=plan, record=record, replay=replay, policy=H["_policy"]()
        )
    except d.DynamicReproductionError:
        return
    assert not outcome.proof_attached


@pytest.mark.parametrize("key,value", [
    ("project_id", "other-project"),
    ("source_revision", "new-source"),
    ("dependency_code_hash", "new-source-hash"),
    ("resource_identity", "other_buffer"),
    ("location", "other.c:200"),
    ("defect_class", "double_free"),
    ("build_configuration", "another-build"),
    ("toolchain_id", "another-toolchain"),
])
def test_adjudication_rejects_changed_current_identity(key, value):
    issue, _, _, _ = qualified_issue()
    issue[key] = value
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_serialized_issue_has_no_authority_even_in_same_process():
    issue, _, _, _ = qualified_issue()
    reloaded = json.loads(json.dumps(issue))
    assert deterministic_decision_proof(reloaded, outcome="confirm") is None


def test_fake_provider_cannot_mint_production_confirmation():
    issue = H["_issue"]()
    plan, record, replay = H["_record_and_replay"](issue)
    d.register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=H["_policy"]()
    )
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_serialized_replay_claim_requires_live_execution_receipt():
    issue = H["_issue"]()
    plan = H["_plan"](issue)
    record = d.FakeDynamicReproductionRunner([H["_witness_run"]()]).execute(plan)
    # No independent execution is performed. This is just deserialized data.
    replay = d.ReplayEvidence(
        plan_digest=plan.digest(), binary_digest=record.binary_digest,
        classifications=record.replay_classifications,
        provider_name="not-executed", provider_version="not-executed",
    )
    outcome = d.register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=H["_policy"]()
    )
    assert not outcome.proof_attached


def test_mixed_independent_replay_cannot_be_collapsed_to_success():
    issue = H["_issue"]()
    plan, record, _ = H["_record_and_replay"](issue)
    mixed = H["_witness_run"](
        outcome="inconclusive", classifications=("heap-buffer-overflow", "none")
    )
    replay = d.replay_witness(plan, d.FakeDynamicReproductionRunner([mixed]), times=2)
    outcome = d.register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=H["_policy"]()
    )
    assert not outcome.proof_attached


def test_independent_replay_for_other_site_cannot_confirm():
    issue = H["_issue"]()
    plan, record, _ = H["_record_and_replay"](issue)
    other = H["_witness_run"](findings=(H["_finding"](site="other.c:400"),))
    replay = d.replay_witness(plan, d.FakeDynamicReproductionRunner([other]), times=2)
    outcome = d.register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=H["_policy"]()
    )
    assert not outcome.proof_attached


def test_clean_execution_cannot_be_given_unqualified_positive_proof(tmp_path):
    issue = H["_issue"]()
    plan = H["_plan"](
        issue, provider_kind="asan", provider_name="asan-runner",
        binary_digest=d.hash_file("/bin/true")[0], run_cwd=str(tmp_path), max_replays=1,
    )
    record = d.SanitizerReproductionRunner("asan", policy=H["_policy"]()).execute(plan)
    assert record.outcome == "not_reproduced"
    # The public helper bypasses qualification. The selector must independently
    # reject a live token whose execution never yielded a matched witness.
    issue["deterministic_proofs"] = [
        d.dynamic_witness_proof_record(plan.binding, plan, record, H["_finding"]())
    ]
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_unavailable_requested_isolation_prevents_launch(tmp_path, monkeypatch):
    plan = dataclasses.replace(
        H["_process_plan"](tmp_path, "true"), isolation="user_net_namespace"
    )
    runner = d.SanitizerReproductionRunner("asan", policy=H["_policy"]())
    monkeypatch.setattr(runner, "_namespace_wrap", lambda argv: (tuple(argv), False, ["unavailable"]))
    calls = []
    def run(**kwargs):
        calls.append(kwargs)
        return d._RunResult(0, "", b"", "", b"", False)
    monkeypatch.setattr(runner, "_run_once", run)
    runner.execute(plan)
    assert calls == []


@pytest.mark.parametrize("changed", ["harness", "input", "executable"])
def test_runner_checks_actual_inputs_before_launch(tmp_path, monkeypatch, changed):
    harness = tmp_path / "harness.c"
    harness.write_text("int main(void){return 0;}\n")
    input_file = tmp_path / "input.txt"
    input_file.write_text("old-input")
    plan = H["_plan"](
        H["_issue"](), provider_kind="asan", provider_name="asan-runner",
        binary_digest=d.hash_file("/bin/true")[0], run_cwd=str(tmp_path), max_replays=1,
        harness_ref=str(harness), harness_digest=d.hash_file(harness)[0],
        input_refs=(str(input_file),), input_digests=(d.hash_file(input_file)[0],),
    )
    if changed == "harness":
        harness.write_text("changed source\n")
    elif changed == "input":
        input_file.write_text("new-input")
    else:
        # The declared binary remains /bin/true while the command is different.
        plan = dataclasses.replace(plan, run_argv=("/bin/false",))
    runner = d.SanitizerReproductionRunner("asan", policy=H["_policy"]())
    calls = []
    def run(**kwargs):
        calls.append(kwargs)
        return d._RunResult(0, "", b"", "", b"", False)
    monkeypatch.setattr(runner, "_run_once", run)
    runner.execute(plan)
    assert calls == []


def test_disabled_runner_never_launches(tmp_path, monkeypatch):
    plan = H["_process_plan"](tmp_path, "true")
    runner = d.SanitizerReproductionRunner("asan")
    calls = []
    def run(**kwargs):
        calls.append(kwargs)
        return d._RunResult(0, "", b"", "", b"", False)
    monkeypatch.setattr(runner, "_run_once", run)
    try:
        runner.execute(plan)
    except d.DynamicReproductionError:
        pass
    assert calls == []
