"""ValidationRunner runs inside its exact scoped build context.

The runner is real in every test; only its collaborators (validator agent,
pipeline user config, code index) are the same controlled fakes the existing
runner tests use.  Coverage: executor and shared-scheduler workers bind and
finally release the precise build context under concurrent BASE/ALT runs,
errors and cancellation restore the worker context, unscoped runs clear any
leftover binding instead of inheriting another variant, incoming candidates
with a conflicting (or missing) build identity are never validated under a
borrowed scope label, and the validator cache environment separates scopes.
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_validation_runner import (
    FakeCodeIndex,
    FakeSnapshotStore,
    FakeUserConfig,
    _issue,
    _state,
    _validator_v3_result,
)
from zscope.framework.base import AgentResponse
from zscope.common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.runner import ValidationRunner
from zscope.orchestration.scheduler import VALIDATOR_ROLE, ScanScheduler
from zscope.retrieval.instance_index import InstanceScope
from zscope.semantics.build_scope import bind_build_scope, current_build_id


class ScopeRecordingAgent:
    """Real-shaped validator agent that records the bound build at call time."""

    def __init__(
        self,
        *,
        delay: float = 0.0,
        raise_on: set[str] | None = None,
        gate: threading.Event | None = None,
    ):
        self.builds: list[str] = []
        self.delay = delay
        self.raise_on = raise_on or set()
        self.gate = gate
        self.started = threading.Event()

    def run(self, input_data):
        self.started.set()
        if self.gate is not None:
            self.gate.wait(timeout=10)
        token = current_cancellation_token()
        if token is not None:
            token.raise_if_cancelled()
        if self.delay:
            threading.Event().wait(self.delay)
        self.builds.append(current_build_id())
        issue_id = str((input_data or {}).get("issue_id") or (input_data or {}).get("id") or "")
        if issue_id in self.raise_on:
            raise RuntimeError(f"controlled failure for {issue_id}")
        return AgentResponse(success=True, data=_validator_v3_result())


class ScopedFakeCodeIndex(FakeCodeIndex):
    def __init__(self, build: str, usr: str = "c:@F@api_entry"):
        super().__init__()
        self.scope = InstanceScope(
            build_context_id=build,
            usr=usr,
            identity=f"{build}:{usr}",
            source="unit.c",
            function_names=("api_entry",),
        )


def _make_runner(agent, *, build: str | None, scheduler=None, validator_workers: 2 | int = 2):
    code_index = ScopedFakeCodeIndex(build) if build else FakeCodeIndex()
    config = SimpleNamespace(
        analysis=None,
        scan=None,
        concurrency=SimpleNamespace(
            validator_workers=validator_workers, evidence_completion_workers=1
        ),
        project=SimpleNamespace(
            agents=[SimpleNamespace(name="validator_agent", enabled=True, llm_ref="default")]
        ),
    )
    return ValidationRunner(
        config=config,
        llm_clients={"default": object()},
        validation_pipeline=ValidationPipeline(FakeUserConfig()),
        code_index=code_index,
        snapshot_store=FakeSnapshotStore(),
        get_tools=lambda agent_name: [],
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=lambda context, agent_name: context.update(
            {"agent_contract": agent_name}
        ),
        remember_validation_result=lambda issue, status: None,
        validator_agent_factory=lambda *args, **kwargs: agent,
        scheduler=scheduler,
    )


def _issues(count: int, prefix: str, build: str = "") -> list[dict]:
    issues = [
        _issue(
            id=f"{prefix}{index}",
            candidate_uid=f"CAND_{prefix}{index}",
            validation_cluster_uid=f"VAL_{prefix}{index}",
        )
        for index in range(count)
    ]
    if build:
        # Candidates carry their variant's compilation receipt on both the
        # issue and the evidence pack, as the scoped analyzers stamp them.
        for issue in issues:
            issue["build_context_id"] = build
            issue["evidence_pack"]["build_context_id"] = build
    return issues


def _stamped(issue: dict, build: str) -> dict:
    issue["build_context_id"] = build
    issue.setdefault("evidence_pack", {})["build_context_id"] = build
    return issue


def _multi_state(issues: list[dict]) -> dict:
    state = _state(issues[0])
    state["pending_new_issues"] = list(issues)
    return state


def _probe_scheduler(scheduler: ScanScheduler) -> str:
    """Run one task on the shared scheduler workers and read its scope."""

    from concurrent.futures import Future

    future: Future[str] = scheduler.submit(VALIDATOR_ROLE, current_build_id)
    return future.result(timeout=15)


# --- binding coverage ---------------------------------------------------------------


def test_run_binds_the_scoped_build_for_validator_and_review(monkeypatch):
    agent = ScopeRecordingAgent()
    runner = _make_runner(agent, build="BASE")
    records: list[tuple[str, str]] = []

    class RecordingChecker:
        def prepare(self, issue):
            records.append(("checker_prepare", current_build_id()))

        def check(self, issue):
            records.append(("checker_check", current_build_id()))

    monkeypatch.setattr(runner, "_review_enabled", lambda: True)
    monkeypatch.setattr(runner, "_review_facts_enabled", lambda: True)
    monkeypatch.setattr(runner, "_review_checker", lambda: RecordingChecker())
    monkeypatch.setattr(
        runner,
        "_review_checkpoint",
        lambda issue, phase: records.append((f"checkpoint:{phase}", current_build_id())),
    )
    monkeypatch.setattr(
        runner,
        "_validate_related_candidates",
        lambda state, issues: records.append(("related_candidates", current_build_id())),
    )

    runner.run(_state(_stamped(_issue(), "BASE")))

    assert set(agent.builds) == {"BASE"}
    phases = {phase for phase, _ in records}
    # (checker.check is gated by the checked-proofs switch, off by default.)
    assert {
        "checker_prepare",
        "checkpoint:prepared",
        "related_candidates",
        "checkpoint:final_disposition",
    } <= phases
    assert {build for _, build in records} == {"BASE"}


def test_executor_workers_bind_the_scoped_build():
    agent = ScopeRecordingAgent()
    runner = _make_runner(agent, build="BASE", validator_workers=3)

    runner.run(_multi_state(_issues(6, "E", "BASE")))

    assert len(agent.builds) == 6
    assert set(agent.builds) == {"BASE"}


def test_unscoped_run_clears_a_leftover_caller_binding():
    agent = ScopeRecordingAgent()
    runner = _make_runner(agent, build=None)

    with bind_build_scope({"build_context_id": "ALT-LEFTOVER"}):
        runner.run(_state(_issue()))

    assert set(agent.builds) == {""}


# --- shared scheduler: concurrent BASE/ALT and context release ----------------------


def test_shared_scheduler_runs_base_and_alt_concurrently_without_cross_binding():
    scheduler = ScanScheduler(entry_workers=1, validator_workers=2, investigator_workers=1)
    try:
        base_agent = ScopeRecordingAgent(delay=0.01)
        alt_agent = ScopeRecordingAgent(delay=0.01)
        base = _make_runner(base_agent, build="BASE", scheduler=scheduler, validator_workers=4)
        alt = _make_runner(alt_agent, build="ALT", scheduler=scheduler, validator_workers=4)
        errors: list[BaseException] = []

        def drive(runner, issues):
            try:
                runner.run(_multi_state(issues))
            except BaseException as exc:  # surfaced below; never silently lost
                errors.append(exc)

        first = threading.Thread(target=drive, args=(base, _issues(8, "B", "BASE")))
        second = threading.Thread(target=drive, args=(alt, _issues(8, "A", "ALT")))
        first.start()
        second.start()
        first.join(timeout=120)
        second.join(timeout=120)
        assert not errors
        assert len(base_agent.builds) == 8 and set(base_agent.builds) == {"BASE"}
        assert len(alt_agent.builds) == 8 and set(alt_agent.builds) == {"ALT"}
        # The same long-lived worker threads must not keep either binding.
        assert _probe_scheduler(scheduler) == ""
    finally:
        scheduler.shutdown()


def test_worker_error_restores_the_scheduler_context():
    scheduler = ScanScheduler(entry_workers=1, validator_workers=1, investigator_workers=1)
    try:
        agent = ScopeRecordingAgent(raise_on={"BOOM0"})
        runner = _make_runner(agent, build="BASE", scheduler=scheduler, validator_workers=2)
        issues = _issues(4, "BOOM", "BASE")

        runner.run(_multi_state(issues))

        # The crashing issue records its error result; the rest still validate.
        assert "BASE" in agent.builds and len(agent.builds) >= 3
        assert _probe_scheduler(scheduler) == ""
    finally:
        scheduler.shutdown()


def test_cancellation_restores_the_scheduler_context():
    scheduler = ScanScheduler(entry_workers=1, validator_workers=1, investigator_workers=1)
    gate = threading.Event()
    try:
        agent = ScopeRecordingAgent(gate=gate)
        runner = _make_runner(agent, build="BASE", scheduler=scheduler, validator_workers=2)
        token = CancellationToken()
        failures: list[BaseException] = []

        def drive():
            try:
                with bind_cancellation_token(token):
                    runner.run(_multi_state(_issues(4, "C", "BASE")))
            except CancellationError as exc:
                failures.append(exc)

        worker = threading.Thread(target=drive)
        worker.start()
        assert agent.started.wait(timeout=15)
        token.cancel("test_cancelled")
        gate.set()
        worker.join(timeout=60)
        assert not worker.is_alive()
        assert failures and isinstance(failures[0], CancellationError)
        assert _probe_scheduler(scheduler) == ""
    finally:
        gate.set()
        scheduler.shutdown()


# --- incoming candidate build identity ----------------------------------------------


def test_candidate_with_a_foreign_build_is_routed_to_review_not_validated():
    agent = ScopeRecordingAgent()
    runner = _make_runner(agent, build="BASE")
    issue = _issue(
        id="ISSUE_FOREIGN",
        candidate_uid="CAND_FOREIGN",
        validation_cluster_uid="VAL_FOREIGN",
        build_context_id="ALT-9",
    )

    state = _state(issue)
    runner.run(state)

    assert agent.builds == []
    assert issue["build_scope_rejection"]["code"] == "candidate_build_mismatch"
    assert issue["build_scope_rejection"]["candidate_build_context_id"] == "ALT-9"
    assert issue["build_scope_rejection"]["scoped_build_context_id"] == "BASE"
    assert issue.get("validation_status") != "validated"
    # The scoped build was never stamped onto the foreign candidate.
    assert issue["build_context_id"] == "ALT-9"


def test_candidate_with_self_conflicting_build_fields_is_rejected():
    agent = ScopeRecordingAgent()
    runner = _make_runner(agent, build="BASE")
    issue = _issue(
        id="ISSUE_CONFLICT",
        candidate_uid="CAND_CONFLICT",
        validation_cluster_uid="VAL_CONFLICT",
        build_context_id="BASE",
    )
    issue["evidence_pack"]["build_context_id"] = "ALT-9"

    state = _state(issue)
    runner.run(state)

    assert agent.builds == []
    assert issue["build_scope_rejection"]["code"] == "candidate_build_conflict"
    assert issue["build_scope_rejection"]["carried_build_context_ids"] == ["ALT-9", "BASE"]
    assert issue.get("validation_status") != "validated"


def test_candidate_without_build_identity_is_routed_to_review_not_validated():
    agent = ScopeRecordingAgent()
    runner = _make_runner(agent, build="BASE")
    issue = _issue(id="ISSUE_PLAIN", candidate_uid="CAND_PLAIN", validation_cluster_uid="VAL_PLAIN")

    state = _state(issue)
    runner.run(state)

    # Unknown is not authorization: the identity-less candidate never runs
    # this variant's Validator and never receives a manufactured build label.
    assert agent.builds == []
    assert issue["build_scope_rejection"]["code"] == "candidate_build_missing"
    assert not issue.get("build_context_id")
    assert issue.get("validation_status") != "validated"
    assert any("no build identity" in note for note in state["notes"])


def test_unscoped_runner_validates_candidates_of_any_build():
    agent = ScopeRecordingAgent()
    runner = _make_runner(agent, build=None)
    issue = _issue(
        id="ISSUE_ANY",
        candidate_uid="CAND_ANY",
        validation_cluster_uid="VAL_ANY",
        build_context_id="ALT-9",
    )

    runner.run(_state(issue))

    assert set(agent.builds) == {""}


# --- cache isolation ----------------------------------------------------------------


def test_cache_environment_separates_runner_scopes():
    base = _make_runner(ScopeRecordingAgent(), build="BASE")
    alt = _make_runner(ScopeRecordingAgent(), build="ALT")
    unscoped = _make_runner(ScopeRecordingAgent(), build=None)

    assert base._validation_environment_fingerprint != alt._validation_environment_fingerprint
    assert base._validation_environment_fingerprint != unscoped._validation_environment_fingerprint
    assert alt._validation_environment_fingerprint != unscoped._validation_environment_fingerprint


def test_validator_cache_never_reuses_a_result_across_scopes():
    shared_cache_agent_calls: list[str] = []
    from zscope.core.validation.runner import ValidationResultCache

    cache = ValidationResultCache(64)
    issues = _issues(1, "S", "SHARED")

    first_agent = ScopeRecordingAgent()
    second_agent = ScopeRecordingAgent()
    first = _make_runner(first_agent, build="BASE", validator_workers=1)
    second = _make_runner(second_agent, build="ALT", validator_workers=1)
    first._validator_result_cache = cache
    second._validator_result_cache = cache

    first.run(_state(_stamped(dict(issues[0]), "BASE")))
    second.run(_state(_stamped(dict(issues[0]), "ALT")))

    shared_cache_agent_calls.extend(first_agent.builds + second_agent.builds)
    # Same candidate content, different scope: the second run cannot reuse the
    # first run's verdict, so both validators actually ran.
    assert len(shared_cache_agent_calls) == 2
    assert shared_cache_agent_calls == ["BASE", "ALT"]
