"""Deterministic acceptance tests for the V01 dynamic-reproduction boundary.

Everything here runs without a sanitizer toolchain. Real ASAN/TSAN execution
lives in ``tests/test_dynamic_reproduction_execution.py`` so the heavy lane
stays a single, explicitly invoked run.

Covered requirements: wrong identity/version, forged logs, stale binary,
timeout, OOM, build failure, cancellation and shutdown, result replay, and
default-off compatibility. See
``docs/handoffs/2026-10-08-zscope/records/V01-dynamic-reproduction.md``.
"""

from __future__ import annotations

import os
import signal
import hashlib
import dataclasses
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from zscope.common.cancellation import CancellationToken, bind_cancellation_token
from zscope.common.validator_protocol import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
)
from zscope.config.config import AnalysisConfig
from zscope.core.validation import dynamic_reproduction as d
from zscope.core.validation.dynamic_reproduction import (
    DYNAMIC_WITNESS_PROOF_KIND,
    EXECUTION_AUTHORITY,
    WITNESS_AUTHORITY,
    BuildSpec,
    CandidateBinding,
    CancellationError,
    DynamicReproductionError,
    DynamicReproductionPolicy,
    ExecutionPlan,
    ExecutionRecord,
    FakeDynamicReproductionRunner,
    FakeRun,
    ReplayEvidence,
    RunEvidence,
    SanitizerFinding,
    SanitizerReproductionRunner,
    _RunResult,
    attempt_dynamic_reproduction,
    bind_candidate,
    build_execution_plan,
    dynamic_reproduction_plan_provider,
    dynamic_witness_proof_is_live,
    families_match,
    inject_test_execution_authority,
    is_shadow_candidate,
    make_dynamic_reproduction_policy,
    match_witness_to_candidate,
    parse_asan_report,
    parse_sanitizer_report,
    parse_tsan_report,
    qualify_witness,
    register_dynamic_reproduction,
    register_dynamic_reproduction_plan_provider,
    release_issue_dynamic_reproduction_authority,
    replay_witness,
    witness_authority_clear,
)
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.proofs import deterministic_decision_proof

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "dynamic_reproduction"
REPO_ROOT = Path(__file__).resolve().parents[1]
POSITIVE_SOURCE_PATH = FIXTURE_DIR / "heap_overflow_positive.c"
POSITIVE_SOURCE = "tests/fixtures/dynamic_reproduction/heap_overflow_positive.c"
NEGATIVE_SOURCE = "tests/fixtures/dynamic_reproduction/heap_overflow_negative.c"
UNRELATED_SOURCE = "tests/fixtures/dynamic_reproduction/unrelated_crash.c"
RACE_SOURCE = "tests/fixtures/dynamic_reproduction/data_race_positive.c"
BINARY_DIGEST = "a" * 64
HARNESS_DIGEST = "b" * 64
# Explicitly authorized execution roots for test plans: the fixture sources, the
# test-owned input directories, the system binaries the tests execute, and the
# temporary directories the runner owns. An empty authorization set means
# "nothing is authorized", so test plans must declare what they may touch.
DEFAULT_EXEC_ROOTS = (
    str(FIXTURE_DIR),
    str(REPO_ROOT / "tests"),
    "/bin",
    "/usr/bin",
    tempfile.gettempdir(),
)


def _sha256_file(path: Path | str) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _marker_line(name: str, marker: str = "ZSCOPE_CANDIDATE_SITE") -> int:
    for index, line in enumerate(
        (FIXTURE_DIR / name).read_text(encoding="utf-8").splitlines(), start=1
    ):
        if marker in line:
            return index
    raise AssertionError(f"marker {marker} missing from {name}")


def _site(source: str = POSITIVE_SOURCE, name: str = "heap_overflow_positive.c") -> str:
    return f"{source}:{_marker_line(name)}"


def _finding(
    *,
    kind: str = "heap-buffer-overflow",
    site: str | None = None,
    frames: tuple[str, ...] | None = None,
) -> SanitizerFinding:
    resolved = site or _site()
    return SanitizerFinding(
        kind=kind,
        access="write",
        frames=frames or (f"zscope_dynamic_repro_positive {resolved}", f"main {resolved}"),
        allocation_frames=(),
        object_ref="0x6020000000f0",
        site=resolved,
        source_mapping=(resolved,),
        raw_digest="c" * 64,
    )


def _issue(**overrides: object) -> dict[str, object]:
    issue: dict[str, object] = {
        "id": "DYNREPRO_1",
        "candidate_uid": "cand-1",
        "validation_cluster_uid": "cluster-1",
        "project_id": "proj-1",
        "source_revision": "rev-abc",
        "dependency_code_hash": "rev-abc",
        "defect_class": "heap_buffer_overflow",
        "location": _site(),
        "function": "zscope_dynamic_repro_positive",
        "resource_identity": "zscope_dynamic_repro_positive",
    }
    issue.update(overrides)
    return issue


def _policy(**overrides: object) -> DynamicReproductionPolicy:
    values: dict[str, object] = {"enabled": True}
    values.update(overrides)
    return DynamicReproductionPolicy(**values)  # type: ignore[arg-type]


def _plan(
    issue: dict[str, object],
    *,
    provider_kind: str = "fake",
    provider_name: str = "fake-fake-runner",
    binary_digest: str = BINARY_DIGEST,
    harness_digest: str = "",
    max_replays: int = 2,
    **overrides: object,
) -> ExecutionPlan:
    binding = bind_candidate(issue)
    values: dict[str, object] = {
        "provider_kind": provider_kind,
        "provider_name": provider_name,
        "provider_version": "1",
        "run_argv": ("/bin/true",),
        "run_cwd": str(FIXTURE_DIR),
        "harness_ref": str(POSITIVE_SOURCE_PATH),
        "harness_digest": harness_digest or _sha256_file(POSITIVE_SOURCE_PATH),
        "binary_path": "/bin/true",
        "binary_digest": binary_digest,
        "toolchain_id": "test-toolchain",
        "build_configuration": "test-build",
        "input_refs": (),
        "input_digests": (),
        "env_allowlist": {"PATH": "/usr/bin:/bin"},
        "timeout_seconds": 10,
        "memory_limit_mb": 256,
        "max_replays": max_replays,
        "allowed_exec_roots": DEFAULT_EXEC_ROOTS,
    }
    values.update(overrides)
    return build_execution_plan(binding, **values)  # type: ignore[arg-type]


def _witness_run(**overrides: object) -> FakeRun:
    values: dict[str, object] = {
        "outcome": "witness_observed",
        "findings": (_finding(),),
        "classifications": ("heap-buffer-overflow", "heap-buffer-overflow"),
    }
    values.update(overrides)
    return FakeRun(**values)  # type: ignore[arg-type]


def _record_and_replay(
    issue: dict[str, object],
    *,
    plan: ExecutionPlan | None = None,
    runs: list[FakeRun] | None = None,
) -> tuple[ExecutionPlan, ExecutionRecord, object]:
    resolved_plan = plan or _plan(issue)
    script = runs or [_witness_run()]
    runner = FakeDynamicReproductionRunner(script)
    record = runner.execute(resolved_plan)
    replay = replay_witness(
        resolved_plan,
        FakeDynamicReproductionRunner(script),
        times=max(2, len(script)),
    )
    return resolved_plan, record, replay


def _promote_production(record: ExecutionRecord, replay: object) -> None:
    """Promote a fake execution *and* each of its replays to production trust.

    Confirmation now requires every execution to have been production-trusted
    with verified inputs, so a positive control that only promotes the primary
    execution would (correctly) no longer confirm. This helper reproduces the
    reviewer's independent positive control.
    """

    inject_test_execution_authority(record.attestation, reason="deterministic-suite")
    for run in getattr(replay, "runs", ()):  # pragma: no branch - simple loop
        inject_test_execution_authority(run.execution_token, reason="deterministic-suite")


# --------------------------------------------------------------------------
# Default-off compatibility and configuration gating
# --------------------------------------------------------------------------


def test_default_policy_is_disabled_and_never_touches_the_issue() -> None:
    issue = _issue()
    before = dict(issue)
    plan, record, replay = _record_and_replay(issue)

    with pytest.raises(DynamicReproductionError):
        register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay)

    assert issue == before
    assert DynamicReproductionPolicy().enabled is False
    assert DynamicReproductionPolicy().attach_proof is True


def test_config_mode_resolves_to_off_shadow_and_on() -> None:
    off = make_dynamic_reproduction_policy(AnalysisConfig())
    assert off.enabled is False and off.attach_proof is False

    shadow = make_dynamic_reproduction_policy(AnalysisConfig(dynamic_reproduction_mode="shadow"))
    assert shadow.enabled is True and shadow.attach_proof is False

    active = make_dynamic_reproduction_policy(AnalysisConfig(dynamic_reproduction_mode="on"))
    assert active.enabled is True and active.attach_proof is True

    # Unknown/missing values fail closed instead of guessing.
    unknown = make_dynamic_reproduction_policy(object())
    assert unknown.enabled is False


@pytest.mark.parametrize(
    "value",
    ["bogus", "ON", "", "active"],
)
def test_config_rejects_unknown_reproduction_modes(value: str) -> None:
    with pytest.raises(ValueError):
        AnalysisConfig(dynamic_reproduction_mode=value)


def test_config_rejects_inconsistent_replay_budget() -> None:
    with pytest.raises(ValueError):
        AnalysisConfig(
            dynamic_reproduction_required_replays=4,
            dynamic_reproduction_max_replays=2,
        )
    with pytest.raises(ValueError):
        AnalysisConfig(dynamic_reproduction_isolation="container")


def test_runtime_defaults_ship_the_feature_off() -> None:
    config = AnalysisConfig()
    assert config.dynamic_reproduction_mode == "off"
    assert config.dynamic_reproduction_required_replays == 2


# --------------------------------------------------------------------------
# Plan/record identity binding
# --------------------------------------------------------------------------


def test_plan_digest_binds_every_reproducible_identity() -> None:
    issue = _issue()
    baseline = _plan(issue)

    assert baseline.digest() == _plan(issue).digest()
    assert _plan(issue, binary_digest="e" * 64).digest() != baseline.digest()
    assert _plan(issue, harness_digest="f" * 64).digest() != baseline.digest()
    assert _plan(issue, toolchain_id="other").digest() != baseline.digest()
    assert _plan(issue, build_configuration="other").digest() != baseline.digest()
    assert _plan(issue, run_argv=("/bin/false",)).digest() != baseline.digest()
    assert (
        _plan(issue, input_refs=("probe.input",), input_digests=("0" * 64,)).digest()
        != baseline.digest()
    )

    changed_revision = _issue(source_revision="rev-other", dependency_code_hash="rev-other")
    assert _plan(changed_revision).digest() != baseline.digest()

    changed_object = _issue(resource_identity="other_object")
    assert _plan(changed_object).digest() != baseline.digest()

    changed_family = _issue(defect_class="use_after_free")
    assert _plan(changed_family).digest() != baseline.digest()

    changed_site = _issue(
        location=f"{POSITIVE_SOURCE}:{_marker_line('heap_overflow_positive.c') + 1}"
    )
    assert _plan(changed_site).digest() != baseline.digest()


def test_binding_requires_complete_candidate_identity() -> None:
    with pytest.raises(DynamicReproductionError):
        bind_candidate({"id": "x", "project_id": "p"})
    with pytest.raises(DynamicReproductionError):
        CandidateBinding(
            project_id="p",
            source_revision="",
            candidate_uid="c",
            validation_cluster_uid="cl",
            object_identity="o",
            site="s:1",
            defect_family="f",
            build_configuration="b",
            toolchain_id="t",
        )


def test_plan_issue_identity_mismatch_is_refused() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)

    stale = _issue(candidate_uid="cand-2")
    with pytest.raises(DynamicReproductionError):
        register_dynamic_reproduction(
            stale, plan=plan, record=record, replay=replay, policy=_policy()
        )

    stale_revision = _issue(source_revision="rev-old", dependency_code_hash="rev-old")
    with pytest.raises(DynamicReproductionError):
        register_dynamic_reproduction(
            stale_revision, plan=plan, record=record, replay=replay, policy=_policy()
        )


def test_record_for_another_plan_is_never_qualified() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    other_plan = _plan(issue, binary_digest="9" * 64)

    qualification = qualify_witness(
        other_plan.binding, other_plan, record, replay=replay, policy=_policy()
    )
    assert qualification.qualified is False
    assert "plan_record_mismatch" in qualification.reasons


# --------------------------------------------------------------------------
# Qualified witness -> shared adjudication
# --------------------------------------------------------------------------


def test_qualified_witness_attaches_descriptive_proof_without_confirmation() -> None:
    """A test-trusted execution attaches evidence but never a confirmation."""

    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )

    assert outcome.proof_attached is True
    assert outcome.qualification.qualified is True
    assert isinstance(outcome.request, DynamicReproductionRequest)
    assert isinstance(outcome.result, DynamicReproductionResult)
    assert outcome.result.outcome == "reproduced"
    assert issue["dynamic_reproduction_outcome"] == "witness_observed"
    assert issue["dynamic_reproduction_qualified"] is True
    authority = issue["dynamic_reproduction"]["confirmation_authority"]
    assert authority["granted"] is False
    assert authority["reasons"], "a refused confirmation must record why"
    assert "replay_run_not_production_trusted" in authority["reasons"]

    attached = issue["deterministic_proofs"][0]
    assert attached["outcome"] == "inconclusive"
    assert attached["completeness"] == "incomplete"
    assert attached["facts"] == []
    assert attached["proof_kind"] == DYNAMIC_WITNESS_PROOF_KIND
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_injected_test_authority_confirms_through_unified_adjudication() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    # Every execution must be production-trusted: a production primary execution
    # combined with test-trusted replays is refused (see
    # test_untrusted_fake_replays_cannot_complete_production_confirmation).
    _promote_production(record, replay)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )

    assert outcome.proof_attached is True
    assert outcome.qualification.qualified is True
    assert issue["dynamic_reproduction"]["confirmation_authority"]["granted"] is True
    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == DYNAMIC_WITNESS_PROOF_KIND
    assert proof.producer_engine.startswith("dynamic-reproduction:")
    assert proof.code_hash == plan.binding.digest()
    assert deterministic_decision_proof(issue, outcome="reject") is None

    pipeline = ValidationPipeline(None)
    decision = pipeline.apply_deterministic_prevalidation(issue, {"final_score": 0.2})
    assert decision is not None
    assert decision.report_bucket == "issues"
    assert issue["candidate_disposition"] == "confirmed"
    assert issue["promotion_reason"] == "deterministic_prevalidation_proof"


def test_test_authority_injection_is_explicit_and_never_in_product_code() -> None:
    with pytest.raises(DynamicReproductionError):
        inject_test_execution_authority("0" * 64, reason="")
    with pytest.raises(DynamicReproductionError):
        inject_test_execution_authority("0" * 64, reason="unknown-token")

    root = Path(__file__).resolve().parents[1] / "zscope"
    defining_module = (
        Path(__file__).resolve().parents[1]
        / "zscope"
        / "core"
        / "validation"
        / "dynamic_reproduction.py"
    )
    offenders = [
        path
        for path in root.rglob("*.py")
        if path != defining_module
        and "inject_test_execution_authority(" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"product code must not inject test authority: {offenders}"


def test_shadow_mode_records_metadata_without_granting_authority() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy(attach_proof=False)
    )

    assert outcome.qualification.qualified is True
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "reproduced"
    assert "shadow_mode_proof_not_attached" in outcome.qualification.reasons
    assert "deterministic_proofs" not in issue
    assert issue["dynamic_reproduction"]["proof_attached"] is False
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_shadow_candidate_never_receives_confirmation_authority() -> None:
    shadow_issue = _issue(
        rollout_visibility="shadow",
        candidate_source="active_discovery",
        attribution={
            "schema_version": "zscope.finding-attribution.v1",
            "discovered_by": ["llm_active_discovery"],
            "discovery_details": [],
            "decided_by": "unresolved",
            "decision_level": "none",
        },
    )
    plan, record, replay = _record_and_replay(shadow_issue)
    outcome = register_dynamic_reproduction(
        shadow_issue, plan=plan, record=record, replay=replay, policy=_policy()
    )

    assert outcome.proof_attached is False
    assert outcome.qualification.qualified is False
    assert "shadow_candidate_not_confirmable" in outcome.qualification.reasons
    assert "deterministic_proofs" not in shadow_issue

    # A candidate that becomes a shadow occurrence after the fact loses the
    # confirmation: the live proof is re-bound to the *current* identity, and the
    # shadow predicates keep the occurrence out of the default view.
    live_issue = _issue()
    live_plan, live_record, live_replay = _record_and_replay(live_issue)
    _promote_production(live_record, live_replay)
    register_dynamic_reproduction(
        live_issue, plan=live_plan, record=live_record, replay=live_replay, policy=_policy()
    )
    assert deterministic_decision_proof(live_issue, outcome="confirm") is not None

    live_issue["rollout_visibility"] = "shadow"
    live_issue["candidate_source"] = "active_discovery"
    live_issue["attribution"] = {
        "schema_version": "zscope.finding-attribution.v1",
        "discovered_by": ["llm_active_discovery"],
        "discovery_details": [],
        "decided_by": "unresolved",
        "decision_level": "none",
    }
    assert deterministic_decision_proof(live_issue, outcome="confirm") is None
    assert is_shadow_candidate(bind_candidate(live_issue)) is True
    assert ValidationPipeline._is_rollout_shadow_candidate(live_issue) is True
    decision = ValidationPipeline(None).apply_deterministic_prevalidation(
        live_issue, {"final_score": 0.8}
    )
    assert decision is None or decision.report_bucket is None


def test_shadow_predicate_matches_the_validation_pipeline() -> None:
    samples = [
        _issue(),
        _issue(rollout_visibility="shadow"),
        _issue(rollout_visibility="shadow", candidate_source="active_discovery"),
        _issue(
            rollout_visibility="shadow",
            attribution={"discovered_by": ["llm_active_discovery"]},
        ),
        _issue(
            rollout_visibility="shadow",
            attribution={"discovered_by": ["llm_active_discovery", "backend_signal"]},
        ),
        _issue(
            rollout_visibility="shadow",
            candidate_kind="conditional_snapshot_observation",
            candidate_source="semantic_snapshot",
            attribution={"discovered_by": ["semantic_modeling"]},
        ),
        _issue(
            rollout_visibility="shadow",
            candidate_kind="conditional_snapshot_observation",
            candidate_source="semantic_snapshot",
            attribution={"discovered_by": ["semantic_modeling", "deterministic_rule"]},
        ),
    ]
    for sample in samples:
        assert is_shadow_candidate(bind_candidate(sample)) == (
            ValidationPipeline._is_rollout_shadow_candidate(sample)
        )


# --------------------------------------------------------------------------
# Wrong evidence: object / site / family / binary / attestation
# --------------------------------------------------------------------------


def test_wrong_object_and_site_report_is_not_qualified() -> None:
    issue = _issue()
    unrelated_site = (
        f"{UNRELATED_SOURCE}:{_marker_line('unrelated_crash.c', 'ZSCOPE_UNRELATED_SITE')}"
    )
    runs = [
        _witness_run(
            findings=(
                _finding(
                    site=unrelated_site,
                    frames=(f"unrelated_helper {unrelated_site}", f"main {unrelated_site}"),
                ),
            )
        )
    ]
    plan, record, replay = _record_and_replay(issue, runs=runs)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )

    assert outcome.proof_attached is False
    assert outcome.qualification.qualified is False
    assert "candidate_site_mismatch" in outcome.qualification.reasons
    assert outcome.qualification.facts["defect_family_matched"] is True
    assert outcome.result.outcome == "inconclusive"


def test_wrong_defect_family_is_not_qualified() -> None:
    issue = _issue()
    runs = [
        _witness_run(
            findings=(_finding(kind="use-after-poison"),), classifications=("use-after-poison",) * 2
        )
    ]
    plan, record, replay = _record_and_replay(issue, runs=runs)
    qualification = qualify_witness(plan.binding, plan, record, replay=replay, policy=_policy())
    assert qualification.qualified is False
    assert "defect_family_mismatch" in qualification.reasons


def test_stale_binary_digest_is_not_qualified() -> None:
    issue = _issue()
    plan = _plan(issue)
    runner = FakeDynamicReproductionRunner(
        [_witness_run(binary_digest_override="7" * 64)],
    )
    record = runner.execute(plan)
    replay = replay_witness(plan, FakeDynamicReproductionRunner([_witness_run()]), times=2)

    qualification = qualify_witness(plan.binding, plan, record, replay=replay, policy=_policy())
    assert qualification.qualified is False
    assert "binary_identity_mismatch" in qualification.reasons
    assert qualification.facts["binary_identity_bound"] is False


def test_unattested_handwritten_record_is_rejected() -> None:
    issue = _issue()
    plan = _plan(issue)
    forged = ExecutionRecord(
        record_id="forged-1",
        plan_digest=plan.digest(),
        provider_name="fake-fake-runner",
        provider_version="1",
        provider_kind="fake",
        outcome="witness_observed",
        run_argv=plan.run_argv,
        run_cwd=plan.run_cwd,
        environment=plan.env_allowlist,
        isolation="process",
        isolation_verified=True,
        isolation_notes=("forged",),
        build_argv=(),
        build_exit_code=None,
        build_stdout_digest="",
        build_stderr_digest="",
        build_stdout_excerpt="",
        build_stderr_excerpt="",
        exit_code=1,
        signal_number=None,
        timed_out=False,
        oom_killed=False,
        binary_digest=plan.binary_digest,
        binary_path=plan.binary_path,
        stdout_digest="1" * 64,
        stderr_digest="2" * 64,
        stdout_excerpt="",
        stderr_excerpt="ERROR: AddressSanitizer: heap-buffer-overflow",
        findings=(_finding(),),
        replay_classifications=("heap-buffer-overflow", "heap-buffer-overflow"),
        replay_count=2,
        duration_ms=1,
        memory_limit_mode="simulated",
        detail="forged",
        attestation="0" * 64,
    )
    replay = replay_witness(plan, FakeDynamicReproductionRunner([_witness_run()]), times=2)
    # A witness claim with no live receipt of its own is refused outright: the
    # process never saw this execution.
    with pytest.raises(DynamicReproductionError, match="execution_receipt_not_live"):
        register_dynamic_reproduction(
            issue, plan=plan, record=forged, replay=replay, policy=_policy()
        )
    assert "deterministic_proofs" not in issue


def test_unattested_fake_run_is_rejected() -> None:
    issue = _issue()
    plan = _plan(issue)
    record = FakeDynamicReproductionRunner([_witness_run()], attest=False).execute(plan)
    replay = replay_witness(plan, FakeDynamicReproductionRunner([_witness_run()]), times=2)

    assert record.attestation == ""
    with pytest.raises(DynamicReproductionError, match="execution_receipt_not_live"):
        register_dynamic_reproduction(
            issue, plan=plan, record=record, replay=replay, policy=_policy()
        )
    assert "deterministic_proofs" not in issue

    # The same record can still be inspected directly, and it never qualifies.
    qualification = qualify_witness(plan.binding, plan, record, replay=replay, policy=_policy())
    assert qualification.qualified is False
    assert "no_live_execution_receipt" in qualification.reasons


def test_handwritten_proof_record_cannot_reach_the_pipeline() -> None:
    issue = _issue()
    issue["deterministic_proofs"] = [
        {
            "proof_version": "zscope.dynamic-witness-proof.v1",
            "outcome": "confirm",
            "proof_kind": DYNAMIC_WITNESS_PROOF_KIND,
            "producer_engine": "dynamic-reproduction:asan-runner@1",
            "facts": [
                "candidate_object_matched",
                "candidate_site_matched",
                "defect_family_matched",
                "binary_identity_bound",
                "source_identity_bound",
                "replay_consistent",
            ],
            "fact_ids": ["dynrepro:forged"],
            "code_hash": "deadbeef",
            "completeness": "complete",
            "witness_attestation": "f" * 64,
            "witness_digest": "e" * 64,
        }
    ]
    assert deterministic_decision_proof(issue, outcome="confirm") is None
    assert ValidationPipeline(None).apply_deterministic_prevalidation(issue) is None


def test_serialized_witness_loses_authority_after_shutdown() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    _promote_production(record, replay)
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    assert dynamic_witness_proof_is_live(issue["deterministic_proofs"][0]) is True

    witness_authority_clear()
    assert dynamic_witness_proof_is_live(issue["deterministic_proofs"][0]) is False
    assert deterministic_decision_proof(issue, outcome="confirm") is None
    # The audit metadata survives; only the capability is gone.
    assert issue["dynamic_reproduction_outcome"] == "witness_observed"
    assert issue["deterministic_proofs"][0]["witness_record_digest"]


def test_serialized_issue_round_trip_does_not_restore_authority() -> None:
    import json

    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    _promote_production(record, replay)
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    reloaded = json.loads(json.dumps(issue))
    assert reloaded["deterministic_proofs"][0]["witness_record_digest"]

    # The copy is a different object, so it is not the minted capability even
    # while the process-local registry is still populated.
    assert dynamic_witness_proof_is_live(reloaded["deterministic_proofs"][0]) is False
    assert deterministic_decision_proof(reloaded, outcome="confirm") is None
    assert ValidationPipeline(None).apply_deterministic_prevalidation(reloaded) is None

    # A persisted issue is read back in a *new* process, where the process-local
    # registry is empty. Simulate that boundary explicitly.
    witness_authority_clear()
    assert dynamic_witness_proof_is_live(reloaded["deterministic_proofs"][0]) is False
    assert deterministic_decision_proof(reloaded, outcome="confirm") is None
    # The audit trail is intact even though the capability is gone.
    assert reloaded["dynamic_reproduction_outcome"] == "witness_observed"


def test_live_witness_cannot_be_repointed_or_edited() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    _promote_production(record, replay)
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    proof = issue["deterministic_proofs"][0]
    assert dynamic_witness_proof_is_live(proof, issue) is True

    # Same live proof object, another candidate: the binding no longer matches.
    other = _issue(
        candidate_uid="cand-other",
        resource_identity="other_function",
        location=f"{UNRELATED_SOURCE}:1",
    )
    other["deterministic_proofs"] = [proof]
    assert dynamic_witness_proof_is_live(proof, other) is False
    assert deterministic_decision_proof(other, outcome="confirm") is None

    # A copy is never the minted capability, even with identical content.
    assert dynamic_witness_proof_is_live(dict(proof), issue) is False

    # Editing the bound code hash invalidates the binding check.
    tampered = dict(proof)
    tampered["code_hash"] = "0" * 64
    assert dynamic_witness_proof_is_live(tampered, issue) is False
    tampered_issue = _issue()
    tampered_issue["deterministic_proofs"] = [tampered]
    assert deterministic_decision_proof(tampered_issue, outcome="confirm") is None


# --------------------------------------------------------------------------
# Undecided outcomes stay undecided
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("run", "expected_result"),
    [
        (FakeRun(outcome="not_reproduced", exit_code=0), "not_reproduced"),
        (
            FakeRun(outcome="not_reproduced", exit_code=0, classifications=("none", "none")),
            "not_reproduced",
        ),
        (
            FakeRun(
                outcome="inconclusive",
                classifications=("heap-buffer-overflow", "none"),
            ),
            "inconclusive",
        ),
        (
            FakeRun(
                outcome="engine_failed", timed_out=True, classifications=("engine_failed:timeout",)
            ),
            "failed",
        ),
        (
            FakeRun(
                outcome="engine_failed",
                oom_killed=True,
                stderr="ERROR: AddressSanitizer: requested allocation size exceeds maximum supported size",
                classifications=("engine_failed:resource_exhaustion",),
            ),
            "failed",
        ),
        (
            FakeRun(
                outcome="engine_failed",
                exit_code=1,
                stderr="broken_build.c:5:12: error: expected expression",
                classifications=("engine_failed:build_failed",),
            ),
            "failed",
        ),
        (
            FakeRun(outcome="unsupported", classifications=("engine_failed:unsupported",)),
            "inconclusive",
        ),
    ],
)
def test_undecided_outcomes_never_confirm_or_reject(run: FakeRun, expected_result: str) -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue, runs=[run])
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )

    assert outcome.proof_attached is False
    assert outcome.result.outcome == expected_result
    assert "deterministic_proofs" not in issue
    assert deterministic_decision_proof(issue, outcome="confirm") is None
    assert deterministic_decision_proof(issue, outcome="reject") is None
    assert "validation_status" not in issue
    assert "candidate_disposition" not in issue
    assert ValidationPipeline(None).apply_deterministic_prevalidation(issue) is None


def test_provider_outcome_mapping_covers_every_declared_outcome() -> None:
    from zscope.core.validation.dynamic_reproduction import (
        RESULT_OUTCOME_BY_PROVIDER_OUTCOME,
        UNDECIDED_OUTCOMES,
    )

    assert set(RESULT_OUTCOME_BY_PROVIDER_OUTCOME) == {
        "witness_observed",
        "not_reproduced",
        "inconclusive",
        "engine_failed",
        "unsupported",
        "cancelled",
    }
    for name in UNDECIDED_OUTCOMES:
        assert RESULT_OUTCOME_BY_PROVIDER_OUTCOME[name] != "reproduced"


# --------------------------------------------------------------------------
# Replay and cancellation
# --------------------------------------------------------------------------


def test_missing_independent_replay_blocks_confirmation() -> None:
    issue = _issue()
    plan, record, _ = _record_and_replay(issue)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=None, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert "independent_replay_missing" in outcome.qualification.reasons


def test_inconsistent_replay_blocks_confirmation() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    inconsistent = replay_witness(
        plan,
        FakeDynamicReproductionRunner(
            [
                _witness_run(),
                _witness_run(findings=(), classifications=("none",), outcome="not_reproduced"),
            ]
        ),
        times=2,
    )
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=inconsistent, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert "replay_inconsistent" in outcome.qualification.reasons
    # And the original record's own replay must also be consistent.
    assert replay.consistent is True


def test_replaying_the_same_plan_reproduces_the_same_decision() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    first = register_dynamic_reproduction(
        _issue(), plan=plan, record=record, replay=replay, policy=_policy()
    )
    second = register_dynamic_reproduction(
        _issue(), plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert first.proof_attached is True
    assert second.proof_attached is True
    assert first.qualification.to_dict() == second.qualification.to_dict()
    assert first.result.to_dict() == second.result.to_dict()
    assert first.result.request_id == plan.plan_id


def test_replay_evidence_records_the_binary_identity() -> None:
    issue = _issue()
    plan = _plan(issue)
    evidence = replay_witness(plan, FakeDynamicReproductionRunner([_witness_run()]), times=2)
    assert evidence.plan_digest == plan.digest()
    assert evidence.binary_digest == plan.binary_digest
    assert evidence.classifications == ("heap-buffer-overflow", "heap-buffer-overflow")
    assert evidence.consistent is True
    assert evidence.to_dict()["consistent"] is True


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX process groups")
def test_timeout_kills_the_owned_process_tree(tmp_path: Path) -> None:
    marker = tmp_path / "timeout_marker"
    plan = _process_plan(tmp_path, f"sleep 30; touch {marker}", timeout_seconds=1)
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    record = runner.execute(plan)

    assert record.timed_out is True
    assert record.outcome == "engine_failed"
    assert record.detail == "timeout"
    assert not marker.exists()
    assert "process_group_isolated" in record.isolation_notes


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX process groups")
def test_cancellation_kills_only_the_owned_process_tree(tmp_path: Path) -> None:
    marker = tmp_path / "cancel_marker"
    plan = _process_plan(tmp_path, f"sleep 30; touch {marker}")
    token = CancellationToken()

    def _cancel_later() -> None:
        time.sleep(0.4)
        token.cancel("operator_cancel")

    thread = threading.Thread(target=_cancel_later)
    thread.start()
    try:
        started = time.monotonic()
        with bind_cancellation_token(token):
            record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
        elapsed = time.monotonic() - started
    finally:
        thread.join()

    assert record.outcome == "cancelled"
    assert elapsed < 10
    assert not marker.exists()
    assert record.detail.startswith("cancelled")
    assert "process_group_isolated" in record.isolation_notes
    assert record.attestation


def test_cancelled_record_is_undecided() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(
        issue,
        runs=[
            FakeRun(
                outcome="cancelled", signal_number=9, classifications=("engine_failed:signal_9",)
            )
        ],
    )
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "inconclusive"
    assert deterministic_decision_proof(issue, outcome="reject") is None


# --------------------------------------------------------------------------
# Execution boundary, tooling and providers
# --------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX /bin/sh")
def test_exec_root_outside_the_plan_is_refused(tmp_path: Path) -> None:
    plan = _process_plan(tmp_path, "true", allowed_exec_roots=(str(tmp_path / "allowed"),))
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
    # The declared cwd is not inside the authorized roots, so nothing launches.
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_unverified"
    assert "run_cwd_outside_exec_roots" in record.limitations
    assert "unverified_plan_never_launched" in record.limitations


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX /bin/sh")
def test_undeclared_exec_roots_authorize_nothing(tmp_path: Path) -> None:
    plan = _process_plan(tmp_path, "true", allowed_exec_roots=())
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_unverified"
    assert "exec_roots_not_declared" in record.limitations


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX /bin/sh")
def test_missing_build_tool_is_unsupported_not_a_refutation(tmp_path: Path) -> None:
    from zscope.core.validation.dynamic_reproduction import BuildSpec

    plan = _process_plan(
        tmp_path,
        "true",
        build=BuildSpec(argv=("/nonexistent/zscope-missing-tool",), cwd=str(tmp_path)),
    )
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
    assert record.outcome == "unsupported"
    assert record.detail.startswith("tool_unavailable")


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX /bin/sh")
def test_stale_declared_binary_digest_stops_execution(tmp_path: Path) -> None:
    plan = _process_plan(tmp_path, "true", binary_digest="0" * 64)
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
    # The actual executable no longer matches the declaration, so it is never
    # launched at all.
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_unverified"
    assert "binary_identity_mismatch" in record.limitations
    assert "unverified_plan_never_launched" in record.limitations


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX /bin/sh")
def test_declared_inputs_are_reverified_before_launch(tmp_path: Path) -> None:
    harness = tmp_path / "harness.c"
    harness.write_text("int main(void){return 0;}\n", encoding="utf-8")
    declared = tmp_path / "declared.txt"
    declared.write_text("original\n", encoding="utf-8")
    plan = _process_plan(
        tmp_path,
        "true",
        harness_ref=str(harness),
        harness_digest=_sha256_file(harness),
        input_refs=(str(declared),),
        input_digests=(_sha256_file(declared),),
    )
    declared.write_text("changed\n", encoding="utf-8")
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_unverified"
    assert any(item.startswith("input_digest_mismatch") for item in record.limitations)


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX /bin/sh")
def test_command_must_be_the_verified_binary(tmp_path: Path) -> None:
    plan = _process_plan(tmp_path, "true")
    swapped = dataclasses.replace(plan, run_argv=("/bin/false",))
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(swapped)
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_unverified"
    assert "run_argv_not_verified_binary" in record.limitations


def test_provider_availability_probes_the_compiler_instead_of_assuming_it() -> None:
    unavailable = SanitizerReproductionRunner(
        "asan", policy=_policy(), compiler="zscope-no-such-compiler"
    )
    status = unavailable.availability()
    assert status.available is False
    assert status.reason == "compiler_unavailable"

    fake = FakeDynamicReproductionRunner(
        [_witness_run()], available=False, availability_reason="no_tool"
    )
    assert fake.availability().available is False
    assert fake.availability().reason == "no_tool"


def test_disabled_availability_never_probes_the_toolchain() -> None:
    runner = SanitizerReproductionRunner("asan", compiler="zscope-no-such-compiler")
    status = runner.availability()
    # A disabled policy is refused before the compiler is even resolved.
    assert status.available is False
    assert status.reason == "dynamic_reproduction_disabled"
    assert "compiler" not in status.details


def test_provider_kind_and_plan_kind_must_agree() -> None:
    issue = _issue()
    plan = _plan(issue, provider_kind="tsan", provider_name="tsan-runner")
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    with pytest.raises(DynamicReproductionError):
        runner.execute(plan)
    with pytest.raises(DynamicReproductionError):
        SanitizerReproductionRunner("cbmc")


def test_execution_record_validates_its_outcome_and_kind() -> None:
    issue = _issue()
    plan, record, _ = _record_and_replay(issue)
    with pytest.raises(DynamicReproductionError):
        ExecutionRecord(**{**record.__dict__, "outcome": "totally_safe"})
    with pytest.raises(DynamicReproductionError):
        ExecutionRecord(**{**record.__dict__, "provider_kind": "cbmc"})


def test_fake_runner_reports_exhausted_script() -> None:
    issue = _issue()
    plan = _plan(issue)
    runner = FakeDynamicReproductionRunner([])
    with pytest.raises(DynamicReproductionError):
        runner.execute(plan)


# --------------------------------------------------------------------------
# Report parsing and fixture integrity
# --------------------------------------------------------------------------

_ASAN_SAMPLE = """\
=================================================================
==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f0 at pc 0x55b1 bp 0x7ffc sp 0x7ff0
WRITE of size 1 at 0x6020000000f0 thread T0
    #0 0x55b1a1b2c3d4 in zscope_dynamic_repro_positive /repo/tests/fixtures/dynamic_reproduction/heap_overflow_positive.c:19:9
    #1 0x55b1a1b2c4d5 in main /repo/tests/fixtures/dynamic_reproduction/heap_overflow_positive.c:29:38
    #2 0x7f2a in __libc_start_main /build/glibc/start.c:266:5

0x6020000000f0 is located 0 bytes after 16-byte region [0x6020000000e0,0x6020000000f0)
allocated by thread T0 here:
    #0 0x55b1a1aaaaaa in malloc /compiler/asan_malloc_linux.cpp:135:3
    #1 0x55b1a1b2b1b2 in zscope_dynamic_repro_positive /repo/tests/fixtures/dynamic_reproduction/heap_overflow_positive.c:11:24

SUMMARY: AddressSanitizer: heap-buffer-overflow /repo/tests/fixtures/dynamic_reproduction/heap_overflow_positive.c:19:9 in zscope_dynamic_repro_positive
==4242==ABORTING
"""

_TSAN_SAMPLE = """\
==================
WARNING: ThreadSanitizer: data race (pid=4242)
  Write of size 4 at 0x0000005b1c00 by thread T1:
    #0 zscope_race_writer /repo/tests/fixtures/dynamic_reproduction/data_race_positive.c:18:9 (exe+0x1a2b)
    #1 <null> <null> (libtsan.so+0x2c3d)

  Previous write of size 4 at 0x0000005b1c00 by thread T2:
    #0 zscope_race_writer /repo/tests/fixtures/dynamic_reproduction/data_race_positive.c:18:9 (exe+0x1a2b)

  Location is global 'shared_counter' of size 4 at 0x0000005b1c00 (exe+0x2b1c)

SUMMARY: ThreadSanitizer: data race /repo/tests/fixtures/dynamic_reproduction/data_race_positive.c:18:9 in zscope_race_writer
==================
ThreadSanitizer: reported 1 warnings
"""


def test_parse_asan_report_extracts_kind_site_and_allocation_frames() -> None:
    findings = parse_asan_report(_ASAN_SAMPLE, raw_digest="e" * 64)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "heap-buffer-overflow"
    assert finding.access == "write"
    assert finding.thread == "T0"
    assert finding.site.endswith("heap_overflow_positive.c:19")
    assert finding.frames[0].startswith("zscope_dynamic_repro_positive ")
    assert finding.allocation_frames[-1].startswith("zscope_dynamic_repro_positive ")
    assert finding.raw_digest == "e" * 64


def test_parse_tsan_report_extracts_data_race_and_object() -> None:
    findings = parse_tsan_report(_TSAN_SAMPLE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "data-race"
    assert finding.access == "write"
    assert finding.object_ref == "shared_counter"
    assert finding.site.endswith("data_race_positive.c:18")


def test_parse_sanitizer_report_dispatches_by_provider_kind() -> None:
    assert parse_sanitizer_report(_ASAN_SAMPLE, "asan")[0].kind == "heap-buffer-overflow"
    assert parse_sanitizer_report(_TSAN_SAMPLE, "tsan")[0].kind == "data-race"
    assert parse_sanitizer_report(_ASAN_SAMPLE, "fake") == ()


def test_report_text_that_only_mentions_the_error_word_is_not_a_finding() -> None:
    assert parse_asan_report("ERROR: AddressSanitizer: heap-buffer-overflow\n") == ()
    assert parse_tsan_report("WARNING: ThreadSanitizer: data race\n") == ()


@pytest.mark.parametrize(
    ("kind", "family", "expected"),
    [
        ("heap-buffer-overflow", "heap_buffer_overflow", True),
        ("heap-buffer-overflow", "buffer_overflow", True),
        ("heap-buffer-overflow", "out_of_bounds_write", True),
        ("heap-buffer-overflow", "use_after_free", False),
        ("heap-use-after-free", "use_after_free", True),
        ("double-free", "double_release", True),
        ("data-race", "race_condition", True),
        ("data-race", "buffer_overflow", False),
    ],
)
def test_family_matching(kind: str, family: str, expected: bool) -> None:
    assert families_match(kind, family) is expected


def test_fixture_set_is_complete_and_marker_based() -> None:
    expected = {
        "heap_overflow_positive.c",
        "heap_overflow_negative.c",
        "unrelated_crash.c",
        "broken_build.c",
        "data_race_positive.c",
        "data_race_negative.c",
        "data_race_flaky.c",
        "README.md",
    }
    present = {path.name for path in FIXTURE_DIR.iterdir()}
    assert expected <= present
    for name, marker in (
        ("heap_overflow_positive.c", "ZSCOPE_CANDIDATE_SITE"),
        ("heap_overflow_negative.c", "ZSCOPE_SAFE_SITE"),
        ("unrelated_crash.c", "ZSCOPE_CANDIDATE_SITE"),
        ("unrelated_crash.c", "ZSCOPE_UNRELATED_SITE"),
        ("data_race_positive.c", "ZSCOPE_CANDIDATE_SITE"),
        ("data_race_negative.c", "ZSCOPE_SAFE_SITE"),
        ("data_race_flaky.c", "ZSCOPE_CANDIDATE_SITE"),
    ):
        assert _marker_line(name, marker) > 0


def test_witness_authority_is_scoped_to_the_process() -> None:
    witness_authority_clear()
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    # Authenticity (the execution receipt) exists even though a test-trusted
    # execution never mints a confirmation capability.
    assert EXECUTION_AUTHORITY.live_count() >= 1
    assert WITNESS_AUTHORITY.live_count() == 0

    witness_authority_clear()
    assert EXECUTION_AUTHORITY.live_count() == 0

    # With explicit test authority injected for every execution the capability
    # does exist, and it disappears together with the registry.
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    _promote_production(record, replay)
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    assert WITNESS_AUTHORITY.live_count() == 1
    witness_authority_clear()
    assert WITNESS_AUTHORITY.live_count() == 0


# --------------------------------------------------------------------------
# Real-process helpers (no compiler required)
# --------------------------------------------------------------------------


def _process_plan(
    tmp_path: Path,
    command: str,
    *,
    timeout_seconds: int = 10,
    build: object = None,
    binary_digest: str = "",
    allowed_exec_roots: tuple[str, ...] = DEFAULT_EXEC_ROOTS,
    **overrides: object,
) -> ExecutionPlan:
    """Build a plan that executes /bin/sh so process-group behaviour is real."""

    from zscope.core.validation.dynamic_reproduction import hash_file

    shell = "/bin/sh"
    digest, _ = hash_file(shell)
    issue = _issue()
    plan = _plan(
        issue,
        provider_kind="asan",
        provider_name="asan-runner",
        binary_digest=binary_digest or digest,
        timeout_seconds=timeout_seconds,
        run_argv=(shell, "-c", command),
        run_cwd=str(tmp_path),
        binary_path=shell,
        allowed_exec_roots=allowed_exec_roots,
        build=build,
        max_replays=1,
        **overrides,
    )
    assert plan.binary_path == shell
    return plan


def _assert_no_lingering_sleep() -> None:
    """Guard: a killed run must not leave the owned sleep behind."""

    completed = subprocess.run(
        ["/bin/sh", "-c", "pgrep -f 'sleep 30' || true"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0


def test_process_helper_matches_platform_expectations() -> None:
    if sys.platform == "linux":
        assert os.path.exists("/bin/sh")
    _assert_no_lingering_sleep()


# --------------------------------------------------------------------------
# Migrated independent acceptance negatives (V01-V02-acceptance-regressions.py)
#
# The 2026-10-09 acceptance review wrote these as an independent file because the
# formal suite did not cover them. They now live here, with the same assertions
# and no assertion weakened, so a regression fails the normal suite.
# --------------------------------------------------------------------------


def test_acceptance_wrong_named_object_at_same_site_is_not_a_match() -> None:
    binding = bind_candidate(_issue(resource_identity="other_buffer"))
    finding = dataclasses.replace(_finding(), object_ref="actual_buffer")
    ok, facts, _ = match_witness_to_candidate(binding, finding)
    assert not ok and not facts["candidate_object_matched"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("resource_identity", "other_buffer"),
        ("location", "other.c:200"),
        ("defect_class", "double_free"),
        ("build_configuration", "another-build"),
        ("toolchain_id", "another-toolchain"),
    ],
)
def test_acceptance_registration_rechecks_entire_candidate_binding(key: str, value: str) -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    issue[key] = value
    with pytest.raises(DynamicReproductionError):
        register_dynamic_reproduction(
            issue, plan=plan, record=record, replay=replay, policy=_policy()
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("project_id", "other-project"),
        ("source_revision", "new-source"),
        ("dependency_code_hash", "new-source-hash"),
        ("resource_identity", "other_buffer"),
        ("location", "other.c:200"),
        ("defect_class", "double_free"),
        ("build_configuration", "another-build"),
        ("toolchain_id", "another-toolchain"),
    ],
)
def test_acceptance_adjudication_rejects_changed_current_identity(key: str, value: str) -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    inject_test_execution_authority(record.attestation, reason="identity-recheck")
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    issue[key] = value
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_acceptance_serialized_issue_has_no_authority_even_in_same_process() -> None:
    import json

    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    inject_test_execution_authority(record.attestation, reason="same-process-copy")
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    reloaded = json.loads(json.dumps(issue))
    assert deterministic_decision_proof(reloaded, outcome="confirm") is None


def test_acceptance_fake_provider_cannot_mint_production_confirmation() -> None:
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_acceptance_serialized_replay_claim_requires_live_execution_receipt() -> None:
    issue = _issue()
    plan = _plan(issue)
    record = FakeDynamicReproductionRunner([_witness_run()]).execute(plan)
    replay = ReplayEvidence(
        plan_digest=plan.digest(),
        binary_digest=record.binary_digest,
        classifications=record.replay_classifications,
        provider_name="not-executed",
        provider_version="not-executed",
    )
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert not outcome.proof_attached


def test_acceptance_mixed_independent_replay_cannot_be_collapsed_to_success() -> None:
    issue = _issue()
    plan, record, _ = _record_and_replay(issue)
    mixed = _witness_run(outcome="inconclusive", classifications=("heap-buffer-overflow", "none"))
    replay = replay_witness(plan, FakeDynamicReproductionRunner([mixed]), times=2)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert not outcome.proof_attached
    assert "replay_run_without_witness" in outcome.qualification.reasons


def test_acceptance_independent_replay_for_other_site_cannot_confirm() -> None:
    issue = _issue()
    plan, record, _ = _record_and_replay(issue)
    other = _witness_run(findings=(_finding(site="other.c:400"),))
    replay = replay_witness(plan, FakeDynamicReproductionRunner([other]), times=2)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert not outcome.proof_attached
    assert "replay_run_witness_not_matching_candidate" in outcome.qualification.reasons


def test_acceptance_clean_execution_cannot_be_given_unqualified_positive_proof(
    tmp_path: Path,
) -> None:
    from zscope.core.validation.dynamic_reproduction import (
        dynamic_witness_proof_record,
        hash_file,
    )

    issue = _issue()
    plan = _plan(
        issue,
        provider_kind="asan",
        provider_name="asan-runner",
        binary_digest=hash_file("/bin/true")[0],
        run_cwd=str(tmp_path),
        max_replays=1,
    )
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
    assert record.outcome == "not_reproduced"
    # The public helper bypasses qualification. The selector must independently
    # reject a proof whose execution never yielded a matched witness.
    issue["deterministic_proofs"] = [
        dynamic_witness_proof_record(plan.binding, plan, record, _finding())
    ]
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_acceptance_unavailable_requested_isolation_prevents_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = dataclasses.replace(_process_plan(tmp_path, "true"), isolation="user_net_namespace")
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    monkeypatch.setattr(
        runner, "_namespace_wrap", lambda argv: (tuple(argv), False, ["unavailable"])
    )
    calls: list[dict[str, object]] = []

    def run(**kwargs: object) -> object:
        calls.append(kwargs)
        return _RunResult(0, "", b"", "", b"", False)

    monkeypatch.setattr(runner, "_run_once", run)
    record = runner.execute(plan)
    assert calls == []
    assert record.outcome == "unsupported"
    assert record.detail == "requested_isolation_unavailable"


@pytest.mark.parametrize("changed", ["harness", "input", "executable"])
def test_acceptance_runner_checks_actual_inputs_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    from zscope.core.validation.dynamic_reproduction import hash_file

    harness = tmp_path / "harness.c"
    harness.write_text("int main(void){return 0;}\n")
    input_file = tmp_path / "input.txt"
    input_file.write_text("old-input")
    plan = _plan(
        _issue(),
        provider_kind="asan",
        provider_name="asan-runner",
        binary_digest=hash_file("/bin/true")[0],
        run_cwd=str(tmp_path),
        max_replays=1,
        harness_ref=str(harness),
        harness_digest=hash_file(harness)[0],
        input_refs=(str(input_file),),
        input_digests=(hash_file(input_file)[0],),
    )
    if changed == "harness":
        harness.write_text("changed source\n")
    elif changed == "input":
        input_file.write_text("new-input")
    else:
        plan = dataclasses.replace(plan, run_argv=("/bin/false",))
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    calls: list[dict[str, object]] = []

    def run(**kwargs: object) -> object:
        calls.append(kwargs)
        return _RunResult(0, "", b"", "", b"", False)

    monkeypatch.setattr(runner, "_run_once", run)
    record = runner.execute(plan)
    assert calls == []
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_unverified"


def test_acceptance_disabled_runner_never_launches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _process_plan(tmp_path, "true")
    runner = SanitizerReproductionRunner("asan")
    calls: list[dict[str, object]] = []

    def run(**kwargs: object) -> object:
        calls.append(kwargs)
        return _RunResult(0, "", b"", "", b"", False)

    monkeypatch.setattr(runner, "_run_once", run)
    with pytest.raises(DynamicReproductionError, match="dynamic_reproduction_disabled"):
        runner.execute(plan)
    assert calls == []


# --------------------------------------------------------------------------
# Product consumption entry, artifact publishing and output truncation
# --------------------------------------------------------------------------


def test_run_dynamic_reproduction_refuses_disabled_and_stale_plans() -> None:
    from zscope.core.validation.dynamic_reproduction import run_dynamic_reproduction

    issue = _issue()
    plan = _plan(issue)
    with pytest.raises(DynamicReproductionError, match="dynamic_reproduction_disabled"):
        run_dynamic_reproduction(issue, plan, policy=DynamicReproductionPolicy())
    with pytest.raises(DynamicReproductionError, match="stale_execution_plan"):
        run_dynamic_reproduction(issue, plan, policy=_policy(), plan_digest="0" * 64)
    other = _issue(resource_identity="other_buffer")
    with pytest.raises(DynamicReproductionError, match="plan_issue_identity_mismatch"):
        run_dynamic_reproduction(other, plan, policy=_policy())


def test_run_dynamic_reproduction_executes_replays_and_registers() -> None:
    from zscope.core.validation.dynamic_reproduction import run_dynamic_reproduction

    issue = _issue()
    plan = _plan(issue, max_replays=3)
    runner = FakeDynamicReproductionRunner([_witness_run()])
    outcome = run_dynamic_reproduction(issue, plan, policy=_policy(), runner=runner)
    # One primary execution plus the required independent replays, all inside the
    # total number of runs the plan authorizes.
    assert len(runner.calls) == 1 + _policy().required_replays
    assert len(runner.calls) <= plan.max_replays
    assert issue["dynamic_reproduction_budget"] == {
        "authorized_runs": 3,
        "primary_runs": 1,
        "replays_requested": 2,
        "replays_run": 2,
        "clamped_to_plan_budget": False,
        "deadline_seconds": _policy().deadline_seconds,
    }
    assert outcome.proof_attached is True
    assert outcome.qualification.qualified is True
    assert issue["dynamic_reproduction"]["record"]["runs"]


def test_run_dynamic_reproduction_clamps_replays_to_the_plan_budget() -> None:
    from zscope.core.validation.dynamic_reproduction import run_dynamic_reproduction

    issue = _issue()
    plan = _plan(issue, max_replays=2)
    runner = FakeDynamicReproductionRunner([_witness_run()])
    outcome = run_dynamic_reproduction(issue, plan, policy=_policy(), runner=runner)
    # max_replays=2 authorizes the primary execution and exactly one replay; the
    # shortfall is recorded instead of refusing before the provider runs.
    assert len(runner.calls) == 2
    assert issue["dynamic_reproduction_budget"]["replays_run"] == 1
    assert issue["dynamic_reproduction_budget"]["clamped_to_plan_budget"] is True
    # Only one of the two required independent replays was authorized, so the
    # witness stays unqualified and the reason names the shortfall.
    assert "replay_below_required_count" in outcome.qualification.reasons
    assert outcome.qualification.qualified is False
    assert outcome.proof_attached is False


def test_run_dynamic_reproduction_propagates_cancellation() -> None:
    from zscope.core.validation.dynamic_reproduction import run_dynamic_reproduction

    issue = _issue()
    plan = _process_plan(Path(tempfile.gettempdir()), "sleep 30", timeout_seconds=30)
    token = CancellationToken()
    token.cancel("operator_stop")
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    single = _policy(required_replays=1, max_replays=1)
    with bind_cancellation_token(token):
        outcome = run_dynamic_reproduction(issue, plan, policy=single, runner=runner)
    assert outcome.record.outcome == "cancelled"
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "inconclusive"
    _assert_no_lingering_sleep()


def test_run_records_per_run_evidence_and_published_artifacts(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    plan = _process_plan(tmp_path, "printf 'ok\\n'")
    runner = SanitizerReproductionRunner("asan", policy=_policy(artifact_dir=str(artifacts)))
    record = runner.execute(plan)
    assert record.outcome == "not_reproduced"
    assert len(record.runs) == 1
    run = record.runs[0]
    assert run.index == 0
    assert run.stdout_bytes >= 3
    assert run.output_truncated is False
    assert len(record.artifact_refs) == 2  # run-0.stdout and run-0.stderr
    for ref in record.artifact_refs:
        assert Path(ref).is_file()
    assert run.artifacts and all(Path(ref).is_file() for ref in run.artifacts)
    assert set(run.artifacts) <= set(record.artifact_refs)
    assert "execution_logs_not_published" not in record.limitations


def test_run_without_artifact_dir_says_logs_were_not_published(tmp_path: Path) -> None:
    plan = _process_plan(tmp_path, "printf 'ok\\n'")
    record = SanitizerReproductionRunner("asan", policy=_policy()).execute(plan)
    assert record.artifact_refs == ()
    assert "execution_logs_not_published" in record.limitations


def test_truncated_output_is_never_reported_as_not_reproduced(tmp_path: Path) -> None:
    plan = _process_plan(tmp_path, "printf '%0.sA' $(seq 1 500)")
    record = SanitizerReproductionRunner(
        "asan", policy=_policy(output_capture_limit_bytes=64)
    ).execute(plan)
    assert record.runs[0].output_truncated is True
    assert record.runs[0].stdout_bytes >= 64
    # A cut-off stream cannot be evidence that no report was produced.
    assert record.outcome == "inconclusive"
    assert record.detail == "output_truncated_without_report"
    assert "output_truncated_before_classification" in record.limitations


def test_output_cap_stops_a_chatty_run_and_is_never_a_clean_result(
    tmp_path: Path,
) -> None:
    """The spool budget is a real boundary, not only a read-back limit."""

    plan = _process_plan(
        tmp_path,
        "while true; do printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; done",
        timeout_seconds=30,
    )
    record = SanitizerReproductionRunner(
        "asan", policy=_policy(output_capture_limit_bytes=4096)
    ).execute(plan)
    assert record.runs[0].output_truncated is True
    assert record.outcome == "inconclusive"
    assert record.detail == "output_truncated_without_report"
    assert "output_truncated_before_classification" in record.limitations
    assert record.runs[0].timed_out is False  # stopped by the cap, not the clock
    _assert_no_lingering_sleep()


def test_authority_entries_expire_without_a_global_clear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zscope.core.validation.dynamic_reproduction as module

    clock = {"now": 1000.0}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])
    witness_authority_clear()
    issue = _issue()
    plan, record, replay = _record_and_replay(issue)
    _promote_production(record, replay)
    register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=_policy())
    proof = issue["deterministic_proofs"][0]
    assert dynamic_witness_proof_is_live(proof) is True
    clock["now"] += _policy().authority_ttl_seconds + 1
    assert dynamic_witness_proof_is_live(proof) is False


# --------------------------------------------------------------------------
# Product seam: approved-plan acquisition and the scan hook (F07)
# --------------------------------------------------------------------------


def _stub_config(mode: str = "on", **analysis_overrides: object) -> object:
    from types import SimpleNamespace

    analysis = SimpleNamespace(dynamic_reproduction_mode=mode, **analysis_overrides)
    return SimpleNamespace(analysis=analysis)


def test_attempt_is_inert_when_disabled_and_leaves_the_issue_untouched() -> None:
    consulted: list[object] = []

    def provider(issue: object, policy: object) -> None:
        consulted.append(issue)
        raise AssertionError("a disabled capability must not ask for a plan")

    issue = _issue()
    assert attempt_dynamic_reproduction(issue, provider=provider) is None
    assert attempt_dynamic_reproduction(issue, config=_stub_config("off")) is None
    assert consulted == []
    assert issue == _issue()
    assert "dynamic_reproduction" not in issue
    assert "dynamic_reproduction_attempt" not in issue


def test_attempt_records_why_no_plan_was_available() -> None:
    issue = _issue()
    assert attempt_dynamic_reproduction(issue, policy=_policy()) is None
    assert issue["dynamic_reproduction_attempt"] == {"status": "no_plan_provider"}
    assert "dynamic_reproduction" not in issue

    other = _issue()
    assert attempt_dynamic_reproduction(other, policy=_policy(), provider=lambda i, p: None) is None
    assert other["dynamic_reproduction_attempt"] == {"status": "no_plan_available"}

    failing = _issue()

    def broken(issue: object, policy: object) -> None:
        raise ValueError("provider exploded")

    assert attempt_dynamic_reproduction(failing, policy=_policy(), provider=broken) is None
    assert failing["dynamic_reproduction_attempt"] == {
        "status": "plan_provider_failed",
        "reason": "ValueError",
    }


def test_attempt_never_touches_a_shadow_candidate() -> None:
    issue = _issue(rollout_visibility="shadow", candidate_source="active_discovery")
    assert is_shadow_candidate(bind_candidate(issue))
    assert (
        attempt_dynamic_reproduction(issue, policy=_policy(), provider=lambda i, p: _plan(i))
        is None
    )
    assert issue["dynamic_reproduction_attempt"] == {"status": "shadow_candidate_not_attempted"}
    assert "dynamic_reproduction" not in issue


def test_attempt_rejects_a_stale_plan_without_breaking_the_scan() -> None:
    issue = _issue()
    foreign = _issue(resource_identity="other_buffer")
    plan = _plan(foreign)
    assert attempt_dynamic_reproduction(issue, policy=_policy(), provider=lambda i, p: plan) is None
    assert issue["dynamic_reproduction_attempt"]["status"] == "plan_rejected"
    assert "plan_issue_identity_mismatch" in issue["dynamic_reproduction_attempt"]["reason"]

    stale = _plan(issue)
    assert (
        attempt_dynamic_reproduction(
            issue, policy=_policy(), provider=lambda i, p: (stale, "0" * 64)
        )
        is None
    )
    assert issue["dynamic_reproduction_attempt"] == {
        "status": "plan_rejected",
        "reason": "stale_execution_plan",
    }


def test_attempt_clamps_replays_instead_of_refusing_before_dispatch() -> None:
    """A plan that authorizes fewer runs than requested is still executed.

    ``max_replays`` is the total authorized execution count, so a plan with one
    authorized run performs the primary execution and records the replay
    shortfall; it must not refuse before the provider has been dispatched.
    """

    issue = _issue()
    plan = _plan(issue, max_replays=1)
    runner = FakeDynamicReproductionRunner([_witness_run()])
    outcome = attempt_dynamic_reproduction(
        issue,
        policy=_policy(required_replays=2, max_replays=2),
        runner=runner,
        provider=lambda i, p: plan,
    )
    assert outcome is not None
    assert len(runner.calls) == 1
    assert issue["dynamic_reproduction_attempt"] == {"status": "attempted"}
    assert issue["dynamic_reproduction_budget"]["clamped_to_plan_budget"] is True
    assert issue["dynamic_reproduction_budget"]["replays_run"] == 0
    # No independent replay means no confirmation, and the reason says why.
    assert "independent_replay_missing" in outcome.qualification.reasons
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_attempt_consumes_an_approved_plan_through_unified_adjudication() -> None:
    issue = _issue()
    plan = _plan(issue, max_replays=3)
    runner = FakeDynamicReproductionRunner([_witness_run()])
    outcome = attempt_dynamic_reproduction(
        issue,
        policy=_policy(),
        runner=runner,
        provider=lambda i, p: (plan, plan.digest()),
    )
    assert outcome is not None and outcome.proof_attached is True
    assert issue["dynamic_reproduction_attempt"] == {"status": "attempted"}
    assert issue["dynamic_reproduction_outcome"] == "witness_observed"
    # A fake execution is not confirmation authority: the selector still refuses.
    assert issue["dynamic_reproduction"]["confirmation_authority"]["granted"] is False
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_plan_provider_registry_is_explicit_and_process_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zscope.core.validation.dynamic_reproduction as module

    monkeypatch.setattr(module, "_PLAN_PROVIDER", None)
    assert dynamic_reproduction_plan_provider() is None

    def provider(issue: object, policy: object) -> None:
        return None

    register_dynamic_reproduction_plan_provider(provider)
    assert dynamic_reproduction_plan_provider() is provider
    register_dynamic_reproduction_plan_provider(None)
    assert dynamic_reproduction_plan_provider() is None
    with pytest.raises(DynamicReproductionError, match="plan_provider_not_callable"):
        register_dynamic_reproduction_plan_provider(object())  # type: ignore[arg-type]


def test_scan_hook_is_inert_by_default_and_executes_when_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scan hook: off never asks the service; sessions never go global."""

    import zscope.core.validation.dynamic_reproduction as module
    from types import SimpleNamespace

    from zscope.core.validation.runner import ValidationRunner

    consulted: list[object] = []

    def global_provider(issue: object, policy: object) -> None:
        consulted.append(issue)
        raise AssertionError("a scan must not consult the process-global provider")

    monkeypatch.setattr(module, "_PLAN_PROVIDER", global_provider)

    class ExplicitService:
        """The session-service contract: serve this session's own plan only."""

        def __init__(self, plan: object = None) -> None:
            self._plan = plan
            self.calls: list[tuple[object, object]] = []

        def attempt(self, issue: object, policy: object) -> None:
            self.calls.append((issue, policy))
            attempt_dynamic_reproduction(issue, policy=policy, provider=lambda *_: self._plan)

    # Default off: the reproduction service is never even asked.
    off_service = ExplicitService()
    off_runner = SimpleNamespace(config=SimpleNamespace(), reproduction_service=off_service)
    untouched = _issue()
    ValidationRunner._attempt_dynamic_reproduction(off_runner, untouched)  # type: ignore[arg-type]
    assert off_service.calls == []
    assert "dynamic_reproduction_attempt" not in untouched
    assert "dynamic_reproduction" not in untouched

    enabled_config = _stub_config(
        "on",
        dynamic_reproduction_required_replays=1,
        dynamic_reproduction_max_replays=1,
    )
    # Without a session service the runner must not borrow a global provider
    # another scan installed; the candidate is left undecided instead.
    no_service_runner = SimpleNamespace(config=enabled_config)
    without_service = _issue()
    ValidationRunner._attempt_dynamic_reproduction(no_service_runner, without_service)  # type: ignore[arg-type]
    assert without_service["dynamic_reproduction_attempt"] == {"status": "no_plan_available"}
    assert "dynamic_reproduction" not in without_service
    assert consulted == []

    plan = _process_plan(tmp_path, "true")
    service = ExplicitService(plan)
    enabled_runner = SimpleNamespace(config=enabled_config, reproduction_service=service)
    issue = _issue()
    ValidationRunner._attempt_dynamic_reproduction(enabled_runner, issue)  # type: ignore[arg-type]
    assert service.calls and service.calls[0][0] is issue
    assert issue["dynamic_reproduction_attempt"] == {"status": "attempted"}
    assert issue["dynamic_reproduction_outcome"] == "not_reproduced"
    assert consulted == []
    # A benign execution may not confirm or refute anything.
    assert deterministic_decision_proof(issue, outcome="confirm") is None
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_scan_hook_policy_comes_from_the_runtime_config() -> None:
    from zscope.core.validation.dynamic_reproduction import (
        make_dynamic_reproduction_policy,
    )

    assert make_dynamic_reproduction_policy(_stub_config("off")).enabled is False
    shadow = make_dynamic_reproduction_policy(_stub_config("shadow"))
    assert shadow.enabled is True and shadow.attach_proof is False
    assert make_dynamic_reproduction_policy(_stub_config("on")).attach_proof is True
    assert make_dynamic_reproduction_policy(object()).enabled is False


# --------------------------------------------------------------------------
# Migrated second-round boundary cases (V01-V02-reacceptance-regressions.py)
#
# The 2026-10-09 re-acceptance review wrote these as an independent file because
# the product suite did not cover them. They now live here as well, with the
# positive controls preserved and no assertion weakened.
# --------------------------------------------------------------------------


def _owned_source(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "owned.c"
    source.write_text("int subject(void){return 0;}\n", encoding="utf-8")
    return source, _sha256_file(source)


def _real_file_plan(tmp_path: Path, source: Path, digest: str) -> ExecutionPlan:
    issue = _issue(
        location=f"{source}:1",
        resource_identity="subject",
        source_revision=digest,
        dependency_code_hash=digest,
    )
    return _plan(issue, harness_ref=str(source), harness_digest=digest)


def test_confirmation_is_revoked_when_the_source_file_changes(tmp_path: Path) -> None:
    """The final boundary re-reads the real files, not only the issue mapping."""

    source, digest = _owned_source(tmp_path)
    issue = _issue(
        location=f"{source}:1",
        resource_identity="subject",
        source_revision=digest,
        dependency_code_hash=digest,
    )
    plan = _plan(issue, harness_ref=str(source), harness_digest=digest)
    finding = _finding(site=f"{source}:1", frames=(f"subject {source}:1",))
    scripted = _witness_run(findings=(finding,))
    record = FakeDynamicReproductionRunner([scripted]).execute(plan)
    replay = replay_witness(plan, FakeDynamicReproductionRunner([scripted]), times=2)
    _promote_production(record, replay)

    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert outcome.proof_attached is True
    assert deterministic_decision_proof(issue, outcome="confirm") is not None
    proof = issue["deterministic_proofs"][0]
    # The proof freezes the actual files it was derived from.
    frozen = {item["path"]: item["sha256"] for item in proof["source_files"]}
    assert frozen.get(str(source)) == digest

    # No upstream pass refreshes the mapping: the selector must notice by itself.
    source.write_text("int subject(void){return 1;}\n", encoding="utf-8")
    assert dynamic_witness_proof_is_live(proof) is False
    assert deterministic_decision_proof(issue, outcome="confirm") is None
    assert ValidationPipeline(None).apply_deterministic_prevalidation(issue) is None


def test_untrusted_replays_cannot_complete_production_confirmation(
    tmp_path: Path,
) -> None:
    source, digest = _owned_source(tmp_path)
    issue = _issue(
        location=f"{source}:1",
        resource_identity="subject",
        source_revision=digest,
        dependency_code_hash=digest,
    )
    plan = _plan(issue, harness_ref=str(source), harness_digest=digest)
    finding = _finding(site=f"{source}:1", frames=(f"subject {source}:1",))
    scripted = _witness_run(findings=(finding,))
    record = FakeDynamicReproductionRunner([scripted]).execute(plan)
    replay = replay_witness(plan, FakeDynamicReproductionRunner([scripted]), times=2)
    # The primary execution is promoted; the independent replays stay test-trusted.
    inject_test_execution_authority(record.attestation, reason="boundary-case")

    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert EXECUTION_AUTHORITY.entry(record.attestation).production is True
    assert all(
        EXECUTION_AUTHORITY.entry(run.execution_token).production is False for run in replay.runs
    )
    assert outcome.qualification.qualified is True
    assert outcome.proof_attached is True
    assert issue["dynamic_reproduction"]["confirmation_authority"]["granted"] is False
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_every_primary_run_must_match_the_candidate(tmp_path: Path) -> None:
    source, digest = _owned_source(tmp_path)
    issue = _issue(
        location=f"{source}:1",
        resource_identity="subject",
        source_revision=digest,
        dependency_code_hash=digest,
    )
    plan = _plan(issue, harness_ref=str(source), harness_digest=digest)
    finding = _finding(site=f"{source}:1", frames=(f"subject {source}:1",))
    scripted = _witness_run(findings=(finding,))
    record = FakeDynamicReproductionRunner([scripted]).execute(plan)
    replay = replay_witness(plan, FakeDynamicReproductionRunner([scripted]), times=2)
    _promote_production(record, replay)

    wrong = dataclasses.replace(finding, site="other.c:999", source_mapping=("other.c:999",))
    runs = (
        RunEvidence(
            index=0, outcome="observed", classifications=(finding.kind,), findings=(finding,)
        ),
        RunEvidence(index=1, outcome="observed", classifications=(wrong.kind,), findings=(wrong,)),
    )
    updated = dataclasses.replace(record, runs=runs, attestation="")
    updated = FakeDynamicReproductionRunner([]).register_execution(updated, plan=plan)
    _promote_production(updated, replay)

    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=updated, replay=replay, policy=_policy()
    )
    assert outcome.qualification.qualified is False
    assert "primary_run_witness_not_matching_candidate" in outcome.qualification.reasons
    assert deterministic_decision_proof(issue, outcome="confirm") is None


@pytest.mark.parametrize("changed", ["harness", "input", "binary"])
def test_a_later_execution_refuses_when_a_verified_file_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    """R01: every execution re-derives the current files before launching."""

    harness_file = tmp_path / "harness.c"
    harness_file.write_text("int main(void){return 0;}\n", encoding="utf-8")
    input_file = tmp_path / "input.txt"
    input_file.write_text("first input", encoding="utf-8")
    binary = tmp_path / "program"
    binary.write_bytes(Path("/bin/true").read_bytes())
    plan = _plan(
        _issue(),
        provider_kind="asan",
        provider_name="asan-runner",
        max_replays=3,
        harness_ref=str(harness_file),
        harness_digest=_sha256_file(harness_file),
        input_refs=(str(input_file),),
        input_digests=(_sha256_file(input_file),),
        binary_path=str(binary),
        binary_digest=_sha256_file(binary),
        run_argv=(str(binary),),
        run_cwd=str(tmp_path),
    )
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    started: list[str] = []

    def once(**kwargs: object) -> object:
        started.append(str(kwargs["tag"]))
        return _RunResult(0, "", b"", "", b"", False)

    monkeypatch.setattr(runner, "_run_once", once)
    first = runner.execute(plan)
    assert first.outcome == "not_reproduced"
    assert started == ["run-0"]

    target = {"harness": harness_file, "input": input_file, "binary": binary}[changed]
    target.write_bytes(target.read_bytes() + b"changed")
    second = runner.execute(plan)
    assert second.outcome == "unsupported"
    assert second.detail == "plan_identity_unverified"
    assert any("mismatch" in item for item in second.limitations)
    # The drifted execution never started a process.
    assert started == ["run-0"]


def test_build_cannot_change_the_verified_source_before_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness_file = tmp_path / "harness.c"
    harness_file.write_text("int main(void){return 0;}\n", encoding="utf-8")
    plan = _plan(
        _issue(),
        provider_kind="asan",
        provider_name="asan-runner",
        max_replays=1,
        harness_ref=str(harness_file),
        harness_digest=_sha256_file(harness_file),
        binary_digest=_sha256_file("/bin/true"),
        run_cwd=str(tmp_path),
        build=BuildSpec(argv=("/bin/true",), cwd=str(tmp_path)),
    )
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    calls: list[str] = []

    def once(**kwargs: object) -> object:
        calls.append(str(kwargs["tag"]))
        if kwargs["tag"] == "build":
            harness_file.write_text("changed by build\n", encoding="utf-8")
        return _RunResult(0, "", b"", "", b"", False)

    monkeypatch.setattr(runner, "_run_once", once)
    record = runner.execute(plan)
    assert calls == ["build"]
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_changed_during_execution"
    assert "harness_digest_mismatch" in record.limitations


def test_default_product_entry_dispatches_on_the_plan_provider_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zscope.core.validation.dynamic_reproduction as module
    from zscope.core.validation.dynamic_reproduction import run_dynamic_reproduction

    issue = _issue()
    plan = _plan(issue, provider_kind="tsan", provider_name="fake-tsan-runner")
    made: list[str] = []

    class Provider(FakeDynamicReproductionRunner):
        def execute(self, value: ExecutionPlan) -> ExecutionRecord:
            if self.kind != value.provider_kind:
                raise DynamicReproductionError("provider_plan_kind_mismatch")
            return super().execute(value)

    def factory(kind: str):
        def make(**kwargs: object) -> Provider:
            made.append(kind)
            return Provider([FakeRun(outcome="not_reproduced")], kind=kind)

        return make

    monkeypatch.setattr(module, "AsanReproductionRunner", factory("asan"))
    monkeypatch.setattr(module, "TsanReproductionRunner", factory("tsan"))
    run_dynamic_reproduction(issue, plan, policy=_policy())
    assert made == ["tsan"]


def test_verification_budget_and_deadline_bound_real_process_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zscope.core.validation.dynamic_reproduction as module

    budget = module._ExecutionBudget(run_limit=1, deadline=time.monotonic() + 60)
    budget.claim("run-0")
    with pytest.raises(module._PlanViolation, match="execution_budget_exhausted"):
        budget.claim("run-1")
    # A build and a run are separate slots.
    budget.claim("build")
    with pytest.raises(module._PlanViolation, match="execution_budget_exhausted:build"):
        budget.claim("build")

    expired = module._ExecutionBudget(run_limit=5, deadline=time.monotonic() - 1)
    sprints: list[object] = []
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: sprints.append((a, kw)))
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    runner.use_budget(expired)
    with pytest.raises(module._PlanViolation, match="execution_deadline_exceeded"):
        runner._run_once(
            argv=("/bin/true",),
            cwd=str(tmp_path),
            env={},
            timeout_seconds=5,
            address_space_limit_mb=0,
            tag="expired",
            workdir=str(tmp_path),
        )
    assert sprints == []


def test_scheduler_binds_the_shared_budget_to_the_provider() -> None:
    from zscope.core.validation.dynamic_reproduction import run_dynamic_reproduction

    issue = _issue()
    plan = _plan(issue, max_replays=3)
    runner = FakeDynamicReproductionRunner([_witness_run()])
    run_dynamic_reproduction(issue, plan, policy=_policy(), runner=runner)
    assert runner._budget is not None
    assert runner._budget.run_limit == 3
    assert runner._budget.runs_started == 0  # the fake runner starts no process


def test_published_artifacts_are_never_overwritten_by_a_later_execution(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    plan = _process_plan(tmp_path, "date +%s%N")
    runner = SanitizerReproductionRunner("asan", policy=_policy(artifact_dir=str(artifacts)))
    first = runner.execute(plan)
    assert first.outcome == "not_reproduced"
    before = {ref: _sha256_file(ref) for ref in first.artifact_refs}
    assert before
    second = runner.execute(plan)
    assert second.outcome == "not_reproduced"
    assert all(_sha256_file(ref) == digest for ref, digest in before.items())
    # The two executions publish into different directories.
    assert set(first.artifact_refs) != set(second.artifact_refs)
    assert first.artifact_root != second.artifact_root


def test_already_cancelled_run_never_spawns_a_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zscope.core.validation.dynamic_reproduction as module

    token = CancellationToken()
    token.cancel("cancel before launch")
    calls: list[object] = []

    class Finished:
        pid = 1
        returncode = 0

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(
        module.subprocess, "Popen", lambda *a, **kw: calls.append((a, kw)) or Finished()
    )
    runner = SanitizerReproductionRunner("asan", policy=_policy())
    with bind_cancellation_token(token):
        with pytest.raises(CancellationError):
            runner._run_once(
                argv=("/bin/true",),
                cwd=str(tmp_path),
                env={},
                timeout_seconds=1,
                address_space_limit_mb=0,
                tag="cancelled",
                workdir=str(tmp_path),
            )
    assert calls == []


def test_authority_release_is_scoped_to_one_candidate() -> None:
    witness_authority_clear()
    issue_a = _issue()
    plan_a, record_a, replay_a = _record_and_replay(issue_a)
    _promote_production(record_a, replay_a)
    register_dynamic_reproduction(
        issue_a, plan=plan_a, record=record_a, replay=replay_a, policy=_policy()
    )
    issue_b = _issue(candidate_uid="cand-b")
    plan_b, record_b, replay_b = _record_and_replay(issue_b)
    _promote_production(record_b, replay_b)
    register_dynamic_reproduction(
        issue_b, plan=plan_b, record=record_b, replay=replay_b, policy=_policy()
    )
    proof_a = issue_a["deterministic_proofs"][0]
    proof_b = issue_b["deterministic_proofs"][0]
    assert dynamic_witness_proof_is_live(proof_a) is True
    assert dynamic_witness_proof_is_live(proof_b) is True

    released = release_issue_dynamic_reproduction_authority(issue_a)
    assert released > 0
    assert dynamic_witness_proof_is_live(proof_a) is False
    # A concurrent candidate keeps its own capability.
    assert dynamic_witness_proof_is_live(proof_b) is True
    assert deterministic_decision_proof(issue_b, outcome="confirm") is not None


def test_importing_the_runner_does_not_require_posix_resource() -> None:
    """The capability must stay importable on a platform without ``resource``."""

    code = (
        "import sys, importlib.abc\n"
        "class MissingResource(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, fullname, path=None, target=None):\n"
        "        if fullname == 'resource':\n"
        "            raise ModuleNotFoundError('no resource', name='resource')\n"
        "sys.meta_path.insert(0, MissingResource())\n"
        "import zscope.core.validation.runner\n"
        "from zscope.core.validation import dynamic_reproduction as d\n"
        "assert d._resource is None\n"
        "print('ok')\n"
    )
    ran = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert ran.returncode == 0, ran.stderr


def test_incomplete_candidate_identity_never_fails_the_scan(tmp_path: Path) -> None:
    ordinary = {
        "id": "RULE_1",
        "candidate_uid": "candidate-1",
        "location": "ordinary.c:5",
        "function": "subject",
        "defect_class": "heap_buffer_overflow",
        "project_id": "local-project",
        "revision": "",
    }
    outcome = attempt_dynamic_reproduction(
        ordinary,
        policy=_policy(),
        provider=lambda issue, policy: (_ for _ in ()).throw(
            AssertionError("an unbound candidate must not consult the provider")
        ),
    )
    assert outcome is None
    assert ordinary["dynamic_reproduction_attempt"]["status"] in {
        "candidate_identity_unavailable",
        "no_plan_provider",
        "plan_provider_invalid",
    }

    # A provider defect is reported and the scan continues; a cancellation is not
    # swallowed, because the caller's shutdown path depends on it.
    issue = _issue()
    plan = _plan(issue)
    failing = attempt_dynamic_reproduction(
        issue,
        policy=_policy(),
        provider=lambda i, p: (_ for _ in ()).throw(DynamicReproductionError("boom")),
    )
    assert failing is None
    assert issue["dynamic_reproduction_attempt"] == {
        "status": "plan_provider_failed",
        "reason": "DynamicReproductionError",
    }

    def cancel(issue_: dict[str, object], policy_: object) -> None:
        raise CancellationError("operator_stop")

    with pytest.raises(CancellationError):
        attempt_dynamic_reproduction(issue, policy=_policy(), provider=cancel)

    garbage = attempt_dynamic_reproduction(
        _issue(), policy=_policy(), provider=lambda i, p: ("not a plan", "")
    )
    assert garbage is None

    # A fake-provider plan has no product runner: it is reported as rejected
    # rather than being executed with an arbitrary provider.
    no_runner_issue = _issue()
    no_runner = attempt_dynamic_reproduction(
        no_runner_issue, policy=_policy(), provider=lambda i, p: plan
    )
    assert no_runner is None
    assert no_runner_issue["dynamic_reproduction_attempt"]["status"] == "plan_rejected"
    assert no_runner_issue["dynamic_reproduction_attempt"]["reason"].startswith(
        "unsupported_provider_kind"
    )


# Bounded build/capture regressions (RG01/RG02), including owned descendants.


def test_build_receives_the_plan_memory_limit(tmp_path, monkeypatch):
    plan = _process_plan(
        tmp_path,
        "true",
        memory_limit_mb=37,
        build=d.BuildSpec(argv=("/bin/true",), cwd=str(tmp_path)),
    )
    calls = []
    runner = d.SanitizerReproductionRunner("asan", policy=_policy())

    def once(**kwargs):
        calls.append(kwargs)
        return d._RunResult(0, "", b"", "", b"", False)

    monkeypatch.setattr(runner, "_run_once", once)
    runner.execute(plan)
    assert [c["tag"] for c in calls] == ["build", "run-0"]
    build = calls[0]
    assert build.get("rss_limit_mb", 0) == plan.memory_limit_mb or (
        build.get("address_space_limit_mb", 0) == plan.memory_limit_mb
    ), "build must receive the declared product memory boundary"


def test_build_resource_failure_stops_before_run_and_stays_undecided(tmp_path, monkeypatch):
    plan = _process_plan(
        tmp_path,
        "true",
        memory_limit_mb=37,
        build=d.BuildSpec(argv=("/bin/true",), cwd=str(tmp_path)),
    )
    calls = []
    runner = d.SanitizerReproductionRunner("asan", policy=_policy())

    def once(**kwargs):
        calls.append(kwargs["tag"])
        return d._RunResult(-9, "", b"", "", b"", False, rss_exceeded=True)

    monkeypatch.setattr(runner, "_run_once", once)
    record = runner.execute(plan)
    assert calls == ["build"]
    assert record.outcome == "engine_failed"
    assert "resource_exhaustion" in record.detail
    assert record.build_exit_code == -9
    assert record.findings == ()
    assert any("memory" in x or "rss" in x for x in record.limitations)


@pytest.mark.parametrize("pause", [0, 0.1], ids=["exit-immediately", "briefly-live"])
def test_capture_never_exceeds_budget_even_before_hashing(tmp_path, monkeypatch, pause):
    # Only 64 bytes on each stream: a tiny deterministic over-cap fixture.
    original_hash = d.hash_file
    checked = []

    def bounded_hash(p):
        q = Path(p)
        if q.name.endswith((".stdout", ".stderr")):
            checked.append(q.name)
            assert q.stat().st_size <= 16, "capture must be bounded before digest work"
        return original_hash(p)

    monkeypatch.setattr(d, "hash_file", bounded_hash)
    runner = d.SanitizerReproductionRunner(
        "asan",
        policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=16),
    )
    code = f'import os,time;os.write(1,b"A"*64);os.write(2,b"B"*64);time.sleep({pause})'
    result = runner._run_once(
        argv=(sys.executable, "-c", code),
        cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        address_space_limit_mb=0,
        tag="bounded",
        workdir=str(tmp_path),
    )
    assert len(checked) == 2
    assert result.stdout_bytes <= 16 and result.stderr_bytes <= 16
    assert (tmp_path / "bounded.stdout").stat().st_size <= 16
    assert (tmp_path / "bounded.stderr").stat().st_size <= 16
    assert result.output_capped or result.stdout_truncated or result.stderr_truncated
    assert (
        result.stdout_digest
        == hashlib.sha256((tmp_path / "bounded.stdout").read_bytes()).hexdigest()
    )
    assert (
        result.stderr_digest
        == hashlib.sha256((tmp_path / "bounded.stderr").read_bytes()).hexdigest()
    )


def test_below_cap_keeps_complete_bytes_and_nonzero_exit(tmp_path):
    runner = d.SanitizerReproductionRunner(
        "asan",
        policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=128),
    )
    result = runner._run_once(
        argv=(
            sys.executable,
            "-c",
            'import os;os.write(1,b"A"*32);os.write(2,b"B"*32);raise SystemExit(7)',
        ),
        cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        address_space_limit_mb=0,
        tag="clean",
        workdir=str(tmp_path),
    )
    assert result.exit_code == 7
    assert result.stdout_bytes == result.stderr_bytes == 32
    assert result.stdout_excerpt == b"A" * 32 and result.stderr_excerpt == b"B" * 32
    assert not result.output_capped and not result.stdout_truncated and not result.stderr_truncated


def test_real_build_uses_existing_watchdog_without_allocating_memory(tmp_path, monkeypatch):
    plan = _process_plan(
        tmp_path,
        "true",
        memory_limit_mb=37,
        build=d.BuildSpec(argv=("/bin/sh", "-c", "sleep 0.2"), cwd=str(tmp_path)),
    )
    runner = d.SanitizerReproductionRunner("asan", policy=_policy())
    checks = []

    def synthetic_limit(pid, limit_mb):
        checks.append((pid, limit_mb))
        return True

    monkeypatch.setattr(runner, "_rss_exceeds", synthetic_limit)
    record = runner.execute(plan)
    assert checks and all(limit == 37 for _, limit in checks)
    assert record.outcome == "engine_failed"
    assert "resource_exhaustion" in record.detail
    assert record.build_exit_code is not None and record.build_exit_code != 0
    assert not record.runs and not record.findings


def test_pipe_capture_keeps_small_late_descendant_bytes(tmp_path):
    child = 'import os,time;time.sleep(0.1);os.write(1,b"A"*32);os.write(2,b"B"*32)'
    code = 'import subprocess,sys;subprocess.Popen([sys.executable,"-c",' + repr(child) + "])"
    runner = d.SanitizerReproductionRunner(
        "asan",
        policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=128),
    )
    result = runner._run_once(
        argv=(sys.executable, "-c", code),
        cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        address_space_limit_mb=0,
        tag="late",
        workdir=str(tmp_path),
    )
    assert result.exit_code == 0
    assert result.stdout_excerpt == b"A" * 32 and result.stderr_excerpt == b"B" * 32
    assert not result.output_capped and not result.stdout_truncated and not result.stderr_truncated


def test_complete_exact_cap_output_is_not_falsely_truncated(tmp_path):
    runner = d.SanitizerReproductionRunner(
        "asan",
        policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=32),
    )
    result = runner._run_once(
        argv=(sys.executable, "-c", 'import os;os.write(1,b"A"*32);os.write(2,b"B"*32)'),
        cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        address_space_limit_mb=0,
        tag="exact",
        workdir=str(tmp_path),
    )
    assert result.exit_code == 0 and result.stdout_bytes == result.stderr_bytes == 32
    assert not result.output_capped and not result.stdout_truncated and not result.stderr_truncated


def _resource_child_command(marker, body):
    child = (
        "import os,time;from pathlib import Path;"
        f"Path({str(marker)!r}).write_text(str(os.getpid()));" + body
    )
    parent = (
        "import subprocess,sys,time;from pathlib import Path;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        f"marker=Path({str(marker)!r});deadline=time.monotonic()+2;"
        "\nwhile not marker.exists() and time.monotonic()<deadline:time.sleep(.005)"
    )
    return (sys.executable, "-c", parent)


def _resource_child_alive(marker):
    if not marker.exists():
        return False
    status = Path(f"/proc/{int(marker.read_text())}/stat")
    try:
        return status.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


def _cleanup_resource_child(marker):
    if _resource_child_alive(marker):
        try:
            os.kill(int(marker.read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass


def _assert_resource_child_stopped(marker):
    until = time.monotonic() + 1
    while _resource_child_alive(marker) and time.monotonic() < until:
        time.sleep(0.01)
    assert marker.is_file(), "the owned child must have actually started"
    assert not _resource_child_alive(marker), "owned descendant survived the runner cleanup"


def _run_resource_process(runner, tmp_path, argv):
    return runner._run_once(
        argv=argv,
        cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        address_space_limit_mb=0,
        tag="owned",
        workdir=str(tmp_path),
    )


def test_shared_deadline_bounds_pipes_after_leader_exit(tmp_path):
    marker = tmp_path / "child.pid"
    runner = d.SanitizerReproductionRunner("asan", policy=d.DynamicReproductionPolicy(enabled=True))
    runner.use_budget(d._ExecutionBudget(run_limit=1, deadline=time.monotonic() + 0.5))
    started = time.monotonic()
    try:
        result = _run_resource_process(
            runner, tmp_path, _resource_child_command(marker, "time.sleep(3)")
        )
        assert result.timed_out
        assert time.monotonic() - started < 2
        _assert_resource_child_stopped(marker)
    finally:
        _cleanup_resource_child(marker)


def test_cancellation_kills_descendant_after_leader_exit(tmp_path):
    marker = tmp_path / "child.pid"
    token = CancellationToken()
    timer = threading.Timer(0.5, lambda: token.cancel("cancel inherited pipes"))
    runner = d.SanitizerReproductionRunner("asan", policy=d.DynamicReproductionPolicy(enabled=True))
    timer.start()
    try:
        with bind_cancellation_token(token), pytest.raises(d.CancellationError):
            _run_resource_process(
                runner, tmp_path, _resource_child_command(marker, "time.sleep(3)")
            )
        _assert_resource_child_stopped(marker)
    finally:
        timer.cancel()
        timer.join()
        _cleanup_resource_child(marker)


def test_eof_does_not_leave_an_owned_descendant_alive(tmp_path):
    marker = tmp_path / "child.pid"
    runner = d.SanitizerReproductionRunner("asan", policy=d.DynamicReproductionPolicy(enabled=True))
    try:
        result = _run_resource_process(
            runner,
            tmp_path,
            _resource_child_command(marker, "os.close(1);os.close(2);time.sleep(3)"),
        )
        assert result.exit_code == 0 and not result.timed_out
        _assert_resource_child_stopped(marker)
    finally:
        _cleanup_resource_child(marker)


def test_output_cap_kills_owned_group_after_leader_exit(tmp_path):
    marker = tmp_path / "child.pid"
    runner = d.SanitizerReproductionRunner(
        "asan",
        policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=16),
    )
    try:
        result = _run_resource_process(
            runner,
            tmp_path,
            _resource_child_command(marker, "time.sleep(.1);os.write(1,b'A'*64);time.sleep(3)"),
        )
        assert result.output_capped and result.stdout_truncated
        assert result.stdout_bytes == 16 and not result.timed_out
        _assert_resource_child_stopped(marker)
    finally:
        _cleanup_resource_child(marker)


def test_pipe_read_failure_is_not_treated_as_complete_eof(tmp_path, monkeypatch):
    import errno

    original_popen, original_read = d.subprocess.Popen, d.os.read
    capture_fds = set()

    def popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        capture_fds.update(pipe.fileno() for pipe in (process.stdout, process.stderr) if pipe)
        return process

    def read(fd, size):
        if fd in capture_fds:
            raise OSError(errno.EIO, "synthetic pipe read failure")
        return original_read(fd, size)

    monkeypatch.setattr(d.subprocess, "Popen", popen)
    monkeypatch.setattr(d.os, "read", read)
    runner = d.SanitizerReproductionRunner("asan", policy=d.DynamicReproductionPolicy(enabled=True))
    with pytest.raises(d._PlanViolation, match="output_capture_failed"):
        _run_resource_process(
            runner, tmp_path, (sys.executable, "-c", "import os;os.write(1,b'A')")
        )
