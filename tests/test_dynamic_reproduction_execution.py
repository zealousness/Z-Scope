"""Real sanitizer execution acceptance for V01 (ASAN) and V02 (TSAN).

This is the heavy lane: it compiles the small, deliberately vulnerable/safe
fixtures and runs them under the controlled runner. The deterministic contract
tests live in ``tests/test_dynamic_reproduction.py``.

Run this file alone, one lane at a time:

    python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction_execution.py

When the compiler or the sanitizer runtime is unavailable every test in this
file skips with an explicit reason, so the real-execution items stay *not run*
instead of being reported as passed.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from zscope.core.validation.dynamic_reproduction import (
    BuildSpec,
    DynamicReproductionPolicy,
    SanitizerReproductionRunner,
    bind_candidate,
    build_execution_plan,
    dynamic_witness_proof_is_live,
    hash_file,
    qualify_witness,
    register_dynamic_reproduction,
    replay_witness,
)
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.proofs import deterministic_decision_proof

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "dynamic_reproduction"
FIXTURE_REL = "tests/fixtures/dynamic_reproduction"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="sanitizer execution acceptance requires Linux",
)

_OBSERVED: dict[str, object] = {}


def _marker_line(name: str, marker: str = "ZSCOPE_CANDIDATE_SITE") -> int:
    for index, line in enumerate(
        (FIXTURE_DIR / name).read_text(encoding="utf-8").splitlines(), start=1
    ):
        if marker in line:
            return index
    raise AssertionError(f"marker {marker} missing from {name}")


def _policy(**overrides: object) -> DynamicReproductionPolicy:
    values: dict[str, object] = {"enabled": True, "required_replays": 2}
    values.update(overrides)
    return DynamicReproductionPolicy(**values)  # type: ignore[arg-type]


def _require_sanitizer(kind: str) -> str:
    """Probe the compiler and runtime inside *this* process, in the real cwd."""

    compiler = shutil.which("clang") or shutil.which("cc") or shutil.which("gcc") or ""
    if not compiler:
        pytest.skip("no C compiler on PATH: real execution not run")
    status = SanitizerReproductionRunner(kind, compiler=compiler, policy=_policy()).availability()
    if not status.available:
        pytest.skip(f"{kind} runtime unavailable ({status.reason}): real execution not run")
    return compiler


def _compile(name: str, binary: Path, kind: str, compiler: str) -> tuple[str, ...]:
    """Compile one fixture with a program-owned argv (never a project script)."""

    source = FIXTURE_DIR / name
    argv: list[str] = [
        compiler,
        f"-fsanitize={'address' if kind == 'asan' else 'thread'}",
        "-g",
        "-O0",
        "-fno-omit-frame-pointer",
    ]
    if kind == "tsan":
        argv.extend(["-std=c11", "-pthread"])
    argv.extend(["-o", str(binary), str(source)])
    built = subprocess.run(argv, capture_output=True, check=False, timeout=300)
    if built.returncode != 0:
        raise AssertionError(
            f"fixture build failed: {built.stderr.decode('utf-8', 'replace')[-800:]}"
        )
    return tuple(argv)


def _issue(
    name: str,
    *,
    function: str,
    defect_class: str,
    object_identity: str | None = None,
    marker: str = "ZSCOPE_CANDIDATE_SITE",
) -> dict[str, object]:
    line = _marker_line(name, marker)
    return {
        "id": f"DYNREPRO_{name}",
        "candidate_uid": f"cand-{name}",
        "validation_cluster_uid": f"cluster-{name}",
        "project_id": "zscope-dynamic-reproduction-fixtures",
        "source_revision": "fixture-rev-1",
        "dependency_code_hash": "fixture-rev-1",
        "defect_class": defect_class,
        "location": f"{FIXTURE_REL}/{name}:{line}",
        "function": function,
        "resource_identity": object_identity or function,
    }


def _plan(
    issue: dict[str, object],
    *,
    kind: str,
    compiler: str,
    binary: Path,
    binary_digest: str,
    run_argv: tuple[str, ...],
    run_cwd: Path,
    build: BuildSpec | None = None,
    timeout_seconds: int = 60,
    memory_limit_mb: int = 512,
    max_replays: int = 2,
    isolation: str = "process",
):
    binding = bind_candidate(issue)
    # The candidate location carries the fixture it belongs to, so the harness
    # digest can never drift from the binding.
    source_name = str(issue["location"]).split("/")[-1].split(":")[0]
    source = FIXTURE_DIR / source_name
    source_digest = hash_file(source)[0]
    return build_execution_plan(
        binding,
        provider_kind=kind,
        provider_name=f"{kind}-runner",
        provider_version="1",
        run_argv=run_argv,
        run_cwd=str(run_cwd),
        harness_ref=str(source),
        harness_digest=source_digest,
        binary_path=str(binary),
        binary_digest=binary_digest,
        toolchain_id=f"{kind}:{Path(compiler).name}",
        build_configuration=f"{kind}-fixture-build",
        # The compiled source is a real, hashed execution input, so the runner
        # re-verifies it against the declaration before launching anything.
        input_refs=(str(source),),
        input_digests=(source_digest,),
        env_allowlist={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout_seconds=timeout_seconds,
        memory_limit_mb=memory_limit_mb,
        isolation=isolation,
        max_replays=max_replays,
        build=build,
        # Explicit authorization for everything this plan may touch.
        allowed_exec_roots=(
            str(run_cwd),
            str(binary.parent),
            str(FIXTURE_DIR),
            str(tmp_root()),
            "/bin",
            "/usr/bin",
        ),
    )


def tmp_root() -> Path:
    import tempfile

    return Path(tempfile.gettempdir())


def _runner(kind: str, compiler: str, **policy_overrides: object) -> SanitizerReproductionRunner:
    return SanitizerReproductionRunner(
        kind, compiler=compiler, policy=_policy(**policy_overrides)
    )


# --------------------------------------------------------------------------
# V01: AddressSanitizer
# --------------------------------------------------------------------------


def test_asan_positive_fixture_confirms_through_shared_adjudication(tmp_path: Path) -> None:
    compiler = _require_sanitizer("asan")
    binary = tmp_path / "positive"
    _compile("heap_overflow_positive.c", binary, "asan", compiler)
    digest, _ = hash_file(binary)

    issue = _issue(
        "heap_overflow_positive.c",
        function="zscope_dynamic_repro_positive",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest=digest,
        run_argv=(str(binary), "64"),
        run_cwd=tmp_path,
    )

    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_positive"] = record.to_dict()
    assert record.outcome == "witness_observed", record.stderr_excerpt
    assert record.findings, "no parsed sanitizer finding"
    finding = record.findings[0]
    assert finding.kind == "heap-buffer-overflow"
    assert finding.site.endswith(f"heap_overflow_positive.c:{_marker_line('heap_overflow_positive.c')}")
    assert record.binary_digest == digest
    assert "rlimit_as_not_applied_to_sanitizer_runtime" in record.limitations
    assert "subprocess_is_not_a_container_sandbox" in record.isolation_notes
    assert record.isolation == "process"
    assert record.memory_limit_mode == "sanitizer_allocation_cap"

    # Independent replay with a second runner instance.
    replay = replay_witness(plan, _runner("asan", compiler), times=2)
    assert replay.consistent is True
    assert replay.classifications == ("heap-buffer-overflow",) * 2

    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert outcome.proof_attached is True
    assert outcome.result.outcome == "reproduced"
    assert dynamic_witness_proof_is_live(issue["deterministic_proofs"][0], issue) is True

    decision = ValidationPipeline(None).apply_deterministic_prevalidation(
        issue, {"final_score": 0.9}
    )
    assert decision is not None
    assert decision.report_bucket == "issues"
    assert issue["candidate_disposition"] == "confirmed"
    assert issue["promotion_reason"] == "deterministic_prevalidation_proof"
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_asan_positive_build_runs_through_the_runner(tmp_path: Path) -> None:
    """The program-owned build path itself is exercised, not just a prebuilt file."""

    compiler = _require_sanitizer("asan")
    binary = tmp_path / "built-positive"
    build_argv = _compile_argv("heap_overflow_positive.c", binary, "asan", compiler)

    issue = _issue(
        "heap_overflow_positive.c",
        function="zscope_dynamic_repro_positive",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest="",  # produced by this build, verified below
        run_argv=(str(binary), "64"),
        run_cwd=tmp_path,
        build=BuildSpec(argv=build_argv, cwd=str(FIXTURE_DIR)),
    )

    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_build"] = record.to_dict()
    assert record.build_exit_code == 0, record.build_stderr_excerpt
    assert record.build_argv == build_argv
    assert record.build_stdout_digest and record.build_stderr_digest
    assert binary.exists()
    assert record.binary_digest == hash_file(binary)[0]
    assert record.outcome == "witness_observed", record.stderr_excerpt
    # The identity of a build-produced artifact is bound by the post-build hash,
    # and it is recorded as such instead of being left unbound.
    assert record.binary_identity_source == "post_build_output"
    assert "binary_identity_bound_after_build" in record.limitations


def test_asan_build_generated_binary_confirms_without_a_declared_digest(
    tmp_path: Path,
) -> None:
    """A plan that builds its own executable can still reach a confirmation.

    The plan authorizes the build, so the executed program's identity is the hash
    of the artifact that build actually wrote; a candidate must not stay undecided
    merely because the digest could not be known before the build ran.
    """

    compiler = _require_sanitizer("asan")
    binary = tmp_path / "built-confirmed"
    build_argv = _compile_argv("heap_overflow_positive.c", binary, "asan", compiler)

    issue = _issue(
        "heap_overflow_positive.c",
        function="zscope_dynamic_repro_positive",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest="",
        run_argv=(str(binary), "64"),
        run_cwd=tmp_path,
        build=BuildSpec(argv=build_argv, cwd=str(FIXTURE_DIR)),
        max_replays=3,
    )

    record = _runner("asan", compiler).execute(plan)
    assert record.outcome == "witness_observed", record.stderr_excerpt
    assert record.binary_digest and record.binary_identity_source == "post_build_output"

    replay = replay_witness(plan, _runner("asan", compiler), times=2)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    _OBSERVED["asan_build_confirmation"] = {
        "record": record.to_dict(),
        "replay": replay.to_dict(),
        "qualified": outcome.qualification.qualified,
        "facts": dict(outcome.qualification.facts),
        "reasons": list(outcome.qualification.reasons),
    }
    assert outcome.qualification.qualified is True, outcome.qualification.reasons
    assert outcome.qualification.facts["binary_identity_bound"] is True
    assert issue["dynamic_reproduction"]["confirmation_authority"]["granted"] is True
    assert deterministic_decision_proof(issue, outcome="confirm") is not None


def test_asan_negative_fixture_is_not_reproduced_and_never_rejects(tmp_path: Path) -> None:
    compiler = _require_sanitizer("asan")
    binary = tmp_path / "negative"
    _compile("heap_overflow_negative.c", binary, "asan", compiler)

    issue = _issue(
        "heap_overflow_negative.c",
        function="zscope_dynamic_repro_negative",
        defect_class="heap_buffer_overflow",
        marker="ZSCOPE_SAFE_SITE",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary), "64"),
        run_cwd=tmp_path,
        max_replays=2,
    )

    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_negative"] = record.to_dict()
    assert record.outcome == "not_reproduced", record.stderr_excerpt
    assert record.findings == ()
    assert record.detail == "no_sanitizer_report"
    # One ``execute`` performs exactly one run, so the record carries exactly one
    # classification; the extra replays are separate executions.
    assert len(record.runs) == 1
    assert record.replay_classifications == ("none",)
    assert record.runs[0].classifications == ("none",)

    replay = replay_witness(plan, _runner("asan", compiler), times=2)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "not_reproduced"
    assert "deterministic_proofs" not in issue
    assert deterministic_decision_proof(issue, outcome="confirm") is None
    # Not reproducing a candidate is never a safety refutation.
    assert deterministic_decision_proof(issue, outcome="reject") is None
    assert ValidationPipeline(None).apply_deterministic_prevalidation(issue) is None


def test_asan_unrelated_crash_never_confirms_the_candidate(tmp_path: Path) -> None:
    compiler = _require_sanitizer("asan")
    binary = tmp_path / "unrelated"
    _compile("unrelated_crash.c", binary, "asan", compiler)

    issue = _issue(
        "unrelated_crash.c",
        function="zscope_dynamic_repro_candidate",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary), "64"),
        run_cwd=tmp_path,
    )

    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_unrelated"] = record.to_dict()
    assert record.outcome == "witness_observed", record.stderr_excerpt
    assert record.findings and "unrelated_helper" in record.findings[0].frames[0]

    replay = replay_witness(plan, _runner("asan", compiler), times=2)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert outcome.qualification.qualified is False
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "inconclusive"
    assert "candidate_site_mismatch" in outcome.qualification.reasons
    assert "deterministic_proofs" not in issue
    assert ValidationPipeline(None).apply_deterministic_prevalidation(issue) is None


def test_asan_build_failure_stays_undecided(tmp_path: Path) -> None:
    compiler = _require_sanitizer("asan")
    issue = _issue(
        "broken_build.c",
        function="zscope_dynamic_repro_broken",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=tmp_path / "never-built",
        binary_digest="",
        run_argv=(str(tmp_path / "never-built"),),
        run_cwd=tmp_path,
        build=BuildSpec(
            argv=(compiler, "-fsanitize=address", "-c", str(FIXTURE_DIR / "broken_build.c")),
            cwd=str(tmp_path),
        ),
    )

    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_build_failure"] = record.to_dict()
    assert record.outcome == "engine_failed"
    assert record.detail == "build_failed"
    assert record.build_exit_code not in (0, None)
    assert "error:" in record.build_stderr_excerpt

    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=None, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "failed"
    assert "deterministic_proofs" not in issue
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_asan_allocation_limit_stays_undecided(tmp_path: Path) -> None:
    compiler = _require_sanitizer("asan")
    binary = tmp_path / "oversize"
    _compile("allocation_oversize.c", binary, "asan", compiler)

    issue = _issue(
        "allocation_oversize.c",
        function="zscope_dynamic_repro_allocate",
        defect_class="unbounded_allocation",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary), str(1024 * 1024 * 1024)),
        run_cwd=tmp_path,
        memory_limit_mb=512,
        max_replays=1,
    )

    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_allocation_limit"] = record.to_dict()
    assert record.outcome == "engine_failed", record.stderr_excerpt
    assert record.detail == "resource_exhaustion"
    assert record.oom_killed is True
    assert "memory_limit_enforced_by_sanitizer_allocation_cap" in record.limitations

    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=None, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "failed"
    assert deterministic_decision_proof(issue, outcome="reject") is None
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_asan_stale_binary_reference_never_launches(tmp_path: Path) -> None:
    compiler = _require_sanitizer("asan")
    binary = tmp_path / "positive"
    _compile("heap_overflow_positive.c", binary, "asan", compiler)

    issue = _issue(
        "heap_overflow_positive.c",
        function="zscope_dynamic_repro_positive",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest="0" * 64,  # declared identity from an older build
        run_argv=(str(binary), "64"),
        run_cwd=tmp_path,
    )

    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_stale_binary"] = record.to_dict()
    # The declaration no longer matches the file, so the stale binary is never
    # executed at all: there is no run whose output could be misread.
    assert record.outcome == "unsupported"
    assert record.detail == "plan_identity_unverified"
    assert "binary_identity_mismatch" in record.limitations
    assert "unverified_plan_never_launched" in record.limitations
    assert record.runs == ()
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=None, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert outcome.result.outcome == "inconclusive"


def test_asan_net_namespace_wrap_is_reported_truthfully(tmp_path: Path) -> None:
    compiler = _require_sanitizer("asan")
    binary = tmp_path / "positive"
    _compile("heap_overflow_positive.c", binary, "asan", compiler)

    issue = _issue(
        "heap_overflow_positive.c",
        function="zscope_dynamic_repro_positive",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary), "64"),
        run_cwd=tmp_path,
        isolation="user_net_namespace",
    )
    record = _runner("asan", compiler).execute(plan)
    _OBSERVED["asan_namespace"] = record.to_dict()

    if "net_namespace_applied" in record.isolation_notes:
        assert record.isolation == "user_net_namespace"
        assert record.outcome == "witness_observed", record.stderr_excerpt
    else:
        # A requested boundary that cannot be provided stops the plan: the run is
        # never executed without the isolation it asked for.
        assert record.outcome == "unsupported"
        assert record.detail == "requested_isolation_unavailable"
        assert record.isolation == "process"
        assert record.isolation_verified is False
        assert "requested_isolation_not_applied" in record.limitations
        assert record.runs == ()
        assert "net_namespace_unavailable" in record.isolation_notes or (
            "net_namespace_probe_failed" in record.isolation_notes
        )
    assert "subprocess_is_not_a_container_sandbox" in record.isolation_notes


# --------------------------------------------------------------------------
# V02: ThreadSanitizer
# --------------------------------------------------------------------------


def test_tsan_positive_fixture_confirms_through_shared_adjudication(tmp_path: Path) -> None:
    compiler = _require_sanitizer("tsan")
    binary = tmp_path / "race"
    _compile("data_race_positive.c", binary, "tsan", compiler)
    digest, _ = hash_file(binary)

    issue = _issue(
        "data_race_positive.c",
        function="zscope_race_writer",
        defect_class="race_without_happens_before",
        object_identity="shared_counter",
    )
    plan = _plan(
        issue,
        kind="tsan",
        compiler=compiler,
        binary=binary,
        binary_digest=digest,
        run_argv=(str(binary),),
        run_cwd=tmp_path,
    )

    record = _runner("tsan", compiler).execute(plan)
    _OBSERVED["tsan_positive"] = record.to_dict()
    assert record.outcome == "witness_observed", _tsan_diagnosis(record.stderr_excerpt)
    finding = record.findings[0]
    assert finding.kind == "data-race"
    assert finding.object_ref == "shared_counter"

    replay = replay_witness(plan, _runner("tsan", compiler), times=2)
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=record, replay=replay, policy=_policy()
    )
    assert outcome.proof_attached is True
    decision = ValidationPipeline(None).apply_deterministic_prevalidation(
        issue, {"final_score": 0.9}
    )
    assert decision is not None and decision.report_bucket == "issues"
    assert issue["candidate_disposition"] == "confirmed"


def test_tsan_negative_fixture_is_not_reproduced(tmp_path: Path) -> None:
    compiler = _require_sanitizer("tsan")
    binary = tmp_path / "locked"
    _compile("data_race_negative.c", binary, "tsan", compiler)

    issue = _issue(
        "data_race_negative.c",
        function="zscope_race_writer",
        defect_class="race_without_happens_before",
        object_identity="shared_counter",
        marker="ZSCOPE_SAFE_SITE",
    )
    plan = _plan(
        issue,
        kind="tsan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary),),
        run_cwd=tmp_path,
        max_replays=1,
    )
    record = _runner("tsan", compiler).execute(plan)
    _OBSERVED["tsan_negative"] = record.to_dict()
    assert record.outcome == "not_reproduced", _tsan_diagnosis(record.stderr_excerpt)
    assert record.findings == ()
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_tsan_memory_limit_is_recorded_as_an_actual_bound(tmp_path: Path) -> None:
    """A limit must be reported as what was really enforced, not implied away."""

    compiler = _require_sanitizer("tsan")
    binary = tmp_path / "locked-mem"
    _compile("data_race_negative.c", binary, "tsan", compiler)

    issue = _issue(
        "data_race_negative.c",
        function="zscope_race_writer",
        defect_class="race_without_happens_before",
        object_identity="shared_counter",
        marker="ZSCOPE_SAFE_SITE",
    )
    plan = _plan(
        issue,
        kind="tsan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary),),
        run_cwd=tmp_path,
        memory_limit_mb=512,
        max_replays=1,
    )
    record = _runner("tsan", compiler).execute(plan)
    _OBSERVED["tsan_memory_limit"] = record.to_dict()
    # TSAN cannot take RLIMIT_AS and its own cap is not a total-memory limit, so
    # the bound really applied is the sampled resident-set watchdog - and the
    # record says that it is sampled rather than a kernel limit.
    assert record.memory_limit_mode == "rss_watchdog"
    assert "memory_limit_enforced_by_rss_watchdog" in record.limitations
    assert "rss_watchdog_is_sampled_not_a_kernel_limit" in record.limitations
    assert "memory_limit_not_enforced_for_tsan" not in record.limitations


def test_tsan_memory_limit_without_a_limit_is_reported_as_not_enforced(
    tmp_path: Path,
) -> None:
    compiler = _require_sanitizer("tsan")
    binary = tmp_path / "unlimited-mem"
    _compile("data_race_negative.c", binary, "tsan", compiler)

    issue = _issue(
        "data_race_negative.c",
        function="zscope_race_writer",
        defect_class="race_without_happens_before",
        object_identity="shared_counter",
        marker="ZSCOPE_SAFE_SITE",
    )
    plan = _plan(
        issue,
        kind="tsan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary),),
        run_cwd=tmp_path,
        memory_limit_mb=0,
        max_replays=1,
    )
    record = _runner("tsan", compiler).execute(plan)
    _OBSERVED["tsan_memory_limit_unset"] = record.to_dict()
    assert record.memory_limit_mode == "none"
    assert "memory_limit_not_enforced_for_tsan" in record.limitations


def test_rss_watchdog_records_and_kills_a_memory_hog(tmp_path: Path) -> None:
    """A run that exceeds the declared resident set is stopped and recorded."""

    if not Path("/proc/self/status").exists():
        pytest.skip("resident-set watchdog requires /proc")
    # A real process that really grows past the declared ceiling: the plan's
    # harness/input identity is the fixture it is derived from, and the executed
    # program is a shell that would keep running if it were not stopped.
    issue = _issue(
        "heap_overflow_positive.c",
        function="zscope_dynamic_repro_positive",
        defect_class="heap_buffer_overflow",
    )
    plan = _plan(
        issue,
        kind="asan",
        compiler="/bin/sh",
        binary=Path("/bin/sh"),
        binary_digest=hash_file("/bin/sh")[0],
        run_argv=(
            "/bin/sh",
            "-c",
            "python3 -c \"a=bytearray(400*1024*1024); print(len(a)); "
            "import time; time.sleep(5)\"",
        ),
        run_cwd=tmp_path,
        memory_limit_mb=64,
        timeout_seconds=60,
        max_replays=1,
    )
    record = SanitizerReproductionRunner(
        "asan", policy=_policy(rss_poll_seconds=0.01)
    ).execute(plan)
    _OBSERVED["rss_watchdog"] = record.to_dict()
    assert record.memory_limit_mode == "sanitizer_allocation_cap"
    assert record.outcome == "engine_failed"
    assert record.classification == "engine_failed:resource_exhaustion"
    assert record.detail == "resource_exhaustion"
    assert record.runs[0].oom_killed is True
    assert "memory_limit_enforced_by_rss_watchdog" in record.limitations
    assert "memory_limit_total_rss_watchdog_applied" in record.limitations


def test_tsan_flaky_fixture_distribution_is_recorded_and_never_forced(tmp_path: Path) -> None:
    """A timing-dependent sample must be measured, never assumed."""

    compiler = _require_sanitizer("tsan")
    binary = tmp_path / "flaky"
    _compile("data_race_flaky.c", binary, "tsan", compiler)

    issue = _issue(
        "data_race_flaky.c",
        function="zscope_flaky_reader",
        defect_class="race_without_happens_before",
        object_identity="shared_slot",
    )
    plan = _plan(
        issue,
        kind="tsan",
        compiler=compiler,
        binary=binary,
        binary_digest=hash_file(binary)[0],
        run_argv=(str(binary),),
        run_cwd=tmp_path,
        max_replays=1,
    )

    # Ten single-run samples: the ratio varies by machine, so the evidence
    # records what actually happened rather than asserting a rate.
    classifications = []
    for _ in range(10):
        record = _runner("tsan", compiler).execute(plan)
        classifications.append(record.classification)
        assert record.outcome in {
            "witness_observed",
            "not_reproduced",
            "inconclusive",
            "engine_failed",
        }
        assert record.outcome != "not_reproduced" or record.detail == "no_sanitizer_report"
    assert set(classifications) <= {"data-race", "none", "engine_failed:timeout"}
    _OBSERVED["tsan_flaky"] = {
        "classifications": classifications,
        "data_race_runs": classifications.count("data-race"),
        "no_report_runs": classifications.count("none"),
        "observed_non_deterministic": len(set(classifications)) > 1,
    }

    # Several *independent* real executions of the same plan: if the sample really
    # varies, the replay evidence is inconsistent and the candidate must stay
    # unconfirmed even though a single run did observe the report. There is no
    # longer a multi-run measure inside one record, so the non-determinism is
    # measured where it actually lives.
    multi_plan = dataclasses.replace(plan, max_replays=8)
    mixed = None
    record = None
    replay = None
    for _ in range(6):
        record = _runner("tsan", compiler).execute(multi_plan)
        replay = replay_witness(
            multi_plan,
            _runner("tsan", compiler),
            times=7,
            policy=_policy(),
        )
        assert len(replay.runs) == 7
        assert replay.consistent == (len(set(replay.classifications)) == 1)
        if record.outcome == "witness_observed" and not replay.consistent:
            mixed = (record, replay)
            break
    _OBSERVED["tsan_flaky_multi_replay"] = replay.to_dict() if replay else {}
    _OBSERVED["tsan_flaky_mixed_observed"] = mixed is not None
    if mixed is not None:
        mixed_record, mixed_replay = mixed
        outcome = register_dynamic_reproduction(
            issue,
            plan=multi_plan,
            record=mixed_record,
            replay=mixed_replay,
            policy=_policy(),
        )
        assert "replay_inconsistent" in outcome.qualification.reasons
        assert outcome.qualification.qualified is False
        assert outcome.proof_attached is False
        assert outcome.result.outcome == "inconclusive"
        assert deterministic_decision_proof(issue, outcome="confirm") is None

    # Independently of what the machine did, a mixed replay set is inconclusive.
    sample = _runner("tsan", compiler).execute(plan)
    mixed = dataclasses.replace(
        sample,
        outcome="witness_observed",
        replay_classifications=("data-race", "none"),
        replay_count=2,
    )
    assert mixed.replay_consistent is False
    outcome = register_dynamic_reproduction(
        issue, plan=plan, record=mixed, replay=None, policy=_policy()
    )
    assert outcome.proof_attached is False
    assert set(outcome.qualification.reasons) & {
        "independent_replay_missing",
        "record_replay_inconsistent",
        "execution_receipt_record_mismatch",
    }


def _tsan_diagnosis(text: str) -> str:
    """Surface the common TSAN start-up failure so the record can state it."""

    lowered = text.lower()
    for marker in (
        "unexpected memory mapping",
        "failed to allocate",
        "unable to mmap",
        "thread sanitizer",
    ):
        if marker in lowered:
            return text[-600:]
    return text[-600:] or "no TSAN output"


def _compile_argv(name: str, binary: Path, kind: str, compiler: str) -> tuple[str, ...]:
    argv: list[str] = [
        compiler,
        f"-fsanitize={'address' if kind == 'asan' else 'thread'}",
        "-g",
        "-O0",
        "-fno-omit-frame-pointer",
    ]
    if kind == "tsan":
        argv.extend(["-std=c11", "-pthread"])
    argv.extend(["-o", str(binary), str(FIXTURE_DIR / name)])
    return tuple(argv)


def test_observed_execution_evidence_is_dumpable() -> None:
    """Real runs above leave records; dump them when a run asks for evidence.

    The evidence path is opt-in so an ordinary pytest run never writes into the
    repository; the acceptance script sets it to the handoff records directory.
    """

    raw = os.environ.get("ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE", "")
    if not raw:
        pytest.skip("ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE is not set")
    if not _OBSERVED:
        pytest.skip("no real execution ran in this session")
    target = Path(raw)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(_OBSERVED, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert target.exists()
