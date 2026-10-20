"""Second independent acceptance round, 2026-10-09.

These are required-invariant assertions, not xfails. No vulnerable fixture runs
in this file. Explicit test authority is used only for valid positive controls.
"""
import dataclasses
import hashlib
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from zscope.common.cancellation import CancellationError, CancellationToken, bind_cancellation_token
from zscope.core.validation import dynamic_reproduction as d
from zscope.core.validation.proofs import deterministic_decision_proof

ROOT = Path(__file__).resolve().parents[4]
H = runpy.run_path(str(ROOT / "tests/test_dynamic_reproduction.py"))


@pytest.fixture(autouse=True)
def clear_authority():
    d.witness_authority_clear()
    d.register_dynamic_reproduction_plan_provider(None)
    yield
    d.witness_authority_clear()
    d.register_dynamic_reproduction_plan_provider(None)


def promote(record, replay, *, include_replays=True):
    d.inject_test_execution_authority(record.attestation, reason="independent deterministic positive control")
    if include_replays:
        for run in replay.runs:
            d.inject_test_execution_authority(run.execution_token, reason="independent deterministic positive control")


def context(tmp_path, *, promote_replays=True):
    source = tmp_path / "owned.c"
    source.write_text("int subject(void){return 0;}\n", encoding="utf-8")
    digest = d.hash_file(source)[0]
    issue = H["_issue"](location=f"{source}:1", resource_identity="subject",
                         source_revision=digest, dependency_code_hash=digest)
    plan = H["_plan"](issue, harness_ref=str(source), harness_digest=digest)
    finding = H["_finding"](site=f"{source}:1", frames=(f"subject {source}:1",))
    scripted = H["_witness_run"](findings=(finding,))
    record = d.FakeDynamicReproductionRunner([scripted]).execute(plan)
    replay = d.replay_witness(plan, d.FakeDynamicReproductionRunner([scripted]), times=2)
    promote(record, replay, include_replays=promote_replays)
    return source, issue, plan, record, replay


@pytest.mark.parametrize("candidate,reported", [
    ("shared_counter", "shared_counter_backup"),
    ("shared_counter_backup", "shared_counter"),
    ("buffer", "other_buffer"),
    ("obj.field", "obj_field"),
])
def test_similar_named_resources_are_not_the_same_object(candidate, reported):
    binding = d.bind_candidate(H["_issue"](resource_identity=candidate))
    finding = dataclasses.replace(H["_finding"](), object_ref=reported)
    assert not d.match_witness_to_candidate(binding, finding)[0]


def test_filesystem_source_change_revokes_live_confirmation(tmp_path):
    source, issue, plan, record, replay = context(tmp_path)
    d.register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=H["_policy"]())
    assert deterministic_decision_proof(issue, outcome="confirm") is not None
    source.write_text("int subject(void){return 1;}\n", encoding="utf-8")
    # No upstream pass has refreshed the issue mapping yet. Current source must
    # still be checked or frozen by the final confirmation boundary.
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_untrusted_fake_replays_cannot_complete_production_confirmation(tmp_path):
    _, issue, plan, record, replay = context(tmp_path, promote_replays=False)
    assert d.EXECUTION_AUTHORITY.entry(record.attestation).production
    assert all(not d.EXECUTION_AUTHORITY.entry(run.execution_token).production for run in replay.runs)
    d.register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay, policy=H["_policy"]())
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_every_primary_run_must_match_the_candidate(tmp_path):
    _, issue, plan, record, replay = context(tmp_path)
    correct = record.findings[0]
    wrong = dataclasses.replace(correct, site="other.c:999", source_mapping=("other.c:999",))
    runs = (
        d.RunEvidence(index=0, outcome="observed", classifications=(correct.kind,), findings=(correct,)),
        d.RunEvidence(index=1, outcome="observed", classifications=(wrong.kind,), findings=(wrong,)),
    )
    updated = dataclasses.replace(record, runs=runs, attestation="")
    updated = d.FakeDynamicReproductionRunner([]).register_execution(updated, plan=plan)
    promote(updated, replay)
    result = d.register_dynamic_reproduction(issue, plan=plan, record=updated, replay=replay, policy=H["_policy"]())
    assert not result.qualification.qualified


@pytest.mark.parametrize("changed", ["harness", "input", "binary"])
def test_each_execution_revalidates_current_files(tmp_path, monkeypatch, changed):
    harness = tmp_path / "harness.c"
    harness.write_text("int main(void){return 0;}\n")
    input_file = tmp_path / "input.txt"
    input_file.write_text("first input")
    binary = tmp_path / "program"
    binary.write_bytes(Path("/bin/true").read_bytes())
    plan = H["_plan"](
        H["_issue"](), provider_kind="asan", provider_name="asan-runner", max_replays=2,
        harness_ref=str(harness), harness_digest=d.hash_file(harness)[0],
        input_refs=(str(input_file),), input_digests=(d.hash_file(input_file)[0],),
        binary_path=str(binary), binary_digest=d.hash_file(binary)[0],
        run_argv=(str(binary),), run_cwd=str(tmp_path),
    )
    runner = d.SanitizerReproductionRunner("asan", policy=H["_policy"]())
    calls = []
    def once(**kwargs):
        calls.append(kwargs)
        target = {"harness": harness, "input": input_file, "binary": binary}[changed]
        target.write_bytes(target.read_bytes() + b"changed")
        return d._RunResult(0, "", b"", "", b"", False)
    monkeypatch.setattr(runner, "_run_once", once)
    runner.execute(plan)
    assert len(calls) == 1


def test_build_cannot_change_verified_source_before_run(tmp_path, monkeypatch):
    harness = tmp_path / "harness.c"
    harness.write_text("int main(void){return 0;}\n")
    plan = H["_plan"](
        H["_issue"](), provider_kind="asan", provider_name="asan-runner", max_replays=1,
        harness_ref=str(harness), harness_digest=d.hash_file(harness)[0],
        binary_digest=d.hash_file("/bin/true")[0], run_cwd=str(tmp_path),
        build=d.BuildSpec(argv=("/bin/true",), cwd=str(tmp_path)),
    )
    runner = d.SanitizerReproductionRunner("asan", policy=H["_policy"]())
    calls = []
    def once(**kwargs):
        calls.append(kwargs["tag"])
        if kwargs["tag"] == "build":
            harness.write_text("changed by build\n")
        return d._RunResult(0, "", b"", "", b"", False)
    monkeypatch.setattr(runner, "_run_once", once)
    runner.execute(plan)
    assert calls == ["build"]


def test_default_product_entry_selects_tsan_provider(monkeypatch):
    issue = H["_issue"]()
    plan = H["_plan"](issue, provider_kind="tsan", provider_name="fake-tsan-runner")
    made = []
    class Provider(d.FakeDynamicReproductionRunner):
        def execute(self, value):
            if self.kind != value.provider_kind:
                raise d.DynamicReproductionError("provider_plan_kind_mismatch")
            return super().execute(value)
    def factory(kind):
        def make(**kwargs):
            made.append(kind)
            return Provider([d.FakeRun(outcome="not_reproduced")], kind=kind)
        return make
    monkeypatch.setattr(d, "AsanReproductionRunner", factory("asan"))
    monkeypatch.setattr(d, "TsanReproductionRunner", factory("tsan"))
    try:
        d.run_dynamic_reproduction(issue, plan, policy=H["_policy"]())
    except d.DynamicReproductionError:
        pass
    assert made == ["tsan"]


def test_execution_budget_counts_primary_and_independent_runs(tmp_path, monkeypatch):
    issue = H["_issue"]()
    plan = H["_plan"](
        issue, provider_kind="asan", provider_name="asan-runner",
        binary_digest=d.hash_file("/bin/true")[0], run_cwd=str(tmp_path), max_replays=2,
    )
    runner = d.SanitizerReproductionRunner("asan", policy=H["_policy"]())
    site_file, line = plan.binding.site_file, plan.binding.site_line
    raw = (f"ERROR: AddressSanitizer: heap-buffer-overflow\n"
           f"WRITE of size 1 at 0x6020000000f0 thread T0\n"
           f"    #0 0x123 in zscope_dynamic_repro_positive {site_file}:{line}\n"
           f"SUMMARY: AddressSanitizer: heap-buffer-overflow\n").encode()
    calls = []
    def once(**kwargs):
        calls.append(kwargs)
        return d._RunResult(1, "", b"", hashlib.sha256(raw).hexdigest(), raw, False)
    monkeypatch.setattr(runner, "_run_once", once)
    d.run_dynamic_reproduction(issue, plan, runner=runner, policy=H["_policy"]())
    assert len(calls) <= plan.max_replays


def test_published_artifacts_survive_next_execution_of_same_plan(tmp_path):
    plan = H["_process_plan"](tmp_path, "date +%s%N")
    runner = d.SanitizerReproductionRunner("asan", policy=H["_policy"](artifact_dir=str(tmp_path/"artifacts")))
    first = runner.execute(plan)
    assert first.outcome == "not_reproduced"
    before = {ref: d.hash_file(ref)[0] for ref in first.artifact_refs}
    assert before
    second = runner.execute(plan)
    assert second.outcome == "not_reproduced"
    assert all(d.hash_file(ref)[0] == digest for ref, digest in before.items())


def test_already_cancelled_execution_does_not_spawn(tmp_path, monkeypatch):
    token = CancellationToken()
    token.cancel("cancel before launch")
    calls = []
    class Finished:
        pid = 1
        returncode = 0
        def poll(self):
            return 0
    monkeypatch.setattr(d.subprocess, "Popen", lambda *a, **kw: calls.append((a,kw)) or Finished())
    runner = d.SanitizerReproductionRunner("asan", policy=H["_policy"]())
    with bind_cancellation_token(token):
        try:
            runner._run_once(argv=("/bin/true",), cwd=str(tmp_path), env={},
                             timeout_seconds=1, address_space_limit_mb=0,
                             tag="cancelled", workdir=str(tmp_path))
        except CancellationError:
            pass
    assert calls == []


def test_disabled_validation_import_does_not_require_posix_resource():
    code = """import sys, importlib.abc
class MissingResource(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'resource':
            raise ModuleNotFoundError('simulated platform without resource', name='resource')
sys.meta_path.insert(0, MissingResource())
import zscope.core.validation.runner
"""
    ran = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert ran.returncode == 0, ran.stderr
