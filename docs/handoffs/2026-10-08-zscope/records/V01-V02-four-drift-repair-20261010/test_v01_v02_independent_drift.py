"""Independent file-drift acceptance checks: fake executions only."""
import runpy
from pathlib import Path
import pytest
from zscope.core.validation import dynamic_reproduction as d
from zscope.core.validation.proofs import deterministic_decision_proof

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
H = runpy.run_path(str(ROOT / "tests/test_dynamic_reproduction.py"))

@pytest.fixture(autouse=True)
def clear_capabilities():
    d.witness_authority_clear()
    yield
    d.witness_authority_clear()

def context(tmp_path):
    source, digest = H["_owned_source"](tmp_path)
    binary = tmp_path / "fake-program"
    binary.write_bytes(b"fake executable identity; never launched")
    issue = H["_issue"](location=f"{source}:1", resource_identity="subject",
                        source_revision=digest, dependency_code_hash=digest)
    plan = H["_plan"](issue, harness_ref=str(source), harness_digest=digest,
                      binary_path=str(binary), binary_digest=d.hash_file(binary)[0],
                      run_argv=(str(binary),), run_cwd=str(tmp_path))
    finding = H["_finding"](site=f"{source}:1", frames=(f"subject {source}:1",))
    scripted = H["_witness_run"](findings=(finding,))
    record = d.FakeDynamicReproductionRunner([scripted]).execute(plan)
    replay = d.replay_witness(plan, d.FakeDynamicReproductionRunner([scripted]), times=2)
    H["_promote_production"](record, replay)
    assert d.qualify_witness(plan.binding, plan, record, replay=replay,
                             policy=H["_policy"]()).qualified
    return source, binary, issue, plan, record, replay

@pytest.mark.parametrize("change", ["mutate", "delete"])
def test_drift_between_last_execution_and_registration_never_confirms(tmp_path, change):
    source, binary, issue, plan, record, replay = context(tmp_path)
    if change == "mutate":
        source.write_text("int subject(void){return 1;}\n", encoding="utf-8")
    else:
        source.unlink()
    d.register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay,
                                    policy=H["_policy"]())
    assert deterministic_decision_proof(issue, outcome="confirm") is None, (
        "current source changed after execution but before proof registration"
    )

@pytest.mark.parametrize("change", ["mutate", "delete"])
def test_binary_drift_after_registration_revokes_confirmation(tmp_path, change):
    source, binary, issue, plan, record, replay = context(tmp_path)
    d.register_dynamic_reproduction(issue, plan=plan, record=record, replay=replay,
                                    policy=H["_policy"]())
    assert deterministic_decision_proof(issue, outcome="confirm") is not None
    if change == "mutate":
        binary.write_bytes(b"changed fake executable identity; never launched")
    else:
        binary.unlink()
    assert deterministic_decision_proof(issue, outcome="confirm") is None, (
        "registered proof survived an actual binary-file change"
    )

