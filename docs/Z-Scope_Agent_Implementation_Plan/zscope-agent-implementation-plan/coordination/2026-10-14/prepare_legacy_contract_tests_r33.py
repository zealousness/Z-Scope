"""Correct stale test inputs in a separate coordinator-owned complete candidate."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-contract-tests-r33"
OUT = ROOT / "artifacts/coordinator-contract-tests-r33-20261017"
FOLLOWUP = "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12/test_scan_checkpoint_dependency_boundary.py"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


inputs = read(ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/supplemental-inputs.json")["candidates"]["stage-currentness-repair-r33"]["complete_candidate_baseline"]
assert len(inputs) == 1077 and all(sha(STAGE / path) == digest for path, digest in inputs.items())
assert not WORK.exists() and not OUT.exists()
WORK.mkdir()
OUT.mkdir()
owned = ["tests/test_parallel_shared_semantics.py", "tests/test_raii_lifecycle.py", "tests/test_rule_cli.py", FOLLOWUP]
ownership = dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", observed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), owner="coordinator", isolated_workspace=WORK.relative_to(ROOT).as_posix(), added_paths=owned, writes_only_isolated_until_independent_review=True, active_native_worker_paths_disjoint=True, production_fingerprint_rule_catalog_unchanged=True, stage_write=False, root_write=False, reason="R32 actual failures: three catalog revisions stale and three mandatory semantics inputs absent in synthetic fingerprint probes")
extension = HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-08.json"
assert not extension.exists()
write(extension, ownership)
for path in inputs:
    target = WORK / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGE / path, target)
before = {path: sha(WORK / path) for path in owned}
revisions = {
    "tests/test_parallel_shared_semantics.py": ('assert candidate_payload["rule_revision"] == 6', 'assert candidate_payload["rule_revision"] == 7'),
    "tests/test_raii_lifecycle.py": ('assert candidate["rule_revision"] == 10', 'assert candidate["rule_revision"] == 11'),
    "tests/test_rule_cli.py": ('assert payload["rule"]["revision"] == 8', 'assert payload["rule"]["revision"] == 9'),
}
for path, (old, new) in revisions.items():
    source = (WORK / path).read_text(encoding="utf-8")
    assert source.count(old) == 1
    (OUT / (Path(path).name + ".before")).write_text(source, encoding="utf-8", newline="\n")
    (WORK / path).write_text(source.replace(old, new), encoding="utf-8", newline="\n")
    assert source.replace(old, new) == (WORK / path).read_text(encoding="utf-8")
source = (WORK / FOLLOWUP).read_text(encoding="utf-8")
assert source.count("compute_plan_fingerprint(plan, config)") == 5
original_asserts = [ast.dump(node) for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Assert)]
(OUT / "test_scan_checkpoint_dependency_boundary.py.before").write_text(source, encoding="utf-8", newline="\n")
source = source.replace("from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint", "from zscope.orchestration.jobs.scan_work import compute_plan_fingerprint\nfrom zscope.orchestration.instance_semantics_context import SEMANTICS_POLICY\nfrom zscope.retrieval.instance_index import instance_scope_from_entry_instance")
helper = '''\n\ndef fingerprint(plan, config):
    # Synthetic plan metadata only: no semantic effects or persisted reuse are
    # authorized by this dependency-digest test. The mandatory production map
    # is explicit and matches every planned exact scope; no empty-map fallback.
    semantics = {}
    for instance in plan.instances:
        scope = instance_scope_from_entry_instance(instance)
        semantics[scope.identity] = SimpleNamespace(
            scope=scope,
            authority_policy=SEMANTICS_POLICY,
            schema="zscope.instance-semantics.v1",
            digest="synthetic-dependency-probe",
        )
    return compute_plan_fingerprint(plan, config, semantics_by_instance=semantics)
'''
source = source.replace("\n\ndef setup(", helper + "\n\ndef setup(")
source = source.replace("compute_plan_fingerprint(plan, config)", "fingerprint(plan, config)")
expected_asserts = [value.replace("id='compute_plan_fingerprint'", "id='fingerprint'") for value in original_asserts]
actual_asserts = [ast.dump(node) for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Assert)]
assert actual_asserts == expected_asserts
(WORK / FOLLOWUP).write_text(source, encoding="utf-8", newline="\n")
after = {path: sha(WORK / path) for path in owned}
assert all(sha(STAGE / path) == digest for path, digest in inputs.items())
write(OUT / "preparation.json", dict(actual_task="/root", prepared_at=ownership["observed_at"], complete_baseline=inputs, owned_paths=owned, before_sha256=before, candidate_sha256=after, ownership_extension=extension.relative_to(ROOT).as_posix(), production_changed=False, assertions_preserved_except_exact_current_revision_literals=True, fingerprint_probe_original_assertions_preserved=True, synthetic_metadata_only=True, stage_intake=False, root_intake=False))
print(json.dumps(dict(workspace=WORK.relative_to(ROOT).as_posix(), owned=after)))
