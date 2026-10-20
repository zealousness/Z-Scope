"""Freeze Stage deltas for source review while tests temporarily edit inputs."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/stage-source-inputs-r32-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


intake_path = ROOT / "artifacts/s01-stage-intake-r32-20261017/receipt.json"
intake = read(intake_path)
stage_inputs = intake["stage_source_after"]
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
changed = {path: digest for path, digest in stage_inputs.items() if root_inputs.get(path) != digest}
assert all(sha(STAGE / path) == digest for path, digest in stage_inputs.items())
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
OUT.mkdir(exist_ok=False)
before = {}
for path, digest in changed.items():
    target = OUT / "candidate" / path
    assert target.resolve().is_relative_to(OUT.resolve())
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGE / path, target)
    assert sha(target) == digest
    if path in root_inputs:
        old = OUT / "root-baseline" / path
        old.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, old)
        before[path] = sha(old)
        assert before[path] == root_inputs[path]
proof = dict(frozen_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), actual_task="/root", stage_workspace=STAGE.relative_to(ROOT).as_posix(), stage_input_count=len(stage_inputs), root_input_count=len(root_inputs), stage_source_sha256=stage_inputs, changed_sources_sha256=changed, changed_root_baseline_sha256=before, intake=intake_path.relative_to(ROOT).as_posix(), intake_sha256=sha(intake_path), source_review_inputs_readonly=True, original_stage_tests_may_temporarily_edit_and_restore_inputs=True, product_source_mutations=False, root_intake=False)
(OUT / "manifest.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "manifest.json").relative_to(ROOT).as_posix(), changed_paths=len(changed), frozen_stage_inputs=len(stage_inputs))))
