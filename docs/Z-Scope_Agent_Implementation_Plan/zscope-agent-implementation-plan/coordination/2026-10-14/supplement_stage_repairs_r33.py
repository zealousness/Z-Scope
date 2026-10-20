"""Add immutable non-product materials omitted by the Stage source projection."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

prep = read(OUT / "preparation.json")
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
stage_sources = read(ROOT / "artifacts/stage-source-inputs-r32-20261017/manifest.json")["stage_source_sha256"]
supplemental = {path: digest for path, digest in root_inputs.items() if path not in stage_sources}
assert len(supplemental) == 108
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert all(sha(STAGE / path) == digest for path, digest in supplemental.items())
result = {}
for name, value in prep["candidates"].items():
    work = ROOT / value["workspace"]
    copied, existing = {}, {}
    for path, digest in supplemental.items():
        target = work / path
        assert target.resolve().is_relative_to(work.resolve())
        if target.exists():
            assert target.is_file() and sha(target) == digest
            existing[path] = digest
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
            assert sha(target) == digest
            copied[path] = digest
    assert len(copied) == 106 and len(existing) == 2
    assert all(sha(work / path) == digest for path, digest in supplemental.items())
    result[name] = dict(workspace=value["workspace"], copied_readonly=copied, existing_readonly=existing, supplemental_baseline=supplemental, complete_candidate_baseline=stage_sources | supplemental, expected_complete_baseline_count=1077, original_preparation_unchanged=True, owned_paths_unchanged=value["owned_paths"])
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert all(sha(STAGE / path) == digest for path, digest in supplemental.items())
receipt = dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), root_input_count=1065, original_stage_projection_count=969, supplemental_count=108, stage_supplemental_sha256=supplemental, stage_supplemental_all_match_frozen_root=True, candidates=result, no_owned_source_or_test_modified=True, no_stage_product_write=True, root_intake=False, prior_receipts_unchanged=True, reason="R32 launcher omitted guard for actual Stage supplemental copies, including 32 relative selected tests; subsequent validation must protect all real candidate inputs")
write(OUT / "supplemental-inputs.json", receipt)
print(json.dumps(dict(receipt=(OUT / "supplemental-inputs.json").relative_to(ROOT).as_posix(), copied_each=106, complete_baseline_count=1077)))
