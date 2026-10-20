"""Reconstruct two isolated candidates from the immutable R32 Stage manifest."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
INPUTS = ROOT / "artifacts/stage-source-inputs-r32-20261017"
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

manifest = read(INPUTS / "manifest.json")
intake = read(ROOT / manifest["intake"])
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
sources = manifest["stage_source_sha256"]
configs = intake["configuration_baseline"]
assert len(sources) == 969
assert all(sha(STAGE / path) == digest for path, digest in configs.items())
specs = {
    "stage-currentness-repair-r33": ["zscope/orchestration/instance_semantics_context.py", "tests/test_instance_currentness_revocation_r33.py"],
    "stage-cost-repair-r33": ["zscope/orchestration/parallel_analyzer.py", "tests/test_instance_recovery_cost_r33.py"],
}
OUT.mkdir(exist_ok=False)
prepared = {}
for name, owned in specs.items():
    work = ROOT / ".coordination/20261014/workspaces" / name
    work.mkdir(exist_ok=False)
    for path, digest in sources.items():
        source = INPUTS / "candidate" / path if path in manifest["changed_sources_sha256"] else ROOT / path
        assert sha(source) == digest, path
        target = work / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        assert sha(target) == digest
    for path, digest in configs.items():
        target = work / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(STAGE / path, target)
        assert sha(target) == digest
    shutil.copyfile(ROOT / "AGENTS.md", work / "AGENTS.md")
    prepared[name] = dict(workspace=work.relative_to(ROOT).as_posix(), owned_paths=owned, baseline_sources=sources, configuration_baseline=configs, extra_readonly={"AGENTS.md": sha(work / "AGENTS.md")}, frozen_stage_manifest_sha256=sha(INPUTS / "manifest.json"), root_unchanged=True, live_stage_source_not_copied=True)
write(OUT / "preparation.json", dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), candidates=prepared, root_intake=False, stage_product_mutations=False, prior_s01_bounded_module_acceptance_unchanged=True))
print(json.dumps(dict(receipt=(OUT / "preparation.json").relative_to(ROOT).as_posix(), candidates=list(prepared))))
