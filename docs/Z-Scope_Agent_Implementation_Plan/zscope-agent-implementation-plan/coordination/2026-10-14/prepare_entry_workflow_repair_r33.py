"""Coordinator-owned correction to the actual entry workflow closure projection."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
INPUTS = ROOT / "artifacts/stage-source-inputs-r32-20261017"
OUT = ROOT / "artifacts/coordinator-entry-workflow-repair-r33-20261017"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

manifest = json.loads((INPUTS / "manifest.json").read_text(encoding="utf-8"))
replacements = {
    "zscope/core/analysis/analyzer.py": [
        ("from ...orchestration.workflow_executor import WorkflowExecutor, WorkflowStepHandler\n", "from ...orchestration.workflow_executor import (\n    WorkflowExecutor,\n    WorkflowStepHandler,\n    workflow_steps_for_scope,\n)\n"),
        ("        selected = [step.id for step in self._selected_workflow_steps()]\n", "        selected = [\n            step.id\n            for step in workflow_steps_for_scope(self._selected_workflow_steps(), \"entry\")\n        ]\n"),
    ],
    "tests/test_instance_semantics_integration.py": [
        ("        SimpleNamespace(id=identity) for identity in DEFAULT_SCAN_STEP_IDS\n", "        SimpleNamespace(id=identity, scope=\"entry\") for identity in DEFAULT_SCAN_STEP_IDS\n"),
    ],
}
OUT.mkdir(exist_ok=False)
before, after = {}, {}
for relative, edits in replacements.items():
    source = INPUTS / "candidate" / relative
    assert sha(source) == manifest["stage_source_sha256"][relative]
    original = source.read_text(encoding="utf-8")
    changed = original
    for old, new in edits:
        assert changed.count(old) == 1, relative
        changed = changed.replace(old, new)
    if relative.startswith("tests/"):
        assertions = lambda text: [ast.dump(node, include_attributes=False) for node in ast.walk(ast.parse(text)) if isinstance(node, ast.Assert)]
        assert assertions(original) == assertions(changed)
    for folder, text in (("before", original), ("candidate", changed)):
        target = OUT / folder / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    before[relative] = sha(OUT / "before" / relative)
    after[relative] = sha(OUT / "candidate" / relative)
receipt = dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), logical_task="COORD-ENTRY-WORKFLOW-CLOSURE-R33", root_cause="Analyzer compared all session+entry steps against the four entry step IDs, while actual WorkflowExecutor executes the entry-scope projection", before_sha256=before, candidate_sha256=after, controlled_fixture_only_adds_real_entry_scope=True, assertions_unchanged=True, shared_source_or_workflow_not_weakened=True, product_execution=False, independent_source_review=False, stage_intake=False, root_intake=False, native_baseline_failure=".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/probe-closure/command-0.log")
(OUT / "candidate.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
