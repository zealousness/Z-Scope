"""Read the current DAG and source facts without dispatching additional work."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ledger = json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
pending, done, layers = set(rows), set(), []
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready, pending
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
assert layers == ledger["topological_layers"]
source_paths = ("zscope/orchestration/scan_session.py", "zscope/orchestration/parallel_analyzer.py", "zscope/core/analysis/analyzer.py", "zscope/config/v3.py")
source = {p: (ROOT / p).read_text(encoding="utf-8") for p in source_paths}
assert "No ``semantic_result`` is passed" in source[source_paths[0]]
assert "shared_semantics: Optional[LocalPatternSemantics] = LocalPatternSemantics()" in source[source_paths[1]]
assert '"instance_scope_isolated"' in source[source_paths[1]]
assert 'reason="instance_scoped_defaults_only"' in source[source_paths[2]]
for field in ("project.platform", "scan.focus", "scan.reproduction", "execution.max_workers"):
    offset = source[source_paths[3]].index('"' + field + '"', source[source_paths[3]].index('WiringNote(\n            "project.platform"'))
    assert "DECLARED_ONLY" in source[source_paths[3]][offset:offset + 100]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"at": at, "nodes": len(rows), "layers": len(layers), "dag_valid": True, "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in source_paths}, "current_active_native": [r["agent_task_id"] for r in rows.values() if r.get("agent_kind") == "native_subagent" and r.get("producer_status") == "running"], "remaining": {"S01": "Exact-instance Analyzer runs, but shared semantics/overlay deliberately empty, semantic_result absent, project fact pass and discovery isolated. Per-instance modeling/full backend and link consumers remain.", "S08": "Actual instance analysis and shared validation and whole-plan bound checkpoint accepted. Per-instance candidate/obligation durable recovery and ongoing fair batches remain.", "U01": "Four runtime meanings are declared-only; multi-target execution rejected. Current effective-window SQL repair does not close them.", "S02-S07": "Additional protocols, unified obligations, harness/TSan, demand and full incremental execution remain dependent work. Existing archived S06-R02 preserved; no new task issued."}, "next_parallel_candidates": [{"work_item": "S01 exact-instance semantic modeling", "owner_preference": "ZCode glm-5.3", "dispatch_state": "not_dispatched", "dependency": "New exact-build/USR modeling, cache/publication contracts and exclusive partition of global_modeler/semantic_modeling/parallel_analyzer/scan_session required; current CLI repair owns none of these but first current-union gate is prioritized."}, {"work_item": "S08 per-instance durable recovery and fair batches", "owner_preference": "ZCode glm-5.3", "dispatch_state": "not_dispatched", "dependency": "Current effective-window and first-cause intake/joint; partition jobs and shared scan_session against S01 before dispatch."}, {"work_item": "Astra UI consumers", "owner_preference": "Astra", "dispatch_state": "not_dispatched", "dependency": "Stable, implemented backend contracts; static files/browser tests remain exclusive, shared HTTP/services/resources coordinator owned. No repeated UI task for already accepted native fixture."}], "not_actual_external_blockers": ["Unknown/unprobed real model connection", "Formal benchmark/portable prerequisites not requested or preflighted", "Conditional S10 and Q01/Q02 not enabled"], "actual_gates": ["SQL repair delivery and independent full acceptance", "Nine-file coordinator intake", "Strict current full selected union plus six commands and source proof"], "no_whole_package_or_real_project_acceptance": True}
out = HERE / "followups-r12" / ("remaining-dependencies-r20-" + at.replace(":", "").replace("+", "_") + ".json")
out.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "nodes": len(rows), "layers": len(layers), "active_native": proof["current_active_native"], "evidence": out.relative_to(HERE).as_posix()}), flush=True)
