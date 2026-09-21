import json, sys, collections
from pathlib import Path

REPO = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
sys.path.insert(0, str(REPO))

from zscope.retrieval.code_index import CodeIndex
from zscope.config.config import ConfigLoader
from zscope.config.function_entry import FunctionEntry
from zscope.semantics.security_map import ZeroLLMSecurityMapBuilder
from zscope.orchestration.active_discovery import CoverageGapPlanner, resolve_discovery_profile

ws = Path("/home/zeal/zscope_dash_ws/scan-input")
cfg = ConfigLoader.load(str(ws.parent / "zscope.yaml"))
idx = CodeIndex(
    cfg.project.project_root, cfg.project.compile_commands_path,
    source_root=cfg.project.source_root, indexing_config=cfg.indexing,
    include_paths=cfg.project.include_paths, exclude_paths=cfg.project.exclude_paths,
    wait_for_cpg=False,
)
profile = resolve_discovery_profile(cfg)
planner = CoverageGapPlanner(profile)

rep = json.loads((REPO / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01/report.json").read_text(encoding="utf-8"))
blind = ["RANGE-006", "RANGE-025", "RANGE-027", "RANGE-052", "RANGE-024", "RANGE-035",
         "RANGE-039", "RANGE-050", "REAL-019", "ISSUE42-009", "ISSUE43-009"]
vmap = {v["id"]: v for v in json.loads((REPO / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))["vulnerabilities"]}
func_of = {t: vmap[t]["function"] for t in blind}
file_of = {t: str(vmap[t]["file"]).split("/")[-1] for t in blind}

entry_list = json.loads((REPO / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01/entry_functions_list.json").read_text(encoding="utf-8"))
fns = entry_list.get("functions") or []
entries = sorted({str(f.get("function_name") or f.get("name") or "") for f in fns} - {""})
print(f"入口数: {len(entries)}")

def fam_of(cat):
    f = str(cat or "").lower()
    if "leak" in f or "resource" in f: return "resource_lifecycle"
    if "race" in f or "synchron" in f or "shared" in f: return "callback_concurrency"
    if "overflow" in f or "bound" in f: return "memory_bounds"
    if "free" in f: return "resource_lifecycle"
    if "lock" in f or "deadlock" in f: return "state_protocol"
    if "wake" in f or "signal" in f: return "callback_concurrency"
    return ""

covered = set()
for i in rep.get("issues", []):
    fam = fam_of(i.get("category"))
    site = str(i.get("location") or "").split(":")[0]
    if fam and site:
        covered.add(f"family:{fam}:{site}")

hits = collections.defaultdict(list)
units_total = 0
for entry_name in entries:
    try:
        smap = ZeroLLMSecurityMapBuilder(
            idx, project_id="m5tpr", revision="offline", profile=profile.name,
            semantic_overlay={}, project_root=str(ws), max_functions=5000,
        ).build([FunctionEntry(function_name=entry_name)])
    except Exception:
        continue
    units = planner.plan(smap, covered_keys=covered)
    units_total += len(units)
    for u in units:
        members = set(str(m) for m in (u.member_functions or ()))
        for t in blind:
            if func_of[t] in members:
                hits[t].append((entry_name, u.unit_id, u.risk_score, u.unit_kind,
                                sorted({x.get("category") for x in smap.functions
                                        if x.function_name in members})))

print(f"\n总规划单元: {units_total}")
print("盲区 truth → 是否被规划单元覆盖:")
for t in blind:
    h = hits.get(t)
    if h:
        entry, uid, score, kind, cats = h[0]
        print(f"  ★ {t} [{vmap[t].get('category')}] @{func_of[t]} -> 单元(score={score}, kind={kind}, 入口={entry})")
    else:
        print(f"  ✗ {t} [{vmap[t].get('category')}] @{func_of[t]} -> 未被任何规划单元覆盖")
