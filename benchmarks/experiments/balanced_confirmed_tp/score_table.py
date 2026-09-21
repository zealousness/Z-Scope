import json, sys, collections
from pathlib import Path

REPO = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
sys.path.insert(0, str(REPO))

from zscope.retrieval.code_index import CodeIndex
from zscope.config.config import ConfigLoader
from zscope.config.function_entry import FunctionEntry
from zscope.semantics.security_map import ZeroLLMSecurityMapBuilder
from zscope.orchestration.active_discovery import (
    CoverageGapPlanner, resolve_discovery_profile, audit_unit_risk_score, _FAMILY_POLICY,
)

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

rep = json.loads((REPO / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/report.json").read_text(encoding="utf-8"))
blind = ["RANGE-006", "RANGE-025", "RANGE-027", "RANGE-052", "RANGE-024", "RANGE-035",
         "RANGE-039", "RANGE-050", "REAL-019", "ISSUE42-009", "ISSUE43-009"]
gt = json.loads((REPO / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vmap = {v["id"]: v for v in gt["vulnerabilities"]}
func_of = {t: vmap[t]["function"] for t in blind}
file_of = {t: str(vmap[t]["file"]).split("/")[-1] for t in blind}

entry_of = {}
for i in rep.get("issues", []) + rep.get("issues_with_needs_review", []):
    fn, ef = i.get("function"), i.get("entry_function")
    if fn in func_of.values() and ef:
        entry_of.setdefault(fn, ef)

# 覆盖键（站点级：family+file；函数级：family+function——校准方案对比用）
covered_site = set()
covered_func = set()
for i in rep.get("issues", []):
    fam = None
    c = str(i.get("category") or "").lower()
    if "leak" in c or "resource" in c: fam = "resource_lifecycle"
    elif "race" in c or "synchron" in c or "shared" in c: fam = "callback_concurrency"
    elif "overflow" in c or "bound" in c: fam = "memory_bounds"
    elif "free" in c: fam = "resource_lifecycle"
    elif "lock" in c or "deadlock" in c: fam = "state_protocol"
    if not fam: continue
    site = str(i.get("location") or "").split(":")[0]
    fnname = i.get("function")
    if site: covered_site.add(f"family:{fam}:{site}")
    if fnname: covered_func.add(f"family:{fam}:{fnname}")

# 确认层同函数的框架类别（用于校准判断：站点被"其它框架"确认的情况）
confirmed_by_func = collections.defaultdict(set)
for i in rep.get("issues", []):
    confirmed_by_func[i.get("function")].add(i.get("category"))

results = []
map_cache = {}
for tid in blind:
    v = vmap[tid]
    func = func_of[tid]
    entry = entry_of.get(func)
    if not entry:
        results.append((tid, v.get("category"), func, "NO_ENTRY", 0, []))
        continue
    try:
        if entry not in map_cache:
            map_cache[entry] = ZeroLLMSecurityMapBuilder(
                idx, project_id="m5tpr", revision="offline", profile=profile.name,
                semantic_overlay={}, project_root=str(ws), max_functions=5000,
            ).build([FunctionEntry(function_name=entry)])
        smap = map_cache[entry]
    except Exception as exc:
        results.append((tid, v.get("category"), func, f"MAP_FAIL:{type(exc).__name__}", 0, []))
        continue
    rec = next((r for r in smap.functions if r.function_name == func), None)
    if rec is None:
        results.append((tid, v.get("category"), func, "NOT_IN_MAP", 0, []))
        continue
    evs = rec.events or []
    fams = {getattr(e, "family", "?") for e in evs}
    policy_fams = [f for f in fams if f in _FAMILY_POLICY]
    # 以第一个 policy family 计算可达分数（真实 plan 循环同款）
    score, reasons = 0, []
    for family in policy_fams[:1]:
        site_key = f"family:{family}:{str(rec.file_path or rec.file or '').split('/')[-1]}"
        func_key = f"family:{family}:{func}"
        desert = not (site_key in covered_site or func_key in covered_func)
        ext_ids = set()
        claims_by_subject = {}
        for claim in smap.claims or []:
            claims_by_subject.setdefault(claim.subject_uid, []).append(claim)
        for uid, cl in claims_by_subject.items():
            if any(c.kind == "input_origin" and str(c.value.get("origin") or "").lower() == "external" for c in cl):
                for r2 in smap.functions:
                    if r2.function_uid == uid:
                        ext_ids.update(r2.entry_identities)
        ext_reach = family in _FAMILY_POLICY and family in {"callback_concurrency", "input_boundary", "sensitive_sink"} \
            and bool(set(rec.entry_identities) & ext_ids)
        unknowns_by_subject = {}
        for unk in smap.unknowns or []:
            unknowns_by_subject.setdefault(unk.subject_uid, []).append(unk)
        subj_unknowns = unknowns_by_subject.get(rec.function_uid, [])
        score, reasons = audit_unit_risk_score(
            known_variant_history=False,
            high_risk_diff=False,
            external_reachable_sensitive=ext_reach,
            same_event_family_candidate_desert=desert,
            callback_dynamic_alias_unresolved=False,
            backend_unavailable_degraded=False,
            cross_module_path=True,
            semantic_unknown_conflict=bool(subj_unknowns),
        )
        results.append((tid, v.get("category"), func, f"score={score} desert={desert} ext={ext_reach} "
                        f"events={len(evs)} fams={sorted(fams)} reasons={reasons}"))
        break

print("11 个盲区函数的可达评分（阈值 60）:")
for row in results:
    desc = row[3] if len(row) >= 4 else ""
    print(f"  {row[0]:12} [{str(row[1])[:28]:30}] {desc}")
