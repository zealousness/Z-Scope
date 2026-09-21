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
print(f"profile: {profile.name} threshold={profile.risk_threshold}")

rep = json.loads((REPO / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01/report.json").read_text(encoding="utf-8"))
blind = ["_lifecycle_wait_for_work", "_lifecycle_schedule_flush", "_runtime_read_peer_record",
         "_runtime_enqueue_rcu_batch", "_runtime_stream_follow_wire_pointer", "_lifecycle_close_connection",
         "_lifecycle_mesh_control_message", "_lifecycle_watch_connection", "td_submit_task",
         "_executor_cleanup_resources", "_lifecycle_reload_config"]
entry_of = {}
for i in rep.get("issues", []) + rep.get("issues_with_needs_review", []):
    fn, ef = i.get("function"), i.get("entry_function")
    if fn in blind and ef:
        entry_of.setdefault(fn, ef)
print("盲区函数入口映射:", entry_of)

# 覆盖家族：用确认层类别近似（answer-free；与 ledger 的 family 投影同粒度）
def fam_of(cat):
    f = str(cat or "").lower()
    if "leak" in f or "resource" in f: return "resource_lifecycle"
    if "race" in f or "synchron" in f or "shared" in f: return "callback_concurrency"
    if "overflow" in f or "bound" in f: return "memory_bounds"
    if "free" in f: return "resource_lifecycle"
    if "lock" in f or "deadlock" in f: return "state_protocol"
    return ""
covered = {f"family:{fam_of(i.get('category'))}" for i in rep.get("issues", []) if fam_of(i.get("category"))}
print("covered families:", sorted(covered))

planner = CoverageGapPlanner(profile)
entries = sorted({e for e in entry_of.values()})
total_units, blind_hits = 0, collections.Counter()
for entry_name in entries[:8]:
    try:
        smap = ZeroLLMSecurityMapBuilder(
            idx, project_id="m5tpr-offline", revision="offline-tpr",
            profile=profile.name, semantic_overlay={},
            project_root=str(ws), max_functions=5000,
        ).build([FunctionEntry(function_name=entry_name)])
    except Exception as exc:
        print(f"entry {entry_name}: build failed {type(exc).__name__}: {str(exc)[:80]}")
        continue
    funcs = smap.functions or []
    ev = sum(len(f.events or []) for f in funcs)
    fams = collections.Counter(e.get("family") for f in funcs for e in (f.events or []) if isinstance(e, dict))
    print(f"entry {entry_name}: map functions={len(funcs)} events={ev}")
    print(f"  事件家族分布: {dict(fams.most_common(12))}")
    print(f"  _FAMILY_POLICY 键: {list(__import__('zscope.orchestration.active_discovery', fromlist=['_FAMILY_POLICY'])._FAMILY_POLICY.keys())}")

    # 评分诊断：复现 plan 的打分输入，看盲区函数的得分
    from zscope.orchestration.active_discovery import audit_unit_risk_score, _FAMILY_POLICY
    claims_by_subject = {}
    for claim in smap.claims or []:
        claims_by_subject.setdefault(claim.subject_uid, []).append(claim)
    unknowns_by_subject = {}
    for unk in smap.unknowns or []:
        unknowns_by_subject.setdefault(unk.subject_uid, []).append(unk)
    funcs_by_name = {}
    for r in smap.functions:
        funcs_by_name.setdefault(r.function_name, r)
    for b in blind:
        rec = funcs_by_name.get(b)
        if rec is None:
            continue
        by_family = {}
        for e in rec.events or []:
            by_family.setdefault(getattr(e, "family", "?"), []).append(e)
        for family, events in by_family.items():
            if family not in _FAMILY_POLICY:
                continue
            members = [rec.function_name]
            ext_ids = set()
            for uid, cls_ in claims_by_subject.items():
                if any(c.kind == "input_origin" and str(c.value.get("origin") or "").lower() == "external" for c in cls_):
                    entry_recs = [r for r in smap.functions if r.function_uid == uid]
                    ext_ids.update(e for r in entry_recs for e in r.entry_identities)
            score, reasons = audit_unit_risk_score(
                known_variant_history=False,
                high_risk_diff=False,
                external_reachable_sensitive=(
                    family in ("callback_concurrency", "input_boundary", "sensitive_sink")
                    and bool(set(rec.entry_identities) & ext_ids)
                ),
                same_event_family_candidate_desert=(
                    f"family:{family}:{str(rec.file_path or rec.file or '').split('/')[-1]}" not in covered
                ),
                callback_dynamic_alias_unresolved=False,
                backend_unavailable_degraded=False,
                cross_module_path=True,
                semantic_unknown_conflict=False,
            )
            print(f"    诊断 {b} [{family}] score={score} reasons={reasons}")

    units = planner.plan(smap, covered_keys=covered)
    print(f"  planned units: {len(units)}")
    for u in units:
        total_units += 1
        members = set(str(m) for m in (u.member_functions or ()))
        hit = sorted(b for b in blind if b in members)
        for b in hit:
            blind_hits[b] += 1
        if hit:
            print(f"    ★ unit {u.unit_id} kind={u.unit_kind} score={u.risk_score} "
                  f"desert={u.candidate_desert} 盲区函数={hit} reasons={list(u.risk_reasons)[:4]}")
print(f"\n总规划单元: {total_units}")
print("盲区函数被规划次数:", dict(blind_hits.most_common()))
