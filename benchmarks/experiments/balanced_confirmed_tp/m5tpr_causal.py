import json, sys
from pathlib import Path
B = Path("C:/Users/10273/home/work/Z-Scope")
sys.path.insert(0, str(B))
from zscope.benchmarking import protocol as BP
A = Path("C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
g_dir = A / "benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01"
n_dir = A / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01"
g = json.loads((g_dir / "score.v2.json").read_text(encoding="utf-8"))["default"]
n = json.loads((n_dir / "score.json").read_text(encoding="utf-8"))
rep_g = json.loads((g_dir / "report.json").read_text(encoding="utf-8"))
rep_n = json.loads((n_dir / "report.json").read_text(encoding="utf-8"))
gt = json.loads((A / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vmap = {v["id"]: v for v in gt["vulnerabilities"]}
issues_g = rep_g["issues"]
issues_n = rep_n["issues"] + [i for i in rep_n.get("issues_with_needs_review", [])
                              if i.get("id") not in {x.get("id") for x in rep_n["issues"]}]

gm = {p["truth_id"]: p["issue_index"] for p in g.get("matched_pairs", [])}
nm = {p["truth_id"] for p in n.get("matched_pairs", [])}
lost = sorted(set(gm) - set(nm))

def dl_of(i):
    return str((i.get("attribution") or {}).get("decision_level") or "?")

def proofs_of(i):
    return [str(p.get("proof_kind"))[:44] for p in (i.get("deterministic_proofs") or [])
            if isinstance(p, dict) and p.get("outcome") == "confirm"]

print(f"lost truths: {len(lost)}\n")
cause = collections = {"M2_M3_demoted": [], "V3_flip": [], "candidate_absent": [], "present_unmatched": []}
cause = {k: [] for k in ("C1_M2_M3_demoted", "C2_V3_flip", "C3_candidate_absent", "C4_present_unmatched")}
for tid in lost:
    v = vmap[tid]
    gi = issues_g[gm[tid]]
    g_dl, g_proofs = dl_of(gi), proofs_of(gi)
    # 新 run 里同 id 条目
    ni = next((i for i in issues_n if i.get("id") == gi.get("id")), None)
    ni_conf = next((i for i in rep_n["issues"] if i.get("id") == gi.get("id")), None)
    # 新 run 同函数条目
    same_func = [i for i in issues_n if i.get("function") == gi.get("function")]
    same_func_conf = [i for i in same_func if str((i.get("attribution") or {}).get("decision_level"))]
    if ni_conf is not None:
        c = "C4_present_unmatched"
        note = f"同id仍confirmed(dl={dl_of(ni_conf)}) 但 v2 不匹配"
    elif ni is not None:
        c = "C2_V3_flip"
        note = f"同id转入review(disp={ni.get('candidate_disposition') or ni.get('terminal_disposition')})"
    elif same_func_conf:
        c = "C4_present_unmatched"
        note = f"同函数有其他确认条目({[x.get('category') for x in same_func_conf]})"
    else:
        c = "C3_candidate_absent"
        note = "同函数无任何条目"
    # C1 判定：guards 确认走 V0 且证明是 M2/M3 针对种类
    if g_dl == "V0" and any("source_lifecycle" in p or "cfg_obligation" in p for p in g_proofs):
        cause["C1_M2_M3_demoted"].append((tid, note, g_dl, g_proofs))
        c = "C1_M2_M3_demoted*" + c
    cause[c if not c.startswith("C1") else "C1_M2_M3_demoted"].append((tid, note, g_dl, g_proofs))
    print(f"{tid} [{v.get('category')}] {v.get('function')[:30]}")
    print(f"   guards: {gi.get('id','')[:38]} dl={g_dl} proofs={g_proofs or '-'}")
    print(f"   new: {note}")
    print(f"   => 归因: {c}")
print("\n== 因果汇总:")
for k, v in cause.items():
    print(f"   {k}: {len(v)}")
