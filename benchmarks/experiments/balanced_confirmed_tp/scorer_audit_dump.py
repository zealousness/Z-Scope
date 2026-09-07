import json, sys
from pathlib import Path

sys.path.insert(0, ".")
from zscope.benchmarking.protocol import issue_match_detail, score_report_views

GT = json.loads(Path("test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vmap = {v["id"]: v for v in GT["vulnerabilities"]}
rd = Path("benchmark-artifacts/c_cpp/trial/20260906T132051Z/run-01")
rep = json.loads((rd / "report.json").read_text(encoding="utf-8"))
issues = rep["issues"]
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in {x.get("id") for x in issues}]
by_id = {i.get("id"): i for i in issues + pool}
d = json.loads((rd / "score.v2.json").read_text(encoding="utf-8"))


def line_of(i):
    loc = str(i.get("location") or "")
    try:
        return int(str(loc.split(":")[1]))
    except Exception:
        return 0


def dump(pairs, title):
    print(f"===== {title} (n={len(pairs)})")
    for p in pairs:
        v = vmap[p["truth_id"]]
        i = by_id.get(next((x for x in ([issues[[n for n, ii in enumerate(issues) if ii.get("id")] .index(0)]] if False else [])), None))
    # 简化：直接按 identity 找回
    for p in pairs:
        v = vmap[p["truth_id"]]
        ident = str(p.get("issue_identity") or "")
        parts = ident.split("|")
        icat, ifile, ifunc = (parts[1] if len(parts) > 1 else "?"), (parts[2] if len(parts) > 2 else "?"), (parts[3] if len(parts) > 3 else "?")
        # 找 issue 实体
        cand = None
        for i in issues + pool:
            try:
                if issue_match_detail(i, v, 8) is not None:
                    if str(i.get("category")) == icat and str(i.get("function")) == ifunc:
                        cand = i
                        break
            except Exception:
                pass
        if cand is None:
            cand = next((i for i in issues + pool if i.get("category") == icat and i.get("function") == ifunc), None)
        tline, teline = int(v.get("line") or 0), int(v.get("end_line") or v.get("line") or 0)
        iline = line_of(cand) if cand else 0
        flags = []
        if v.get("category") != (cand.get("category") if cand else icat):
            flags.append("CAT-DIFF")
        if abs(iline - tline) > 2 and not (tline <= iline <= teline):
            flags.append(f"DIST{abs(iline-tline) if cand else '?'}")
        if v.get("function") != ifunc:
            flags.append("FUNC-DIFF")
        print(f"  [{'|'.join(flags) or 'ok'}] {p['truth_id']} [{v.get('category')}] {v.get('function')}:{tline}-{teline}")
        print(f"      vs [{icat}] {ifunc}:{iline}  {(cand or {}).get('id','')[:34]} rule={str((cand or {}).get('rule'))[:36]}")
        if flags:
            print(f"      truth_desc={str(v.get('description'))[:70]!r}")
            print(f"      issue_sink={str((cand or {}).get('sink'))[:70]!r}")


dump(d["default"].get("matched_pairs") or [], "confirmed TP")
dump((d["with_needs_review"].get("matched_pairs") or []), "with_review TP")

# FN 与同函数候选
matched = set(d["default"].get("matched") or [])
wr_matched = set(d["with_needs_review"].get("matched") or [])
print(f"===== missed (confirmed FN) n={len([v for v in GT['vulnerabilities'] if v['id'] not in matched])}")
for v in GT["vulnerabilities"]:
    if v["id"] in matched:
        continue
    in_wr = v["id"] in wr_matched
    same_func = [i for i in issues + pool if i.get("function") == v.get("function")]
    print(f"  {v['id']} [{v.get('category')}] {v.get('function')}:{v.get('line')}-{v.get('end_line')} "
          f"in_with_review_tp={in_wr} same_func_items={len(same_func)}")
