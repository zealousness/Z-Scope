"""M5-TPR R1: replay re-adjudication of pool items that strictly match
unconfirmed truths.  uncertain -> V3@50 re-investigation; rejected -> V2b audit.
"""
import json, sys, collections
from pathlib import Path

A = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope") if Path("/mnt/c").exists() else Path("C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
# 抢在登录 shell 的 PYTHONPATH（可能指向旧 checkout）之前绑定 A 的包
sys.path.insert(0, str(A))
for _stale in [m for m in list(sys.modules) if m == "zscope" or m.startswith("zscope.")]:
    del sys.modules[_stale]

from zscope.benchmarking import protocol as BP  # A 的 v2 matcher
RUN = A / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01"
WS = Path("/home/zeal/zscope_dash_ws/scan-input")
OUT = A / "benchmarks/experiments/balanced_confirmed_tp/m5tpr_replay_results.jsonl"

sys.path.insert(0, str(A / "benchmarks/experiments/balanced_confirmed_tp"))
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("r3drv", Path(__file__).parent / "replay_r3_review_pool.py")
r3drv = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(r3drv)

gt = json.loads((A / "test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
vulns = gt["vulnerabilities"]
rep = json.loads((RUN / "report.json").read_text(encoding="utf-8"))
issues = rep["issues"]
conf_ids = {i.get("id") for i in issues}
pool = [i for i in rep.get("issues_with_needs_review", []) if i.get("id") not in conf_ids]

targets = []
seen_truth = set()
for i in pool:
    ts = [v["id"] for v in vulns if BP.issue_match_detail(i, v, 8) is not None]
    ts_unconfirmed = [t for t in ts]
    if ts and not (set(ts) & seen_truth):
        # 仅取互相不同的 truth 组代表（同 truth 多条目只 replay 一条）
        targets.append((i, ts))
        seen_truth.update(ts)
print(f"replay targets: {len(targets)} (覆盖 truth {len(seen_truth)})")

# 运行时：配置 = 本轮 execution yaml，root 重定向到持久 workspace
cfg_text = (RUN / "zscope.execution.yaml").read_text(encoding="utf-8")
import re as _re
cfg_text = _re.sub(r"root: \S+", f"root: {WS.as_posix()}", cfg_text, count=1)
cfg_path = WS.parent / "zscope_tpr.yaml"
cfg_path.write_text(cfg_text, encoding="utf-8")

runner, _cfg = r3drv.build_runtime(cfg_path, WS, 4)

out_f = open(OUT, "w", encoding="utf-8")
done = 0
for issue, truths in targets:
    vid = str(issue.get("verdict") or issue.get("model_verdict") or "uncertain").lower()
    prior = {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": issue.get("candidate_uid"),
        "validation_cluster_uid": issue.get("validation_cluster_uid"),
        "pass": issue.get("validator_result_pass") or "investigation_synthesis",
        "verdict": vid,
        "reasoning": str(issue.get("validation_reasoning") or "")[:4000],
        "positive_evidence": list(issue.get("positive_evidence") or []),
        "negative_evidence": list(issue.get("negative_evidence") or []),
        "evidence_refs": list(issue.get("evidence_refs") or []),
        "blocking_negative_evidence": bool(issue.get("blocking_negative_evidence")),
        "missing_fact_request": issue.get("validator_missing_fact_request"),
        "stop_reason": issue.get("validator_stop_reason") or "",
    }
    rec = {"id": issue.get("id"), "prior": vid, "truths": truths, "cat": issue.get("category")}
    try:
        result = runner.replay_review_candidate(
            dict(issue), prior,
            investigate_uncertain=(vid == "uncertain"),
            audit_rejection=(vid == "rejected"),
        )
        cand = result.get("candidate") or {}
        rec.update({
            "final_verdict": cand.get("model_verdict") or cand.get("validator_verdict"),
            "final_disposition": cand.get("candidate_disposition"),
            "hold": cand.get("review_disposition_reason"),
            "ok": True,
        })
    except Exception as exc:
        rec.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]})
    out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    out_f.flush()
    done += 1
    print(f"[{done}/{len(targets)}] {rec['id'][:36]} prior={vid} final={rec.get('final_verdict')}")
out_f.close()
print("TPR replay done")
