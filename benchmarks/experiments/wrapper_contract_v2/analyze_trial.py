"""Independent post-score audit for one trial; never imported by the scanner."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from audit_run import audit
from compare_runs import LOST, metrics, views
from zscope.semantics.contracts import ApiContract


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, action="append", default=[])
    args = parser.parse_args()
    run = args.run.resolve()
    if not (run / "score.json").exists():
        raise RuntimeError("Freeze and independently score the trial before analysis")
    repo = Path(__file__).resolve().parents[3]
    publication = read(run / "semantic-publication/publication.json")
    current = read(run / "score.json")
    baselines = args.baseline or [
        repo / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01/score.v2.json",
        repo / "benchmark-artifacts/c_cpp/trial/20260910T015537Z/run-01/score.json",
    ]
    scores = {str(p): read(p) for p in baselines}
    scores["current"] = current
    scoring_inputs = read(run / "scoring-inputs.json") if (run / "scoring-inputs.json").exists() else {}
    truth_path = Path(scoring_inputs.get("truth_path") or repo / "test/range/benchmark/ground_truth.json")
    if scoring_inputs:
        import hashlib
        if hashlib.sha256(truth_path.read_bytes()).hexdigest() != scoring_inputs["truth_sha256"]:
            raise RuntimeError("Frozen scoring truth changed before comparison")
    truth = {v["id"]: v for v in read(truth_path)["vulnerabilities"]}
    calls = publication.get("call_sites", [])
    contracts = publication.get("api_contracts", [])
    pairs = publication.get("api_pairs", [])
    interfaces = []
    for contract in contracts:
        if contract.get("source") == "builtin_defaults":
            continue
        symbol = contract["symbol"]
        parsed = ApiContract.from_row({"contract": contract})
        if parsed is None:
            raise ValueError("Published contract cannot be decoded: " + repr(symbol))
        events = [
            e
            for e in calls
            if e.get("symbol") == symbol
            and e.get("role") == parsed.role
            and e.get("object")
            == parsed.carrier.resolve(e.get("arguments", []), e.get("returned", ""))
            and e.get("conditions") == (parsed.effect_cases or parsed.conditions)
        ]
        verification = contract.get("verification") or {}
        interfaces.append(
            {
                "symbol": symbol,
                "role": contract["role"],
                "source": contract.get("source"),
                "carrier": contract.get("carrier"),
                "resource_domain": contract.get("resource_domain"),
                "resource_family": contract.get("resource_family"),
                "verification": verification,
                "preconditions": contract.get("preconditions"),
                "effect_cases": contract.get("effect_cases"),
                "matched_call_sites": len(events),
                "trusted_effect_call_sites": sum(e.get("effects_trusted") is True for e in events),
                "applicability": dict(Counter(e.get("applicability", "unknown") for e in events)),
                "pairs": [
                    p for p in pairs if p.get("acquire") == symbol or p.get("release") == symbol
                ],
            }
        )
    regressions = []
    for tid in LOST:
        target = truth.get(tid)
        if target is None:
            regressions.append({"truth_id": tid, "status": "absent_from_current_truth"})
            continue
        function = target["function"]
        records = views(current)["with_needs_review"].get("issue_identity_records", [])
        regressions.append(
            {
                "truth_id": tid,
                "function": function,
                "file": target["file"],
                "category": target["category"],
                "matched": {
                    label: {
                        view: tid in set(data.get(view, {}).get("matched", []))
                        for view in ("default", "with_needs_review")
                    }
                    for label, score in scores.items()
                    for data in [views(score)]
                },
                "wrapper_events": [
                    e
                    for e in calls
                    if str(e.get("caller", "")).split("@", 1)[0] == function
                    and e.get("source") != "builtin_defaults"
                ],
                "candidate_records": [
                    r for r in records if "|" + function + "|" in str(r.get("identity", ""))
                ],
            }
        )
    recovery = read(run / "recovery.json") if (run / "recovery.json").exists() else None
    combined_usage = read(run / "recovery-usage.json") if (run / "recovery-usage.json").exists() else None
    result = {
        "recovery": recovery,
        "combined_observed_usage": combined_usage,
        "release_eligible": False,
        "metrics": {name: metrics(score) for name, score in scores.items()},
        "contract_audit": audit(run, run / "semantic-publication/publication.json"),
        "interfaces": interfaces,
        "regressions_26": regressions,
        "interpretation": "Role matches are distinct from applicability. Conditional allocation events may remain unknown without caller branch facts. Association with recovered truth is not causal proof. Historical score matcher differences must be checked separately.",
    }
    (run / "analysis.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    text = [
        "# 自动契约扫描结果",
        "",
        ("断电后在保留目录续跑；不是连续冷扫描，未取得正式资格。费用以 recovery-usage.json 的跨进程合计为准，普通 score 用量仅对应最后进程。" if recovery else "单轮 trial，未取得正式资格。"),
        "",
        "| Run | Confirmed TP | Confirmed raw FP | With-review TP | With-review raw FP |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, data in result["metrics"].items():
        a, b = data["default"], data["with_needs_review"]
        label = "current" if name == "current" else Path(name).parents[1].name
        if name != "current" and Path(name).name == "baseline-score.json":
            baseline_manifest = Path(name).parent / "manifest.json"
            if baseline_manifest.exists():
                origin = read(baseline_manifest).get("baseline_report")
                if origin:
                    label = Path(origin).parents[1].name + "（同输入重评分）"
        text.append(
            f"| {label} | {a['true_positives']} | {a['false_positives_raw']} | {b['true_positives']} | {b['false_positives_raw']} |"
        )
    text += [
        "",
        "## 接口提取与消费",
        "",
        "| 接口 | 角色 | 验证依据 | 效果权限 | 调用匹配数 | 配对边数 |",
        "|---|---|---|---|---:|---:|",
    ]
    for interface in interfaces:
        v = interface["verification"]
        text.append(
            f"| {interface['symbol']['name']} | {interface['role']} | {v.get('method', interface['source'])} | {v.get('effect_strength', 'explicit contract')} | {interface['matched_call_sites']} | {len(interface['pairs'])} |"
        )
    text += [
        "",
        "模型条件在没有调用者路径事实时可能为 unknown；匹配数不是有效释放数。原始与规范化契约、逐站点事件、26 条回退和用量归因见 analysis.json。",
        "",
    ]
    text += ["## 原 26 条回退", "", "| Truth ID | 函数 | Confirmed | 含 review | 项目接口事件 | 报告记录 |", "|---|---|---|---|---:|---:|"]
    for regression in regressions:
        if regression.get("status") == "absent_from_current_truth":
            text.append(f"| {regression['truth_id']} | 当前 truth 不存在 | — | — | — | — |")
            continue
        matched = regression["matched"]["current"]
        text.append(f"| {regression['truth_id']} | {regression['function']} | {'是' if matched['default'] else '否'} | {'是' if matched['with_needs_review'] else '否'} | {len(regression['wrapper_events'])} | {len(regression['candidate_records'])} |")
    text += ["", "接口事件及同函数报告记录仅表示关联，不证明配对效果或修复因果。", ""]
    (run / "analysis.md").write_text("\n".join(text), encoding="utf-8")
    print(
        json.dumps(
            {
                "metrics": result["metrics"],
                "modeling": result["contract_audit"]["modeling"],
                "snapshot_absent": result["contract_audit"]["snapshot_independent_tasks_absent"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
