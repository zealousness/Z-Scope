"""Post-scan, independent comparison of frozen scores and semantic publications.

This script is never imported by scanner/modeler code. It reads truth only after
the new run has a completed score and does not make any LLM requests.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path


LOST = "ISSUE42-013 ISSUE42-021 ISSUE42-026 ISSUE42-027 ISSUE43-012 ISSUE43-016 ISSUE43-017 RANGE-005 RANGE-009 RANGE-014 RANGE-016 RANGE-020 RANGE-021 RANGE-022 RANGE-031 RANGE-038 RANGE-041 RANGE-044 RANGE-048 REAL-001 REAL-004 REAL-005 REAL-021 REAL-024 REAL-025 REAL-031".split()


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def views(score):
    return score.get("report_views", score)


def metrics(score):
    result = {}
    for name, view in views(score).items():
        if name not in {"default", "with_needs_review"}:
            continue
        result[name] = {
            key: view.get(key)
            for key in (
                "true_positives",
                "false_positives",
                "false_positives_raw",
                "recall",
                "root_cause_precision",
                "report_issue_count",
            )
        }
        result[name]["candidate_sources"] = dict(
            Counter(
                r.get("candidate_source") or "unknown"
                for r in view.get("issue_identity_records", [])
            )
        )
    result["usage"] = score.get("usage_accounting", {})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    if not (run / "score.json").is_file() or not (run / "hot-rescan/score.json").is_file():
        raise RuntimeError("Both scans must finish scoring before truth comparison")
    repo = Path(__file__).resolve().parents[3]
    earlier = read(repo / "benchmark-artifacts/c_cpp/trial/20260908T055018Z/run-01/score.v2.json")
    prior = read(repo / "benchmark-artifacts/c_cpp/trial/20260910T015537Z/run-01/score.json")
    cold, hot = read(run / "score.json"), read(run / "hot-rescan/score.json")
    truth = {
        v["id"]: v for v in read(repo / "test/range/benchmark/ground_truth.json")["vulnerabilities"]
    }
    publication = read(run / "semantic-publication/publication.json")
    hot_publication = read(run / "hot-rescan/publication.json")
    contracts = {
        c["symbol"]["name"]
        for c in publication["api_contracts"]
        if c["source"].startswith("inferred")
    }
    matches = {
        name: set(views(score)["with_needs_review"].get("matched", []))
        for name, score in (("earlier", earlier), ("prior", prior), ("cold", cold), ("hot", hot))
    }
    rows = []
    for tid in LOST:
        target = truth[tid]
        function = target["function"]
        events = [
            e
            for e in publication.get("call_sites", [])
            if str(e.get("caller", "")).split("@", 1)[0] == function
            and e["symbol"]["name"] in contracts
        ]
        related = [
            r
            for r in views(cold)["with_needs_review"].get("issue_identity_records", [])
            if "|" + function + "|" in str(r.get("identity", ""))
        ]
        rows.append(
            {
                "truth_id": tid,
                "function": function,
                "file": target["file"],
                "category": target["category"],
                "matched": {name: tid in ids for name, ids in matches.items()},
                "published_wrapper_events": events,
                "same_function_candidate_records": related,
            }
        )
    result = {
        "release_eligible": False,
        "metrics": {
            name: metrics(score)
            for name, score in (
                ("earlier", earlier),
                ("prior", prior),
                ("cold", cold),
                ("hot", hot),
            )
        },
        "regressions_26": rows,
        "cold_modeling": publication["stats"],
        "hot_modeling": hot_publication["stats"],
        "same_contract_version": publication["contract_version"]
        == hot_publication["contract_version"],
        "cold_call_site_counts": publication.get("call_site_counts"),
        "hot_call_site_counts": hot_publication.get("call_site_counts"),
    }
    (run / "comparison.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    text = [
        "# Wrapper 契约修复试验",
        "",
        "本文件为 trial 对照，不提供正式 benchmark 资格。",
        "",
        "| Run | Confirmed TP | Confirmed raw FP | Review TP | Review raw FP |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, item in result["metrics"].items():
        a, b = item["default"], item["with_needs_review"]
        text.append(
            f"| {name} | {a['true_positives']} | {a['false_positives_raw']} | {b['true_positives']} | {b['false_positives_raw']} |"
        )
    text += [
        "",
        "| Truth | Function | 冷扫恢复 | 热扫命中 | 已发布 wrapper 事件 |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        wrappers = sorted(
            {
                e["symbol"]["name"] + ":" + e["applicability"]
                for e in row["published_wrapper_events"]
            }
        )
        text.append(
            f"| {row['truth_id']} | {row['function']} | {row['matched']['cold']} | {row['matched']['hot']} | {', '.join(wrappers) or '无'} |"
        )
    text += [
        "",
        "逐候选、调用事件、契约版本及用量见 comparison.json。wrapper 事件与 truth 恢复同时出现只表明关联，不独立证明因果。",
        "",
    ]
    (run / "comparison.md").write_text("\n".join(text), encoding="utf-8")
    print(run / "comparison.md")


if __name__ == "__main__":
    main()
