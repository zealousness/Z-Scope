"""Score completed paired runs against independent, non-model-visible expectations."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def public_outcome(result):
    audit = result["metadata"].get("validator_protocol_audit", {})
    valid = result["success"] and audit.get("parsed") is True
    return result["data"].get("verdict") if valid else "invalid"


def protocol_observations(exchanges, result):
    names, replies, terminal_calls = {}, {}, 0
    for exchange in exchanges:
        for choice in (exchange.get("response") or {}).get("choices") or []:
            for call in choice.get("message", {}).get("tool_calls") or []:
                name = call.get("function", {}).get("name")
                names[call.get("id")] = name
                terminal_calls += name == "emit_validator_result_v3"
        for message in exchange["messages"]:
            if message.get("role") == "tool":
                replies[message["tool_call_id"]] = json.loads(message["content"])
    failures = Counter()
    for call_id, reply in replies.items():
        if reply.get("success") is False:
            failures[names.get(call_id, "unknown")] += 1
    metadata = result["metadata"]
    first_audit = metadata.get("validator_first_attempt_audit", {})
    return {
        "terminal_calls": terminal_calls,
        "first_terminal_success": (
            public_outcome(result) != "invalid"
            and terminal_calls == 1
            and first_audit.get("parsed", True)
        ),
        "fact_registration_rejections": failures["record_validator_investigation_fact"],
        "terminal_rejections": failures["emit_validator_result_v3"],
    }


def score_pair(expected, before, after):
    outcomes = {"before": public_outcome(before), "after": public_outcome(after)}
    truth, target = expected["truth_class"], expected["expected_verdict"]
    return {
        "id": expected["id"],
        "truth_class": truth,
        "expected_verdict": target,
        "scope": expected["scope"],
        "stage": before.get("stage"),
        "source_runs": {"before": before.get("source_run"), "after": after.get("source_run")},
        "correlation_group": expected["correlation_group"],
        "outcomes": outcomes,
        "agree": outcomes["before"] != "invalid" and outcomes["before"] == outcomes["after"],
        "regression": outcomes["before"] == target and outcomes["after"] != target,
        "improvement": outcomes["before"] != target and outcomes["after"] == target,
        "tokens": {
            "before": before["usage"]["consumed_tokens"],
            "after": after["usage"]["consumed_tokens"],
        },
        "seconds": {"before": before["seconds"], "after": after["seconds"]},
    }


def arm_metrics(rows, results, arm):
    counts = Counter()
    token_counts = Counter()
    for row in rows:
        outcome = row["outcomes"][arm]
        counts["sessions"] += 1
        counts["protocol_successes"] += outcome != "invalid"
        counts["expected_matches"] += outcome == row["expected_verdict"]
        counts[f"verdict_{outcome}"] += 1
        if row["truth_class"] == "defect":
            counts["known_defects"] += 1
            counts["true_positives"] += outcome == "verified"
            counts["false_negatives"] += outcome != "verified"
            if outcome != "verified":
                counts[f"missed_as_{outcome}"] += 1
        elif row["truth_class"] == "safe":
            counts["known_safe"] += 1
            counts["false_positives"] += outcome == "verified"
            counts["safe_rejections"] += outcome == "rejected"
            counts["safe_abstentions"] += outcome == "uncertain"
        else:
            counts["unresolved_cases"] += 1
            counts["unsupported_confirmations"] += outcome == "verified"
            counts["unsupported_rejections"] += outcome == "rejected"
        result = results[(row["id"], arm)]
        metadata = result["metadata"]
        for key, value in result.get("protocol_observations", {}).items():
            counts[key] += value
        counts["repair_attempts"] += metadata.get("validator_repair_attempted", 0)
        counts["length_retries"] += metadata.get("validator_length_retry_count", 0)
        totals = result["usage"]["usage_attribution"]["totals"]
        for key in (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "cached_prompt_tokens",
            "reasoning_tokens",
            "request_count",
            "provider_reported_calls",
            "estimated_or_conservative_calls",
            "failed_or_unknown_calls",
        ):
            token_counts[key] += totals[key]
    return {
        **dict(counts),
        "protocol_success_rate": counts["protocol_successes"] / counts["sessions"],
        "recall_on_known_defects": (
            counts["true_positives"] / counts["known_defects"] if counts["known_defects"] else None
        ),
        "false_positive_rate_on_known_safe": (
            counts["false_positives"] / counts["known_safe"] if counts["known_safe"] else None
        ),
        "usage": dict(token_counts),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", type=Path, nargs="+")
    parser.add_argument("--expected", type=Path, default=HERE / "expected.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--update", type=Path, action="append", default=[])
    args = parser.parse_args()
    # A run emits results.json only after every selected pair has finished.
    # Load and validate those artifacts before opening independent labels.
    results = {}
    replacements = []
    for run in [*args.runs, *args.update]:
        for result in json.loads((run / "results.json").read_text(encoding="utf-8")):
            key = (result["case_id"], result["arm"])
            if key in results and run not in args.update:
                raise ValueError(f"Duplicate run for {key}")
            if run in args.update:
                if key not in results:
                    raise ValueError(f"Cannot replace a missing original run: {key}")
                replacements.append(
                    {
                        "case": key[0],
                        "arm": key[1],
                        "from": results[key]["source_run"],
                        "to": str(run),
                    }
                )
            exchanges = json.loads(
                (run / key[0] / key[1] / "exchanges.json").read_text(encoding="utf-8")
            )
            result["protocol_observations"] = protocol_observations(exchanges, result)
            result["source_run"] = str(run)
            results[key] = result
    if not results or any(
        (case, other) not in results for case, _ in results for other in ("before", "after")
    ):
        raise ValueError("Every case requires both completed arms")
    for case in {case for case, _ in results}:
        inputs = []
        for arm in ("before", "after"):
            path = Path(results[(case, arm)]["source_run"]) / case / arm / "input.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value.pop("agent_contract", None)
            inputs.append(value)
        if inputs[0] != inputs[1]:
            raise ValueError(f"Case input differs between arms: {case}")
    expected = json.loads(args.expected.read_text(encoding="utf-8"))
    selected = [case for case in expected["cases"] if (case["id"], "before") in results]
    if len(selected) * 2 != len(results):
        raise ValueError("Unknown case or arm")
    rows = [
        score_pair(case, results[(case["id"], "before")], results[(case["id"], "after")])
        for case in selected
    ]
    metrics = {arm: arm_metrics(rows, results, arm) for arm in ("before", "after")}
    before, after = (metrics[arm]["usage"]["total_tokens"] for arm in ("before", "after"))
    summary = {
        "case_count": len(rows),
        "agreement_count": sum(row["agree"] for row in rows),
        "agreement_rate": sum(row["agree"] for row in rows) / len(rows),
        "regressions": [row["id"] for row in rows if row["regression"]],
        "improvements": [row["id"] for row in rows if row["improvement"]],
        "metrics": metrics,
        "token_reduction_fraction": 1 - after / before if before else None,
        "cases": rows,
        "replacements": replacements,
        "selection_bias": expected["selection_bias"],
        "scope": "Validator decisions on selected fixtures, not full-pipeline or production precision/recall.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                key: value
                for key, value in summary.items()
                if key not in {"cases", "selection_bias"}
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
