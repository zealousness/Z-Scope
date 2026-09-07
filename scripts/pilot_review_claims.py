"""Compiler-only diagnostic on a report projection; never a formal replay score."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zscope.retrieval.validation_facts import CompleteFactStore
from zscope.core.validation.review_checks import ReviewClaimChecker
from zscope.core.validation.proofs import deterministic_decision_proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--compile-commands", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Range diagnostics use Linux/WSL compiler facts")
    report = json.loads(args.report.read_text(encoding="utf-8"))
    confirmed = {str(i.get("candidate_uid") or i.get("id")) for i in report.get("issues", [])}
    candidates = report.get("issues_with_needs_review") or report.get("observations", [])
    if args.limit:
        candidates = candidates[: args.limit]
    store = CompleteFactStore(args.project, args.compile_commands, args.output.parent / "facts")
    checker = ReviewClaimChecker(store)
    results, audit = [], []
    started = time.monotonic()
    for item in candidates:
        issue = dict(item)
        uid = str(issue.get("candidate_uid") or issue.get("id"))
        issue["review_checked_proofs_enabled"] = True
        checker.prepare(issue)
        check = checker.check(issue)
        proof = deterministic_decision_proof(issue, outcome="reject")
        results.append(
            {
                "candidate_uid": uid,
                "function": issue.get("function"),
                "rule_id": issue.get("rule_id"),
                "original_pool": "confirmed" if uid in confirmed else "review",
                "check": check,
                "rejection_proof": proof.to_dict() if proof else None,
                "conditional_risks": issue.get("review_conditional_risks", []),
                "related_proposals": issue.get("review_related_proposals", []),
            }
        )
        audit.append(
            {"candidate_uid": uid, "classification": "unknown", "auditor": "", "rationale": ""}
        )
    payload = {
        "schema_version": "zscope.review-compiler-pilot.v1",
        "formal": False,
        "input_kind": "report_projection_not_complete_checkpoint",
        "tokens": 0,
        "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
        "implementation_sha256": {
            str(path.relative_to(Path(__file__).resolve().parents[1])): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in [
                Path(__file__).resolve(),
                Path(__file__).resolve().parents[1] / "zscope/retrieval/validation_facts.py",
                Path(__file__).resolve().parents[1] / "zscope/core/validation/review_checks.py",
            ]
        },
        "elapsed_seconds": time.monotonic() - started,
        "counts": dict(Counter(f'{r["original_pool"]}:{r["check"]["status"]}' for r in results)),
        "reasons": dict(Counter(r["check"]["reason"] for r in results)),
        "results": results,
        "acceptance": "unverified_independent_audit_and_paired_model_replay_required",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    args.output.with_name("audit-pending.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {k: payload[k] for k in ("counts", "reasons", "elapsed_seconds", "acceptance")},
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
