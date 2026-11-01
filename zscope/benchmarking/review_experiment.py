"""Offline review experiment accounting, separate from scanner/model inputs.

The official Range scorer is unchanged. Unmatched findings are never inferred
to be false positives here. Independent audit labels and official truth-set
results must be supplied after replay.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any, Callable, Dict, Iterable

from ..retrieval.validation_facts import digest

AUDIT_VERSION = "zscope.review-audit.v1"
ARMS = ("baseline", "protocol", "facts", "neutral", "positive", "related")
CLASSES = {"true_defect", "provable_fp", "duplicate", "out_of_scope", "unknown"}


def freeze_audit(records: list[Dict[str, Any]], directory: Path) -> Path:
    ids = set()
    for record in records:
        uid = str(record.get("candidate_uid") or "")
        if not uid or uid in ids or record.get("classification") not in CLASSES:
            raise ValueError(
                "audit requires unique candidate identities and explicit classifications"
            )
        if record["classification"] != "unknown" and not (
            record.get("rationale") and record.get("auditor")
        ):
            raise ValueError("resolved audit labels require rationale and independent auditor")
        ids.add(uid)
    payload = {
        "schema_version": AUDIT_VERSION,
        "records": sorted(records, key=lambda r: r["candidate_uid"]),
    }
    uid = "AUDIT_" + digest(payload)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{uid}.json"
    content = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if target.exists() and target.read_text(encoding="utf-8") != content:
        raise ValueError("frozen audit cannot be overwritten")
    target.write_text(content, encoding="utf-8")
    return target


def load_audit(path: Path) -> Dict[str, Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != AUDIT_VERSION or path.stem != "AUDIT_" + digest(data):
        raise ValueError("audit identity mismatch")
    seen = set()
    for record in data.get("records", []):
        uid = record.get("candidate_uid")
        label = record.get("classification")
        if not uid or uid in seen or label not in CLASSES:
            raise ValueError("invalid or duplicate frozen audit record")
        if label != "unknown" and not (record.get("rationale") and record.get("auditor")):
            raise ValueError("resolved frozen audit requires independent rationale")
        seen.add(uid)
    return {str(r["candidate_uid"]): r for r in data["records"]}


def arm_flags(arm: str) -> Dict[str, bool]:
    if arm not in ARMS:
        raise ValueError("unknown review ablation")
    return {
        "validation_review_protocol": arm != "baseline",
        "validation_checked_proofs": arm in {"facts", "neutral", "positive", "related"},
        "validation_positive_case": arm in {"positive", "related"},
        "validation_related_findings": arm == "related",
        # Baseline and protocol execute the same pass; only its envelope and
        # acceptance gate change in the protocol ablation.
        "validation_v2b_adjudication": True,
        "validation_v3_reattempt": True,
        "validation_review_checkpoint": True,
    }


def _outcomes(run: Dict[str, Any]) -> list[Dict[str, Any]]:
    return [item for item in run.get("outcomes", []) if isinstance(item, dict)]


def compare_paired_replays(
    baseline: Dict[str, Any],
    runs: list[Dict[str, Any]],
    audit: Dict[str, Dict[str, Any]],
    *,
    replay_proof: Callable[[Dict[str, Any]], bool],
) -> Dict[str, Any]:
    """Fail closed on unknown labels, omitted candidates, or unscored truth sets."""
    base = _outcomes(baseline)
    base_ids = {str(i["candidate_uid"]) for i in base}

    def classification(item: Dict[str, Any]) -> str:
        label = str(
            audit.get(str(item.get("candidate_uid") or ""), {}).get("classification") or "unknown"
        )
        return label if label in CLASSES else "unknown"

    def count(items: Iterable[Dict[str, Any]], disposition: str, label: str) -> int:
        return sum(
            i.get("candidate_disposition") == disposition and classification(i) == label
            for i in items
        )

    base_fp = count(base, "needs_review", "provable_fp")
    base_confirmed_fp = count(base, "confirmed", "provable_fp")
    base_confirmed_truth = set(baseline.get("confirmed_truth_ids") or [])
    base_review_truth = set(baseline.get("review_truth_ids") or [])
    measurements = []
    audit_commitment = "AUDIT_" + digest(
        {
            "schema_version": AUDIT_VERSION,
            "records": sorted(audit.values(), key=lambda r: r["candidate_uid"]),
        }
    )
    for run in runs:
        items = _outcomes(run)
        ids = {str(i["candidate_uid"]) for i in items}
        aliases = {str(uid) for i in items for uid in i.get("alias_candidate_uids", [])}
        rejections = [i for i in items if i.get("candidate_disposition") in {
            "rejected_with_proof", "rejected_with_evidence"}]
        proof_replay = all(replay_proof(i) for i in rejections
                           if i.get("candidate_disposition") == "rejected_with_proof")
        audited_defect_rejected = any(classification(i) == "true_defect" for i in rejections)
        unlabelled = [str(i["candidate_uid"]) for i in items if classification(i) == "unknown"]
        confirmed_truth = set(run.get("confirmed_truth_ids") or [])
        review_truth = set(run.get("review_truth_ids") or [])
        truth_available = all(
            key in value
            for value in (baseline, run)
            for key in ("confirmed_truth_ids", "review_truth_ids")
        )
        measurements.append(
            {
                "pair_id": run.get("pair_id"),
                "review_true_fp": count(items, "needs_review", "provable_fp"),
                "arm": run.get("arm"),
                "confirmed_true_fp": count(items, "confirmed", "provable_fp"),
                "confirmed_truth_preserved": truth_available
                and base_confirmed_truth <= confirmed_truth,
                "review_truth_preserved": truth_available
                and base_review_truth <= (review_truth | confirmed_truth),
                "confirmed_fp_not_increased": count(items, "confirmed", "provable_fp")
                <= base_confirmed_fp,
                "all_original_candidates_accounted": base_ids <= (ids | aliases),
                "frozen_audit_matches": baseline.get("audit_commitment")
                == run.get("audit_commitment")
                == audit_commitment,
                "paired_inputs_match": all(
                    baseline.get(key) is not None and baseline.get(key) == run.get(key)
                    for key in ("checkpoint_manifest_hash", "model", "investigation_limits")
                ),
                "rejections_replayed": proof_replay,
                "audited_defect_rejected": audited_defect_rejected,
                "semantic_rejected_true_fp": count(items, "rejected_with_evidence", "provable_fp"),
                "semantic_rejected_true_defect": count(items, "rejected_with_evidence", "true_defect"),
                "unresolved_audit_ids": unlabelled,
                "new_confirmed_truth_ids": sorted(confirmed_truth - base_confirmed_truth),
                "conditional_review_count": sum(
                    i.get("analysis_scope") == "conditional_source_branch"
                    and i.get("candidate_disposition") == "needs_review"
                    for i in items
                ),
                "tokens": run.get("tokens"),
                "contributions": {
                    "checked_counterproof_rejections": sum(
                        bool(i.get("review_checked_proof")) for i in rejections
                    ),
                    "rejection_refuted_unconfirmed": sum(
                        i.get("review_disposition_reason") == "rejection_refuted_unconfirmed"
                        for i in items
                    ),
                    "v3_positive_case_entries": sum(
                        i.get("review_v3_objective") == "positive_case" for i in items
                    ),
                    "v3_neutral_entries": sum(
                        i.get("review_v3_objective") == "neutral_investigation" for i in items
                    ),
                    "v2b_audit_entries": sum(i.get("validator_v2b_entered") is True for i in items),
                    "related_candidates": sum(i.get("related_generation") == 1 for i in items),
                    "related_confirmed": sum(
                        i.get("related_generation") == 1
                        and i.get("candidate_disposition") == "confirmed"
                        for i in items
                    ),
                    "recorded_investigation_facts": sum(
                        int(i.get("v3_investigation_fact_count") or 0) for i in items
                    ),
                },
                "elapsed_seconds": run.get("elapsed_seconds"),
                "unknown_reasons": [
                    r.get("reason")
                    for i in items
                    for r in i.get("review_claim_checks", [])
                    if r.get("status") == "unknown"
                ],
            }
        )
    median = (
        statistics.median([m["review_true_fp"] for m in measurements]) if measurements else None
    )
    reduction = 1 - median / base_fp if median is not None and base_fp > 0 else None
    five_pairs = (
        len(measurements) == 5
        and len({m["pair_id"] for m in measurements}) == 5
        and all(m["pair_id"] is not None for m in measurements)
    )
    same_arm = bool(
        runs and len({r.get("arm") for r in runs}) == 1 and runs[0].get("arm") in ARMS[1:]
    )
    passed = bool(
        five_pairs
        and same_arm
        and reduction is not None
        and reduction >= 0.5
        and not any(classification(i) == "unknown" for i in base)
        and all(
            m["confirmed_truth_preserved"]
            and m["review_truth_preserved"]
            and m["confirmed_fp_not_increased"]
            and m["all_original_candidates_accounted"]
            and m["rejections_replayed"]
            and m["frozen_audit_matches"]
            and m["paired_inputs_match"]
            and not m["audited_defect_rejected"]
            and not m["unresolved_audit_ids"]
            for m in measurements
        )
    )
    return {
        "schema_version": "zscope.review-experiment-evaluation.v1",
        "status": "passed" if passed else "experimental",
        "baseline_review_true_fp": base_fp,
        "median_review_true_fp": median,
        "review_true_fp_reduction": reduction,
        "five_unique_pairs": five_pairs,
        "same_ablation_arm": same_arm,
        "runs": measurements,
        "note": "Independent audit and official root-deduplicated scoring are required; unmatched is not FP.",
    }
