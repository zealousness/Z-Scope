"""Post-score TP/FP/FN diagnostics over frozen product decision traces.

This module is deliberately owned by the scorer.  It reads truth only after a
scan report and its answer-free traces have been frozen, and never mutates
those product artifacts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .protocol import report_issues
from ..orchestration.decision_trace import (
    DecisionTraceError,
    load_decision_trace,
    verify_coverage_trace,
)


POSTSCORE_TRACE_SCHEMA_VERSION = "zscope.postscore-decision-trace.v1"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _truth_records(truth: Mapping[str, Any]) -> List[Dict[str, Any]]:
    values = truth.get("vulnerabilities") or []
    return [dict(value) for value in values if isinstance(value, Mapping)]


def _truth_by_id(truth: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(value.get("id") or index): value for index, value in enumerate(_truth_records(truth))
    }


def _truth_anchor_terms(value: Mapping[str, Any]) -> List[str]:
    terms: set[str] = set()
    for key in (
        "file",
        "function",
        "primary_function",
        "secondary_function",
        "category",
        "cwe",
    ):
        item = str(value.get(key) or "").strip().lower().replace("\\", "/")
        if item:
            terms.add(item)
    for key in ("locations", "additional_locations", "secondary_locations"):
        raw = value.get(key)
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
            for location in raw:
                if not isinstance(location, Mapping):
                    continue
                for location_key in ("file", "function"):
                    item = str(location.get(location_key) or "").strip().lower()
                    if item:
                        terms.add(item.replace("\\", "/"))
    return sorted(terms)


def _safe_trace_path(snapshot_dir: Path, relative: str) -> Optional[Path]:
    if not relative:
        return None
    candidate = (snapshot_dir / relative).resolve()
    root = snapshot_dir.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if candidate.is_symlink() or not candidate.is_file():
        return None
    return candidate


def _load_trace_for_issue(issue: Mapping[str, Any], snapshot_dir: Path) -> Dict[str, Any]:
    path = _safe_trace_path(snapshot_dir, str(issue.get("decision_trace_ref") or ""))
    if path is None:
        return {}
    expected = str(issue.get("decision_trace_sha256") or "")
    try:
        value = load_decision_trace(path)
    except DecisionTraceError:
        return {"trace_error": "finding_trace_invalid_json"}
    if expected and str(value.get("document_sha256") or "") != expected:
        return {"trace_error": "finding_trace_hash_mismatch"}
    return dict(value) if isinstance(value, Mapping) else {"trace_error": "invalid_trace"}


def _coverage_candidates(
    manifest: Mapping[str, Any],
    snapshot_dir: Path,
) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    raw = manifest.get("coverage_traces") or {}
    if not isinstance(raw, Mapping):
        return result
    for unit_uid, record in sorted(raw.items()):
        if not isinstance(record, Mapping):
            continue
        path = _safe_trace_path(snapshot_dir, str(record.get("path") or ""))
        if path is None:
            continue
        body = path.read_bytes()
        try:
            trace = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        valid, _reason = verify_coverage_trace(trace) if isinstance(trace, Mapping) else (False, "")
        if (
            not valid
            or str(trace.get("trace_root_sha256") or "")
            != str(record.get("trace_root_sha256") or "")
            or str(trace.get("document_sha256") or "") != str(record.get("document_sha256") or "")
        ):
            continue
        if isinstance(trace, Mapping):
            result.append({"audit_unit_uid": str(unit_uid), "trace": dict(trace)})
    return result


def _load_frozen_manifest(summary: Mapping[str, Any], snapshot_dir: Path) -> Dict[str, Any]:
    path = snapshot_dir / "decision_trace_manifest.json"
    if not path.is_file() or path.is_symlink():
        return dict(summary)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return dict(summary)
    if not isinstance(value, Mapping):
        return dict(summary)
    body = dict(value)
    supplied = str(body.pop("manifest_sha256", ""))
    if supplied != _sha256_json(body):
        return dict(summary)
    expected = str(summary.get("manifest_sha256") or "")
    if expected and expected != supplied:
        return dict(summary)
    return dict(value)


def _matching_coverage(
    truth_record: Mapping[str, Any],
    coverage: Iterable[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    terms = _truth_anchor_terms(truth_record)
    matches: List[Dict[str, Any]] = []
    for record in coverage:
        serialized = (
            json.dumps(record.get("trace") or {}, ensure_ascii=False).lower().replace("\\", "/")
        )
        matched = [term for term in terms if term and term in serialized]
        if not matched:
            continue
        trace = record.get("trace") or {}
        events = trace.get("events") if isinstance(trace, Mapping) else []
        reason_codes = [
            str(event.get("reason_code") or "")
            for event in events or []
            if isinstance(event, Mapping)
        ]
        matches.append(
            {
                "audit_unit_uid": str(record.get("audit_unit_uid") or ""),
                "matched_anchor_terms": sorted(matched),
                "reason_codes": reason_codes,
            }
        )
    return matches


def _fn_reason(
    *,
    review_issue: Optional[Mapping[str, Any]],
    trace: Mapping[str, Any],
    coverage: Sequence[Mapping[str, Any]],
) -> str:
    if review_issue is not None:
        disposition = str(
            trace.get("terminal_disposition") or review_issue.get("candidate_disposition") or ""
        )
        reasons = {str(value) for value in trace.get("terminal_reason_codes") or []}
        if disposition == "needs_review":
            if "NEEDS_REVIEW_VERIFIED_BUT_PROMOTION_BLOCKED" in reasons:
                return "closure_complete_but_promotion_failed"
            if "NEEDS_REVIEW_EVIDENCE_CONFLICT" in reasons:
                return "evidence_conflict_unresolved"
            if "NEEDS_REVIEW_MODEL_REJECT_NO_PROOF" in reasons:
                return "model_rejected_without_counterproof"
            if "V3_NOT_ELIGIBLE_RISK" in reasons:
                return "v3_not_eligible"
            if "V3_STOP_NO_PROGRESS" in reasons:
                return "v3_no_fact_gain"
            return "provider_or_verifier_open_clauses"
        if disposition in {"rejected", "rejected_with_proof"}:
            return "deterministic_counterproof_or_scope_error"
        return "scorer_structured_anchor_mismatch"
    coverage_reasons = {
        str(reason) for record in coverage for reason in record.get("reason_codes") or []
    }
    if "AUDIT_UNIT_SUPPRESSED_LOCAL_COVERAGE" in coverage_reasons:
        return "audit_unit_suppressed_local_coverage"
    if "SIGNAL_REGISTRATION_REJECTED" in coverage_reasons:
        return "signal_registration_rejected"
    if "PRODUCER_NO_SIGNAL" in coverage_reasons:
        return "producer_no_signal"
    if coverage:
        return "audit_unit_ran_without_matching_candidate"
    return "audit_unit_not_planned_or_not_traceable"


def build_postscore_decision_trace(
    *,
    report: Mapping[str, Any],
    truth: Mapping[str, Any],
    score_views: Mapping[str, Any],
    snapshot_dir: Path,
) -> Dict[str, Any]:
    """Join frozen report/trace artifacts with truth, strictly after scoring."""

    default_score = score_views.get("default") or {}
    review_score = score_views.get("with_needs_review") or {}
    default_issues = report_issues(dict(report), "default")
    review_issues = report_issues(dict(report), "with_needs_review")
    truth_map = _truth_by_id(truth)
    manifest_summary = (
        (
            (report.get("run_manifest") or {}).get("decision_trace")
            if isinstance(report.get("run_manifest"), Mapping)
            else None
        )
        or (
            (report.get("metadata") or {}).get("decision_trace")
            if isinstance(report.get("metadata"), Mapping)
            else None
        )
        or {}
    )
    manifest = _load_frozen_manifest(manifest_summary, snapshot_dir)
    coverage = _coverage_candidates(manifest, snapshot_dir)

    default_pair_by_truth = {
        str(pair.get("truth_id") or ""): pair
        for pair in default_score.get("matched_pairs") or []
        if isinstance(pair, Mapping)
    }
    review_pair_by_truth = {
        str(pair.get("truth_id") or ""): pair
        for pair in review_score.get("matched_pairs") or []
        if isinstance(pair, Mapping)
    }
    records: List[Dict[str, Any]] = []
    for truth_id, truth_record in sorted(truth_map.items()):
        default_pair = default_pair_by_truth.get(truth_id)
        review_pair = review_pair_by_truth.get(truth_id)
        pair = default_pair or review_pair
        issue: Optional[Dict[str, Any]] = None
        view = "missed"
        if default_pair is not None:
            index = int(default_pair.get("issue_index") or 0)
            issue = default_issues[index] if 0 <= index < len(default_issues) else None
            view = "default"
        elif review_pair is not None:
            index = int(review_pair.get("issue_index") or 0)
            issue = review_issues[index] if 0 <= index < len(review_issues) else None
            view = "with_needs_review_only"
        trace = _load_trace_for_issue(issue or {}, snapshot_dir) if issue else {}
        coverage_matches = _matching_coverage(truth_record, coverage)
        records.append(
            {
                "truth_id": truth_id,
                "classification": "TP" if pair is not None else "FN",
                "view": view,
                "issue_identity": str((pair or {}).get("issue_identity") or ""),
                "validation_cluster_uid": str((issue or {}).get("validation_cluster_uid") or ""),
                "decision_trace_ref": str((issue or {}).get("decision_trace_ref") or ""),
                "terminal_disposition": str(trace.get("terminal_disposition") or ""),
                "terminal_reason_codes": list(trace.get("terminal_reason_codes") or []),
                "first_divergence": (
                    "none"
                    if default_pair is not None
                    else _fn_reason(
                        review_issue=issue,
                        trace=trace,
                        coverage=coverage_matches,
                    )
                ),
                "coverage_matches": coverage_matches,
                "matcher": dict((pair or {}).get("match") or {}),
            }
        )

    fp_records: List[Dict[str, Any]] = []
    for record in default_score.get("unmatched_issue_classifications") or []:
        if not isinstance(record, Mapping):
            continue
        index = int(record.get("issue_index") or 0)
        issue = default_issues[index] if 0 <= index < len(default_issues) else {}
        trace = _load_trace_for_issue(issue, snapshot_dir)
        fp_records.append(
            {
                "classification": "FP",
                "issue_index": index,
                "issue_identity": str(record.get("issue_identity") or ""),
                "validation_cluster_uid": str(issue.get("validation_cluster_uid") or ""),
                "decision_trace_ref": str(issue.get("decision_trace_ref") or ""),
                "terminal_reason_codes": list(trace.get("terminal_reason_codes") or []),
                "matcher_classification": str(record.get("classification") or "false_positive"),
                "first_possible_divergence": (
                    "finding_root_projection"
                    if record.get("classification") == "same_product_root"
                    else (
                        "scorer_structured_anchor_mismatch"
                        if record.get("classification")
                        in {"cross_anchor_overlap", "weak_legacy_overlap"}
                        else "candidate_or_truth_contract_requires_independent_review"
                    )
                ),
                "diagnostic_only": True,
            }
        )

    result: Dict[str, Any] = {
        "schema_version": POSTSCORE_TRACE_SCHEMA_VERSION,
        "answer_material_present": True,
        "product_trace_mutated": False,
        "scoring_contract": dict(default_score.get("scoring_contract") or {}),
        "report_sha256": _sha256_json(report),
        "truth_sha256": _sha256_json(truth),
        "score_views_sha256": _sha256_json(score_views),
        "truth_records": records,
        "false_positive_records": fp_records,
        "summary": {
            "default_tp": int(default_score.get("true_positives") or 0),
            "with_needs_review_tp": int(review_score.get("true_positives") or 0),
            "false_negatives": int(default_score.get("false_negatives") or 0),
            "raw_false_positives": int(default_score.get("false_positives_raw") or 0),
        },
    }
    result["postscore_trace_sha256"] = _sha256_json(result)
    return result


def write_postscore_decision_trace(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_bytes(value) + b"\n")
