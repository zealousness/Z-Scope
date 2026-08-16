"""Post-score Range gap classification with answer-bearing inputs kept offline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from .protocol import issue_match_detail


GAP_ANALYSIS_SCHEMA_VERSION = "zscope.range-gap-analysis.v1"
GAP_CAUSES = frozenset(
    {
        "incorrect_deterministic_counterproof",
        "discovered_not_v3_eligible",
        "fact_resolution_exhausted",
        "v3_evidence_not_consumed",
        "model_rejected_with_closed_facts",
        "wrong_obligation_or_anchor",
        "no_candidate",
        "truth_contract_disputed",
    }
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _truth_id(record: Mapping[str, Any]) -> str:
    return str(record.get("id") or record.get("truth_id") or "")


def _view(score: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    views = _mapping(score.get("report_views"))
    candidate = views.get(name)
    if isinstance(candidate, Mapping):
        return candidate
    if name == "default":
        return score
    return {}


def _matched_pairs_by_truth(view: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    output: Dict[str, Mapping[str, Any]] = {}
    for raw in _list(view.get("matched_pairs")):
        if not isinstance(raw, Mapping):
            continue
        truth_id = str(raw.get("truth_id") or "")
        if truth_id:
            output[truth_id] = raw
    return output


def _issue_for_pair(
    pair: Mapping[str, Any],
    issues: list[Mapping[str, Any]],
) -> Mapping[str, Any]:
    raw_index = pair.get("issue_index")
    try:
        index = int(raw_index) if raw_index is not None else -1
    except (TypeError, ValueError):
        return {}
    return issues[index] if 0 <= index < len(issues) else {}


def _model_verdict(issue: Mapping[str, Any]) -> str:
    for field in ("model_verdict", "validator_verdict", "verdict"):
        value = str(issue.get(field) or "").strip().lower()
        if value:
            return value
    history = _list(issue.get("validator_pass_history"))
    if history and isinstance(history[-1], Mapping):
        return str(history[-1].get("verdict") or "").strip().lower()
    return ""


def _automatic_cause(issue: Mapping[str, Any]) -> tuple[str, str]:
    eligibility = _mapping(issue.get("validator_v3_eligibility"))
    if eligibility and eligibility.get("eligible") is False:
        return (
            "discovered_not_v3_eligible",
            str(eligibility.get("reason") or "candidate did not pass the V3 gate"),
        )
    closure = _mapping(issue.get("v3_evidence_closure"))
    fact_count = int(issue.get("v3_investigation_cited_fact_count") or 0)
    promotion = issue.get("candidate_promotion_eligible") is True
    if issue.get("validator_v3_entered"):
        if closure.get("complete") is True and _model_verdict(issue) == "rejected":
            return (
                "model_rejected_with_closed_facts",
                "V3 closed the required fact slice but the model verdict remained rejected",
            )
        if fact_count and not promotion:
            return (
                "v3_evidence_not_consumed",
                "V3 produced cited tool facts that did not satisfy the promotion contract",
            )
    return (
        "fact_resolution_exhausted",
        str(
            _mapping(issue.get("validator_fact_resolution")).get("status")
            or issue.get("evidence_completion_status")
            or "no deterministic fact delta closed the obligation"
        ),
    )


def _complete_rejection_proof(issue: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    for raw in _list(issue.get("deterministic_proofs")):
        if not isinstance(raw, Mapping):
            continue
        if (
            str(raw.get("outcome") or "").lower() == "reject"
            and str(raw.get("completeness") or "").lower() == "complete"
        ):
            return raw
    return None


def _terminal_match(
    truth_record: Mapping[str, Any],
    terminal_records: Iterable[Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Find a hidden terminal candidate using the same strong matcher-v2 pair."""

    for record in terminal_records:
        if issue_match_detail(dict(record), dict(truth_record), 8) is not None:
            return record
    return {}


def _load_overrides(value: Optional[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    if not value:
        return {}
    records = value.get("adjudications")
    if not isinstance(records, list):
        raise ValueError("gap adjudication must contain an adjudications array")
    output: Dict[str, Mapping[str, Any]] = {}
    for raw in records:
        if not isinstance(raw, Mapping):
            raise ValueError("gap adjudication records must be objects")
        truth_id = str(raw.get("truth_id") or "")
        cause = str(raw.get("primary_cause") or "")
        if not truth_id or cause not in GAP_CAUSES or truth_id in output:
            raise ValueError("gap adjudication has invalid or duplicate truth/cause")
        output[truth_id] = raw
    return output


def analyze_range_gaps(
    *,
    report: Mapping[str, Any],
    score: Mapping[str, Any],
    truth: Mapping[str, Any],
    source_hashes: Mapping[str, str],
    adjudication: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Classify every default-view miss exactly once after scoring."""

    scoring = _mapping(score.get("scoring_contract"))
    if scoring.get("matcher_version") != "zscope.truth-matcher.v2":
        raise ValueError("Range gap analysis requires zscope.truth-matcher.v2")
    truth_records = [
        record for record in _list(truth.get("vulnerabilities")) if isinstance(record, Mapping)
    ]
    truth_ids = {_truth_id(record) for record in truth_records}
    if "" in truth_ids or len(truth_ids) != len(truth_records):
        raise ValueError("truth IDs must be unique and non-empty")

    default_view = _view(score, "default")
    review_view = _view(score, "with_needs_review")
    default_matched = set(str(value) for value in _list(default_view.get("matched")))
    review_pairs = _matched_pairs_by_truth(review_view)
    report_review = [
        issue
        for issue in _list(report.get("issues_with_needs_review"))
        if isinstance(issue, Mapping)
    ]
    terminal_records = [
        issue
        for issue in _list(report.get("candidate_terminal_states"))
        if isinstance(issue, Mapping)
    ]
    overrides = _load_overrides(adjudication)
    unknown_overrides = sorted(set(overrides) - truth_ids)
    if unknown_overrides:
        raise ValueError(f"gap adjudication references unknown truth IDs: {unknown_overrides}")
    weak_truth_ids = {
        str(record.get("truth_id") or "")
        for record in _list(_mapping(default_view.get("match_diagnostics")).get("weak_pairs"))
        if isinstance(record, Mapping)
    }

    entries: list[Dict[str, Any]] = []
    counts = {cause: 0 for cause in sorted(GAP_CAUSES)}
    for record in truth_records:
        truth_id = _truth_id(record)
        if truth_id in default_matched:
            continue
        pair = review_pairs.get(truth_id)
        issue = _issue_for_pair(pair or {}, report_review)
        hidden_terminal = _terminal_match(record, terminal_records) if not pair else {}
        if truth_id in overrides:
            override = overrides[truth_id]
            cause = str(override["primary_cause"])
            reason = str(override.get("reason") or "independent adjudication")[:1000]
            evidence_refs = sorted(
                str(value) for value in _list(override.get("evidence_refs")) if str(value)
            )
            source = "independent_adjudication"
        elif pair:
            cause, reason = _automatic_cause(issue)
            evidence_refs = sorted(
                str(value) for value in _list(issue.get("evidence_refs")) if str(value)
            )[:32]
            source = "validation_lifecycle"
        elif hidden_terminal and _complete_rejection_proof(hidden_terminal):
            issue = hidden_terminal
            proof = _complete_rejection_proof(hidden_terminal) or {}
            cause = "incorrect_deterministic_counterproof"
            reason = (
                "matcher-v2 found a structurally coherent hidden candidate that was "
                f"rejected by deterministic proof {proof.get('proof_kind') or 'unknown'}; "
                "path correctness requires offline adjudication"
            )
            evidence_refs = sorted(
                str(value) for value in _list(proof.get("fact_ids")) if str(value)
            )
            source = "hidden_terminal_lifecycle"
        elif hidden_terminal:
            issue = hidden_terminal
            cause = "wrong_obligation_or_anchor"
            reason = "a coherent terminal candidate existed but was absent from both report views"
            evidence_refs = []
            source = "hidden_terminal_lifecycle"
        elif truth_id in weak_truth_ids:
            cause = "wrong_obligation_or_anchor"
            reason = "only a weak or incoherent candidate/truth pair was available"
            evidence_refs = []
            source = "matcher_v2_diagnostics"
        else:
            cause = "no_candidate"
            reason = "no strong or weak candidate/truth pair was present in the review view"
            evidence_refs = []
            source = "matcher_v2_diagnostics"
        counts[cause] += 1
        entries.append(
            {
                "truth_id": truth_id,
                "primary_cause": cause,
                "classification_source": source,
                "reason": reason,
                "matched_in_with_review": bool(pair),
                "candidate_uid": str(issue.get("candidate_uid") or ""),
                "validation_cluster_uid": str(issue.get("validation_cluster_uid") or ""),
                "evidence_refs": evidence_refs,
            }
        )
    if len(entries) != int(default_view.get("false_negatives") or len(entries)):
        raise ValueError("gap entry count does not match default-view false negatives")
    if sum(counts.values()) != len(entries):
        raise ValueError("gap cause counts do not conserve the miss set")
    return {
        "schema_version": GAP_ANALYSIS_SCHEMA_VERSION,
        "truth_version": str(truth.get("version") or ""),
        "matcher_version": "zscope.truth-matcher.v2",
        "source_hashes": dict(source_hashes),
        "run_binding": _run_binding(report),
        "default_true_positives": int(default_view.get("true_positives") or 0),
        "with_review_true_positives": int(review_view.get("true_positives") or 0),
        "false_negative_count": len(entries),
        "cause_counts": counts,
        "entries": entries,
    }


def _run_binding(report: Mapping[str, Any]) -> Dict[str, Any]:
    metadata = _mapping(report.get("metadata"))
    manifest = _mapping(report.get("run_manifest"))
    return {
        "run_id": str(manifest.get("run_id") or metadata.get("run_id") or ""),
        "git_commit": str(metadata.get("commit_sha") or manifest.get("source_revision") or ""),
        "source_tree_hash": str(manifest.get("source_tree_hash") or ""),
        "config_hash": str(manifest.get("config_hash") or metadata.get("config_hash") or ""),
        "effective_rules_sha256": str(
            manifest.get("effective_rules_sha256") or metadata.get("effective_rules_sha256") or ""
        ),
        "model_manifest_hash": str(manifest.get("model_manifest_hash") or ""),
        "runtime_spec": dict(_mapping(metadata.get("runtime_spec"))),
        "scan_depth": str(manifest.get("scan_depth") or metadata.get("scan_depth") or ""),
        "usage_events_sha256": str(
            _mapping(manifest.get("llm_usage_events_artifact")).get("sha256")
            or _mapping(metadata.get("llm_usage_events_artifact")).get("sha256")
            or ""
        ),
    }


def analyze_range_gap_files(
    *,
    report_path: Path,
    score_path: Path,
    truth_path: Path,
    adjudication_path: Optional[Path] = None,
    usage_events_path: Optional[Path] = None,
    replay_bundle_path: Optional[Path] = None,
) -> Dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    score = json.loads(score_path.read_text(encoding="utf-8"))
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    adjudication = (
        json.loads(adjudication_path.read_text(encoding="utf-8"))
        if adjudication_path is not None
        else None
    )
    return analyze_range_gaps(
        report=report,
        score=score,
        truth=truth,
        adjudication=adjudication,
        source_hashes={
            "report_sha256": _sha256(report_path),
            "score_sha256": _sha256(score_path),
            "truth_sha256": _sha256(truth_path),
            "adjudication_sha256": (
                _sha256(adjudication_path) if adjudication_path is not None else ""
            ),
            "usage_events_sha256": (
                _sha256(usage_events_path) if usage_events_path is not None else ""
            ),
            "replay_bundle_sha256": (
                _sha256(replay_bundle_path) if replay_bundle_path is not None else ""
            ),
        },
    )


__all__ = [
    "GAP_ANALYSIS_SCHEMA_VERSION",
    "GAP_CAUSES",
    "analyze_range_gap_files",
    "analyze_range_gaps",
]
