"""P5 validation evidence projection and review-memory helpers.

This module deliberately has no terminal-promotion policy.  The optional model
adapter can enrich evidence, but only the Proof Kernel and TerminalAuthority may
close a live Candidate Ledger record.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, cast

from ...common.issue_identity import canonical_issue_key, parse_issue_location
from ...memory import ReviewMemory


FALSE_POSITIVE_BASELINE_STATUSES = {"false_positive", "suppressed"}
TRUE_POSITIVE_BASELINE_STATUSES = {"accepted", "verified", "true_positive"}
VALIDATOR_DETAIL_FIELDS = (
    "exploit_scenario",
    "source",
    "sink",
    "control_of_source",
    "guard_analysis",
    "positive_evidence",
    "negative_evidence",
    "blocking_negative_evidence",
)
LOCATION_FILE_FIELDS = ("file", "file_path", "module_path")
LOCATION_LINE_FIELDS = ("line", "start_line")
LOCATION_END_LINE_FIELDS = ("end_line",)
LOCATION_STRING_FIELDS = (
    "location",
    "source_location",
    "sink_location",
    "source_loc",
    "sink_loc",
    "origin_location",
    "target_location",
)


def _as_dict(value: Any) -> Dict[str, Any]:
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


@dataclass
class PreValidationDecision:
    """Non-authoritative feedback retained for audit and history display."""

    action: str
    finding_kind: str
    rejection_source: str
    report_bucket: Optional[str] = "observations"
    baseline: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class ValidationOutcome:
    """Report projection after validation has mutated an issue."""

    report_bucket: Optional[str]
    memory_status: Optional[str] = None
    verdict: str = ""
    final_score: float = 0.0


class ValidationPipeline:
    """Collect validation evidence without deciding a live terminal outcome."""

    def __init__(
        self,
        user_config: Any,
        issue_key_fn: Callable[[Dict[str, Any]], str] = canonical_issue_key,
    ) -> None:
        self.user_config = user_config
        self.review_memory = (
            user_config if isinstance(user_config, ReviewMemory) else ReviewMemory(user_config)
        )
        self.issue_key_fn = issue_key_fn

    def suppression_category(self, issue: Dict[str, Any]) -> str:
        return str(
            issue.get("defect_class") or issue.get("subcategory") or issue.get("category") or ""
        )

    def apply_pre_validation_feedback(
        self,
        issue: Dict[str, Any],
        issue_func: str,
    ) -> Optional[PreValidationDecision]:
        """Return legacy/static feedback as an advisory, never as a closure."""

        static_decision = self._static_validation_advisory(issue)
        if static_decision:
            return static_decision

        category = self.suppression_category(issue)
        if self.review_memory.is_false_positive(
            str(issue_func),
            str(issue.get("location") or ""),
            category,
        ):
            return PreValidationDecision(
                action="suppress",
                finding_kind="suppressed_false_positive",
                rejection_source="user_config",
            )

        baseline = self.find_baseline(issue)
        if (
            baseline
            and str(baseline.get("status") or "").lower() in FALSE_POSITIVE_BASELINE_STATUSES
        ):
            return PreValidationDecision(
                action="suppress",
                finding_kind="suppressed_baseline",
                rejection_source="finding_baseline",
                baseline=baseline,
            )
        return None

    @staticmethod
    def _static_validation_advisory(
        issue: Dict[str, Any],
    ) -> Optional[PreValidationDecision]:
        evidence_pack = _as_dict(issue.get("evidence_pack"))
        validation_required = issue.get("validation_required")
        if validation_required is None:
            validation_required = evidence_pack.get("validation_required")
        if validation_required is not False:
            return None
        finding_kind = str(issue.get("finding_kind") or "").strip().lower()
        action = "audit_observation" if finding_kind == "audit_observation" else "suppress"
        return PreValidationDecision(
            action=action,
            finding_kind=(
                "audit_observation"
                if action == "audit_observation"
                else "static_suppressed_false_positive"
            ),
            rejection_source="static_analysis",
            report_bucket="observations" if action == "audit_observation" else None,
        )

    def find_baseline(self, issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        dedup_key = str(issue.get("dedup_key") or self.issue_key_fn(issue))
        return self.review_memory.get_finding_baseline_for_issue(issue, dedup_key)

    def history_feedback_score(self, issue: Dict[str, Any]) -> float:
        try:
            baseline = self.find_baseline(issue)
        except Exception:
            baseline = None
        if not baseline:
            return 0.5
        status = str(baseline.get("status") or "").lower()
        if status in TRUE_POSITIVE_BASELINE_STATUSES:
            return 1.0
        if status in FALSE_POSITIVE_BASELINE_STATUSES or status == "rejected":
            return 0.0
        return 0.5

    def score_components(
        self,
        issue: Dict[str, Any],
        val_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """Compute diagnostic scores; scores cannot close a P5 candidate."""

        val_data = val_data or {}
        rule_confidence = self._coerce_score(
            issue.get("rule_confidence", issue.get("confidence", 0.5)), default=0.5
        )
        path_completeness = self._path_completeness_score(issue, val_data)
        contract_consistency = self._contract_consistency_score(issue, val_data)
        validation_confidence = self._coerce_score(
            val_data.get("confidence_score", issue.get("confidence", 0.5)), default=0.5
        )
        closure = issue.get("v3_evidence_closure")
        if (
            str(val_data.get("pass") or "") == "investigation_synthesis"
            and str(val_data.get("verdict") or "").lower() == "verified"
            and isinstance(closure, dict)
            and closure.get("complete") is True
        ):
            validation_confidence = max(validation_confidence, 0.85)
        history_feedback = self.history_feedback_score(issue)
        final_score = (
            0.25 * rule_confidence
            + 0.25 * path_completeness
            + 0.20 * contract_consistency
            + 0.20 * validation_confidence
            + 0.10 * history_feedback
        )
        return {
            "rule_confidence": round(rule_confidence, 4),
            "path_completeness": round(path_completeness, 4),
            "contract_consistency": round(contract_consistency, 4),
            "validation_confidence": round(validation_confidence, 4),
            "history_feedback": round(history_feedback, 4),
            "final_score": round(final_score, 4),
        }

    def apply_unvalidated(
        self,
        issue: Dict[str, Any],
        score_data: Dict[str, float],
    ) -> ValidationOutcome:
        """Fail closed when the optional Proof Engine model adapter is disabled."""

        preserve_issue_location(issue)
        issue["validation_status"] = "needs_review"
        issue["candidate_disposition"] = "needs_review"
        issue["finding_kind"] = "needs_review"
        issue["score_components"] = score_data
        final_score = self._final_score(score_data)
        issue["final_score"] = final_score
        return ValidationOutcome(
            report_bucket="observations",
            verdict="needs_review",
            final_score=final_score,
        )

    def apply_validator_result(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        *,
        verdict: str,
        score_data: Dict[str, float],
    ) -> ValidationOutcome:
        """Record adapter evidence and fail closed pending Proof Engine closure."""

        preserve_issue_location(issue)
        issue["score_components"] = score_data
        final_score = self._final_score(score_data)
        issue["final_score"] = final_score
        issue["validator_verdict"] = verdict
        issue["model_verdict"] = verdict
        issue["model_adapter_effect"] = "evidence_only"
        if isinstance(val_data.get("blocking_negative_evidence"), bool):
            issue["blocking_negative_evidence"] = val_data["blocking_negative_evidence"]
        issue["validation_status"] = "needs_review"
        issue["candidate_disposition"] = "needs_review"
        issue["finding_kind"] = "needs_review"
        issue["validation_reasoning"] = str(val_data.get("reasoning") or "").strip()
        issue["confidence"] = val_data.get("confidence_score", issue.get("confidence", 0.5))
        self._copy_validator_detail_fields(issue, val_data)
        preserve_issue_location(issue, val_data)
        return ValidationOutcome(
            report_bucket="observations",
            memory_status="needs_review",
            verdict=verdict,
            final_score=final_score,
        )

    def apply_validation_failure(
        self,
        issue: Dict[str, Any],
        error: Any,
    ) -> ValidationOutcome:
        preserve_issue_location(issue)
        issue["validation_status"] = "engine_failed"
        issue["candidate_disposition"] = "engine_failed"
        issue["finding_kind"] = "validation_engine_failed"
        issue["record_role"] = "operational_obligation"
        issue["engine_status"] = "failed"
        issue["validation_error"] = error
        return ValidationOutcome(
            report_bucket="observations",
            memory_status="engine_failed",
            verdict="engine_failed",
        )

    @staticmethod
    def _final_score(score_data: Dict[str, float]) -> float:
        try:
            return float(score_data.get("final_score", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _coerce_score(value: Any, default: float = 0.5) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            score = default
        return max(0.0, min(1.0, score))

    def _path_completeness_score(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> float:
        closure = issue.get("v3_evidence_closure")
        resolved = {
            str(value)
            for value in (
                (closure.get("resolved_fact_kinds") or []) if isinstance(closure, dict) else []
            )
            if str(value)
        }
        if (
            str(val_data.get("pass") or "") == "investigation_synthesis"
            and str(val_data.get("verdict") or "").lower() == "verified"
            and isinstance(closure, dict)
            and closure.get("complete") is True
            and "source_sink_reachability" in resolved
        ):
            return 1.0
        evidence = _as_dict(issue.get("evidence_pack"))
        path = _as_dict(evidence.get("path"))
        if path.get("complete") is True or path.get("complete_in_function") is True:
            return 1.0
        if (issue.get("source") or val_data.get("source")) and (
            issue.get("sink") or val_data.get("sink")
        ):
            return 0.75
        if issue.get("evidence_refs"):
            return 0.7
        return 0.5

    @staticmethod
    def _contract_consistency_score(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> float:
        closure = issue.get("v3_evidence_closure")
        resolved = {
            str(value)
            for value in (
                (closure.get("resolved_fact_kinds") or []) if isinstance(closure, dict) else []
            )
            if str(value)
        }
        contract_fact_kinds = {
            "caller_contract",
            "cleanup_coverage",
            "happens_before",
            "lockset",
            "ownership_transfer",
        }
        if (
            str(val_data.get("pass") or "") == "investigation_synthesis"
            and str(val_data.get("verdict") or "").lower() == "verified"
            and val_data.get("blocking_negative_evidence") is False
            and isinstance(closure, dict)
            and closure.get("complete") is True
            and bool(resolved & contract_fact_kinds)
            and not bool(issue.get("evidence_conflict"))
        ):
            return 0.8
        negative = issue.get("negative_evidence") or val_data.get("negative_evidence") or []
        if negative:
            return 0.55
        if (issue.get("source") or val_data.get("source")) and (
            issue.get("sink") or val_data.get("sink")
        ):
            return 0.8
        if issue.get("finding_kind") == "backend_signal":
            return 0.7
        return 0.6

    @staticmethod
    def _copy_validator_detail_fields(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> None:
        for field in VALIDATOR_DETAIL_FIELDS:
            if field in val_data and val_data.get(field) not in (None, ""):
                issue[field] = val_data.get(field)


def preserve_issue_location(issue: Dict[str, Any], *extra_sources: Any) -> None:
    """Keep candidate source coordinates on reviewable evidence records."""

    if not isinstance(issue, dict):
        return
    current = _location_from_issue(issue)
    sources: List[Any] = [issue]
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        sources.append(pack)
        candidate_evidence = pack.get("candidate_evidence")
        if isinstance(candidate_evidence, dict):
            sources.append(candidate_evidence)
    sources.extend(source for source in extra_sources if source)
    _preserve_location_detail_fields(issue, sources)

    recovered = current
    for candidate in _iter_location_candidates(sources):
        recovered = _merge_location(recovered, candidate)
        if recovered.file_path and recovered.start_line is not None:
            break
    if recovered.file_path:
        if not issue.get("file"):
            issue["file"] = recovered.file_path
        if not issue.get("file_path"):
            issue["file_path"] = recovered.file_path
        if not issue.get("location") and recovered.start_line is not None:
            issue["location"] = _format_location(recovered)
    if recovered.start_line is not None:
        if not issue.get("line"):
            issue["line"] = recovered.start_line
        if not issue.get("start_line"):
            issue["start_line"] = recovered.start_line
    if recovered.end_line is not None:
        if not issue.get("end_line"):
            issue["end_line"] = recovered.end_line

    if issue.get("location"):
        parsed_file, parsed_line = parse_issue_location(str(issue.get("location") or ""))
        if parsed_file and parsed_line:
            if not issue.get("file"):
                issue["file"] = parsed_file
            if not issue.get("file_path"):
                issue["file_path"] = parsed_file
            if not issue.get("line"):
                issue["line"] = parsed_line
            if not issue.get("start_line"):
                issue["start_line"] = parsed_line


def _preserve_location_detail_fields(issue: Dict[str, Any], sources: Iterable[Any]) -> None:
    for field in LOCATION_STRING_FIELDS:
        if issue.get(field):
            continue
        value = _find_first_field(sources, field)
        if value not in (None, ""):
            issue[field] = value


def _find_first_field(values: Iterable[Any], field: str, *, depth: int = 0) -> Any:
    if depth > 5:
        return None
    for value in values:
        if isinstance(value, dict):
            if field in value and value.get(field) not in (None, ""):
                return value.get(field)
            found = _find_first_field(value.values(), field, depth=depth + 1)
            if found not in (None, ""):
                return found
        elif isinstance(value, list):
            found = _find_first_field(value[:40], field, depth=depth + 1)
            if found not in (None, ""):
                return found
    return None


@dataclass
class _LocationCandidate:
    file_path: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None


def _location_from_issue(issue: Dict[str, Any]) -> _LocationCandidate:
    location = _parse_location_text(str(issue.get("location") or ""))
    for key in LOCATION_FILE_FIELDS:
        file_value = _coerce_file(issue.get(key))
        if file_value and not location.file_path:
            location.file_path = file_value
    for key in LOCATION_LINE_FIELDS:
        line_value = _coerce_int(issue.get(key))
        if line_value is not None and location.start_line is None:
            location.start_line = line_value
    for key in LOCATION_END_LINE_FIELDS:
        line_value = _coerce_int(issue.get(key))
        if line_value is not None and location.end_line is None:
            location.end_line = line_value
    return location


def _iter_location_candidates(
    values: Iterable[Any], *, depth: int = 0
) -> Iterable[_LocationCandidate]:
    if depth > 5:
        return
    for value in values:
        if isinstance(value, dict):
            candidate = _location_from_mapping(value)
            if candidate.file_path or candidate.start_line is not None:
                yield candidate
            yield from _iter_location_candidates(value.values(), depth=depth + 1)
        elif isinstance(value, list):
            yield from _iter_location_candidates(value[:40], depth=depth + 1)
        elif isinstance(value, str):
            candidate = _parse_location_text(value)
            if candidate.file_path or candidate.start_line is not None:
                yield candidate


def _location_from_mapping(value: Dict[str, Any]) -> _LocationCandidate:
    candidate = _LocationCandidate()
    for key in LOCATION_STRING_FIELDS:
        if key in value:
            candidate = _merge_location(candidate, _parse_location_text(str(value.get(key) or "")))
    for key in LOCATION_FILE_FIELDS:
        file_value = _coerce_file(value.get(key))
        if file_value and not candidate.file_path:
            candidate.file_path = file_value
    for key in LOCATION_LINE_FIELDS:
        line_value = _coerce_int(value.get(key))
        if line_value is not None and candidate.start_line is None:
            candidate.start_line = line_value
    for key in LOCATION_END_LINE_FIELDS:
        line_value = _coerce_int(value.get(key))
        if line_value is not None and candidate.end_line is None:
            candidate.end_line = line_value
    return candidate


def _parse_location_text(value: str) -> _LocationCandidate:
    text = value.replace("\\", "/").strip()
    if not text:
        return _LocationCandidate()
    file_path, line = parse_issue_location(text)
    end_line = None
    if file_path and line is not None:
        match = re.search(r":\s*\d+\s*-\s*(\d+)", text)
        if match:
            end_line = _coerce_int(match.group(1))
        return _LocationCandidate(file_path=file_path, start_line=line, end_line=end_line)
    if line is not None:
        match = re.search(r"^\s*\d+\s*-\s*(\d+)\s*$", text)
        return _LocationCandidate(
            start_line=line, end_line=_coerce_int(match.group(1)) if match else None
        )
    match = re.search(
        r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+|[A-Za-z0-9_./-]+\.[chp]+)"
        r"(?:[^\d\n\r]{0,24})(\d+)(?:\s*-\s*(\d+))?",
        text,
        flags=re.IGNORECASE,
    )
    if match:
        return _LocationCandidate(
            file_path=match.group(1).lower(),
            start_line=_coerce_int(match.group(2)),
            end_line=_coerce_int(match.group(3)),
        )
    return _LocationCandidate()


def _merge_location(base: _LocationCandidate, incoming: _LocationCandidate) -> _LocationCandidate:
    return _LocationCandidate(
        file_path=base.file_path or incoming.file_path,
        start_line=base.start_line if base.start_line is not None else incoming.start_line,
        end_line=base.end_line if base.end_line is not None else incoming.end_line,
    )


def _format_location(location: _LocationCandidate) -> str:
    if location.start_line is None:
        return location.file_path
    if location.end_line is not None and location.end_line != location.start_line:
        return f"{location.file_path}:{location.start_line}-{location.end_line}"
    return f"{location.file_path}:{location.start_line}"


def _coerce_file(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if re.search(r"\.[chp]+$", text, flags=re.IGNORECASE):
        return text.lower()
    parsed_file, _line = parse_issue_location(text)
    return parsed_file


def _coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None
