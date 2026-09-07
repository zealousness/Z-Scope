"""Machine-readable benchmark protocol and metrics for Z-SCOPE."""

from __future__ import annotations

import json
import hashlib
import heapq
import math
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, cast

from zscope._version import __version__
from zscope.common.issue_identity import stable_issue_fingerprint
from zscope.benchmarking.policy import DEFAULT_BENCHMARK_POLICY
from zscope.benchmarking.attestation import validate_balanced_attestation
from zscope.benchmarking.isolation import validate_oci_execution_evidence
from zscope.benchmarking.truth_contract import (
    summarize_truth_contract,
    truth_records_for_contract,
)
from zscope.reporting.attribution import (
    FINDING_ATTRIBUTION_SCHEMA_VERSION,
    FindingAttribution,
    finding_attribution_mapping_errors,
)

SCHEMA_VERSION = "zscope.benchmark.v4"
INTEGRITY_SCHEMA_VERSION = "zscope.benchmark.integrity.v1"
ATTRIBUTION_SCHEMA_VERSION = FINDING_ATTRIBUTION_SCHEMA_VERSION
USAGE_LEDGER_SCHEMA_VERSION = "zscope.llm-usage-ledger.v1"
CANDIDATE_FUNNEL_SCHEMA_VERSION = "zscope.candidate-funnel.v1"
MATCHER_VERSION = "zscope.truth-matcher.v2"
SOURCE_FILE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".i",
}

MIN_RELEASE_TRIALS = DEFAULT_BENCHMARK_POLICY.minimum_formal_trials
DEFAULT_BOOTSTRAP_SAMPLES = 2000


def _as_dict(value: Any) -> Dict[str, Any]:
    """Narrow dynamic benchmark artifacts to their expected mapping shape."""
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


FP_AUDIT_DUPLICATE_OF_GT = "duplicate_of_gt"
FP_AUDIT_TRUE_EXTRA_ADD_GT = "true_extra_add_gt"
FP_AUDIT_NEEDS_REVIEW_ONLY = "needs_review_only"
FP_AUDIT_FALSE_POSITIVE_SUPPRESS = "false_positive_suppress"
FP_AUDIT_SAME_PRODUCT_ROOT = "same_product_root"
FP_AUDIT_TRUTH_COVERED_ADDITIONAL = "truth_covered_additional"
FP_AUDIT_CROSS_ANCHOR_OVERLAP = "cross_anchor_overlap"
FP_AUDIT_WEAK_LEGACY_OVERLAP = "weak_legacy_overlap"

CONDITION_PURE_LLM_ENTRY = "pure_llm_entry_source"
CONDITION_PURE_LLM_REPO = "pure_llm_repo_context"
CONDITION_FULL_ZSCOPE = "full_zscope_pipeline"
CONDITION_CANDIDATES = "candidate_layer"

BENCHMARK_CONDITIONS = (
    CONDITION_PURE_LLM_ENTRY,
    CONDITION_PURE_LLM_REPO,
    CONDITION_FULL_ZSCOPE,
    CONDITION_CANDIDATES,
)

RUN_KINDS = ("smoke", "sample", "formal")

FalsePositiveClassifier = Callable[[Dict[str, Any]], Dict[str, Any]]


@dataclass(frozen=True)
class BenchmarkTrialKey:
    suite: str
    condition: str
    trial_index: int
    run_kind: str


def json_dump(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a file, or an empty string when unavailable."""

    path = Path(path)
    if not path.is_file():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_payload(payload: Any) -> str:
    """Return a deterministic SHA-256 digest for a JSON-compatible payload."""

    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def source_tree_manifest(project_root: Path) -> Dict[str, Any]:
    """Hash source inputs without including generated reports, caches, or build output."""

    project_root = Path(project_root)
    digest = hashlib.sha256()
    file_count = 0
    if not project_root.is_dir():
        return {"sha256": "", "file_count": 0}

    ignored_parts = {
        ".git",
        "build",
        "benchmark",
        "benchmark_runs",
        "runs",
    }
    candidates: List[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(project_root)
        if any(part in ignored_parts or part.startswith(".zscope") for part in relative.parts):
            continue
        if path.suffix.lower() not in SOURCE_FILE_SUFFIXES and path.name != "compile_commands.json":
            continue
        candidates.append(path)

    for path in sorted(candidates, key=lambda item: item.relative_to(project_root).as_posix()):
        relative_path = path.relative_to(project_root).as_posix()
        file_digest = sha256_file(path)
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        file_count += 1
    return {
        "sha256": digest.hexdigest() if file_count else "",
        "file_count": file_count,
    }


def build_benchmark_artifact_manifest(
    suite_root: Path,
    *,
    truth: Optional[Dict[str, Any]] = None,
    config_path: Optional[Path] = None,
    execution_config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Capture immutable benchmark/scorer/config/source identities for a trial."""

    suite_root = Path(suite_root)
    project_root = suite_root / "project"
    if not project_root.is_dir():
        project_root = suite_root
    truth_path = suite_root / "benchmark" / "ground_truth.json"
    entries_path = suite_root / "benchmark" / "entries.json"
    if not entries_path.is_file():
        entries_path = suite_root / "benchmark" / "deterministic_entries.json"
    benchmark_manifest_path = suite_root / "benchmark" / "manifest.json"
    selected_config = Path(config_path) if config_path else suite_root / "zscope.benchmark.yaml"
    selected_execution_config = (
        Path(execution_config_path) if execution_config_path else selected_config
    )
    source_manifest = source_tree_manifest(project_root)
    truth_digest = sha256_file(truth_path)
    if not truth_digest and truth is not None:
        truth_digest = sha256_payload(truth)
    return {
        "schema_version": INTEGRITY_SCHEMA_VERSION,
        "hash_algorithm": "sha256",
        "truth_sha256": truth_digest,
        "scorer_sha256": sha256_file(Path(__file__)),
        "config_sha256": sha256_file(selected_config),
        "execution_config_sha256": sha256_file(selected_execution_config),
        "benchmark_manifest_sha256": sha256_file(benchmark_manifest_path),
        "entries_sha256": sha256_file(entries_path),
        "source_manifest_sha256": source_manifest["sha256"],
        "source_file_count": source_manifest["file_count"],
        "benchmark_policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
        "benchmark_policy_id": DEFAULT_BENCHMARK_POLICY.policy_id,
    }


def issue_identity(issue: Dict[str, Any]) -> str:
    """Return a stable issue identity for run-to-run overlap metrics."""

    stable = stable_issue_fingerprint(issue)
    if stable:
        return str(stable)

    parts = [
        str(issue.get("dedup_key") or issue.get("id") or ""),
        str(issue.get("category") or issue.get("type") or issue.get("cwe") or ""),
        str(issue.get("function") or issue.get("func_name") or ""),
        _location_file(issue),
        str(_location_line(issue) or ""),
        _short_text(issue),
    ]
    raw = "|".join(part.lower().replace("\\", "/") for part in parts if part)
    return raw or json.dumps(issue, ensure_ascii=False, sort_keys=True)[:240]


def issue_identity_record(issue: Dict[str, Any]) -> Dict[str, Any]:
    """Return auditable identity metadata for benchmark reports."""

    pack = _as_dict(issue.get("evidence_pack"))
    stable = stable_issue_fingerprint(issue)
    return {
        "identity": issue_identity(issue),
        "stable_fingerprint": stable,
        "dedup_key": issue.get("dedup_key"),
        "candidate_id": issue.get("candidate_id") or issue.get("id"),
        "candidate_source": issue.get("candidate_source")
        or pack.get("candidate_source")
        or issue.get("finding_kind"),
        "baseline_match_strategy": issue.get("baseline_match_strategy"),
        "suppression_source": issue.get("suppression_source"),
        "attribution": finding_attribution(issue),
    }


def finding_attribution(issue: Dict[str, Any]) -> Dict[str, Any]:
    """Return explicit or conservatively inferred discovery/decision provenance."""

    explicit = issue.get("attribution") or issue.get("finding_attribution")
    confirmed_via = str(issue.get("confirmed_via") or "")
    if isinstance(explicit, dict):
        parsed = FindingAttribution.from_mapping(explicit)
        errors = finding_attribution_mapping_errors(explicit)
        return {
            "schema_version": ATTRIBUTION_SCHEMA_VERSION,
            "discovered_by": list(parsed.discovered_by) or ["unknown"],
            "decided_by": parsed.decided_by,
            "decision_level": parsed.decision_level,
            "confirmed_via": confirmed_via or str(explicit.get("confirmed_via") or ""),
            "attribution_inferred": False,
            "inferred": False,
            "valid": not errors,
            "errors": errors,
        }

    pack = _as_dict(issue.get("evidence_pack"))
    source_values = {
        str(value).strip().lower()
        for value in (
            issue.get("candidate_source"),
            issue.get("candidate_kind"),
            issue.get("finding_kind"),
            pack.get("candidate_source"),
        )
        if value
    }
    source_values.update(
        str(value).strip().lower() for value in (issue.get("evidence_sources") or []) if value
    )
    discovered = set()
    if any("llm" in value or "active_audit" in value for value in source_values):
        discovered.add("llm_active_discovery")
    if any(
        "backend_signal" in value
        or value.startswith("svf")
        or value.startswith("saber")
        or value.startswith("joern")
        for value in source_values
    ):
        discovered.add("backend_signal")
    if (
        issue.get("rule")
        or issue.get("rule_id")
        or "deterministic_rule" in source_values
        or any("rule" in value or "clang_ast" in value for value in source_values)
    ):
        discovered.add("deterministic_rule")

    disposition = str(
        issue.get("candidate_disposition")
        or issue.get("terminal_disposition")
        or issue.get("validation_status")
        or ""
    ).lower()
    if (
        issue.get("decision_proof")
        or issue.get("proof_provider")
        or issue.get("deterministic_prevalidation_decision")
        or issue.get("validator_avoided") is True
    ):
        decided = "deterministic_proof"
        level = "V0"
    elif issue.get("dynamic_reproduction") or issue.get("reproduction_evidence"):
        decided = "dynamic_reproduction"
        level = "V4"
    elif disposition in {"validated", "verified", "confirmed"}:
        decided = "validator_llm"
        level = "V1"
    else:
        decided = "unresolved"
        level = "none"
    return {
        "schema_version": ATTRIBUTION_SCHEMA_VERSION,
        "discovered_by": sorted(discovered) or ["unknown"],
        "decided_by": decided,
        "decision_level": level,
        "confirmed_via": confirmed_via,
        "attribution_inferred": True,
        "inferred": True,
        "valid": True,
        "errors": [],
    }


def attribution_summary(
    issues: Sequence[Dict[str, Any]],
    *,
    matched_issue_indices: Iterable[int],
    raw_false_positive_indices: Iterable[int],
) -> Dict[str, Any]:
    """Aggregate multi-source discovery independently from terminal decisions."""

    matched = set(matched_issue_indices)
    raw_fp = set(raw_false_positive_indices)
    discovery: Dict[str, Dict[str, int]] = {}
    exclusive_discovery: Dict[str, Dict[str, int]] = {}
    decision: Dict[str, Dict[str, int]] = {}
    decision_level: Dict[str, Dict[str, int]] = {}
    intersections: Dict[str, Dict[str, int]] = {}
    confirmed_via_counter: Dict[str, Dict[str, int]] = {}
    explicit = 0
    for index, issue in enumerate(issues):
        value = finding_attribution(issue)
        explicit += int(value.get("attribution_inferred") is False and value.get("valid") is True)
        outcome = (
            "true_positive"
            if index in matched
            else "raw_false_positive" if index in raw_fp else "other"
        )
        for source in value["discovered_by"]:
            row = discovery.setdefault(
                source, {"issues": 0, "true_positives": 0, "raw_false_positives": 0}
            )
            row["issues"] += 1
            row["true_positives"] += int(outcome == "true_positive")
            row["raw_false_positives"] += int(outcome == "raw_false_positive")
            key = f"{source}|{value['decided_by']}"
            cross = intersections.setdefault(
                key, {"issues": 0, "true_positives": 0, "raw_false_positives": 0}
            )
            cross["issues"] += 1
            cross["true_positives"] += int(outcome == "true_positive")
            cross["raw_false_positives"] += int(outcome == "raw_false_positive")
        if len(value["discovered_by"]) == 1:
            source = value["discovered_by"][0]
            exclusive = exclusive_discovery.setdefault(
                source,
                {"issues": 0, "true_positives": 0, "raw_false_positives": 0},
            )
            exclusive["issues"] += 1
            exclusive["true_positives"] += int(outcome == "true_positive")
            exclusive["raw_false_positives"] += int(outcome == "raw_false_positive")
        decided = decision.setdefault(
            value["decided_by"], {"issues": 0, "true_positives": 0, "raw_false_positives": 0}
        )
        decided["issues"] += 1
        decided["true_positives"] += int(outcome == "true_positive")
        decided["raw_false_positives"] += int(outcome == "raw_false_positive")
        level = decision_level.setdefault(
            str(value["decision_level"]),
            {"issues": 0, "true_positives": 0, "raw_false_positives": 0},
        )
        level["issues"] += 1
        level["true_positives"] += int(outcome == "true_positive")
        level["raw_false_positives"] += int(outcome == "raw_false_positive")
        confirmed_via = str(value.get("confirmed_via") or "")
        if confirmed_via:
            row = confirmed_via_counter.setdefault(
                confirmed_via, {"issues": 0, "true_positives": 0, "raw_false_positives": 0}
            )
            row["issues"] += 1
            row["true_positives"] += int(outcome == "true_positive")
            row["raw_false_positives"] += int(outcome == "raw_false_positive")
    return {
        "schema_version": ATTRIBUTION_SCHEMA_VERSION,
        "issue_count": len(issues),
        "explicit_count": explicit,
        "inferred_count": len(issues) - explicit,
        "explicit_coverage": round(explicit / len(issues), 4) if issues else 1.0,
        "by_discovery": discovery,
        "exclusive_by_discovery": exclusive_discovery,
        "by_decision": decision,
        "by_decision_level": decision_level,
        "by_discovery_and_decision": intersections,
        "by_confirmed_via": confirmed_via_counter,
        "counting_contract": "discovery is a set and may overlap; decision is terminal and exclusive",
    }


def candidate_funnel(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Summarize candidate flow while keeping occurrence/group/finding units explicit."""

    manifest = _as_dict(report.get("run_manifest"))
    summary = _as_dict(report.get("summary"))
    validation_performance = _as_dict(summary.get("validation_performance"))
    governance = _as_dict(report.get("needs_review_governance"))
    raw_terminal = report.get("candidate_terminal_states")
    terminal = (
        [item for item in raw_terminal or [] if isinstance(item, dict)]
        if isinstance(raw_terminal, list)
        else []
    )
    issues = report_issues(dict(report), view="default")
    views = report.get("report_views")
    review_view = _as_dict(views.get("with_needs_review")) if isinstance(views, dict) else {}
    review_issues = review_view.get("issues")
    review_issues = (
        [item for item in review_issues if isinstance(item, dict)]
        if isinstance(review_issues, list)
        else []
    )

    def first_numeric(*sources: tuple[Mapping[str, Any], str]) -> tuple[Optional[int], str]:
        for owner, key in sources:
            value = owner.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return int(value), key
        return None, "unavailable"

    raw_occurrences, raw_source = first_numeric(
        (summary, "scan_level_raw_occurrence_count"),
        (manifest, "raw_occurrence_count"),
        (governance, "raw_occurrence_count"),
    )
    candidate_ids = {
        str(item.get("candidate_uid") or _as_dict(item.get("issue")).get("candidate_uid") or "")
        for item in terminal
        if str(item.get("candidate_uid") or _as_dict(item.get("issue")).get("candidate_uid") or "")
    }
    group_ids = {
        str(item.get("validation_cluster_uid") or "")
        for item in terminal
        if str(item.get("validation_cluster_uid") or "")
    }
    manifest_groups, manifest_group_source = first_numeric(
        (manifest, "canonical_validation_group_count"),
        (manifest, "unique_security_obligation_count"),
        (summary, "validation_group_count"),
    )
    canonical_groups = len(group_ids) if group_ids else manifest_groups
    canonical_source = "candidate_terminal_states" if group_ids else manifest_group_source

    by_decision: Dict[str, int] = {}
    by_decision_level: Dict[str, int] = {}
    by_discovery: Dict[str, int] = {}
    exclusive_by_discovery: Dict[str, int] = {}
    intersections: Dict[str, int] = {}
    reached_by_level: Dict[str, int] = {f"V{level}": 0 for level in range(5)}
    transition_counts: Dict[str, int] = {}
    drop_reasons: Dict[str, int] = {}
    # Escalation-rung dimension (plan Phase 5): the same terminal population
    # projected onto the LLM participation ladder.  ``R3_v2b_adjudication``
    # is forward-compatible — no runner writes the marker yet, so it stays
    # zero until the R3 arm ships.
    reached_by_rung: Dict[str, int] = {
        "R1_validator_v1": 0,
        "R2_v3_reattempt": 0,
        "R3_v2b_adjudication": 0,
    }
    confirmed_by_rung: Dict[str, int] = dict(reached_by_rung)
    drop_reasons_by_rung: Dict[str, Dict[str, int]] = {
        "R1_validator_v1": {},
        "R2_v3_reattempt": {},
        "R3_v2b_adjudication": {},
    }
    v3_counts = {"eligible": 0, "entered": 0, "confirmed": 0}
    v3_by_source_terminal: Dict[str, int] = {}
    v3_by_risk_layer: Dict[str, Dict[str, int]] = {}
    v3_by_fact_kind: Dict[str, Dict[str, int]] = {}
    invoked_groups: set[str] = set()
    for index, item in enumerate(terminal):
        issue = {
            **_as_dict(item.get("issue")),
            **{key: value for key, value in item.items() if key != "issue"},
        }
        attribution = finding_attribution(issue)
        decision = str(attribution["decided_by"])
        by_decision[decision] = by_decision.get(decision, 0) + 1
        level = str(attribution["decision_level"])
        by_decision_level[level] = by_decision_level.get(level, 0) + 1
        history = issue.get("validator_pass_history")
        history = history if isinstance(history, list) else []
        history_passes = {
            str(entry.get("pass") or "") for entry in history if isinstance(entry, Mapping)
        }
        disposition = str(
            item.get("candidate_disposition")
            or issue.get("candidate_disposition")
            or item.get("status")
            or ""
        ).lower()
        schema_version = str(item.get("candidate_schema_version") or "").lower()
        reached: set[str] = set()
        if not (
            schema_version == "zscope.entry-candidate.v1"
            or (
                disposition in {"engine_failed", "interrupted", "deferred_budget"}
                and not issue.get("deterministic_prevalidation_decision")
                and not issue.get("validator_pass_history")
                and int(item.get("validation_attempt_count") or 0) == 0
            )
        ):
            reached.add("V0")
        if (
            int(
                item.get("validation_attempt_count") or issue.get("validator_invocation_count") or 0
            )
            > 0
            or decision == "validator_llm"
            or level in {"V1", "V2", "V3", "V4"}
            or "initial" in history_passes
        ):
            reached.add("V1")
        # V3 may follow V1 directly when deterministic fact resolution adds no
        # evidence delta.  A terminal V3 attribution therefore does not prove
        # that the stateless V2 model pass was reached.
        if level == "V2" or "evidence_recheck" in history_passes:
            reached.add("V2")
        if level in {"V3", "V4"} or "investigation_synthesis" in history_passes:
            reached.add("V3")
        if level == "V4" or str(issue.get("dynamic_reproduction_status") or ""):
            reached.add("V4")
        for reached_level in reached:
            reached_by_level[reached_level] += 1
        for current, following in zip(("V0", "V1", "V2", "V3"), ("V1", "V2", "V3", "V4")):
            if current in reached and following in reached:
                key = f"{current}->{following}"
                transition_counts[key] = transition_counts.get(key, 0) + 1
        if "V1" in reached and "V3" in reached and "V2" not in reached:
            transition_counts["V1->V3"] = transition_counts.get("V1->V3", 0) + 1
        terminal_level = (
            max(reached, key=lambda value: int(value[1:])) if reached else "pre_validation"
        )
        terminal_reason = str(
            issue.get("stop_reason")
            or _as_dict(issue.get("validator_policy_outcome")).get("stop_reason")
            or item.get("candidate_disposition")
            or decision
            or "unknown"
        )
        terminal_transition = f"{terminal_level}->terminal:{terminal_reason}"
        transition_counts[terminal_transition] = transition_counts.get(terminal_transition, 0) + 1
        drop_reasons[terminal_reason] = drop_reasons.get(terminal_reason, 0) + 1
        # Rung projection: R2 when the V3 reattempt was entered (its pass
        # marker or the explicit flag), R3 when a V2b adjudication pass is
        # ever recorded.  The deciding rung for a confirmation is the
        # highest rung that participated.
        r2_reached = (
            item.get("validator_v3_entered") is True or "investigation_synthesis" in history_passes
        )
        r3_reached = (
            item.get("validator_v2b_entered") is True or "v2b_adjudication" in history_passes
        )
        rungs: set[str] = set()
        if "V1" in reached:
            rungs.add("R1_validator_v1")
        if r2_reached:
            rungs.add("R2_v3_reattempt")
        if r3_reached:
            rungs.add("R3_v2b_adjudication")
        for rung in rungs:
            reached_by_rung[rung] += 1
        confirmed = disposition in {"confirmed", "validated"}
        if confirmed and rungs:
            deciding = (
                "R3_v2b_adjudication"
                if r3_reached
                else ("R2_v3_reattempt" if r2_reached else "R1_validator_v1")
            )
            confirmed_by_rung[deciding] += 1
        deciding_rung_for_drop = (
            "R3_v2b_adjudication"
            if r3_reached
            else ("R2_v3_reattempt" if r2_reached else "R1_validator_v1")
        )
        rung_drops = drop_reasons_by_rung[deciding_rung_for_drop]
        rung_drops[terminal_reason] = rung_drops.get(terminal_reason, 0) + 1
        cluster = str(item.get("validation_cluster_uid") or f"terminal:{index}")
        if int(item.get("validation_attempt_count") or 0) > 0 or decision == "validator_llm":
            invoked_groups.add(cluster)
        for source in attribution["discovered_by"]:
            by_discovery[source] = by_discovery.get(source, 0) + 1
            key = f"{source}|{decision}"
            intersections[key] = intersections.get(key, 0) + 1
        if len(attribution["discovered_by"]) == 1:
            source = attribution["discovered_by"][0]
            exclusive_by_discovery[source] = exclusive_by_discovery.get(source, 0) + 1

        v3_eligibility = _as_dict(issue.get("validator_v3_eligibility"))
        v3_eligible = v3_eligibility.get("eligible") is True
        v3_entered = issue.get("validator_v3_entered") is True or "V3" in reached
        v3_confirmed = bool(
            v3_entered
            and (
                issue.get("validator_v3_confirmed") is True
                or disposition in {"confirmed", "validated"}
            )
        )
        if v3_eligible:
            v3_counts["eligible"] += 1
        if v3_entered:
            v3_counts["entered"] += 1
        if v3_confirmed:
            v3_counts["confirmed"] += 1
        if v3_entered:
            sources = attribution["discovered_by"] or ["unknown"]
            for source in sources:
                key = f"{source}|{disposition or 'unknown'}"
                v3_by_source_terminal[key] = v3_by_source_terminal.get(key, 0) + 1
        risk_layer = str(v3_eligibility.get("severity") or "unknown")
        risk_counts = v3_by_risk_layer.setdefault(
            risk_layer,
            {"eligible": 0, "entered": 0, "confirmed": 0},
        )
        if v3_eligible:
            risk_counts["eligible"] += 1
        if v3_entered:
            risk_counts["entered"] += 1
        if v3_confirmed:
            risk_counts["confirmed"] += 1
        raw_fact_kinds = v3_eligibility.get("required_fact_kinds")
        if not isinstance(raw_fact_kinds, list):
            closure = _as_dict(issue.get("v3_evidence_closure"))
            raw_fact_kinds = closure.get("resolved_fact_kinds")
        fact_kinds = (
            sorted({str(value) for value in raw_fact_kinds if str(value)})
            if isinstance(raw_fact_kinds, list)
            else []
        )
        for fact_kind in fact_kinds:
            fact_counts = v3_by_fact_kind.setdefault(
                fact_kind,
                {"eligible": 0, "entered": 0, "confirmed": 0},
            )
            if v3_eligible:
                fact_counts["eligible"] += 1
            if v3_entered:
                fact_counts["entered"] += 1
            if v3_confirmed:
                fact_counts["confirmed"] += 1

    unique_count: Optional[int] = len(candidate_ids) if candidate_ids else None
    if unique_count is None:
        unique_count, unique_source = first_numeric(
            (summary, "unique_candidate_count"),
            (manifest, "unique_security_obligation_count"),
        )
    else:
        unique_source = "candidate_terminal_states"

    def stage(count: Optional[int], *, unit: str, source: str) -> Dict[str, Any]:
        return {
            "count": count,
            "available": count is not None,
            "unit": unit,
            "source": source,
        }

    prevalidation = _as_dict(summary.get("deterministic_prevalidation"))
    v0_decision_count, v0_decision_source = first_numeric(
        (summary, "deterministic_prevalidation_total"),
        (prevalidation, "total"),
        (prevalidation, "candidate_count"),
        (validation_performance, "deterministic_prevalidation_decision_count"),
    )
    v0_count = reached_by_level.get("V0") if terminal else None
    v0_source = "candidate_terminal_states.lifecycle" if terminal else "unavailable"
    v1_count = len(invoked_groups) if terminal else None
    v2_count = reached_by_level.get("V2") if terminal else None
    v3_count = reached_by_level.get("V3") if terminal else None
    v4_count = reached_by_level.get("V4") if terminal else None

    return {
        "schema_version": CANDIDATE_FUNNEL_SCHEMA_VERSION,
        "stages": {
            "raw_occurrences": stage(
                raw_occurrences,
                unit="occurrence",
                source=raw_source,
            ),
            "unique_candidates": stage(
                unique_count,
                unit="candidate",
                source=unique_source,
            ),
            "canonical_validation_groups": stage(
                canonical_groups,
                unit="validation_group",
                source=canonical_source,
            ),
            "v0_prevalidation": stage(
                v0_count,
                unit="validation_group",
                source=v0_source,
            ),
            "v0_deterministic_decisions": stage(
                v0_decision_count,
                unit="validation_group",
                source=v0_decision_source,
            ),
            "v1_initial_decision": stage(
                v1_count,
                unit="validation_group",
                source="candidate_terminal_states.validator_pass_history",
            ),
            "v2_evidence_recheck": stage(
                v2_count,
                unit="validation_group",
                source="candidate_terminal_states.validator_pass_history",
            ),
            "v3_targeted_investigation": stage(
                v3_count,
                unit="validation_group",
                source="candidate_terminal_states.validator_pass_history",
            ),
            "v4_dynamic_reproduction": stage(
                v4_count,
                unit="validation_group",
                source="reserved_not_implemented",
            ),
            "validator_invoked_groups": stage(
                len(invoked_groups) if terminal else None,
                unit="validation_group",
                source="candidate_terminal_states.validation_attempt_count",
            ),
            "reported_findings": stage(
                len(issues),
                unit="finding",
                source="default_report_view",
            ),
            "reported_with_review": stage(
                len(review_issues) if review_view else None,
                unit="finding",
                source="with_needs_review_report_view",
            ),
        },
        "canonical_group_attribution": {
            "by_discovery": dict(sorted(by_discovery.items())),
            "exclusive_by_discovery": dict(sorted(exclusive_by_discovery.items())),
            "by_decision": dict(sorted(by_decision.items())),
            "by_decision_level": dict(sorted(by_decision_level.items())),
            "reached_by_level": dict(sorted(reached_by_level.items())),
            "reached_by_rung": dict(sorted(reached_by_rung.items())),
            "confirmed_by_rung": dict(sorted(confirmed_by_rung.items())),
            "drop_reason_by_rung": {
                key: dict(sorted(value.items())) for key, value in drop_reasons_by_rung.items()
            },
            "transition_counts": dict(sorted(transition_counts.items())),
            "drop_reason": dict(sorted(drop_reasons.items())),
            "by_discovery_and_decision": dict(sorted(intersections.items())),
            "counting_contract": (
                "discovery counts overlap; decision counts are terminal and exclusive"
            ),
        },
        "v3_investigation": {
            **v3_counts,
            "by_source_terminal": dict(sorted(v3_by_source_terminal.items())),
            "by_risk_layer": {key: dict(value) for key, value in sorted(v3_by_risk_layer.items())},
            "by_fact_kind": {key: dict(value) for key, value in sorted(v3_by_fact_kind.items())},
            "unit": "validation_group",
        },
        "contract": {
            "linear_conversion_rates_valid": False,
            "reason": (
                "stages intentionally use occurrence, candidate, validation-group, and "
                "finding units; compare like units only"
            ),
        },
    }


def classify_false_positive_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Classify an unmatched finding when no suite-specific audit rules are provided."""

    audited = dict(record)
    audited["fp_audit_classification"] = FP_AUDIT_NEEDS_REVIEW_ONLY
    audited["fp_audit_reason"] = (
        "unmatched finding should remain review-only until a benchmark-specific "
        "audit classifies it"
    )
    return audited


def false_positive_audit_summary(
    effective_records: Sequence[Dict[str, Any]],
    duplicate_records: Sequence[Dict[str, Any]],
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
    *,
    truth_covered_additional_records: Sequence[Dict[str, Any]] = (),
    overlap_records: Sequence[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    """Return the matcher-v2 split without conflating truth overlap and product roots."""

    classifier = fp_audit_classifier or classify_false_positive_record
    audited_duplicates = [
        {
            **dict(record),
            "fp_audit_classification": FP_AUDIT_SAME_PRODUCT_ROOT,
            "fp_audit_reason": "unmatched issue has the same explicit finding_root_uid",
        }
        for record in duplicate_records
    ]
    audited_additional = [
        {
            **dict(record),
            "fp_audit_classification": FP_AUDIT_TRUTH_COVERED_ADDITIONAL,
            "fp_audit_reason": (
                "different product root has a strong structured match to an already covered truth"
            ),
        }
        for record in truth_covered_additional_records
    ]
    audited_overlaps = [dict(record) for record in overlap_records]
    audited_effective = [classifier(record) for record in effective_records]
    all_records = audited_duplicates + audited_additional + audited_overlaps + audited_effective
    counts: Dict[str, int] = {}
    for record in all_records:
        key = str(record.get("fp_audit_classification") or FP_AUDIT_NEEDS_REVIEW_ONLY)
        counts[key] = counts.get(key, 0) + 1
    return {
        "schema_version": "zscope.fp-audit.v2",
        "counts": counts,
        "effective_records": audited_effective,
        "duplicate_of_matched_records": audited_duplicates,
        "same_product_root_records": audited_duplicates,
        "truth_covered_additional_records": audited_additional,
        "overlap_records": audited_overlaps,
    }


def report_issues(report: Dict[str, Any], view: str = "default") -> List[Dict[str, Any]]:
    views = report.get("report_views")
    if isinstance(views, dict):
        selected = views.get(view)
        if isinstance(selected, dict) and isinstance(selected.get("issues"), list):
            return [item for item in selected["issues"] if isinstance(item, dict)]
    if isinstance(report.get("issues"), list):
        return [item for item in report["issues"] if isinstance(item, dict)]
    issues: List[Dict[str, Any]] = []
    results = report.get("results")
    if isinstance(results, dict):
        for result in results.values():
            if isinstance(result, dict) and isinstance(result.get("issues"), list):
                issues.extend(item for item in result["issues"] if isinstance(item, dict))
    return issues


def _alerted_safe_entry_identities(
    issues: Sequence[Dict[str, Any]],
    safe_entries: Sequence[Dict[str, Any]],
) -> List[str]:
    """Return known-safe entry identities that have an attributed alert."""

    alerted: Set[str] = set()
    for safe_index, safe_entry in enumerate(safe_entries):
        name = str(
            safe_entry.get("function")
            or safe_entry.get("function_name")
            or safe_entry.get("name")
            or ""
        ).strip()
        if not name:
            continue
        signature = str(
            safe_entry.get("signature") or safe_entry.get("full_signature") or ""
        ).strip()
        file_path = (
            str(safe_entry.get("file") or safe_entry.get("file_path") or "")
            .strip()
            .replace("\\", "/")
        )
        identity = (
            "|".join(
                part
                for part in (
                    file_path.lower(),
                    signature.lower() or name.lower(),
                )
                if part
            )
            or f"safe-entry-{safe_index}"
        )
        expected_names = {name.lower()}
        if signature:
            expected_names.add(signature.lower())
        for issue in issues:
            if _issue_function_anchors(issue).intersection(expected_names):
                alerted.add(identity)
                break
    return sorted(alerted)


def _normalize_cwe(value: Any) -> str:
    text = str(value or "").strip().upper().replace("_", "-")
    if not text:
        return ""
    if text.isdigit():
        return f"CWE-{text}"
    match = re.search(r"CWE-?(\d+)", text)
    return f"CWE-{match.group(1)}" if match else text


def score_report(
    report: Dict[str, Any],
    truth: Dict[str, Any],
    *,
    view: str = "default",
    line_tolerance: int = 8,
    count_duplicate_of_matched_as_fp: bool = False,
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
) -> Dict[str, Any]:
    issues = report_issues(report, view)
    issue_texts = [_flatten(issue).lower().replace("\\", "/") for issue in issues]
    truth_contract = summarize_truth_contract(truth)
    if truth_contract["present"]:
        vulns = truth_records_for_contract(
            truth,
            kinds=("concrete_trigger", "public_api_contract"),
        )
    else:
        vulns = [item for item in truth.get("vulnerabilities", []) if isinstance(item, dict)]
    matched_truth: Dict[str, int] = {}
    matched_pairs: List[Dict[str, Any]] = []
    matched_issues: Set[int] = set()
    potential_pairs: List[Dict[str, Any]] = []
    weak_pairs: List[Dict[str, Any]] = []
    for truth_index, vuln in enumerate(vulns):
        truth_id = str(vuln.get("id") or truth_index)
        for issue_index, issue in enumerate(issues):
            issue_text = issue_texts[issue_index]
            match_detail = issue_match_detail(
                issue,
                vuln,
                line_tolerance,
                preflattened_text=issue_text,
            )
            if match_detail is not None:
                potential_pairs.append(
                    {
                        "truth_index": truth_index,
                        "truth_id": truth_id,
                        "issue_index": issue_index,
                        "issue": issue,
                        "match": match_detail,
                        "score": _issue_match_score(
                            issue,
                            vuln,
                            match_detail,
                            preflattened_text=issue_text,
                        ),
                    }
                )
                continue
            weak_detail = _legacy_issue_match_detail(
                issue,
                vuln,
                line_tolerance,
                preflattened_text=issue_text,
            )
            if weak_detail is not None:
                weak_pairs.append(
                    {
                        "truth_index": truth_index,
                        "truth_id": truth_id,
                        "issue_index": issue_index,
                        "match": weak_detail,
                        "classification": _weak_pair_classification(issue, vuln),
                    }
                )

    potential_pairs.sort(
        key=lambda pair: (
            -int(pair.get("score") or 0),
            int(pair.get("truth_index") or 0),
            int(pair.get("issue_index") or 0),
        )
    )
    matched_truth_indices: Set[int] = set()
    matched_issue_by_truth_index: Dict[int, int] = {}
    selected_pairs = _select_max_weight_pairs(potential_pairs, len(vulns), len(issues))
    for pair in selected_pairs:
        truth_index = int(pair.get("truth_index") or 0)
        issue_index = int(pair.get("issue_index") or 0)
        truth_id = str(pair.get("truth_id") or truth_index)
        if truth_index in matched_truth_indices or issue_index in matched_issues:
            continue
        matched_truth_indices.add(truth_index)
        matched_truth[truth_id] = issue_index
        matched_issues.add(issue_index)
        matched_issue_by_truth_index[truth_index] = issue_index
        raw_issue = pair.get("issue")
        issue = raw_issue if isinstance(raw_issue, dict) else issues[issue_index]
        matched_pairs.append(
            {
                "truth_id": truth_id,
                "issue_index": issue_index,
                "issue_identity": issue_identity(issue),
                "attribution": finding_attribution(issue),
                "match": pair.get("match") or {},
                "score": pair.get("score") or 0,
            }
        )

    matched_pairs.sort(
        key=lambda pair: next(
            (
                idx
                for idx, vuln in enumerate(vulns)
                if str(vuln.get("id") or idx) == str(pair.get("truth_id"))
            ),
            0,
        )
    )

    unmatched_classifications = _classify_unmatched_issues(
        issues,
        potential_pairs,
        weak_pairs,
        matched_issues,
        matched_truth_indices,
        matched_issue_by_truth_index,
    )
    same_product_root_indices = {
        index
        for index, record in unmatched_classifications.items()
        if record.get("classification") == "same_product_root"
    }
    truth_covered_additional_indices = {
        index
        for index, record in unmatched_classifications.items()
        if record.get("classification") == "truth_covered_additional"
    }
    cross_anchor_overlap_indices = {
        index
        for index, record in unmatched_classifications.items()
        if record.get("classification") == "cross_anchor_overlap"
    }
    weak_legacy_overlap_indices = {
        index
        for index, record in unmatched_classifications.items()
        if record.get("classification") == "weak_legacy_overlap"
    }
    raw_fp = max(0, len(issues) - len(matched_issues))
    root_covered_indices = same_product_root_indices | truth_covered_additional_indices
    effective_fp = (
        raw_fp if count_duplicate_of_matched_as_fp else max(0, raw_fp - len(root_covered_indices))
    )

    tp = len(matched_truth)
    fp = effective_fp
    fn = max(0, len(vulns) - tp)
    precision = tp / (tp + fp) if tp + fp else 0.0
    actionable_precision = tp / (tp + raw_fp) if tp + raw_fp else 0.0
    recall = tp / len(vulns) if vulns else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    actionable_f1 = (
        2 * actionable_precision * recall / (actionable_precision + recall)
        if actionable_precision + recall
        else 0.0
    )
    false_discovery_rate = fp / (tp + fp) if tp + fp else 0.0
    actionable_false_discovery_rate = raw_fp / (tp + raw_fp) if tp + raw_fp else 0.0
    safe_entries = [item for item in truth.get("safe_entries", []) if isinstance(item, dict)]
    alerted_safe_entries = _alerted_safe_entry_identities(issues, safe_entries)
    standard_false_positive_rate = (
        len(alerted_safe_entries) / len(safe_entries) if safe_entries else None
    )
    issue_ids = [issue_identity(issue) for issue in issues]
    issue_records = [issue_identity_record(issue) for issue in issues]
    raw_fp_indices = [
        index for index, _identity in enumerate(issue_ids) if index not in matched_issues
    ]
    effective_fp_indices = [
        index
        for index in raw_fp_indices
        if count_duplicate_of_matched_as_fp or index not in root_covered_indices
    ]
    fp_issue_ids = [issue_ids[index] for index in effective_fp_indices]
    fp_issue_records = [issue_records[index] for index in effective_fp_indices]
    raw_fp_issue_ids = [issue_ids[index] for index in raw_fp_indices]
    raw_fp_issue_records = [issue_records[index] for index in raw_fp_indices]

    def classified_record(index: int) -> Dict[str, Any]:
        return {
            **issue_records[index],
            "issue_index": index,
            **dict(unmatched_classifications.get(index) or {}),
        }

    duplicate_records = [
        {
            **classified_record(index),
            "duplicate_of_matched": True,
        }
        for index in sorted(same_product_root_indices)
    ]
    truth_covered_additional_records = [
        classified_record(index) for index in sorted(truth_covered_additional_indices)
    ]
    overlap_indices = cross_anchor_overlap_indices | weak_legacy_overlap_indices
    overlap_records = [
        {
            **classified_record(index),
            "fp_audit_classification": (
                FP_AUDIT_CROSS_ANCHOR_OVERLAP
                if index in cross_anchor_overlap_indices
                else FP_AUDIT_WEAK_LEGACY_OVERLAP
            ),
            "fp_audit_reason": str(
                unmatched_classifications[index].get("reason") or "weak matcher overlap"
            ),
        }
        for index in sorted(overlap_indices)
    ]
    ordinary_effective_records = [
        issue_records[index] for index in effective_fp_indices if index not in overlap_indices
    ]
    fp_audit = false_positive_audit_summary(
        ordinary_effective_records,
        duplicate_records,
        fp_audit_classifier=fp_audit_classifier,
        truth_covered_additional_records=truth_covered_additional_records,
        overlap_records=overlap_records,
    )
    high_critical_truth = [
        (index, vuln)
        for index, vuln in enumerate(vulns)
        if str(vuln.get("severity") or vuln.get("impact_level") or vuln.get("priority") or "")
        .strip()
        .lower()
        in {"high", "critical"}
    ]
    high_critical_tp = sum(
        1 for index, vuln in high_critical_truth if str(vuln.get("id") or index) in matched_truth
    )
    high_critical_recall = (
        high_critical_tp / len(high_critical_truth) if high_critical_truth else None
    )
    cwe_groups: Dict[str, List[tuple[int, Dict[str, Any]]]] = {}
    for index, vuln in enumerate(vulns):
        cwe = _normalize_cwe(vuln.get("cwe"))
        if cwe:
            cwe_groups.setdefault(cwe, []).append((index, vuln))
    per_cwe_recall: Dict[str, Dict[str, Any]] = {}
    for cwe, group in sorted(cwe_groups.items()):
        matched_count = sum(
            1 for index, vuln in group if str(vuln.get("id") or index) in matched_truth
        )
        per_cwe_recall[cwe] = {
            "sample_count": len(group),
            "true_positives": matched_count,
            "recall": round(matched_count / len(group), 4),
        }
    result = {
        "schema_version": SCHEMA_VERSION,
        "benchmark": truth.get("benchmark", "unknown"),
        "suite": truth.get("suite", "unknown"),
        "view": view,
        "report_issue_count": len(issues),
        "ground_truth_count": len(vulns),
        "truth_contract": truth_contract,
        "required_confirmed_tp": int(truth_contract["required_confirmed_tp"]),
        "safe_entry_count": len(safe_entries),
        "alerted_safe_entry_count": len(alerted_safe_entries),
        "alerted_safe_entries": alerted_safe_entries,
        "safe_entry_alert_rate": (
            round(standard_false_positive_rate, 4)
            if standard_false_positive_rate is not None
            else None
        ),
        "true_positives": tp,
        "false_positives": fp,
        "false_positives_raw": raw_fp,
        "false_positives_effective": effective_fp,
        # Deprecated matcher-v1 name.  Under matcher v2 this is intentionally
        # a strict alias of same_product_root_count, not every second issue
        # that can mention an already covered truth.
        "duplicate_of_matched_count": len(same_product_root_indices),
        "same_product_root_count": len(same_product_root_indices),
        "truth_covered_additional_count": len(truth_covered_additional_indices),
        "cross_anchor_overlap_count": len(cross_anchor_overlap_indices),
        "weak_legacy_overlap_count": len(weak_legacy_overlap_indices),
        "unclassified_false_positive_count": sum(
            1
            for record in unmatched_classifications.values()
            if record.get("classification") == "false_positive"
        ),
        "false_negatives": fn,
        "actionable_precision": round(actionable_precision, 4),
        "actionable_f1": round(actionable_f1, 4),
        "actionable_false_discovery_rate": round(actionable_false_discovery_rate, 4),
        "root_cause_precision": round(precision, 4),
        "root_cause_f1": round(f1, 4),
        "root_cause_false_discovery_rate": round(false_discovery_rate, 4),
        "effective_precision": round(precision, 4),
        "effective_f1": round(f1, 4),
        "precision": round(precision, 4),
        "false_discovery_rate": round(false_discovery_rate, 4),
        "recall": round(recall, 4),
        "distinct_root_recall": round(recall, 4),
        "high_critical_recall": (
            round(high_critical_recall, 4) if high_critical_recall is not None else None
        ),
        "high_critical_sample_count": len(high_critical_truth),
        "high_critical_true_positives": high_critical_tp,
        "per_cwe_recall": per_cwe_recall,
        "f1": round(f1, 4),
        "matched": sorted(matched_truth),
        "matched_pairs": matched_pairs,
        "missed": [
            str(vuln.get("id") or idx)
            for idx, vuln in enumerate(vulns)
            if str(vuln.get("id") or idx) not in matched_truth
        ],
        "matched_issue_indices": sorted(matched_issues),
        "issue_identities": issue_ids,
        "issue_identity_records": issue_records,
        "true_positive_truth_ids": sorted(matched_truth),
        "false_positive_issue_identities": fp_issue_ids,
        "false_positive_issue_records": fp_issue_records,
        "false_positive_issue_identities_raw": raw_fp_issue_ids,
        "false_positive_issue_records_raw": raw_fp_issue_records,
        "duplicate_of_matched_issue_records": duplicate_records,
        "same_product_root_issue_records": duplicate_records,
        "truth_covered_additional_issue_records": truth_covered_additional_records,
        "cross_anchor_overlap_issue_records": [
            classified_record(index) for index in sorted(cross_anchor_overlap_indices)
        ],
        "weak_legacy_overlap_issue_records": [
            classified_record(index) for index in sorted(weak_legacy_overlap_indices)
        ],
        "unmatched_issue_classifications": [
            classified_record(index) for index in sorted(unmatched_classifications)
        ],
        "false_positive_audit": fp_audit,
        "attribution": attribution_summary(
            issues,
            matched_issue_indices=matched_issues,
            raw_false_positive_indices=raw_fp_indices,
        ),
        "match_diagnostics": _match_diagnostics(
            potential_pairs,
            matched_truth_indices,
            matched_issues,
            matched_issue_by_truth_index,
            vulns,
            issues,
            weak_pairs=weak_pairs,
        ),
        "scoring_contract": {
            "matcher_version": MATCHER_VERSION,
            "truth_contract_version": str(truth_contract["schema_version"]),
            "truth_manifest_sha256": str(truth_contract["manifest_sha256"]),
            "confirmable_truth_count": int(truth_contract["confirmable_truth_count"]),
            "line_tolerance": line_tolerance,
            "count_duplicate_of_matched_as_fp": count_duplicate_of_matched_as_fp,
            "function_anchors": ["primary", "structured_source_sink", "fact_location"],
            "line_placeholder_policy": "truth line <= 1 is treated as unknown",
            "category_policy": (
                "explicit category/defect_family/CWE plus a versioned generic alias family; "
                "truth keywords never establish an official match"
            ),
            "anchor_policy": (
                "file, function, and line range must come from one coherent issue/truth anchor"
            ),
            "weak_match_policy": "keyword/text/cross-anchor pairs are diagnostic and never TP",
            "primary_precision_metric": "actionable_precision",
            "primary_f1_metric": "actionable_f1",
            "primary_recall_metric": "distinct_root_recall",
            "safe_unit_rate_metric": ("safe_entry_alert_rate" if safe_entries else "unavailable"),
            "legacy_precision_metric": (
                "precision (root-cause/effective; strong truth-covered additions excluded)"
            ),
            "deprecated_fields": {
                "duplicate_of_matched_count": "same_product_root_count",
                "duplicate_of_matched_issue_records": "same_product_root_issue_records",
            },
        },
    }
    if standard_false_positive_rate is not None:
        # Classical false-positive-rate names are emitted only when the suite
        # provides an explicit safe-unit denominator.  Range has no such units,
        # so its unmatched-alert ratio remains a false-discovery rate.
        result["standard_false_positive_rate"] = round(standard_false_positive_rate, 4)
        result["scoring_contract"]["standard_false_positive_rate_metric"] = "safe_entry_alert_rate"
    if truth_contract["present"] and int(truth_contract["pattern_model_count"]):
        design_truth = {
            "benchmark": truth.get("benchmark", "unknown"),
            "suite": truth.get("suite", "unknown"),
            "vulnerabilities": truth_records_for_contract(truth, kinds=("pattern_model",)),
            "safe_entries": truth.get("safe_entries", []),
        }
        design_score = score_report(
            report,
            design_truth,
            view=view,
            line_tolerance=line_tolerance,
            count_duplicate_of_matched_as_fp=count_duplicate_of_matched_as_fp,
            fp_audit_classifier=fp_audit_classifier,
        )
        result["design_risk_view"] = {
            "truth_count": int(design_score["ground_truth_count"]),
            "true_positives": int(design_score["true_positives"]),
            "recall": float(design_score["recall"]),
            "matched": list(design_score["matched"]),
            "missed": list(design_score["missed"]),
            "counting_contract": "diagnostic only; excluded from confirmed recall gate",
        }
    return result


def _select_max_weight_pairs(
    potential_pairs: List[Dict[str, Any]],
    truth_count: int,
    issue_count: int,
) -> List[Dict[str, Any]]:
    """Return a deterministic maximum-cardinality, maximum-score bipartite match."""
    if not potential_pairs or not truth_count or not issue_count:
        return []
    source = truth_count + issue_count
    sink = source + 1
    graph: List[List[Dict[str, Any]]] = [[] for _ in range(sink + 1)]

    def add_edge(
        u: int, v: int, cap: int, cost: int, payload: Optional[Dict[str, Any]] = None
    ) -> None:
        graph[u].append(
            {"to": v, "rev": len(graph[v]), "cap": cap, "cost": cost, "payload": payload}
        )
        graph[v].append(
            {"to": u, "rev": len(graph[u]) - 1, "cap": 0, "cost": -cost, "payload": None}
        )

    for truth_index in range(truth_count):
        add_edge(source, truth_index, 1, 0)
    for issue_index in range(issue_count):
        add_edge(truth_count + issue_index, sink, 1, 0)

    # Encode the objectives lexicographically:
    #   1. maximum cardinality,
    #   2. maximum total match score,
    #   3. deterministic minimum stable tie value.
    #
    # A fixed cardinality bonus is incorrect because ``stable_tie`` grows with
    # the report size.  Once a report contains enough findings, a valid edge can
    # otherwise become non-negative and the min-cost flow stops before reaching
    # maximum cardinality.
    matching_bound = max(1, min(truth_count, issue_count))
    max_stable_tie = max(
        (
            int(pair.get("truth_index") or 0) * (issue_count + 1)
            + int(pair.get("issue_index") or 0)
            for pair in potential_pairs
        ),
        default=0,
    )
    max_score = max((max(0, int(pair.get("score") or 0)) for pair in potential_pairs), default=0)
    tie_total_bound = matching_bound * max_stable_tie
    score_scale = tie_total_bound + 1
    secondary_total_bound = matching_bound * (max_score * score_scale + max_stable_tie)
    cardinality_bonus = secondary_total_bound + 1
    for pair in potential_pairs:
        truth_index = int(pair.get("truth_index") or 0)
        issue_index = int(pair.get("issue_index") or 0)
        if not (0 <= truth_index < truth_count and 0 <= issue_index < issue_count):
            continue
        score = int(pair.get("score") or 0)
        stable_tie = truth_index * (issue_count + 1) + issue_index
        add_edge(
            truth_index,
            truth_count + issue_index,
            1,
            -cardinality_bonus - score * score_scale + stable_tie,
            pair,
        )

    # Initial Johnson potentials are the shortest distances in the initial
    # acyclic residual graph.  They make every reduced edge cost non-negative,
    # allowing Dijkstra for each augmentation instead of SPFA.  SPFA degrades
    # badly on large needs-review reports because residual rerouting introduces
    # many alternating paths.
    infinity = 10**100
    potential = [0] * len(graph)
    issue_distances = [infinity] * issue_count
    for truth_index in range(truth_count):
        for edge in graph[truth_index]:
            if edge.get("payload") is None or int(edge.get("cap") or 0) <= 0:
                continue
            issue_index = int(edge["to"]) - truth_count
            if 0 <= issue_index < issue_count:
                issue_distances[issue_index] = min(
                    issue_distances[issue_index],
                    int(edge["cost"]),
                )
    reachable_issue_distances = [distance for distance in issue_distances if distance < infinity]
    for issue_index, distance in enumerate(issue_distances):
        if distance < infinity:
            potential[truth_count + issue_index] = distance
    potential[sink] = min(reachable_issue_distances, default=0)

    while True:
        dist = [infinity] * len(graph)
        prev_node = [-1] * len(graph)
        prev_edge = [-1] * len(graph)
        dist[source] = 0
        queue: List[tuple[int, int]] = [(0, source)]
        while queue:
            current_dist, node = heapq.heappop(queue)
            if current_dist != dist[node]:
                continue
            for edge_index, edge in enumerate(graph[node]):
                if int(edge["cap"]) <= 0:
                    continue
                nxt = int(edge["to"])
                reduced_cost = int(edge["cost"]) + potential[node] - potential[nxt]
                if reduced_cost < 0:
                    raise RuntimeError("negative reduced cost in benchmark matching graph")
                new_dist = current_dist + reduced_cost
                if new_dist < dist[nxt]:
                    dist[nxt] = new_dist
                    prev_node[nxt] = node
                    prev_edge[nxt] = edge_index
                    heapq.heappush(queue, (new_dist, nxt))
        if prev_node[sink] < 0:
            break
        for node, distance in enumerate(dist):
            if distance < infinity:
                potential[node] += distance
        node = sink
        while node != source:
            parent = prev_node[node]
            edge_index = prev_edge[node]
            edge = graph[parent][edge_index]
            edge["cap"] = int(edge["cap"]) - 1
            graph[node][int(edge["rev"])]["cap"] = int(graph[node][int(edge["rev"])]["cap"]) + 1
            node = parent

    selected: List[Dict[str, Any]] = []
    for truth_index in range(truth_count):
        for edge in graph[truth_index]:
            payload = edge.get("payload")
            if payload is not None and int(edge.get("cap") or 0) == 0:
                selected.append(payload)
    selected.sort(key=lambda pair: int(pair.get("truth_index") or 0))
    return selected


def _match_diagnostics(
    potential_pairs: List[Dict[str, Any]],
    matched_truth_indices: Set[int],
    matched_issues: Set[int],
    matched_issue_by_truth_index: Dict[int, int],
    vulns: List[Dict[str, Any]],
    issues: List[Dict[str, Any]],
    *,
    weak_pairs: Sequence[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    """Explain common non-match causes without changing the scoring contract."""
    potentials_by_truth: Dict[int, List[Dict[str, Any]]] = {}
    for pair in potential_pairs:
        potentials_by_truth.setdefault(int(pair.get("truth_index") or 0), []).append(pair)

    issue_to_truth = {
        issue_index: truth_index
        for truth_index, issue_index in matched_issue_by_truth_index.items()
    }
    matched_elsewhere: List[Dict[str, Any]] = []
    for truth_index, vuln in enumerate(vulns):
        if truth_index in matched_truth_indices:
            continue
        pairs = potentials_by_truth.get(truth_index, [])
        diverted = [pair for pair in pairs if int(pair.get("issue_index") or 0) in matched_issues]
        if not diverted:
            continue
        best = max(diverted, key=lambda pair: int(pair.get("score") or 0))
        issue_index = int(best.get("issue_index") or 0)
        matched_truth_index = issue_to_truth.get(issue_index)
        matched_truth = (
            vulns[matched_truth_index]
            if matched_truth_index is not None and matched_truth_index < len(vulns)
            else {}
        )
        matched_elsewhere.append(
            {
                "truth_id": str(vuln.get("id") or truth_index),
                "issue_index": issue_index,
                "issue_identity": (
                    issue_identity(issues[issue_index]) if issue_index < len(issues) else ""
                ),
                "matched_truth_id": str(matched_truth.get("id") or matched_truth_index or ""),
                "score": best.get("score") or 0,
                "match": best.get("match") or {},
            }
        )

    return {
        "matcher_version": MATCHER_VERSION,
        "candidate_still_present_but_matched_another_truth": matched_elsewhere,
        "unmatched_truth_with_potential_pair_count": sum(
            1 for truth_index in potentials_by_truth if truth_index not in matched_truth_indices
        ),
        "weak_pair_count": len(weak_pairs),
        "weak_pairs": [
            {
                key: pair.get(key)
                for key in (
                    "truth_index",
                    "truth_id",
                    "issue_index",
                    "classification",
                    "match",
                )
            }
            for pair in weak_pairs
        ],
    }


def _classify_unmatched_issues(
    issues: List[Dict[str, Any]],
    potential_pairs: List[Dict[str, Any]],
    weak_pairs: Sequence[Dict[str, Any]],
    matched_issues: Set[int],
    matched_truth_indices: Set[int],
    matched_issue_by_truth_index: Dict[int, int],
) -> Dict[int, Dict[str, Any]]:
    """Classify every unmatched issue without equating truth overlap and roots."""

    potentials_by_issue: Dict[int, List[Dict[str, Any]]] = {}
    for pair in potential_pairs:
        issue_index = int(pair.get("issue_index") or 0)
        potentials_by_issue.setdefault(issue_index, []).append(pair)
    weak_by_issue: Dict[int, List[Dict[str, Any]]] = {}
    for pair in weak_pairs:
        issue_index = int(pair.get("issue_index") or 0)
        weak_by_issue.setdefault(issue_index, []).append(dict(pair))

    matched_by_root: Dict[str, tuple[int, int]] = {}
    for truth_index, issue_index in matched_issue_by_truth_index.items():
        if not (0 <= issue_index < len(issues)):
            continue
        root_uid = str(issues[issue_index].get("finding_root_uid") or "")
        if root_uid:
            matched_by_root.setdefault(root_uid, (truth_index, issue_index))

    result: Dict[int, Dict[str, Any]] = {}

    for issue_index, issue in enumerate(issues):
        if issue_index in matched_issues:
            continue
        root_uid = str(issue.get("finding_root_uid") or "")
        root_match = matched_by_root.get(root_uid) if root_uid else None
        if root_match is not None:
            truth_index, primary_issue_index = root_match
            result[issue_index] = {
                "classification": "same_product_root",
                "matched_truth_index": truth_index,
                "matched_truth_id": _truth_id_from_pair_index(
                    potentials_by_issue,
                    truth_index,
                ),
                "matched_primary_issue_index": primary_issue_index,
                "finding_root_uid": root_uid,
                "pair_strength": "explicit_product_root",
                "reason": "explicit finding_root_uid equals the matched primary root",
            }
            continue

        direct_pairs = [
            pair
            for pair in potentials_by_issue.get(issue_index, [])
            if int(pair.get("truth_index") or 0) in matched_truth_indices
        ]
        if direct_pairs:
            best = max(direct_pairs, key=lambda pair: int(pair.get("score") or 0))
            truth_index = int(best.get("truth_index") or 0)
            result[issue_index] = {
                "classification": "truth_covered_additional",
                "matched_truth_index": truth_index,
                "matched_truth_id": str(best.get("truth_id") or truth_index),
                "matched_primary_issue_index": matched_issue_by_truth_index.get(truth_index),
                "finding_root_uid": root_uid,
                "pair_strength": "strong_structured",
                "match": dict(best.get("match") or {}),
                "reason": (
                    "different product root has a strong structured pair to an already "
                    "covered truth"
                ),
            }
            continue

        weak = weak_by_issue.get(issue_index, [])
        if weak:
            best = sorted(
                weak,
                key=lambda pair: (
                    0 if pair.get("classification") == "cross_anchor_overlap" else 1,
                    int(pair.get("truth_index") or 0),
                ),
            )[0]
            classification = str(best.get("classification") or "weak_legacy_overlap")
            result[issue_index] = {
                "classification": classification,
                "matched_truth_index": int(best.get("truth_index") or 0),
                "matched_truth_id": str(best.get("truth_id") or ""),
                "matched_primary_issue_index": matched_issue_by_truth_index.get(
                    int(best.get("truth_index") or 0)
                ),
                "finding_root_uid": root_uid,
                "pair_strength": "weak_diagnostic",
                "match": dict(best.get("match") or {}),
                "reason": (
                    "explicit category overlaps but no coherent structured anchor exists"
                    if classification == "cross_anchor_overlap"
                    else "match requires truth keywords or free-form/text function anchors"
                ),
            }
            continue

        result[issue_index] = {
            "classification": "false_positive",
            "finding_root_uid": root_uid,
            "pair_strength": "none",
            "reason": "no strong or weak truth pair",
        }
    return result


def _truth_id_from_pair_index(
    potentials_by_issue: Mapping[int, Sequence[Mapping[str, Any]]],
    truth_index: int,
) -> str:
    for pairs in potentials_by_issue.values():
        for pair in pairs:
            if int(pair.get("truth_index") or 0) == truth_index:
                return str(pair.get("truth_id") or truth_index)
    return str(truth_index)


def score_report_views(
    report: Dict[str, Any],
    truth: Dict[str, Any],
    *,
    line_tolerance: int = 8,
    count_duplicate_of_matched_as_fp: bool = False,
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
) -> Dict[str, Dict[str, Any]]:
    return {
        "default": score_report(
            report,
            truth,
            view="default",
            line_tolerance=line_tolerance,
            count_duplicate_of_matched_as_fp=count_duplicate_of_matched_as_fp,
            fp_audit_classifier=fp_audit_classifier,
        ),
        "with_needs_review": score_report(
            report,
            truth,
            view="with_needs_review",
            line_tolerance=line_tolerance,
            count_duplicate_of_matched_as_fp=count_duplicate_of_matched_as_fp,
            fp_audit_classifier=fp_audit_classifier,
        ),
    }


def issue_matches(issue: Dict[str, Any], truth: Dict[str, Any], line_tolerance: int) -> bool:
    return issue_match_detail(issue, truth, line_tolerance) is not None


def issue_match_detail(
    issue: Dict[str, Any],
    truth: Dict[str, Any],
    line_tolerance: int,
    *,
    preflattened_text: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    """Return a matcher-v2 pair only for one coherent structured anchor."""

    del preflattened_text
    category_reason = _structured_category_match_reason(issue, truth)
    if not category_reason:
        return None
    issue_anchors = _issue_structured_anchors(issue)
    truth_anchors = _truth_structured_anchors(truth)
    matches: List[tuple[tuple[int, int, int], Dict[str, str]]] = []
    truth_priority = {"primary": 0, "secondary": 1, "sibling": 2, "additional": 3}
    issue_priority = {"primary": 0, "sink": 1, "source": 2, "fact": 3}
    for issue_anchor in issue_anchors:
        for truth_anchor in truth_anchors:
            if not _same_source_path(
                str(issue_anchor.get("file") or ""),
                str(truth_anchor.get("file") or ""),
            ):
                continue
            if (
                str(issue_anchor.get("function") or "").lower()
                != str(truth_anchor.get("function") or "").lower()
            ):
                continue
            issue_start = int(issue_anchor.get("start") or 0)
            issue_end = int(issue_anchor.get("end") or issue_start)
            truth_start = int(truth_anchor.get("start") or 0)
            truth_end = int(truth_anchor.get("end") or truth_start)
            truth_line_known = truth_start > 1
            if truth_line_known and not _ranges_overlap_with_tolerance(
                issue_start, issue_end, truth_start, truth_end, line_tolerance
            ):
                continue
            distance = (
                min(
                    abs(issue_start - truth_start),
                    abs(issue_end - truth_end),
                )
                if truth_line_known
                else 0
            )
            issue_kind = str(issue_anchor.get("kind") or "fact")
            truth_kind = str(truth_anchor.get("kind") or "additional")
            matches.append(
                (
                    (
                        truth_priority.get(truth_kind, 9),
                        issue_priority.get(issue_kind, 9),
                        distance,
                    ),
                    {
                        "category": category_reason,
                        "function": f"{truth_kind}:coherent_structured_anchor",
                        "file": "coherent_path",
                        "line": (
                            f"{truth_kind}_line:within_tolerance"
                            if truth_line_known
                            else f"{truth_kind}_line:unknown"
                        ),
                        "pair_strength": "strong_structured",
                        "issue_anchor_kind": issue_kind,
                        "truth_anchor_kind": truth_kind,
                        "issue_anchor": _anchor_label(issue_anchor),
                        "truth_anchor": _anchor_label(truth_anchor),
                    },
                )
            )
    if not matches:
        return None
    return sorted(matches, key=lambda item: item[0])[0][1]


def _legacy_issue_match_detail(
    issue: Dict[str, Any],
    truth: Dict[str, Any],
    line_tolerance: int,
    *,
    preflattened_text: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    """Return the matcher-v1 text pair for audit only, never official TP."""

    text = (
        preflattened_text
        if preflattened_text is not None
        else _flatten(issue).lower().replace("\\", "/")
    )
    category_reason = _category_match_reason(text, truth)
    if not category_reason:
        return None
    function_reason = _function_match_reason(issue, text, truth)
    if not function_reason:
        return None
    file_reason = _file_match_reason(text, truth)
    if not file_reason:
        return None
    line_reason = _line_match_reason(issue, truth, line_tolerance)
    if not line_reason:
        return None
    return {
        "category": category_reason,
        "function": function_reason,
        "file": file_reason,
        "line": line_reason,
        "pair_strength": "weak_legacy",
    }


def _issue_match_score(
    issue: Dict[str, Any],
    truth: Dict[str, Any],
    detail: Dict[str, str],
    *,
    preflattened_text: Optional[str] = None,
) -> int:
    del issue, truth, preflattened_text
    category = str(detail.get("category") or "")
    score = 70 if category.startswith("category_exact") else 0
    score += 65 if category.startswith("cwe_exact") else 0
    score += 50 if category.startswith("category_family") else 0
    truth_kind = str(detail.get("truth_anchor_kind") or "")
    issue_kind = str(detail.get("issue_anchor_kind") or "")
    score += {"primary": 120, "secondary": 100, "sibling": 90, "additional": 85}.get(truth_kind, 0)
    score += {"primary": 40, "sink": 35, "source": 30, "fact": 25}.get(issue_kind, 0)
    return score


_STRUCTURED_CATEGORY_FAMILIES: Dict[str, frozenset[str]] = {
    "bounds": frozenset(
        {
            "bounds",
            "size_limit_mismatch",
            "out_of_bounds_write",
            "buffer_overflow",
            "heap_overflow",
            "out_of_range_pointer_offset",
            "buffer_overread",
            "buffer_over_read",
            "buffer_underread",
            "buffer_underwrite",
            "buffer_underflow",
        }
    ),
    "resource_leak": frozenset(
        {
            "memory_leak",
            "resource_leak",
            "fd_leak",
            "file_descriptor_leak",
            "optimization_resource_lifecycle",
            "thread_cache_leak",
        }
    ),
    "race": frozenset({"race", "data_race", "shared_state_race", "refcount_race"}),
    "deadlock": frozenset({"deadlock", "signal_deadlock", "lock_order_deadlock"}),
    "allocation_limit": frozenset(
        {
            "resource_allocation_without_limits",
            "unchecked_allocation",
            "excessive_allocation",
        }
    ),
    "use_after_free": frozenset({"use_after_free", "expired_pointer", "stale_pointer"}),
    "busy_loop": frozenset({"busy_loop", "infinite_loop", "spin_loop"}),
    "integer_conversion": frozenset(
        {"integer_overflow", "signed_unsigned", "signed_unsigned_conversion"}
    ),
    "file_type_validation": frozenset({"file_type_validation", "incorrect_validation_order"}),
    "permission": frozenset({"permission", "incorrect_permission_check"}),
    "shared_state_race": frozenset(
        {"unsynchronized_shared_state", "race", "data_race", "shared_state_race"}
    ),
    "dynamic_array_race": frozenset({"dynamic_array_race", "race", "data_race"}),
}


def _structured_category_match_reason(issue: Mapping[str, Any], truth: Mapping[str, Any]) -> str:
    issue_categories = _issue_explicit_categories(issue)
    truth_category = _normalize_category(truth.get("category"))
    if truth_category and truth_category in issue_categories:
        return f"category_exact:{truth_category}"
    issue_cwes = _cwe_values(
        [
            issue.get("cwe"),
            _as_dict(issue.get("evidence_pack")).get("cwe"),
        ]
    )
    truth_cwes = _cwe_values([truth.get("cwe")])
    common_cwes = sorted(issue_cwes & truth_cwes)
    if common_cwes:
        return f"cwe_exact:{common_cwes[0]}"
    if truth_category:
        for family, members in _STRUCTURED_CATEGORY_FAMILIES.items():
            if truth_category in members and issue_categories.intersection(members):
                return f"category_family:{family}"
    return ""


def _issue_explicit_categories(issue: Mapping[str, Any]) -> Set[str]:
    values: List[Any] = [
        issue.get("category"),
        issue.get("defect_family"),
        issue.get("defect_class"),
    ]
    obligation = issue.get("security_obligation")
    if isinstance(obligation, Mapping):
        values.append(obligation.get("defect_family"))
    pack = issue.get("evidence_pack")
    if isinstance(pack, Mapping):
        values.extend((pack.get("defect_family"), pack.get("defect_class")))
        nested = pack.get("security_obligation")
        if isinstance(nested, Mapping):
            values.append(nested.get("defect_family"))
    return {value for value in (_normalize_category(item) for item in values) if value}


def _normalize_category(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _cwe_values(values: Iterable[Any]) -> Set[str]:
    result: Set[str] = set()
    for value in values:
        normalized = _normalize_cwe(value)
        if re.fullmatch(r"CWE-\d+", normalized):
            result.add(normalized)
        for number in re.findall(r"CWE[-_ ]?(\d+)", str(value or ""), flags=re.IGNORECASE):
            result.add(f"CWE-{number}")
    return result


def _truth_structured_anchors(truth: Mapping[str, Any]) -> List[Dict[str, Any]]:
    anchors: List[Dict[str, Any]] = []

    def add(kind: str, file_value: Any, function_value: Any, start: Any, end: Any) -> None:
        try:
            numeric_start = int(start or 0)
        except (TypeError, ValueError):
            numeric_start = 0
        anchor = _structured_anchor(
            kind,
            file_value,
            function_value,
            start,
            end,
            allow_unknown_line=kind == "primary" and start not in (None, "") and numeric_start <= 1,
        )
        if anchor and anchor not in anchors:
            anchors.append(anchor)

    primary_file = truth.get("file")
    add("primary", primary_file, truth.get("function"), truth.get("line"), truth.get("end_line"))
    add(
        "secondary",
        truth.get("secondary_file") or primary_file,
        truth.get("secondary_function"),
        truth.get("secondary_line"),
        truth.get("secondary_end_line"),
    )
    add(
        "sibling",
        truth.get("sibling_file") or primary_file,
        truth.get("sibling_function"),
        truth.get("sibling_line"),
        truth.get("sibling_end_line"),
    )
    locations = truth.get("additional_locations")
    if isinstance(locations, list):
        for item in locations:
            if isinstance(item, Mapping):
                add(
                    "additional",
                    item.get("file"),
                    item.get("function"),
                    item.get("line"),
                    item.get("end_line"),
                )
    return anchors


def _issue_structured_anchors(issue: Mapping[str, Any]) -> List[Dict[str, Any]]:
    anchors: List[Dict[str, Any]] = []
    primary_file = str(issue.get("file_path") or _location_file(dict(issue)) or "")
    primary_function = str(issue.get("function") or issue.get("func_name") or "")
    primary_range = _location_line_range(dict(issue))
    if primary_range:
        anchor = _structured_anchor(
            "primary",
            primary_file,
            primary_function,
            primary_range[0],
            primary_range[1],
        )
        if anchor:
            anchors.append(anchor)

    raw_obligation = issue.get("security_obligation")
    if isinstance(raw_obligation, Mapping):
        obligation: Mapping[str, Any] = raw_obligation
    else:
        pack = issue.get("evidence_pack")
        nested_obligation = pack.get("security_obligation") if isinstance(pack, Mapping) else None
        obligation = nested_obligation if isinstance(nested_obligation, Mapping) else {}
    for kind, value in (
        ("source", obligation.get("source_uid")),
        ("sink", obligation.get("sink_uid")),
    ):
        location = _structured_location_value(value)
        if location:
            anchor = _structured_anchor(
                kind,
                location.get("file") or primary_file,
                location.get("function") or primary_function,
                location.get("line"),
                location.get("end_line"),
            )
            if anchor and anchor not in anchors:
                anchors.append(anchor)

    fact_slices: List[Mapping[str, Any]] = []
    direct_slice = issue.get("decision_fact_slice")
    if isinstance(direct_slice, Mapping):
        fact_slices.append(direct_slice)
    nested_slice = obligation.get("decision_fact_slice")
    if isinstance(nested_slice, Mapping):
        fact_slices.append(nested_slice)
    for fact_slice in fact_slices:
        for fact in fact_slice.get("facts") or []:
            if not isinstance(fact, Mapping):
                continue
            for location in fact.get("locations") or []:
                if not isinstance(location, Mapping) or not location.get("function"):
                    continue
                anchor = _structured_anchor(
                    "fact",
                    location.get("file"),
                    location.get("function"),
                    location.get("start_line") or location.get("line"),
                    location.get("end_line"),
                )
                if anchor and anchor not in anchors:
                    anchors.append(anchor)
    pack = issue.get("evidence_pack")
    if isinstance(pack, Mapping):
        for kind in ("source", "sink", "entry"):
            value = pack.get(kind)
            if not isinstance(value, Mapping):
                continue
            file_value, start, end = _mapping_location_range(value)
            anchor = _structured_anchor(
                "source" if kind == "entry" else kind,
                file_value,
                value.get("function") or primary_function,
                start,
                end,
            )
            if anchor and anchor not in anchors:
                anchors.append(anchor)
    return anchors


def _structured_location_value(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        parsed = value
    else:
        try:
            parsed = json.loads(str(value or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    if not isinstance(parsed, Mapping):
        return {}
    return {
        "file": parsed.get("file"),
        "function": parsed.get("function") or parsed.get("func_name"),
        "line": parsed.get("line") or parsed.get("start_line"),
        "end_line": parsed.get("end_line"),
    }


def _structured_anchor(
    kind: str,
    file_value: Any,
    function_value: Any,
    start_value: Any,
    end_value: Any,
    *,
    allow_unknown_line: bool = False,
) -> Dict[str, Any]:
    file_path = str(file_value or "").replace("\\", "/").strip().lower()
    function = str(function_value or "").strip().lower()
    try:
        start = int(start_value or 0)
    except (TypeError, ValueError):
        return {}
    try:
        end = int(end_value if end_value not in (None, "") else start)
    except (TypeError, ValueError):
        end = start
    if not file_path or not function or (start <= 1 and not allow_unknown_line):
        return {}
    return {
        "kind": kind,
        "file": file_path,
        "function": function,
        "start": start,
        "end": max(start, end),
    }


def _mapping_location_range(value: Mapping[str, Any]) -> tuple[str, int, int]:
    file_value = str(value.get("file") or "")
    location = str(value.get("location") or "")
    if location:
        parsed = re.match(r"^(.*?):(\d+)(?:-(\d+))?(?::\d+)?$", location)
        if parsed:
            file_value = file_value or parsed.group(1)
            start = int(parsed.group(2))
            end = int(parsed.group(3) or start)
            return file_value, start, end
    try:
        start = int(value.get("start_line") or value.get("line") or 0)
    except (TypeError, ValueError):
        start = 0
    try:
        end = int(value.get("end_line") or start)
    except (TypeError, ValueError):
        end = start
    return file_value, start, end


def _same_source_path(left: str, right: str) -> bool:
    left_path = str(left or "").replace("\\", "/").strip("/").lower()
    right_path = str(right or "").replace("\\", "/").strip("/").lower()
    return bool(
        left_path
        and right_path
        and (
            left_path == right_path
            or left_path.endswith("/" + right_path)
            or right_path.endswith("/" + left_path)
        )
    )


def _ranges_overlap_with_tolerance(
    left_start: int,
    left_end: int,
    right_start: int,
    right_end: int,
    tolerance: int,
) -> bool:
    return right_start - tolerance <= left_end and left_start <= right_end + tolerance


def _anchor_label(anchor: Mapping[str, Any]) -> str:
    return "{file}:{function}:{start}-{end}".format(**anchor)


def _weak_pair_classification(issue: Mapping[str, Any], truth: Mapping[str, Any]) -> str:
    return (
        "cross_anchor_overlap"
        if _structured_category_match_reason(issue, truth)
        else "weak_legacy_overlap"
    )


def collect_environment_metadata(
    *,
    suite_root: Path,
    condition: str,
    run_kind: str,
    command: Sequence[str],
    started_at: float,
    finished_at: float,
    return_code: Optional[int] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    config = config or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "condition": condition,
        "run_kind": run_kind,
        "suite_root": str(suite_root),
        "command": list(command),
        "return_code": return_code,
        "wall_time_seconds": round(max(0.0, finished_at - started_at), 4),
        "started_at_unix": started_at,
        "finished_at_unix": finished_at,
        "zscope_version": __version__,
        "commit_sha": _git_commit_sha(Path.cwd()),
        "python": sys.version.split()[0],
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "backend": config.get("backend", ""),
        "model": config.get("model", ""),
        "prompt_autofill": config.get("prompt_autofill", {}),
        "env": {
            "Z_SCOPE_BASE_URL": _redact_url(str(os.environ.get("Z_SCOPE_BASE_URL", ""))),
            "Z_SCOPE_MODEL": os.environ.get("Z_SCOPE_MODEL", ""),
        },
    }


def aggregate_usage_ledger(
    report: Dict[str, Any],
    *,
    usage_spans: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Aggregate one response-boundary usage span per unique provider call."""

    metadata = _as_dict(report.get("metadata"))
    summary = _as_dict(report.get("summary"))
    raw_spans: Any = list(usage_spans) if usage_spans is not None else report.get("llm_usage_spans")
    if not isinstance(raw_spans, list):
        raw_spans = metadata.get("llm_usage_spans")
    if not isinstance(raw_spans, list):
        raw_spans = summary.get("llm_usage_spans")
    if not isinstance(raw_spans, list):
        raw_spans = []
    if not raw_spans:
        existing = _usage_attribution_snapshot(report)
        if existing:
            return _aggregate_usage_snapshot(existing)

    errors: List[str] = []
    seen: Set[str] = set()
    totals = {
        "prompt_tokens": 0,
        "cached_prompt_tokens": 0,
        "completion_tokens": 0,
        "reasoning_tokens": 0,
        "total_tokens": 0,
        "tool_call_count": 0,
        "new_fact_count": 0,
    }
    by_agent: Dict[str, Dict[str, int]] = {}
    by_stage: Dict[str, Dict[str, int]] = {}
    provider_reported = 0
    finish_reasons: Dict[str, int] = {}

    def normalized_values(span: Mapping[str, Any], *, index: int) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for key in totals:
            value = span.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(f"span[{index}].{key} must be a non-negative integer")
                value = 0
            result[key] = value
        return result

    def add(target: Dict[str, int], values: Mapping[str, int]) -> None:
        for key, value in values.items():
            target[key] = target.get(key, 0) + value

    for index, raw in enumerate(raw_spans):
        if not isinstance(raw, dict):
            errors.append(f"span[{index}] is not an object")
            continue
        call_id = str(raw.get("call_id") or "")
        if not call_id:
            errors.append(f"span[{index}] has no call_id")
            continue
        if call_id in seen:
            errors.append(f"duplicate call_id: {call_id}")
            continue
        seen.add(call_id)
        values = normalized_values(raw, index=index)
        for required_key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            if required_key not in raw:
                errors.append(f"span[{index}] has no {required_key}")
        add(totals, values)
        agent = str(raw.get("agent") or "")
        stage = str(raw.get("stage") or "")
        if not agent:
            errors.append(f"span[{index}] has no agent")
            agent = "unknown"
        if not stage:
            errors.append(f"span[{index}] has no stage")
            stage = "unknown"
        add(by_agent.setdefault(agent, {}), values)
        add(by_stage.setdefault(stage, {}), values)
        provider_reported += int(
            raw.get("provider_reported") is True or raw.get("estimated") is False
        )
        if raw.get("provider_reported") is not True and raw.get("estimated") is not False:
            errors.append(f"span[{index}] is not provider-reported")
        finish = str(raw.get("finish_reason") or "")
        if not finish:
            errors.append(f"span[{index}] has no finish_reason")
            finish = "unknown"
        finish_reasons[finish] = finish_reasons.get(finish, 0) + 1
        expected_total = values["prompt_tokens"] + values["completion_tokens"]
        if values["total_tokens"] != expected_total:
            errors.append(f"span[{index}] total_tokens does not equal prompt+completion")
        if values["cached_prompt_tokens"] > values["prompt_tokens"]:
            errors.append(f"span[{index}] cached_prompt_tokens exceeds prompt_tokens")

    conservation = all(
        totals[key]
        == sum(row.get(key, 0) for row in by_agent.values())
        == sum(row.get(key, 0) for row in by_stage.values())
        for key in totals
    )
    if not conservation:
        errors.append("usage aggregation does not conserve totals")
    call_count = len(seen)
    return {
        "schema_version": USAGE_LEDGER_SCHEMA_VERSION,
        "source": "response_usage_spans",
        "present": bool(raw_spans),
        "complete": bool(raw_spans) and not errors and provider_reported == call_count,
        "call_count": call_count,
        "provider_reported_call_count": provider_reported,
        "provider_usage_coverage": round(provider_reported / call_count if call_count else 0.0, 4),
        "totals": totals,
        "by_agent": by_agent,
        "by_stage": by_stage,
        "finish_reasons": finish_reasons,
        "conservation_passed": conservation,
        "telemetry_complete": bool(raw_spans) and not errors,
        "errors": list(dict.fromkeys(errors)),
    }


def _usage_attribution_snapshot(report: Mapping[str, Any]) -> Dict[str, Any]:
    metadata = _as_dict(report.get("metadata"))
    summary = _as_dict(report.get("summary"))
    manifest = _as_dict(report.get("run_manifest"))
    metadata_usage = _as_dict(metadata.get("llm_usage")) or _as_dict(metadata.get("llm_budget"))
    summary_usage = _as_dict(summary.get("llm_usage")) or _as_dict(summary.get("llm_budget"))
    metadata_scan_usage = _as_dict(metadata_usage.get("scan_token_usage"))
    summary_scan_usage = _as_dict(summary_usage.get("scan_token_usage"))
    candidates = (
        (report.get("llm_usage_attribution"), report),
        (manifest.get("llm_usage_attribution"), manifest),
        (metadata_scan_usage.get("usage_attribution"), metadata_scan_usage),
        (summary_scan_usage.get("usage_attribution"), summary_scan_usage),
        (metadata_usage.get("usage_attribution"), metadata_usage),
        (summary_usage.get("usage_attribution"), summary_usage),
    )
    for value, owner in candidates:
        if isinstance(value, dict) and isinstance(value.get("totals"), dict):
            result = dict(value)
            if "telemetry_complete" not in result:
                result["telemetry_complete"] = (
                    owner.get("telemetry_complete") is True
                    or metadata_usage.get("telemetry_complete") is True
                    or summary_usage.get("telemetry_complete") is True
                )
            return result
    return {}


def _aggregate_usage_snapshot(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize the scan budget manager's already de-duplicated aggregation."""

    errors: List[str] = []
    numeric_fields = (
        "request_count",
        "successful_calls",
        "denied_requests",
        "failed_or_unknown_calls",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "provider_reported_calls",
        "estimated_or_conservative_calls",
        "budget_violation_count",
        "cached_prompt_tokens",
        "reasoning_tokens",
        "retry_count",
        "repair_count",
        "tool_call_count",
        "new_fact_count",
        "duration_ms",
    )

    def normalize_row(raw: Any, *, path: str) -> Dict[str, int]:
        value = raw if isinstance(raw, dict) else {}
        if not isinstance(raw, dict):
            errors.append(f"{path} is not an object")
        result: Dict[str, int] = {}
        for field in numeric_fields:
            item = value.get(field, 0)
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                errors.append(f"{path}.{field} must be a non-negative integer")
                item = 0
            result[field] = item
        return result

    totals = normalize_row(snapshot.get("totals"), path="totals")

    def normalize_dimension(name: str) -> Dict[str, Dict[str, int]]:
        raw_dimension = snapshot.get(name)
        if not isinstance(raw_dimension, dict) or not raw_dimension:
            errors.append(f"{name} is missing")
            return {}
        return {
            str(key or "unattributed"): normalize_row(
                value,
                path=f"{name}.{key or 'unattributed'}",
            )
            for key, value in raw_dimension.items()
        }

    by_agent = normalize_dimension("by_agent")
    by_stage = normalize_dimension("by_stage")
    by_finish_reason = normalize_dimension("by_finish_reason")
    conservation_fields = (
        "request_count",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
    )
    conservation = bool(by_agent and by_stage) and all(
        totals[field]
        == sum(row[field] for row in by_agent.values())
        == sum(row[field] for row in by_stage.values())
        for field in conservation_fields
    )
    if not conservation:
        errors.append("usage aggregation does not conserve totals")
    if totals["total_tokens"] < totals["prompt_tokens"] + totals["completion_tokens"]:
        errors.append("totals.total_tokens is below prompt_tokens+completion_tokens")
    successful = totals["successful_calls"]
    provider_reported = totals["provider_reported_calls"]
    if provider_reported > successful:
        errors.append("provider_reported_calls exceeds successful_calls")
    provider_coverage = provider_reported / successful if successful else 0.0
    telemetry_complete = snapshot.get("telemetry_complete") is True
    if not telemetry_complete:
        errors.append("usage telemetry persistence is incomplete")
    complete = (
        not errors
        and successful > 0
        and provider_reported == successful
        and totals["failed_or_unknown_calls"] == 0
        and totals["budget_violation_count"] == 0
    )
    canonical_totals = {
        "prompt_tokens": totals["prompt_tokens"],
        "cached_prompt_tokens": totals["cached_prompt_tokens"],
        "completion_tokens": totals["completion_tokens"],
        "reasoning_tokens": totals["reasoning_tokens"],
        "total_tokens": totals["total_tokens"],
        "tool_call_count": totals["tool_call_count"],
        "new_fact_count": totals["new_fact_count"],
        **totals,
    }
    return {
        "schema_version": USAGE_LEDGER_SCHEMA_VERSION,
        "source": "scan_token_usage_attribution",
        "present": True,
        "complete": complete,
        "call_count": totals["request_count"],
        "provider_reported_call_count": provider_reported,
        "provider_usage_coverage": round(provider_coverage, 4),
        "totals": canonical_totals,
        "by_agent": by_agent,
        "by_stage": by_stage,
        "finish_reasons": {
            key: row["request_count"] for key, row in sorted(by_finish_reason.items())
        },
        "conservation_passed": conservation,
        "telemetry_complete": telemetry_complete,
        "errors": list(dict.fromkeys(errors)),
    }


def build_cost_metrics(
    report: Dict[str, Any],
    evaluation: Dict[str, Any],
    *,
    wall_time_seconds: float = 0.0,
) -> Dict[str, Any]:
    ledger = aggregate_usage_ledger(report)
    metadata = _collect_metadata(report)
    context_tokens = _sum_numeric(metadata, ("context_tokens",))
    cumulative_tokens = _sum_numeric(metadata, ("cumulative_total_tokens",))
    tool_calls = _sum_numeric(metadata, ("tool_call_count", "tool_calls"))
    report_tail_seconds = _max_numeric(
        metadata,
        (
            "report_tail_seconds",
            "report_assembly_seconds",
            "reporting_seconds",
            "final_report_seconds",
        ),
    )
    ledger_tokens = int(_as_dict(ledger.get("totals")).get("total_tokens") or 0)
    billable_tokens = ledger_tokens or cumulative_tokens or context_tokens
    verified = max(1, int(evaluation.get("true_positives") or 0))
    return {
        "context_tokens": context_tokens,
        "cumulative_total_tokens": cumulative_tokens,
        "billable_tokens": billable_tokens,
        "accounting_mode": (
            str(ledger.get("source")) if ledger.get("present") else "legacy_aggregate"
        ),
        "usage_ledger": ledger,
        "tool_calls": tool_calls,
        "wall_time_seconds": round(wall_time_seconds, 4),
        "report_tail_seconds": report_tail_seconds,
        "tokens_per_verified_issue": (
            round(billable_tokens / verified, 4) if billable_tokens else 0.0
        ),
        "tool_calls_per_verified_issue": round(tool_calls / verified, 4) if tool_calls else 0.0,
    }


def copy_conversation_trajectory(project_root: Path, run_dir: Path) -> List[str]:
    """Copy the latest verbose conversation recorder output into the run dir."""

    source_root = project_root / ".zscope_conversations"
    if not source_root.exists():
        return []
    run_dirs = [path for path in source_root.iterdir() if path.is_dir()]
    if not run_dirs:
        return []
    latest = max(run_dirs, key=lambda path: path.stat().st_mtime)
    target = run_dir / "trajectory" / "conversations" / latest.name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(latest, target)
    return [
        path.relative_to(run_dir).as_posix() for path in sorted(target.rglob("*")) if path.is_file()
    ]


def build_trajectory_summary(
    report: Dict[str, Any],
    *,
    run_dir: Path,
    conversation_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    metadata = _as_dict(report.get("metadata"))
    worker_reports = metadata.get("subagent_reports")
    workflow_progress = metadata.get("workflow_progress")
    return {
        "schema_version": SCHEMA_VERSION,
        "run_dir": run_dir.as_posix(),
        "conversation_files": conversation_files or [],
        "workflow_progress": workflow_progress if isinstance(workflow_progress, list) else [],
        "worker_report_count": len(worker_reports) if isinstance(worker_reports, list) else 0,
        "worker_reports": worker_reports if isinstance(worker_reports, list) else [],
        "validator": {
            "present": "validator" in _flatten(metadata).lower(),
            "audit_observation_count": metadata.get("audit_observation_count", 0),
        },
    }


def grade_trial(
    evaluation: Dict[str, Any],
    cost: Dict[str, Any],
    trajectory: Dict[str, Any],
) -> Dict[str, Any]:
    actionable_f1 = evaluation.get("actionable_f1")
    final_value = actionable_f1 if actionable_f1 is not None else evaluation.get("f1")
    final_outcome_score = float(str(final_value or 0.0))
    has_trajectory = bool(
        trajectory.get("conversation_files") or trajectory.get("workflow_progress")
    )
    evidence_score = 1.0 if has_trajectory or trajectory.get("worker_report_count", 0) else 0.5
    tool_behavior_score = 1.0
    if cost.get("tool_calls_per_verified_issue", 0.0) > 80:
        tool_behavior_score = 0.5
    return {
        "schema_version": SCHEMA_VERSION,
        "final_outcome": {
            "score": round(final_outcome_score, 4),
            "basis": (
                "Actionable F1 against ground truth; every surfaced duplicate "
                "counts as a false positive."
            ),
        },
        "tool_behavior": {
            "score": tool_behavior_score,
            "basis": "Deterministic check over tool-call cost and policy-visible trajectory.",
        },
        "evidence_traceability": {
            "score": evidence_score,
            "basis": "Workflow progress, conversation files, or worker reports are replayable.",
        },
        "cost_efficiency": {
            "tokens_per_verified_issue": cost.get("tokens_per_verified_issue", 0.0),
            "tool_calls_per_verified_issue": cost.get("tool_calls_per_verified_issue", 0.0),
        },
    }


def _build_release_evidence(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Extract scanner-owned invariants; independent attestations are never inferred."""

    manifest = _as_dict(report.get("run_manifest"))
    summary = _as_dict(report.get("summary"))
    metadata = _as_dict(report.get("metadata"))
    terminal = report.get("candidate_terminal_states")
    terminal_items = (
        [item for item in terminal or [] if isinstance(item, dict)]
        if isinstance(terminal, list)
        else []
    )
    silent_rejections = 0
    for item in terminal_items:
        disposition = str(
            item.get("candidate_disposition")
            or item.get("terminal_disposition")
            or item.get("validation_status")
            or ""
        ).lower()
        if disposition not in {"rejected", "false_positive", "dismissed"}:
            continue
        if not (item.get("decision_proof") or item.get("rejection_proof")):
            silent_rejections += 1
    completeness = str(
        report.get("completeness")
        or manifest.get("completeness")
        or summary.get("completeness")
        or ""
    ).lower()
    benchmark_ablation = _as_dict(metadata.get("benchmark_ablation")) or _as_dict(
        summary.get("benchmark_ablation")
    )
    return {
        "queue_drained": manifest.get("validation_queue_drained") is True,
        "protocol_anomaly_count": int(summary.get("validator_protocol_exhausted_count") or 0),
        "budget_limited": False,
        "silent_rejection_without_proof_count": silent_rejections,
        "validator_arm": str(manifest.get("validator_experiment_arm") or ""),
        "baseline_frozen": manifest.get("validator_baseline_frozen") is True,
        "benchmark_ablation": benchmark_ablation or None,
        # Sealed/shadow attestations are supplied by the independent evaluator,
        # never copied from scanner-controlled output.
        "sealed_attested": False,
        "shadow_attested": False,
        "active_discovery_exclusive_projects": [],
        "active_discovery_exclusive_cwe_families": [],
    }


def build_trial_summary(
    *,
    suite_root: Path,
    run_dir: Path,
    condition: str,
    run_kind: str,
    trial_index: int,
    report: Dict[str, Any],
    truth: Dict[str, Any],
    environment: Dict[str, Any],
    line_tolerance: int = 8,
    conversation_files: Optional[List[str]] = None,
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
    integrity: Optional[Dict[str, Any]] = None,
    artifact_manifest: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evaluation_views = score_report_views(
        report,
        truth,
        line_tolerance=line_tolerance,
        fp_audit_classifier=fp_audit_classifier,
    )
    default_eval = evaluation_views["default"]
    cost = build_cost_metrics(
        report,
        default_eval,
        wall_time_seconds=float(environment.get("wall_time_seconds") or 0.0),
    )
    trajectory = build_trajectory_summary(
        report,
        run_dir=run_dir,
        conversation_files=conversation_files,
    )
    grader = grade_trial(default_eval, cost, trajectory)
    if artifact_manifest is None:
        artifact_manifest = build_benchmark_artifact_manifest(
            suite_root,
            truth=truth,
        )
    if integrity is None:
        integrity = {
            "schema_version": INTEGRITY_SCHEMA_VERSION,
            "status": "not_run_verified",
            "errors": [],
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": truth.get("benchmark", suite_root.name),
        "suite": truth.get("suite", "unknown"),
        "condition": condition,
        "run_kind": run_kind,
        "trial_index": trial_index,
        "run_dir": run_dir.as_posix(),
        "benchmark_policy": DEFAULT_BENCHMARK_POLICY.as_dict(),
        "environment": environment,
        "evaluation_views": evaluation_views,
        "evaluation": default_eval,
        "candidate_funnel": candidate_funnel(report),
        "cost": cost,
        "release_evidence": _build_release_evidence(report),
        "trajectory": trajectory,
        "grader": grader,
        "artifact_manifest": artifact_manifest,
        "integrity": integrity,
        "final_answer": {
            "report_issue_count": default_eval.get("report_issue_count", 0),
            "issue_identities": default_eval.get("issue_identities", []),
        },
        "final_outcome": {
            "true_positive_truth_ids": default_eval.get("true_positive_truth_ids", []),
            "false_positive_issue_identities": default_eval.get(
                "false_positive_issue_identities", []
            ),
            "missed_truth_ids": default_eval.get("missed", []),
        },
    }


def aggregate_trial_summaries(
    summaries: Sequence[Dict[str, Any]],
    *,
    baseline_summaries: Optional[Sequence[Dict[str, Any]]] = None,
    baseline_tokens_per_tp: Optional[float] = None,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
    require_improvement_claim: bool = False,
    balanced_attestation: Optional[Mapping[str, Any]] = None,
    balanced_attestation_workflow_run_id: str = "",
    release_sha: str = "",
) -> Dict[str, Any]:
    summaries = [summary for summary in summaries if isinstance(summary, dict)]
    by_condition: Dict[str, List[Dict[str, Any]]] = {}
    for summary in summaries:
        by_condition.setdefault(str(summary.get("condition") or "unknown"), []).append(summary)

    conditions: Dict[str, Any] = {}
    for condition, items in by_condition.items():
        f1_values = [float(item.get("evaluation", {}).get("f1") or 0.0) for item in items]
        actionable_f1_values = [
            float(
                item.get("evaluation", {}).get("actionable_f1")
                if item.get("evaluation", {}).get("actionable_f1") is not None
                else item.get("evaluation", {}).get("f1") or 0.0
            )
            for item in items
        ]
        precision_values = [
            float(item.get("evaluation", {}).get("precision") or 0.0) for item in items
        ]
        actionable_precision_values = [
            float(
                item.get("evaluation", {}).get("actionable_precision")
                if item.get("evaluation", {}).get("actionable_precision") is not None
                else item.get("evaluation", {}).get("precision") or 0.0
            )
            for item in items
        ]
        recall_values = [float(item.get("evaluation", {}).get("recall") or 0.0) for item in items]
        issue_sets = [
            set(item.get("evaluation", {}).get("issue_identities") or []) for item in items
        ]
        tp_sets = [
            set(item.get("evaluation", {}).get("true_positive_truth_ids") or []) for item in items
        ]
        fp_sets = [
            set(item.get("evaluation", {}).get("false_positive_issue_identities") or [])
            for item in items
        ]
        wall_values = _summary_numeric_values(items, "cost", "wall_time_seconds")
        token_values = _summary_numeric_values(items, "cost", "billable_tokens")
        token_per_tp_values = _summary_numeric_values(
            items,
            "cost",
            "tokens_per_verified_issue",
            positive_only=True,
        )
        report_tail_values = _summary_numeric_values(
            items,
            "cost",
            "report_tail_seconds",
        )
        high_critical_values = _summary_numeric_values(
            items,
            "evaluation",
            "high_critical_recall",
        )
        safe_alert_values = _summary_numeric_values(
            items,
            "evaluation",
            "safe_entry_alert_rate",
        )
        cwe_values = _aggregate_cwe_series(
            items,
            bootstrap_samples=bootstrap_samples,
            confidence_level=confidence_level,
        )
        release_valid = [item for item in items if _is_valid_release_trial(item)]
        conditions[condition] = {
            "trial_count": len(items),
            "valid_release_trial_count": len(release_valid),
            "precision": _series_stats(
                precision_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "actionable_precision": _series_stats(
                actionable_precision_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "recall": _series_stats(
                recall_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "distinct_root_recall": _series_stats(
                recall_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "high_critical_recall": _series_stats(
                high_critical_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "safe_entry_alert_rate": _series_stats(
                safe_alert_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "per_cwe_recall": cwe_values,
            "f1": _series_stats(
                f1_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "actionable_f1": _series_stats(
                actionable_f1_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "wall_time_seconds": _series_stats(
                wall_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "billable_tokens": _series_stats(
                token_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "tokens_per_verified_issue": _series_stats(
                token_per_tp_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "report_tail_seconds": _series_stats(
                report_tail_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "issue_jaccard": _mean_pairwise_jaccard(issue_sets),
            "true_positive_overlap": _mean_pairwise_jaccard(tp_sets),
            "false_positive_overlap": _mean_pairwise_jaccard(fp_sets),
        }
    result = {
        "schema_version": SCHEMA_VERSION,
        "benchmark_policy": DEFAULT_BENCHMARK_POLICY.as_dict(),
        "trial_count": len(summaries),
        "bootstrap": {
            "method": "nonparametric_resampling_with_replacement",
            "confidence_level": confidence_level,
            "samples": max(0, int(bootstrap_samples)),
            "seed": 0,
        },
        "conditions": conditions,
    }
    result["release_readiness"] = evaluate_release_readiness(
        summaries,
        conditions=conditions,
        baseline_summaries=baseline_summaries,
        baseline_tokens_per_tp=baseline_tokens_per_tp,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        require_improvement_claim=require_improvement_claim,
        balanced_attestation=balanced_attestation,
        balanced_attestation_workflow_run_id=balanced_attestation_workflow_run_id,
        release_sha=release_sha,
    )
    return result


def _summary_numeric_values(
    summaries: Sequence[Dict[str, Any]],
    section: str,
    key: str,
    *,
    positive_only: bool = False,
) -> List[float]:
    values: List[float] = []
    for summary in summaries:
        data = summary.get(section)
        value = data.get(key) if isinstance(data, dict) else None
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        number = float(value)
        if positive_only and number <= 0:
            continue
        values.append(number)
    return values


def _aggregate_cwe_series(
    summaries: Sequence[Dict[str, Any]],
    *,
    bootstrap_samples: int,
    confidence_level: float,
) -> Dict[str, Any]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for summary in summaries:
        evaluation = summary.get("evaluation")
        per_cwe = evaluation.get("per_cwe_recall") if isinstance(evaluation, dict) else None
        if not isinstance(per_cwe, dict):
            continue
        for raw_cwe, row in per_cwe.items():
            if not isinstance(row, dict):
                continue
            cwe = _normalize_cwe(raw_cwe)
            if not cwe:
                continue
            target = grouped.setdefault(cwe, {"sample_counts": [], "values": []})
            sample_count = row.get("sample_count")
            recall = row.get("recall")
            if isinstance(sample_count, int) and not isinstance(sample_count, bool):
                target["sample_counts"].append(sample_count)
            if isinstance(recall, (int, float)) and not isinstance(recall, bool):
                target["values"].append(float(recall))
    result: Dict[str, Any] = {}
    for cwe, row in sorted(grouped.items()):
        sample_counts = row["sample_counts"]
        result[cwe] = {
            "sample_count": max(sample_counts) if sample_counts else 0,
            **_series_stats(
                row["values"],
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
        }
    return result


def _release_trial_errors(summary: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if str(summary.get("run_kind") or "") != "formal":
        errors.append("run_kind is not formal")
    evaluation = summary.get("evaluation")
    scoring_contract = evaluation.get("scoring_contract") if isinstance(evaluation, dict) else None
    if (
        not isinstance(scoring_contract, dict)
        or scoring_contract.get("matcher_version") != MATCHER_VERSION
    ):
        errors.append(f"truth matcher is not {MATCHER_VERSION}")
    integrity = summary.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("status") != "passed":
        errors.append("integrity status is not passed")
    else:
        chain_sha = str(integrity.get("chain_sha256") or "")
        if len(chain_sha) != 64:
            errors.append("integrity chain hash is missing")
    environment = summary.get("environment")
    return_code = environment.get("return_code") if isinstance(environment, dict) else None
    if return_code not in {0, 1}:
        errors.append(f"unexpected return code: {return_code}")
    condition = str(summary.get("condition") or "")
    cache_mode = ""
    if isinstance(integrity, dict):
        cache_mode = str(integrity.get("cache_mode") or "")
    if not cache_mode and isinstance(environment, dict):
        cache_mode = str(environment.get("cache_mode") or "")
    expected_cache_modes = (
        {"isolated_cold"}
        if condition == CONDITION_FULL_ZSCOPE
        else {"isolated_cold", "not_applicable"}
    )
    if cache_mode not in expected_cache_modes:
        errors.append(f"invalid cache mode for release trial: {cache_mode or 'missing'}")
    manifest = summary.get("artifact_manifest")
    required_hashes = (
        "truth_sha256",
        "scorer_sha256",
        "config_sha256",
        "entries_sha256",
        "source_manifest_sha256",
        "benchmark_policy_sha256",
    )
    if not isinstance(manifest, dict):
        errors.append("artifact manifest is missing")
    else:
        missing = [key for key in required_hashes if len(str(manifest.get(key) or "")) != 64]
        if missing:
            errors.append(f"artifact hashes missing: {', '.join(missing)}")
    if DEFAULT_BENCHMARK_POLICY.requirements.get("require_oci_isolation_for_release", False):
        isolation = summary.get("isolation")
        isolation_errors = validate_oci_execution_evidence(
            isolation if isinstance(isolation, dict) else None
        )
        if isolation_errors:
            errors.append("OCI isolation is not release-verified: " + "; ".join(isolation_errors))
    replay = summary.get("validator_replay_bundle")
    if (
        not isinstance(replay, dict)
        or replay.get("schema_version") != "zscope.validator-replay-bundle.v1"
        or len(str(replay.get("bundle_sha256") or "")) != 64
        or replay.get("answer_material_present") is not False
    ):
        errors.append("answer-free validator replay bundle is missing")
    release_evidence = summary.get("release_evidence")
    if isinstance(release_evidence, dict) and release_evidence.get("benchmark_ablation"):
        errors.append("semantic/discovery ablation artifacts are not release eligible")
    return errors


def _is_valid_release_trial(summary: Dict[str, Any]) -> bool:
    return not _release_trial_errors(summary)


def _artifact_protocol_signature(summary: Dict[str, Any]) -> tuple[str, ...]:
    manifest = summary.get("artifact_manifest")
    if not isinstance(manifest, dict):
        return ()
    environment = summary.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    return tuple(
        str(manifest.get(key) or "")
        for key in (
            "truth_sha256",
            "scorer_sha256",
            "config_sha256",
            "entries_sha256",
            "source_manifest_sha256",
            "benchmark_policy_sha256",
        )
    ) + (
        str(environment.get("backend") or ""),
        str(environment.get("model") or ""),
    )


def _artifact_dataset_signature(summary: Dict[str, Any]) -> tuple[str, ...]:
    manifest = summary.get("artifact_manifest")
    if not isinstance(manifest, dict):
        return ()
    return tuple(
        str(manifest.get(key) or "")
        for key in (
            "truth_sha256",
            "scorer_sha256",
            "entries_sha256",
            "source_manifest_sha256",
            "benchmark_policy_sha256",
        )
    )


def _trial_protocol_status(
    summaries: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    by_condition: Dict[str, List[Dict[str, Any]]] = {}
    for summary in summaries:
        by_condition.setdefault(str(summary.get("condition") or "unknown"), []).append(summary)
    condition_rows: Dict[str, Any] = {}
    valid_index_sets: List[Set[int]] = []
    protocol_passed = bool(by_condition)
    all_signatures: Set[tuple[str, ...]] = set()
    for condition, items in sorted(by_condition.items()):
        valid_items = [item for item in items if _is_valid_release_trial(item)]
        valid_indices: Set[int] = set()
        for item in valid_items:
            trial_index = item.get("trial_index")
            if isinstance(trial_index, int) and not isinstance(trial_index, bool):
                valid_indices.add(trial_index)
        valid_index_sets.append(valid_indices)
        signatures = {
            signature
            for signature in (_artifact_protocol_signature(item) for item in valid_items)
            if signature
        }
        all_signatures.update(
            signature
            for signature in (_artifact_dataset_signature(item) for item in valid_items)
            if signature
        )
        duplicate_indices = len(valid_indices) != len(valid_items)
        passed = (
            len(items) >= MIN_RELEASE_TRIALS
            and len(valid_items) == len(items)
            and len(valid_indices) >= MIN_RELEASE_TRIALS
            and not duplicate_indices
            and len(signatures) == 1
        )
        protocol_passed = protocol_passed and passed
        condition_rows[condition] = {
            "trial_count": len(items),
            "valid_cold_trial_count": len(valid_items),
            "valid_trial_indices": sorted(valid_indices),
            "minimum_required": MIN_RELEASE_TRIALS,
            "duplicate_trial_indices": duplicate_indices,
            "artifact_signature_count": len(signatures),
            "passed": passed,
            "invalid_trials": [
                {
                    "trial_index": item.get("trial_index"),
                    "errors": _release_trial_errors(item),
                }
                for item in items
                if not _is_valid_release_trial(item)
            ],
        }
    paired_indices = set.intersection(*valid_index_sets) if valid_index_sets else set()
    paired_passed = len(paired_indices) >= MIN_RELEASE_TRIALS
    protocol_passed = protocol_passed and paired_passed and len(all_signatures) == 1
    return {
        "minimum_trials_per_condition": MIN_RELEASE_TRIALS,
        "conditions": condition_rows,
        "paired_trial_indices": sorted(paired_indices),
        "paired_trial_count": len(paired_indices),
        "paired_trials_passed": paired_passed,
        "cross_condition_artifact_signature_count": len(all_signatures),
        "passed": protocol_passed,
    }


def _metric_gate(
    *,
    actual: Optional[float],
    threshold: float,
    operator: str,
    statistics: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    available = actual is not None
    actual_value = float(actual) if actual is not None else 0.0
    if operator == ">=":
        passed = available and actual_value >= threshold
    elif operator == "<=":
        passed = available and actual_value <= threshold
    else:  # pragma: no cover - internal contract
        raise ValueError(f"Unsupported release gate operator: {operator}")
    result: Dict[str, Any] = {
        "actual": round(actual_value, 4) if available else None,
        "threshold": threshold,
        "operator": operator,
        "available": available,
        "passed": bool(passed),
    }
    if statistics is not None:
        result["statistics"] = statistics
    if details:
        result["details"] = details
    return result


def evaluate_release_readiness(
    summaries: Sequence[Dict[str, Any]],
    *,
    conditions: Optional[Dict[str, Any]] = None,
    baseline_summaries: Optional[Sequence[Dict[str, Any]]] = None,
    baseline_tokens_per_tp: Optional[float] = None,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
    require_improvement_claim: bool = False,
    balanced_attestation: Optional[Mapping[str, Any]] = None,
    balanced_attestation_workflow_run_id: str = "",
    release_sha: str = "",
) -> Dict[str, Any]:
    del conditions, baseline_tokens_per_tp  # retained for API compatibility
    summaries = [item for item in summaries if isinstance(item, dict)]
    trial_protocol = _trial_protocol_status(summaries)
    target_items = [
        item
        for item in summaries
        if str(item.get("condition") or "") == CONDITION_FULL_ZSCOPE
        and _is_valid_release_trial(item)
    ]
    baseline_candidates = [item for item in (baseline_summaries or []) if isinstance(item, dict)]
    baseline_protocol = _trial_protocol_status(baseline_candidates) if baseline_candidates else None
    baseline_items = [
        item
        for item in baseline_candidates
        if str(item.get("condition") or "") == CONDITION_FULL_ZSCOPE
        and _is_valid_release_trial(item)
    ]
    if not target_items:
        return {
            "status": "not_evaluated",
            "passed": False,
            "reason": "no valid formal cold full-pipeline trials",
            "trial_protocol": trial_protocol,
            "hard_gates": {},
            "non_regression_readiness": {"status": "not_evaluated", "passed": False},
        }

    def numbers(items: Sequence[Dict[str, Any]], section: str, key: str) -> List[float]:
        return _summary_numeric_values(items, section, key)

    def evaluation_numbers(
        items: Sequence[Dict[str, Any]], key: str, fallback: str = ""
    ) -> List[float]:
        values = numbers(items, "evaluation", key)
        return values or (numbers(items, "evaluation", fallback) if fallback else [])

    def median_or_none(values: Sequence[float]) -> Optional[float]:
        return float(statistics.median(values)) if len(values) == len(target_items) else None

    tp_values = evaluation_numbers(target_items, "true_positives")
    token_values = numbers(target_items, "cost", "billable_tokens")
    recalls = evaluation_numbers(target_items, "distinct_root_recall", "recall")
    fdrs = evaluation_numbers(
        target_items, "actionable_false_discovery_rate", "false_discovery_rate"
    )
    tp_sets = [
        set(item.get("evaluation", {}).get("true_positive_truth_ids") or [])
        for item in target_items
    ]
    evidence_rows = [_as_dict(item.get("release_evidence")) for item in target_items]
    usage_ledgers = [
        _as_dict(_as_dict(item.get("cost")).get("usage_ledger")) for item in target_items
    ]
    attribution_rows = [
        _as_dict(_as_dict(item.get("evaluation")).get("attribution")) for item in target_items
    ]

    baseline_fdrs = evaluation_numbers(
        baseline_items, "actionable_false_discovery_rate", "false_discovery_rate"
    )

    def paired_delta_pp(current: Sequence[float], baseline: Sequence[float]) -> Optional[float]:
        if (
            len(current) != len(target_items)
            or len(baseline) != len(baseline_items)
            or not baseline
        ):
            return None
        return round(
            (float(statistics.median(current)) - float(statistics.median(baseline))) * 100.0,
            8,
        )

    range_actuals: Dict[str, Optional[float]] = {
        "median_confirmed_tp": median_or_none(tp_values),
        "median_tokens": median_or_none(token_values),
        "per_run_tokens": max(token_values) if len(token_values) == len(target_items) else None,
        "actionable_fdr_delta_vs_arm_a_pp": paired_delta_pp(fdrs, baseline_fdrs),
        "true_positive_jaccard": _mean_pairwise_jaccard(tp_sets),
        "recall_range_pp": (
            (max(recalls) - min(recalls)) * 100.0
            if len(recalls) == len(target_items) and recalls
            else None
        ),
        "provider_usage_coverage": (
            min(float(row.get("provider_usage_coverage") or 0.0) for row in usage_ledgers)
            if usage_ledgers
            else None
        ),
        "explicit_attribution_coverage": (
            min(float(row.get("explicit_coverage") or 0.0) for row in attribution_rows)
            if attribution_rows
            else None
        ),
        "queue_drained_rate": (
            sum(row.get("queue_drained") is True for row in evidence_rows) / len(evidence_rows)
            if evidence_rows
            else None
        ),
        "token_conservation_rate": (
            sum(row.get("conservation_passed") is True for row in usage_ledgers)
            / len(usage_ledgers)
            if usage_ledgers
            else None
        ),
        "telemetry_complete_rate": (
            sum(row.get("telemetry_complete") is True for row in usage_ledgers) / len(usage_ledgers)
            if usage_ledgers
            else None
        ),
        "protocol_anomaly_count": (
            sum(int(row.get("protocol_anomaly_count") or 0) for row in evidence_rows)
            if evidence_rows
            else None
        ),
    }

    def gate_set(
        actuals: Mapping[str, Optional[float]],
        policy_gates: Mapping[str, tuple[str, float]],
    ) -> Dict[str, Any]:
        return {
            name: _metric_gate(actual=actuals.get(name), threshold=threshold, operator=operator)
            for name, (operator, threshold) in policy_gates.items()
        }

    hard_gates: Dict[str, Any] = {
        "trial_protocol": {
            "actual": trial_protocol.get("paired_trial_count", 0),
            "threshold": MIN_RELEASE_TRIALS,
            "operator": ">=",
            "available": True,
            "passed": bool(trial_protocol.get("passed")),
            "details": trial_protocol,
        },
        **gate_set(range_actuals, DEFAULT_BENCHMARK_POLICY.range_gates),
    }

    if isinstance(balanced_attestation, Mapping) and release_sha:
        attestation_result = validate_balanced_attestation(
            balanced_attestation,
            release_sha=release_sha,
            workflow_run_id=balanced_attestation_workflow_run_id,
        )
        raw_balanced_metrics = balanced_attestation.get("metrics")
    else:
        attestation_result = {
            "passed": False,
            "errors": ["balanced attestation and release_sha are required"],
        }
        raw_balanced_metrics = None
    raw_balanced_metrics = raw_balanced_metrics if isinstance(raw_balanced_metrics, Mapping) else {}
    balanced_actuals: Dict[str, Optional[float]] = {
        name: (
            float(raw_balanced_metrics[name])
            if isinstance(raw_balanced_metrics.get(name), (int, float))
            and not isinstance(raw_balanced_metrics.get(name), bool)
            else None
        )
        for name in DEFAULT_BENCHMARK_POLICY.sealed_delta_gates
    }
    hard_gates.update(gate_set(balanced_actuals, DEFAULT_BENCHMARK_POLICY.sealed_delta_gates))
    baseline_evidence = [_as_dict(item.get("release_evidence")) for item in baseline_items]
    arm_a_attested = bool(
        baseline_protocol
        and baseline_protocol.get("passed")
        and baseline_evidence
        and all(
            row.get("validator_arm") == "A" and row.get("baseline_frozen") is True
            for row in baseline_evidence
        )
    )
    hard_gates["arm_a_baseline_attested"] = {
        "available": baseline_protocol is not None,
        "passed": arm_a_attested,
        "details": baseline_protocol,
    }
    for key, requirement in (
        ("public_external_attested", "require_public_external_attestation_for_release"),
        ("sealed_attested", "require_sealed_attestation_for_release"),
        ("shadow_attested", "require_shadow_attestation_for_release"),
    ):
        if DEFAULT_BENCHMARK_POLICY.requirements.get(requirement, False):
            hard_gates[key] = {
                "available": balanced_attestation is not None,
                "passed": attestation_result.get("passed") is True,
                "details": attestation_result,
            }

    improvement_claim = evaluate_improvement_claim(
        target_items,
        baseline_items,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
    )
    if require_improvement_claim:
        hard_gates["improvement_claim"] = {
            **improvement_claim,
            "available": improvement_claim.get("status") != "not_evaluated",
        }
    non_regression = evaluate_non_regression_readiness(target_items, baseline_items)
    passed = all(bool(gate.get("passed")) for gate in hard_gates.values())
    return {
        "status": "passed" if passed else "failed",
        "passed": passed,
        "target_condition": CONDITION_FULL_ZSCOPE,
        "benchmark_policy": DEFAULT_BENCHMARK_POLICY.as_dict(),
        "trial_protocol": trial_protocol,
        "hard_gates": hard_gates,
        "range_actuals": range_actuals,
        "balanced_default_actuals": balanced_actuals,
        "balanced_default_attestation": attestation_result,
        "non_regression_readiness": non_regression,
        "improvement_claim": improvement_claim,
        "require_improvement_claim": require_improvement_claim,
    }


def evaluate_non_regression_readiness(
    current_summaries: Sequence[Dict[str, Any]],
    baseline_summaries: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Evaluate post-rollout releases against the frozen previous release."""

    def median_metric(items: Sequence[Dict[str, Any]], section: str, key: str) -> Optional[float]:
        values = _summary_numeric_values(items, section, key, positive_only=False)
        return float(statistics.median(values)) if len(values) == len(items) and values else None

    def delta_pp(key: str, fallback: str = "") -> Optional[float]:
        current = median_metric(current_summaries, "evaluation", key)
        baseline = median_metric(baseline_summaries, "evaluation", key)
        if (current is None or baseline is None) and fallback:
            current = median_metric(current_summaries, "evaluation", fallback)
            baseline = median_metric(baseline_summaries, "evaluation", fallback)
        return (
            round((current - baseline) * 100.0, 8)
            if current is not None and baseline is not None
            else None
        )

    current_efficiency = median_metric(current_summaries, "cost", "tokens_per_verified_issue")
    baseline_efficiency = median_metric(baseline_summaries, "cost", "tokens_per_verified_issue")
    growth = (
        current_efficiency / baseline_efficiency - 1.0
        if current_efficiency is not None
        and baseline_efficiency is not None
        and baseline_efficiency > 0
        else None
    )
    actuals = {
        "sealed_recall_delta_pp": delta_pp("distinct_root_recall", "recall"),
        "sealed_precision_delta_pp": delta_pp("actionable_precision", "precision"),
        "sealed_high_critical_recall_delta_pp": delta_pp("high_critical_recall"),
        "tokens_per_kloc_or_tp_growth": growth,
    }
    gates = {
        name: _metric_gate(actual=actuals[name], threshold=threshold, operator=operator)
        for name, (operator, threshold) in DEFAULT_BENCHMARK_POLICY.non_regression_gates.items()
    }
    passed = bool(current_summaries and baseline_summaries) and all(
        bool(gate.get("passed")) for gate in gates.values()
    )
    return {
        "status": "passed" if passed else "failed",
        "passed": passed,
        "actuals": actuals,
        "gates": gates,
    }


def select_validator_arm(arms: Mapping[str, Mapping[str, Any]]) -> Optional[str]:
    """Select the lowest-token passing arm when recall differs by <1pp."""

    eligible = {
        name: row
        for name, row in arms.items()
        if row.get("passed") is True
        and isinstance(row.get("median_recall"), (int, float))
        and isinstance(row.get("median_tokens"), (int, float))
    }
    if not eligible:
        return None
    best_recall = max(float(row["median_recall"]) for row in eligible.values())
    tie_pp = float(DEFAULT_BENCHMARK_POLICY.matrix_thresholds["arm_recall_tie_pp"])
    contenders = {
        name: row
        for name, row in eligible.items()
        if (best_recall - float(row["median_recall"])) * 100.0 < tie_pp
    }
    return min(contenders, key=lambda name: (float(contenders[name]["median_tokens"]), name))


def evaluate_improvement_claim(
    current_summaries: Sequence[Dict[str, Any]],
    baseline_summaries: Sequence[Dict[str, Any]],
    *,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
) -> Dict[str, Any]:
    if not current_summaries or not baseline_summaries:
        return {
            "status": "not_evaluated",
            "passed": False,
            "reason": "paired current and baseline summaries are required",
        }
    current_by_index = {
        int(item["trial_index"]): item
        for item in current_summaries
        if isinstance(item.get("trial_index"), int)
        and not isinstance(item.get("trial_index"), bool)
    }
    baseline_by_index = {
        int(item["trial_index"]): item
        for item in baseline_summaries
        if isinstance(item.get("trial_index"), int)
        and not isinstance(item.get("trial_index"), bool)
    }
    paired_indices = sorted(set(current_by_index).intersection(baseline_by_index))
    if len(paired_indices) < MIN_RELEASE_TRIALS:
        return {
            "status": "insufficient_data",
            "passed": False,
            "reason": f"at least {MIN_RELEASE_TRIALS} paired trials are required",
            "paired_trial_indices": paired_indices,
        }
    current_signatures = {
        _artifact_dataset_signature(current_by_index[index]) for index in paired_indices
    }
    baseline_signatures = {
        _artifact_dataset_signature(baseline_by_index[index]) for index in paired_indices
    }
    if len(current_signatures) != 1 or current_signatures != baseline_signatures:
        return {
            "status": "invalid_pairing",
            "passed": False,
            "reason": "current and baseline trials do not share one artifact signature",
            "paired_trial_indices": paired_indices,
        }

    quality_deltas: List[float] = []
    current_walls: List[float] = []
    baseline_walls: List[float] = []
    for index in paired_indices:
        current = current_by_index[index]
        baseline = baseline_by_index[index]
        current_eval = current.get("evaluation")
        baseline_eval = baseline.get("evaluation")
        current_quality = (
            current_eval.get("actionable_f1") if isinstance(current_eval, dict) else None
        )
        baseline_quality = (
            baseline_eval.get("actionable_f1") if isinstance(baseline_eval, dict) else None
        )
        if current_quality is None and isinstance(current_eval, dict):
            current_quality = current_eval.get("f1")
        if baseline_quality is None and isinstance(baseline_eval, dict):
            baseline_quality = baseline_eval.get("f1")
        current_cost = current.get("cost")
        baseline_cost = baseline.get("cost")
        current_wall = (
            current_cost.get("wall_time_seconds") if isinstance(current_cost, dict) else None
        )
        baseline_wall = (
            baseline_cost.get("wall_time_seconds") if isinstance(baseline_cost, dict) else None
        )
        if not all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            for value in (current_quality, baseline_quality, current_wall, baseline_wall)
        ):
            return {
                "status": "insufficient_data",
                "passed": False,
                "reason": "paired trials are missing actionable F1 or wall time",
                "paired_trial_indices": paired_indices,
            }
        quality_deltas.append(
            float(cast(float, current_quality)) - float(cast(float, baseline_quality))
        )
        current_walls.append(float(cast(float, current_wall)))
        baseline_walls.append(float(cast(float, baseline_wall)))

    quality_delta = sum(quality_deltas) / len(quality_deltas)
    quality_ci = _bootstrap_ci(
        quality_deltas,
        confidence_level=confidence_level,
        samples=bootstrap_samples,
        statistic="mean",
    )
    current_wall_stats = _series_stats(
        current_walls,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    baseline_wall_stats = _series_stats(
        baseline_walls,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    median_reduction = (
        1.0 - float(current_wall_stats["median"]) / float(baseline_wall_stats["median"])
        if float(baseline_wall_stats["median"]) > 0
        else 0.0
    )
    p95_reduction = (
        1.0 - float(current_wall_stats["p95"]) / float(baseline_wall_stats["p95"])
        if float(baseline_wall_stats["p95"]) > 0
        else 0.0
    )
    quality_gain_path = (
        quality_delta >= 0.05 and quality_ci is not None and float(quality_ci["lower"]) > 0.0
    )
    performance_path = quality_delta >= -0.02 and max(median_reduction, p95_reduction) >= 0.20
    passed = quality_gain_path or performance_path
    return {
        "status": "passed" if passed else "failed",
        "passed": passed,
        "paired_trial_indices": paired_indices,
        "paired_trial_count": len(paired_indices),
        "quality_metric": "actionable_f1",
        "quality_delta": round(quality_delta, 4),
        "quality_delta_percentage_points": round(quality_delta * 100.0, 4),
        "quality_delta_bootstrap_ci": quality_ci,
        "median_wall_time_reduction": round(median_reduction, 4),
        "p95_wall_time_reduction": round(p95_reduction, 4),
        "quality_gain_path": {
            "required_delta_percentage_points": 5.0,
            "requires_ci_lower_above_zero": True,
            "passed": quality_gain_path,
        },
        "performance_path": {
            "maximum_quality_degradation_percentage_points": 2.0,
            "required_wall_time_reduction": 0.20,
            "passed": performance_path,
        },
    }


def load_summaries(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            summaries.append(data)
    return summaries


def _collect_metadata(value: Any) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    if isinstance(value, dict):
        metadata = value.get("metadata")
        if isinstance(metadata, dict):
            found.append(metadata)
        for item in value.values():
            found.extend(_collect_metadata(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_collect_metadata(item))
    return found


def _sum_numeric(dicts: Iterable[Dict[str, Any]], keys: Sequence[str]) -> float:
    total = 0.0
    for data in dicts:
        for key in keys:
            value = data.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                total += float(value)
    return round(total, 4)


def _max_numeric(
    dicts: Iterable[Dict[str, Any]],
    keys: Sequence[str],
) -> Optional[float]:
    values: List[float] = []
    for data in dicts:
        for key in keys:
            value = data.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                values.append(float(value))
    return round(max(values), 4) if values else None


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _text_has_category(text: str, truth: Dict[str, Any]) -> bool:
    return bool(_category_match_reason(text, truth))


def _category_match_reason(text: str, truth: Dict[str, Any]) -> str:
    lowered = text.replace("_", " ").replace("-", " ").lower()
    category = str(truth.get("category") or "").lower()
    cwe = str(truth.get("cwe") or "").lower()
    aliases = _category_aliases(category, cwe)
    if cwe and cwe in lowered:
        return f"cwe:{cwe}"
    for alias in aliases:
        if alias and alias in lowered:
            return f"category_alias:{alias}"
    keyword_hits = _truth_keyword_hits(lowered, truth)
    if keyword_hits >= 2:
        return f"keyword_hits:{keyword_hits}"
    return ""


def _category_aliases(category: str, cwe: str) -> List[str]:
    category_key = category.replace("-", "_").lower()
    builtins = {
        "memory_safety": ["memory safety", "bounds", "buffer", "overflow", "leak"],
        "integer_overflow": [
            "integer overflow",
            "overflow",
            "wrap",
            "signed unsigned",
            "bounds",
            "cwe-190",
        ],
        "heap_overflow": [
            "heap overflow",
            "heap buffer overflow",
            "buffer overflow",
            "bounds",
            "cwe-122",
        ],
        "buffer_overflow": [
            "buffer overflow",
            "heap overflow",
            "out of bounds",
            "bounds",
            "cwe-787",
            "cwe-122",
        ],
        "out_of_bounds_write": [
            "out of bounds write",
            "out-of-bounds write",
            "out of bounds",
            "bounds",
            "object offset",
            "pointer offset",
            "out of range pointer offset",
            "cwe-787",
            "cwe-823",
        ],
        "out_of_range_pointer_offset": [
            "out of range pointer offset",
            "out-of-range pointer offset",
            "pointer offset",
            "object offset",
            "offset-derived pointer",
            "out of bounds write",
            "out-of-bounds write",
            "out of bounds",
            "bounds",
            "cwe-823",
            "cwe-787",
        ],
        "buffer_overread": [
            "buffer overread",
            "buffer over read",
            "out-of-bounds read",
            "bounds",
            "cwe-126",
        ],
        "buffer_over_read": [
            "buffer overread",
            "buffer over read",
            "out-of-bounds read",
            "bounds",
            "cwe-126",
        ],
        "buffer_underread": [
            "buffer underread",
            "buffer under read",
            "buffer underflow",
            "cwe-127",
        ],
        "buffer_underwrite": [
            "buffer underwrite",
            "buffer under write",
            "buffer underflow",
            "cwe-124",
        ],
        "buffer_underflow": [
            "buffer underflow",
            "buffer underread",
            "buffer underwrite",
            "cwe-127",
            "cwe-124",
        ],
        "bounds": [
            "bounds",
            "out of bounds",
            "buffer overflow",
            "heap overflow",
            "buffer overread",
            "buffer over read",
            "buffer underread",
            "buffer underwrite",
            "buffer underflow",
            "overread",
            "over read",
            "protocol validation",
            "magic validation",
            "wide count",
            "unchecked count",
            "count before magic",
            "cwe-125",
            "cwe-787",
            "cwe-20",
        ],
        "format_string": ["format string", "cwe-134"],
        "deadlock": [
            "deadlock",
            "lock order",
            "recursive lock",
            "callback lock",
            "timer callback",
            "lock-order cycle",
            "cwe-833",
        ],
        "command_injection": ["command injection", "shell injection", "system(", "cwe-78"],
        "memory_leak": [
            "memory leak",
            "resource leak",
            "leak",
            "child list",
            "owned member",
            "children",
            "proc head",
            "cwe-401",
            "cwe-772",
        ],
        "resource_lifecycle": [
            "resource lifecycle",
            "memory leak",
            "resource leak",
            "child list",
            "owned member",
            "children",
            "proc head",
            "cwe-772",
        ],
        "double_free": ["double free", "cwe-415"],
        "use_after_free": ["use after free", "use-after-free", "uaf", "dangling", "cwe-416"],
        "invalid_free": ["invalid free", "non-heap", "cwe-590"],
        "null_pointer_dereference": ["null pointer", "null dereference", "cwe-476"],
        "stack_escape": ["stack escape", "stack address", "cwe-562"],
        "stack_overflow": ["stack overflow", "stack buffer", "vla", "cwe-121"],
        "signed_unsigned": [
            "signed",
            "unsigned",
            "negative",
            "integer overflow",
            "bounds",
            "cwe-195",
            "cwe-190",
        ],
        "off_by_one": ["off by one", "off-by-one", "one byte", "cwe-193"],
        "uninitialized_read": ["uninitialized", "padding", "cwe-457"],
        "race": [
            "race",
            "data race",
            "toctou",
            "unsynchronized",
            "unsynchronized shared state",
            "shared state race",
            "without synchronization",
            "missing lock",
            "concurrent",
            "use after free",
            "use-after-free",
            "uaf",
            "dangling",
            "unmap",
            "munmap",
            "cwe-362",
            "cwe-367",
        ],
        "data_race": ["data race", "race", "cwe-362"],
        "unsynchronized_shared_state": [
            "unsynchronized shared state",
            "shared state race",
            "data race",
            "race",
            "without synchronization",
            "global state",
            "watermark",
            "map/unmap",
            "mmap",
            "munmap",
            "cwe-362",
        ],
        "shared_state_race": [
            "shared state race",
            "unsynchronized shared state",
            "data race",
            "race",
            "global state",
            "cwe-362",
        ],
        "object_publication": [
            "object publication",
            "published before initialization",
            "half initialized",
            "published",
            "cwe-362",
        ],
        "refcount_race": ["refcount", "reference count", "ref count", "race", "cwe-362"],
        "held_lock_callback": [
            "held lock callback",
            "callback while lock",
            "under lock",
            "cwe-667",
        ],
        "missing_unlock": ["missing unlock", "return while lock", "forgot unlock", "cwe-667"],
        "unlock_without_lock": [
            "unlock without lock",
            "unlock without owning",
            "unlock without held lock",
            "lock protocol violation",
            "not held",
            "cwe-832",
        ],
        "lock_protocol_violation": [
            "lock protocol violation",
            "unlock without lock",
            "unlock without owning",
            "not held",
            "cwe-832",
        ],
        "double_checked_locking": ["double checked", "lazy initialization", "race", "cwe-362"],
        "lost_wakeup": ["lost wakeup", "condition variable", "pthread_cond_wait", "cwe-366"],
        "realloc_misuse": ["realloc misuse", "direct realloc", "old pointer", "cwe-401"],
        "alignment": ["alignment", "unaligned", "strict alias", "cwe-704"],
        "stale_fd": ["stale fd", "file descriptor", "closed fd", "cwe-672"],
        "fd_leak": [
            "fd leak",
            "file descriptor leak",
            "descriptor leak",
            "unclosed fd",
            "unclosed descriptor",
            "cwe-775",
        ],
        "file_descriptor_leak": [
            "fd leak",
            "file descriptor leak",
            "descriptor leak",
            "unclosed fd",
            "unclosed descriptor",
            "cwe-775",
        ],
        "missing_fd_release": [
            "missing fd release",
            "fd leak",
            "file descriptor leak",
            "descriptor leak",
            "unclosed fd",
            "unclosed descriptor",
            "cwe-775",
        ],
        "state_inconsistency": [
            "state not restored",
            "state inconsistency",
            "rollback",
            "race",
            "resource lifecycle",
            "global state",
            "not restored",
            "unmap",
            "munmap",
            "map rules",
            "cwe-672",
            "cwe-362",
        ],
        "unchecked_return": ["unchecked return", "unchecked result", "return success", "cwe-252"],
        "busy_loop": [
            "busy loop",
            "infinite loop",
            "spin",
            "no delay",
            "resource exhaustion",
            "cwe-400",
        ],
        "infinite_loop": ["infinite loop", "busy loop", "spin", "cwe-835", "cwe-400"],
        "log_amplification": ["log amplification", "log storm", "resource exhaustion", "cwe-400"],
        "key_truncation": ["key truncation", "truncated key", "partial comparison", "cwe-187"],
        "size_limit_mismatch": [
            "size limit",
            "fixed limit",
            "buffer limit",
            "spec",
            "cwe-131",
            "cwe-190",
        ],
        "fd_type_mismatch": ["fd type", "reliable fd", "raw fd", "mismatched parameter", "cwe-628"],
        "permission": [
            "permission",
            "incorrect permission check",
            "mode validation",
            "mode",
            "chmod",
            "requested permission",
            "hard-coded mode",
            "hardcoded mode",
            "cwe-732",
            "cwe-276",
        ],
        "incorrect_permission_check": [
            "incorrect permission check",
            "permission",
            "mode validation",
            "requested permission",
            "cwe-732",
            "cwe-276",
        ],
        "mode_validation": [
            "mode validation",
            "permission",
            "incorrect permission check",
            "cwe-732",
            "cwe-276",
        ],
        "protocol_mixup": [
            "protocol mismatch",
            "protocol mixup",
            "auth level",
            "origin validation",
            "cwe-346",
        ],
        "partial_resource_leak": ["partial resource leak", "resource leak", "retry", "cwe-401"],
        "dynamic_array_race": [
            "dynamic array",
            "array expansion",
            "race",
            "double free",
            "cwe-362",
        ],
        "version_filtering": ["version", "missing version", "low version", "filter", "cwe-20"],
        "missing_refcount": [
            "refcount",
            "reference count",
            "shared resource",
            "cleanup",
            "cwe-772",
        ],
        "thread_cache_leak": [
            "thread cache leak",
            "cache leak",
            "cached blocks",
            "memory leak",
            "resource leak",
            "resource allocation without limits",
            "unbounded allocation",
            "tls",
            "thread cache",
            "cwe-772",
            "cwe-770",
        ],
        "sigpipe_unhandled": ["sigpipe", "signal", "closed peer", "not handled", "cwe-404"],
        "premature_destroy": [
            "premature destroy",
            "active tasks",
            "active users",
            "pool",
            "shared pool",
            "use after free",
            "use-after-free",
            "uaf",
            "resource lifecycle",
            "dangling",
            "cwe-416",
        ],
        "registration_race": [
            "registration race",
            "check then act",
            "ops registration",
            "race",
            "cwe-362",
        ],
        "alloc_free_mismatch": [
            "allocator mismatch",
            "alloc free mismatch",
            "allocator pairing",
            "cwe-762",
        ],
        "key_generation_race": ["ftok", "key generation", "key collision", "path state", "cwe-362"],
        "fd_encoding_mismatch": ["encoded fd", "fd encoding", "check value", "raw fd", "cwe-587"],
        "type_confusion": [
            "type confusion",
            "wrong type",
            "invalid mutex",
            "sharedresources",
            "cwe-843",
        ],
        "semantic_mismatch": [
            "semantic mismatch",
            "callback parameter",
            "counter domain",
            "busy work",
            "cwe-628",
        ],
        "byte_order_logic": ["byte order", "endian", "ctz", "trailing zero", "cwe-682"],
        "reader_state_race": [
            "reader state",
            "reader pid",
            "multiple readers",
            "rwlock",
            "race",
            "cwe-362",
        ],
        "uninitialized_output": [
            "uninitialized output",
            "partially initialized",
            "output parameter",
            "cwe-457",
        ],
        "file_type_validation": [
            "file type",
            "character device",
            "regular file",
            "mapping size",
            "incorrect validation order",
            "validation order",
            "validate file type",
            "file type validation",
            "cwe-20",
        ],
        "ownership_contract_violation": [
            "ownership contract",
            "ownership transfer",
            "memory leak",
            "resource lifecycle",
            "resource leak",
            "orphan",
            "owner",
            "cwe-772",
        ],
        "resource_allocation_without_limits": [
            "resource allocation without limits",
            "unbounded allocation",
            "without limit",
            "missing quota",
            "no quota",
            "resource exhaustion",
            "memory leak",
            "thread cache leak",
            "cwe-770",
            "cwe-772",
        ],
        "log_level_misuse": ["log level", "logged at error", "alert noise", "cwe-778"],
        "logic_error": ["logic error", "wrong group", "wrong index", "cwe-682"],
        "global_mode_race": ["global mode", "qrcu", "crcu", "race", "cwe-362"],
        "slot_race": ["slot race", "cas result", "process slot", "race", "cwe-362"],
        "shared_memory_race": [
            "shared memory race",
            "lookup before lock",
            "concurrent create",
            "memzone",
            "cwe-362",
        ],
        "state_machine": ["state machine", "missing transition", "lifecycle state", "cwe-672"],
        "signal_deadlock": [
            "signal deadlock",
            "signal handler",
            "semaphore",
            "deadlock",
            "cwe-833",
        ],
        "signal_race": ["signal race", "signal handler", "async signal", "callstack", "cwe-479"],
        "callback_self_destroy_race": [
            "callback self destroy",
            "self destruction",
            "callback can free",
            "use after free",
            "cwe-416",
        ],
    }
    aliases = builtins.get(category_key, [category_key.replace("_", " ")])
    if cwe:
        aliases = aliases + [cwe]
    return aliases


def _truth_keyword_hits(text: str, truth: Dict[str, Any]) -> int:
    keywords = truth.get("keywords")
    if not isinstance(keywords, list):
        return 0
    hits = 0
    for keyword in keywords:
        needle = str(keyword or "").replace("_", " ").replace("-", " ").lower().strip()
        if needle and needle in text:
            hits += 1
    return hits


def _issue_function(issue: Dict[str, Any]) -> str:
    return str(issue.get("function") or issue.get("func_name") or "").lower()


def _function_match_reason(issue: Dict[str, Any], text: str, truth: Dict[str, Any]) -> str:
    expected = _truth_function_anchors(truth)
    if not expected:
        return "no_expected_function"

    anchors = _issue_function_anchors(issue)
    for kind, func in expected:
        if func in anchors:
            return f"{kind}:structured_anchor"
    for kind, func in expected:
        if func in text:
            return f"{kind}:text_anchor"
    return ""


def _truth_function_anchors(truth: Dict[str, Any]) -> List[tuple[str, str]]:
    expected: List[tuple[str, str]] = []

    def add(kind: str, value: Any) -> None:
        func = str(value or "").strip().lower()
        if func and (kind, func) not in expected:
            expected.append((kind, func))

    add("primary", truth.get("function"))
    add("secondary", truth.get("secondary_function"))

    add("sibling", truth.get("sibling_function"))

    for field in ("related_functions", "additional_functions", "sibling_functions"):
        values = truth.get(field)
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, dict):
                add(field, value.get("function") or value.get("name"))
            else:
                add(field, value)

    locations = truth.get("additional_locations")
    if isinstance(locations, list):
        for item in locations:
            if isinstance(item, dict):
                add("additional", item.get("function"))

    return expected


def _issue_function_anchors(issue: Dict[str, Any]) -> Set[str]:
    anchors: Set[str] = set()

    def add(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, dict):
            for item in value.values():
                add(item)
            return
        if isinstance(value, list):
            for item in value:
                add(item)
            return
        text = str(value).strip().lower()
        if text:
            anchors.add(text)

    for key in (
        "function",
        "func_name",
        "entry_function",
        "sink_function",
        "target_function",
        "analyzed_from",
    ):
        add(issue.get(key))
    for key in ("call_path", "call_paths"):
        add(issue.get(key))
    evidence_pack = issue.get("evidence_pack")
    if isinstance(evidence_pack, dict):
        for key in (
            "entry_function",
            "sink_function",
            "target_function",
            "call_path",
            "call_paths",
            "duplicate_sources",
        ):
            add(evidence_pack.get(key))
        path = evidence_pack.get("path")
        if isinstance(path, dict):
            for key in (
                "entry_function",
                "sink_function",
                "target_function",
                "call_path",
                "call_paths",
            ):
                add(path.get(key))
    return anchors


def _location_file(issue: Dict[str, Any]) -> str:
    location = str(issue.get("location") or issue.get("file") or "")
    if ":" in location:
        return location.split(":", 1)[0]
    return location


def _file_match_reason(text: str, truth: Dict[str, Any]) -> str:
    expected_file = str(truth.get("file") or "").lower().replace("\\", "/")
    if not expected_file:
        return "no_expected_file"
    basename = Path(expected_file).name.lower()
    if expected_file in text:
        return "path"
    if basename and basename in text:
        return "basename"
    secondary_file = str(truth.get("secondary_file") or "").lower().replace("\\", "/")
    if secondary_file and secondary_file in text:
        return "secondary_path"
    if secondary_file:
        secondary_basename = Path(secondary_file).name.lower()
        if secondary_basename and secondary_basename in text:
            return "secondary_basename"
    locations = truth.get("additional_locations")
    if isinstance(locations, list):
        for idx, item in enumerate(locations):
            if not isinstance(item, dict):
                continue
            file_value = str(item.get("file") or "").lower().replace("\\", "/")
            if not file_value:
                continue
            if file_value in text:
                return f"additional_path:{idx}"
            additional_basename = Path(file_value).name.lower()
            if additional_basename and additional_basename in text:
                return f"additional_basename:{idx}"
    return ""


def _line_match_reason(
    issue: Dict[str, Any],
    truth: Dict[str, Any],
    line_tolerance: int,
) -> str:
    expected_ranges = _truth_line_ranges(truth)
    if not expected_ranges:
        return "no_expected_line"
    actual_ranges = _issue_line_ranges(issue)
    if not actual_ranges:
        return "no_issue_line"
    for actual_start, actual_end in actual_ranges:
        for label, start, end in expected_ranges:
            if start - line_tolerance <= actual_end and actual_start <= end + line_tolerance:
                return f"{label}:within_tolerance"
    return ""


def _truth_line_ranges(truth: Dict[str, Any]) -> List[tuple[str, int, int]]:
    ranges: List[tuple[str, int, int]] = []

    def add(label: str, start_key: str, end_key: str) -> None:
        start_value = truth.get(start_key)
        if start_value in (None, ""):
            return
        try:
            start = int(str(start_value))
        except (TypeError, ValueError):
            return
        if start <= 1:
            return
        try:
            end_value = truth.get(end_key)
            end = int(str(end_value if end_value not in (None, "") else start))
        except (TypeError, ValueError):
            end = start
        if end < start:
            end = start
        ranges.append((label, start, end))

    add("primary_line", "line", "end_line")
    add("current_primary_line", "_current_line", "_current_end_line")
    add("secondary_line", "secondary_line", "secondary_end_line")
    add("current_secondary_line", "_current_secondary_line", "_current_secondary_end_line")
    locations = truth.get("additional_locations")
    if isinstance(locations, list):
        for idx, item in enumerate(locations):
            if not isinstance(item, dict):
                continue
            try:
                start = int(item.get("line") or 0)
            except (TypeError, ValueError):
                continue
            if start <= 1:
                continue
            try:
                end = int(item.get("end_line") or start)
            except (TypeError, ValueError):
                end = start
            if end < start:
                end = start
            ranges.append((f"additional_line:{idx}", start, end))
    return ranges


def _location_line(issue: Dict[str, Any]) -> Optional[int]:
    line_range = _location_line_range(issue)
    return line_range[0] if line_range else None


def _location_line_range(issue: Dict[str, Any]) -> Optional[tuple[int, int]]:
    ranges = _issue_line_ranges(issue)
    return ranges[0] if ranges else None


def _issue_line_ranges(issue: Dict[str, Any]) -> List[tuple[int, int]]:
    ranges: List[tuple[int, int]] = []
    seen: Set[tuple[int, int]] = set()

    def add_range(start_value: Any, end_value: Any = None) -> None:
        try:
            start = int(start_value)
        except (TypeError, ValueError):
            return
        if start <= 0:
            return
        try:
            end = int(end_value) if end_value not in (None, "") else start
        except (TypeError, ValueError):
            end = start
        span = (start, max(start, end))
        if span not in seen:
            seen.add(span)
            ranges.append(span)

    def add_location(value: Any) -> None:
        if not isinstance(value, str):
            return
        for token in value.split(":")[1:]:
            match = re.match(r"\s*(\d+)(?:\s*-\s*(\d+))?", token)
            if match:
                add_range(match.group(1), match.group(2) or match.group(1))

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if "line" in value or "start_line" in value:
                add_range(value.get("line") or value.get("start_line"), value.get("end_line"))
            for key in (
                "location",
                "file",
                "source_location",
                "sink_location",
                "primary_location",
                "secondary_location",
            ):
                add_location(value.get(key))
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(issue)
    return ranges


def _short_text(issue: Dict[str, Any]) -> str:
    text = str(issue.get("description") or issue.get("message") or issue.get("title") or "")
    return " ".join(text.lower().split())[:120]


def _percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = min(1.0, max(0.0, quantile)) * (len(ordered) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _bootstrap_ci(
    values: Sequence[float],
    *,
    confidence_level: float = 0.95,
    samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    statistic: str = "mean",
) -> Optional[Dict[str, Any]]:
    values = [float(value) for value in values]
    samples = max(0, int(samples))
    if not values or samples <= 0:
        return None
    if statistic not in {"mean", "median"}:
        raise ValueError(f"Unsupported bootstrap statistic: {statistic}")
    confidence_level = min(0.999, max(0.001, float(confidence_level)))
    rng = random.Random(0)
    estimates: List[float] = []
    size = len(values)
    for _ in range(samples):
        resample = [values[rng.randrange(size)] for _ in range(size)]
        if statistic == "median":
            estimate = _percentile(resample, 0.5)
        else:
            estimate = sum(resample) / size
        estimates.append(estimate)
    alpha = (1.0 - confidence_level) / 2.0
    return {
        "confidence_level": round(confidence_level, 4),
        "method": "percentile_bootstrap",
        "statistic": statistic,
        "samples": samples,
        "lower": round(_percentile(estimates, alpha), 4),
        "upper": round(_percentile(estimates, 1.0 - alpha), 4),
    }


def _series_stats(
    values: Sequence[float],
    *,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
    ci_statistic: str = "mean",
) -> Dict[str, Any]:
    if not values:
        return {
            "mean": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "min": 0.0,
            "max": 0.0,
            "stdev": 0.0,
            "values": [],
            "bootstrap_ci": None,
        }
    numeric_values = [float(value) for value in values]
    mean = sum(numeric_values) / len(numeric_values)
    variance = sum((value - mean) ** 2 for value in numeric_values) / len(numeric_values)
    return {
        "mean": round(mean, 4),
        "median": round(_percentile(numeric_values, 0.5), 4),
        "p95": round(_percentile(numeric_values, 0.95), 4),
        "min": round(min(numeric_values), 4),
        "max": round(max(numeric_values), 4),
        "stdev": round(math.sqrt(variance), 4),
        "values": [round(value, 4) for value in numeric_values],
        "bootstrap_ci": _bootstrap_ci(
            numeric_values,
            confidence_level=confidence_level,
            samples=bootstrap_samples,
            statistic=ci_statistic,
        ),
    }


def _mean_pairwise_jaccard(sets: Sequence[Set[str]]) -> float:
    if len(sets) < 2:
        return 1.0
    scores: List[float] = []
    for left_idx, left in enumerate(sets):
        for right in sets[left_idx + 1 :]:
            scores.append(_jaccard(left, right))
    return round(sum(scores) / len(scores), 4) if scores else 1.0


def _jaccard(left: Set[str], right: Set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _git_commit_sha(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=5,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def _redact_url(value: str) -> str:
    if not value:
        return ""
    if "@" not in value:
        return value
    scheme, rest = value.split("://", 1) if "://" in value else ("", value)
    host = rest.rsplit("@", 1)[-1]
    return f"{scheme}://[redacted]@{host}" if scheme else f"[redacted]@{host}"
