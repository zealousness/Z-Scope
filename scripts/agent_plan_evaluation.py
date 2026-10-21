#!/usr/bin/env python3
"""Development evaluation prep and same-version comparison helper.

This is the S09 development-only assistant.  It plans answer-free
evaluation matrices (cold / warm / incremental), freezes structured
observations from already produced scan artifacts (reports, usage
ledgers, projections), and compares frozen runs under strict identity
binding (same source, target, build contexts, schema, model, config,
scanner and tools).

Hard boundaries:

- It never starts a scan, model call, formal benchmark or network
  request itself.  Matrix cells carry operator-executable commands and
  ``autostart=false``.
- It never reads ground truth or scores findings.  The only
  answer-related logic is rejection: scan inputs and artifacts that
  contain truth/scoring material fail closed.
- Reports and projections are read through the official zscope reader:
  production ``zscope.shared-json.v1`` storage envelopes are decoded
  with the complete shared-graph validation (references, object
  digests, cycles, orphan objects) and every scan/extraction runs on
  the logical report, while frozen SHAs always cover the raw stored
  bytes.  Legacy plain JSON continues to work unchanged.
- Frozen run records carry a canonical content digest (``record_id``).
  Loading a record re-verifies that digest against the record body, and
  a report-manifest-bound identity is re-anchored to the unmodified
  report file, so editing a frozen record fails closed instead of
  feeding tampered counts or identity into a comparison.  This is local
  content integrity only, not a signature or permission platform, and
  no JSON artifact grants runtime proof.
- Missing values stay ``null`` (never zero), zero denominators become
  ``N/A`` (never 100%), and failure/cancel/retry costs are preserved.
- Every artifact is ``benchmark_scope=development_only`` with
  ``formal_eligible=false`` and ``release_eligible=false``.  Formal
  gates and scorers are unchanged and must not consume this output.

Schema versions:

- identity: ``zscope.agent-plan-evaluation-identity.v1``
- plan:     ``zscope.agent-plan-evaluation-plan.v1``
- run:      ``zscope.agent-plan-evaluation-run.v1``
- comparison: ``zscope.agent-plan-evaluation-comparison.v1``
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Reports are stored by the production writer as ``zscope.shared-json.v1``
# storage envelopes.  Reading reuses the official reader (and therefore the
# complete shared-graph validation: references, object digests, cycles and
# orphan objects); nothing here reimplements or simplifies that decoder.
from zscope.reporting.json_io import read_report
from zscope.reporting.shared_objects import STORAGE_SCHEMA

IDENTITY_SCHEMA_VERSION = "zscope.agent-plan-evaluation-identity.v1"
PLAN_SCHEMA_VERSION = "zscope.agent-plan-evaluation-plan.v1"
RUN_SCHEMA_VERSION = "zscope.agent-plan-evaluation-run.v1"
COMPARISON_SCHEMA_VERSION = "zscope.agent-plan-evaluation-comparison.v1"

# Matches the streaming threshold inside zscope.reporting.json_io; larger
# files are only read through the official streaming reader, and the raw
# envelope probe below is skipped for them.
LARGE_REPORT_BYTES = 16 * 1024 * 1024
ENVELOPE_STANDARD_KEYS = ("storage_schema", "root", "objects")

SCAN_MODES = ("cold", "warm", "incremental")
VARIANT_KINDS = ("baseline", "source_change")
DECLARED_CHANGE_KINDS = (
    "added_callback",
    "removed_code",
    "removed_variant",
    "contract_change",
    "header_change",
    "other_declared_change",
)
TERMINAL_DISPOSITIONS = (
    "confirmed",
    "rejected_with_proof",
    "needs_review",
    "deferred_budget",
    "engine_failed",
    "interrupted",
    "deduplicated_alias",
    "shadow_observation",
)
PENDING_VALIDATION_STATUSES = {"pending", "queued", "planned", "running"}
NEEDS_REVIEW_SUB_STATES = ("protocol_pending", "business_conditional")
USAGE_SUCCESS_OUTCOMES = {"success", "succeeded", "ok"}
USAGE_DENIED_OUTCOMES = {"denied", "budget_denied"}
OPERATOR_RUN_STATUSES = ("failed", "cancelled")
# Identity fields that must be present and equal for a same-version
# (equivalence) comparison.  ``source_tree_hash`` and
# ``build_context_ids`` may only differ in an explicitly declared
# variant comparison.
REQUIRED_IDENTITY_FIELDS = (
    "source_tree_hash",
    "project_id",
    "entry_functions",
    "build_context_ids",
    "candidate_schema_version",
    "validation_policy_version",
    "report_schema_version",
    "config_hash",
    "model_manifest_hash",
    "scanner_identity",
    "tool_sha256",
)
VARIANT_OVERRIDABLE_FIELDS = ("source_tree_hash", "build_context_ids")
# Keys that mark scanner-side material as truth/scoring derived.  A
# report or projection carrying any of these is rejected at record time.
FORBIDDEN_ARTIFACT_KEYS = {
    "matched_pairs",
    "ground_truth",
    "truth",
    "tp",
    "fp",
    "fn",
    "tp_count",
    "fp_count",
    "fn_count",
    "true_positive",
    "false_positive",
    "true_positives",
    "false_positives",
    "release_eligible",
    "formal_eligible",
    "benchmark_eligible",
    "benchmark_score",
}
TRUTH_SHAPED_JSON_KEYS = {
    "total_vulnerabilities",
    "vulnerabilities",
    "matched_pairs",
}
MAX_SNIFF_JSON_BYTES = 1_000_000


class PlanEvaluationError(Exception):
    """Validation failure that must fail closed without writing output."""

    def __init__(self, code: str, message: str, details: Optional[Mapping[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(dict(value), handle, indent=2, sort_keys=False, ensure_ascii=True)
        handle.write("\n")
    os.replace(tmp, path)


def _median(values: Sequence[Optional[float]]) -> Optional[float]:
    present = sorted(v for v in values if v is not None)
    if not present:
        return None
    mid = len(present) // 2
    if len(present) % 2:
        return float(present[mid])
    return (float(present[mid - 1]) + float(present[mid])) / 2.0


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


# ---------------------------------------------------------------------------
# Answer isolation guards (EVAL01)
# ---------------------------------------------------------------------------


def scan_input_answer_violations(root: Path) -> List[Dict[str, str]]:
    """Walk a scan-input root and report answer-bearing material.

    The walk does not follow directory symlinks.  Rules mirror the Range
    answer-isolation intent: no benchmark directory, no ground truth
    files, no scanner state/history, no historical reports and no
    truth-shaped JSON payloads.
    """

    violations: List[Dict[str, str]] = []
    seen: set = set()
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        resolved = os.path.realpath(dirpath)
        if resolved in seen:
            dirnames[:] = []
            continue
        seen.add(resolved)
        base = Path(dirpath)
        rel_dir = base.relative_to(root).as_posix() if base != root else ""
        for part in ([rel_dir] if rel_dir else []):
            lowered = part.lower()
            if lowered == "benchmark":
                violations.append({"path": rel_dir, "rule": "benchmark_directory_forbidden"})
            if lowered.startswith("benchmark-artifacts"):
                violations.append({"path": rel_dir, "rule": "benchmark_artifacts_forbidden"})
            if part.startswith(".zscope"):
                violations.append({"path": rel_dir, "rule": "scanner_state_directory_forbidden"})
        for name in filenames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            lowered = name.lower()
            if lowered == "deterministic_entries.json":
                violations.append({"path": rel, "rule": "benchmark_manifest_forbidden"})
            if "ground_truth" in lowered:
                violations.append({"path": rel, "rule": "ground_truth_file_forbidden"})
            if lowered == "report.json" or lowered.endswith(".sarif"):
                violations.append({"path": rel, "rule": "historical_report_forbidden"})
            if "scorer" in lowered:
                violations.append({"path": rel, "rule": "scorer_file_forbidden"})
            if lowered.endswith(".json"):
                candidate = base / name
                try:
                    if candidate.stat().st_size > MAX_SNIFF_JSON_BYTES:
                        continue
                    data = load_json(candidate)
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
                if isinstance(data, Mapping) and TRUTH_SHAPED_JSON_KEYS & set(data):
                    violations.append({"path": rel, "rule": "truth_shaped_json_forbidden"})
    # De-duplicate while keeping deterministic order.
    unique: List[Dict[str, str]] = []
    seen_paths: set = set()
    for item in violations:
        key = (item["path"], item["rule"])
        if key not in seen_paths:
            seen_paths.add(key)
            unique.append(item)
    return unique


def find_forbidden_artifact_keys(value: Any, path: str = "$") -> List[str]:
    """Recursively locate truth/scoring keys inside a loaded artifact."""

    found: List[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            location = f"{path}.{key}"
            if str(key).lower() in FORBIDDEN_ARTIFACT_KEYS:
                found.append(location)
            found.extend(find_forbidden_artifact_keys(item, location))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(find_forbidden_artifact_keys(item, f"{path}[{index}]"))
    return found


def load_logical_report(path: Path) -> Tuple[Any, Dict[str, Any]]:
    """Load a report (or projection) through the official zscope reader.

    Production reports are stored as ``zscope.shared-json.v1`` envelopes;
    ``read_report`` performs the complete shared-graph validation
    (reference existence, object digests, cycles, orphan objects) and
    returns the logical report, so every downstream scan/extraction sees
    the real report instead of the storage envelope.  Legacy plain JSON
    passes through unchanged.  Callers keep hashing the raw file bytes:
    the frozen SHA always covers the stored envelope, never a decoded
    view.

    Envelope metadata outside the standard ``storage_schema``/``root``/
    ``objects`` keys is additionally scanned for truth/scoring markers so
    the answer-isolation standard is not lowered relative to plain JSON.
    """

    try:
        logical = read_report(path)
    except (OSError, ValueError, RuntimeError) as exc:
        raise PlanEvaluationError(
            "report_storage_invalid",
            f"storage failed the official validation for {path}: {exc}",
            {"path": str(path)},
        ) from exc
    format_info: Dict[str, Any] = {
        "storage": "plain-json",
        "storage_schema": None,
        "envelope_extra_keys": [],
    }
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    raw: Any = None
    if 0 < size < LARGE_REPORT_BYTES:
        try:
            raw = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            raw = None
    elif size >= LARGE_REPORT_BYTES:
        format_info["storage"] = "not-probed-large-file"
    if isinstance(raw, Mapping) and raw.get("storage_schema") == STORAGE_SCHEMA:
        extras = sorted(str(key) for key in raw if key not in ENVELOPE_STANDARD_KEYS)
        format_info = {
            "storage": "shared-json",
            "storage_schema": str(raw.get("storage_schema")),
            "envelope_extra_keys": extras,
        }
        forbidden: List[str] = []
        for key in extras:
            location = f"$.{key}"
            if str(key).lower() in FORBIDDEN_ARTIFACT_KEYS:
                forbidden.append(location)
            forbidden.extend(find_forbidden_artifact_keys(raw[key], location))
        if forbidden:
            raise PlanEvaluationError(
                "answer_leak_detected",
                "shared storage envelope carries truth/scoring fields outside"
                " the logical report; refusing to load",
                {"path": str(path), "forbidden_keys": forbidden[:20]},
            )
    return logical, format_info


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def _normalize_identity(raw: Mapping[str, Any], source: str) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise PlanEvaluationError("invalid_identity", f"{source} identity is not an object")
    if raw.get("schema_version") != IDENTITY_SCHEMA_VERSION:
        raise PlanEvaluationError(
            "invalid_identity",
            f"{source} identity schema_version must be {IDENTITY_SCHEMA_VERSION}",
        )
    raw_model = raw.get("model")
    if isinstance(raw_model, Mapping):
        model: Mapping[str, Any] = raw_model
    else:
        model = {}
    raw_tools = raw.get("tools")
    if isinstance(raw_tools, Mapping):
        tools: Mapping[str, Any] = raw_tools
    else:
        tools = {}
    identity: Dict[str, Any] = {
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "source_tree_hash": str(raw.get("source_tree_hash") or ""),
        "source_revision": str(raw.get("source_revision") or ""),
        "project_id": str(raw.get("project_id") or ""),
        "entry_functions": sorted(str(v) for v in (raw.get("entry_functions") or []) if str(v)),
        "build_context_ids": sorted(str(v) for v in (raw.get("build_context_ids") or []) if str(v)),
        "scanner_identity": str(raw.get("scanner_identity") or ""),
        "config_hash": str(raw.get("config_hash") or ""),
        "model_manifest_hash": str(
            raw.get("model_manifest_hash") or model.get("manifest_hash") or ""
        ),
        "model_provider": str(raw.get("model_provider") or model.get("provider") or ""),
        "model_name": str(raw.get("model_name") or model.get("model") or ""),
        "tool_sha256": {str(k): str(v) for k, v in tools.items() if str(v)},
        "candidate_schema_version": str(raw.get("candidate_schema_version") or ""),
        "validation_policy_version": str(raw.get("validation_policy_version") or ""),
        "report_schema_version": raw.get("report_schema_version"),
    }
    if not isinstance(identity["report_schema_version"], int) or isinstance(
        identity["report_schema_version"], bool
    ):
        identity["report_schema_version"] = None
    return identity


def load_identity_file(path: Path) -> Dict[str, Any]:
    try:
        raw = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PlanEvaluationError("invalid_identity", f"cannot read identity file: {exc}") from exc
    return _normalize_identity(raw, "declared")


def identity_from_report(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Extract the identity fields a report's run manifest can bind."""

    manifest = report.get("run_manifest")
    manifest = manifest if isinstance(manifest, Mapping) else {}
    metadata = report.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    states = report.get("candidate_terminal_states")
    build_ids = set()
    if isinstance(states, list):
        for item in states:
            if isinstance(item, Mapping) and item.get("build_context_id"):
                build_ids.add(str(item["build_context_id"]))
    schema_version = report.get("schema_version")
    return {
        "source_tree_hash": str(manifest.get("source_tree_hash") or ""),
        "source_revision": str(manifest.get("source_revision") or ""),
        "project_id": str(manifest.get("project_id") or ""),
        "entry_functions": sorted(
            [str(manifest["entry_function"])] if manifest.get("entry_function") else []
        ),
        "build_context_ids": sorted(build_ids),
        "config_hash": str(manifest.get("config_hash") or ""),
        "model_manifest_hash": str(manifest.get("model_manifest_hash") or ""),
        "candidate_schema_version": str(manifest.get("candidate_schema_version") or ""),
        "validation_policy_version": str(manifest.get("validation_policy_version") or ""),
        "report_schema_version": schema_version if isinstance(schema_version, int) else None,
        "_manifest_present": bool(manifest),
    }


def merge_identity(
    declared: Mapping[str, Any], extracted: Mapping[str, Any]
) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Union declared and report-bound identity; conflicting fields fail."""

    merged: Dict[str, Any] = dict(declared)
    conflicts: List[Dict[str, str]] = []
    for field in (
        "source_tree_hash",
        "source_revision",
        "project_id",
        "entry_functions",
        "build_context_ids",
        "config_hash",
        "model_manifest_hash",
        "candidate_schema_version",
        "validation_policy_version",
        "report_schema_version",
    ):
        report_value = extracted.get(field)
        if report_value in (None, "", [], {}):
            continue
        declared_value = merged.get(field)
        if declared_value in (None, "", [], {}):
            merged[field] = report_value
        elif declared_value != report_value:
            conflicts.append(
                {
                    "field": field,
                    "declared": canonical_json(declared_value),
                    "report": canonical_json(report_value),
                }
            )
    return merged, conflicts


def identity_missing_fields(identity: Mapping[str, Any]) -> List[str]:
    missing: List[str] = []
    for field in REQUIRED_IDENTITY_FIELDS:
        value = identity.get(field)
        if value is None or value == "" or value == [] or value == {}:
            missing.append(field)
    return missing


# ---------------------------------------------------------------------------
# Report observation extraction
# ---------------------------------------------------------------------------


def extract_counts(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Extract candidate/terminal/pending buckets; missing stays null."""

    manifest = report.get("run_manifest")
    manifest = manifest if isinstance(manifest, Mapping) else {}
    raw_states = report.get("candidate_terminal_states")
    if isinstance(raw_states, list):
        states: List[Any] = raw_states
        has_states = True
    else:
        states = []
        has_states = False
    dict_states = [item for item in states if isinstance(item, Mapping)]

    buckets: Dict[str, int] = {}
    sub_states: Dict[str, int] = {}
    pending_validation = 0
    for item in dict_states:
        disposition = str(item.get("candidate_disposition") or item.get("status") or "").lower()
        if disposition in TERMINAL_DISPOSITIONS:
            buckets[disposition] = buckets.get(disposition, 0) + 1
        else:
            buckets["unrecognized"] = buckets.get("unrecognized", 0) + 1
        if str(item.get("status") or "").lower() in PENDING_VALIDATION_STATUSES:
            pending_validation += 1
        if disposition == "needs_review":
            sub = str(item.get("needs_review_sub_state") or "").lower()
            if sub in NEEDS_REVIEW_SUB_STATES:
                sub_states[sub] = sub_states.get(sub, 0) + 1

    if has_states:
        pending_count = (
            sub_states.get("protocol_pending", 0)
            + sub_states.get("business_conditional", 0)
            + buckets.get("deferred_budget", 0)
            + pending_validation
        )
        return {
            "source": "candidate_terminal_states",
            "candidate_count": len(states),
            "confirmed_count": buckets.get("confirmed", 0),
            "with_review_count": buckets.get("needs_review", 0),
            "pending_count": pending_count,
            "ruled_out_count": buckets.get("rejected_with_proof", 0),
            "deduplicated_alias_count": buckets.get("deduplicated_alias", 0),
            "operational_incomplete_count": buckets.get("engine_failed", 0)
            + buckets.get("interrupted", 0),
            "shadow_observation_count": buckets.get("shadow_observation", 0),
            "terminal_disposition_counts": buckets,
            "needs_review_sub_states": sub_states,
            "pending_validation_count": pending_validation,
        }
    # Fallback: run manifest summary fields only.  Fields the manifest
    # cannot provide stay null rather than being defaulted to zero.
    return {
        "source": "run_manifest_fallback",
        "candidate_count": None,
        "confirmed_count": _int_or_none(manifest.get("issue_count")),
        "with_review_count": _int_or_none(manifest.get("needs_review_count")),
        "pending_count": _int_or_none(manifest.get("pending_validation_count")),
        "ruled_out_count": None,
        "deduplicated_alias_count": None,
        "operational_incomplete_count": None,
        "shadow_observation_count": None,
        "terminal_disposition_counts": {},
        "needs_review_sub_states": {},
        "pending_validation_count": _int_or_none(manifest.get("pending_validation_count")),
    }


def extract_coverage(report: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    metadata = report.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    coverage = metadata.get("build_coverage")
    return dict(coverage) if isinstance(coverage, Mapping) else None


def extract_report_wall_seconds(report: Mapping[str, Any]) -> Optional[float]:
    metadata = report.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    summary = report.get("summary")
    summary = summary if isinstance(summary, Mapping) else {}
    for holder in (metadata, summary):
        for key in ("scan_wall_seconds", "batch_wall_seconds", "wall_seconds"):
            value = holder.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
    return None


def aggregate_usage_ledger(path: Path) -> Dict[str, Any]:
    """Aggregate an llm_usage_events JSONL sidecar, preserving costs.

    One physical event is counted once.  Failed, denied and retried
    calls keep their token cost so retry/failure overhead stays visible.
    """

    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    outcomes: Dict[str, int] = {}
    totals = {
        "request_count": 0,
        "successful_calls": 0,
        "denied_requests": 0,
        "failed_or_unknown_calls": 0,
        "retry_count": 0,
        "repair_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cached_prompt_tokens": 0,
        "reasoning_tokens": 0,
        "failed_or_denied_token_cost": 0,
        "retry_token_cost": 0,
        "budget_violation_count": 0,
        "provider_reported_calls": 0,
        "estimated_or_conservative_calls": 0,
        "tool_call_count": 0,
        "new_fact_count": 0,
        "duration_ms": 0,
    }
    models: set = set()
    for event in events:
        if not isinstance(event, Mapping):
            continue
        totals["request_count"] += 1
        outcome = str(event.get("outcome") or "unknown")
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        if outcome in USAGE_SUCCESS_OUTCOMES:
            totals["successful_calls"] += 1
        elif outcome in USAGE_DENIED_OUTCOMES:
            totals["denied_requests"] += 1
        else:
            totals["failed_or_unknown_calls"] += 1
        prompt = _int_or_none(event.get("prompt_tokens")) or 0
        completion = _int_or_none(event.get("completion_tokens")) or 0
        total = _int_or_none(event.get("total_tokens")) or 0
        totals["prompt_tokens"] += prompt
        totals["completion_tokens"] += completion
        totals["total_tokens"] += total
        totals["cached_prompt_tokens"] += _int_or_none(event.get("cached_prompt_tokens")) or 0
        totals["reasoning_tokens"] += _int_or_none(event.get("reasoning_tokens")) or 0
        if outcome not in USAGE_SUCCESS_OUTCOMES:
            totals["failed_or_denied_token_cost"] += total
        if event.get("retry"):
            totals["retry_count"] += 1
            totals["retry_token_cost"] += total
        if event.get("repair"):
            totals["repair_count"] += 1
        if event.get("budget_violation"):
            totals["budget_violation_count"] += 1
        if event.get("provider_reported"):
            totals["provider_reported_calls"] += 1
        if event.get("conservative_charge") or not event.get("provider_reported"):
            totals["estimated_or_conservative_calls"] += 1
        totals["tool_call_count"] += _int_or_none(event.get("tool_call_count")) or 0
        totals["new_fact_count"] += _int_or_none(event.get("new_fact_count")) or 0
        totals["duration_ms"] += _int_or_none(event.get("duration_ms")) or 0
        model = str(event.get("model") or "")
        if model:
            models.add(model)
    return {
        "event_count": len(events),
        "outcomes": outcomes,
        "aggregates": totals,
        "models": sorted(models),
    }


# ---------------------------------------------------------------------------
# Plan command
# ---------------------------------------------------------------------------


def _parse_variant(spec: str) -> Dict[str, Any]:
    if spec.strip() == "baseline":
        return {"variant_id": "baseline", "kind": "baseline"}
    fields: Dict[str, str] = {}
    for chunk in spec.split(","):
        if "=" not in chunk:
            raise PlanEvaluationError("invalid_variant", f"variant chunk lacks '=': {chunk!r}")
        key, value = chunk.split("=", 1)
        fields[key.strip()] = value.strip()
    variant_id = fields.get("id") or ""
    kind = fields.get("kind") or "source_change"
    if not variant_id:
        raise PlanEvaluationError("invalid_variant", "variant requires id=<value>")
    if kind not in VARIANT_KINDS:
        raise PlanEvaluationError("invalid_variant", f"unknown variant kind: {kind}")
    variant: Dict[str, Any] = {"variant_id": variant_id, "kind": kind}
    if kind == "source_change":
        change = fields.get("change") or ""
        if change not in DECLARED_CHANGE_KINDS:
            raise PlanEvaluationError(
                "invalid_variant",
                f"source_change requires declared change in {DECLARED_CHANGE_KINDS}",
            )
        source_hash = fields.get("source-tree-hash") or ""
        if not source_hash:
            raise PlanEvaluationError(
                "invalid_variant",
                "source_change requires source-tree-hash=<sha256 of changed source>",
            )
        variant["declared_change"] = change
        variant["expected_source_tree_hash"] = source_hash
        if fields.get("build-context-ids"):
            variant["expected_build_context_ids"] = sorted(
                v for v in fields["build-context-ids"].split("|") if v
            )
        note = fields.get("note") or ""
        if note:
            variant["note"] = note
    elif "source-tree-hash" in fields or "change" in fields:
        raise PlanEvaluationError(
            "invalid_variant", "baseline variant must not declare source changes"
        )
    return variant


def _variant_expected_identity(
    base_identity: Mapping[str, Any], variant: Mapping[str, Any]
) -> Dict[str, Any]:
    expected = dict(base_identity)
    if variant.get("kind") == "source_change":
        expected["source_tree_hash"] = variant["expected_source_tree_hash"]
        if variant.get("expected_build_context_ids"):
            expected["build_context_ids"] = list(variant["expected_build_context_ids"])
    return expected


def _render_command(template: str, variant_id: str, mode: str) -> str:
    return (
        template.replace("{variant}", variant_id)
        .replace("{mode}", mode)
        .replace("{variant_id}", variant_id)
    )


def run_preflight_checks(
    tools: Sequence[str], env_vars: Sequence[str]
) -> Tuple[Dict[str, Any], List[str]]:
    missing: List[str] = []
    tool_results: Dict[str, Any] = {}
    env_results: Dict[str, bool] = {}
    for tool in tools:
        found = shutil.which(tool)
        tool_results[tool] = found or ""
        if not found:
            missing.append(f"tool:{tool}")
    for var in env_vars:
        present = bool(os.environ.get(var))
        env_results[var] = present
        if not present:
            missing.append(f"env:{var}")
    execution = {
        "executed": True,
        "tool_results": tool_results,
        "env_results": env_results,
        "status": "failed" if missing else "passed",
        "missing": missing,
    }
    return execution, missing


def build_plan(
    *,
    identity_path: Path,
    scan_input_root: Path,
    variant_specs: Sequence[str],
    modes: Sequence[str],
    scan_command_template: Optional[str],
    preflight_tools: Sequence[str],
    preflight_env: Sequence[str],
    run_preflight: bool,
    output: Path,
) -> Dict[str, Any]:
    if not scan_input_root.is_dir():
        raise PlanEvaluationError(
            "invalid_input", f"scan input root is not a directory: {scan_input_root}"
        )
    violations = scan_input_answer_violations(scan_input_root)
    if violations:
        raise PlanEvaluationError(
            "answer_leak_detected",
            "scan input root contains answer/scoring material; refusing to plan",
            {"violations": violations[:20], "violation_count": len(violations)},
        )

    identity = load_identity_file(identity_path)
    missing = identity_missing_fields(identity)
    if missing:
        raise PlanEvaluationError(
            "identity_incomplete",
            "declared identity is missing required fields",
            {"missing_fields": missing},
        )

    variants: List[Dict[str, Any]] = []
    if variant_specs:
        for spec in variant_specs:
            variants.append(_parse_variant(spec))
    else:
        variants.append({"variant_id": "baseline", "kind": "baseline"})
    if not any(v["kind"] == "baseline" for v in variants):
        variants.insert(0, {"variant_id": "baseline", "kind": "baseline"})
    if sum(1 for v in variants if v["kind"] == "baseline") > 1:
        raise PlanEvaluationError("invalid_variant", "only one baseline variant is allowed")
    seen_ids = {v["variant_id"] for v in variants}
    if len(seen_ids) != len(variants):
        raise PlanEvaluationError("invalid_variant", "duplicate variant id")

    selected_modes = list(modes) if modes else list(SCAN_MODES)
    for mode in selected_modes:
        if mode not in SCAN_MODES:
            raise PlanEvaluationError("invalid_input", f"unknown mode: {mode}")

    matrix: List[Dict[str, Any]] = []
    for variant in variants:
        expected_identity = _variant_expected_identity(identity, variant)
        for mode in selected_modes:
            cell: Dict[str, Any] = {
                "cell_id": f"{variant['variant_id']}:{mode}",
                "variant_id": variant["variant_id"],
                "mode": mode,
                "autostart": False,
                "expected_identity": expected_identity,
                "command": None,
                "command_source": "not_supplied",
                "record_hint": (
                    "python scripts/agent_plan_evaluation.py record"
                    f" --identity {identity_path.as_posix()}"
                    f" --plan {output.as_posix()}"
                    f" --variant-id {variant['variant_id']}"
                    f" --mode {mode}"
                    " --label <label> --report <report.json> --output <runs/<label>.json>"
                ),
            }
            if scan_command_template:
                cell["command"] = _render_command(
                    scan_command_template, variant["variant_id"], mode
                )
                cell["command_source"] = "operator_template"
            matrix.append(cell)

    workflow: List[Dict[str, Any]] = [
        {
            "step": 1,
            "action": "verify_answer_free_input",
            "detail": (
                "scan input root passed the answer-free walk; ground truth, "
                "benchmark directories, scanner state and historical reports "
                "must stay outside scan input"
            ),
        },
        {
            "step": 2,
            "action": "cold_scan_baseline",
            "detail": "run the baseline cold scan cell manually; record its report",
        },
    ]
    step = 3
    if "warm" in selected_modes:
        workflow.append(
            {
                "step": step,
                "action": "warm_rescan_baseline",
                "detail": (
                    "re-scan the unchanged input with the existing cache "
                    "(reuse full run); record it with mode=warm"
                ),
            }
        )
        step += 1
    for variant in variants:
        if variant["kind"] != "source_change":
            continue
        workflow.append(
            {
                "step": step,
                "action": "apply_declared_change",
                "variant_id": variant["variant_id"],
                "declared_change": variant["declared_change"],
                "detail": (
                    "apply the declared source change outside scan input; "
                    "the changed tree is a new identity, not the baseline"
                ),
            }
        )
        step += 1
        if "incremental" in selected_modes:
            workflow.append(
                {
                    "step": step,
                    "action": "incremental_rescan",
                    "variant_id": variant["variant_id"],
                    "detail": (
                        "incrementally re-scan the changed tree over the "
                        "baseline cache; record with mode=incremental"
                    ),
                }
            )
            step += 1
        workflow.append(
            {
                "step": step,
                "action": "independent_cold_rescan",
                "variant_id": variant["variant_id"],
                "detail": (
                    "independently cold-scan the changed tree (fresh cache); "
                    "record with mode=cold; compare equivalence against the "
                    "incremental run of the same identity"
                ),
            }
        )
        step += 1
    workflow.append(
        {
            "step": step,
            "action": "compare",
            "detail": (
                "compare recorded runs: equivalence for same-identity "
                "cold/warm/incremental pairs; declared variant diffs only "
                "with --variant-comparison against this plan"
            ),
        }
    )

    preflight: Dict[str, Any] = {
        "tools": [
            {"name": tool, "check_command": f"command -v {tool}"} for tool in preflight_tools
        ],
        "env_vars": [
            {"name": var, "check_command": f'test -n "${{{var}:-}}"'} for var in preflight_env
        ],
        "execution": {"executed": False, "status": "not_run", "missing": []},
    }
    if run_preflight:
        execution, _missing = run_preflight_checks(preflight_tools, preflight_env)
        preflight["execution"] = execution

    file_count = sum(
        len(files) for _root, _dirs, files in os.walk(scan_input_root, followlinks=False)
    )
    plan: Dict[str, Any] = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_id": "",
        "generated_at": _utc_now(),
        "benchmark_scope": "development_only",
        "autostart": False,
        "formal_eligible": False,
        "release_eligible": False,
        "identity": identity,
        "answer_isolation": {
            "scan_input_root": scan_input_root.resolve().as_posix(),
            "status": "answer_free",
            "checked_files": file_count,
            "violations": [],
            "rules": [
                "no benchmark/ or benchmark-artifacts directory",
                "no ground_truth files",
                "no .zscope* scanner state directories",
                "no historical report.json / *.sarif / scorer files",
                "no deterministic_entries.json benchmark manifest",
                "no truth-shaped JSON payloads",
            ],
        },
        "variants": variants,
        "modes": selected_modes,
        "matrix": matrix,
        "workflow": workflow,
        "preflight": preflight,
        "comparison_policy": {
            "required_identity_fields": list(REQUIRED_IDENTITY_FIELDS),
            "variant_overridable_fields": list(VARIANT_OVERRIDABLE_FIELDS),
            "notes": [
                "equivalence comparison requires all required identity fields to match",
                "declared variant comparison may only differ in source_tree_hash and"
                " build_context_ids and must bind to this plan",
                "missing values stay null and zero denominators become N/A",
            ],
        },
        "inputs": {
            "identity": {
                "path": identity_path.resolve().as_posix(),
                "sha256": sha256_file(identity_path),
            }
        },
    }
    plan["plan_id"] = (
        "ape-"
        + content_sha256({k: v for k, v in plan.items() if k not in ("plan_id", "generated_at")})[
            :16
        ]
    )
    write_json_atomic(output, plan)
    return plan


# ---------------------------------------------------------------------------
# Record command
# ---------------------------------------------------------------------------


def _parse_projection(spec: str) -> Tuple[str, str]:
    if "=" not in spec:
        raise PlanEvaluationError("invalid_input", f"projection lacks 'name=path': {spec!r}")
    name, path = spec.split("=", 1)
    name = name.strip()
    if not name:
        raise PlanEvaluationError("invalid_input", "projection name is empty")
    return name, path.strip()


def build_run_record(
    *,
    identity_path: Path,
    mode: str,
    label: str,
    plan_path: Optional[Path],
    variant_id: Optional[str],
    report_path: Optional[Path],
    usage_ledger_path: Optional[Path],
    projection_specs: Sequence[str],
    run_status_override: Optional[str],
    status_note: str,
    wall_seconds: Optional[float],
    end_to_end_wall_seconds: Optional[float],
    output: Path,
) -> Dict[str, Any]:
    declared = load_identity_file(identity_path)
    missing = identity_missing_fields(declared)
    if missing:
        raise PlanEvaluationError(
            "identity_incomplete",
            "declared identity is missing required fields",
            {"missing_fields": missing},
        )

    plan = None
    if plan_path is not None:
        try:
            plan = load_json(plan_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise PlanEvaluationError("invalid_input", f"cannot read plan: {exc}") from exc
        if plan.get("schema_version") != PLAN_SCHEMA_VERSION:
            raise PlanEvaluationError("invalid_input", "plan schema version mismatch")
        if not variant_id:
            raise PlanEvaluationError(
                "invalid_input", "--variant-id is required when binding to a plan"
            )
        variants = {
            v.get("variant_id"): v for v in plan.get("variants", []) if isinstance(v, Mapping)
        }
        if variant_id not in variants:
            raise PlanEvaluationError(
                "invalid_input", f"variant id not declared in plan: {variant_id}"
            )
        if mode not in (plan.get("modes") or []):
            raise PlanEvaluationError("invalid_input", f"mode not declared in plan: {mode}")
        expected = _variant_expected_identity(plan.get("identity") or {}, variants[variant_id])
        for field in REQUIRED_IDENTITY_FIELDS:
            expected_value = expected.get(field)
            declared_value = declared.get(field)
            if variant_id != "baseline" and field in VARIANT_OVERRIDABLE_FIELDS:
                # The declared value must still equal the plan-declared
                # variant expectation for overridable fields.
                if expected_value not in (None, "", [], {}) and expected_value != declared_value:
                    raise PlanEvaluationError(
                        "plan_identity_mismatch",
                        f"declared identity {field} does not match plan variant {variant_id}",
                        {
                            "field": field,
                            "plan_expected": canonical_json(expected_value),
                            "declared": canonical_json(declared_value),
                        },
                    )
                continue
            if expected_value not in (None, "", [], {}) and expected_value != declared_value:
                raise PlanEvaluationError(
                    "plan_identity_mismatch",
                    f"declared identity {field} does not match plan variant {variant_id}",
                    {
                        "field": field,
                        "plan_expected": canonical_json(expected_value),
                        "declared": canonical_json(declared_value),
                    },
                )

    report: Optional[Dict[str, Any]] = None
    report_input: Optional[Dict[str, Any]] = None
    if report_path is not None:
        if not report_path.is_file():
            # A run whose report never landed is preserved as an explicit
            # missing_report observation; its counts stay null, never zero.
            report_input = {
                "path": report_path.resolve().as_posix(),
                "sha256": None,
                "missing": True,
                "format": None,
            }
        else:
            # The official reader decodes ``zscope.shared-json.v1``
            # envelopes with the production validation and returns the
            # logical report; legacy plain JSON passes through.  The
            # frozen SHA below still covers the raw stored bytes.
            report, report_format = load_logical_report(report_path)
            if not isinstance(report, Mapping):
                raise PlanEvaluationError("invalid_input", "report is not a JSON object")
            forbidden = find_forbidden_artifact_keys(report)
            if forbidden:
                raise PlanEvaluationError(
                    "answer_leak_detected",
                    "report contains truth/scoring fields; refusing to record",
                    {"forbidden_keys": forbidden[:20]},
                )
            report_input = {
                "path": report_path.resolve().as_posix(),
                "sha256": sha256_file(report_path),
                "missing": False,
                "format": report_format,
            }

    extracted = identity_from_report(report) if report is not None else {}
    merged, conflicts = merge_identity(declared, extracted)
    if conflicts:
        raise PlanEvaluationError(
            "identity_mismatch",
            "report run manifest contradicts the declared identity",
            {"conflicts": conflicts},
        )

    usage_ledger: Optional[Dict[str, Any]] = None
    usage_input: Optional[Dict[str, Any]] = None
    if usage_ledger_path is not None:
        if not usage_ledger_path.is_file():
            raise PlanEvaluationError(
                "invalid_input", f"usage ledger does not exist: {usage_ledger_path}"
            )
        usage_ledger = aggregate_usage_ledger(usage_ledger_path)
        usage_input = {
            "path": usage_ledger_path.resolve().as_posix(),
            "sha256": sha256_file(usage_ledger_path),
        }

    projections: Dict[str, Any] = {}
    projection_inputs: Dict[str, Any] = {}
    for spec in projection_specs:
        name, path_text = _parse_projection(spec)
        projection_path = Path(path_text)
        if not projection_path.is_file():
            raise PlanEvaluationError(
                "invalid_input", f"projection file does not exist: {projection_path}"
            )
        content, projection_format = load_logical_report(projection_path)
        forbidden = find_forbidden_artifact_keys(content)
        if forbidden:
            raise PlanEvaluationError(
                "answer_leak_detected",
                f"projection {name} contains truth/scoring fields; refusing to record",
                {"projection": name, "forbidden_keys": forbidden[:20]},
            )
        projections[name] = content
        projection_inputs[name] = {
            "path": projection_path.resolve().as_posix(),
            "sha256": sha256_file(projection_path),
            "format": projection_format,
        }

    if run_status_override and run_status_override not in OPERATOR_RUN_STATUSES:
        raise PlanEvaluationError("invalid_input", f"invalid --run-status: {run_status_override}")

    status: str
    completeness: Optional[str] = None
    scan_outcome: Optional[str] = None
    status_reason: str = status_note
    if run_status_override:
        status = run_status_override
        if report is not None:
            status_reason = status_reason or f"operator_declared_{run_status_override}_with_report"
    elif report is None:
        status = "missing_report"
        status_reason = status_reason or "report_file_missing"
    else:
        completeness = str(report.get("completeness") or "") or None
        scan_outcome = str(report.get("scan_outcome") or "") or None
        if completeness == "complete":
            status = "complete"
        else:
            status = "incomplete"
            status_reason = status_reason or f"completeness:{completeness or 'unknown'}"

    counts = (
        extract_counts(report)
        if report is not None
        else {
            "source": "missing_report",
            "candidate_count": None,
            "confirmed_count": None,
            "with_review_count": None,
            "pending_count": None,
            "ruled_out_count": None,
            "deduplicated_alias_count": None,
            "operational_incomplete_count": None,
            "shadow_observation_count": None,
            "terminal_disposition_counts": {},
            "needs_review_sub_states": {},
            "pending_validation_count": None,
        }
    )
    coverage = extract_coverage(report) if report is not None else None

    report_llm_usage = None
    if report is not None:
        manifest = report.get("run_manifest")
        if isinstance(manifest, Mapping) and isinstance(manifest.get("llm_usage"), Mapping):
            report_llm_usage = dict(manifest["llm_usage"])
    governance = None
    if report is not None and isinstance(report.get("needs_review_governance"), Mapping):
        governance = dict(report["needs_review_governance"])

    resolved_wall = wall_seconds
    if resolved_wall is None and report is not None:
        resolved_wall = extract_report_wall_seconds(report)

    record: Dict[str, Any] = {
        "schema_version": RUN_SCHEMA_VERSION,
        "record_id": "",
        "created_at": _utc_now(),
        "label": label,
        "mode": mode,
        "plan_id": plan.get("plan_id") if plan else None,
        "variant_id": variant_id,
        "identity": merged,
        "identity_binding": {
            "declared_identity": {
                "path": identity_path.resolve().as_posix(),
                "sha256": sha256_file(identity_path),
            },
            "report_manifest": "bound" if extracted.get("_manifest_present") else "absent",
            "report_bound_fields": sorted(
                k
                for k, v in extracted.items()
                if k != "_manifest_present" and v not in (None, "", [], {})
            ),
        },
        "run_status": {
            "status": status,
            "completeness": completeness,
            "scan_outcome": scan_outcome,
            "operator_declared": bool(run_status_override),
            "reason": status_reason,
        },
        "counts": counts,
        "coverage": coverage,
        "governance_projection": governance,
        "resources": {
            "wall_seconds": resolved_wall,
            "end_to_end_wall_seconds": end_to_end_wall_seconds,
            "report_llm_usage": report_llm_usage,
            "usage_ledger": usage_ledger,
        },
        "projections": projections,
        "inputs": {
            "report": report_input,
            "usage_ledger": usage_input,
            "projections": projection_inputs,
            "plan": (
                {
                    "path": plan_path.resolve().as_posix(),
                    "sha256": sha256_file(plan_path),
                }
                if plan_path is not None
                else None
            ),
        },
        "operator_note": status_note,
        "benchmark_scope": "development_only",
        "formal_eligible": False,
        "release_eligible": False,
    }
    record["record_id"] = _expected_record_id(record)
    write_json_atomic(output, record)
    return record


# ---------------------------------------------------------------------------
# Compare command
# ---------------------------------------------------------------------------

COUNT_FIELDS = (
    "candidate_count",
    "confirmed_count",
    "with_review_count",
    "pending_count",
    "ruled_out_count",
    "deduplicated_alias_count",
    "operational_incomplete_count",
    "shadow_observation_count",
)

RESOURCE_SUM_FIELDS = (
    "request_count",
    "successful_calls",
    "denied_requests",
    "failed_or_unknown_calls",
    "retry_count",
    "repair_count",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cached_prompt_tokens",
    "reasoning_tokens",
    "failed_or_denied_token_cost",
    "retry_token_cost",
    "budget_violation_count",
    "tool_call_count",
    "new_fact_count",
    "duration_ms",
)


def _expected_record_id(record: Mapping[str, Any]) -> str:
    """Canonical content digest over the record body (record_id excluded).

    The same computation is used when freezing a record and when loading
    one, so any post-freeze edit of counts, identity, coverage, costs or
    any other body field leaves the stored record_id stale.  This is a
    local content check, not a signature: it detects accidental edits
    and unchanged-ID tampering, and does not turn the artifact into a
    permission or authorization platform.
    """

    body = {key: value for key, value in record.items() if key != "record_id"}
    return "run-" + content_sha256(body)[:16]


def _load_run_record(path: Path) -> Dict[str, Any]:
    try:
        record = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PlanEvaluationError("invalid_input", f"cannot read run record {path}: {exc}") from exc
    if not isinstance(record, Mapping) or record.get("schema_version") != RUN_SCHEMA_VERSION:
        raise PlanEvaluationError("invalid_input", f"not a {RUN_SCHEMA_VERSION} record: {path}")
    record = dict(record)
    stored_id = record.get("record_id")
    if not isinstance(stored_id, str) or not stored_id.startswith("run-"):
        raise PlanEvaluationError(
            "record_integrity",
            "run record is missing a valid record_id",
            {"path": str(path), "stored_record_id": str(stored_id)},
        )
    expected_id = _expected_record_id(record)
    if stored_id != expected_id:
        raise PlanEvaluationError(
            "record_integrity",
            "record_id does not match the canonical content digest; the frozen"
            " record body was modified after freezing",
            {
                "path": str(path),
                "stored_record_id": stored_id,
                "expected_record_id": expected_id,
            },
        )
    return record


def _integrity_recheck(
    records_by_label: Mapping[str, Sequence[Mapping[str, Any]]],
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Re-verify frozen inputs and report-anchored identity at compare time.

    Two independent checks run per record:

    - ``input_hash``: re-hash the frozen report/usage/projection files
      when they still exist; a changed file is a violation.
    - ``identity_vs_bound_report``: for records whose identity was bound
      to a report manifest, re-derive the report-provided identity
      fields from the (hash-verified, unmodified) report file and
      compare them with the record identity.  This anchors the bound
      identity chain to the original report, so swapping identity in the
      frozen JSON fails even if the record_id digest was recomputed.

    Missing files only produce notes; neither check grants runtime
    proof, and declared-only records (no report manifest) keep their
    explicit declared source without being described as measured.
    """

    violations: List[Dict[str, str]] = []
    notes: List[str] = []
    for label, records in records_by_label.items():
        for record in records:
            inputs = record.get("inputs") or {}
            for kind in ("report", "usage_ledger"):
                entry = inputs.get(kind)
                if not isinstance(entry, Mapping) or not entry.get("path"):
                    continue
                path = Path(str(entry["path"]))
                if not path.exists():
                    if entry.get("sha256"):
                        notes.append(f"{label}:{kind}:input_file_missing_after_freeze")
                    continue
                if entry.get("missing"):
                    continue
                try:
                    current = sha256_file(path)
                except OSError:
                    notes.append(f"{label}:{kind}:input_file_unreadable")
                    continue
                if entry.get("sha256") and current != entry["sha256"]:
                    violations.append(
                        {
                            "label": label,
                            "check": "input_hash",
                            "kind": kind,
                            "path": str(entry["path"]),
                            "frozen_sha256": str(entry["sha256"]),
                            "current_sha256": current,
                        }
                    )
            for name, entry in (inputs.get("projections") or {}).items():
                if not isinstance(entry, Mapping):
                    continue
                path = Path(str(entry.get("path") or ""))
                if not path.exists():
                    notes.append(f"{label}:projection:{name}:input_file_missing_after_freeze")
                    continue
                try:
                    current = sha256_file(path)
                except OSError:
                    continue
                if entry.get("sha256") and current != entry["sha256"]:
                    violations.append(
                        {
                            "label": label,
                            "check": "input_hash",
                            "kind": f"projection:{name}",
                            "path": str(entry.get("path")),
                            "frozen_sha256": str(entry.get("sha256")),
                            "current_sha256": current,
                        }
                    )
            report_entry = inputs.get("report")
            if (
                isinstance(report_entry, Mapping)
                and report_entry.get("path")
                and not report_entry.get("missing")
                and report_entry.get("sha256")
                and (record.get("identity_binding") or {}).get("report_manifest") == "bound"
            ):
                report_path = Path(str(report_entry["path"]))
                report_data = None
                if report_path.is_file():
                    try:
                        if sha256_file(report_path) == report_entry["sha256"]:
                            # Hash-verified bytes: decode through the same
                            # official reader used at record time.  A decode
                            # or answer-isolation failure here means the
                            # record does not honestly describe this file,
                            # so it propagates and fails closed.
                            report_data, _report_format = load_logical_report(report_path)
                    except OSError:
                        report_data = None
                if isinstance(report_data, Mapping):
                    extracted = identity_from_report(report_data)
                    for field, report_value in extracted.items():
                        if field == "_manifest_present" or report_value in (None, "", [], {}):
                            continue
                        record_value = (record.get("identity") or {}).get(field)
                        if record_value != report_value:
                            violations.append(
                                {
                                    "label": label,
                                    "check": "identity_vs_bound_report",
                                    "kind": "report",
                                    "field": field,
                                    "record_value": canonical_json(record_value),
                                    "report_value": canonical_json(report_value),
                                    "path": str(report_entry["path"]),
                                }
                            )
    return violations, notes


def _identity_field_results(
    records_by_label: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    variant_mode: bool,
) -> Dict[str, Any]:
    """Compare required identity fields across all records."""

    field_results: Dict[str, Any] = {}
    mismatched: List[str] = []
    missing: List[str] = []
    label_values: Dict[str, Dict[str, Any]] = {}
    empty_markers = {
        canonical_json(None),
        canonical_json(""),
        canonical_json([]),
        canonical_json({}),
    }
    for field in REQUIRED_IDENTITY_FIELDS:
        values: Dict[str, Any] = {}
        for label, records in records_by_label.items():
            per_run = [canonical_json((r.get("identity") or {}).get(field)) for r in records]
            distinct = sorted(set(per_run))
            values[label] = per_run[0] if len(distinct) == 1 else None
            if len(distinct) > 1:
                mismatched.append(f"{label}:{field}")
            label_values.setdefault(label, {})[field] = per_run
        absent = [
            label
            for label, per_label in label_values.items()
            if any(value in empty_markers for value in per_label[field])
        ]
        field_results[field] = {"values": values, "labels_missing_field": absent}
        if absent:
            missing.append(field)
        elif len(set(values.values())) > 1:
            if not (variant_mode and field in VARIANT_OVERRIDABLE_FIELDS):
                mismatched.append(field)
    if missing:
        status = "untested_identity_incomplete"
    elif mismatched:
        status = "rejected_identity_mismatch"
    else:
        status = "matched"
    return {
        "required_fields": list(REQUIRED_IDENTITY_FIELDS),
        "field_results": field_results,
        "mismatched_fields": sorted(set(mismatched)),
        "missing_fields": sorted(set(missing)),
        "status": status,
    }


def _variant_mode_binding(
    records_by_label: Mapping[str, Sequence[Mapping[str, Any]]], plan: Mapping[str, Any]
) -> Dict[str, Any]:
    """Validate declared-variant comparison binding against the plan."""

    variants = {
        v.get("variant_id"): v
        for v in plan.get("variants", [])
        if isinstance(v, Mapping) and v.get("variant_id")
    }
    label_variants: Dict[str, Any] = {}
    problems: List[str] = []
    for label, records in records_by_label.items():
        ids = {(r.get("variant_id") or "") for r in records}
        if len(ids) != 1 or not ids.pop():
            problems.append(f"{label}:records_do_not_share_one_variant_id")
            continue
        variant_id = records[0].get("variant_id")
        if records[0].get("plan_id") != plan.get("plan_id"):
            problems.append(f"{label}:record_not_bound_to_plan")
        variant = variants.get(variant_id)
        if variant is None:
            problems.append(f"{label}:variant_not_declared_in_plan")
            continue
        label_variants[label] = variant
    if problems:
        return {"status": "untested_variant_binding_invalid", "problems": problems}
    baseline_labels = [
        label for label, variant in label_variants.items() if variant.get("kind") == "baseline"
    ]
    if not baseline_labels:
        return {
            "status": "untested_variant_binding_invalid",
            "problems": ["no_baseline_variant_label"],
        }
    for label, variant in label_variants.items():
        if variant.get("kind") == "source_change":
            expected_hash = variant.get("expected_source_tree_hash")
            actual = records_by_label[label][0].get("identity", {}).get("source_tree_hash")
            if expected_hash and actual and expected_hash != actual:
                return {
                    "status": "untested_variant_binding_invalid",
                    "problems": [f"{label}:source_tree_hash_differs_from_declared_variant"],
                }
    return {
        "status": "bound",
        "label_variants": {
            label: {
                "variant_id": variant.get("variant_id"),
                "kind": variant.get("kind"),
                "declared_change": variant.get("declared_change"),
                "note": variant.get("note", ""),
            }
            for label, variant in label_variants.items()
        },
    }


def _aggregate_label_counts(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    per_field: Dict[str, Any] = {}
    for field in COUNT_FIELDS:
        values = [_int_or_none((r.get("counts") or {}).get(field)) for r in records]
        per_field[field] = {
            "values": values,
            "median": _median([v for v in values]),  # type: ignore[arg-type]
            "min": min([v for v in values if v is not None], default=None),
            "max": max([v for v in values if v is not None], default=None),
            "missing_runs": [i for i, v in enumerate(values) if v is None],
            "sample_size": len(records),
        }
    return per_field


def _aggregate_label_resources(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    walls = [r.get("resources", {}).get("wall_seconds") for r in records]
    end_to_end = [r.get("resources", {}).get("end_to_end_wall_seconds") for r in records]
    ledger_sums: Dict[str, Any] = {field: 0 for field in RESOURCE_SUM_FIELDS}
    ledger_events: List[int] = []
    ledger_present = False
    for record in records:
        ledger = (record.get("resources") or {}).get("usage_ledger")
        if not isinstance(ledger, Mapping):
            continue
        ledger_present = True
        ledger_events.append(_int_or_none(ledger.get("event_count")) or 0)
        aggregates = ledger.get("aggregates") or {}
        for field in RESOURCE_SUM_FIELDS:
            ledger_sums[field] += _int_or_none(aggregates.get(field)) or 0
    return {
        "wall_seconds": {
            "values": walls,
            "median": _median([w for w in walls if w is not None]),  # type: ignore[arg-type]
        },
        "end_to_end_wall_seconds": {
            "values": end_to_end,
            "median": _median([w for w in end_to_end if w is not None]),  # type: ignore[arg-type]
        },
        "usage_ledger": {
            "present": ledger_present,
            "event_counts": ledger_events,
            **ledger_sums,
        },
    }


def _confirmation_rate(counts: Mapping[str, Any]) -> Dict[str, Any]:
    candidate = _int_or_none(counts.get("candidate_count"))
    confirmed = _int_or_none(counts.get("confirmed_count"))
    if candidate is None or confirmed is None:
        return {
            "numerator": confirmed,
            "denominator": candidate,
            "value": None,
            "status": "missing_input",
        }
    if candidate == 0:
        return {
            "numerator": confirmed,
            "denominator": candidate,
            "value": None,
            "status": "na_zero_denominator",
        }
    return {
        "numerator": confirmed,
        "denominator": candidate,
        "value": round(confirmed / candidate, 6),
        "status": "computed",
    }


def build_comparison(
    *,
    run_specs: Sequence[str],
    baseline_label: Optional[str],
    variant_comparison: bool,
    plan_path: Optional[Path],
    output: Path,
) -> Dict[str, Any]:
    if len(run_specs) < 2:
        raise PlanEvaluationError("invalid_input", "compare needs at least two --run entries")
    records_by_label: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for spec in run_specs:
        if "=" not in spec:
            raise PlanEvaluationError("invalid_input", f"--run expects label=path: {spec!r}")
        label, path_text = spec.split("=", 1)
        label = label.strip()
        if not label:
            raise PlanEvaluationError("invalid_input", "--run label is empty")
        record = _load_run_record(Path(path_text.strip()))
        if label not in records_by_label:
            records_by_label[label] = []
            order.append(label)
        records_by_label[label].append(record)
    baseline = baseline_label or order[0]
    if baseline not in records_by_label:
        raise PlanEvaluationError("invalid_input", f"baseline label not among runs: {baseline}")

    plan: Optional[Dict[str, Any]] = None
    if plan_path is not None:
        try:
            plan = load_json(plan_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise PlanEvaluationError("invalid_input", f"cannot read plan: {exc}") from exc
        if plan.get("schema_version") != PLAN_SCHEMA_VERSION:
            raise PlanEvaluationError("invalid_input", "plan schema version mismatch")

    integrity_violations, integrity_notes = _integrity_recheck(records_by_label)

    variant_binding: Optional[Dict[str, Any]] = None
    if variant_comparison:
        if plan is None:
            raise PlanEvaluationError(
                "invalid_input",
                "declared variant comparison requires --plan with declared changes",
            )
        variant_binding = _variant_mode_binding(records_by_label, plan)

    identity_check = _identity_field_results(records_by_label, variant_mode=variant_comparison)

    comparison_status: str
    if any(v.get("check") == "identity_vs_bound_report" for v in integrity_violations):
        comparison_status = "untested_record_integrity"
    elif integrity_violations:
        comparison_status = "untested_input_modified_after_freeze"
    elif identity_check["status"] != "matched":
        comparison_status = identity_check["status"]
    elif variant_comparison and variant_binding and variant_binding["status"] != "bound":
        comparison_status = variant_binding["status"]
    else:
        comparison_status = "compared"

    identity_binding_sources: Dict[str, Any] = {}
    for label in order:
        records = records_by_label[label]
        bound = sum(
            1
            for record in records
            if (record.get("identity_binding") or {}).get("report_manifest") == "bound"
        )
        if bound == len(records):
            source = "report_manifest"
        elif bound == 0:
            source = "declared_only"
        else:
            source = "mixed"
        identity_binding_sources[label] = {
            "report_manifest_bound_records": bound,
            "declared_only_records": len(records) - bound,
            "source": source,
        }
    all_report_bound = all(
        info["source"] == "report_manifest" for info in identity_binding_sources.values()
    )

    runs_summary: Dict[str, Any] = {}
    for label in order:
        records = records_by_label[label]
        runs_summary[label] = {
            "sample_size": len(records),
            "modes": [r.get("mode") for r in records],
            "run_statuses": [r.get("run_status", {}).get("status") for r in records],
            "all_runs_complete": all(
                r.get("run_status", {}).get("status") == "complete" for r in records
            ),
            "record_ids": [r.get("record_id") for r in records],
        }

    counts_comparison: Dict[str, Any] = {}
    resource_comparison: Dict[str, Any] = {}
    derived: Dict[str, Any] = {}
    differences: List[Dict[str, Any]] = []
    if comparison_status == "compared":
        baseline_counts = _aggregate_label_counts(records_by_label[baseline])
        baseline_resources = _aggregate_label_resources(records_by_label[baseline])
        for field in COUNT_FIELDS:
            entry: Dict[str, Any] = {}
            for label in order:
                entry[label] = _aggregate_label_counts(records_by_label[label])[field]["median"]
            entry["baseline_value"] = baseline_counts[field]["median"]
            entry["difference_vs_baseline"] = any(
                entry[label] != entry["baseline_value"] for label in order if label != baseline
            )
            counts_comparison[field] = entry
            if entry["difference_vs_baseline"]:
                differences.append(
                    {
                        "field": field,
                        "values": {label: entry[label] for label in order},
                        "note": "explicit_count_difference",
                    }
                )
        coverage_entry: Dict[str, Any] = {}
        for label in order:
            values = [canonical_json(r.get("coverage")) for r in records_by_label[label]]
            coverage_entry[label] = json.loads(values[0]) if len(set(values)) == 1 else None
        coverage_entry["baseline_value"] = coverage_entry[baseline]
        coverage_entry["difference_vs_baseline"] = any(
            coverage_entry[label] != coverage_entry["baseline_value"]
            for label in order
            if label != baseline
        )
        counts_comparison["coverage"] = coverage_entry
        if coverage_entry["difference_vs_baseline"]:
            differences.append(
                {
                    "field": "coverage",
                    "values": {label: coverage_entry[label] for label in order},
                    "note": "explicit_coverage_difference",
                }
            )

        for label in order:
            resource_comparison[label] = _aggregate_label_resources(records_by_label[label])
        resource_comparison["baseline_label"] = baseline
        for label in order:
            if label == baseline:
                continue
            base_ledger = resource_comparison[baseline]["usage_ledger"]
            side_ledger = resource_comparison[label]["usage_ledger"]
            for field in RESOURCE_SUM_FIELDS:
                if base_ledger.get(field) != side_ledger.get(field):
                    differences.append(
                        {
                            "field": f"resources.usage_ledger.{field}",
                            "values": {
                                baseline: base_ledger.get(field),
                                label: side_ledger.get(field),
                            },
                            "note": "explicit_resource_difference",
                        }
                    )
            base_wall = resource_comparison[baseline]["wall_seconds"]["median"]
            side_wall = resource_comparison[label]["wall_seconds"]["median"]
            if base_wall != side_wall:
                differences.append(
                    {
                        "field": "resources.wall_seconds",
                        "values": {baseline: base_wall, label: side_wall},
                        "note": "explicit_time_difference",
                    }
                )

        for label in order:
            medians = _aggregate_label_counts(records_by_label[label])
            counts_median_view = {field: medians[field]["median"] for field in COUNT_FIELDS}
            derived[label] = {
                "confirmation_rate": _confirmation_rate(counts_median_view),
            }
    else:
        counts_comparison = {"not_computed_reason": comparison_status}
        resource_comparison = {"not_computed_reason": comparison_status}
        derived = {"not_computed_reason": comparison_status}

    caveats: List[str] = [
        "missing values are preserved as null and never treated as zero",
        "zero denominators are reported as N/A and never as 100%",
        "failed, cancelled and missing runs keep their costs and are never dropped",
        "development-only output; formal gates and scorers are unchanged",
    ]
    if all(info["sample_size"] == 1 for info in runs_summary.values()):
        caveats.append(
            "every side has a single run; single-run samples are not a stable advantage claim"
        )
    if variant_comparison:
        caveats.append(
            "declared variant comparison spans different source identities by design;"
            " it is not a same-version quality equivalence claim"
        )
    if comparison_status == "compared" and not all_report_bound:
        not_bound = sorted(
            label
            for label, info in identity_binding_sources.items()
            if info["source"] != "report_manifest"
        )
        caveats.append(
            "identity for label(s) "
            + ", ".join(not_bound)
            + " is not report-manifest bound for every run; a declared-only"
            " identity source is an explicit operator declaration, not a"
            " measured same-version binding"
        )

    comparison: Dict[str, Any] = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "comparison_id": "cmp-"
        + content_sha256(
            {
                "runs": {
                    label: [r.get("record_id") for r in records]
                    for label, records in records_by_label.items()
                },
                "variant_comparison": variant_comparison,
            }
        )[:16],
        "created_at": _utc_now(),
        "mode": "declared_variant_diff" if variant_comparison else "equivalence",
        "benchmark_scope": "development_only",
        "formal_eligible": False,
        "release_eligible": False,
        "identity_bound_same_version": (
            comparison_status == "compared" and not variant_comparison and all_report_bound
        ),
        "identity_binding_sources": identity_binding_sources,
        "baseline_label": baseline,
        "comparison_status": comparison_status,
        "integrity": {
            "violations": integrity_violations,
            "notes": integrity_notes,
        },
        "identity_check": identity_check,
        "variant_binding": variant_binding,
        "runs": runs_summary,
        "counts_comparison": counts_comparison,
        "resource_comparison": resource_comparison,
        "derived_metrics": derived,
        "differences": differences,
        "caveats": caveats,
    }
    write_json_atomic(output, comparison)
    return comparison


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plan_p = sub.add_parser("plan", help="build an answer-free evaluation matrix plan")
    plan_p.add_argument("--identity", required=True, type=Path)
    plan_p.add_argument("--scan-input-root", required=True, type=Path)
    plan_p.add_argument(
        "--variant",
        action="append",
        default=None,
        metavar="SPEC",
        help=(
            "baseline, or id=<id>,kind=source_change,change=<kind>,"
            "source-tree-hash=<sha>[,build-context-ids=a|b][,note=...]"
        ),
    )
    plan_p.add_argument("--mode", action="append", choices=SCAN_MODES, default=None)
    plan_p.add_argument(
        "--scan-command-template",
        default=None,
        help="operator scan command template with optional {variant} and {mode} slots",
    )
    plan_p.add_argument("--preflight-tool", action="append", default=[])
    plan_p.add_argument("--preflight-env", action="append", default=[])
    plan_p.add_argument(
        "--run-preflight",
        action="store_true",
        help="execute local tool/env existence checks (never starts scans)",
    )
    plan_p.add_argument("--output", required=True, type=Path)
    plan_p.set_defaults(func=cmd_plan)

    record_p = sub.add_parser("record", help="freeze one run observation")
    record_p.add_argument("--identity", required=True, type=Path)
    record_p.add_argument("--mode", required=True, choices=SCAN_MODES)
    record_p.add_argument("--label", required=True)
    record_p.add_argument("--plan", type=Path, default=None)
    record_p.add_argument("--variant-id", default=None)
    record_p.add_argument("--report", type=Path, default=None)
    record_p.add_argument("--usage-ledger", type=Path, default=None)
    record_p.add_argument("--projection", action="append", default=[], metavar="NAME=PATH")
    record_p.add_argument("--run-status", choices=list(OPERATOR_RUN_STATUSES), default=None)
    record_p.add_argument("--status-note", default="")
    record_p.add_argument("--wall-seconds", type=float, default=None)
    record_p.add_argument("--end-to-end-wall-seconds", type=float, default=None)
    record_p.add_argument("--output", required=True, type=Path)
    record_p.set_defaults(func=cmd_record)

    compare_p = sub.add_parser("compare", help="compare frozen runs under identity binding")
    compare_p.add_argument("--run", action="append", required=True, metavar="LABEL=PATH")
    compare_p.add_argument("--baseline", default=None)
    compare_p.add_argument(
        "--variant-comparison",
        action="store_true",
        help="compare declared source-change variants; requires --plan",
    )
    compare_p.add_argument("--plan", type=Path, default=None)
    compare_p.add_argument("--output", required=True, type=Path)
    compare_p.set_defaults(func=cmd_compare)
    return parser


def cmd_plan(args: argparse.Namespace) -> int:
    plan = build_plan(
        identity_path=args.identity,
        scan_input_root=args.scan_input_root,
        variant_specs=args.variant or [],
        modes=args.mode or [],
        scan_command_template=args.scan_command_template,
        preflight_tools=args.preflight_tool,
        preflight_env=args.preflight_env,
        run_preflight=args.run_preflight,
        output=args.output,
    )
    print(
        f"plan written: {args.output} (plan_id={plan['plan_id']}, cells={len(plan['matrix'])},"
        f" preflight={plan['preflight']['execution']['status']})"
    )
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    if args.report is None and not args.run_status and not args.status_note:
        raise PlanEvaluationError(
            "invalid_input",
            "nothing to record: pass --report and/or --run-status/--status-note",
        )
    record = build_run_record(
        identity_path=args.identity,
        mode=args.mode,
        label=args.label,
        plan_path=args.plan,
        variant_id=args.variant_id,
        report_path=args.report,
        usage_ledger_path=args.usage_ledger,
        projection_specs=args.projection,
        run_status_override=args.run_status,
        status_note=args.status_note,
        wall_seconds=args.wall_seconds,
        end_to_end_wall_seconds=args.end_to_end_wall_seconds,
        output=args.output,
    )
    print(
        f"record written: {args.output}"
        f" (record_id={record['record_id']}, status={record['run_status']['status']},"
        f" mode={record['mode']})"
    )
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    comparison = build_comparison(
        run_specs=args.run,
        baseline_label=args.baseline,
        variant_comparison=args.variant_comparison,
        plan_path=args.plan,
        output=args.output,
    )
    print(
        f"comparison written: {args.output}"
        f" (status={comparison['comparison_status']},"
        f" differences={len(comparison['differences'])})"
    )
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except PlanEvaluationError as exc:
        details = f" details={canonical_json(exc.details)}" if exc.details else ""
        print(f"error[{exc.code}]: {exc.message}{details}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
