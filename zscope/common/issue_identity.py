"""Issue canonicalization and duplicate merging helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, cast


MAX_CATEGORY_TOKEN_LENGTH = 64
MAX_ISSUE_KEY_PART_LENGTH = 160
ISSUE_KEY_HASH_LENGTH = 12


def issue_build_context_id(issue: Mapping[str, Any]) -> str:
    """Return the explicit compilation scope; absence is never a wildcard."""
    pack = issue.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    return str(issue.get("build_context_id") or pack.get("build_context_id") or "")


def same_build_context(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return issue_build_context_id(left) == issue_build_context_id(right)


def _build_scoped_key(issue: Mapping[str, Any], key: str) -> str:
    scope = issue_build_context_id(issue)
    if not key or not scope:
        return key
    return key + "|build=" + hashlib.sha256(scope.encode("utf-8")).hexdigest()


def _as_dict(value: Any) -> Dict[str, Any]:
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


def _same_defect_site(
    left: Dict[str, Any],
    right: Dict[str, Any],
    tolerance: int = 8,
) -> bool:
    """Return True when two issues point at the same defect site.

    Site-aware dedup guard: a destructive merge must not swallow a distinct
    finding merely because both items share a root-cause token or call path.
    Primary lines within ``tolerance`` lines (the official matcher's own
    tolerance) count as the same site; unknown lines fall back to the
    equivalence decision.
    """
    # Endpoint coordinates are the strongest site identity: when both issues
    # carry source/sink flow keys, the equivalence check has already required
    # their equality, so the endpoints decide the site.
    left_flow = source_sink_location_issue_key(left)
    right_flow = source_sink_location_issue_key(right)
    if left_flow and right_flow:
        return True
    left_file, left_line = parse_issue_location(
        str(left.get("location") or left.get("file") or "")
    )
    right_file, right_line = parse_issue_location(
        str(right.get("location") or right.get("file") or "")
    )
    if left_file and right_file and left_file != right_file:
        return False
    if left_line is not None and right_line is not None:
        return abs(left_line - right_line) <= tolerance
    return True


def deduplicate_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge findings that point at the same root cause.

    A destructive merge additionally requires both issues to sit at the same
    defect site (primary lines within the scorer tolerance).  This prevents a
    distant second truth in the same function from being silently swallowed by
    a shared root-cause token or call path.
    """
    records: Dict[str, Dict[str, Any]] = {}
    occurrence_keys: Dict[str, List[str]] = {}
    merge_cache: Dict[int, Dict[str, Any]] = {}
    for issue in issues:
        normalize_issue_fields(issue)
        source_sink_key = source_sink_location_issue_key(issue)
        key = source_sink_key or canonical_issue_key(issue)
        if issue.get("analysis_scope") == "conditional_source_branch":
            condition_hash = hashlib.sha256(str(issue.get("trigger_condition") or "unknown").encode("utf-8")).hexdigest()[:16]
            key += "|conditional=" + condition_hash
        decision_method = "source_sink_location" if source_sink_key else "canonical_issue_key"
        existing = records.get(key)
        if existing is None:
            issue["dedup_key"] = key
            issue.setdefault("category_family", semantic_category_family(issue.get("category")))
            signature = issue_resource_signature(issue)
            if signature:
                issue.setdefault("resource_signature", signature)
            issue.setdefault("duplicate_sources", [])
            records[key] = issue
            occurrence_keys[key] = [key]
            continue

        # A canonical root may contain several independent occurrences. Search
        # all of them so later copies of the second occurrence do not become
        # extra findings simply because they differ from the first one.
        matched_key = next(
            (
                candidate_key
                for candidate_key in occurrence_keys[key]
                if issues_have_destructive_equivalence(records[candidate_key], issue)
                and _same_defect_site(records[candidate_key], issue)
            ),
            None,
        )
        if matched_key is None:
            occurrence_key = _independent_occurrence_key(issue, key)
            suffix = 1
            unique_key = occurrence_key
            while unique_key in records:
                suffix += 1
                unique_key = f"{occurrence_key}:{suffix}"
            issue["dedup_key"] = unique_key
            issue.setdefault("category_family", semantic_category_family(issue.get("category")))
            signature = issue_resource_signature(issue)
            if signature:
                issue.setdefault("resource_signature", signature)
            issue.setdefault("duplicate_sources", [])
            records[unique_key] = issue
            occurrence_keys[key].append(unique_key)
            continue

        existing = records[matched_key]
        if issue_rank(issue) > issue_rank(existing):
            merge_duplicate_issue(
                issue,
                existing,
                dedup_key=matched_key,
                decision={"method": decision_method, "root_cause_key": key},
                merge_cache=merge_cache,
            )
            issue["dedup_key"] = matched_key
            records[matched_key] = issue
            continue

        merge_duplicate_issue(
            existing,
            issue,
            dedup_key=matched_key,
            decision={"method": decision_method, "root_cause_key": key},
            merge_cache=merge_cache,
        )
    return list(records.values())


def issues_have_destructive_equivalence(
    left: Dict[str, Any],
    right: Dict[str, Any],
) -> bool:
    """Return True only when deleting one occurrence is structurally safe."""

    if not same_build_context(left, right):
        return False

    if "conditional_source_branch" in {left.get("analysis_scope"), right.get("analysis_scope")}:
        if (left.get("analysis_scope"), left.get("trigger_condition")) != (right.get("analysis_scope"), right.get("trigger_condition")):
            return False

    left_internal = _internal_occurrence_identity(left)
    right_internal = _internal_occurrence_identity(right)
    if left_internal and right_internal:
        return left_internal == right_internal

    left_flow = source_sink_location_issue_key(left)
    right_flow = source_sink_location_issue_key(right)
    if left_flow and right_flow:
        return left_flow == right_flow

    left_category = canonical_category(left, flatten_issue_text(left))
    right_category = canonical_category(right, flatten_issue_text(right))
    if not category_families_compatible(left_category, right_category):
        return False

    left_file = issue_file_identity(left)
    right_file = issue_file_identity(right)
    left_function = issue_function_identity(left)
    right_function = issue_function_identity(right)
    if left_file and right_file and left_file != right_file:
        return False
    if left_function and right_function and left_function != right_function:
        return False

    left_resource = issue_resource_signature(left)
    right_resource = issue_resource_signature(right)
    left_sink = issue_sink_signature(left)
    right_sink = issue_sink_signature(right)

    # Two exact detector facts at the same coordinate are the same occurrence
    # even when their human-readable sink summaries differ.  Display IDs are
    # deliberately excluded from this identity.
    left_detector = _detector_occurrence_signature(left)
    right_detector = _detector_occurrence_signature(right)
    left_location_file, left_line = parse_issue_location(
        str(left.get("location") or left.get("file") or "")
    )
    right_location_file, right_line = parse_issue_location(
        str(right.get("location") or right.get("file") or "")
    )
    if (
        left_detector
        and left_detector == right_detector
        and left_location_file
        and right_location_file
        and left_location_file == right_location_file
        and left_line is not None
        and right_line is not None
        and left_line == right_line
    ):
        return True

    left_explicit_resource = _explicit_resource_signature(left)
    right_explicit_resource = _explicit_resource_signature(right)
    if (
        left_explicit_resource
        and right_explicit_resource
        and left_explicit_resource != right_explicit_resource
    ):
        return False

    left_root = _structured_root_cause_token(left)
    right_root = _structured_root_cause_token(right)
    if left_root and right_root and left_root == right_root:
        # A structured root is sufficient unless the evidence names two
        # different concrete sinks.  This prevents broad roots such as
        # "numeric size calculation" from collapsing distinct flows.
        if left_sink and right_sink and left_sink != right_sink:
            return False
        return bool(
            (left_file and right_file and left_file == right_file)
            or (left_function and right_function and left_function == right_function)
        )

    # A concrete object/resource can identify the same lifecycle or race root
    # across nearby cleanup stages.  Canonical-key agreement supplies the
    # structural root; file/function agreement prevents cross-context deletion.
    if left_resource and left_resource == right_resource:
        if left_root and right_root and left_root != right_root:
            return False
        if canonical_issue_key(left) != canonical_issue_key(right):
            return False
        return bool(
            (left_file and right_file and left_file == right_file)
            or (left_function and right_function and left_function == right_function)
        )

    # Legacy candidates without endpoint fields may still carry an exact
    # coordinate and a concrete sink operation.  Exactness is required here;
    # line adjacency and prose similarity are intentionally ignored.
    if (
        left_location_file
        and right_location_file
        and left_location_file == right_location_file
        and left_line is not None
        and right_line is not None
        and left_line == right_line
        and left_sink
        and left_sink == right_sink
    ):
        return True
    if (
        left_location_file
        and right_location_file
        and left_location_file == right_location_file
        and left_line is not None
        and right_line is not None
        and left_line == right_line
        and canonical_issue_key(left) == canonical_issue_key(right)
    ):
        return True
    if left_resource and right_resource and left_resource != right_resource:
        return False

    left_path = issue_call_path_signature(left)
    right_path = issue_call_path_signature(right)
    return bool(
        left_path
        and right_path
        and left_path == right_path
        and (
            (left_sink and left_sink == right_sink)
            or (left_resource and left_resource == right_resource)
        )
    )


def _detector_occurrence_signature(issue: Dict[str, Any]) -> str:
    """Return a detector fact identity that never depends on a display ID."""

    pack = _as_dict(issue.get("evidence_pack"))
    source = normalize_issue_key_part(
        issue.get("candidate_source")
        or issue.get("detector")
        or pack.get("candidate_source")
        or pack.get("detector")
    )
    rule = normalize_issue_key_part(
        issue.get("rule")
        or issue.get("rule_id")
        or issue.get("evidence_checker")
        or pack.get("rule")
        or pack.get("rule_id")
        or pack.get("evidence_checker")
    )
    if not rule:
        return ""
    return "|".join(part for part in (source, rule) if part)


def _explicit_resource_signature(issue: Dict[str, Any]) -> str:
    """Return only caller/detector supplied object identity, never prose inference."""

    for mapping in _identity_mappings(issue):
        explicit = first_issue_value(mapping, *_RESOURCE_IDENTITY_KEYS)
        if explicit:
            return _resource_signature_from_text(explicit) or _concrete_resource_token(explicit)
    return ""


def _internal_occurrence_identity(issue: Dict[str, Any]) -> str:
    pack = _as_dict(issue.get("evidence_pack"))
    validation_cluster_uid = str(
        issue.get("validation_cluster_uid") or pack.get("validation_cluster_uid") or ""
    )
    if validation_cluster_uid:
        return "|".join(("validation_cluster", validation_cluster_uid))
    occurrence_uid = str(issue.get("occurrence_uid") or pack.get("occurrence_uid") or "")
    candidate_uid = str(issue.get("candidate_uid") or pack.get("candidate_uid") or "")
    evidence_hash = str(issue.get("evidence_hash") or pack.get("evidence_hash") or "")
    context_signature = str(issue.get("context_signature") or pack.get("context_signature") or "")
    if occurrence_uid and evidence_hash and context_signature:
        return "|".join(("occurrence", occurrence_uid, evidence_hash, context_signature))
    if candidate_uid and evidence_hash and context_signature:
        return "|".join(("candidate", candidate_uid, evidence_hash, context_signature))
    return ""


def _independent_occurrence_key(issue: Dict[str, Any], base_key: str) -> str:
    file_path, line = parse_issue_location(str(issue.get("location") or issue.get("file") or ""))
    payload = {
        "base": base_key,
        "internal": _internal_occurrence_identity(issue),
        "file": file_path,
        "line": line,
        "function": issue.get("function") or issue.get("func_name"),
        "resource": issue_resource_signature(issue),
        "sink": issue_sink_signature(issue),
        "source_location": _issue_endpoint_location(issue, "source"),
        "sink_location": _issue_endpoint_location(issue, "sink"),
        "evidence_hash": issue.get("evidence_hash"),
    }
    digest = hashlib.sha256(repr(sorted(payload.items())).encode("utf-8")).hexdigest()[:16]
    return f"{base_key}|occurrence:{digest}"


def merge_duplicate_issue(
    primary: Dict[str, Any],
    duplicate: Dict[str, Any],
    *,
    dedup_key: str = "",
    decision: Optional[Dict[str, Any]] = None,
    merge_cache: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Attach duplicate evidence to ``primary`` without silently discarding it."""
    if dedup_key:
        primary["dedup_key"] = dedup_key
    primary.setdefault("category_family", semantic_category_family(primary.get("category")))
    signature = issue_resource_signature(primary)
    if signature:
        primary.setdefault("resource_signature", signature)

    duplicate_extra_count = int(duplicate.get("duplicate_count", 0) or 0)
    primary["duplicate_count"] = (
        int(primary.get("duplicate_count", 0) or 0) + 1 + duplicate_extra_count
    )

    sources = primary.get("duplicate_sources")
    if not isinstance(sources, list):
        sources = []
        primary["duplicate_sources"] = sources
    source_cache = _dedup_record_cache(
        merge_cache,
        primary,
        "duplicate_sources",
        sources,
    )
    for source in _duplicate_source_records(duplicate):
        _append_unique_record(sources, source, source_cache)

    alternate = primary.get("alternate_evidence")
    if not isinstance(alternate, list):
        alternate = []
        primary["alternate_evidence"] = alternate
    evidence_cache = _dedup_record_cache(
        merge_cache,
        primary,
        "alternate_evidence",
        alternate,
    )
    for evidence in _alternate_evidence_records(duplicate):
        _append_unique_record(alternate, evidence, evidence_cache)

    if decision:
        decisions = primary.get("dedup_decisions")
        if not isinstance(decisions, list):
            decisions = []
            primary["dedup_decisions"] = decisions
        compact_decision = {
            key: value for key, value in decision.items() if value not in (None, "", [], {})
        }
        if compact_decision and compact_decision not in decisions:
            decisions.append(compact_decision)
        primary["dedup_decision"] = compact_decision or primary.get("dedup_decision")
    for field in (
        "occurrence_uids",
        "occurrences",
        "entries",
        "entry_paths",
        "validation_contexts",
        "evidence_hashes",
        "provenance_hashes",
        "alias_occurrence_uids",
    ):
        values = primary.get(field)
        if not isinstance(values, list):
            values = []
            primary[field] = values
        duplicate_values = duplicate.get(field)
        if not isinstance(duplicate_values, list):
            singular = duplicate.get(field[:-1]) if field.endswith("s") else None
            duplicate_values = [singular] if singular not in (None, "") else []
        for value in duplicate_values:
            if value not in values:
                values.append(value)
    if primary.get("occurrence_uids"):
        primary["occurrence_count"] = len(primary["occurrence_uids"])
    if primary.get("entries"):
        primary["entry_count"] = len(primary["entries"])
    return primary


def _dedup_record_cache(
    merge_cache: Optional[Dict[int, Dict[str, Any]]],
    primary: Dict[str, Any],
    field: str,
    records: List[Dict[str, Any]],
) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    """Build a collision-safe membership index for one merge accumulator.

    Final-report aggregation can merge the same candidate from dozens of
    entries.  Repeated ``record not in list`` checks compare increasingly
    large nested evidence dictionaries and make that path quadratic.  The
    caller-owned cache keeps the public issue schema unchanged while reducing
    membership checks to a hash bucket plus an exact collision check.
    """

    if merge_cache is None:
        return None
    primary_cache = merge_cache.setdefault(id(primary), {})
    cached = primary_cache.get(field)
    if isinstance(cached, dict):
        return cached
    index: Dict[str, List[Dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        index.setdefault(_dedup_record_fingerprint(record), []).append(record)
    primary_cache[field] = index
    return index


def _append_unique_record(
    records: List[Dict[str, Any]],
    record: Dict[str, Any],
    cache: Optional[Dict[str, List[Dict[str, Any]]]],
) -> None:
    if cache is None:
        if record not in records:
            records.append(record)
        return
    fingerprint = _dedup_record_fingerprint(record)
    bucket = cache.setdefault(fingerprint, [])
    if any(existing == record for existing in bucket):
        return
    records.append(record)
    bucket.append(record)


def _dedup_record_fingerprint(record: Dict[str, Any]) -> str:
    payload = json.dumps(
        record,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _duplicate_source_records(issue: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    existing_sources = issue.get("duplicate_sources")
    if isinstance(existing_sources, list):
        for source in existing_sources:
            if isinstance(source, dict):
                records.append(dict(source))
            elif source not in (None, ""):
                records.append({"source": str(source)})
    record = {
        "id": issue.get("id"),
        "candidate_id": issue.get("candidate_id"),
        "candidate_source": issue.get("candidate_source") or issue.get("finding_kind"),
        "function": issue.get("function") or issue.get("func_name"),
        "location": issue.get("location") or issue.get("file"),
        "category": issue.get("category"),
        "dedup_key": issue.get("dedup_key"),
        "resource_signature": issue_resource_signature(issue),
    }
    records.append({key: value for key, value in record.items() if value not in (None, "", [], {})})
    return records


def _alternate_evidence_records(issue: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    existing = issue.get("alternate_evidence")
    if isinstance(existing, list):
        records.extend(item for item in existing if isinstance(item, dict))
    record = {
        "id": issue.get("id"),
        "candidate_id": issue.get("candidate_id"),
        "candidate_source": issue.get("candidate_source") or issue.get("finding_kind"),
        "description": issue.get("description"),
        "root_cause": issue.get("root_cause"),
        "reasoning": issue.get("reasoning"),
        "positive_evidence": issue.get("positive_evidence"),
        "negative_evidence": issue.get("negative_evidence"),
        "source": issue.get("source"),
        "sink": issue.get("sink") or issue.get("sink_function"),
        "call_path": issue.get("call_path"),
        "location": issue.get("location") or issue.get("file"),
    }
    compact = {key: value for key, value in record.items() if value not in (None, "", [], {})}
    if compact:
        records.append(compact)
    return records


def normalize_issue_fields(issue: Dict[str, Any]) -> None:
    """Fill stable report fields derived from free-form finding text."""
    text = flatten_issue_text(issue)
    inferred_category = normalize_issue_category(
        " ".join(
            str(part or "")
            for part in (
                issue.get("category"),
                issue.get("subcategory"),
                issue.get("defect_class"),
                issue.get("vulnerability_type"),
                issue.get("cwe"),
                text,
            )
        )
    )
    structured_category = structured_issue_category(issue)
    normalized_category = (
        semantic_category_override(structured_category, inferred_category)
        or structured_category
        or inferred_category
    )
    current = str(issue.get("category") or "").replace("-", "_").lower()
    generic_categories = {
        "",
        "logic",
        "concurrency",
        "api_contract",
        "memory_safety",
        "resource_leak",
        "backend_signal",
        "use_after_return",
        "use_after_scope",
    }
    if current in generic_categories:
        issue["category"] = normalized_category
    elif len(current) > 48 or re.search(r"\s", current):
        issue["category"] = normalized_category
    elif current not in _KNOWN_CATEGORIES:
        issue["category"] = normalized_category
    if normalized_category == "stack_escape":
        issue.setdefault("cwe", "CWE-562")
        subcategory = str(issue.get("subcategory") or "").replace("-", "_").lower()
        if subcategory in {"", "use_after_scope"}:
            issue["subcategory"] = "stack_escape"
    issue["normalized_category"] = normalized_category


def structured_issue_category(issue: Dict[str, Any]) -> str:
    """Return an explicit category-like field before scanning noisy prose."""
    generic_categories = {
        "",
        "logic",
        "concurrency",
        "api_contract",
        "memory_safety",
        "resource_leak",
        "backend_signal",
        "use_after_return",
        "use_after_scope",
    }
    for key in ("category", "subcategory", "defect_class", "vulnerability_type"):
        raw_value = str(issue.get(key) or "").strip()
        value = raw_value.replace("-", "_").lower().strip()
        if value in _KNOWN_CATEGORIES and value not in generic_categories:
            return value
        token = safe_category_token(value) if not re.search(r"\s", raw_value) else ""
        if token and token not in generic_categories:
            return token
    return ""


def semantic_category_override(structured_category: str, inferred_category: str) -> str:
    """Let narrow root-cause categories outrank broad buckets when prose is explicit."""
    structured = str(structured_category or "").replace("-", "_").lower()
    inferred = str(inferred_category or "").replace("-", "_").lower()
    alias = semantic_category_alias(structured, inferred)
    if alias:
        return alias
    if inferred in {"key_truncation", "log_amplification"} and structured in {
        "race",
        "memory_leak",
        "busy_loop",
        "deadlock",
        "concurrency",
        "resource_leak",
        "memory_safety",
        "",
    }:
        return inferred
    return ""


def semantic_category_alias(structured_category: str, inferred_category: str = "") -> str:
    """Map noisy LLM category labels into canonical families for dedup only."""
    structured = str(structured_category or "").replace("-", "_").lower()
    inferred = str(inferred_category or "").replace("-", "_").lower()
    if structured in _CATEGORY_ALIASES:
        return _CATEGORY_ALIASES[structured]
    if structured in _COMMAND_VALIDATION_ALIASES and inferred == "command_injection":
        return "command_injection"
    if structured in {"resource_lifecycle", "resource_management"} and inferred in {
        "sigpipe_unhandled",
        "stale_fd",
        "fd_leak",
        "memory_leak",
    }:
        return inferred
    return ""


def issue_rank(issue: Dict[str, Any]) -> tuple[int, int, int, int, float, int]:
    status_order = {
        "validated": 4,
        "verified": 4,
        "accepted": 4,
        "true_positive": 4,
        "needs_review": 3,
        "uncertain": 2,
        "pending": 1,
    }
    status = status_order.get(str(issue.get("validation_status") or "").lower(), 0)
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    severity = severity_order.get(
        str(issue.get("impact_level") or issue.get("severity") or "").lower(),
        0,
    )
    try:
        confidence = float(issue.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    precision = issue_precision_rank(issue)
    source_rank = structured_evidence_rank(issue)
    detail_len = len(str(issue.get("reasoning") or issue.get("description") or ""))
    return status, severity, precision, source_rank, confidence, detail_len


def issue_precision_rank(issue: Dict[str, Any]) -> int:
    """Prefer precise sink/category reports over broad static audit candidates."""
    category = (
        str(issue.get("category") or issue.get("subcategory") or issue.get("defect_class") or "")
        .replace("-", "_")
        .lower()
    )
    group = str(issue.get("candidate_priority_group") or "").lower()
    finding_kind = str(issue.get("finding_kind") or "").lower()
    generic_categories = {
        "integer_overflow",
        "protocol_validation",
        "resource_allocation_without_limits",
        "version_filtering",
    }
    exact_categories = {
        "bounds",
        "buffer_overflow",
        "heap_overflow",
        "buffer_overread",
        "buffer_over_read",
        "buffer_underread",
        "buffer_underwrite",
        "buffer_underflow",
        "double_free",
        "fd_leak",
        "invalid_free",
        "memory_leak",
        "signed_unsigned",
        "stack_overflow",
        "use_after_free",
    }
    if (
        finding_kind == "audit_observation"
        or group == "generic_audit"
        or category in generic_categories
    ):
        return 0
    if group == "exact_sink" or category in exact_categories:
        return 3
    if category:
        return 2
    return 1


def structured_evidence_rank(issue: Dict[str, Any]) -> int:
    """Prefer concrete local/backend evidence over long free-form duplicates."""
    pack = _as_dict(issue.get("evidence_pack"))
    source = str(
        issue.get("candidate_source")
        or pack.get("candidate_source")
        or issue.get("finding_kind")
        or ""
    ).lower()
    rule = str(issue.get("rule") or pack.get("rule") or issue.get("id") or "").lower()
    category = (
        str(issue.get("category") or issue.get("subcategory") or issue.get("defect_class") or "")
        .replace("-", "_")
        .lower()
    )
    if source == "clang_ast_cfg" and category in {
        "integer_overflow",
        "protocol_validation",
        "resource_allocation_without_limits",
        "version_filtering",
    }:
        return 0
    if source in {
        "clang_ast_cfg",
        "graph",
        "svf_value_flow",
        "clang_ast_matcher",
        "clang_knowledgedb_call_edges",
    }:
        return 2
    if rule.startswith(("clang_cfg_", "graph_", "svf_")) or "graph_" in rule:
        return 2
    if issue.get("positive_evidence") or pack.get("positive_evidence"):
        return 1
    return 0


def canonical_issue_key(issue: Dict[str, Any]) -> str:
    """Return a stable key based on root cause rather than only line number."""
    text = flatten_issue_text(issue)
    location = str(issue.get("location") or issue.get("file") or "")
    file_path, line = parse_issue_location(location)
    if not file_path:
        match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+)", text)
        file_path = match.group(1).lower() if match else ""
    function = str(issue.get("function") or issue.get("func_name") or "")
    category = canonical_category(issue, text)
    root = _concrete_root_token(root_cause_token(issue, category, text))
    category = report_cluster_category(category, root)
    scope = file_path or function
    if root:
        scoped_root = root_scope_token(issue, category, root)
        parts = (category, scope, scoped_root, root) if scoped_root else (category, scope, root)
        return _build_scoped_key(issue, "|".join(normalize_issue_key_part(part) for part in parts))

    sink = str(issue.get("sink") or issue.get("sink_function") or "")
    if not sink:
        sink_match = re.search(
            r"\b(memcpy|memmove|strcpy|strcat|sprintf|snprintf|printf|system|fopen|"
            r"free|malloc|calloc|realloc|close|munmap|pthread_create|pthread_cond_wait|"
            r"pthread_mutex_lock|pthread_mutex_unlock|pthread_rwlock_wrlock|"
            r"pthread_rwlock_rdlock|pthread_rwlock_unlock|strlen|callback|handler)\b",
            text,
            flags=re.IGNORECASE,
        )
        sink = sink_match.group(1).lower() if sink_match else ""
    return _build_scoped_key(
        issue,
        "|".join(
            normalize_issue_key_part(part)
            for part in (category, scope, str(line or ""), sink or function)
        ),
    )


def source_sink_location_issue_key(issue: Dict[str, Any]) -> str:
    """Return an exact source/sink coordinate key when both endpoints are known."""
    text = flatten_issue_text(issue)
    category = normalize_issue_key_part(canonical_category(issue, text))
    source_location = _issue_endpoint_location(issue, "source")
    sink_location = _issue_endpoint_location(issue, "sink")
    if not (category and source_location and sink_location):
        return ""
    source_file, source_line = source_location
    sink_file, sink_line = sink_location
    if not (source_file and source_line and sink_file and sink_line):
        return ""
    return _build_scoped_key(
        issue,
        "|".join(
            (
                "source-sink-v1",
                category,
                f"{source_file}:{source_line}",
                f"{sink_file}:{sink_line}",
            )
        ),
    )


def _issue_endpoint_location(issue: Dict[str, Any], endpoint: str) -> Optional[Tuple[str, int]]:
    fallback_file = issue_file_identity(issue)
    candidates: List[Any] = [
        issue.get(f"{endpoint}_loc"),
        issue.get(f"{endpoint}_location"),
    ]
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        candidates.extend(
            [
                pack.get(f"{endpoint}_loc"),
                pack.get(f"{endpoint}_location"),
                pack.get(endpoint),
            ]
        )
        candidate_evidence = pack.get("candidate_evidence")
        if isinstance(candidate_evidence, dict):
            candidates.extend(
                [
                    candidate_evidence.get(f"{endpoint}_loc"),
                    candidate_evidence.get(f"{endpoint}_location"),
                    candidate_evidence.get(endpoint),
                ]
            )
    candidates.append(issue.get(endpoint))

    for candidate in candidates:
        location = _coerce_endpoint_location(candidate, fallback_file, endpoint)
        if location:
            return location
    return None


def _coerce_endpoint_location(
    value: Any,
    fallback_file: str,
    endpoint: str,
) -> Optional[Tuple[str, int]]:
    if value in (None, ""):
        return None
    if isinstance(value, dict):
        return _endpoint_location_from_mapping(value, fallback_file, endpoint)
    if isinstance(value, (list, tuple)):
        for item in value[:16]:
            location = _coerce_endpoint_location(item, fallback_file, endpoint)
            if location:
                return location
        return None
    line = _positive_line(value)
    if line is not None and fallback_file:
        return fallback_file, line
    return _endpoint_location_from_text(str(value), fallback_file)


def _endpoint_location_from_mapping(
    value: Dict[str, Any],
    fallback_file: str,
    endpoint: str,
) -> Optional[Tuple[str, int]]:
    for key in (
        f"{endpoint}_loc",
        f"{endpoint}_location",
        "location",
        "loc",
        "reported_location",
    ):
        if key in value:
            location = _coerce_endpoint_location(value.get(key), fallback_file, endpoint)
            if location:
                return location

    file_path = ""
    line: Optional[int] = None
    for key in ("file", "file_path", "filename", "module_path"):
        item = value.get(key)
        location = _endpoint_location_from_text(str(item or ""), "")
        if location:
            return location
        file_path = file_path or _endpoint_file_from_text(str(item or ""))

    for key in (
        "line",
        "line_number",
        "lineNumber",
        "start_line",
        "startLine",
        f"{endpoint}_line",
    ):
        line = _positive_line(value.get(key))
        if line is not None:
            break

    file_path = file_path or fallback_file
    if file_path and line is not None:
        return file_path, line
    return None


def _endpoint_location_from_text(value: str, fallback_file: str) -> Optional[Tuple[str, int]]:
    text = str(value or "").replace("\\", "/").strip()
    if not text:
        return None
    file_path, parsed_line = parse_issue_location(text)
    if parsed_line is not None:
        endpoint_file = normalize_issue_key_part(file_path) if file_path else fallback_file
        if endpoint_file:
            return endpoint_file, parsed_line
    line_match = re.search(r"\bline\s*[:#]?\s*(\d+)\b", text, flags=re.IGNORECASE)
    if not line_match:
        line_match = re.search(r"第\s*(\d+)\s*行", text)
    if line_match and fallback_file:
        line = _positive_line(line_match.group(1))
        if line is not None:
            return fallback_file, line
    return None


def _endpoint_file_from_text(value: str) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if not text:
        return ""
    file_path, _line = parse_issue_location(text)
    if file_path:
        return normalize_issue_key_part(file_path)
    if re.search(r"\.[chp]+$", text, flags=re.IGNORECASE):
        return normalize_issue_key_part(text)
    return ""


def _positive_line(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def report_cluster_category(category: str, root: str) -> str:
    """Return the category bucket used for same-report root-cause merging.

    This is intentionally narrower than user-facing category normalization.  It
    only folds categories when the root token points at the same concrete
    operation/resource, so distinct resources or member fields remain separate.
    """
    normalized = str(category or "").replace("-", "_").lower()
    root_key = str(root or "").replace("-", "_").lower()
    if (
        root_key.startswith("numeric_")
        or any(
            marker in root_key for marker in ("allocation_size", "byte_limit", "size_calculation")
        )
    ) and normalized in {
        "integer_overflow",
        "bounds",
        "size_limit_mismatch",
    }:
        return "numeric_size_mismatch"
    if (
        root_key == "path_check_before_open"
        or ("path" in root_key and "open" in root_key and "check" in root_key)
    ) and normalized in {
        "sigpipe_unhandled",
        "race",
        "path_traversal",
        "toctou",
    }:
        return "path_check_use"
    return normalized


def semantic_category_family(category: Any) -> str:
    """Return a conservative semantic family used for duplicate clustering."""
    normalized = str(category or "").replace("-", "_").lower().strip()
    if not normalized:
        return ""
    for family, categories in _CATEGORY_FAMILIES.items():
        if normalized in categories:
            return family
    return normalized


def category_families_compatible(left_category: Any, right_category: Any) -> bool:
    left = semantic_category_family(left_category)
    right = semantic_category_family(right_category)
    if not left or not right:
        return False
    if left == right:
        return True
    return frozenset({left, right}) in _CATEGORY_FAMILY_COMPATIBLE_PAIRS


def semantic_related_family(category: Any) -> str:
    """Return the broader family used only for possible-duplicate clustering."""
    normalized = str(category or "").replace("-", "_").lower().strip()
    family = semantic_category_family(normalized)
    if normalized in _MEMORY_LIFETIME_RELATED_CATEGORIES or family in {
        "memory_leak",
        "memory_release",
    }:
        return "memory_lifetime"
    return family


def issue_resource_signature(issue: Dict[str, Any]) -> str:
    """Return the concrete object/member identity that constrains semantic merges."""
    if not isinstance(issue, dict):
        return ""
    explicit = first_issue_value(issue, *_RESOURCE_IDENTITY_KEYS)
    if explicit:
        explicit_signature = _resource_signature_from_text(explicit)
        if explicit_signature:
            return explicit_signature
        explicit_token = _concrete_resource_token(explicit)
        if explicit_token:
            return explicit_token

    pack = _as_dict(issue.get("evidence_pack"))
    clang_fact = _as_dict(pack.get("clang_matcher_fact"))
    for key in (
        "resource_symbol",
        "object_symbol",
        "member",
        "field",
        "source_symbol",
        "sink_symbol",
    ):
        token = _concrete_resource_token(clang_fact.get(key))
        if token:
            return token

    text = flatten_issue_text(issue)
    text_signature = _resource_signature_from_text(text)
    if text_signature:
        return text_signature
    category = canonical_category(issue, text)
    root = _concrete_root_token(root_cause_token(issue, category, text))
    if root and _looks_like_resource_root(root):
        return root
    return ""


def _resource_signature_from_text(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    raw_lower = text.lower()
    identifier = r"[A-Za-z_][A-Za-z0-9_]*"
    member_identifier = r"[a-z_][a-z0-9_]*"
    allocator = r"(?:calloc|malloc|realloc|strdup)"

    assignment = re.search(
        rf"(?<![A-Za-z0-9_])({identifier})\s*=\s*(?:\([^)]*\)\s*)?{allocator}\s*\(",
        text,
        flags=re.IGNORECASE,
    )
    if assignment:
        token = _concrete_resource_token(assignment.group(1))
        if token:
            return token

    for member_match in re.finditer(
        rf"(?<![a-z0-9_])({member_identifier}(?:(?:->|\.){member_identifier})+)(?![a-z0-9_])",
        raw_lower,
    ):
        token = member_match.group(1)
        if re.search(r"\.(?:c|h|cc|cpp|hpp)$", token):
            continue
        concrete = _concrete_resource_token(token)
        if concrete:
            return concrete
    global_match = re.search(r"\b(g_[a-z0-9_]{3,})\b", raw_lower)
    if global_match:
        token = _concrete_resource_token(global_match.group(1))
        if token:
            return token
    backtick_match = re.search(r"`([^`]{2,80})`", text)
    if backtick_match:
        token = _concrete_resource_token(backtick_match.group(1).strip())
        if token:
            return token

    described_resources = re.finditer(
        rf"(?<![A-Za-z0-9_])"
        rf"({identifier}(?:(?:->|\.){member_identifier})*)"
        rf"(?![A-Za-z0-9_])"
        r"(?:\s+(?:is|was|remains|gets|becomes)|\s*=)"
        r"[^.;\n]{0,48}\b(?:heap[- ]allocated|allocated|reallocated|freed|released|"
        r"destroyed|resized|leaked)\b",
        text,
        flags=re.IGNORECASE,
    )
    for described_resource in described_resources:
        token = _concrete_resource_token(described_resource.group(1))
        if token and re.search(r"\.(?:c|h|cc|cpp|hpp)$", token):
            continue
        if token:
            return token

    allocation_failure = re.search(
        rf"(?<![A-Za-z0-9_])"
        rf"({identifier}(?:(?:->|\.){member_identifier})*)"
        rf"(?![A-Za-z0-9_])\s+"
        r"(?:allocation|reallocation|initialization|cleanup)\s+"
        r"(?:failure|error|path)\b",
        text,
        flags=re.IGNORECASE,
    )
    if allocation_failure:
        token = _concrete_resource_token(allocation_failure.group(1))
        if token:
            return token

    allocator_ref = re.search(allocator, text, flags=re.IGNORECASE)
    if allocator_ref:
        prefix = text[max(0, allocator_ref.start() - 96) : allocator_ref.start()]
        identifiers = re.findall(rf"(?<![A-Za-z0-9_])({identifier})(?![A-Za-z0-9_])", prefix)
        for name in reversed(identifiers):
            token = _concrete_resource_token(name)
            if token:
                return token

    return ""


def _looks_like_resource_root(value: Any) -> bool:
    token = _concrete_resource_token(value)
    if not token:
        return False
    return bool(
        token.startswith("g_")
        or "->" in token
        or "." in token
        or re.match(r"^[a-z_][a-z0-9_]*$", token)
    )


def _resource_root_for_issue(issue: Dict[str, Any], text: str) -> str:
    explicit = first_issue_value(issue, *_RESOURCE_IDENTITY_KEYS)
    if explicit:
        return _resource_signature_from_text(explicit) or _concrete_resource_token(explicit)

    pack = _as_dict(issue.get("evidence_pack"))
    clang_fact = _as_dict(pack.get("clang_matcher_fact"))
    for key in (
        "resource_symbol",
        "object_symbol",
        "member",
        "field",
        "source_symbol",
        "sink_symbol",
    ):
        token = _concrete_resource_token(clang_fact.get(key))
        if token:
            return token
    return _resource_signature_from_text(text)


def _concrete_resource_token(value: Any) -> str:
    normalized = normalize_issue_key_part(value)
    if not normalized or _is_generic_identity_token(normalized):
        return ""
    if re.search(r"\s", normalized):
        return ""
    if len(normalized) > 96:
        return ""
    if re.match(r"^[a-z_][a-z0-9_]*(?:(?:->|\.)[a-z_][a-z0-9_]*)*$", normalized):
        return normalized
    if re.match(r"^g_[a-z0-9_.]+$", normalized):
        return normalized
    return ""


def _concrete_root_token(value: Any) -> str:
    normalized = normalize_issue_key_part(value)
    if not normalized or _is_generic_identity_token(normalized):
        return ""
    return normalized


def _is_generic_identity_token(value: Any) -> bool:
    normalized = normalize_issue_key_part(value).strip("_")
    return not normalized or normalized in _GENERIC_IDENTITY_TOKENS


def semantic_root_cause_key(issue: Dict[str, Any]) -> str:
    """Return a report-level semantic root key with resource guardrails."""
    normalize_issue_fields(issue)
    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)
    root = _concrete_root_token(root_cause_token(issue, category, text))
    family = semantic_category_family(report_cluster_category(category, root))
    file_path = issue_file_identity(issue, text)
    function = issue_function_identity(issue)
    resource = issue_resource_signature(issue)
    parts = ["semantic-v1", family, file_path, function, root or resource]
    normalized = [
        normalize_issue_key_part(part) for part in parts if normalize_issue_key_part(part)
    ]
    if len(normalized) < 4:
        return ""
    return _build_scoped_key(issue, "|".join(normalized))


def semantic_cluster_key(issue: Dict[str, Any]) -> str:
    """Return a loose key for LLM duplicate adjudication pre-clusters."""
    normalize_issue_fields(issue)
    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)
    family = semantic_category_family(category)
    file_path = issue_file_identity(issue, text)
    function = issue_function_identity(issue)
    if not family or not (file_path or function):
        return ""
    return _build_scoped_key(
        issue,
        "|".join(
            normalize_issue_key_part(part)
            for part in ("semantic-cluster-v1", family, file_path, function)
            if normalize_issue_key_part(part)
        ),
    )


def semantic_related_cluster_keys(issue: Dict[str, Any]) -> List[str]:
    """Return conservative LLM pre-cluster keys, including cross-entry roots.

    The first key keeps the original same-function behavior.  The additional
    key is only concrete when a stable root cause or resource signature exists,
    so it can gather duplicate reports for the same internal defect reached
    through different public entries without broad file/category clustering.
    """
    keys: List[str] = []
    same_context_key = semantic_cluster_key(issue)
    if same_context_key:
        keys.append(same_context_key)

    normalize_issue_fields(issue)
    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)
    family = semantic_related_family(category)
    file_path = issue_file_identity(issue, text)
    root = _concrete_root_token(root_cause_token(issue, category, text))
    resource = issue_resource_signature(issue)
    if not (family and file_path and (root or resource)):
        root_related_key = ""
    else:
        root_related_key = "|".join(
            normalize_issue_key_part(part)
            for part in ("semantic-related-v1", family, file_path, root or resource)
            if normalize_issue_key_part(part)
        )
        if root_related_key and root_related_key not in keys:
            keys.append(root_related_key)

    if family and root and root in _CROSS_FILE_ROOT_DEDUP_ROOTS:
        global_root_key = "|".join(
            normalize_issue_key_part(part)
            for part in ("semantic-global-root-v1", family, root)
            if normalize_issue_key_part(part)
        )
        if global_root_key and global_root_key not in keys:
            keys.append(global_root_key)

    if file_path and _category_allows_cross_context_residual_dedup(category):
        path_sig = issue_call_path_signature(issue)
        if path_sig:
            path_key = "|".join(
                normalize_issue_key_part(part)
                for part in ("semantic-path-v1", family, file_path, path_sig)
                if normalize_issue_key_part(part)
            )
            if path_key and path_key not in keys:
                keys.append(path_key)

        sink_sig = issue_sink_signature(issue)
        if sink_sig:
            sink_key = "|".join(
                normalize_issue_key_part(part)
                for part in ("semantic-sink-v1", family, file_path, sink_sig)
                if normalize_issue_key_part(part)
            )
            if sink_key and sink_key not in keys:
                keys.append(sink_key)
    return [key if key == same_context_key else _build_scoped_key(issue, key) for key in keys]


def issues_same_context(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Return whether two issues are anchored to the same function/path context."""
    if not same_build_context(left, right):
        return False
    left_file = issue_file_identity(left, flatten_issue_text(left))
    right_file = issue_file_identity(right, flatten_issue_text(right))
    left_func = issue_function_identity(left)
    right_func = issue_function_identity(right)
    if (
        left_file
        and right_file
        and left_file == right_file
        and left_func
        and right_func
        and left_func == right_func
    ):
        return True

    left_paths = _call_path_sets(left)
    right_paths = _call_path_sets(right)
    if _call_paths_related(left_paths, right_paths):
        return True

    left_anchors = _function_anchor_set(left)
    right_anchors = _function_anchor_set(right)
    return bool(left_anchors and right_anchors and left_anchors.intersection(right_anchors))


def resource_signatures_conflict(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Return true when both issues name concrete, different resources."""
    left_sig = issue_resource_signature(left)
    right_sig = issue_resource_signature(right)
    if not left_sig or not right_sig:
        return False
    return left_sig != right_sig


def issues_share_file_root_or_resource(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Return whether cross-function issues name the same file-local root/resource."""
    left_text = flatten_issue_text(left)
    right_text = flatten_issue_text(right)
    left_file = issue_file_identity(left, left_text)
    right_file = issue_file_identity(right, right_text)
    if not left_file or not right_file or left_file != right_file:
        return False

    left_category = canonical_category(left, left_text)
    right_category = canonical_category(right, right_text)
    left_root = _concrete_root_token(root_cause_token(left, left_category, left_text))
    right_root = _concrete_root_token(root_cause_token(right, right_category, right_text))
    if left_root and right_root and left_root == right_root:
        return True

    left_resource = issue_resource_signature(left)
    right_resource = issue_resource_signature(right)
    return bool(left_resource and right_resource and left_resource == right_resource)


def issues_share_file_sink_or_call_path(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Return whether cross-function residuals are related by sink/call path."""
    left_text = flatten_issue_text(left)
    right_text = flatten_issue_text(right)
    left_file = issue_file_identity(left, left_text)
    right_file = issue_file_identity(right, right_text)
    if not left_file or not right_file or left_file != right_file:
        return False

    left_category = canonical_category(left, left_text)
    right_category = canonical_category(right, right_text)
    if not (
        _category_allows_cross_context_residual_dedup(left_category)
        and _category_allows_cross_context_residual_dedup(right_category)
    ):
        return False
    if not category_families_compatible(left_category, right_category):
        return False

    if _call_paths_related(_call_path_sets(left), _call_path_sets(right)):
        return True

    left_sink = issue_sink_signature(left)
    right_sink = issue_sink_signature(right)
    return bool(left_sink and right_sink and left_sink == right_sink)


def issues_share_cross_file_root(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Return whether a named root is intentionally allowed to merge across files."""
    left_text = flatten_issue_text(left)
    right_text = flatten_issue_text(right)
    left_category = canonical_category(left, left_text)
    right_category = canonical_category(right, right_text)
    if not category_families_compatible(left_category, right_category):
        return False
    left_root = _concrete_root_token(root_cause_token(left, left_category, left_text))
    right_root = _concrete_root_token(root_cause_token(right, right_category, right_text))
    if not left_root or left_root != right_root or left_root not in _CROSS_FILE_ROOT_DEDUP_ROOTS:
        return False
    left_sink = issue_sink_signature(left)
    right_sink = issue_sink_signature(right)
    if left_sink and right_sink and left_sink == right_sink:
        return True
    return "system" in f"{left_text} {right_text}".lower()


def issues_may_share_root_cause(
    left: Dict[str, Any],
    right: Dict[str, Any],
    *,
    confidence: float = 1.0,
    threshold: float = 0.85,
    require_concrete_root: bool = False,
    allow_cross_function_root: bool = False,
) -> bool:
    """Guardrail for deterministic and LLM-backed duplicate decisions."""
    if not same_build_context(left, right):
        return False
    if confidence < threshold:
        return False
    # A v3 validation cluster is the immutable structured decision identity.
    # Two explicit, different clusters may share text, function, or a broad
    # category but must not be destructively merged without a primary/alias
    # relationship created by the ledger.
    left_cluster = _internal_occurrence_identity(left)
    right_cluster = _internal_occurrence_identity(right)
    if left_cluster and right_cluster and left_cluster != right_cluster:
        return False
    normalize_issue_fields(left)
    normalize_issue_fields(right)
    if not category_families_compatible(left.get("category"), right.get("category")):
        return False
    if resource_signatures_conflict(left, right):
        return False
    same_context = issues_same_context(left, right)
    if not same_context and not (
        allow_cross_function_root
        and (
            issues_share_file_root_or_resource(left, right)
            or issues_share_file_sink_or_call_path(left, right)
            or issues_share_cross_file_root(left, right)
        )
    ):
        return False

    left_text = flatten_issue_text(left)
    right_text = flatten_issue_text(right)
    left_category = canonical_category(left, left_text)
    right_category = canonical_category(right, right_text)
    left_root = _concrete_root_token(root_cause_token(left, left_category, left_text))
    right_root = _concrete_root_token(root_cause_token(right, right_category, right_text))
    left_resource = issue_resource_signature(left)
    right_resource = issue_resource_signature(right)

    if require_concrete_root and left_root and right_root and left_root != right_root:
        return False
    if left_root and right_root and left_root == right_root:
        if require_concrete_root:
            if left_resource and right_resource and left_resource == right_resource:
                return True
            left_sink = issue_sink_signature(left)
            right_sink = issue_sink_signature(right)
            left_flow = source_sink_location_issue_key(left)
            right_flow = source_sink_location_issue_key(right)
            if (
                left_sink
                and right_sink
                and left_sink == right_sink
                and left_flow
                and right_flow
                and left_flow == right_flow
            ):
                return True
            left_path = issue_call_path_signature(left)
            right_path = issue_call_path_signature(right)
            return bool(
                left_sink
                and right_sink
                and left_sink == right_sink
                and left_path
                and right_path
                and left_path == right_path
                and left_resource
                and right_resource
                and left_resource == right_resource
            )
        return True
    if left_resource and right_resource and left_resource == right_resource:
        return True
    if require_concrete_root:
        return False
    if allow_cross_function_root:
        if _call_paths_related(_call_path_sets(left), _call_path_sets(right)):
            return True
        left_sink = issue_sink_signature(left)
        right_sink = issue_sink_signature(right)
        if left_sink and right_sink and left_sink == right_sink:
            return True
    return True


def deduplicate_semantic_issues_programmatic(
    issues: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Apply deterministic semantic duplicate collapse after canonical dedup."""
    base = deduplicate_issues(issues)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for issue in base:
        for key in semantic_related_cluster_keys(issue):
            groups.setdefault(key, []).append(issue)

    merged_ids: Set[int] = set()
    result: List[Dict[str, Any]] = []
    merge_count = 0
    merge_cache: Dict[int, Dict[str, Any]] = {}
    for group_key, group in groups.items():
        group = [issue for issue in group if id(issue) not in merged_ids]
        if len(group) < 2:
            continue
        primaries: List[Dict[str, Any]] = []
        active_primary_ids: Set[int] = set()
        primary_index: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}

        def add_primary(issue: Dict[str, Any]) -> None:
            primaries.append(issue)
            active_primary_ids.add(id(issue))
            for lookup_key in _programmatic_merge_lookup_keys(issue):
                primary_index.setdefault(lookup_key, []).append(issue)

        for issue in group:
            matched = None
            candidates: List[Dict[str, Any]] = []
            seen_candidate_ids: Set[int] = set()
            for lookup_key in _programmatic_merge_lookup_keys(issue):
                for primary in primary_index.get(lookup_key, []):
                    primary_id = id(primary)
                    if primary_id not in active_primary_ids or primary_id in seen_candidate_ids:
                        continue
                    seen_candidate_ids.add(primary_id)
                    candidates.append(primary)
            for primary in candidates:
                if issues_may_share_root_cause(
                    primary,
                    issue,
                    require_concrete_root=True,
                    allow_cross_function_root=True,
                ):
                    matched = primary
                    break
            if matched is None:
                add_primary(issue)
                continue
            root_key = (
                semantic_root_cause_key(matched) or semantic_root_cause_key(issue) or group_key
            )
            if issue_rank(issue) > issue_rank(matched):
                primaries.remove(matched)
                active_primary_ids.discard(id(matched))
                merge_duplicate_issue(
                    issue,
                    matched,
                    dedup_key=root_key,
                    decision={"method": "programmatic_semantic", "root_cause_key": root_key},
                    merge_cache=merge_cache,
                )
                add_primary(issue)
                merged_ids.add(id(matched))
            else:
                merge_duplicate_issue(
                    matched,
                    issue,
                    dedup_key=root_key,
                    decision={"method": "programmatic_semantic", "root_cause_key": root_key},
                    merge_cache=merge_cache,
                )
                merged_ids.add(id(issue))
            merge_count += 1

    for issue in base:
        if id(issue) not in merged_ids:
            result.append(issue)
    return result, {
        "programmatic_merge_count": merge_count,
        "candidate_cluster_count": sum(1 for group in groups.values() if len(group) > 1),
    }


def _programmatic_merge_lookup_keys(
    issue: Dict[str, Any],
) -> List[Tuple[str, ...]]:
    """Index the positive branches of programmatic semantic dedup.

    ``deduplicate_semantic_issues_programmatic`` always calls
    ``issues_may_share_root_cause`` with ``require_concrete_root=True``.
    Under that contract a pair can only pass via a shared concrete resource,
    or via a shared root plus identical sink and source/sink flow.  Indexing
    exactly those sufficient conditions avoids scanning every primary in a
    large generic cluster.  The full predicate still confirms each indexed
    pair, so category, context, and resource-conflict guardrails remain
    authoritative.
    """

    keys: List[Tuple[str, ...]] = []
    resource = issue_resource_signature(issue)
    if resource:
        keys.append(("resource", resource))

    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)
    root = _concrete_root_token(root_cause_token(issue, category, text))
    sink = issue_sink_signature(issue)
    flow = source_sink_location_issue_key(issue)
    if root and sink and flow:
        keys.append(("root_sink_flow", root, sink, flow))
    return keys


def _function_anchor_set(issue: Dict[str, Any]) -> Set[str]:
    anchors: Set[str] = set()
    for key in (
        "function",
        "func_name",
        "entry_function",
        "sink_function",
        "target_function",
        "analyzed_from",
    ):
        value = issue.get(key)
        if value:
            anchors.add(str(value).lower())
    return anchors


def _call_path_sets(issue: Dict[str, Any]) -> Set[Tuple[str, ...]]:
    paths: Set[Tuple[str, ...]] = set()

    def add_path(value: Any) -> None:
        if (
            isinstance(value, list)
            and value
            and all(not isinstance(item, (list, dict)) for item in value)
        ):
            normalized = tuple(str(item).lower() for item in value if str(item).strip())
            if normalized:
                paths.add(normalized)
        elif isinstance(value, list):
            for item in value:
                add_path(item)

    add_path(issue.get("call_path"))
    add_path(issue.get("call_paths"))
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        add_path(pack.get("call_path"))
        add_path(pack.get("call_paths"))
        path = pack.get("path")
        if isinstance(path, dict):
            add_path(path.get("call_path"))
            add_path(path.get("call_paths"))
    return paths


def issue_call_path_signature(issue: Dict[str, Any]) -> str:
    """Return a stable call-path signature for same-report duplicate clustering."""
    paths = _call_path_sets(issue)
    if not paths:
        return ""
    shortest = min(paths, key=lambda path: (len(path), path))
    return "->".join(shortest)


def _call_paths_related(
    left_paths: Set[Tuple[str, ...]],
    right_paths: Set[Tuple[str, ...]],
) -> bool:
    if not left_paths or not right_paths:
        return False
    for left in left_paths:
        for right in right_paths:
            if left == right or _path_contains(left, right) or _path_contains(right, left):
                return True
    return False


def _path_contains(needle: Tuple[str, ...], haystack: Tuple[str, ...]) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    width = len(needle)
    for index in range(0, len(haystack) - width + 1):
        if haystack[index : index + width] == needle:
            return True
    return False


def issue_sink_signature(issue: Dict[str, Any]) -> str:
    """Return the concrete sink/callee operation used for residual dedup."""
    explicit = first_issue_value(
        issue,
        "sink_function",
        "target_function",
        "release_func",
        "sink_symbol",
        "sink",
    )
    if explicit:
        return _normalize_sink_signature(explicit)

    text = flatten_issue_text(issue)
    lower = text.lower()
    operation_match = re.search(
        r"\b(system|popen|execl|execlp|execle|execv|execvp|execve|"
        r"close|fclose|free|safe_free|munmap|pthread_create|"
        r"memcpy|memmove|strcpy|strncpy|snprintf|printf)\s*\(",
        lower,
        flags=re.IGNORECASE,
    )
    if operation_match:
        return normalize_issue_key_part(operation_match.group(1))
    if "descriptor" in lower or re.search(r"\bfd\b", lower):
        return "file_descriptor_lifecycle"
    if "ref_count" in lower or "refcount" in lower or "reference count" in lower:
        return "reference_count_lifecycle"
    return ""


def _normalize_sink_signature(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    function_call = re.search(r"\b([A-Za-z_]\w*)\s*\(", text)
    if function_call:
        return normalize_issue_key_part(function_call.group(1))
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", text):
        return normalize_issue_key_part(text)
    return normalize_issue_key_part(re.sub(r"\s+", " ", text))


def _category_allows_cross_context_residual_dedup(category: Any) -> bool:
    normalized = str(category or "").replace("-", "_").lower().strip()
    if normalized in _CROSS_CONTEXT_RESIDUAL_DEDUP_CATEGORIES:
        return True
    return semantic_related_family(normalized) == "memory_lifetime"


def stable_issue_fingerprint(issue: Dict[str, Any]) -> str:
    """Return a line-insensitive identity for baseline/suppression tracking."""
    if not isinstance(issue, dict):
        return ""
    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)
    file_path = issue_file_identity(issue, text)
    function = issue_function_identity(issue)
    root = root_cause_token(issue, category, text)
    rule = first_issue_value(
        issue,
        "rule",
        "rule_id",
        "evidence_checker",
        "candidate_source",
        "finding_kind",
    )
    source = first_issue_value(issue, "source", "source_function", "acquire_func")
    sink = first_issue_value(issue, "sink", "sink_function", "target_function", "release_func")
    resource = first_issue_value(
        issue,
        "resource",
        "resource_object",
        "affected_object",
        "symbol",
        "variable",
    )
    parts = ["v1", category, file_path, function, root, rule, source, sink, resource]
    normalized = [
        normalize_issue_key_part(part) for part in parts if normalize_issue_key_part(part)
    ]
    # Avoid producing a dangerously broad fingerprint such as only category/file.
    if len(normalized) < 4:
        return ""
    return _build_scoped_key(issue, "|".join(normalized))


def source_context_fingerprint(issue: Dict[str, Any]) -> str:
    """Return a best-effort source-window identity used to narrow baseline matches.

    This fingerprint is intentionally optional.  When source snippets or AST-like
    spans are unavailable, callers should fall back to the broader stable issue
    fingerprint instead of treating the absence as a mismatch.
    """
    if not isinstance(issue, dict):
        return ""
    explicit = first_issue_value(
        issue,
        "source_context_fingerprint",
        "context_fingerprint",
        "source_window_fingerprint",
    )
    if explicit:
        return normalize_issue_key_part(explicit)

    fragments = list(_source_context_fragments(issue))
    if fragments:
        normalized = "\n".join(
            sorted(
                {
                    normalized
                    for normalized in (
                        _normalize_source_context(fragment) for fragment in fragments
                    )
                    if normalized
                }
            )
        )
        if normalized:
            return "srcctx:v1:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    span = _source_span_identity(issue)
    if span:
        return "span:v1:" + hashlib.sha256(span.encode("utf-8")).hexdigest()[:16]
    return ""


def source_context_fingerprints_compatible(
    current_issue: Dict[str, Any],
    baseline_issue: Dict[str, Any],
) -> bool:
    """Return whether optional source-window identities allow a baseline match."""
    if not same_build_context(current_issue, baseline_issue):
        return False
    current = source_context_fingerprint(current_issue)
    baseline = source_context_fingerprint(baseline_issue)
    return not current or not baseline or current == baseline


def ensure_source_context_fingerprint(issue: Dict[str, Any]) -> str:
    """Populate and return the optional source-context fingerprint for persistence."""
    fingerprint = source_context_fingerprint(issue)
    if fingerprint:
        issue.setdefault("source_context_fingerprint", fingerprint)
    return fingerprint


def root_scope_token(issue: Dict[str, Any], category: str, root: str) -> str:
    """Scope semantic roots unless evidence explicitly identifies global state."""
    if not root:
        return ""
    resource_scope = first_issue_value(issue, "resource_scope", "object_scope", "storage_duration")
    if str(resource_scope).lower() in {"global", "static", "process"}:
        return ""
    if root.startswith("g_"):
        return ""
    return issue_function_identity(issue)


def issue_file_identity(issue: Dict[str, Any], text: str = "") -> str:
    """Return a normalized file identity without line number."""
    candidates = [
        issue.get("location"),
        issue.get("file_path"),
        issue.get("file"),
        issue.get("module_path"),
    ]
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        candidates.extend([pack.get("file_path"), pack.get("file"), pack.get("location")])
        path = pack.get("path")
        if isinstance(path, dict):
            candidates.extend([path.get("file_path"), path.get("file"), path.get("location")])

    for value in candidates:
        file_path, _ = parse_issue_location(str(value or ""))
        if file_path:
            return normalize_issue_key_part(file_path)
        raw = str(value or "").replace("\\", "/").strip()
        if re.search(r"\.[chp]+$", raw, flags=re.IGNORECASE):
            return normalize_issue_key_part(raw)

    match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+)", text)
    return normalize_issue_key_part(match.group(1)) if match else ""


def issue_function_identity(issue: Dict[str, Any]) -> str:
    """Prefer the concrete sink/target function for dedup identity."""

    def as_text(value: Any) -> str:
        return str(value or "").strip().lower()

    for key in ("sink_function", "target_function", "function", "func_name"):
        value = as_text(issue.get(key))
        if value:
            return value

    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        for key in ("sink_function", "target_function", "function", "entry_function"):
            value = as_text(pack.get(key))
            if value:
                return value
        path = pack.get("path")
        if isinstance(path, dict):
            for key in ("sink_function", "target_function", "function", "entry_function"):
                value = as_text(path.get(key))
                if value:
                    return value
    return ""


def first_issue_value(issue: Dict[str, Any], *keys: str) -> str:
    """Find an identity-bearing value on the issue or its evidence pack."""
    for key in keys:
        value = issue.get(key)
        if value not in (None, ""):
            return str(value)
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        for key in keys:
            value = pack.get(key)
            if value not in (None, ""):
                return str(value)
        path = pack.get("path")
        if isinstance(path, dict):
            for key in keys:
                value = path.get(key)
                if value not in (None, ""):
                    return str(value)
    return ""


def _source_context_fragments(value: Any, *, depth: int = 0) -> List[str]:
    if depth > 4:
        return []
    if isinstance(value, str):
        return []
    fragments: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text in {
                "code_snippet",
                "context_slice",
                "source_context",
                "source_snippet",
                "reported_snippet",
                "primary_location_snippet",
                "code_excerpt",
            }:
                fragments.extend(_coerce_context_fragment(item))
            elif key_text in {
                "evidence_pack",
                "candidate_evidence",
                "source_path",
                "path",
                "ast_cfg",
                "clang_tooling",
            }:
                fragments.extend(_source_context_fragments(item, depth=depth + 1))
        return fragments
    if isinstance(value, list):
        for item in value[:24]:
            fragments.extend(_source_context_fragments(item, depth=depth + 1))
    return fragments


def _coerce_context_fragment(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        fragments = []
        for key in ("code", "text", "snippet", "source", "line"):
            item = value.get(key)
            if isinstance(item, str):
                fragments.append(item)
        lines = value.get("lines")
        if isinstance(lines, list):
            line_text = []
            for line in lines[:80]:
                if isinstance(line, dict):
                    line_text.append(str(line.get("text") or ""))
                elif isinstance(line, str):
                    line_text.append(line)
            if line_text:
                fragments.append("\n".join(line_text))
        return fragments
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, str)]
    return []


def _normalize_source_context(fragment: str) -> str:
    lines = []
    for line in str(fragment or "").splitlines():
        clean = re.sub(r"^\s*(?:\d+\s*(?:\||:)|\d+\s+)", "", line).strip()
        clean = re.sub(r"\s+", " ", clean)
        if clean:
            lines.append(clean)
    return "\n".join(lines)


def _source_span_identity(issue: Dict[str, Any]) -> str:
    pack = _as_dict(issue.get("evidence_pack"))
    values: List[Any] = [
        issue_file_identity(issue),
        issue_function_identity(issue),
        first_issue_value(issue, "sink", "sink_function", "target_function", "release_func"),
        first_issue_value(issue, "source", "source_function", "acquire_func"),
        first_issue_value(
            issue, "resource", "resource_object", "affected_object", "symbol", "variable"
        ),
    ]
    clang_fact = _as_dict(pack.get("clang_matcher_fact"))
    values.extend(
        [
            clang_fact.get("matcher"),
            clang_fact.get("kind"),
            clang_fact.get("resource_symbol"),
            clang_fact.get("source_symbol"),
            clang_fact.get("sink_symbol"),
        ]
    )
    ast_cfg = _as_dict(pack.get("ast_cfg"))
    events = ast_cfg.get("events")
    if isinstance(events, list):
        for event in events[:5]:
            if isinstance(event, dict):
                values.extend([event.get("kind"), event.get("variable"), event.get("callee")])
    normalized = [
        normalize_issue_key_part(value) for value in values if normalize_issue_key_part(value)
    ]
    if len(normalized) < 3:
        return ""
    return "|".join(normalized)


def canonical_category(issue: Dict[str, Any], text: str = "") -> str:
    """Prefer structured issue category over noisy flattened validation text."""
    structured = structured_issue_category(issue)
    inferred = normalize_issue_category(
        " ".join(
            str(part or "")
            for part in (
                issue.get("category"),
                issue.get("subcategory"),
                issue.get("defect_class"),
                issue.get("vulnerability_type"),
                issue.get("cwe"),
                text,
            )
        )
    )
    return semantic_category_override(structured, inferred) or structured or inferred


_ROOT_CAUSE_KEYS = (
    "root_cause_key",
    "root_cause_signature",
    "cause_signature",
    "semantic_root",
    "protocol_identity",
)


_RULE_ROOT_ALIASES = (
    ("shared_resource_freed_without_refcount_protocol", "shared_resource_refcount_protocol"),
    ("partial_resource_not_released_on_retry_failure", "retry_cleanup_missing"),
    ("parsed_protocol_version_is_ignored", "parsed_protocol_version_ignored"),
    ("raw_fd_revalidated_as_encoded", "raw_fd_reaches_encoded_fd_validator"),
    (
        "protocol_units_length_reaches_copy_without_packet_bound",
        "protocol_length_without_packet_bound",
    ),
    ("global_dynamic_array_resize_without_lock", "unsynchronized_dynamic_array_resize"),
    ("probe_error_branch_can_return_success_status", "error_branch_returns_success"),
    ("stack_address_passed_to_thread", "stack_address_async_escape"),
    ("negative_length_cast_to_size_t", "negative_length_to_unsigned_size"),
    ("unaligned_integer_pointer_cast", "unaligned_integer_access"),
    ("write_without_sigpipe_handling", "write_without_sigpipe_handling"),
    ("unchecked_strchr_result", "unchecked_delimiter_lookup"),
    ("path_check_before_open", "path_check_before_open"),
    ("fixed_byte_limit_mismatch", "numeric_allocation_size_calculation"),
    ("paired_nested_mutex_cleanup_omitted", "embedded_mutex_cleanup_omitted"),
    ("paired_self_referential_traversal_log_amplification", "self_referential_list_link"),
    ("self_referential_list_link", "self_referential_list_link"),
    ("paired_full_key_lookup_truncated_insert", "full_key_lookup_truncated_insert"),
    ("full_key_lookup_truncated_insert", "full_key_lookup_truncated_insert"),
)


def _identity_mappings(issue: Dict[str, Any]) -> List[Dict[str, Any]]:
    mappings: List[Dict[str, Any]] = [issue]
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        mappings.append(pack)
        for key in ("candidate_evidence", "path", "ast_cfg", "clang_matcher_fact"):
            nested = pack.get(key)
            if isinstance(nested, dict):
                mappings.append(nested)
    return mappings


def _structured_root_cause_token(issue: Dict[str, Any]) -> str:
    for mapping in _identity_mappings(issue):
        for key in _ROOT_CAUSE_KEYS:
            value = mapping.get(key)
            if value in (None, "", [], {}):
                continue
            text = str(value).strip().lower()
            token = safe_category_token(text)
            if token and not _is_generic_identity_token(token):
                return token
            if "|" in text:
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
                return f"structured_root_{digest}"
    return ""


def _detector_rule_root(issue: Dict[str, Any]) -> str:
    raw_rule = first_issue_value(issue, "rule", "rule_id", "evidence_checker", "matcher")
    rule = safe_category_token(raw_rule)
    if not rule:
        return ""
    for prefix in (
        "clang_cfg_",
        "clang_ast_",
        "clang_matcher_",
        "graph_",
        "regex_",
        "svf_",
        "rule_",
    ):
        if rule.startswith(prefix):
            rule = rule[len(prefix) :]
            break
    rule = re.sub(r"_[0-9a-f]{8,}$", "", rule)
    for marker, root in _RULE_ROOT_ALIASES:
        if marker in rule:
            return root
    if len(rule.split("_")) >= 3 and rule not in _GENERIC_IDENTITY_TOKENS:
        return rule
    return ""


def _structured_lock_order_root(issue: Dict[str, Any], text: str) -> str:
    lock_tokens: Set[str] = set()
    for mapping in _identity_mappings(issue):
        for key in ("lock_order", "locks", "held_locks", "lockset"):
            value = mapping.get(key)
            items = value if isinstance(value, (list, tuple, set)) else [value]
            for item in items:
                if isinstance(item, dict):
                    item = item.get("lock") or item.get("name") or item.get("object")
                token = safe_category_token(item)
                if token and token not in {"lock", "mutex", "spinlock", "rwlock"}:
                    lock_tokens.add(token)
    if len(lock_tokens) < 2:
        for match in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*" r"(?:_lock|_mutex))\b",
            text,
            flags=re.IGNORECASE,
        ):
            token = safe_category_token(match.group(1))
            if token and token not in {"lock", "mutex", "spinlock", "rwlock"}:
                lock_tokens.add(token)
    if len(lock_tokens) < 2:
        return ""
    joined = "_".join(sorted(lock_tokens))
    if len(joined) > 112:
        joined = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]
    return f"lock_order_{joined}"


def _structured_type_root(issue: Dict[str, Any], text: str) -> str:
    source_type = first_issue_value(issue, "source_type", "actual_type", "from_type")
    target_type = first_issue_value(issue, "target_type", "expected_type", "to_type")
    if not (source_type and target_type):
        match = re.search(
            r"\bexpects?\s+(?:an?\s+)?([A-Za-z_]\w*)"
            r"[^.;\n]{0,80}\b(?:receives?|gets?|passed)\s+(?:an?\s+)?([A-Za-z_]\w*)",
            text,
            flags=re.IGNORECASE,
        )
        if match:
            target_type, source_type = match.group(1), match.group(2)
    source_token = safe_category_token(source_type)
    target_token = safe_category_token(target_type)
    if source_token and target_token and source_token != target_token:
        return f"type_confusion_{source_token}_to_{target_token}"
    return ""


def _async_stack_resource(text: str) -> str:
    if "pthread_create" not in text.lower():
        return ""
    match = re.search(r"\bpthread_create\s*\([^;]*,\s*&([A-Za-z_]\w*)\s*\)", text, re.IGNORECASE)
    if not match:
        match = re.search(r"\b(?:local|stack)\s+([A-Za-z_]\w*)\b", text, re.IGNORECASE)
    return safe_category_token(match.group(1)) if match else ""


def _project_agnostic_root_cause_token(
    issue: Dict[str, Any],
    category: str,
    text: str,
) -> str:
    raw_lower = text.lower()
    lower = raw_lower.replace("_", " ").replace("-", " ")
    compact = re.sub(r"[^a-z0-9]+", "", raw_lower)

    explicit_root = _structured_root_cause_token(issue)
    if explicit_root:
        return explicit_root

    lock_root = _structured_lock_order_root(issue, text)
    if lock_root and category in {"deadlock", "race", "missing_unlock", "held_lock_callback"}:
        return lock_root

    if category == "type_confusion":
        type_root = _structured_type_root(issue, text)
        if type_root:
            return type_root

    resource_categories = {
        "memory_leak",
        "resource_leak",
        "partial_resource_leak",
        "missing_refcount",
        "use_after_free",
        "double_free",
        "invalid_free",
        "race",
        "dynamic_array_race",
        "shared_state_race",
    }
    if category in resource_categories:
        resource = _resource_root_for_issue(issue, text)
        if resource:
            return resource

    rule_root = _detector_rule_root(issue)
    if rule_root:
        return rule_root

    stack_resource = _async_stack_resource(text)
    if stack_resource and category == "stack_escape":
        return f"stack_address_async_escape_{stack_resource}"

    if (
        category == "signed_unsigned"
        and ("size_t" in raw_lower or "unsigned" in lower or "size max" in lower)
        and (
            "recv" in lower
            or "read" in lower
            or "signed length" in lower
            or "signed return" in lower
        )
    ):
        return "negative_length_to_unsigned_size"
    if ("dynamic array" in lower or "array resize" in lower or "old storage" in lower) and (
        "without a lock" in lower or "without synchronization" in lower or "race" in lower
    ):
        return "unsynchronized_dynamic_array_resize"
    if ("error branch" in lower or "probe failure" in lower) and (
        "return success" in lower
        or "returns ret" in lower
        or "returns the transport status" in lower
    ):
        return "error_branch_returns_success"
    if (
        "path" in lower
        and ("fopen" in lower or "open(" in raw_lower)
        and ("checked separately" in lower or "check before" in lower or "time of check" in lower)
    ):
        return "path_check_before_open"
    if (
        ("ref_count" in raw_lower or "refcount" in lower or "reference count" in lower)
        and ("free" in lower or "released" in lower)
        and ("shared" in lower or "linked" in lower or "resource" in lower)
    ):
        return "shared_resource_refcount_protocol"
    if "retry" in lower and (
        "leak" in lower or "not released" in lower or "missing cleanup" in lower
    ):
        return "retry_cleanup_missing"
    if (
        "encoded fd" in lower
        and "raw fd" in lower
        and ("check value" in lower or "validate" in lower)
    ):
        return "raw_fd_reaches_encoded_fd_validator"
    if (
        "strchr" in lower
        and category == "null_pointer_dereference"
        and ("unchecked" in lower or "null" in lower or "delimiter" in lower)
    ):
        return "unchecked_delimiter_lookup"
    if "pthread_mutex_init" in lower and (
        "without destroy" in lower or "cleanup omitted" in lower or "not destroyed" in lower
    ):
        return "embedded_mutex_cleanup_omitted"
    if "self referential" in lower and ("list" in lower or "link" in lower):
        return "self_referential_list_link"
    if (
        "key truncation" in lower
        or "truncated key" in lower
        or ("full key" in lower and ("strncpy" in lower or "bounded" in lower))
    ):
        return "full_key_lookup_truncated_insert"
    if "active tasks" in lower and ("destroy" in lower or "free" in lower):
        return "pool_destroyed_with_active_tasks"
    if (
        "registration" in lower
        and ("ops" in lower or "slot" in lower)
        and ("race" in lower or "check then act" in lower)
    ):
        return "operation_registration_check_then_act"
    if "hash node" in lower and ("allocator" in lower or "alloc free" in lower):
        return "hash_node_allocator_pairing"
    if ("ftok" in lower or "key generation" in lower) and ("path" in lower or "collision" in lower):
        return "shared_key_generation_collision"
    if "value+1" in compact and category == "invalid_free":
        return "interior_pointer_free"
    if "topic[sizeof" in compact and category in {"off_by_one", "bounds"}:
        return "sizeof_used_as_array_index"
    if "vla" in lower and category in {"stack_overflow", "bounds"}:
        return "unbounded_variable_length_array"
    if "pthread_cond_wait" in lower and category in {"lost_wakeup", "race"}:
        return "condition_wait_protocol"
    if category == "format_string" and "printf" in lower:
        return "printf_format_string"

    return ""


def root_cause_token(issue: Dict[str, Any], category: str, text: str) -> str:
    """Return a stable root derived from structural, project-agnostic evidence."""
    return _project_agnostic_root_cause_token(issue, category, text)


def normalize_issue_category(value: str) -> str:
    text = value.replace("_", " ").replace("-", " ").lower()
    compact = re.sub(r"\s+", "", text)
    stack_terms = (
        "stack escape",
        "stack address",
        "stack memory escape",
        "use after return",
        "use after scope",
        "useafterscope",
        "return stack",
        "栈地址逃逸",
        "栈内存逃逸",
        "栈指针",
        "cwe-562",
    )
    if any(term in text or term in compact for term in stack_terms):
        return "stack_escape"
    if ("pthread_create" in text or "pthread create" in text) and any(
        term in text or term in compact
        for term in ("stack", "local address", "栈", "&job", "&ctx", "&arg")
    ):
        return "stack_escape"
    groups = {
        "format_string": ("format string", "格式化字符串", "cwe-134"),
        "command_injection": (
            "command injection",
            "shell injection",
            "命令注入",
            "system(",
            "cwe-78",
        ),
        "double_checked_locking": ("double checked locking", "double checked", "双重检查"),
        "signed_unsigned": (
            "signed unsigned",
            "negative length",
            "size_max",
            "sizemax",
            "有符号",
            "无符号",
            "cwe-195",
        ),
        "off_by_one": ("off by one", "off-by-one", "sizeof index", "差一", "cwe-193"),
        "uninitialized_read": ("uninitialized read", "未初始化", "栈上垃圾", "cwe-457"),
        "stack_escape": (
            "stack escape",
            "use after return",
            "return stack",
            "栈地址逃逸",
            "栈指针",
            "cwe-562",
        ),
        "stack_overflow": ("stack overflow", "vla", "栈溢出", "cwe-121"),
        "double_free": ("double free", "free twice", "same object released twice", "cwe-415"),
        "invalid_free": ("invalid free", "non owner", "非堆", "栈缓冲区内部", "cwe-590"),
        "type_confusion": (
            "type confusion",
            "wrong type",
            "invalid mutex",
            "sharedresources",
            "类型混淆",
            "cwe-843",
        ),
        "use_after_free": (
            "use after free",
            "use-after-free",
            "uaf",
            "dangling",
            "释放后使用",
            "悬垂",
            "cwe-416",
        ),
        "null_pointer_dereference": ("null pointer", "null dereference", "空指针", "cwe-476"),
        "realloc_misuse": ("realloc misuse", "direct realloc", "realloc返回值直接", "cwe-401"),
        "missing_unlock": ("missing unlock", "return while lock", "锁泄漏", "未释放锁", "cwe-667"),
        "held_lock_callback": (
            "callback while lock",
            "held lock callback",
            "under lock",
            "cwe-667",
        ),
        "lost_wakeup": (
            "lost wakeup",
            "condition variable",
            "虚假唤醒",
            "pthread cond wait",
            "cwe-366",
        ),
        "refcount_race": ("refcount race", "reference count", "ref count"),
        "object_publication": (
            "object publication",
            "published before initialization",
            "half initialized",
        ),
        "integer_overflow": ("integer overflow", "overflow", "wrap", "整数溢出", "回绕", "cwe-190"),
        "bounds": (
            "bounds",
            "out of bounds",
            "buffer overflow",
            "buffer overread",
            "越界",
            "缓冲区",
            "cwe-125",
            "cwe-787",
        ),
        "race": (
            "race",
            "data race",
            "toctou",
            "concurrency",
            "竞态",
            "无锁",
            "cwe-362",
            "cwe-367",
        ),
        "deadlock": ("deadlock", "lock order", "死锁", "重入", "cwe-833"),
        "memory_leak": (
            "memory leak",
            "resource leak",
            "leak",
            "内存泄漏",
            "资源泄漏",
            "未释放",
            "cwe-401",
            "cwe-772",
        ),
        "fd_leak": (
            "fd leak",
            "file descriptor leak",
            "descriptor leak",
            "unclosed fd",
            "unclosed descriptor",
            "cwe-775",
        ),
        "alignment": ("alignment", "unaligned", "strict alias", "cwe-704"),
        "stale_fd": ("stale fd", "file descriptor", "closed fd", "cwe-672"),
        "path_traversal": ("path traversal", "路径遍历"),
        "state_inconsistency": ("state inconsistency", "state not restored", "rollback", "cwe-672"),
        "unchecked_return": ("unchecked return", "unchecked result", "return success", "cwe-252"),
        "busy_loop": (
            "busy loop",
            "infinite loop",
            "spin",
            "no delay",
            "resource exhaustion",
            "cwe-400",
            "cwe-835",
        ),
        "log_amplification": ("log amplification", "log storm", "resource exhaustion", "cwe-400"),
        "key_truncation": ("key truncation", "truncated key", "partial comparison", "cwe-187"),
        "size_limit_mismatch": (
            "size limit",
            "fixed limit",
            "buffer limit",
            "spec mismatch",
            "cwe-131",
        ),
        "fd_type_mismatch": ("fd type", "reliable fd", "raw fd", "mismatched parameter", "cwe-628"),
        "protocol_mixup": (
            "protocol mixup",
            "protocol mismatch",
            "auth level",
            "origin validation",
            "cwe-346",
        ),
        "partial_resource_leak": ("partial resource leak", "retry leak"),
        "dynamic_array_race": ("dynamic array", "array expansion"),
        "version_filtering": (
            "version filtering",
            "missing version",
            "low version",
            "version filter",
            "cwe-20",
        ),
        "missing_refcount": (
            "missing refcount",
            "reference count",
            "refcount",
            "shared resource",
            "cwe-772",
        ),
        "sigpipe_unhandled": ("sigpipe", "closed peer", "signal", "cwe-404"),
        "premature_destroy": (
            "premature destroy",
            "destroyed while active",
            "active tasks",
            "cwe-416",
        ),
        "registration_race": ("registration race", "check then act", "ops registration", "cwe-362"),
        "alloc_free_mismatch": (
            "allocator mismatch",
            "alloc free mismatch",
            "allocator pairing",
            "cwe-762",
        ),
        "key_generation_race": ("ftok", "key generation", "key collision", "cwe-362"),
        "fd_encoding_mismatch": ("fd encoding", "encoded fd", "raw fd", "check value", "cwe-587"),
        "semantic_mismatch": (
            "semantic mismatch",
            "semantic unit",
            "callback parameter",
            "counter domain",
            "cwe-628",
        ),
        "byte_order_logic": ("byte order", "endian", "ctz", "trailing zero", "cwe-682"),
        "reader_state_race": (
            "reader state",
            "reader pid",
            "multiple readers",
            "rwlock",
            "cwe-362",
        ),
        "uninitialized_output": (
            "uninitialized output",
            "partially initialized",
            "output parameter",
            "cwe-457",
        ),
        "file_type_validation": (
            "file type",
            "character device",
            "regular file",
            "mapping size",
            "cwe-20",
        ),
        "log_level_misuse": ("log level", "logged at error", "alert noise", "cwe-778"),
        "logic_error": (
            "logic error",
            "wrong group",
            "wrong index",
            "semantic mismatch",
            "cwe-682",
        ),
        "global_mode_race": ("global mode", "mutable global mode", "cwe-362"),
        "slot_race": ("slot race", "cas result", "process slot", "stolen slot", "cwe-362"),
        "shared_memory_race": (
            "shared memory race",
            "lookup before lock",
            "concurrent create",
            "memzone",
            "cwe-362",
        ),
        "state_machine": ("state machine", "missing transition", "lifecycle state", "cwe-672"),
        "signal_deadlock": (
            "signal deadlock",
            "signal handler",
            "async signal",
            "semaphore",
            "cwe-833",
        ),
        "signal_race": ("signal race", "signal handler", "async signal", "callstack", "cwe-479"),
        "callback_self_destroy_race": (
            "callback self destroy",
            "self destruction",
            "callback can free",
            "cwe-416",
        ),
        "backend_signal": ("backend signal", "svf", "saber", "knowledge db"),
    }
    priority_groups = (
        "key_truncation",
        "log_amplification",
        "busy_loop",
        "size_limit_mismatch",
        "fd_type_mismatch",
        "protocol_mixup",
        "partial_resource_leak",
        "fd_leak",
        "dynamic_array_race",
        "version_filtering",
        "missing_refcount",
        "signal_race",
        "sigpipe_unhandled",
        "premature_destroy",
        "registration_race",
        "alloc_free_mismatch",
        "key_generation_race",
        "fd_encoding_mismatch",
        "semantic_mismatch",
        "byte_order_logic",
        "reader_state_race",
        "uninitialized_output",
        "file_type_validation",
        "log_level_misuse",
        "logic_error",
        "global_mode_race",
        "slot_race",
        "shared_memory_race",
        "state_machine",
        "signal_deadlock",
        "callback_self_destroy_race",
    )
    for canonical in priority_groups:
        needles = groups.get(canonical, ())
        if any(needle in text or needle in compact for needle in needles):
            return canonical
    for canonical, needles in groups.items():
        if any(needle in text or needle in compact for needle in needles):
            return canonical
    stripped = text.strip()
    if stripped in {"memory safety", "memory_safety"}:
        return "memory_safety"
    token = safe_category_token(stripped)
    return token or "unknown"


def normalize_issue_key_part(value: Any) -> str:
    text = str(value or "").replace("\\", "/").lower().strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) <= MAX_ISSUE_KEY_PART_LENGTH:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:ISSUE_KEY_HASH_LENGTH]
    prefix_len = MAX_ISSUE_KEY_PART_LENGTH - ISSUE_KEY_HASH_LENGTH - 1
    return f"{text[:prefix_len].rstrip()}~{digest}"


def safe_category_token(value: Any) -> str:
    """Return a short category token, never a prose paragraph."""
    text = str(value or "").replace("-", "_").lower().strip()
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"[^a-z0-9_]+", "_", text).strip("_")
    if not text or len(text) > MAX_CATEGORY_TOKEN_LENGTH:
        return ""
    if not re.match(r"^[a-z][a-z0-9_]*$", text):
        return ""
    return text


_KNOWN_CATEGORIES = {
    "alignment",
    "api_contract_violation",
    "backend_signal",
    "bounds",
    "buffer_overread",
    "buffer_over_read",
    "buffer_overflow",
    "buffer_underflow",
    "buffer_underread",
    "buffer_underwrite",
    "busy_loop",
    "busy_wait_loop",
    "command_injection",
    "data_race",
    "deadlock",
    "double_checked_locking",
    "double_free",
    "dynamic_array_race",
    "byte_order_logic",
    "callback_self_destroy_race",
    "fd_encoding_mismatch",
    "fd_leak",
    "file_descriptor_leak",
    "fd_type_mismatch",
    "file_type_validation",
    "format_string",
    "global_mode_race",
    "held_lock_callback",
    "heap_overflow",
    "integer_overflow",
    "integer_truncation",
    "invalid_free",
    "key_truncation",
    "logic_error",
    "log_amplification",
    "lost_wakeup",
    "lock_protocol_violation",
    "memory_leak",
    "memory_safety",
    "missing_refcount",
    "missing_fd_release",
    "missing_unlock",
    "null_pointer_dereference",
    "object_publication",
    "off_by_one",
    "partial_resource_leak",
    "premature_destroy",
    "path_traversal",
    "protocol_mixup",
    "race",
    "race_condition",
    "registration_race",
    "realloc_misuse",
    "refcount_race",
    "reader_state_race",
    "resource_leak",
    "resource_lifecycle",
    "resource_management",
    "resource_allocation_without_limits",
    "semantic_mismatch",
    "shared_state_race",
    "shared_memory_race",
    "signal_deadlock",
    "signal_race",
    "signal_handler_unsafe",
    "signed_unsigned",
    "sigpipe_unhandled",
    "size_limit_mismatch",
    "slot_race",
    "stack_escape",
    "stack_overflow",
    "stale_fd",
    "state_inconsistency",
    "state_machine",
    "alloc_free_mismatch",
    "key_generation_race",
    "unchecked_return",
    "type_confusion",
    "toctou",
    "toctou_race",
    "uninitialized_output",
    "uninitialized_pointer",
    "uninitialized_read",
    "unchecked_allocation",
    "untrusted_pointer",
    "out_of_bounds_write",
    "out_of_range_pointer_offset",
    "use_after_free",
    "use_after_close",
    "version_filtering",
}


_COMMAND_VALIDATION_ALIASES = {
    "incomplete_input_validation",
    "incomplete_security_filter",
    "insufficient_validation",
}


_CATEGORY_ALIASES = {
    "buffer_over_read": "buffer_overread",
    "busy_wait_loop": "busy_loop",
    "file_descriptor_leak": "fd_leak",
    "integer_truncation": "signed_unsigned",
    "race_condition": "race",
    "signal_handler_unsafe": "signal_race",
    "toctou_race": "toctou",
    "use_after_close": "stale_fd",
}


_CATEGORY_FAMILIES = {
    "loop": {
        "busy_loop",
        "infinite_loop",
        "busy_wait_loop",
    },
    "race": {
        "race",
        "race_condition",
        "data_race",
        "shared_state_race",
        "dynamic_array_race",
        "reader_state_race",
        "global_mode_race",
        "slot_race",
        "shared_memory_race",
        "registration_race",
        "key_generation_race",
        "signal_race",
        "signal_handler_unsafe",
        "refcount_race",
        "object_publication",
        "callback_self_destroy_race",
        "double_checked_locking",
        "toctou",
        "toctou_race",
    },
    "memory_leak": {
        "fd_leak",
        "file_descriptor_leak",
        "memory_leak",
        "resource_leak",
        "resource_lifecycle",
        "resource_management",
        "partial_resource_leak",
        "resource_allocation_without_limits",
        "missing_refcount",
        "realloc_misuse",
    },
    "memory_release": {
        "use_after_free",
        "double_free",
        "invalid_free",
        "stack_escape",
        "premature_destroy",
        "alloc_free_mismatch",
    },
    "bounds": {
        "bounds",
        "buffer_overread",
        "buffer_over_read",
        "buffer_overflow",
        "buffer_underflow",
        "buffer_underread",
        "buffer_underwrite",
        "heap_overflow",
        "integer_overflow",
        "integer_truncation",
        "size_limit_mismatch",
        "off_by_one",
        "stack_overflow",
        "signed_unsigned",
        "out_of_bounds_write",
        "out_of_range_pointer_offset",
        "unchecked_allocation",
        "untrusted_pointer",
        "uninitialized_pointer",
        "alignment",
    },
    "type_contract": {
        "type_confusion",
        "api_contract_violation",
        "semantic_mismatch",
        "fd_type_mismatch",
        "fd_encoding_mismatch",
        "protocol_mixup",
    },
    "input_validation": {
        "incomplete_input_validation",
        "incomplete_security_filter",
        "insufficient_validation",
    },
    "lock": {
        "deadlock",
        "lock_protocol_violation",
        "missing_unlock",
        "held_lock_callback",
        "lost_wakeup",
        "signal_deadlock",
    },
}


_CATEGORY_FAMILY_COMPATIBLE_PAIRS = {
    frozenset({"memory_leak", "memory_release"}),
    frozenset({"command_injection", "input_validation"}),
}


_MEMORY_LIFETIME_RELATED_CATEGORIES = {
    "fd_leak",
    "file_descriptor_leak",
    "memory_leak",
    "resource_leak",
    "resource_lifecycle",
    "resource_management",
    "partial_resource_leak",
    "missing_refcount",
    "realloc_misuse",
    "use_after_free",
    "use_after_close",
    "double_free",
    "invalid_free",
    "stack_escape",
    "premature_destroy",
    "alloc_free_mismatch",
}


_CROSS_CONTEXT_RESIDUAL_DEDUP_CATEGORIES = {
    "command_injection",
    "fd_leak",
    "file_descriptor_leak",
    "stale_fd",
    "use_after_close",
    "resource_lifecycle",
    "resource_management",
    "resource_leak",
    "memory_leak",
    "partial_resource_leak",
    "missing_refcount",
    "use_after_free",
    "double_free",
    "invalid_free",
    "premature_destroy",
}


_CROSS_FILE_ROOT_DEDUP_ROOTS: Set[str] = set()


_GENERIC_IDENTITY_TOKENS = {
    "allocation",
    "alloc",
    "array",
    "buffer",
    "calloc",
    "container",
    "free",
    "item",
    "leak",
    "malloc",
    "memory",
    "memory_",
    "memory_leak",
    "node",
    "object",
    "pointer",
    "resource",
    "resource_leak",
    "resources",
    "safe_calloc",
    "safe_free",
    "storage",
    "strdup",
    "value",
    "xmalloc",
}


_RESOURCE_IDENTITY_KEYS = (
    "resource_signature",
    "resource",
    "resource_object",
    "affected_object",
    "owner_object",
    "thread_object",
    "symbol",
    "variable",
    "member",
    "member_field",
    "field",
    "allocation",
    "allocation_symbol",
    "source_symbol",
    "sink_symbol",
)


_NON_SEMANTIC_IDENTITY_FIELDS = {
    "alternate_evidence",
    "attached_needs_review_count",
    "candidate_schema_version",
    "candidate_uid",
    "occurrence_uid",
    "history_key",
    "evidence_hash",
    "run_issue_uid",
    "candidate_disposition",
    "dedup_decision",
    "dedup_decisions",
    "duplicate_count",
    "duplicate_sources",
    "evidence_completeness",
    "evidence_sources",
    "entry_paths",
    "related_needs_review_observations",
}


def flatten_issue_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(
            flatten_issue_text(item)
            for key, item in value.items()
            if str(key) not in _NON_SEMANTIC_IDENTITY_FIELDS
        )
    if isinstance(value, list):
        return " ".join(flatten_issue_text(v) for v in value)
    return "" if value is None else str(value)


def parse_issue_location(location: str) -> tuple[str, Optional[int]]:
    """Parse an identity coordinate using case-folded path spelling.

    This helper is intentionally for stable identity and deduplication.  Code
    that opens a path on a case-sensitive filesystem must use
    :func:`parse_issue_location_preserving_path_case` instead.
    """

    file_path, line = parse_issue_location_preserving_path_case(location)
    return file_path.lower(), line


def parse_issue_location_preserving_path_case(
    location: str,
) -> tuple[str, Optional[int]]:
    """Parse a report coordinate without changing its physical path spelling."""

    normalized = location.replace("\\", "/")
    match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+):(\d+)", normalized)
    if match:
        return match.group(1), int(match.group(2))
    match = re.search(r"(.+\.[chp]+):(\d+)", normalized)
    if match:
        return match.group(1), int(match.group(2))
    match = re.match(r"^\s*(\d+)(?:\s*-\s*\d+)?\s*$", normalized)
    if match:
        return "", int(match.group(1))
    return "", None
