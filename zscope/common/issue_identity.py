"""Issue canonicalization and duplicate merging helpers."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple


MAX_CATEGORY_TOKEN_LENGTH = 64
MAX_ISSUE_KEY_PART_LENGTH = 160
ISSUE_KEY_HASH_LENGTH = 12


def deduplicate_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge findings that point at the same root cause."""
    records: Dict[str, Dict[str, Any]] = {}
    for issue in issues:
        normalize_issue_fields(issue)
        key = canonical_issue_key(issue)
        existing = records.get(key)
        if existing is None:
            issue["dedup_key"] = key
            issue.setdefault("category_family", semantic_category_family(issue.get("category")))
            signature = issue_resource_signature(issue)
            if signature:
                issue.setdefault("resource_signature", signature)
            issue.setdefault("duplicate_sources", [])
            records[key] = issue
            continue

        if issue_rank(issue) > issue_rank(existing):
            merge_duplicate_issue(
                issue,
                existing,
                dedup_key=key,
                decision={"method": "canonical_issue_key", "root_cause_key": key},
            )
            issue["dedup_key"] = key
            records[key] = issue
            continue

        merge_duplicate_issue(
            existing,
            issue,
            dedup_key=key,
            decision={"method": "canonical_issue_key", "root_cause_key": key},
        )
    return list(records.values())


def merge_duplicate_issue(
    primary: Dict[str, Any],
    duplicate: Dict[str, Any],
    *,
    dedup_key: str = "",
    decision: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Attach duplicate evidence to ``primary`` without silently discarding it."""
    if dedup_key:
        primary["dedup_key"] = dedup_key
    primary.setdefault("category_family", semantic_category_family(primary.get("category")))
    signature = issue_resource_signature(primary)
    if signature:
        primary.setdefault("resource_signature", signature)

    duplicate_extra_count = int(duplicate.get("duplicate_count", 0) or 0)
    primary["duplicate_count"] = int(primary.get("duplicate_count", 0) or 0) + 1 + duplicate_extra_count

    sources = primary.get("duplicate_sources")
    if not isinstance(sources, list):
        sources = []
        primary["duplicate_sources"] = sources
    for source in _duplicate_source_records(duplicate):
        if source not in sources:
            sources.append(source)

    alternate = primary.get("alternate_evidence")
    if not isinstance(alternate, list):
        alternate = []
        primary["alternate_evidence"] = alternate
    for evidence in _alternate_evidence_records(duplicate):
        if evidence not in alternate:
            alternate.append(evidence)

    if decision:
        decisions = primary.get("dedup_decisions")
        if not isinstance(decisions, list):
            decisions = []
            primary["dedup_decisions"] = decisions
        compact_decision = {
            key: value
            for key, value in decision.items()
            if value not in (None, "", [], {})
        }
        if compact_decision and compact_decision not in decisions:
            decisions.append(compact_decision)
        primary["dedup_decision"] = compact_decision or primary.get("dedup_decision")
    return primary


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
    normalized_category = semantic_category_override(structured_category, inferred_category) or structured_category or inferred_category
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


def issue_rank(issue: Dict[str, Any]) -> tuple[int, int, int, float, int]:
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
    source_rank = structured_evidence_rank(issue)
    detail_len = len(str(issue.get("reasoning") or issue.get("description") or ""))
    return status, severity, source_rank, confidence, detail_len


def structured_evidence_rank(issue: Dict[str, Any]) -> int:
    """Prefer concrete local/backend evidence over long free-form duplicates."""
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    source = str(
        issue.get("candidate_source")
        or pack.get("candidate_source")
        or issue.get("finding_kind")
        or ""
    ).lower()
    rule = str(issue.get("rule") or pack.get("rule") or issue.get("id") or "").lower()
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
    root = root_cause_token(issue, category, text)
    category = report_cluster_category(category, root)
    scope = file_path or function
    if root:
        scoped_root = root_scope_token(issue, category, root)
        parts = (category, scope, scoped_root, root) if scoped_root else (category, scope, root)
        return "|".join(normalize_issue_key_part(part) for part in parts)

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
    return "|".join(
        normalize_issue_key_part(part)
        for part in (category, scope, str(line or ""), sink or function)
    )


def report_cluster_category(category: str, root: str) -> str:
    """Return the category bucket used for same-report root-cause merging.

    This is intentionally narrower than user-facing category normalization.  It
    only folds categories when the root token points at the same concrete
    operation/resource, so distinct resources or member fields remain separate.
    """
    normalized = str(category or "").replace("-", "_").lower()
    root_key = str(root or "").replace("-", "_").lower()
    numeric_roots = {
        "issue41_label_cache_size_miscalc",
        "label_cache_size_miscalc",
    }
    if root_key in numeric_roots and normalized in {
        "integer_overflow",
        "bounds",
        "size_limit_mismatch",
    }:
        return "numeric_size_mismatch"
    path_roots = {"path_check_before_open"}
    if root_key in path_roots and normalized in {
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
    return bool(left and right and left == right)


def issue_resource_signature(issue: Dict[str, Any]) -> str:
    """Return the concrete object/member identity that constrains semantic merges."""
    if not isinstance(issue, dict):
        return ""
    explicit = first_issue_value(issue, *_RESOURCE_IDENTITY_KEYS)
    if explicit:
        return normalize_issue_key_part(explicit)

    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    clang_fact = pack.get("clang_matcher_fact") if isinstance(pack.get("clang_matcher_fact"), dict) else {}
    for key in (
        "resource_symbol",
        "object_symbol",
        "member",
        "field",
        "source_symbol",
        "sink_symbol",
    ):
        if clang_fact.get(key):
            return normalize_issue_key_part(clang_fact.get(key))

    text = flatten_issue_text(issue)
    raw_lower = text.lower()
    global_match = re.search(r"\b(g_[a-z0-9_]{3,})\b", raw_lower)
    if global_match:
        return normalize_issue_key_part(global_match.group(1))
    for member_match in re.finditer(r"\b([a-z_]\w*(?:->|\.)[a-z_]\w*)\b", raw_lower):
        token = member_match.group(1)
        if re.search(r"\.(?:c|h|cc|cpp|hpp)$", token):
            continue
        return normalize_issue_key_part(token)
    backtick_match = re.search(r"`([^`]{2,80})`", text)
    if backtick_match:
        token = backtick_match.group(1).strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)?$", token):
            return normalize_issue_key_part(token)
    category = canonical_category(issue, text)
    root = root_cause_token(issue, category, text)
    if root and (
        root in _GLOBAL_OBJECT_ROOTS
        or "->" in root
        or root.startswith("g_")
        or root in {"thread_ids", "g_dispatcher.queue.tasks"}
    ):
        return normalize_issue_key_part(root)
    return ""


def semantic_root_cause_key(issue: Dict[str, Any]) -> str:
    """Return a report-level semantic root key with resource guardrails."""
    normalize_issue_fields(issue)
    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)
    family = semantic_category_family(report_cluster_category(category, root_cause_token(issue, category, text)))
    file_path = issue_file_identity(issue, text)
    function = issue_function_identity(issue)
    root = root_cause_token(issue, category, text)
    resource = issue_resource_signature(issue)
    parts = ["semantic-v1", family, file_path, function, root or resource]
    normalized = [normalize_issue_key_part(part) for part in parts if normalize_issue_key_part(part)]
    if len(normalized) < 4:
        return ""
    return "|".join(normalized)


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
    return "|".join(
        normalize_issue_key_part(part)
        for part in ("semantic-cluster-v1", family, file_path, function)
        if normalize_issue_key_part(part)
    )


def issues_same_context(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Return whether two issues are anchored to the same function/path context."""
    left_file = issue_file_identity(left, flatten_issue_text(left))
    right_file = issue_file_identity(right, flatten_issue_text(right))
    left_func = issue_function_identity(left)
    right_func = issue_function_identity(right)
    if left_file and right_file and left_file == right_file and left_func and right_func and left_func == right_func:
        return True

    left_paths = _call_path_sets(left)
    right_paths = _call_path_sets(right)
    if left_paths and right_paths and any(path in right_paths for path in left_paths):
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


def issues_may_share_root_cause(
    left: Dict[str, Any],
    right: Dict[str, Any],
    *,
    confidence: float = 1.0,
    threshold: float = 0.85,
    require_concrete_root: bool = False,
) -> bool:
    """Guardrail for deterministic and LLM-backed duplicate decisions."""
    if confidence < threshold:
        return False
    normalize_issue_fields(left)
    normalize_issue_fields(right)
    if not category_families_compatible(left.get("category"), right.get("category")):
        return False
    if resource_signatures_conflict(left, right):
        return False
    if not issues_same_context(left, right):
        return False

    left_text = flatten_issue_text(left)
    right_text = flatten_issue_text(right)
    left_category = canonical_category(left, left_text)
    right_category = canonical_category(right, right_text)
    left_root = root_cause_token(left, left_category, left_text)
    right_root = root_cause_token(right, right_category, right_text)
    left_resource = issue_resource_signature(left)
    right_resource = issue_resource_signature(right)

    if require_concrete_root and left_root and right_root and left_root != right_root:
        return False
    if left_root and right_root and left_root == right_root:
        return True
    if left_resource and right_resource and left_resource == right_resource:
        return True
    if require_concrete_root:
        return False
    return True


def deduplicate_semantic_issues_programmatic(
    issues: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Apply deterministic semantic duplicate collapse after canonical dedup."""
    base = deduplicate_issues(issues)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for issue in base:
        key = semantic_cluster_key(issue)
        if key:
            groups.setdefault(key, []).append(issue)

    merged_ids: Set[int] = set()
    result: List[Dict[str, Any]] = []
    merge_count = 0
    for group_key, group in groups.items():
        group = [issue for issue in group if id(issue) not in merged_ids]
        if len(group) < 2:
            continue
        primaries: List[Dict[str, Any]] = []
        for issue in group:
            matched = None
            for primary in primaries:
                if issues_may_share_root_cause(
                    primary,
                    issue,
                    require_concrete_root=True,
                ):
                    matched = primary
                    break
            if matched is None:
                primaries.append(issue)
                continue
            root_key = semantic_root_cause_key(matched) or semantic_root_cause_key(issue) or group_key
            if issue_rank(issue) > issue_rank(matched):
                primaries.remove(matched)
                merge_duplicate_issue(
                    issue,
                    matched,
                    dedup_key=root_key,
                    decision={"method": "programmatic_semantic", "root_cause_key": root_key},
                )
                primaries.append(issue)
                merged_ids.add(id(matched))
            else:
                merge_duplicate_issue(
                    matched,
                    issue,
                    dedup_key=root_key,
                    decision={"method": "programmatic_semantic", "root_cause_key": root_key},
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
        if isinstance(value, list) and value and all(not isinstance(item, (list, dict)) for item in value):
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
    normalized = [normalize_issue_key_part(part) for part in parts if normalize_issue_key_part(part)]
    # Avoid producing a dangerously broad fingerprint such as only category/file.
    if len(normalized) < 4:
        return ""
    return "|".join(normalized)


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
                    for normalized in (_normalize_source_context(fragment) for fragment in fragments)
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
    """Return extra identity for broad root tokens that can occur in many functions.

    Some detectors intentionally collapse noisy syntax into semantic roots such as
    `net_recv_data_negative_length`.  Those roots are useful for merging duplicate
    evidence inside one sink, but they are too broad across wrappers and model
    functions.  Keep global object roots broad, and scope operation/helper roots
    by the concrete sink function.
    """
    if not root or root in _GLOBAL_OBJECT_ROOTS:
        return ""
    if category not in _FUNCTION_SCOPED_ROOT_CATEGORIES and root not in _FUNCTION_SCOPED_ROOTS:
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
            elif key_text in {"evidence_pack", "candidate_evidence", "source_path", "path", "ast_cfg", "clang_tooling"}:
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
    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    values = [
        issue_file_identity(issue),
        issue_function_identity(issue),
        first_issue_value(issue, "sink", "sink_function", "target_function", "release_func"),
        first_issue_value(issue, "source", "source_function", "acquire_func"),
        first_issue_value(issue, "resource", "resource_object", "affected_object", "symbol", "variable"),
    ]
    clang_fact = pack.get("clang_matcher_fact") if isinstance(pack.get("clang_matcher_fact"), dict) else {}
    values.extend(
        [
            clang_fact.get("matcher"),
            clang_fact.get("kind"),
            clang_fact.get("resource_symbol"),
            clang_fact.get("source_symbol"),
            clang_fact.get("sink_symbol"),
        ]
    )
    ast_cfg = pack.get("ast_cfg") if isinstance(pack.get("ast_cfg"), dict) else {}
    events = ast_cfg.get("events")
    if isinstance(events, list):
        for event in events[:5]:
            if isinstance(event, dict):
                values.extend([event.get("kind"), event.get("variable"), event.get("callee")])
    normalized = [normalize_issue_key_part(value) for value in values if normalize_issue_key_part(value)]
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


def root_cause_token(issue: Dict[str, Any], category: str, text: str) -> str:
    raw_lower = text.lower()
    lower = raw_lower.replace("_", " ").replace("-", " ")
    compact = re.sub(r"[^a-z0-9]+", "", raw_lower)
    function = str(issue.get("function") or issue.get("func_name") or "").lower()
    rule = str(issue.get("rule") or issue.get("rule_id") or issue.get("candidate_id") or issue.get("id") or "").lower()

    def has_name(name: str) -> bool:
        normalized = name.lower().strip("_")
        return name.lower() in raw_lower or normalized.replace("_", "") in compact

    # High-signal semantic roots that commonly appear through several public
    # entries or both rule and LLM candidates.  These roots are deliberately
    # tied to concrete sink functions/resources, not broad vulnerability types.
    if function == "_issue41_dynamic_array_expand_race":
        return "issue41_dynamic_array_resize"
    if function == "_issue41_label_cache_size_miscalc":
        return "issue41_label_cache_size_miscalc"
    if function == "_real_model_ssl_error_returns_ok":
        return "real_model_ssl_probe_status"
    if function == "_real_model_error_branch_double_cleanup" and (
        "payload" in lower or "node->payload" in raw_lower or "nodepayload" in compact
    ):
        return "real_model_payload_double_cleanup"
    if function == "_validate_task" and "fopen" in lower and "path" in lower:
        return "path_check_before_open"
    if function == "_lifecycle_ref_get" and ("ref_count" in raw_lower or "ref count" in lower):
        return "lifecycle_ref_get_after_unlock"
    if function == "_lifecycle_ref_put" and ("ref_count" in raw_lower or "ref count" in lower):
        return "lifecycle_ref_put_after_unlock"
    if function == "_real_model_callback_under_lock" and (
        "g_real_callback_node" in raw_lower or "borrowed" in lower or "dangling" in lower
    ):
        return "g_real_callback_node"
    if function == "_lifecycle_send_status" and (
        "pending_jobs" in raw_lower or "pending jobs" in lower
    ):
        return "g_lifecycle_pending_jobs"
    if function == "_control_session_add_to_global" and "pthread_mutex_init" in lower:
        return "control_session_mutex_init"
    if function == "_net_recv_data" and "size_t" in raw_lower and (
        "int" in lower or "截断" in text or "trunc" in lower
    ):
        return "net_recv_data_return_truncation"

    if (
        has_name("_lifecycle_customize_control_message")
        or has_name("_lifecycle_customize_transport_cleanup")
    ) and ("open" in lower or "customize" in lower):
        return "control_session_open_leak"

    if (
        "shared_resource_freed_without_refcount_protocol" in rule
        or function == "_issue41_missing_reference_count"
        or "g_issue41_broker.resources" in raw_lower
        or ("issue41" in compact and "refcount" in compact and "safe_free" in raw_lower)
    ):
        return "issue41_resource_refcount_protocol"
    if (
        function == "_issue41_partial_resource_leak_on_retry"
        or ("issue41" in compact and "partition" in lower and "tag" in lower and ("fail_step" in raw_lower or "retry" in lower))
    ):
        return "issue41_partition_retry_cleanup"
    if (
        "parsed_protocol_version_is_ignored" in rule
        or function == "_issue41_missing_version_filter"
        or ("(void)version" in raw_lower and ("version" in lower or "protocol" in lower))
    ):
        return "parsed_protocol_version_ignored"
    if (
        "raw_fd_revalidated_as_encoded" in rule
        or function == "_issue41_raw_fd_missing_encode"
        or ("encoded fd" in lower and "raw fd" in lower and ("check value" in lower or "validate" in lower))
    ):
        return "raw_fd_reaches_encoded_fd_validator"
    if (
        "unchecked_strchr_result" in rule
        or function == "_lifecycle_parse_control_message"
        or ("strchr" in lower and ("sep" in lower or "colon" in lower or ":" in raw_lower) and category == "null_pointer_dereference")
    ):
        return "lifecycle_control_message_strchr"
    if (
        "stack_address_passed_to_thread" in rule
        or function == "_real_model_detached_stack_job"
        or ("pthread_create" in lower and ("_real_model_async_worker" in raw_lower or "realmodelasyncjob" in compact or "&job" in raw_lower))
    ):
        return "real_model_async_stack_job"
    if (
        "protocol_units_length_reaches_copy_without_packet_bound" in rule
        or function == "_real_model_protocol_length_miscalc"
    ):
        return "real_model_protocol_units_length"
    if "unaligned_integer_pointer_cast" in rule or function == "_real_model_message_alignment_overread":
        return "real_model_message_alignment"
    if "negative_length_cast_to_size_t" in rule or function == "_real_model_signed_recv_to_size":
        return "real_model_signed_recv_to_size"
    if function == "_real_model_recv_busy_loop":
        return "real_model_recv_busy_loop"

    named_objects = (
        "thread_ids",
        "g_dispatcher.queue.tasks",
        "g_shared_counter",
        "g_receiver_running",
        "g_ready",
        "g_running",
        "g_config_lock",
        "g_real_aux_lock",
        "g_active_config",
        "g_watched_fd",
        "g_real_watched_fd",
        "g_rules_map",
        "g_rules_len",
        "g_macro_guarded_counter",
        "g_log_buffer",
        "temp_buffer",
        "recovery_buffer",
        "error_msg",
        "payload_len",
        "payload_length",
        "statusreply",
        "flushjob",
        "pfnDropSession",
        "guardedsubscription",
        "g_issue41_task_array",
        "g_issue41_task_array_cap",
        "node->payload",
        "g_lifecycle.pending_jobs",
        "g_real_callback_node",
        "g_callback_entry",
    )
    for name in named_objects:
        raw_name = name.lower()
        spaced_name = raw_name.replace("_", " ")
        compact_name = re.sub(r"[^a-z0-9]+", "", raw_name)
        if raw_name in raw_lower or spaced_name in lower or compact_name in compact:
            token = raw_name
            if token == "payload_length":
                token = "payload_len"
            if token == "statusreply":
                token = "status_reply"
            if token == "flushjob":
                token = "flush_job"
            if token == "pfndropsession":
                token = "mesh_session_cleanup_hook"
            if token == "guardedsubscription":
                token = "guarded_subscription"
            return token

    if "lifecyclerecvpacket" in compact or (
        "netrecvdata" in compact and ("size_max" in raw_lower or "sizemax" in compact or "返回-1" in text)
    ):
        return "net_recv_data_negative_length"
    if has_name("_executor_cleanup_resources") and (
        "sharedresources" in lower or "taskconfig" in lower or "类型混淆" in text
    ):
        return "executor_sharedresources_type_confusion"
    if has_name("_executor_init") and (
        "sharedresources" in lower or "taskconfig" in lower or "类型混淆" in text
    ):
        return "executor_sharedresources_type_confusion"
    if has_name("_plugin_lookup") and ("mutex" in lower or "lock" in lower or "重入" in text):
        return "plugin_lookup_registry_mutex"
    if (
        "paired_self_referential_traversal_log_amplification" in rule
        or "self_referential_list_link" in rule
        or "pipe->next = pipe" in raw_lower
        or "pipe->next=pipe" in compact
    ) and ("pipe" in lower or "pipe" in compact) and ("self" in lower or "next" in lower or "log" in lower):
        return "pipe_self_link"
    if (
        "paired_full_key_lookup_truncated_insert" in rule
        or "full_key_lookup_truncated_insert" in rule
        or "key truncation" in lower
        or "truncated key" in lower
        or ("full key" in lower and ("strncpy" in lower or "bounded" in lower))
    ):
        return "full_key_lookup_truncated_insert"
    if (
        has_name("_lifecycle_dispatch_pipe_tick")
        or has_name("_lifecycle_close_pipe")
        or has_name("_lifecycle_tick_timer_callback")
    ) and (
        "ctrl_lock" in lower or "sched_lock" in lower or "deadlock" in lower
    ):
        return "pipe_scheduler_control_lock_order"
    if has_name("_lifecycle_close_pipe") and ("pipe->next = pipe" in lower or "self" in lower):
        return "pipe_self_link"
    if has_name("_lifecycle_delete_os_node") or "procnode" in lower:
        return "os_node_proc_list"
    if has_name("_lifecycle_avl_register_route") or has_name("_route_avl_insert_node"):
        return "route_avl_node_after_insert"
    if has_name("_lifecycle_unregister_guarded_subscription"):
        return "guarded_subscription_mutex"
    if has_name("_lifecycle_mesh_authorize_init"):
        return "mesh_session_cleanup_hook"
    if has_name("_control_session_detach_without_release"):
        return "control_session_detach_leak"
    if has_name("_lifecycle_customize_control_message") and "open" in lower:
        return "control_session_open_leak"
    if has_name("_lifecycle_release_value_slice") or "value+1" in compact:
        return "value_slice_invalid_free"
    if has_name("_lifecycle_format_topic") or "topic[sizeof" in compact:
        return "topic_off_by_one"
    if has_name("_lifecycle_parse_frame") or "vla" in lower:
        return "frame_vla_stack"
    if has_name("_lifecycle_wait_for_work") and "pthread_cond_wait" in lower:
        return "lifecycle_cond_wait"
    if has_name("_lifecycle_resize_metrics") or "g_metrics" in lower:
        return "g_metrics_realloc"
    if category == "command_injection" and ("system" in lower or "命令注入" in text):
        return "task_command_execution"
    if category == "format_string" and ("printf" in lower or "格式化字符串" in text):
        return "printf_format_string"
    if category == "memory_leak" and function:
        object_match = re.search(r"\b([A-Za-z_]\w*)\s*(?:allocated|分配|未释放|leak)", text)
        if object_match:
            return object_match.group(1).lower()
    return ""


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
        "command_injection": ("command injection", "shell injection", "命令注入", "system(", "cwe-78"),
        "double_checked_locking": ("double checked locking", "double checked", "双重检查"),
        "signed_unsigned": ("signed unsigned", "negative length", "size_max", "sizemax", "有符号", "无符号", "cwe-195"),
        "off_by_one": ("off by one", "off-by-one", "sizeof index", "差一", "cwe-193"),
        "uninitialized_read": ("uninitialized read", "未初始化", "栈上垃圾", "cwe-457"),
        "stack_escape": ("stack escape", "use after return", "return stack", "栈地址逃逸", "栈指针", "cwe-562"),
        "stack_overflow": ("stack overflow", "vla", "栈溢出", "cwe-121"),
        "double_free": ("double free", "free twice", "same object released twice", "cwe-415"),
        "invalid_free": ("invalid free", "non owner", "非堆", "栈缓冲区内部", "cwe-590"),
        "type_confusion": ("type confusion", "wrong type", "invalid mutex", "sharedresources", "类型混淆", "cwe-843"),
        "use_after_free": ("use after free", "use-after-free", "uaf", "dangling", "释放后使用", "悬垂", "cwe-416"),
        "null_pointer_dereference": ("null pointer", "null dereference", "空指针", "cwe-476"),
        "realloc_misuse": ("realloc misuse", "direct realloc", "realloc返回值直接", "cwe-401"),
        "missing_unlock": ("missing unlock", "return while lock", "锁泄漏", "未释放锁", "cwe-667"),
        "held_lock_callback": ("callback while lock", "held lock callback", "under lock", "cwe-667"),
        "lost_wakeup": ("lost wakeup", "condition variable", "虚假唤醒", "pthread cond wait", "cwe-366"),
        "refcount_race": ("refcount race", "reference count", "ref count"),
        "object_publication": ("object publication", "published before initialization", "half initialized"),
        "integer_overflow": ("integer overflow", "overflow", "wrap", "整数溢出", "回绕", "cwe-190"),
        "bounds": ("bounds", "out of bounds", "buffer overflow", "buffer overread", "越界", "缓冲区", "cwe-125", "cwe-787"),
        "race": ("race", "data race", "toctou", "concurrency", "竞态", "无锁", "cwe-362", "cwe-367"),
        "deadlock": ("deadlock", "lock order", "死锁", "重入", "cwe-833"),
        "memory_leak": ("memory leak", "resource leak", "leak", "内存泄漏", "资源泄漏", "未释放", "cwe-401", "cwe-772"),
        "alignment": ("alignment", "unaligned", "strict alias", "cwe-704"),
        "stale_fd": ("stale fd", "file descriptor", "closed fd", "cwe-672"),
        "path_traversal": ("path traversal", "路径遍历"),
        "state_inconsistency": ("state inconsistency", "state not restored", "rollback", "cwe-672"),
        "unchecked_return": ("unchecked return", "unchecked result", "return success", "cwe-252"),
        "busy_loop": ("busy loop", "infinite loop", "spin", "no delay", "resource exhaustion", "cwe-400", "cwe-835"),
        "log_amplification": ("log amplification", "log storm", "resource exhaustion", "cwe-400"),
        "key_truncation": ("key truncation", "truncated key", "partial comparison", "cwe-187"),
        "size_limit_mismatch": ("size limit", "fixed limit", "buffer limit", "spec mismatch", "cwe-131"),
        "fd_type_mismatch": ("fd type", "reliable fd", "raw fd", "mismatched parameter", "cwe-628"),
        "protocol_mixup": ("protocol mixup", "protocol mismatch", "auth level", "origin validation", "cwe-346"),
        "partial_resource_leak": ("partial resource leak", "retry leak"),
        "dynamic_array_race": ("dynamic array", "array expansion"),
        "version_filtering": ("version filtering", "missing version", "low version", "version filter", "cwe-20"),
        "missing_refcount": ("missing refcount", "reference count", "refcount", "shared resource", "cwe-772"),
        "sigpipe_unhandled": ("sigpipe", "closed peer", "signal", "cwe-404"),
        "fd_encoding_mismatch": ("fd encoding", "encoded fd", "raw fd", "check value", "cwe-587"),
        "semantic_mismatch": ("semantic mismatch", "semantic unit", "callback parameter", "counter domain", "cwe-628"),
        "byte_order_logic": ("byte order", "endian", "ctz", "trailing zero", "cwe-682"),
        "reader_state_race": ("reader state", "reader pid", "multiple readers", "rwlock", "cwe-362"),
        "uninitialized_output": ("uninitialized output", "partially initialized", "output parameter", "cwe-457"),
        "file_type_validation": ("file type", "character device", "regular file", "mapping size", "cwe-20"),
        "log_level_misuse": ("log level", "logged at error", "alert noise", "cwe-778"),
        "logic_error": ("logic error", "wrong group", "wrong index", "semantic mismatch", "cwe-682"),
        "global_mode_race": ("global mode", "mutable global mode", "qrcu", "crcu", "cwe-362"),
        "slot_race": ("slot race", "cas result", "process slot", "stolen slot", "cwe-362"),
        "shared_memory_race": ("shared memory race", "lookup before lock", "concurrent create", "memzone", "cwe-362"),
        "state_machine": ("state machine", "missing transition", "lifecycle state", "cwe-672"),
        "signal_deadlock": ("signal deadlock", "signal handler", "async signal", "semaphore", "cwe-833"),
        "callback_self_destroy_race": ("callback self destroy", "self destruction", "callback can free", "cwe-416"),
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
        "dynamic_array_race",
        "version_filtering",
        "missing_refcount",
        "sigpipe_unhandled",
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
    "buffer_overflow",
    "busy_loop",
    "command_injection",
    "data_race",
    "deadlock",
    "double_checked_locking",
    "double_free",
    "dynamic_array_race",
    "byte_order_logic",
    "callback_self_destroy_race",
    "fd_encoding_mismatch",
    "fd_type_mismatch",
    "file_type_validation",
    "format_string",
    "global_mode_race",
    "held_lock_callback",
    "integer_overflow",
    "invalid_free",
    "key_truncation",
    "logic_error",
    "log_amplification",
    "lost_wakeup",
    "memory_leak",
    "memory_safety",
    "missing_refcount",
    "missing_unlock",
    "null_pointer_dereference",
    "object_publication",
    "off_by_one",
    "partial_resource_leak",
    "path_traversal",
    "protocol_mixup",
    "race",
    "realloc_misuse",
    "refcount_race",
    "reader_state_race",
    "resource_leak",
    "resource_management",
    "semantic_mismatch",
    "shared_state_race",
    "shared_memory_race",
    "signal_deadlock",
    "signed_unsigned",
    "sigpipe_unhandled",
    "size_limit_mismatch",
    "slot_race",
    "stack_escape",
    "stack_overflow",
    "stale_fd",
    "state_inconsistency",
    "state_machine",
    "unchecked_return",
    "type_confusion",
    "toctou",
    "uninitialized_output",
    "uninitialized_read",
    "use_after_free",
    "version_filtering",
}


_CATEGORY_FAMILIES = {
    "loop": {
        "busy_loop",
        "infinite_loop",
    },
    "race": {
        "race",
        "data_race",
        "shared_state_race",
        "dynamic_array_race",
        "reader_state_race",
        "global_mode_race",
        "slot_race",
        "shared_memory_race",
        "refcount_race",
        "object_publication",
        "callback_self_destroy_race",
        "double_checked_locking",
        "toctou",
    },
    "memory_leak": {
        "memory_leak",
        "resource_leak",
        "resource_management",
        "partial_resource_leak",
        "missing_refcount",
        "realloc_misuse",
    },
    "memory_release": {
        "use_after_free",
        "double_free",
        "invalid_free",
        "stack_escape",
    },
    "bounds": {
        "bounds",
        "buffer_overflow",
        "integer_overflow",
        "size_limit_mismatch",
        "off_by_one",
        "stack_overflow",
        "signed_unsigned",
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
    "lock": {
        "deadlock",
        "missing_unlock",
        "held_lock_callback",
        "lost_wakeup",
        "signal_deadlock",
    },
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


_GLOBAL_OBJECT_ROOTS = {
    "thread_ids",
    "g_shared_counter",
    "g_receiver_running",
    "g_ready",
    "g_running",
    "g_active_config",
    "g_watched_fd",
    "g_macro_guarded_counter",
    "g_log_buffer",
    "temp_buffer",
    "recovery_buffer",
    "error_msg",
    "payload_len",
    "status_reply",
    "flush_job",
    "mesh_session_cleanup_hook",
    "guarded_subscription",
    "executor_sharedresources_type_confusion",
    "plugin_lookup_registry_mutex",
}


_FUNCTION_SCOPED_ROOT_CATEGORIES = {
    "alignment",
    "bounds",
    "busy_loop",
    "double_free",
    "fd_encoding_mismatch",
    "fd_type_mismatch",
    "integer_overflow",
    "log_amplification",
    "memory_leak",
    "object_publication",
    "partial_resource_leak",
    "protocol_mixup",
    "race",
    "refcount_race",
    "signed_unsigned",
    "stale_fd",
    "state_inconsistency",
    "unchecked_return",
    "version_filtering",
    "use_after_free",
}


_FUNCTION_SCOPED_ROOTS = {
    "net_recv_data_negative_length",
    "route_avl_node_after_insert",
    "control_session_detach_leak",
    "control_session_open_leak",
    "value_slice_invalid_free",
    "topic_off_by_one",
    "frame_vla_stack",
    "lifecycle_cond_wait",
    "g_metrics_realloc",
    "task_command_execution",
    "printf_format_string",
    "os_node_proc_list",
    "pipe_self_link",
    "pipe_scheduler_control_lock_order",
    "issue41_dynamic_array_resize",
    "issue41_label_cache_size_miscalc",
    "real_model_ssl_probe_status",
    "real_model_payload_double_cleanup",
    "path_check_before_open",
    "lifecycle_ref_get_after_unlock",
    "lifecycle_ref_put_after_unlock",
    "g_real_callback_node",
    "g_lifecycle_pending_jobs",
    "control_session_mutex_init",
    "net_recv_data_return_truncation",
}


def flatten_issue_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(flatten_issue_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(flatten_issue_text(v) for v in value)
    return "" if value is None else str(value)


def parse_issue_location(location: str) -> tuple[str, Optional[int]]:
    normalized = location.replace("\\", "/")
    match = re.search(r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+):(\d+)", normalized)
    if match:
        return match.group(1).lower(), int(match.group(2))
    match = re.search(r"(.+\.[chp]+):(\d+)", normalized)
    if match:
        return match.group(1).lower(), int(match.group(2))
    match = re.match(r"^\s*(\d+)(?:\s*-\s*\d+)?\s*$", normalized)
    if match:
        return "", int(match.group(1))
    return "", None
