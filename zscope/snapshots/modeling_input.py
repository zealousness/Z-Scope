"""Resolve canonical function metadata and source for semantic modeling."""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

_HEADER_LIKE_SUFFIXES = (".h", ".hh", ".hpp", ".hxx", ".ph", ".inc", ".inl")


class SemanticModelInputError(RuntimeError):
    """Stable failure raised before an LLM snapshot build can start."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _normalized_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip().lstrip("./")


def is_header_like_path(value: Any) -> bool:
    """Return whether a path identifies a header or header-like declaration file."""
    return _normalized_path(value).lower().endswith(_HEADER_LIKE_SUFFIXES)


def _candidate_index_names(matches: Iterable[Dict[str, Any]]) -> List[str]:
    return [
        str(match.get("index_name") or "")
        for match in matches
        if str(match.get("index_name") or "")
    ]


def _select_indexed_header_implementation(
    code_index: Any,
    query: str,
    matches: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Use the index's canonical implementation only when it selects one candidate."""
    if len(matches) <= 1:
        return matches
    try:
        impl = code_index.get_function_impl(
            query,
            max_lines=None,
            warn_missing=False,
            include_context=False,
            file_path="",
        )
    except TypeError:
        try:
            impl = code_index.get_function_impl(query)
        except Exception:
            return matches
    except Exception:
        return matches
    selected_index = str((impl or {}).get("index_name") or "").strip()
    if not selected_index:
        return matches
    selected = [
        item for item in matches if str(item.get("index_name") or "").strip() == selected_index
    ]
    return selected if len(selected) == 1 else matches


def _select_unique_match(
    matches: List[Dict[str, Any]],
    *,
    index_name: str,
    file_path: str,
    start_line: Optional[int],
) -> Optional[Dict[str, Any]]:
    candidates = list(matches)
    if index_name:
        exact = [item for item in candidates if str(item.get("index_name") or "") == index_name]
        if exact:
            candidates = exact
    if len(candidates) > 1 and file_path:
        normalized_file = _normalized_path(file_path)
        exact = [
            item
            for item in candidates
            if _normalized_path(item.get("file_path")) == normalized_file
        ]
        if exact:
            candidates = exact
    if len(candidates) > 1 and start_line is not None:
        exact = [item for item in candidates if int(item.get("start_line") or 0) == int(start_line)]
        if exact:
            candidates = exact
    return dict(candidates[0]) if len(candidates) == 1 else None


def resolve_function_info(
    code_index: Any,
    func_name: str,
    *,
    file_path: str = "",
    index_name: str = "",
    start_line: Optional[int] = None,
) -> Dict[str, Any]:
    """Resolve one canonical function-info record or raise a stable error."""

    raw_func_name = str(func_name or "").strip()
    file_hint = str(file_path or "").strip()
    index_hint = str(index_name or "").strip()
    query = index_hint or raw_func_name
    logger.debug(
        "[snapshot-resolve] start query_func=%s file_hint=%s index_hint=%s",
        raw_func_name,
        file_hint,
        index_hint,
    )

    find_metadata = getattr(code_index, "find_function_metadata", code_index.find_function_infos)
    matches = list(find_metadata(query, file_path=file_hint) or [])
    if not matches and index_hint and index_hint != raw_func_name:
        matches = list(find_metadata(raw_func_name, file_path=file_hint) or [])
    if not matches and file_hint and is_header_like_path(file_hint):
        logger.debug(
            "[snapshot-resolve] retrying header declaration without file constraint "
            "query_func=%s file_hint=%s index_hint=%s",
            raw_func_name,
            file_hint,
            index_hint,
        )
        matches = list(find_metadata(query, file_path="") or [])
        if not matches and index_hint and index_hint != raw_func_name:
            matches = list(find_metadata(raw_func_name, file_path="") or [])
        matches = _select_indexed_header_implementation(code_index, query, matches)
    if not matches:
        logger.warning(
            "[snapshot-resolve] function info not found query_func=%s file_hint=%s "
            "index_hint=%s llm_called=false reason=function_info_not_found",
            raw_func_name,
            file_hint,
            index_hint,
        )
        raise SemanticModelInputError(
            "function_info_not_found",
            f"Function info not found for '{raw_func_name or query}'",
        )

    info = _select_unique_match(
        matches,
        index_name=index_hint,
        file_path=file_hint,
        start_line=start_line,
    )
    if info is None:
        candidate_names = _candidate_index_names(matches)
        logger.warning(
            "[snapshot-resolve] ambiguous function info query_func=%s file_hint=%s "
            "index_hint=%s matches=%d candidates=%s llm_called=false "
            "reason=function_info_ambiguous",
            raw_func_name,
            file_hint,
            index_hint,
            len(matches),
            candidate_names[:20],
        )
        raise SemanticModelInputError(
            "function_info_ambiguous",
            f"Function info for '{raw_func_name or query}' matched {len(matches)} definitions",
        )

    resolved_index = str(info.get("index_name") or "").strip()
    resolved_func = str(info.get("function_name") or "").strip()
    resolved_file = str(info.get("file_path") or "").strip()
    resolved_start = int(info.get("start_line") or 0)
    resolved_end = int(info.get("end_line") or 0)
    signature = str(info.get("signature") or "").strip()
    missing = [
        name
        for name, value in (
            ("function_name", resolved_func),
            ("index_name", resolved_index),
            ("file_path", resolved_file),
            ("start_line", resolved_start),
            ("end_line", resolved_end),
            ("signature", signature),
        )
        if not value
    ]
    if missing:
        logger.error(
            "[snapshot-resolve] incomplete function info index_name=%s missing=%s "
            "llm_called=false reason=function_info_incomplete",
            resolved_index or index_hint,
            missing,
        )
        raise SemanticModelInputError(
            "function_info_incomplete",
            f"Function info is missing required fields: {', '.join(missing)}",
        )

    get_types = getattr(code_index, "get_function_type_context", None)
    if callable(get_types) and not info.get("is_macro"):
        from ..retrieval.clang_type_state import TypeContextUnavailable
        try:
            info.update(get_types(resolved_index, resolved_file, resolved_start))
        except TypeContextUnavailable as exc:
            raise SemanticModelInputError("type_context_unavailable", str(exc)) from exc

    logger.debug(
        "[snapshot-resolve] resolved index_name=%s match_count=%d",
        resolved_index,
        len(matches),
    )
    return info


def build_semantic_model_input(
    code_index: Any,
    func_name: str,
    *,
    file_path: str = "",
    index_name: str = "",
    start_line: Optional[int] = None,
    include_context: bool = True,
) -> Dict[str, Any]:
    """Build one canonical SemanticModeler input with the complete function source."""

    info = resolve_function_info(
        code_index,
        func_name,
        file_path=file_path,
        index_name=index_name,
        start_line=start_line,
    )
    resolved_index = str(info["index_name"])
    resolved_func = str(info["function_name"])
    resolved_file = str(info["file_path"])
    resolved_start = int(info["start_line"])
    resolved_end = int(info["end_line"])
    signature = str(info["signature"])

    referenced_types = info.get("referenced_types")
    if not isinstance(referenced_types, list):
        logger.error(
            "[snapshot-resolve] invalid type context index_name=%s field=referenced_types "
            "llm_called=false reason=semantic_model_input_invalid",
            resolved_index,
        )
        raise SemanticModelInputError(
            "semantic_model_input_invalid",
            "Function info is missing required referenced_types array",
        )
    required_type_fields = {
        "type_index_name",
        "kind",
        "full_definition",
        "reference_kinds",
        "reference_lines",
    }
    for item in referenced_types:
        if (
            not isinstance(item, dict)
            or set(item) != required_type_fields
            or not isinstance(item.get("reference_kinds"), list)
            or not isinstance(item.get("reference_lines"), list)
        ):
            logger.error(
                "[snapshot-resolve] invalid type context index_name=%s field=referenced_types.item "
                "llm_called=false reason=semantic_model_input_invalid",
                resolved_index,
            )
            raise SemanticModelInputError(
                "semantic_model_input_invalid",
                "Function info contains an invalid referenced_types item",
            )

    unresolved_types = info.get("unresolved_referenced_types")
    if unresolved_types is not None and (
        not isinstance(unresolved_types, list) or not unresolved_types
    ):
        raise SemanticModelInputError(
            "semantic_model_input_invalid",
            "unresolved_referenced_types must be a non-empty array when present",
        )
    type_truncation = info.get("referenced_types_truncation")
    if type_truncation is not None and not isinstance(type_truncation, dict):
        raise SemanticModelInputError(
            "semantic_model_input_invalid",
            "referenced_types_truncation must be an object when present",
        )

    try:
        impl = code_index.get_function_impl(
            resolved_index,
            max_lines=None,
            warn_missing=False,
            include_context=include_context,
            file_path=resolved_file,
        )
    except TypeError:
        impl = code_index.get_function_impl(resolved_index)
    if not impl:
        logger.warning(
            "[snapshot-resolve] implementation not found index_name=%s llm_called=false "
            "reason=function_impl_not_found",
            resolved_index,
        )
        raise SemanticModelInputError(
            "function_impl_not_found",
            f"Implementation not found for '{resolved_index}'",
        )

    mismatches: List[str] = []
    impl_file = _normalized_path(impl.get("file"))
    if impl_file and impl_file != _normalized_path(resolved_file):
        mismatches.append("file_path")
    impl_start = int(impl.get("start_line") or 0)
    if impl_start and impl_start != resolved_start:
        mismatches.append("start_line")
    impl_index = str(impl.get("index_name") or "").strip()
    if impl_index and impl_index != resolved_index:
        mismatches.append("index_name")
    if mismatches:
        logger.error(
            "[snapshot-resolve] function info/impl mismatch index_name=%s fields=%s "
            "llm_called=false reason=function_info_impl_mismatch",
            resolved_index,
            mismatches,
        )
        raise SemanticModelInputError(
            "function_info_impl_mismatch",
            f"Function info and implementation disagree on: {', '.join(mismatches)}",
        )

    result: Dict[str, Any] = {
        "func_name": resolved_func,
        "index_name": resolved_index,
        "file_path": resolved_file,
        "start_line": resolved_start,
        "end_line": resolved_end,
        "signature": signature,
        "is_static": bool(info.get("is_static")),
        "is_macro": bool(info.get("is_macro")),
        "code": str(impl.get("code") or info.get("code") or ""),
        "project_callees": list(info.get("project_callees") or []),
        "external_callees": list(info.get("external_callees") or []),
        "referenced_globals": list(info.get("referenced_globals") or []),
        "referenced_macros": list(info.get("referenced_macros") or []),
        "referenced_types": deepcopy(referenced_types),
    }
    if info.get("unresolved_callees"):
        result["unresolved_callees"] = list(info["unresolved_callees"])
    for key in (
        "project_callees_truncation",
        "external_callees_truncation",
        "unresolved_callees_truncation",
        "referenced_globals_truncation",
        "referenced_macros_truncation",
        "unresolved_referenced_types",
        "referenced_types_truncation",
    ):
        if key in info:
            result[key] = deepcopy(info[key])

    return result


def hydrate_project_callee_summaries(
    input_data: Dict[str, Any],
    code_index: Any,
    snapshot_store: Any,
    *,
    _visiting: Optional[set[str]] = None,
    _summary_cache: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Fill project callee summaries from current snapshots without invoking an LLM."""

    result = deepcopy(input_data)
    is_top_level = _visiting is None
    visiting = set(_visiting or ())
    current_index = str(result.get("index_name") or "")
    if current_index:
        visiting.add(current_index)
    summary_cache = _summary_cache if _summary_cache is not None else {}
    hydrated: List[Dict[str, Any]] = []

    for raw_callee in list(result.get("project_callees") or []):
        if not isinstance(raw_callee, dict):
            continue
        if "is_macro" in raw_callee:
            raise SemanticModelInputError(
                "snapshot_shape_changed",
                "project_callees contains legacy is_macro field",
            )
        callee = deepcopy(raw_callee)
        index_name = str(callee.get("callee_index_name") or "").strip()
        summary = "unknown"
        if index_name and index_name == current_index:
            snapshot = snapshot_store.load_snapshot(index_name)
            candidate = str(snapshot.get("summary") or "").strip() if snapshot else ""
            if candidate:
                summary = candidate
        elif index_name and index_name not in visiting:
            cached = summary_cache.get(index_name)
            if cached is not None:
                summary = cached
            else:
                snapshot = snapshot_store.load_snapshot(index_name)
                if isinstance(snapshot, dict):
                    try:
                        callee_context = build_semantic_model_input(
                            code_index,
                            index_name,
                            index_name=index_name,
                            include_context=False,
                        )
                        callee_context = hydrate_project_callee_summaries(
                            callee_context,
                            code_index,
                            snapshot_store,
                            _visiting=visiting | {index_name},
                            _summary_cache=summary_cache,
                        )
                        needs_refresh, _reason = snapshot_store.needs_refresh(
                            index_name,
                            str(callee_context.get("code") or ""),
                            callee_context,
                        )
                    except Exception as exc:
                        logger.debug(
                            "Callee summary hydration failed index_name=%s error=%s",
                            index_name,
                            exc,
                        )
                        needs_refresh = True
                    if not needs_refresh:
                        candidate = str(snapshot.get("summary") or "").strip()
                        if candidate:
                            summary = candidate
                summary_cache[index_name] = summary
        callee["callee_summary"] = summary
        hydrated.append(callee)

    result["project_callees"] = hydrated
    reconciler = getattr(snapshot_store, "reconcile_project_callee_summaries", None)
    if (
        is_top_level
        and current_index
        and callable(reconciler)
        and snapshot_store.load_snapshot(current_index)
    ):
        status = reconciler(current_index, result)
        if status in {"failed", "timeout"}:
            raise SemanticModelInputError(
                "callee_summary_reconcile_failed",
                f"Unable to reconcile project callee summaries for {current_index}",
            )
    return result


def hydrate_project_callee_summaries_from_map(
    input_data: Dict[str, Any],
    summary_map: Dict[str, str],
) -> Dict[str, Any]:
    """Hydrate project callee summaries from one frozen canonical summary map."""

    result = deepcopy(input_data)
    hydrated: List[Dict[str, Any]] = []
    for raw_callee in list(result.get("project_callees") or []):
        if not isinstance(raw_callee, dict):
            continue
        if "is_macro" in raw_callee:
            raise SemanticModelInputError(
                "snapshot_shape_changed",
                "project_callees contains legacy is_macro field",
            )
        callee = deepcopy(raw_callee)
        index_name = str(callee.get("callee_index_name") or "").strip()
        summary = str(summary_map.get(index_name) or "").strip()
        callee["callee_summary"] = summary or "unknown"
        hydrated.append(callee)
    result["project_callees"] = hydrated
    return result
