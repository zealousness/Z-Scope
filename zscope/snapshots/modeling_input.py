"""Resolve canonical function metadata and source for semantic modeling."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


class SemanticModelInputError(RuntimeError):
    """Stable failure raised before an LLM snapshot build can start."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _normalized_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip().lstrip("./")


def _candidate_index_names(matches: Iterable[Dict[str, Any]]) -> List[str]:
    return [
        str(match.get("index_name") or "")
        for match in matches
        if str(match.get("index_name") or "")
    ]


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
        exact = [
            item
            for item in candidates
            if int(item.get("start_line") or 0) == int(start_line)
        ]
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

    matches = list(code_index.find_function_infos(query, file_path=file_hint) or [])
    if not matches and index_hint and index_hint != raw_func_name:
        matches = list(code_index.find_function_infos(raw_func_name, file_path=file_hint) or [])
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
        "callees": list(info.get("callees") or []),
        "referenced_globals": list(info.get("referenced_globals") or []),
        "referenced_macros": list(info.get("referenced_macros") or []),
    }
    for key in (
        "callees_truncation",
        "referenced_globals_truncation",
        "referenced_macros_truncation",
    ):
        if key in info:
            result[key] = info[key]

    return result
