"""Relevant user-config context extraction for analysis prompts."""

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any, List


def relevant_user_config_context(
    user_config: Any,
    entry_func: str,
    code: str,
    file_path: str = "",
) -> str:
    """Return only user-config rows referenced by the current function."""
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code or ""))
    identifiers.add(entry_func)
    parts: List[str] = []

    external_lines = []
    for item in user_config.list_external_functions():
        name = str(item.get("func_name") or "")
        if name not in identifiers:
            continue
        summary = str(item.get("description") or "").strip()
        memory = str(item.get("memory_behavior") or "").strip()
        concurrency = str(item.get("concurrency_behavior") or "").strip()
        details = ", ".join(part for part in (summary, memory, concurrency) if part)
        external_lines.append(f"  {name}: {details}" if details else f"  {name}")
    if external_lines:
        parts.append("[Relevant user-config API semantics]\n" + "\n".join(external_lines))

    pair_lines = []
    for pair in user_config.list_paired_functions():
        acquire = str(pair.get("acquire_func") or "")
        release = str(pair.get("release_func") or "")
        if acquire not in identifiers and release not in identifiers:
            continue
        desc = str(pair.get("description") or "").strip()
        suffix = f" ({desc})" if desc else ""
        pair_lines.append(
            f"  {pair.get('category', 'pair')}: {acquire} <-> {release}{suffix}"
        )
    if pair_lines:
        parts.append("[Relevant user-config pairs]\n" + "\n".join(pair_lines))

    pointer_lines = []
    for target in user_config.get_pointer_targets():
        if not user_config_scope_matches(str(target.get("scope") or "*"), file_path):
            continue
        pointer_location = str(target.get("pointer_location") or "")
        target_functions = parse_user_config_list(target.get("target_functions"))
        if (
            pointer_location not in code
            and pointer_location not in identifiers
            and not identifiers.intersection(target_functions)
        ):
            continue
        pointer_lines.append(
            f"  {pointer_location} -> {', '.join(target_functions)}"
            + (f" (scope: {target.get('scope')})" if target.get("scope") else "")
        )
    if pointer_lines:
        parts.append("[Relevant user-config function pointers]\n" + "\n".join(pointer_lines))

    dispatcher_lines = []
    list_dispatchers = getattr(user_config, "list_dispatchers", None)
    if callable(list_dispatchers):
        for row in list_dispatchers():
            if not user_config_scope_matches(str(row.get("file_path") or "*"), file_path):
                continue
            dispatcher = str(row.get("dispatcher_name") or "")
            handler = str(row.get("handler_name") or "")
            pair = str(row.get("pair") or "")
            if dispatcher not in identifiers and handler not in identifiers and pair not in identifiers:
                continue
            fields = [
                f"message={row.get('message_type', '')}",
                f"handler={handler}",
                f"kind={row.get('handler_kind', '')}",
                f"resource={row.get('resource', '')}",
            ]
            if pair:
                fields.append(f"pair={pair}")
            desc = str(row.get("description") or "").strip()
            dispatcher_lines.append(
                f"  {dispatcher}: " + ", ".join(fields) + (f" ({desc})" if desc else "")
            )
    if dispatcher_lines:
        parts.append("[Relevant user-config dispatcher branches]\n" + "\n".join(dispatcher_lines))

    lifecycle_lines = []
    list_module_lifecycle = getattr(user_config, "list_module_lifecycle", None)
    if callable(list_module_lifecycle):
        for row in list_module_lifecycle():
            if not user_config_scope_matches(str(row.get("file_path") or "*"), file_path):
                continue
            name = str(row.get("symbol_name") or "")
            pair = str(row.get("pair") or "")
            if name not in identifiers and pair not in identifiers:
                continue
            lifecycle_lines.append(
                f"  {name}: kind={row.get('kind', '')}, pair={pair}, "
                f"needs_finit={row.get('needs_finit', '')}, "
                f"error_path_cleanup_required={row.get('error_path_cleanup_required', '')}, "
                f"description={row.get('description', '')}"
            )
    if lifecycle_lines:
        parts.append("[Relevant user-config module lifecycle]\n" + "\n".join(lifecycle_lines))

    intent_ctx = user_config.get_function_intent_context(entry_func, file_path)
    if intent_ctx:
        parts.append(intent_ctx)

    return "\n".join(parts)


def user_config_scope_matches(scope: str, file_path: str) -> bool:
    scope = (scope or "*").replace("\\", "/").strip()
    if scope in {"", "*"}:
        return True
    normalized = str(file_path or "").replace("\\", "/")
    candidates = [normalized, "/" + normalized.lstrip("/")]
    return any(fnmatch.fnmatch(candidate, scope) for candidate in candidates)


def parse_user_config_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return [item.strip() for item in str(value).split(",") if item.strip()]
    if isinstance(parsed, list):
        return [str(item) for item in parsed if item]
    return [str(parsed)]
