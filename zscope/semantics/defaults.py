"""Load built-in C API semantics from the packaged defaults file."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Any, Dict, Iterable, List

import yaml

from .models import LocalPatternSemantics


DEFAULT_SEMANTICS_SOURCE = "builtin_defaults"
DEFAULT_SEMANTICS_FILE = "defaults.yaml"

_ROLE_TO_CATEGORY = {
    "allocators": "allocator",
    "calloc_allocators": "calloc",
    "reallocators": "reallocator",
    "deallocators": "deallocator",
    "copy_sinks": "copy",
    "lock_apis": "lock",
    "unlock_apis": "unlock",
    "io_acquirers": "io_acquire",
    "io_releasers": "io_release",
    "send_sinks": "send_sink",
    "recv_sources": "recv_source",
    "format_sinks": "format_sink",
    "callback_registrars": "callback_register",
}


@lru_cache(maxsize=1)
def load_default_semantics_data() -> Dict[str, Any]:
    """Return the packaged defaults as a plain dictionary."""

    path = files(__package__).joinpath(DEFAULT_SEMANTICS_FILE)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return raw if isinstance(raw, dict) else {}


def default_local_pattern_semantics() -> LocalPatternSemantics:
    """Return default API roles in the LocalPatternSemantics shape."""

    data = load_default_semantics_data()
    semantics = LocalPatternSemantics()
    aliases = data.get("type_aliases")
    if isinstance(aliases, dict):
        semantics.type_aliases.update(
            {
                str(name).strip(): str(value).strip()
                for name, value in aliases.items()
                if str(name).strip() and str(value).strip()
            }
        )
    roles = data.get("api_roles")
    if isinstance(roles, dict):
        for role_name, category in _ROLE_TO_CATEGORY.items():
            for api in _string_list(roles.get(role_name)):
                semantics.add_api(category, api, DEFAULT_SEMANTICS_SOURCE)
    return semantics


def default_overlay_models() -> Dict[str, List[Dict[str, Any]]]:
    """Return checker-facing overlay rows for built-in API semantics."""

    data = load_default_semantics_data()
    raw_roles = data.get("api_roles")
    roles: Dict[str, Any] = raw_roles if isinstance(raw_roles, dict) else {}
    resources: List[Dict[str, Any]] = []
    locks: List[Dict[str, Any]] = []
    for role_name, category in _ROLE_TO_CATEGORY.items():
        for api in _string_list(roles.get(role_name)):
            model = _api_model(api, category)
            if category in {"lock", "unlock"}:
                locks.append(model)
            else:
                resources.append(model)
    return {
        "resource_models": resources,
        "lock_models": locks,
        "macro_models": [],
    }


def default_checker_api_names(role_name: str) -> List[str]:
    """Return checker-specific default names that should not affect every generator."""

    data = load_default_semantics_data()
    raw_roles = data.get("checker_roles")
    roles: Dict[str, Any] = raw_roles if isinstance(raw_roles, dict) else {}
    return _string_list(roles.get(role_name))


def _api_model(name: str, kind: str) -> Dict[str, Any]:
    return {
        "name": name,
        "kind": kind,
        "symbol_type": "function",
        "carrier": _carrier(kind),
        "source": DEFAULT_SEMANTICS_SOURCE,
    }


def _carrier(kind: str) -> str:
    if kind in {"allocator", "calloc", "reallocator", "resource", "resource_acquire"}:
        return "return_value"
    if kind in {"deallocator", "resource_release"}:
        return "argument_resource"
    if kind == "copy":
        return "copy_arguments"
    if kind in {"lock", "unlock"}:
        return "lock_argument"
    if kind == "io_acquire":
        return "return_value"
    if kind == "io_release":
        return "argument_resource"
    if kind == "send_sink":
        return "copy_arguments"
    if kind == "recv_source":
        return "return_value"
    if kind == "format_sink":
        return "format_arguments"
    if kind == "callback_register":
        return "callback_arguments"
    return "unknown"


def _string_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, Iterable):
        return []
    result: List[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            result.append(text)
    return result
