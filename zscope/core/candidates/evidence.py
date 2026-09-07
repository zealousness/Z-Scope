"""Evidence metadata for backend-aware vulnerability candidates.

The candidate layer produces suspicious evidence, not final findings.  This
module keeps backend capabilities and user supplied semantic models visible to
the validator without letting any rule bypass validation.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional

from ...semantics.defaults import default_overlay_models

if TYPE_CHECKING:
    from ...config.user_config_store import UserConfigStore


SUPPORTED_BACKEND_PROFILES = {
    "regex",
    "clang",
    "joern",
    "unified",
    "java_source",
    "java_unified",
}

_RESOURCE_KINDS = {
    "allocator",
    "calloc",
    "reallocator",
    "deallocator",
    "copy",
    "resource",
    "resource_acquire",
    "resource_release",
    "io_acquire",
    "io_release",
    "send_sink",
    "recv_source",
    "format_sink",
    "callback_register",
}
_LOCK_KINDS = {"lock", "unlock"}
_IDENTIFIER_TOKEN_RE = re.compile(r"[A-Za-z_]\w*")


@lru_cache(maxsize=4096)
def _compiled_identifier_token_pattern(needle: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(needle)}\b")


def backend_profile_for_code_index(code_index: Any) -> str:
    """Return the configured evidence profile, normalized to supported values."""

    backend = getattr(code_index, "backend", None)
    if callable(backend):
        try:
            backend = backend()
        except TypeError:
            backend = None
    backend_obj = backend or getattr(code_index, "_backend", None)
    backend_class = type(backend_obj).__name__.lower() if backend_obj is not None else ""
    if "javaunified" in backend_class or "java_unified" in backend_class:
        return "java_unified"
    if "javasource" in backend_class or "java_source" in backend_class:
        return "java_source"
    if "unified" in backend_class:
        return "unified"
    if "joern" in backend_class:
        return "joern"
    if "clang" in backend_class:
        return "clang"

    configured = str(getattr(code_index, "backend_name", "") or "").strip().lower()
    if backend_obj is None:
        return "regex"
    if configured in SUPPORTED_BACKEND_PROFILES:
        return configured
    if configured == "svf":
        return "unified"
    return "regex"


def evidence_engines_for_profile(profile: str) -> List[str]:
    """List evidence engines that should be available for a backend profile."""

    profile = str(profile or "").strip().lower()
    if profile == "unified":
        return [
            "clang_ast_cfg_checker",
            "clang_knowledgedb_callgraph_checker",
            "svf_value_flow_checker",
            "saber_memory_signal_adapter",
        ]
    if profile == "clang":
        return ["clang_ast_cfg_checker", "clang_knowledgedb_callgraph_checker"]
    if profile == "joern":
        return ["joern_cpg_query_checker"]
    if profile == "java_unified":
        return [
            "java_source_structure_checker",
            "java_framework_ir_checker",
            "java_signal_provider_adapter",
        ]
    if profile == "java_source":
        return ["java_source_structure_checker", "java_framework_ir_checker"]
    return ["regex_fallback_checker"]


class SemanticOverlayCompiler:
    """Compile user configuration rows into checker-facing semantic models."""

    def __init__(self, user_config: "UserConfigStore"):
        self.user_config = user_config
        self._query_attempts = 0
        self._query_errors: List[Dict[str, str]] = []

    def compile(self) -> Dict[str, Any]:
        self._query_attempts = 0
        self._query_errors = []
        defaults = default_overlay_models()
        resources: List[Dict[str, Any]] = list(defaults.get("resource_models") or [])
        locks: List[Dict[str, Any]] = list(defaults.get("lock_models") or [])
        macros: List[Dict[str, Any]] = list(defaults.get("macro_models") or [])

        for row in self._safe_rows("list_external_functions"):
            model = self._symbol_model(row)
            if not model.get("name"):
                continue
            kind = str(model.get("kind") or "").lower()
            symbol_type = str(model.get("symbol_type") or "").lower()
            if kind in _RESOURCE_KINDS:
                resources.append(model)
            if kind in _LOCK_KINDS:
                locks.append(model)
            if "macro" in symbol_type:
                macros.append(model)

        for row in self._safe_rows("list_paired_functions"):
            resources.extend(self._paired_models(row, role="resource"))
            locks.extend(self._paired_models(row, role="lock"))

        overlay: Dict[str, Any] = {
            "resource_models": self._dedupe_models(resources),
            "lock_models": self._dedupe_models(locks),
            "macro_models": self._dedupe_models(macros),
            "dispatcher_models": self._sanitize_rows(self._safe_rows("list_dispatchers")),
            "lifecycle_models": self._sanitize_rows(self._safe_rows("list_module_lifecycle")),
            "pointer_target_models": self._sanitize_rows(self._safe_rows("get_pointer_targets")),
            "function_intent_models": self._sanitize_rows(self._safe_rows("list_function_intents")),
        }
        if not self._query_errors:
            engine_status = "complete"
        elif len(self._query_errors) >= self._query_attempts:
            engine_status = "failed"
        else:
            engine_status = "degraded"
        overlay["engine_status"] = engine_status
        overlay["engine_errors"] = list(self._query_errors)
        overlay["summary"] = overlay_summary(overlay)
        return overlay

    def _safe_rows(self, method_name: str) -> List[Dict[str, Any]]:
        method = getattr(self.user_config, method_name, None)
        if not callable(method):
            return []
        self._query_attempts += 1
        try:
            rows = method()
            if rows is None:
                return []
            if not isinstance(rows, (list, tuple)):
                rows = list(rows)
        except Exception as exc:
            self._query_errors.append(
                {
                    "operation": method_name,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            return []
        return [dict(row) for row in rows if isinstance(row, dict)]

    def _symbol_model(self, row: Dict[str, Any]) -> Dict[str, Any]:
        memory_behavior = _jsonish(row.get("memory_behavior"))
        concurrency_behavior = _jsonish(row.get("concurrency_behavior"))
        kind = str(row.get("kind") or "").strip().lower()
        return {
            "name": str(row.get("func_name") or row.get("symbol_name") or "").strip(),
            "kind": kind,
            "symbol_type": str(row.get("symbol_type") or "function").strip() or "function",
            "carrier": self._carrier(kind, memory_behavior, concurrency_behavior),
            "pair": str(row.get("pair") or row.get("release_func") or row.get("acquire_func") or "").strip(),
            "description": str(row.get("description") or "").strip(),
            "source": str(row.get("source") or "user_config").strip() or "user_config",
            "memory_behavior": memory_behavior,
            "concurrency_behavior": concurrency_behavior,
            "return_semantics": str(row.get("return_semantics") or "").strip(),
        }

    def _paired_models(self, row: Dict[str, Any], *, role: str) -> List[Dict[str, Any]]:
        category = str(row.get("category") or "").lower()
        is_lock = any(word in category for word in ("lock", "mutex", "rwlock", "spin", "sync"))
        if role == "lock" and not is_lock:
            return []
        if role == "resource" and is_lock:
            return []
        acquire = str(row.get("acquire_func") or "").strip()
        release = str(row.get("release_func") or "").strip()
        description = str(row.get("description") or "").strip()
        if role == "lock":
            return [
                self._paired_model(acquire, "lock", release, description),
                self._paired_model(release, "unlock", acquire, description),
            ]
        return [
            self._paired_model(acquire, "resource_acquire", release, description),
            self._paired_model(release, "resource_release", acquire, description),
        ]

    def _paired_model(self, name: str, kind: str, pair: str, description: str) -> Dict[str, Any]:
        return {
            "name": name,
            "kind": kind,
            "symbol_type": "function",
            "carrier": self._carrier(kind, {}, {}),
            "pair": pair,
            "description": description,
            "source": "user_config:paired_functions",
            "memory_behavior": {},
            "concurrency_behavior": {},
            "return_semantics": "",
        }

    @staticmethod
    def _carrier(kind: str, memory_behavior: Dict[str, Any], concurrency_behavior: Dict[str, Any]) -> str:
        kind = str(kind or "").lower()
        if memory_behavior.get("caller_owns_return") or kind in {"allocator", "calloc", "reallocator", "resource", "resource_acquire"}:
            return "return_value"
        if memory_behavior.get("releases") or kind in {"deallocator", "resource_release"}:
            return "argument_resource"
        if memory_behavior.get("copies_memory") or kind == "copy":
            return "copy_arguments"
        if concurrency_behavior.get("acquires_lock") or kind == "lock":
            return "lock_argument"
        if concurrency_behavior.get("releases_lock") or kind == "unlock":
            return "lock_argument"
        return "unknown"

    @staticmethod
    def _dedupe_models(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        result = []
        for row in rows:
            name = str(row.get("name") or "").strip()
            kind = str(row.get("kind") or "").strip()
            if not name:
                continue
            key = (name, kind)
            if key in seen:
                continue
            seen.add(key)
            result.append(_compact_row(row))
        return result

    @staticmethod
    def _sanitize_rows(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [_compact_row(row) for row in rows]


def overlay_summary(overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact overlay summary suitable for reports and prompts."""

    resource_models = _as_list(overlay.get("resource_models"))
    lock_models = _as_list(overlay.get("lock_models"))
    macro_models = _as_list(overlay.get("macro_models"))
    dispatcher_models = _as_list(overlay.get("dispatcher_models"))
    lifecycle_models = _as_list(overlay.get("lifecycle_models"))
    pointer_target_models = _as_list(overlay.get("pointer_target_models"))
    function_intent_models = _as_list(overlay.get("function_intent_models"))
    return {
        "resource_model_count": len(resource_models),
        "lock_model_count": len(lock_models),
        "macro_model_count": len(macro_models),
        "dispatcher_count": len(dispatcher_models),
        "lifecycle_count": len(lifecycle_models),
        "pointer_target_count": len(pointer_target_models),
        "function_intent_count": len(function_intent_models),
        "resource_names": _names(resource_models),
        "lock_names": _names(lock_models),
        "macro_names": _names(macro_models),
    }


def relevant_overlay_models(issue: Dict[str, Any], overlay: Dict[str, Any], limit: int = 16) -> Dict[str, Any]:
    """Select user-config models directly referenced by a candidate."""

    haystack = _issue_haystack(issue)
    relevant: Dict[str, Any] = {}
    selections = {
        "resource_models": _matching_named_rows(_as_list(overlay.get("resource_models")), haystack, limit),
        "lock_models": _matching_named_rows(_as_list(overlay.get("lock_models")), haystack, limit),
        "macro_models": _matching_named_rows(_as_list(overlay.get("macro_models")), haystack, limit),
        "pointer_target_models": _matching_pointer_rows(_as_list(overlay.get("pointer_target_models")), haystack, limit),
        "dispatcher_models": _matching_any_rows(_as_list(overlay.get("dispatcher_models")), haystack, limit),
        "lifecycle_models": _matching_any_rows(_as_list(overlay.get("lifecycle_models")), haystack, limit),
        "function_intent_models": _matching_any_rows(_as_list(overlay.get("function_intent_models")), haystack, limit),
    }
    for key, rows in selections.items():
        if rows:
            relevant[key] = rows
    return relevant


def annotate_candidate_evidence(
    issue: Dict[str, Any],
    *,
    backend_profile: str,
    checker: str,
    overlay: Optional[Dict[str, Any]] = None,
    evidence_engines: Optional[List[str]] = None,
    path_kind: str = "local",
) -> Dict[str, Any]:
    """Attach evidence-only metadata to a candidate issue in-place."""

    profile = backend_profile if backend_profile in SUPPORTED_BACKEND_PROFILES else "regex"
    engines = list(evidence_engines or evidence_engines_for_profile(profile))
    overlay = overlay or {}
    overlay_brief = overlay_summary(overlay or {})
    overlay_evidence = relevant_overlay_models(issue, overlay)
    metadata = {
        "schema": "candidate_evidence_v1",
        "backend_profile": profile,
        "checker": checker,
        "evidence_engines": engines,
        "semantic_overlays": overlay_brief,
        "semantic_overlay_evidence": overlay_evidence,
        "path_kind": path_kind,
        "candidate_is_conclusion": False,
        "validation_required": True,
    }
    issue["candidate_evidence_schema"] = metadata["schema"]
    issue["backend_profile"] = profile
    issue["evidence_checker"] = checker
    issue["evidence_engines"] = engines
    issue["semantic_overlays"] = overlay_brief
    issue["semantic_overlay_evidence"] = overlay_evidence
    issue["validation_required"] = True
    issue["must_validate"] = True
    issue.setdefault("candidate_role", "evidence_only")

    pack = issue.get("evidence_pack")
    if not isinstance(pack, dict):
        pack = {}
        issue["evidence_pack"] = pack
    pack.update(metadata)
    pack.setdefault("candidate_source", issue.get("candidate_source") or issue.get("finding_kind"))
    pack.setdefault("validation_notes", [])
    notes = pack["validation_notes"]
    if isinstance(notes, list):
        note = "Candidate evidence must be independently verified by the Validator Agent."
        if note not in notes:
            notes.append(note)
    return issue


def _issue_haystack(issue: Dict[str, Any]) -> str:
    fields = [
        issue.get("id"),
        issue.get("candidate_id"),
        issue.get("function"),
        issue.get("location"),
        issue.get("rule"),
        issue.get("description"),
        issue.get("root_cause"),
        issue.get("source"),
        issue.get("sink"),
        issue.get("positive_evidence"),
        issue.get("negative_evidence"),
        issue.get("evidence_pack"),
    ]
    return "\n".join(
        json.dumps(field, ensure_ascii=False, sort_keys=True, default=str)
        for field in fields
        if field
    )


def _matching_named_rows(rows: List[Dict[str, Any]], haystack: str, limit: int) -> List[Dict[str, Any]]:
    matches = []
    for row in rows:
        name = str(row.get("name") or row.get("func_name") or row.get("symbol_name") or "").strip()
        pair = str(row.get("pair") or "").strip()
        if (name and _contains_token(haystack, name)) or (pair and _contains_token(haystack, pair)):
            matches.append(row)
        if len(matches) >= limit:
            break
    return matches


def _matching_pointer_rows(rows: List[Dict[str, Any]], haystack: str, limit: int) -> List[Dict[str, Any]]:
    matches = []
    for row in rows:
        pointer_location = str(row.get("pointer_location") or "").strip()
        targets = _target_values(row.get("target_functions"))
        if (pointer_location and pointer_location in haystack) or any(_contains_token(haystack, target) for target in targets):
            matches.append(row)
        if len(matches) >= limit:
            break
    return matches


def _matching_any_rows(rows: List[Dict[str, Any]], haystack: str, limit: int) -> List[Dict[str, Any]]:
    matches = []
    for row in rows:
        values = [
            row.get("func_name"),
            row.get("symbol_name"),
            row.get("dispatcher_name"),
            row.get("handler_name"),
        ]
        if any(value and _contains_token(haystack, str(value)) for value in values):
            matches.append(row)
        if len(matches) >= limit:
            break
    return matches


def _target_values(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        parsed = [part.strip() for part in str(value).split(",")]
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    return [str(parsed).strip()] if str(parsed).strip() else []


def _contains_token(haystack: str, needle: str) -> bool:
    if not needle:
        return False
    if not _IDENTIFIER_TOKEN_RE.fullmatch(needle):
        return needle in haystack
    return bool(_compiled_identifier_token_pattern(needle).search(haystack))


def _jsonish(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, json.JSONDecodeError):
        return {"text": str(value)}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _compact_row(row: Dict[str, Any]) -> Dict[str, Any]:
    kept: Dict[str, Any] = {}
    for key, value in row.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str) and len(value) > 300:
            kept[key] = value[:297] + "..."
        else:
            kept[key] = value
    return kept


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _names(rows: List[Dict[str, Any]], limit: int = 96) -> List[str]:
    names = []
    for row in rows:
        name = str(row.get("name") or row.get("func_name") or row.get("symbol_name") or "").strip()
        if name and name not in names:
            names.append(name)
        if len(names) >= limit:
            break
    return names
