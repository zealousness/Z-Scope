"""Opt-in observation schema and process-local source bindings, never proof."""

from __future__ import annotations

import hashlib
import json
import math
import re
import weakref
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ..agents.semantic_modeler.schema import (
    DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
    SUSPICIOUS_POINT_CATEGORY_ENUM,
)
from ..framework.base import validate_function_arguments
from ..semantics.contract_conditions import evaluate, predicate_errors
from ..semantics.contracts import SymbolIdentity, code_tokens
from ..tools.source_access import ProjectSourceAccess, SourceAccessError


OBSERVATION_SCHEMA_VERSION = "zscope.snapshot_observation.v1"
VIOLATED_PROPERTIES = (
    "resource_not_released",
    "use_after_release",
    "double_release",
    "bounds_not_established",
    "ownership_not_established",
    "lock_not_balanced",
    "error_path_cleanup_missing",
)
OBSERVATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "category",
        "lines",
        "source_anchor",
        "description",
        "object",
        "source",
        "sink",
        "violated_property",
        "conditions",
        "missing_facts",
        "ownership",
        "exit_kind",
    ],
    "properties": {
        "schema_version": {"const": OBSERVATION_SCHEMA_VERSION},
        "category": {"enum": SUSPICIOUS_POINT_CATEGORY_ENUM},
        "lines": {"type": "string", "minLength": 1, "maxLength": 64},
        "source_anchor": {"type": "string", "minLength": 1, "maxLength": 2000},
        "description": {"type": "string", "minLength": 1, "maxLength": 2000},
        "object": {"type": "string", "maxLength": 256},
        "source": {"type": "string", "maxLength": 256},
        "sink": {"type": "string", "maxLength": 256},
        "violated_property": {"enum": list(VIOLATED_PROPERTIES)},
        "conditions": {"$ref": "#/$defs/predicate"},
        "missing_facts": {
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "items": {"type": "string", "minLength": 1, "maxLength": 128},
        },
        "ownership": {
            "enum": ["unknown", "caller_retains", "returned_to_caller", "transferred", "borrowed"]
        },
        "exit_kind": {"enum": ["ordinary", "return", "error"]},
    },
    "$defs": deepcopy(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["$defs"]),
}


def conditional_snapshot_schema(
    base_schema: Mapping[str, Any], mode: str = "off"
) -> dict[str, Any]:
    if mode not in {"off", "shadow"}:
        raise ValueError("snapshot observation mode must be off or shadow")
    result = deepcopy(dict(base_schema))
    if mode == "off":
        return result
    item = deepcopy(OBSERVATION_SCHEMA)
    definitions = item.pop("$defs")
    result.setdefault("$defs", {}).update(definitions)
    result.setdefault("properties", {})["conditional_observations"] = {
        "type": "array",
        "maxItems": 16,
        "items": item,
        "description": "Optional shadow investigation leads, never verdicts. Use [] unless an explicit source object/site, violated property, conditional predicate and missing facts are identifiable. Keep vague concerns only in suspicious_points. source_anchor must quote the exact source statement. Do not claim effects_trusted or proof.",
    }
    if "conditional_observations" not in result.setdefault("required", []):
        result["required"].append("conditional_observations")
    return result


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def source_rows(snapshot: Mapping[str, Any]) -> dict[int, str]:
    start = snapshot.get("start_line")
    if type(start) is not int or start < 1:
        raise ValueError("snapshot_source_range_unverifiable")
    rows = {}
    for offset, raw in enumerate(str(snapshot.get("code") or "").splitlines()):
        match = re.fullmatch(r"\s*(\d+)\s*\| ?(.*)", raw)
        line = int(match[1]) if match else start + offset
        if line < start or line in rows:
            raise ValueError("snapshot_source_range_unverifiable")
        rows[line] = match[2] if match else raw
    if not rows:
        raise ValueError("snapshot_source_unavailable")
    return rows


@dataclass(frozen=True, eq=False)
class ObservationBinding:
    symbol: str
    snapshot_hash: str
    modeling_spec: str
    schema_hash: str
    contract_version: str
    project_root: str
    file_path: str
    source_revision: str
    input_identity: str
    current_inputs: Callable[[], str | None]


_LIVE_BINDINGS: weakref.WeakSet[ObservationBinding] = weakref.WeakSet()


def bind_snapshot_observation(
    snapshot: Mapping[str, Any],
    *,
    symbol: str,
    modeling_spec: str,
    source_context: Mapping[str, Any],
    contract_version: str,
    project_root: str | Path,
    current_inputs: Callable[[], str | None] | None = None,
    expected_inputs: str | None = None,
) -> ObservationBinding | None:
    """Called only at the current modeling publication barrier, not JSON load."""
    if (
        not symbol
        or not modeling_spec
        or "conditional_observations" not in snapshot
        or not callable(current_inputs)
        or not expected_inputs
    ):
        return None
    try:
        if current_inputs() != expected_inputs:
            return None
        if SymbolIdentity.from_value(dict(snapshot)).key != symbol:
            return None
        file_path = str(snapshot.get("file_path") or "").replace("\\", "/")
        context_file = str(
            source_context.get("file_path") or source_context.get("file") or ""
        ).replace("\\", "/")
        if (
            not file_path
            or file_path != context_file
            or source_rows(snapshot) != source_rows(source_context)
        ):
            return None
        if any(
            snapshot.get(name) != source_context.get(name)
            for name in ("func_name", "signature", "start_line", "end_line")
        ):
            return None
        access = ProjectSourceAccess(Path(project_root))
        text, revision, _stat = access.read(file_path)
        lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
        if any(
            line > len(lines) or lines[line - 1] != value
            for line, value in source_rows(snapshot).items()
        ):
            return None
        binding = ObservationBinding(
            symbol,
            _digest(snapshot),
            modeling_spec,
            _digest(OBSERVATION_SCHEMA),
            contract_version,
            str(Path(project_root).resolve()),
            file_path,
            revision,
            expected_inputs,
            current_inputs,
        )
        _LIVE_BINDINGS.add(binding)
        return binding
    except (ValueError, TypeError, SourceAccessError, OSError):
        return None


def check_observation_binding(
    binding: Any,
    snapshot: Mapping[str, Any],
    *,
    symbol: str,
    contract_version: str,
    project_root: str | Path,
) -> str:
    if not isinstance(binding, ObservationBinding) or binding not in _LIVE_BINDINGS:
        return "snapshot_binding_unavailable"
    if (
        binding.symbol != symbol
        or binding.snapshot_hash != _digest(snapshot)
        or binding.contract_version != contract_version
        or binding.schema_hash != _digest(OBSERVATION_SCHEMA)
    ):
        return "snapshot_binding_changed"
    if binding.project_root != str(Path(project_root).resolve()):
        return "snapshot_project_mismatch"
    try:
        revision = ProjectSourceAccess(Path(project_root)).read(binding.file_path)[1]
    except (SourceAccessError, ValueError, OSError):
        return "snapshot_source_unavailable"
    if revision != binding.source_revision:
        return "snapshot_source_changed"
    try:
        current = binding.current_inputs()
    except Exception:
        return "snapshot_inputs_unverifiable"
    if not current:
        return "snapshot_inputs_unverifiable"
    return "current" if current == binding.input_identity else "snapshot_inputs_changed"


def observation_project_inputs(
    project_root: str | Path,
    *,
    excluded: Iterable[str | Path] = (),
    required_paths: Iterable[str | Path] = (),
) -> str | None:
    """Bounded local input receipt, not a TU or effects certificate.

    The initial scope deliberately excludes compiled TU databases, Java class
    paths and unresolved/external includes. It also rejects incomplete scans;
    a partial corpus is never called current.
    Callers add their mutable model/schema/publication identity separately.
    """
    access = ProjectSourceAccess(Path(project_root), excluded=excluded)
    try:
        view = access._scan("files", "", "")
        if view["missing"]:
            return None
        if any(
            not directory and Path(path).suffix.lower() in {".java", ".jar", ".class"}
            for path, directory, _identity in view["watched"]
        ):
            return None
        files = {row["file"]: row["revision"] for row in view["matches"]}
        for value in required_paths:
            path = Path(value)
            absolute = path if path.is_absolute() else access.root / path
            relative = absolute.resolve().relative_to(access.root).as_posix()
            if relative not in files and not absolute.is_dir():
                return None
            if not access.allowed(relative):
                return None
        if any(Path(relative).name == "compile_commands.json" for relative in files):
            # No independently current TU receipt is available to this adapter.
            # A database's own bytes do not bind response files, preincludes,
            # sysroots or compiler identity. Do not invent another TU parser.
            return None
        # Program includes are inputs even when no declaration was referenced
        # in the model context. Missing/project-external includes fail closed.
        for relative, expected in files.items():
            if Path(relative).suffix.lower() not in {
                ".c",
                ".cc",
                ".cpp",
                ".cxx",
                ".h",
                ".hh",
                ".hpp",
                ".hxx",
                ".inc",
            }:
                continue
            text, revision, _ = access.read(relative)
            if revision != expected:
                return None
            for line in text.splitlines():
                if not re.match(r"\s*#\s*include\b", line):
                    continue
                match = re.match(r'\s*#\s*include\s*[<"]([^>"]+)[>"]', line)
                if not match:
                    return None
                candidates = (Path(relative).parent / match[1], Path(match[1]))
                if not any(candidate.as_posix() in files for candidate in candidates):
                    return None
        if not access._unchanged(view):
            return None
        # Only hashes leave this helper. Include environment identity using the
        # existing native compiler convention, without executing any tool.
        from ..retrieval.indexing_identity import environment_identity

        environment = environment_identity()
        if environment:
            # Stable environment strings do not bind external header/toolchain
            # contents. Implicit compiler inputs need a future verified receipt.
            return None
        return _digest({"files": files, "environment": environment})
    except (OSError, ValueError, TypeError, SourceAccessError):
        return None


def observation_qualification(
    point: Any, snapshot: Mapping[str, Any]
) -> tuple[int | None, str, str]:
    """Return a source-bound lead, not path feasibility or property proof."""
    if (
        validate_function_arguments(OBSERVATION_SCHEMA, point)
        or point.get("schema_version") != OBSERVATION_SCHEMA_VERSION
    ):
        return None, "invalid_observation_schema", "unknown"
    condition = point["conditions"]
    if (
        not _bounded_predicate(condition)
        or predicate_errors(condition)
        or condition.get("op") == "unknown"
    ):
        return None, "condition_unresolved", "unknown"
    # No model-supplied facts are passed to the evaluator. This only folds
    # literal predicates; a symbolic condition stays unknown for validation.
    applicability = evaluate(condition)
    if applicability == "does_not_apply":
        return None, "condition_impossible", applicability
    if not re.fullmatch(r"[1-9]\d*", point["lines"]):
        return None, "observation_location_unresolved", applicability
    line = int(point["lines"])
    rows = source_rows(snapshot)
    anchor = code_tokens(point["source_anchor"])
    if not anchor or line not in rows or code_tokens(rows[line]) != anchor:
        return None, "observation_anchor_mismatch", applicability
    identities = [point["object"]] if point["object"] else [point["source"], point["sink"]]
    source = [token for row in rows.values() for token in code_tokens(row)]
    for value in identities:
        tokens = code_tokens(value)
        if (
            not value
            or not tokens
            or not any(re.fullmatch(r"[A-Za-z_]\w*", token) for token in tokens)
            or not any(
                source[index : index + len(tokens)] == tokens for index in range(len(source))
            )
        ):
            return None, "observation_object_unresolved", applicability
    if point["exit_kind"] in {"return", "error"} and not any(
        token in anchor for token in ("return", "goto", "throw")
    ):
        return None, "observation_exit_unresolved", applicability
    if (
        point["ownership"] == "returned_to_caller"
        and point["violated_property"] == "resource_not_released"
        and anchor == ["return", *code_tokens(point["object"]), ";"]
    ):
        return None, "return_ownership_requires_caller_scope", applicability
    return line, "eligible_shadow_observation", applicability


def _bounded_predicate(value: Any) -> bool:
    """Validate recursive refs explicitly; the common tool validator is a subset."""
    pending = [(value, 0)]
    count = 0
    operand = OBSERVATION_SCHEMA["$defs"]["operand"]
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 64 or depth > 8 or not isinstance(node, dict):
            return False
        op = node.get("op")
        if not isinstance(op, str):
            return False
        fields = {
            "true": {"op"},
            "false": {"op"},
            "unknown": {"op"},
            "compare": {"op", "left", "right", "operator"},
            "all": {"op", "items"},
            "any": {"op", "items"},
            "not": {"op", "item"},
        }.get(op)
        if fields is None or set(node) != fields:
            return False
        if op == "compare":
            if any(validate_function_arguments(operand, node[side]) for side in ("left", "right")):
                return False
            if not isinstance(node["operator"], str) or node["operator"] not in {
                "==",
                "!=",
                "<",
                "<=",
                ">",
                ">=",
            }:
                return False
            if any(
                isinstance(node[side].get("value"), float)
                and not math.isfinite(node[side]["value"])
                for side in ("left", "right")
            ):
                return False
        elif op in {"all", "any"}:
            if not isinstance(node["items"], list) or not node["items"]:
                return False
            pending.extend((item, depth + 1) for item in node["items"])
        elif op == "not":
            pending.append((node["item"], depth + 1))
    return True
