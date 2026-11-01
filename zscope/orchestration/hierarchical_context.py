"""Model projections over the unchanged, admitted deep evidence inventory.

References are not proof receipts. The owner still validates full inputs before
and after each read/publication and hashes full facts for cache invalidation.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Mapping


PROJECTION_VERSION = "zscope.hierarchical-context.v4"


def encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def child_pointer(pointer: str, key: Any) -> str:
    return pointer + "/" + str(key).replace("~", "~0").replace("/", "~1")


def reference(value: Any, unit_id: str, pointer: str) -> dict[str, Any]:
    return {
        "evidence_ref": {
            "unit_id": unit_id,
            "pointer": pointer,
            "sha256": hashlib.sha256(encoded(value).encode()).hexdigest(),
        },
        "kind": (
            "object" if isinstance(value, dict) else "array" if isinstance(value, list) else "text"
        ),
        "count": len(value),
        "coverage": "referenced_only; read_semantic_evidence to inspect; absence is not safety",
    }


def project(value: Any, unit_id: str, pointer: str, allowance: int = 12000) -> Any:
    """Keep small data intact; large fields become exact, readable references."""
    if len(encoded(value)) <= allowance:
        return deepcopy(value)
    if isinstance(value, dict) and len(value) <= 32:
        # Preserve status/identity/gaps even when a sibling contains a huge AST.
        remaining = allowance
        result = {}
        for key, item in value.items():
            size = len(encoded(item))
            if size <= max(256, remaining):
                result[key] = deepcopy(item)
                remaining -= size
            else:
                result[key] = reference(item, unit_id, child_pointer(pointer, key))
        return result
    return reference(value, unit_id, pointer)


def unit_view(unit: Mapping[str, Any]) -> dict[str, Any]:
    if unit["level"] != "function":
        return deepcopy(dict(unit))
    result = {k: deepcopy(v) for k, v in unit.items() if k != "facts"}
    facts = unit["facts"]
    shown: dict[str, Any] = {}
    for key, value in facts.items():
        pointer = child_pointer("/facts", key)
        if key == "build_context" and isinstance(value, dict):
            # Keep receipt state explicit. Full command/dependency/include-probe
            # receipts remain authoritative on the program side and retrievable.
            shown[key] = {
                **reference(value, unit["id"], pointer),
                **{
                    k: deepcopy(value[k])
                    for k in (
                        "build_context_id",
                        "command_id",
                        "status",
                        "dependencies_complete",
                    )
                    if k in value
                },
            }
        elif key == "functions" and isinstance(value, list):
            shown[key] = [
                project(
                    body, unit["id"], child_pointer(pointer, index), 12000 // max(1, len(value))
                )
                for index, body in enumerate(value)
            ]
        elif (
            key == "events"
            and isinstance(value, list)
            and value
            == [event for body in facts.get("functions", []) for event in body.get("events", [])]
        ):
            shown[key] = {
                **reference(value, unit["id"], pointer),
                "also_in": "/facts/functions/*/events",
            }
        else:
            shown[key] = project(value, unit["id"], pointer)
    result["facts"] = shown
    result["citation_format"] = unit["id"] + ":<absolute source line>"
    result["projection_version"] = PROJECTION_VERSION
    return result


def read_evidence(unit: Mapping[str, Any], pointer: str, offset: int, limit: int) -> dict[str, Any]:
    """Page any original field; never flatten list/object identities or drop gaps."""
    if not pointer.startswith("/") or offset < 0 or not 1 <= limit <= 32:
        raise ValueError("expected JSON pointer, nonnegative offset and limit 1..32")
    value: Any = unit
    for part in pointer.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value[part]
        elif isinstance(value, list) and part.isdigit():
            value = value[int(part)]
        else:
            raise ValueError("unknown evidence pointer")
    unit_id = unit["id"]
    data: Any  # Pages preserve the selected JSON value's array/text/scalar shape.
    if isinstance(value, (dict, list)):
        keys = list(value) if isinstance(value, dict) else list(range(len(value)))
        selected = keys[offset : offset + limit]
        data = [
            {
                "pointer": child_pointer(pointer, key),
                "value": project(
                    value[key], unit_id, child_pointer(pointer, key), 12000 // max(1, len(selected))
                ),
            }
            for key in selected
        ]
        next_offset = offset + len(selected)
        total = len(keys)
    elif isinstance(value, str):
        data = value[offset : offset + 12000]
        next_offset = offset + len(data)
        total = len(value)
    else:
        data, next_offset, total = value, 1, 1
    return {
        "success": True,
        "unit_id": unit_id,
        "build_context_id": unit["build_context_id"],
        "usr": unit["usr"],
        "pointer": pointer,
        "sha256": hashlib.sha256(encoded(value).encode()).hexdigest(),
        "data": data,
        "page": {
            "offset": offset,
            "next_offset": next_offset,
            "total": total,
            "has_more": next_offset < total,
        },
        "coverage": "page_only; nested references require additional reads",
    }
