"""Validate every level of the semantic modeler's published JSON schema."""

from __future__ import annotations

import json
import re
from typing import Any


def schema_errors(
    value: Any,
    schema: dict[str, Any],
    *,
    root: dict[str, Any] | None = None,
    path: str = "function_snapshot",
) -> list[str]:
    root = root or schema
    if "$ref" in schema:
        ref = str(schema["$ref"])
        target: Any = root
        if not ref.startswith("#/"):
            return [f"{path}: unsupported schema reference"]
        for part in ref[2:].split("/"):
            target = target.get(part) if isinstance(target, dict) else None
        return (
            schema_errors(value, target, root=root, path=path)
            if isinstance(target, dict)
            else [f"{path}: unknown schema reference"]
        )
    errors = []
    for union in ("anyOf", "oneOf"):
        if union in schema:
            matches = sum(
                not schema_errors(value, child, root=root, path=path) for child in schema[union]
            )
            if not matches or union == "oneOf" and matches != 1:
                return [f"{path}: does not match {union}"]
    types = schema.get("type")
    types = [types] if isinstance(types, str) else types
    if types:
        valid = {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "boolean": isinstance(value, bool),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "null": value is None,
        }
        if not any(valid.get(t, False) for t in types):
            return [f"{path}: expected {types}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: invalid enum value")
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: invalid constant")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        errors.extend(
            f"{path}.{key}: required" for key in schema.get("required", []) if key not in value
        )
        for key, item in value.items():
            if key in properties:
                errors.extend(schema_errors(item, properties[key], root=root, path=f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key}: unknown property")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: too many items")
        if schema.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in value}) != len(
            value
        ):
            errors.append(f"{path}: duplicate items")
        if isinstance(schema.get("items"), dict):
            for i, item in enumerate(value):
                errors.extend(schema_errors(item, schema["items"], root=root, path=f"{path}[{i}]"))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if (
            "minimum" in schema
            and value < schema["minimum"]
            or "maximum" in schema
            and value > schema["maximum"]
        ):
            errors.append(f"{path}: out of range")
    if isinstance(value, str):
        if (
            len(value) < schema.get("minLength", 0)
            or "pattern" in schema
            and not re.search(schema["pattern"], value)
        ):
            errors.append(f"{path}: invalid string")
    return errors
