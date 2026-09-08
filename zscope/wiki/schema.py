"""Offline Draft 2020-12 schema registry and bounded instance validator.

The Wiki contracts use schema IDs for local ``$ref`` values.  This module
loads the checked-in registry instead of resolving network URIs.  When the
optional :mod:`jsonschema` package is installed it delegates full Draft
2020-12 validation to that implementation; otherwise it performs the subset
used by the materialized contracts (types, required/additional properties,
enums/const, patterns, bounds, arrays and local refs).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# Schemas are shipped as package data beside the Wiki runtime.  Keeping the
# resolver relative to this module also makes installed wheels independent of
# the source checkout layout.
DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"


class SchemaValidationError(ValueError):
    def __init__(self, schema_id: str, errors: Sequence[str]) -> None:
        self.schema_id = schema_id
        self.errors = tuple(str(item) for item in errors)
        super().__init__(f"{schema_id}: " + "; ".join(self.errors[:8]))


class SchemaRegistry:
    def __init__(self, schema_dir: Optional[Path] = None) -> None:
        self.schema_dir = Path(schema_dir or DEFAULT_SCHEMA_DIR)
        registry_path = self.schema_dir / "schema-registry.json"
        if not registry_path.is_file():
            raise FileNotFoundError(f"Wiki schema registry not found: {registry_path}")
        self.registry = json.loads(registry_path.read_text(encoding="utf-8"))
        if self.registry.get("schema_version") != "zscope.schema-registry.v1":
            raise ValueError("unsupported Wiki schema registry version")
        self.schemas: Dict[str, Dict[str, Any]] = {}
        for schema_id, filename in dict(self.registry.get("schemas", {})).items():
            path = self.schema_dir / str(filename)
            if not path.is_file():
                raise FileNotFoundError(f"schema {schema_id} points to missing file {path}")
            document = json.loads(path.read_text(encoding="utf-8"))
            if document.get("$id") != schema_id:
                raise ValueError(f"schema registry drift for {schema_id}")
            self.schemas[schema_id] = document
        self._check_refs()

    def _check_refs(self) -> None:
        for schema_id, document in self.schemas.items():
            for ref in _walk_refs(document):
                if ref not in self.schemas:
                    raise ValueError(f"unregistered local $ref {ref!r} in {schema_id}")

    def get(self, schema_id: str) -> Dict[str, Any]:
        try:
            return self.schemas[str(schema_id)]
        except KeyError as exc:
            raise KeyError(f"unknown Wiki schema: {schema_id}") from exc

    def validate(self, instance: Any, schema_id: str) -> Any:
        schema = self.get(schema_id)
        errors: List[str] = []
        try:
            import jsonschema  # type: ignore
        except ImportError:
            _validate_subset(instance, schema, self.schemas, "$", errors)
        else:
            resolver = jsonschema.RefResolver.from_schema(schema, store=self.schemas)
            validator = jsonschema.Draft202012Validator(schema, resolver=resolver)
            errors = [error.message for error in validator.iter_errors(instance)]
        if errors:
            raise SchemaValidationError(schema_id, errors)
        return instance


def _walk_refs(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        ref = value.get("$ref")
        if ref is not None:
            yield str(ref)
        for child in value.values():
            yield from _walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_refs(child)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    return "unknown"


def _validate_subset(instance: Any, schema: Mapping[str, Any], schemas: Mapping[str, Mapping[str, Any]], path: str, errors: List[str]) -> None:
    if "$ref" in schema:
        target = schemas.get(str(schema["$ref"]))
        if target is None:
            errors.append(f"{path}: unresolved $ref {schema['$ref']}")
            return
        _validate_subset(instance, target, schemas, path, errors)
        return
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: must equal const {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value is not in enum")
    expected = schema.get("type")
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        actual = _json_type(instance)
        compatible = actual in allowed or (actual == "integer" and "number" in allowed)
        if not compatible:
            errors.append(f"{path}: expected {allowed}, got {actual}")
            return
    if isinstance(instance, Mapping):
        required = schema.get("required", ())
        for key in required:
            if key not in instance:
                errors.append(f"{path}: missing required property {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: additional property {key}")
        for key, child_schema in properties.items():
            if key in instance:
                _validate_subset(instance[key], child_schema, schemas, f"{path}.{key}", errors)
        additional = schema.get("additionalProperties")
        if isinstance(additional, Mapping):
            for key, value in instance.items():
                if key not in properties:
                    _validate_subset(value, additional, schemas, f"{path}.{key}", errors)
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < int(schema["minItems"]):
            errors.append(f"{path}: fewer than minItems")
        if "maxItems" in schema and len(instance) > int(schema["maxItems"]):
            errors.append(f"{path}: exceeds maxItems")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, ensure_ascii=False) for item in instance]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: items are not unique")
        if isinstance(schema.get("items"), Mapping):
            for index, value in enumerate(instance):
                _validate_subset(value, schema["items"], schemas, f"{path}[{index}]", errors)
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < int(schema["minLength"]):
            errors.append(f"{path}: shorter than minLength")
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            errors.append(f"{path}: exceeds maxLength")
        if "pattern" in schema:
            try:
                matched = re.search(str(schema["pattern"]), instance) is not None
            except re.error:
                matched = True
            if not matched:
                errors.append(f"{path}: does not match pattern")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum")
    if len(errors) > 32:
        del errors[32:]


_DEFAULT_REGISTRY: Optional[SchemaRegistry] = None


def get_schema_registry(schema_dir: Optional[Path] = None) -> SchemaRegistry:
    global _DEFAULT_REGISTRY
    if schema_dir is not None:
        return SchemaRegistry(schema_dir)
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = SchemaRegistry()
    return _DEFAULT_REGISTRY


def validate_instance(instance: Any, schema_id: str, *, schema_dir: Optional[Path] = None) -> Any:
    return get_schema_registry(schema_dir).validate(instance, schema_id)


__all__ = ["SchemaRegistry", "SchemaValidationError", "get_schema_registry", "validate_instance"]
