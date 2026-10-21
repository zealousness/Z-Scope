from __future__ import annotations

import pytest

from zscope.wiki.schema import SchemaValidationError, get_schema_registry, validate_instance


def test_registry_loads_all_local_refs_without_network() -> None:
    registry = get_schema_registry()
    assert "zscope.wiki-changeset.v1" in registry.schemas
    assert registry.get("zscope.project-constraint.v1")["$id"] == "zscope.project-constraint.v1"


def test_dependency_free_validator_checks_required_and_nested_refs() -> None:
    valid = {
        "schema_version": "zscope.document-source.v1",
        "source_id": "docsrc_fixture",
        "project_id": "fixture",
        "source_kind": "markdown_document",
        "relative_path": "README.md",
        "content_digest": "sha256:" + "a" * 64,
        "size_bytes": 1,
        "classification": "explanatory",
        "classification_reason": "explicit_project_readme",
        "input_language": "en",
        "module_hints": [],
        "observed_at": "2026-01-01T00:00:00Z",
    }
    assert validate_instance(valid, "zscope.document-source.v1") == valid
    invalid = dict(valid)
    invalid.pop("relative_path")
    with pytest.raises(SchemaValidationError):
        validate_instance(invalid, "zscope.document-source.v1")

