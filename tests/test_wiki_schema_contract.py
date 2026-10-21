"""Contract checks for the materialized LLM Wiki JSON Schemas.

These checks intentionally use only the standard library.  Runtime validation
may use a Draft 2020-12 implementation, but the repository must still be able
to detect missing, duplicated, or drifted schema artifacts without optional
dependencies.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "zscope" / "wiki" / "schemas"

EXPECTED = {
    "zscope.document-source.v1": "document-source.schema.json",
    "zscope.document-section.v1": "document-section.schema.json",
    "zscope.document-source-manifest.v1": "document-source-manifest.schema.json",
    "zscope.project-constraint.v1": "project-constraint.schema.json",
    "zscope.project-constraint-proposal.v1": "project-constraint-proposal.schema.json",
    "zscope.document-ref.v1": "document-ref.schema.json",
    "zscope.wiki-edge.v1": "wiki-edge.schema.json",
    "zscope.wiki-revision.v1": "wiki-revision.schema.json",
    "zscope.wiki-page-frontmatter.v1": "wiki-page-frontmatter.schema.json",
    "zscope.wiki-index.v1": "wiki-index.schema.json",
    "zscope.wiki-event.v1": "wiki-event.schema.json",
    "zscope.wiki-ingest-workset.v1": "wiki-ingest-workset.schema.json",
    "zscope.wiki-changeset.v1": "wiki-changeset.schema.json",
    "zscope.validator-project-knowledge.v1": "validator-project-knowledge.schema.json",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_materialized_schema_set_matches_registry() -> None:
    registry = _load(SCHEMA_DIR / "schema-registry.json")
    assert registry["schema_version"] == "zscope.schema-registry.v1"
    assert registry["schemas"] == EXPECTED

    actual = {}
    for path in SCHEMA_DIR.glob("*.schema.json"):
        document = _load(path)
        schema_id = document.get("$id")
        assert schema_id, path
        assert schema_id not in actual, f"duplicate schema id: {schema_id}"
        actual[schema_id] = path.name
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert document["type"] == "object"
    assert actual == EXPECTED


def test_external_refs_resolve_through_registry() -> None:
    registry = _load(SCHEMA_DIR / "schema-registry.json")["schemas"]
    for path in SCHEMA_DIR.glob("*.schema.json"):
        document = _load(path)
        refs = []

        def walk(value: object) -> None:
            if isinstance(value, dict):
                if "$ref" in value:
                    refs.append(value["$ref"])
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(document)
        for ref in refs:
            assert ref in registry, f"unregistered $ref {ref!r} in {path.name}"
            assert (SCHEMA_DIR / registry[ref]).is_file()


def test_project_knowledge_excerpt_bound_is_program_owned() -> None:
    schema = _load(SCHEMA_DIR / "validator-project-knowledge.schema.json")
    assert "maxItems" not in schema["properties"]["source_excerpts"]
    selection = schema["properties"]["selection"]
    assert "omitted_source_excerpt_count" in selection["required"]
    assert selection["properties"]["omitted_source_excerpt_count"] == {
        "type": "integer",
        "minimum": 0,
    }
