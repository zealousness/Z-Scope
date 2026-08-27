"""Wiki Compiler adapter with deterministic no-LLM degradation."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from .changeset import validate_changeset


class WikiCompiler:
    """Compile one bounded workset; provider is optional and never trusted."""

    def __init__(self, provider: Optional[Callable[[Mapping[str, Any]], Any]] = None) -> None:
        self.provider = provider

    def compile(self, workset: Mapping[str, Any]) -> Dict[str, Any]:
        source_ids = (
            list(workset.get("added_source_ids", []))
            + list(workset.get("changed_source_ids", []))
            + list(workset.get("removed_source_ids", []))
        )
        if self.provider is None:
            results = [
                {
                    "source_ref": source_id,
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [],
                    "constraint_ids": [],
                    "reason": "deterministic_compiler_does_not_infer_constraints",
                }
                for source_id in source_ids
            ] or [
                {
                    "source_ref": "docsrc_none",
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [],
                    "constraint_ids": [],
                    "reason": "empty_workset",
                }
            ]
            result = {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": workset.get("base_revision_id"),
                "outcome": "background_only",
                "source_results": results,
                "page_changes": [],
                "constraint_proposals": [],
                "edge_proposals": [],
                "retire_proposals": [],
                "unresolved_conflicts": [],
                "summary": "No-LLM compiler emitted no constraints.",
                "compiler": {"kind": "deterministic", "identity": "zscope.wiki.deterministic.v1", "prompt_version": None, "model": None},
            }
            return validate_changeset(result, workset)
        try:
            raw = self.provider(workset)
            if isinstance(raw, str):
                raw = json.loads(raw)
            if not isinstance(raw, Mapping):
                raise ValueError("provider output is not an object")
            enriched = dict(raw)
            enriched.setdefault("compiler", {"kind": "llm", "identity": "zscope.wiki.provider.v1", "prompt_version": None, "model": None})
            return validate_changeset(enriched, workset)
        except Exception as exc:
            return {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": workset.get("base_revision_id"),
                "outcome": "extraction_failed",
                "source_results": [{"source_ref": source_ids[0] if source_ids else "docsrc_none", "extraction_status": "extraction_failed", "source_refs_used": [], "constraint_ids": [], "reason": str(exc)[:1000]}],
                "page_changes": [],
                "constraint_proposals": [],
                "edge_proposals": [],
                "retire_proposals": [],
                "unresolved_conflicts": [],
                "summary": "Compiler output was rejected and no new content was published.",
            }

    compile_workset = compile
