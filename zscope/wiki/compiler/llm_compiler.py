"""OpenAI-compatible Compiler provider with strict no-side-effect output."""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any, Dict, Mapping, Optional

from ...framework.llm_client import LLMClient
from ...orchestration.specs import SpecRegistry
from ..schema import get_schema_registry
from .changeset import validate_changeset
from .compiler import program_summary
from .workset import build_llm_input_projection

PROMPT_VERSION = "zscope.constraint-compiler.agent.v3"
FINAL_TOOL_NAME = "emit_project_constraints"
MAX_ATTEMPTS = 5

class LLMWikiCompilerProvider:
    """Turn one bounded workset into validated documented constraints.

    The provider receives only the program-created workset projection.  Source
    text retrieval remains a separate allowlisted runtime concern; arbitrary
    paths, shell and network instructions are never passed through this API.
    """

    def __init__(self, llm_client: LLMClient, *, max_tokens: Optional[int] = None) -> None:
        self.llm_client = llm_client
        self.max_tokens = None if max_tokens is None else max(256, int(max_tokens))

    @classmethod
    def _final_tool_schema(cls) -> Dict[str, Any]:
        registry = get_schema_registry()

        def materialize(value: Any, resolving: tuple[str, ...] = ()) -> Any:
            if isinstance(value, Mapping):
                ref = value.get("$ref")
                if ref is not None:
                    schema_id = str(ref)
                    if schema_id in resolving:
                        raise ValueError(f"recursive Wiki schema reference: {schema_id}")
                    return materialize(
                        deepcopy(registry.get(schema_id)),
                        (*resolving, schema_id),
                    )
                return {
                    key: materialize(child, resolving)
                    for key, child in value.items()
                    if key not in {"$schema", "$id"}
                }
            if isinstance(value, list):
                return [materialize(child, resolving) for child in value]
            return value

        proposal = materialize(registry.get("zscope.project-constraint-proposal.v1"))
        # ``schema_version`` is a program-owned provenance field.  Keep it in
        # the persisted proposal contract, but do not ask the model to emit it
        # in the terminal tool payload.
        if isinstance(proposal, dict):
            proposal.get("properties", {}).pop("schema_version", None)
            required = proposal.get("required", [])
            proposal["required"] = [item for item in required if item != "schema_version"]
        parameters = {
            "type": "object",
            "additionalProperties": False,
            "required": ["constraint_proposals"],
            "properties": {
                "constraint_proposals": {
                    "type": "array",
                    "items": proposal,
                },
            },
        }
        return {
            "type": "function",
            "function": {
                "name": FINAL_TOOL_NAME,
                "description": (
                    "Submit only semantic project constraint proposals. "
                    "The program creates the validated zscope.wiki-changeset.v1 envelope."
                ),
                "parameters": parameters,
            },
        }

    def _validate_terminal_payload(
        self,
        payload: Dict[str, Any],
        workset: Mapping[str, Any],
    ) -> Dict[str, Any]:
        try:
            candidate = self._changeset_from_terminal_payload(payload, workset)
            candidate["compiler"] = self._compiler_metadata()
            return {"valid": True, "payload": validate_changeset(candidate, workset)}
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

    @staticmethod
    def _changeset_from_terminal_payload(
        payload: Mapping[str, Any], workset: Mapping[str, Any]
    ) -> Dict[str, Any]:
        """Build the program-owned ChangeSet envelope around LLM proposals."""

        if not isinstance(payload, Mapping):
            raise ValueError("final tool payload must be an object")
        unknown = set(payload) - {
            "constraint_proposals",
        }
        if unknown:
            raise ValueError(
                "final tool payload contains program-owned or unknown fields: "
                + ", ".join(sorted(str(item) for item in unknown))
            )
        proposals = payload.get("constraint_proposals")
        if not isinstance(proposals, list):
            raise ValueError("constraint_proposals must be an array")
        materialized_proposals = []
        for proposal in proposals:
            if not isinstance(proposal, Mapping):
                materialized_proposals.append(proposal)
                continue
            if "schema_version" in proposal:
                raise ValueError("schema_version is program-owned and must not be submitted")
            item = dict(proposal)
            item["schema_version"] = "zscope.project-constraint-proposal.v1"
            materialized_proposals.append(item)
        proposals = materialized_proposals
        active_sources = list(workset.get("added_source_ids", ())) + list(
            workset.get("changed_source_ids", ())
        )
        ref_to_source = {
            str(item.get("ref_id")): str(item.get("source_id"))
            for item in workset.get("source_ref_catalog", ())
            if isinstance(item, Mapping)
        }
        used_by_source: Dict[str, set[str]] = {str(source): set() for source in active_sources}
        for proposal in proposals:
            if not isinstance(proposal, Mapping):
                continue
            for ref in proposal.get("source_refs", ()):
                source = ref_to_source.get(str(ref))
                if source in used_by_source:
                    used_by_source[source].add(str(ref))
        source_results = [
            {
                "source_ref": source_id,
                "extraction_status": (
                    "constraints_found"
                    if used_by_source[str(source_id)]
                    else "no_constraints_found"
                ),
                "source_refs_used": sorted(used_by_source[str(source_id)]),
                "reason": (
                    "documented constraints extracted"
                    if used_by_source[str(source_id)]
                    else "no_constraints_found"
                ),
            }
            for source_id in active_sources
        ] or [
            {
                "source_ref": "docsrc_none",
                "extraction_status": "no_constraints_found",
                "source_refs_used": [],
                "reason": "empty_workset",
            }
        ]
        return {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": workset.get("base_revision_id"),
            "outcome": "changed" if proposals else "background_only",
            "source_results": source_results,
            "constraint_proposals": list(proposals),
            "summary": program_summary(
                "changed" if proposals else "background_only",
                len(proposals),
                source_results,
            ),
        }

    def _compiler_metadata(self) -> Dict[str, Any]:
        return {
            "kind": "llm",
            "identity": "zscope.wiki.openai-compatible.v1",
            "prompt_version": PROMPT_VERSION,
            "model": (
                str(self.llm_client.models[0]) if getattr(self.llm_client, "models", None) else None
            ),
        }

    @staticmethod
    def _system_prompt() -> str:
        spec = SpecRegistry().get_agent("wiki_compiler")
        if spec is None:
            raise RuntimeError("wiki_compiler AGENT.md is not available")
        return spec.to_prompt_block()

    def __call__(self, workset: Mapping[str, Any]) -> Dict[str, Any]:
        request: Dict[str, Any] = {
            "tools_schema": [self._final_tool_schema()],
            "tool_executor": lambda name, args: {
                "success": False,
                "error": f"Unsupported Wiki Compiler tool: {name}",
            },
            "max_iterations": MAX_ATTEMPTS,
            "temperature": 0.0,
            "trace_agent": "wiki_compiler",
            "trace_label": "wiki_changeset",
            "terminal_tool_name": FINAL_TOOL_NAME,
            "terminal_tool_handler": lambda payload: self._validate_terminal_payload(
                payload,
                workset,
            ),
            "terminal_tool_required": True,
            "max_identical_invalid_terminal_calls": MAX_ATTEMPTS,
            "max_invalid_terminal_calls": MAX_ATTEMPTS,
        }
        if self.max_tokens is not None:
            request["max_tokens"] = self.max_tokens
        result = self.llm_client.run_conversation_with_tools(
            [
                {"role": "system", "content": self._system_prompt()},
                {
                    "role": "user",
                    "content": json.dumps(
                        build_llm_input_projection(workset),
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                },
            ],
            **request,
        )
        value = result.get("terminal_tool_payload")
        if not result.get("terminal_tool_valid") or not isinstance(value, Mapping):
            reason = result.get("terminal_loop_guard_reason") or result.get("finish_reason")
            raise ValueError(
                "Compiler did not submit a valid final tool payload"
                + (f": {reason}" if reason else "")
            )
        value = dict(value)
        value["compiler"] = self._compiler_metadata()
        return validate_changeset(value, workset)


__all__ = [
    "FINAL_TOOL_NAME",
    "LLMWikiCompilerProvider",
    "MAX_ATTEMPTS",
    "PROMPT_VERSION",
]
