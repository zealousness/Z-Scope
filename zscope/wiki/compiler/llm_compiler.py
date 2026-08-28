"""OpenAI-compatible Compiler provider with strict no-side-effect output."""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any, Dict, Mapping, Optional

from ...framework.llm_client import LLMClient
from ...orchestration.specs import SpecRegistry
from ..schema import get_schema_registry
from .changeset import validate_changeset

PROMPT_VERSION = "zscope.wiki-compiler.agent.v1"
FINAL_TOOL_NAME = "emit_wiki_changeset"
MAX_ATTEMPTS = 5


class LLMWikiCompilerProvider:
    """Turn one bounded workset into a validated WikiChangeSet.

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

        parameters = materialize(registry.get("zscope.wiki-changeset.v1"))
        return {
            "type": "function",
            "function": {
                "name": FINAL_TOOL_NAME,
                "description": (
                    "Submit the complete validated zscope.wiki-changeset.v1 result. "
                    "This is the only accepted final output channel."
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
            candidate = dict(payload)
            candidate["compiler"] = self._compiler_metadata()
            return {"valid": True, "payload": validate_changeset(candidate, workset)}
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

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
                    "content": json.dumps(dict(workset), ensure_ascii=False, sort_keys=True),
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
