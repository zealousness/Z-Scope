"""OpenAI-compatible Compiler provider with strict no-side-effect output."""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping, Optional

from ...framework.llm_client import LLMClient
from .changeset import validate_changeset


PROMPT_VERSION = "zscope.wiki-compiler.prompt.v2"


class LLMWikiCompilerProvider:
    """Turn one bounded workset into a validated WikiChangeSet.

    The provider receives only the program-created workset projection.  Source
    text retrieval remains a separate allowlisted runtime concern; arbitrary
    paths, shell and network instructions are never passed through this API.
    """

    def __init__(self, llm_client: LLMClient, *, max_tokens: Optional[int] = None) -> None:
        self.llm_client = llm_client
        self.max_tokens = None if max_tokens is None else max(256, int(max_tokens))

    @staticmethod
    def _extract(response: Mapping[str, Any]) -> Dict[str, Any]:
        choices = response.get("choices") or []
        if not choices or not isinstance(choices[0], Mapping):
            raise ValueError("Compiler response has no choice")
        message = choices[0].get("message") or {}
        if not isinstance(message, Mapping):
            raise ValueError("Compiler response message is not an object")
        tool_calls = message.get("tool_calls") or []
        if tool_calls:
            function = tool_calls[0].get("function") if isinstance(tool_calls[0], Mapping) else None
            arguments = function.get("arguments") if isinstance(function, Mapping) else None
            if arguments:
                value = json.loads(arguments) if isinstance(arguments, str) else arguments
                if isinstance(value, dict):
                    return value
        content = message.get("content")
        if isinstance(content, Mapping):
            return dict(content)
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Compiler response has no JSON content")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError("Compiler JSON root is not an object")
        return value

    def __call__(self, workset: Mapping[str, Any]) -> Dict[str, Any]:
        system = (
            "You are the Z-SCOPE Wiki Compiler. Return exactly one JSON object "
            "matching zscope.wiki-changeset.v1. Use only source/page IDs in the "
            "workset. Every upsert page must be human-readable Chinese Markdown "
            "with exactly these H2 headings in order: 摘要, 适用范围和模块边界, "
            "已声明约束, 限定条件、例外和常见误报模式, 冲突与未决问题, 来源索引. "
            "Use [[page_id|中文标题]] for links between pages; when changing multiple "
            "pages, every changed page must link to another changed page. Put every "
            "source_refs_used ID in 来源索引 as [docref_id]. Never output verdicts, "
            "proof, shell commands, secrets, or unquoted constraints. If no structured "
            "constraint exists, return background_only with constraint_proposals=[] "
            "and no_constraints_found or background_page_updated."
        )
        request = {
            "temperature": 0.0,
            "trace_agent": "wiki_compiler",
            "trace_label": "wiki_changeset",
        }
        if self.max_tokens is not None:
            request["max_tokens"] = self.max_tokens
        response = self.llm_client.chat_completion(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(dict(workset), ensure_ascii=False, sort_keys=True)},
            ],
            **request,
        )
        value = self._extract(response)
        value.setdefault(
            "compiler",
            {
                "kind": "llm",
                "identity": "zscope.wiki.openai-compatible.v1",
                "prompt_version": PROMPT_VERSION,
                "model": (
                    str(self.llm_client.models[0])
                    if getattr(self.llm_client, "models", None)
                    else None
                ),
            },
        )
        return validate_changeset(value, workset)


__all__ = ["LLMWikiCompilerProvider", "PROMPT_VERSION"]
