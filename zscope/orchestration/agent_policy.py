"""Agent prompt, skill-routing, subagent, and tool-policy helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from ..common.utils import extract_json_blocks
from .skill_selection import SkillSelection
from ..tools.policy import ToolPolicy, deny_sensitive_paths_hook

SKILL_DESCRIPTIONS = {
    "resource_lifecycle": "allocation, ownership, cleanup, leaks, missing release",
    "bounds_and_integer": "buffer bounds, length validation, integer overflow/truncation",
    "null_and_failure": "null dereference, unchecked return, failure/error paths",
    "temporal_memory": "use-after-free, double free, invalid free, stale pointer",
    "concurrency_lock_order": "deadlock, lock balance, lock-order problems",
    "shared_state_race": "data race, TOCTOU, shared mutable state",
    "stack_escape": "stack address escaping, async lifetime of locals",
    "ownership_contract": "API ownership contracts, caller/callee responsibility",
    "string_and_format": "format strings, string termination, printf-like misuse",
}


def attach_agent_contract(
    context: Dict[str, Any],
    agent_name: str,
    spec_registry: Any,
    *,
    extra_skills: Optional[List[str]] = None,
    active_skill_names: Optional[List[str]] = None,
    visible_tool_names: Optional[Sequence[str]] = None,
    visible_mcp_tool_names: Optional[Sequence[str]] = None,
    visible_mcp_resource_names: Optional[Sequence[str]] = None,
) -> None:
    """Attach agent/skill contracts to a single agent invocation."""
    if visible_tool_names is not None:
        visible_mcp_tool_names = visible_mcp_tool_names or []
        visible_mcp_resource_names = visible_mcp_resource_names or []
    agent_spec = spec_registry.get_agent(agent_name)
    if agent_spec:
        context["agent_contract"] = agent_spec.to_prompt_block(
            active_skills=active_skill_names,
            allowed_tools=visible_tool_names,
        )
    else:
        context.pop("agent_contract", None)

    skills = spec_registry.skills_for_agent(
        agent_name,
        extra=extra_skills,
        only=active_skill_names,
    )
    if skills:
        context["skill_contracts"] = "\n\n".join(
            skill.to_prompt_block(
                allowed_tools=visible_tool_names,
                allowed_mcp_tools=visible_mcp_tool_names,
                allowed_mcp_resources=visible_mcp_resource_names,
            )
            for skill in skills
        )
    else:
        context.pop("skill_contracts", None)


def agent_system_prompt(
    agent_name: str,
    spec_registry: Any,
    *,
    active_skill_names: Optional[List[str]] = None,
    substitutions: Optional[Dict[str, Any]] = None,
    visible_tool_names: Optional[Sequence[str]] = None,
    visible_mcp_tool_names: Optional[Sequence[str]] = None,
    visible_mcp_resource_names: Optional[Sequence[str]] = None,
) -> str:
    if visible_tool_names is not None:
        visible_mcp_tool_names = visible_mcp_tool_names or []
        visible_mcp_resource_names = visible_mcp_resource_names or []
    agent_spec = spec_registry.get_agent(agent_name)
    prompt = (
        agent_spec.to_prompt_block(
            active_skills=active_skill_names,
            allowed_tools=visible_tool_names,
        )
        if agent_spec
        else agent_name
    )
    for key, value in (substitutions or {}).items():
        prompt = prompt.replace("{" + key + "}", str(value))
    return prompt


def route_vulnerability_skills_with_llm(
    task: str,
    available_skill_names: Sequence[str],
    llm_client: Any,
    cache: Dict[str, SkillSelection],
) -> Dict[str, Any]:
    """Ask the analyzer model for a tiny structured skill-routing decision."""
    available = list(dict.fromkeys(available_skill_names))
    cache_key = json.dumps(
        {
            "task": task,
            "available": available,
            "models": getattr(llm_client, "models", []),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    if cache_key in cache:
        cached = cache[cache_key]
        return {
            "skills": cached.skills,
            "restricted": cached.restricted,
            "confidence": cached.confidence,
            "reasons": cached.reasons,
        }

    catalog = {name: SKILL_DESCRIPTIONS.get(name, name) for name in available}
    messages = [
        {
            "role": "system",
            "content": (
                "Classify a vulnerability-analysis task into the provided skill names. "
                "Return only JSON with keys: skills (array), restricted (boolean), "
                "confidence (0..1), reasons (array of short strings). "
                "Use restricted=false when the task is broad, ambiguous, or asks for a general audit. "
                "Prefer widening over missing a relevant vulnerability family."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "task": task,
                    "available_skills": catalog,
                },
                ensure_ascii=False,
            ),
        },
    ]
    response = llm_client.chat_completion(
        messages,
        temperature=0.0,
        max_tokens=300,
        trace_agent="skill_selection",
        trace_label=str(task)[:120],
    )
    content = str(((response.get("choices") or [{}])[0].get("message") or {}).get("content") or "")
    blocks = extract_json_blocks(content)
    parsed = blocks[0] if blocks else json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("skill router returned non-object JSON")

    try:
        confidence = float(parsed.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    selection = SkillSelection(
        skills=[
            name for name in available if name in {str(item) for item in parsed.get("skills", [])}
        ],
        restricted=bool(parsed.get("restricted")),
        source="semantic_cache",
        confidence=max(0.0, min(1.0, confidence)),
        reasons=(
            [str(item) for item in parsed.get("reasons", [])]
            if isinstance(parsed.get("reasons"), list)
            else []
        ),
    )
    cache[cache_key] = selection
    return parsed


def subagent_llm_ref_for_ticket(
    ticket: Any,
    skill_llm_refs: Dict[str, str],
    fallback_ref: str,
) -> str:
    skill = str(getattr(ticket, "skill", "") or "")
    return str(skill_llm_refs.get(skill) or skill_llm_refs.get("*") or fallback_ref)


def compact_subagent_items(items: Any, *, limit: int = 50) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [compact_subagent_item(item) for item in items[:limit]]


def compact_subagent_item(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {"value": str(item)}
    compact = dict(item)
    context = compact.pop("context_slice", "")
    if context:
        compact["context_slice_chars"] = len(str(context))
        compact["context_slice_preview"] = str(context)[:240]
    return compact


def compact_subagent_reports(reports: Any, *, limit: int = 50) -> List[Dict[str, Any]]:
    if not isinstance(reports, list):
        return []
    compact_reports: List[Dict[str, Any]] = []
    for report in reports[:limit]:
        if not isinstance(report, dict):
            compact_reports.append({"value": str(report)})
            continue
        raw_data = report.get("data")
        data: Dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        raw_metadata = report.get("metadata")
        metadata: Dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
        compact_reports.append(
            {
                "ticket": compact_subagent_item(report.get("ticket", {})),
                "status": report.get("status"),
                "success": report.get("success"),
                "error": report.get("error"),
                "metadata": dict(report.get("metadata") or {}),
                "conclusion": data.get("conclusion"),
                "issues_found_count": len(data.get("issues_found") or []),
                "needs_human_review": bool(
                    metadata.get("needs_human_review") or data.get("needs_human_review")
                ),
            }
        )
    return compact_reports


def tool_policy_for_agent(
    spec_registry: Any,
    config: Any,
    agent_name: Optional[str],
    *,
    active_skill_names: Optional[List[str]] = None,
) -> ToolPolicy:
    """Build the effective runtime tool policy for an agent run."""
    audit_log_path = tool_audit_log_path(config)
    if not agent_name:
        return ToolPolicy.allow_all(
            pre_hooks=[deny_sensitive_paths_hook],
            audit_log_path=audit_log_path,
        )

    agent_spec = spec_registry.get_agent(agent_name)
    agent_tools = set(agent_spec.tools) if agent_spec and agent_spec.tools else set()
    skill_names = (
        list(active_skill_names)
        if active_skill_names is not None
        else list(agent_spec.skills) if agent_spec else []
    )
    skill_tools: Set[str] = set()
    for skill_name in skill_names:
        skill = spec_registry.get_skill(skill_name)
        if skill:
            skill_tools.update(skill.allowed_tools)

    if agent_tools and skill_tools:
        allowed_tools: Optional[Set[str]] = agent_tools & skill_tools
    elif agent_tools:
        allowed_tools = agent_tools
    elif skill_tools:
        allowed_tools = skill_tools
    else:
        allowed_tools = None

    return ToolPolicy(
        allowed_tools=allowed_tools,
        pre_hooks=[deny_sensitive_paths_hook],
        audit_log_path=audit_log_path,
    )


def tool_audit_log_path(config: Any) -> Optional[Path]:
    analysis = getattr(config, "analysis", None)
    configured = str(getattr(analysis, "tool_audit_log", "") or "").strip()
    if not configured:
        return None
    path = Path(configured)
    if path.is_absolute():
        return path
    project = getattr(config, "project", None)
    project_root = getattr(project, "project_root", Path("."))
    return Path(project_root) / path
