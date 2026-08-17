"""Agent prompt, skill-routing, and tool-policy helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from ..tools.policy import ToolPolicy, deny_sensitive_paths_hook


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

    tools_declared = bool(agent_spec and getattr(agent_spec, "tools_declared", False))
    if tools_declared and skill_tools:
        allowed_tools: Optional[Set[str]] = agent_tools & skill_tools
    elif tools_declared:
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
