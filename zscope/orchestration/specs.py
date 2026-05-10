"""Declarative workflow/agent/skill specification loading.

The design intentionally mirrors the Claude Code pattern: agents and skills are
small markdown contracts with YAML front matter, while workflows are YAML files
that decide which agents participate in a run.  The runtime keeps these specs
out of the LLM context until an agent actually needs them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - ConfigLoader already depends on yaml.
    yaml = None


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, Iterable):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


def _read_frontmatter(path: Path) -> Tuple[Dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            raw = parts[1].strip()
            body = parts[2].lstrip()
            meta = yaml.safe_load(raw) if yaml and raw else {}
            if not isinstance(meta, dict):
                meta = {}
            return meta, body
    return {}, text


@dataclass
class SkillSpec:
    """One SKILL.md contract."""

    name: str
    description: str = ""
    category: str = ""
    triggers: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    allowed_mcp_tools: List[str] = field(default_factory=list)
    allowed_mcp_resources: List[str] = field(default_factory=list)
    allowed_mcp_prompts: List[str] = field(default_factory=list)
    context: str = "inline"
    path: Optional[Path] = None
    body: str = ""

    @classmethod
    def from_markdown(cls, path: Path) -> "SkillSpec":
        meta, body = _read_frontmatter(path)
        return cls(
            name=str(meta.get("name") or path.parent.name),
            description=str(meta.get("description") or ""),
            category=str(meta.get("category") or ""),
            triggers=_as_list(meta.get("triggers")),
            allowed_tools=_as_list(meta.get("allowed_tools") or meta.get("tools")),
            allowed_mcp_tools=_as_list(meta.get("allowed_mcp_tools")),
            allowed_mcp_resources=_as_list(meta.get("allowed_mcp_resources")),
            allowed_mcp_prompts=_as_list(meta.get("allowed_mcp_prompts")),
            context=str(meta.get("context") or "inline"),
            path=path,
            body=body.strip(),
        )

    def to_prompt_block(self, max_chars: int = 6000) -> str:
        body = self.body[:max_chars]
        if len(self.body) > max_chars:
            body += "\n\n[truncated]"
        return (
            f"## Skill: {self.name}\n"
            f"Description: {self.description}\n"
            f"Category: {self.category}\n"
            f"Allowed tools: {', '.join(self.allowed_tools) or 'none'}\n"
            f"Allowed MCP tools: {', '.join(self.allowed_mcp_tools) or 'none'}\n"
            f"Allowed MCP resources: {', '.join(self.allowed_mcp_resources) or 'none'}\n\n"
            f"{body}"
        )


@dataclass
class AgentSpec:
    """One AGENT.md contract."""

    name: str
    description: str = ""
    role: str = ""
    skills: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    mcp_servers: List[str] = field(default_factory=list)
    context_policy: str = ""
    can_spawn_subagents: bool = False
    max_subagents: int = 0
    path: Optional[Path] = None
    body: str = ""

    @classmethod
    def from_markdown(cls, path: Path) -> "AgentSpec":
        meta, body = _read_frontmatter(path)
        return cls(
            name=str(meta.get("name") or path.parent.name),
            description=str(meta.get("description") or ""),
            role=str(meta.get("role") or ""),
            skills=_as_list(meta.get("skills")),
            tools=_as_list(meta.get("tools")),
            mcp_servers=_as_list(meta.get("mcp_servers") or meta.get("mcpServers")),
            context_policy=str(meta.get("context_policy") or ""),
            can_spawn_subagents=bool(meta.get("can_spawn_subagents", False)),
            max_subagents=int(meta.get("max_subagents") or 0),
            path=path,
            body=body.strip(),
        )

    def to_prompt_block(self, max_chars: int = 5000) -> str:
        body = self.body[:max_chars]
        if len(self.body) > max_chars:
            body += "\n\n[truncated]"
        return (
            f"## Agent: {self.name}\n"
            f"Role: {self.role or self.description}\n"
            f"Skills: {', '.join(self.skills) or 'none'}\n"
            f"Allowed tools: {', '.join(self.tools) or 'runtime default'}\n"
            f"Context policy: {self.context_policy or 'runtime default'}\n"
            f"Can spawn subagents: {self.can_spawn_subagents}\n\n"
            f"{body}"
        )


@dataclass
class WorkflowStep:
    id: str
    agent: str = ""
    action: str = ""
    skills: List[str] = field(default_factory=list)
    context_policy: str = ""
    spawn_policy: str = ""


@dataclass
class WorkflowSpec:
    """Workflow-level orchestration contract."""

    name: str
    description: str = ""
    mode: str = "default"
    entry_strategy: str = "configured"
    steps: List[WorkflowStep] = field(default_factory=list)
    path: Optional[Path] = None

    @classmethod
    def from_yaml(cls, path: Path) -> "WorkflowSpec":
        data = yaml.safe_load(path.read_text(encoding="utf-8")) if yaml else {}
        if not isinstance(data, dict):
            data = {}
        steps: List[WorkflowStep] = []
        for idx, raw in enumerate(data.get("steps") or []):
            if not isinstance(raw, dict):
                continue
            steps.append(
                WorkflowStep(
                    id=str(raw.get("id") or f"step_{idx + 1}"),
                    agent=str(raw.get("agent") or ""),
                    action=str(raw.get("action") or ""),
                    skills=_as_list(raw.get("skills")),
                    context_policy=str(raw.get("context_policy") or ""),
                    spawn_policy=str(raw.get("spawn_policy") or ""),
                )
            )
        return cls(
            name=str(data.get("name") or path.stem),
            description=str(data.get("description") or ""),
            mode=str(data.get("mode") or path.stem),
            entry_strategy=str(data.get("entry_strategy") or "configured"),
            steps=steps,
            path=path,
        )

    def to_prompt_block(self) -> str:
        lines = [
            f"## Workflow: {self.name}",
            f"Mode: {self.mode}",
            f"Entry strategy: {self.entry_strategy}",
            f"Description: {self.description}",
            "Steps:",
        ]
        for step in self.steps:
            lines.append(
                f"- {step.id}: agent={step.agent}, action={step.action}, "
                f"skills={','.join(step.skills) or 'none'}, spawn={step.spawn_policy or 'none'}"
            )
        return "\n".join(lines)


class SpecRegistry:
    """Loads built-in and project-level agent/skill/workflow specs."""

    def __init__(self, package_root: Optional[Path] = None, project_root: Optional[Path] = None):
        self.package_root = package_root or Path(__file__).resolve().parents[1]
        self.project_root = Path(project_root).resolve() if project_root else None
        self.agents: Dict[str, AgentSpec] = {}
        self.skills: Dict[str, SkillSpec] = {}
        self.workflows: Dict[str, WorkflowSpec] = {}
        self.reload()

    def reload(self) -> None:
        self.agents.clear()
        self.skills.clear()
        self.workflows.clear()
        self._load_package_specs()
        self._load_project_overrides()

    def _load_package_specs(self) -> None:
        self._load_agents(self.package_root / "agents")
        self._load_skills(self.package_root / "skills")
        self._load_workflows(self.package_root / "workflows")

    def _load_project_overrides(self) -> None:
        if not self.project_root:
            return
        self._load_agents(self.project_root / ".zscope" / "agents")
        self._load_skills(self.project_root / ".zscope" / "skills")
        self._load_workflows(self.project_root / ".zscope" / "workflows")

    def _load_agents(self, root: Path) -> None:
        if not root.exists():
            return
        for path in root.glob("*/AGENT.md"):
            spec = AgentSpec.from_markdown(path)
            self.agents[spec.name] = spec

    def _load_skills(self, root: Path) -> None:
        if not root.exists():
            return
        for path in root.glob("*/SKILL.md"):
            spec = SkillSpec.from_markdown(path)
            self.skills[spec.name] = spec

    def _load_workflows(self, root: Path) -> None:
        if not root.exists():
            return
        for path in root.glob("*.yaml"):
            spec = WorkflowSpec.from_yaml(path)
            self.workflows[spec.name] = spec
            self.workflows[spec.mode] = spec

    def get_agent(self, name: str) -> Optional[AgentSpec]:
        return self.agents.get(name)

    def get_skill(self, name: str) -> Optional[SkillSpec]:
        return self.skills.get(name)

    def get_workflow(self, name: str) -> Optional[WorkflowSpec]:
        return self.workflows.get(name)

    def skills_for_agent(self, agent_name: str, extra: Optional[List[str]] = None) -> List[SkillSpec]:
        names: List[str] = []
        agent = self.get_agent(agent_name)
        if agent:
            names.extend(agent.skills)
        names.extend(extra or [])
        seen = set()
        result: List[SkillSpec] = []
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            skill = self.get_skill(name)
            if skill:
                result.append(skill)
        return result
