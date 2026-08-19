"""Declarative workflow/agent/skill specification loading.

The design intentionally mirrors the Claude Code pattern: agents and skills are
small markdown contracts with YAML front matter, while workflows are YAML files
that decide which agents participate in a run.  The runtime keeps these specs
out of the LLM context until an agent actually needs them.
"""

from __future__ import annotations

import threading
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

_yaml: Any
try:
    import yaml as _yaml
except ImportError:  # pragma: no cover - ConfigLoader already depends on yaml.
    _yaml = None

yaml: Any = _yaml
_SPEC_REGISTRY_CACHE_LOCK = threading.RLock()
_SPEC_REGISTRY_CACHE: Dict[
    Tuple[str, str],
    Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]],
] = {}

SUPPORTED_SKILL_LANGUAGES = frozenset({"c_cpp", "java"})


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, Iterable):
        return [str(part).strip() for part in value if str(part).strip()]
    return []


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off"}
    return bool(value)


def _parse_skill_languages(value: Any, path: Path) -> List[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{path}: skill frontmatter 'languages' must be a non-empty YAML list")
    languages: List[str] = []
    for index, raw_language in enumerate(value):
        if not isinstance(raw_language, str) or not raw_language.strip():
            raise ValueError(
                f"{path}: skill frontmatter languages[{index}] must be a non-empty string"
            )
        language = raw_language.strip()
        if language not in SUPPORTED_SKILL_LANGUAGES:
            allowed = ", ".join(sorted(SUPPORTED_SKILL_LANGUAGES))
            raise ValueError(
                f"{path}: unsupported skill language {language!r}; expected one of: {allowed}"
            )
        if language in languages:
            raise ValueError(f"{path}: duplicate skill language {language!r}")
        languages.append(language)
    return languages


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
    languages: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    allowed_mcp_tools: List[str] = field(default_factory=list)
    allowed_mcp_resources: List[str] = field(default_factory=list)
    allowed_mcp_prompts: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
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
            languages=_parse_skill_languages(meta.get("languages"), path),
            triggers=_as_list(meta.get("triggers")),
            allowed_tools=_as_list(meta.get("allowed_tools") or meta.get("tools")),
            allowed_mcp_tools=_as_list(meta.get("allowed_mcp_tools")),
            allowed_mcp_resources=_as_list(meta.get("allowed_mcp_resources")),
            allowed_mcp_prompts=_as_list(meta.get("allowed_mcp_prompts")),
            references=_as_list(meta.get("references")),
            context=str(meta.get("context") or "inline"),
            path=path,
            body=body.strip(),
        )

    def to_prompt_block(
        self,
        max_chars: Optional[int] = None,
        allowed_tools: Optional[Sequence[str]] = None,
        allowed_mcp_tools: Optional[Sequence[str]] = None,
        allowed_mcp_resources: Optional[Sequence[str]] = None,
    ) -> str:
        body = self.body if max_chars is None else self.body[:max_chars]
        if max_chars is not None and len(self.body) > max_chars:
            body += "\n\n[truncated]"
        if allowed_tools is None:
            tool_names = self.allowed_tools
        else:
            visible = set(allowed_tools)
            tool_names = [name for name in self.allowed_tools if name in visible]
        if allowed_mcp_tools is None:
            mcp_tool_names = self.allowed_mcp_tools
        else:
            visible_mcp_tools = set(allowed_mcp_tools)
            mcp_tool_names = [name for name in self.allowed_mcp_tools if name in visible_mcp_tools]
        if allowed_mcp_resources is None:
            mcp_resource_names = self.allowed_mcp_resources
        else:
            visible_mcp_resources = set(allowed_mcp_resources)
            mcp_resource_names = [
                name for name in self.allowed_mcp_resources if name in visible_mcp_resources
            ]
        return (
            f"## Skill: {self.name}\n"
            f"Description: {self.description}\n"
            f"Category: {self.category}\n"
            f"Allowed tools: {', '.join(tool_names) or 'none'}\n"
            f"Allowed MCP tools: {', '.join(mcp_tool_names) or 'none'}\n"
            f"Allowed MCP resources: {', '.join(mcp_resource_names) or 'none'}\n"
            f"References: {', '.join(self.references) or 'none'}\n\n"
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
    tools_declared: bool = False
    mcp_servers: List[str] = field(default_factory=list)
    context_policy: str = ""
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
            tools_declared="tools" in meta,
            mcp_servers=_as_list(meta.get("mcp_servers") or meta.get("mcpServers")),
            context_policy=str(meta.get("context_policy") or ""),
            path=path,
            body=body.strip(),
        )

    def to_prompt_block(
        self,
        max_chars: Optional[int] = None,
        active_skills: Optional[List[str]] = None,
        allowed_tools: Optional[Sequence[str]] = None,
    ) -> str:
        body = self.body if max_chars is None else self.body[:max_chars]
        if max_chars is not None and len(self.body) > max_chars:
            body += "\n\n[truncated]"
        skill_names = self.skills if active_skills is None else active_skills
        if allowed_tools is None:
            tool_text = ", ".join(self.tools) or "runtime default"
        else:
            tool_text = ", ".join(allowed_tools) or "none"
        return (
            f"## Agent: {self.name}\n"
            f"Role: {self.role or self.description}\n"
            f"Skills: {', '.join(skill_names) or 'none'}\n"
            f"Allowed tools: {tool_text}\n"
            f"Context policy: {self.context_policy or 'runtime default'}\n\n"
            f"{body}"
        )


@dataclass
class WorkflowStep:
    id: str
    scope: str = "entry"
    handler: str = ""
    agent: str = ""
    action: str = ""
    stop_policy: str = "continue"
    required: bool = True


@dataclass
class WorkflowSpec:
    """Workflow-level orchestration contract."""

    name: str
    description: str = ""
    mode: str = "default"
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
            unsupported = sorted(
                key
                for key in ("skills", "context_policy", "spawn_policy")
                if raw.get(key) not in (None, "", [], {})
            )
            if unsupported:
                raise ValueError(
                    f"Workflow step {raw.get('id') or idx + 1!r} uses unsupported "
                    f"non-executable field(s): {', '.join(unsupported)}"
                )
            steps.append(
                WorkflowStep(
                    id=str(raw.get("id") or f"step_{idx + 1}"),
                    scope=str(raw.get("scope") or "entry"),
                    handler=str(raw.get("handler") or ""),
                    agent=str(raw.get("agent") or ""),
                    action=str(raw.get("action") or ""),
                    stop_policy=str(raw.get("stop_policy") or "continue"),
                    required=_as_bool(raw.get("required"), True),
                )
            )
        return cls(
            name=str(data.get("name") or path.stem),
            description=str(data.get("description") or ""),
            mode=str(data.get("mode") or path.stem),
            steps=steps,
            path=path,
        )

    def to_prompt_block(self) -> str:
        lines = [
            f"## Workflow: {self.name}",
            f"Mode: {self.mode}",
            f"Description: {self.description}",
            "Steps:",
        ]
        for step in self.steps:
            lines.append(
                f"- {step.id}: scope={step.scope}, handler={step.handler or step.id}, "
                f"agent={step.agent}, action={step.action}, "
                f"stop={step.stop_policy}"
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
        self._load_from_cache_or_disk()

    def reload(self) -> None:
        with _SPEC_REGISTRY_CACHE_LOCK:
            self._reload_unlocked()
            _SPEC_REGISTRY_CACHE[self._cache_key()] = self._snapshot_specs()

    def _load_from_cache_or_disk(self) -> None:
        with _SPEC_REGISTRY_CACHE_LOCK:
            cached = _SPEC_REGISTRY_CACHE.get(self._cache_key())
            if cached is not None:
                self.agents, self.skills, self.workflows = deepcopy(cached)
                return
            self._reload_unlocked()
            _SPEC_REGISTRY_CACHE[self._cache_key()] = self._snapshot_specs()

    def _reload_unlocked(self) -> None:
        self.agents.clear()
        self.skills.clear()
        self.workflows.clear()
        self._load_package_specs()
        self._load_project_overrides()

    def _cache_key(self) -> Tuple[str, str]:
        project_root = str(self.project_root) if self.project_root else ""
        return str(self.package_root.resolve()), project_root

    def _snapshot_specs(
        self,
    ) -> Tuple[Dict[str, AgentSpec], Dict[str, SkillSpec], Dict[str, WorkflowSpec]]:
        return deepcopy((self.agents, self.skills, self.workflows))

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

    def skills_for_agent(
        self,
        agent_name: str,
        extra: Optional[List[str]] = None,
        only: Optional[List[str]] = None,
    ) -> List[SkillSpec]:
        names: List[str] = []
        agent = self.get_agent(agent_name)
        if agent:
            names.extend(agent.skills)
        names.extend(extra or [])
        allowed = set(only) if only is not None else None
        seen = set()
        result: List[SkillSpec] = []
        for name in names:
            if allowed is not None and name not in allowed:
                continue
            if name in seen:
                continue
            seen.add(name)
            skill = self.get_skill(name)
            if skill:
                result.append(skill)
        return result
