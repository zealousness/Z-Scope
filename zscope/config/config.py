"""
Configuration management for Z-SCOPE.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

_yaml: Any
try:
    import yaml as _yaml
except ImportError:
    _yaml = None

yaml: Any = _yaml

logger = logging.getLogger(__name__)


def _normalize_llm_base_urls(value: Any, default: str = "https://api.openai.com/v1") -> List[str]:
    if value is None:
        raw_items: List[Any] = [default]
    elif isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, list):
        raw_items = value
    else:
        raw_items = [value]

    urls: List[str] = []
    for item in raw_items:
        if isinstance(item, dict):
            item = item.get("url") or item.get("base_url")
        cleaned = str(item or "").strip().rstrip("/")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls or [default.rstrip("/")]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class LLMConfig:
    """Configuration for LLM client."""

    provider: str = "openai"  # 预留字段，当前未在运行时使用
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    base_urls: List[str] = field(default_factory=list)
    base_url_rate_limit_per_minute: int = 0
    base_url_max_concurrent_requests: int = 0
    models: List[str] = field(default_factory=list)
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 120
    max_retries: int = 2

    def __post_init__(self) -> None:
        self.base_urls = _normalize_llm_base_urls(self.base_urls or self.base_url)
        self.base_url = self.base_urls[0]
        self.base_url_rate_limit_per_minute = max(
            0, _safe_int(self.base_url_rate_limit_per_minute, 0)
        )
        self.base_url_max_concurrent_requests = max(
            0, _safe_int(self.base_url_max_concurrent_requests, 0)
        )


@dataclass
class AgentConfig:
    """Configuration for a specific agent."""

    name: str
    task: Optional[str] = None
    enabled: bool = True
    llm_ref: Optional[str] = None
    skills: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    mcp_servers: List[str] = field(default_factory=list)
    can_spawn_subagents: Optional[bool] = None
    entry_custom_prompt: Optional[str] = None


@dataclass
class EntryDiscoveryConfig:
    """Configuration for automatic entry-point discovery."""

    enabled: bool = False
    max_candidates: int = 200
    max_functions: int = 10000
    header_files: List[str] = field(default_factory=list)
    search_root: Optional[Path] = None


@dataclass
class DiffImpactConfig:
    """Configuration for diff-impact entry planning."""

    strategy: str = "semantic_obligation"
    llm_triage: str = "on_demand"
    caller_search_depth_by_intent: Dict[str, int] = field(
        default_factory=lambda: {
            "new_external_api": 3,
            "resource_acquire_change": 4,
            "input_boundary_change": 4,
            "dispatcher_route_change": 3,
            "thread_or_callback_entry_change": 4,
            "resource_release_change": 6,
            "sink_or_check_change": 5,
            "lock_release_change": 5,
            "destroy_or_unregister_change": 6,
            "ownership_transfer_change": 5,
            "container_registration_change": 5,
            "lifecycle_contract_change": 5,
            "local_logic_change": 2,
            "comment_or_trivial_change": 1,
            "declaration_or_contract_change": 3,
        }
    )


@dataclass
class IndexingConfig:
    """Configuration for code indexing."""

    backend: str = "joern"  # joern | clang | unified | regex
    # Joern 配置
    joern_path: str = "joern"
    joern_server_host: str = "127.0.0.1"
    joern_server_port: int = 8080
    joern_heap_size: str = "8g"
    # Clang 配置（Phase 1+）
    clangd_path: str = "clangd"
    knowledge_db_path: str = ".zscope_knowledge/code_knowledge.db"
    batch_size: int = 50
    max_clangd_threads: int = 8
    # SVF 配置（Phase 4+）
    svf_bin_dir: str = ""  # SVF 工具目录（含 wpa, saber 等）
    gclang_path: str = "gclang"  # gllvm 前端路径
    get_bc_path: str = "get-bc"  # gllvm 提取 bc 路径
    llvm_link_path: str = "llvm-link"
    svf_heap_limit_mb: int = 32768  # SVF 内存上限（默认 32GB）
    svf_timeout: int = 1800  # SVF 单次执行超时（秒）
    svf_groups_config: str = ""  # JSON file for multi-group bitcode linking
    svf_scope: str = "auto"  # full | auto | entry
    svf_entry_depth: int = 4
    svf_max_selected_tus: int = 300
    svf_fallback: str = "full"  # full | skip
    svf_always_include: List[str] = field(default_factory=list)
    svf_symbol_closure: bool = True
    svf_exclusive_pools: List[Dict[str, Any]] = field(default_factory=list)
    svf_shared_pools: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AnalysisConfig:
    """Configuration for analysis behavior."""

    max_recursion_depth: int = 3
    max_function_lines: int = 500
    max_tool_iterations: int = 50
    snapshot_dir: str = ".zscope_snapshots"
    enable_snapshot_cache: bool = True
    parallel_workers: int = 5  # Number of concurrent workers for batch analysis
    user_config_db: str = ""  # Path to user config workbook or directory, defaults to {snapshot_dir}/
    max_premodel_depth: int = 3  # Callee recursive pre-modeling max depth
    max_premodel_callees: int = 20  # Max callees to expand per level
    trivial_function_max_lines: int = 5  # Skip modeling if function <= this many valid lines
    workflow_name: str = "default"
    enable_subagent_workers: bool = False
    max_subagent_tickets: int = 4
    subagent_max_turns: int = 20  # Per-ticket tool/LLM turn budget for focused workers.
    subagent_ticket_timeout: float = 0.0  # Seconds per focused worker ticket; 0 disables timeout.
    validation_parallel_workers: int = 0  # 0 auto; set 1 to keep validator calls serial per entry.
    subagent_spawn_allowlist: List[str] = field(default_factory=lambda: ["deep_worker"])
    subagent_skill_llm_refs: Dict[str, str] = field(default_factory=dict)
    subagent_skill_efforts: Dict[str, str] = field(default_factory=dict)
    tool_audit_log: str = ""  # Optional JSONL audit sink for tool/MCP policy events.


@dataclass
class SemanticDedupConfig:
    """Configuration for final-report semantic duplicate handling."""

    enabled: bool = True
    llm_enabled: bool = True
    llm_confidence_threshold: float = 0.85
    max_cluster_size: int = 8


@dataclass
class ReportingConfig:
    """Configuration for report assembly and presentation."""

    semantic_dedup: SemanticDedupConfig = field(default_factory=SemanticDedupConfig)


@dataclass
class ProjectConfig:
    """Configuration for the C project being analyzed."""

    project_root: Path
    source_root: Path
    entry_function: Optional[str] = None
    entry_file_path: Optional[str] = None
    agents: List[AgentConfig] = field(default_factory=list)
    compile_commands_path: Optional[Path] = None
    entry_functions_list: Optional[Path] = None  # Path to JSON file for batch mode
    entry_diff_focus: Optional[Dict[str, Any]] = None
    include_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    entry_discovery: EntryDiscoveryConfig = field(default_factory=EntryDiscoveryConfig)
    diff_impact: DiffImpactConfig = field(default_factory=DiffImpactConfig)

    def __post_init__(self):
        self.project_root = Path(self.project_root).resolve()

        # Resolve source_root: relative to project_root if not absolute
        if not self.source_root:
            self.source_root = self.project_root
        else:
            self.source_root = Path(self.source_root)
            if not self.source_root.is_absolute():
                self.source_root = (self.project_root / self.source_root).resolve()
            else:
                self.source_root = self.source_root.resolve()

        # Resolve include/exclude paths relative to source_root
        resolved_includes = []
        for p in self.include_paths or []:
            path_obj = Path(p)
            if not path_obj.is_absolute():
                resolved_includes.append((self.source_root / path_obj).absolute())
            else:
                resolved_includes.append(path_obj.absolute())
        self.include_paths = resolved_includes

        resolved_excludes = []
        for p in self.exclude_paths or []:
            path_obj = Path(p)
            if not path_obj.is_absolute():
                resolved_excludes.append((self.source_root / path_obj).absolute())
            else:
                resolved_excludes.append(path_obj.absolute())
        self.exclude_paths = resolved_excludes

        # Resolve compile_commands_path:
        #   1. 显式配置 → 相对路径基于 project_root 解析
        #   2. 自动发现 → 依次查找 project_root、source_root
        if self.compile_commands_path:
            self.compile_commands_path = Path(self.compile_commands_path)
            if not self.compile_commands_path.is_absolute():
                self.compile_commands_path = (
                    self.project_root / self.compile_commands_path
                ).resolve()
            else:
                self.compile_commands_path = self.compile_commands_path.resolve()
        else:
            # 自动发现：project_root 优先（compile_commands.json 通常在构建/任务目录）
            for root in [self.project_root, self.source_root]:
                candidate = root / "compile_commands.json"
                if candidate.exists():
                    self.compile_commands_path = candidate
                    break

        # Resolve entry_functions_list path relative to project root
        if self.entry_functions_list:
            if not Path(self.entry_functions_list).is_absolute():
                self.entry_functions_list = (
                    self.project_root / self.entry_functions_list
                ).resolve()
            else:
                self.entry_functions_list = Path(self.entry_functions_list).resolve()

        if self.entry_discovery.search_root:
            search_root = Path(self.entry_discovery.search_root)
            if not search_root.is_absolute():
                raise ValueError("project.entry_discovery.search_root must be an absolute path")
            search_root = search_root.resolve()
            if not search_root.is_dir():
                raise ValueError(
                    f"project.entry_discovery.search_root is not a directory: {search_root}"
                )
            self.entry_discovery.search_root = search_root


@dataclass
class ZScopeConfig:
    """Main configuration container."""

    llm: LLMConfig
    llms: Dict[str, LLMConfig]
    indexing: IndexingConfig
    analysis: AnalysisConfig
    project: ProjectConfig
    reporting: ReportingConfig = field(default_factory=ReportingConfig)


class ConfigLoader:
    """Load and parse ZScope configuration from YAML files."""

    DEFAULT_CONFIG_LOCATIONS = [
        "./zscope.yaml",
        "~/.zscope/config.yaml",
        "/etc/zscope/config.yaml",
    ]

    @staticmethod
    def _expand_env_vars(value: Any) -> Any:
        """Recursively expand environment variables in config values."""
        if isinstance(value, str):
            # Replace ${VAR} or $VAR with environment variable
            def replace_var(match):
                var_name = match.group(1) or match.group(2)
                return os.environ.get(var_name, match.group(0))

            return re.sub(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)", replace_var, value)
        elif isinstance(value, dict):
            return {k: ConfigLoader._expand_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [ConfigLoader._expand_env_vars(item) for item in value]
        return value

    @staticmethod
    def _string_list(value: Any, default: Optional[List[str]] = None) -> List[str]:
        if value is None:
            return list(default or [])
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        if isinstance(value, list):
            return [str(part).strip() for part in value if str(part).strip()]
        return list(default or [])

    @staticmethod
    def _string_dict(value: Any) -> Dict[str, str]:
        if not isinstance(value, dict):
            return {}
        return {str(key): str(val) for key, val in value.items() if str(key).strip() and str(val).strip()}

    @staticmethod
    def _int_dict(value: Any, default: Optional[Dict[str, int]] = None) -> Dict[str, int]:
        result = dict(default or {})
        if not isinstance(value, dict):
            return result
        for key, val in value.items():
            clean_key = str(key).strip()
            if not clean_key:
                continue
            result[clean_key] = max(0, _safe_int(val, result.get(clean_key, 0)))
        return result

    @staticmethod
    def _config_string(value: Any, default: str) -> str:
        if value is None:
            return default
        if isinstance(value, bool):
            return "on" if value else "off"
        cleaned = str(value).strip()
        return cleaned or default

    @staticmethod
    def load(config_path: Optional[str] = None) -> ZScopeConfig:
        """
        Load configuration from YAML file.
        """
        if yaml is None:
            raise ImportError("PyYAML is required for config file support.")

        # Find config file
        config_file = None
        if config_path:
            config_file = Path(config_path).expanduser()
            if not config_file.exists():
                raise FileNotFoundError(f"Config file not found: {config_file}")
        else:
            for loc in ConfigLoader.DEFAULT_CONFIG_LOCATIONS:
                potential_path = Path(loc).expanduser()
                if potential_path.exists():
                    config_file = potential_path
                    logger.info(f"Using config file: {config_file}")
                    break

        if not config_file:
            raise FileNotFoundError("No config file found.")

        # Load YAML
        with open(config_file, "r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f)

        if not isinstance(raw_config, dict):
            raise ValueError(f"Invalid config file: {config_file}")

        # Expand environment variables
        raw_config = ConfigLoader._expand_env_vars(raw_config)

        # Parse sections
        try:
            # LLM config
            llms_data = raw_config.get("llms", {})
            llm_data = raw_config.get("llm", {})

            parsed_llms = {}
            default_llm_config = None

            # 1. Parse legacy 'llm' block if present
            if llm_data:
                models = llm_data.get("models", [])
                if not models and llm_data.get("model"):
                    models = [llm_data.get("model")]
                if models:
                    base_urls = _normalize_llm_base_urls(
                        llm_data.get(
                            "base_urls",
                            llm_data.get("base_url", "https://api.openai.com/v1"),
                        )
                    )
                    default_llm_config = LLMConfig(
                        provider=llm_data.get("provider", "openai"),
                        api_key=llm_data.get("api_key", ""),
                        base_url=base_urls[0],
                        base_urls=base_urls,
                        base_url_rate_limit_per_minute=_safe_int(
                            llm_data.get(
                                "base_url_rate_limit_per_minute",
                                llm_data.get(
                                    "base_url_rpm",
                                    llm_data.get("requests_per_minute", 0),
                                ),
                            )
                        ),
                        base_url_max_concurrent_requests=_safe_int(
                            llm_data.get(
                                "base_url_max_concurrent_requests",
                                llm_data.get(
                                    "base_url_max_in_flight",
                                    llm_data.get("max_concurrent_requests", 0),
                                ),
                            )
                        ),
                        models=models,
                        temperature=llm_data.get("temperature", 0.1),
                        max_tokens=llm_data.get("max_tokens", 4096),
                        timeout=llm_data.get("timeout", 120),
                        max_retries=llm_data.get("max_retries", 2),
                    )
                    parsed_llms["default"] = default_llm_config

            # 2. Parse 'llms' block if present
            for name, data in llms_data.items():
                models = data.get("models", [])
                if not models and data.get("model"):
                    models = [data.get("model")]
                if not models:
                    logger.warning(f"Skipping LLM config '{name}' due to missing models")
                    continue
                base_urls = _normalize_llm_base_urls(
                    data.get(
                        "base_urls",
                        data.get("base_url", "https://api.openai.com/v1"),
                    )
                )
                cfg = LLMConfig(
                    provider=data.get("provider", "openai"),
                    api_key=data.get("api_key", ""),
                    base_url=base_urls[0],
                    base_urls=base_urls,
                    base_url_rate_limit_per_minute=_safe_int(
                        data.get(
                            "base_url_rate_limit_per_minute",
                            data.get(
                                "base_url_rpm",
                                data.get("requests_per_minute", 0),
                            ),
                        )
                    ),
                    base_url_max_concurrent_requests=_safe_int(
                        data.get(
                            "base_url_max_concurrent_requests",
                            data.get(
                                "base_url_max_in_flight",
                                data.get("max_concurrent_requests", 0),
                            ),
                        )
                    ),
                    models=models,
                    temperature=data.get("temperature", 0.1),
                    max_tokens=data.get("max_tokens", 4096),
                    timeout=data.get("timeout", 120),
                    max_retries=data.get("max_retries", 2),
                )
                parsed_llms[name] = cfg
                if default_llm_config is None and name == "default":
                    default_llm_config = cfg

            if not parsed_llms:
                raise ValueError("Missing 'llm' or 'llms' configuration.")

            if default_llm_config is None:
                default_llm_config = list(parsed_llms.values())[0]
                parsed_llms["default"] = default_llm_config

            # Indexing config
            indexing_data = raw_config.get("indexing", {})
            indexing_config = IndexingConfig(
                backend=indexing_data.get("backend", "joern"),
                joern_path=indexing_data.get("joern_path", "joern"),
                joern_server_host=indexing_data.get("joern_server_host", "127.0.0.1"),
                joern_server_port=indexing_data.get("joern_server_port", 8080),
                joern_heap_size=indexing_data.get("joern_heap_size", "8g"),
                clangd_path=indexing_data.get("clangd_path", "clangd"),
                knowledge_db_path=indexing_data.get(
                    "knowledge_db_path", ".zscope_knowledge/code_knowledge.db"
                ),
                batch_size=indexing_data.get("batch_size", 50),
                max_clangd_threads=indexing_data.get("max_clangd_threads", 8),
                svf_bin_dir=indexing_data.get("svf_bin_dir", ""),
                gclang_path=indexing_data.get("gclang_path", "gclang"),
                get_bc_path=indexing_data.get("get_bc_path", "get-bc"),
                llvm_link_path=indexing_data.get("llvm_link_path", "llvm-link"),
                svf_heap_limit_mb=indexing_data.get("svf_heap_limit_mb", 32768),
                svf_timeout=indexing_data.get("svf_timeout", 1800),
                svf_groups_config=indexing_data.get("svf_groups_config", ""),
                svf_scope=indexing_data.get("svf_scope", "auto"),
                svf_entry_depth=indexing_data.get("svf_entry_depth", 4),
                svf_max_selected_tus=indexing_data.get("svf_max_selected_tus", 300),
                svf_fallback=indexing_data.get("svf_fallback", "full"),
                svf_always_include=indexing_data.get("svf_always_include", []) or [],
                svf_symbol_closure=indexing_data.get("svf_symbol_closure", True),
                svf_exclusive_pools=indexing_data.get("svf_exclusive_pools", []) or [],
                svf_shared_pools=indexing_data.get("svf_shared_pools", []) or [],
            )

            # Analysis config
            analysis_data = raw_config.get("analysis", {})
            if "workflow_name" in analysis_data:
                raise ValueError(
                    "'analysis.workflow_name' is runtime-only and cannot be set in zscope.yaml. "
                    "Use CLI flags such as --resume or --maintain to select a workflow."
                )
            analysis_config = AnalysisConfig(
                max_recursion_depth=analysis_data.get("max_recursion_depth", 3),
                max_function_lines=analysis_data.get("max_function_lines", 500),
                max_tool_iterations=analysis_data.get("max_tool_iterations", 50),
                snapshot_dir=analysis_data.get("snapshot_dir", ".zscope_snapshots"),
                enable_snapshot_cache=analysis_data.get("enable_snapshot_cache", True),
                parallel_workers=analysis_data.get("parallel_workers", 5),
                user_config_db=analysis_data.get("user_config_db", ""),
                max_premodel_depth=analysis_data.get("max_premodel_depth", 3),
                max_premodel_callees=analysis_data.get("max_premodel_callees", 20),
                trivial_function_max_lines=analysis_data.get("trivial_function_max_lines", 5),
                workflow_name="default",
                enable_subagent_workers=analysis_data.get("enable_subagent_workers", False),
                max_subagent_tickets=analysis_data.get("max_subagent_tickets", 4),
                subagent_max_turns=analysis_data.get("subagent_max_turns", 20),
                subagent_ticket_timeout=analysis_data.get("subagent_ticket_timeout", 0.0),
                validation_parallel_workers=analysis_data.get("validation_parallel_workers", 0),
                subagent_spawn_allowlist=ConfigLoader._string_list(
                    analysis_data.get("subagent_spawn_allowlist"),
                    default=["deep_worker"],
                ),
                subagent_skill_llm_refs=ConfigLoader._string_dict(
                    analysis_data.get("subagent_skill_llm_refs")
                ),
                subagent_skill_efforts=ConfigLoader._string_dict(
                    analysis_data.get("subagent_skill_efforts")
                ),
                tool_audit_log=analysis_data.get("tool_audit_log", ""),
            )

            reporting_data = raw_config.get("reporting", {}) or {}
            semantic_dedup_data = reporting_data.get("semantic_dedup", {}) or {}
            reporting_config = ReportingConfig(
                semantic_dedup=SemanticDedupConfig(
                    enabled=semantic_dedup_data.get("enabled", True),
                    llm_enabled=semantic_dedup_data.get("llm_enabled", True),
                    llm_confidence_threshold=float(
                        semantic_dedup_data.get("llm_confidence_threshold", 0.85)
                    ),
                    max_cluster_size=int(semantic_dedup_data.get("max_cluster_size", 8)),
                )
            )

            # Project config
            project_data = raw_config.get("project", {})
            if not project_data:
                raise ValueError("Missing 'project' section")

            project_root = project_data.get("root")
            if not project_root:
                raise ValueError("Missing 'project.root'")

            entry_function = project_data.get("entry_function")
            entry_file_path = project_data.get("entry_file_path")
            entry_functions_list = project_data.get("entry_functions_list")

            entry_discovery_data = project_data.get("entry_discovery") or {}
            entry_discovery_config = EntryDiscoveryConfig(
                enabled=entry_discovery_data.get("enabled", False),
                max_candidates=entry_discovery_data.get("max_candidates", 200),
                max_functions=entry_discovery_data.get("max_functions", 10000),
                header_files=entry_discovery_data.get("header_files", []),
                search_root=(
                    entry_discovery_data.get("search_root")
                    or entry_discovery_data.get("root")
                    or entry_discovery_data.get("discovery_root")
                ),
            )
            diff_impact_data = project_data.get("diff_impact") or {}
            diff_impact_defaults = DiffImpactConfig()
            diff_impact_config = DiffImpactConfig(
                strategy=ConfigLoader._config_string(
                    diff_impact_data.get("strategy"),
                    diff_impact_defaults.strategy,
                ),
                llm_triage=ConfigLoader._config_string(
                    diff_impact_data.get("llm_triage"),
                    diff_impact_defaults.llm_triage,
                ),
                caller_search_depth_by_intent=ConfigLoader._int_dict(
                    diff_impact_data.get("caller_search_depth_by_intent"),
                    diff_impact_defaults.caller_search_depth_by_intent,
                ),
            )
            # Parse Agents
            agents_data = project_data.get("agents", [])
            agents = []
            for a in agents_data:
                agents.append(
                    AgentConfig(
                        name=a.get("name"),
                        task=a.get("task"),
                        enabled=a.get("enabled", True),
                        llm_ref=a.get("llm_ref"),
                        skills=a.get("skills", []) or [],
                        tools=a.get("tools", []) or [],
                        mcp_servers=a.get("mcp_servers", []) or a.get("mcpServers", []) or [],
                        can_spawn_subagents=a.get("can_spawn_subagents"),
                    )
                )

            # Fallback for old 'task' field
            if not agents and project_data.get("task"):
                agents.append(
                    AgentConfig(name="vulnerability_analyzer", task=project_data.get("task"))
                )

            compile_commands = project_data.get("compile_commands_path") or project_data.get(
                "compile_commands"
            )
            compile_commands_path = Path(compile_commands) if compile_commands else None

            # Parse entry_functions_list for batch mode
            entry_functions_list = project_data.get("entry_functions_list")
            entry_functions_list_path = Path(entry_functions_list) if entry_functions_list else None

            project_config = ProjectConfig(
                project_root=Path(project_root),
                source_root=Path(project_data.get("source_root", project_root)),
                entry_function=entry_function,
                entry_file_path=entry_file_path,
                agents=agents,
                compile_commands_path=compile_commands_path,
                entry_functions_list=Path(entry_functions_list) if entry_functions_list else None,
                include_paths=project_data.get("include_paths", []),
                exclude_paths=project_data.get("exclude_paths", []),
                entry_discovery=entry_discovery_config,
                diff_impact=diff_impact_config,
            )

            return ZScopeConfig(
                llm=default_llm_config,
                llms=parsed_llms,
                indexing=indexing_config,
                analysis=analysis_config,
                project=project_config,
                reporting=reporting_config,
            )

        except KeyError as e:
            raise ValueError(f"Missing required config key: {e}")
        except Exception as e:
            raise ValueError(f"Invalid config format: {e}")
