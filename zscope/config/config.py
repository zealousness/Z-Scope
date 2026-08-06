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


def _safe_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _optional_positive_seconds(value: Any, default: Optional[float]) -> Optional[float]:
    """Parse a deadline once, preserving one-release legacy sentinel support.

    New configuration should use ``null`` for unlimited.  Legacy ``0``, ``-1``
    and ``"unlimited"`` are accepted here only so individual subsystems never
    assign conflicting meanings to them.
    """
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in {
        "",
        "none",
        "null",
        "unlimited",
    }:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid deadline value: {value!r}") from exc
    return seconds if seconds > 0 else None


def minimum_optional_positive_seconds(*values: Any) -> Optional[float]:
    """Return the strictest configured deadline, or ``None`` if all are unlimited."""

    parsed = [
        _optional_positive_seconds(value, None)
        for value in values
        if value is not None
    ]
    positive = [value for value in parsed if value is not None]
    return min(positive) if positive else None


def _optional_positive_int(value: Any, default: Optional[int]) -> Optional[int]:
    """Parse an optional positive limit at the configuration boundary.

    ``null`` is the canonical unlimited value.  Legacy non-positive numbers
    and the string ``unlimited`` remain accepted for one release, but are
    normalized here so downstream schedulers never assign their own meaning.
    """

    if value is None:
        return default
    if isinstance(value, str) and value.strip().lower() in {
        "",
        "none",
        "null",
        "unlimited",
    }:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid positive integer limit: {value!r}") from exc
    return parsed if parsed > 0 else None


def _bounded_cache_entries(value: Any, default: int = 4096) -> int:
    """Normalize a bounded cache size; ``null`` means the cache is disabled."""

    if value is None:
        return 0
    if isinstance(value, str) and value.strip().lower() in {
        "",
        "none",
        "null",
        "disabled",
        "unlimited",
    }:
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid cache entry limit: {value!r}") from exc
    return parsed if parsed > 0 else 0


def _normalize_budget_exhaustion_policy(value: Any) -> str:
    """Normalize runtime budgets to observability-only semantics.

    Budgets are tuning signals, not cancellation authority.  Legacy
    ``cancel``/``hard`` spellings remain accepted for one release, but are
    deliberately mapped to ``observe`` so an available LLM cannot be turned
    into an entry failure merely by exhausting a local budget.
    """

    normalized = str(value or "observe").strip().lower().replace("-", "_")
    aliases = {
        "observe": "observe",
        "observe_only": "observe",
        "soft": "observe",
        "cancel": "observe",
        "hard": "observe",
        "enforce": "observe",
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise ValueError(
            "Invalid budget_exhaustion_policy "
            f"{value!r}; expected 'observe' (legacy cancel/hard are accepted "
            "as observe-only aliases)."
        ) from exc


@dataclass
class LLMConfig:
    """Configuration for LLM client."""

    provider: str = "openai"  # 预留字段，当前未在运行时使用
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    base_urls: List[str] = field(default_factory=list)
    base_url_rate_limit_per_minute: Optional[int] = None
    base_url_max_concurrent_requests: Optional[int] = None
    models: List[str] = field(default_factory=list)
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: Optional[float] = 120.0
    max_retries: int = 2
    retry_until_available: bool = False
    supports_structured_output: bool = False

    def __post_init__(self) -> None:
        self.base_urls = _normalize_llm_base_urls(self.base_urls or self.base_url)
        self.base_url = self.base_urls[0]
        self.base_url_rate_limit_per_minute = _optional_positive_int(
            self.base_url_rate_limit_per_minute,
            None,
        )
        self.base_url_max_concurrent_requests = _optional_positive_int(
            self.base_url_max_concurrent_requests,
            None,
        )
        self.timeout = _optional_positive_seconds(self.timeout, 120.0)


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
    shared_cache_max_bytes: int = 512 * 1024 * 1024
    # SVF 配置（Phase 4+）
    svf_bin_dir: str = ""  # SVF 工具目录（含 wpa, saber 等）
    gclang_path: str = "gclang"  # gllvm 前端路径
    get_bc_path: str = "get-bc"  # gllvm 提取 bc 路径
    llvm_link_path: str = "llvm-link"
    svf_heap_limit_mb: int = 32768  # SVF 内存上限（默认 32GB）
    svf_timeout: Optional[float] = 1800.0  # null means no subprocess deadline.
    svf_groups_config: str = ""  # JSON file for multi-group bitcode linking
    svf_scope: str = "auto"  # full | auto | entry
    svf_entry_depth: int = 4
    svf_max_selected_tus: int = 200
    svf_fallback: str = "full"  # full | skip
    svf_always_include: List[str] = field(default_factory=list)
    svf_symbol_closure: bool = True
    svf_exclusive_pools: List[Dict[str, Any]] = field(default_factory=list)
    svf_shared_pools: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.svf_timeout = _optional_positive_seconds(self.svf_timeout, 1800.0)


@dataclass
class AnalysisConfig:
    """Configuration for analysis behavior."""

    max_recursion_depth: int = 3
    max_function_lines: int = 500
    max_tool_iterations: int = 50
    snapshot_dir: str = ".zscope_snapshots"
    enable_snapshot_cache: bool = True
    # Legacy shared worker count. New configurations should prefer the
    # role-specific fields below; this remains the compatibility fallback.
    parallel_workers: int = 5
    entry_workers: int = 0  # 0 inherits parallel_workers.
    llm_max_inflight: int = 8  # Process-wide hard cap; legacy non-positive values map to 8.
    validator_workers: int = 0  # Normalized to legacy override or role default 4.
    investigator_workers: int = 0  # Normalized to role default 2.
    evidence_completion_workers: int = 2
    enable_evidence_completion_queue: bool = True
    # v3 rollout controls.  They default on for new scans, but can be
    # independently disabled for one-release shadow/rollback comparisons.
    candidate_lifecycle_v3: bool = True
    canonical_outcome_projection: bool = True
    deterministic_proof_routing: bool = True
    # Batch scans collect all deterministic candidates before one shared
    # validation queue.  Keeping this switch separate permits a one-release
    # rollback to entry-local validation for compatibility diagnostics.
    global_validation_group_queue: bool = True
    validation_cache_entries: int = 4096
    user_config_db: str = ""  # Path to user config workbook or directory, defaults to {snapshot_dir}/
    enable_global_model: bool = False  # Batch-level global premodel/model_entry replacement.
    # The normal v3 path is deterministic discovery followed by validation.
    # Keep unconstrained whole-entry LLM exploration opt-in: it is useful for
    # investigations, but is not a substitute for a candidate lifecycle and
    # multiplies the same reasoning across overlapping entries.
    candidate_first_validation: bool = True
    max_premodel_depth: int = 3  # Callee recursive pre-modeling max depth
    max_premodel_callees: int = 20  # Max callees to expand per level
    trivial_function_max_lines: int = 5  # Skip modeling if function <= this many valid lines
    workflow_name: str = "default"
    enable_subagent_workers: bool = False
    max_subagent_tickets: int = 4
    subagent_max_turns: int = 20  # Per-ticket tool/LLM turn budget for focused workers.
    request_deadline_seconds: Optional[float] = 120.0
    validation_deadline_seconds: Optional[float] = 240.0
    subagent_ticket_timeout: Optional[float] = 300.0
    entry_deadline_seconds: Optional[float] = 1800.0
    scan_deadline_seconds: Optional[float] = None
    budget_exhaustion_policy: str = "observe"
    validation_parallel_workers: int = 0  # 0 auto; set 1 to keep validator calls serial per entry.
    subagent_spawn_allowlist: List[str] = field(default_factory=lambda: ["deep_worker"])
    subagent_skill_llm_refs: Dict[str, str] = field(default_factory=dict)
    subagent_skill_efforts: Dict[str, str] = field(default_factory=dict)
    tool_audit_log: str = ""  # Optional JSONL audit sink for tool/MCP policy events.

    def __post_init__(self) -> None:
        legacy_workers = max(1, _safe_int(self.parallel_workers, 5))
        self.parallel_workers = legacy_workers

        configured_entry_workers = _safe_int(self.entry_workers, 0)
        self.entry_workers = (
            configured_entry_workers if configured_entry_workers > 0 else legacy_workers
        )
        configured_llm_limit = _safe_int(self.llm_max_inflight, 8)
        self.llm_max_inflight = (
            configured_llm_limit if configured_llm_limit > 0 else 8
        )

        legacy_validator_workers = max(
            0, _safe_int(self.validation_parallel_workers, 0)
        )
        configured_validator_workers = max(0, _safe_int(self.validator_workers, 4))
        if configured_validator_workers <= 0:
            configured_validator_workers = legacy_validator_workers or 4
        self.validator_workers = configured_validator_workers
        # Keep older consumers and serialized config views coherent.
        self.validation_parallel_workers = configured_validator_workers
        self.validation_cache_entries = _bounded_cache_entries(
            self.validation_cache_entries,
            4096,
        )
        self.request_deadline_seconds = _optional_positive_seconds(
            self.request_deadline_seconds, 120.0
        )
        self.validation_deadline_seconds = _optional_positive_seconds(
            self.validation_deadline_seconds, 240.0
        )
        self.subagent_ticket_timeout = _optional_positive_seconds(
            self.subagent_ticket_timeout, 300.0
        )
        self.entry_deadline_seconds = _optional_positive_seconds(
            self.entry_deadline_seconds, 1800.0
        )
        self.scan_deadline_seconds = _optional_positive_seconds(
            self.scan_deadline_seconds, None
        )
        self.budget_exhaustion_policy = _normalize_budget_exhaustion_policy(
            self.budget_exhaustion_policy
        )

        configured_investigator_workers = _safe_int(self.investigator_workers, 0)
        self.investigator_workers = (
            configured_investigator_workers
            if configured_investigator_workers > 0
            else 2
        )
        configured_completion_workers = _safe_int(self.evidence_completion_workers, 2)
        self.evidence_completion_workers = max(1, configured_completion_workers)


@dataclass
class SemanticDedupConfig:
    """Configuration for final-report semantic duplicate handling."""

    enabled: bool = True
    llm_enabled: bool = False
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
    project_id: str = ""
    entry_function: Optional[str] = None
    entry_file_path: Optional[str] = None
    entry_signature: Optional[str] = None
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
        self.project_id = str(self.project_id or self.project_root.name or "project").strip()

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
                        base_url_rate_limit_per_minute=llm_data.get(
                            "base_url_rate_limit_per_minute",
                            llm_data.get(
                                "base_url_rpm",
                                llm_data.get("requests_per_minute"),
                            ),
                        ),
                        base_url_max_concurrent_requests=llm_data.get(
                            "base_url_max_concurrent_requests",
                            llm_data.get(
                                "base_url_max_in_flight",
                                llm_data.get("max_concurrent_requests"),
                            ),
                        ),
                        models=models,
                        temperature=llm_data.get("temperature", 0.1),
                        max_tokens=llm_data.get("max_tokens", 4096),
                        timeout=llm_data.get("timeout", 120),
                        max_retries=llm_data.get("max_retries", 2),
                        retry_until_available=_safe_bool(
                            llm_data.get("retry_until_available", False)
                        ),
                        supports_structured_output=_safe_bool(
                            llm_data.get("supports_structured_output", False)
                        ),
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
                    base_url_rate_limit_per_minute=data.get(
                        "base_url_rate_limit_per_minute",
                        data.get(
                            "base_url_rpm",
                            data.get("requests_per_minute"),
                        ),
                    ),
                    base_url_max_concurrent_requests=data.get(
                        "base_url_max_concurrent_requests",
                        data.get(
                            "base_url_max_in_flight",
                            data.get("max_concurrent_requests"),
                        ),
                    ),
                    models=models,
                    temperature=data.get("temperature", 0.1),
                    max_tokens=data.get("max_tokens", 4096),
                    timeout=data.get("timeout", 120),
                    max_retries=data.get("max_retries", 2),
                    retry_until_available=_safe_bool(
                        data.get("retry_until_available", False)
                    ),
                    supports_structured_output=_safe_bool(
                        data.get("supports_structured_output", False)
                    ),
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
                shared_cache_max_bytes=indexing_data.get(
                    "shared_cache_max_bytes", 512 * 1024 * 1024
                ),
                svf_bin_dir=indexing_data.get("svf_bin_dir", ""),
                gclang_path=indexing_data.get("gclang_path", "gclang"),
                get_bc_path=indexing_data.get("get_bc_path", "get-bc"),
                llvm_link_path=indexing_data.get("llvm_link_path", "llvm-link"),
                svf_heap_limit_mb=indexing_data.get("svf_heap_limit_mb", 32768),
                svf_timeout=indexing_data.get("svf_timeout", 1800),
                svf_groups_config=indexing_data.get("svf_groups_config", ""),
                svf_scope=indexing_data.get("svf_scope", "auto"),
                svf_entry_depth=indexing_data.get("svf_entry_depth", 4),
                svf_max_selected_tus=indexing_data.get("svf_max_selected_tus", 200),
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
                entry_workers=analysis_data.get(
                    "entry_workers",
                    min(8, max(1, os.cpu_count() or 1)),
                ),
                llm_max_inflight=analysis_data.get("llm_max_inflight", 8),
                validator_workers=analysis_data.get("validator_workers", 4),
                investigator_workers=analysis_data.get("investigator_workers", 2),
                evidence_completion_workers=analysis_data.get(
                    "evidence_completion_workers", 2
                ),
                enable_evidence_completion_queue=analysis_data.get(
                    "enable_evidence_completion_queue", True
                ),
                candidate_lifecycle_v3=analysis_data.get(
                    "candidate_lifecycle_v3", True
                ),
                canonical_outcome_projection=analysis_data.get(
                    "canonical_outcome_projection", True
                ),
                deterministic_proof_routing=analysis_data.get(
                    "deterministic_proof_routing", True
                ),
                global_validation_group_queue=analysis_data.get(
                    "global_validation_group_queue", True
                ),
                validation_cache_entries=analysis_data.get(
                    "validation_cache_entries", 4096
                ),
                user_config_db=analysis_data.get("user_config_db", ""),
                enable_global_model=analysis_data.get("enable_global_model", False),
                candidate_first_validation=analysis_data.get(
                    "candidate_first_validation", True
                ),
                max_premodel_depth=analysis_data.get("max_premodel_depth", 3),
                max_premodel_callees=analysis_data.get("max_premodel_callees", 20),
                trivial_function_max_lines=analysis_data.get("trivial_function_max_lines", 5),
                workflow_name="default",
                enable_subagent_workers=analysis_data.get("enable_subagent_workers", False),
                max_subagent_tickets=analysis_data.get("max_subagent_tickets", 4),
                subagent_max_turns=analysis_data.get("subagent_max_turns", 20),
                request_deadline_seconds=analysis_data.get(
                    "request_deadline_seconds", 120.0
                ),
                validation_deadline_seconds=analysis_data.get(
                    "validation_deadline_seconds", 240.0
                ),
                subagent_ticket_timeout=analysis_data.get(
                    "subagent_ticket_timeout", 300.0
                ),
                entry_deadline_seconds=analysis_data.get(
                    "entry_deadline_seconds", 1800.0
                ),
                scan_deadline_seconds=analysis_data.get("scan_deadline_seconds"),
                budget_exhaustion_policy=analysis_data.get(
                    "budget_exhaustion_policy", "observe"
                ),
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
                    llm_enabled=semantic_dedup_data.get("llm_enabled", False),
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
            entry_signature = project_data.get("entry_signature")
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
                project_id=str(project_data.get("id") or project_data.get("project_id") or ""),
                entry_function=entry_function,
                entry_file_path=entry_file_path,
                entry_signature=entry_signature,
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
