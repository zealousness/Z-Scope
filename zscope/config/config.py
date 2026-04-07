"""
Configuration management for Z-SCOPE.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """Configuration for LLM client."""

    provider: str = "openai"  # 预留字段，当前未在运行时使用
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    models: List[str] = field(default_factory=list)
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 120
    max_retries: int = 2


@dataclass
class AgentConfig:
    """Configuration for a specific agent."""
    name: str
    task: Optional[str] = None
    enabled: bool = True
    llm_ref: Optional[str] = None


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



@dataclass
class AnalysisConfig:
    """Configuration for analysis behavior."""

    max_recursion_depth: int = 3
    max_function_lines: int = 500
    max_tool_iterations: int = 50
    snapshot_dir: str = ".zscope_snapshots"
    enable_snapshot_cache: bool = True
    parallel_workers: int = 5  # Number of concurrent workers for batch analysis
    user_config_db: str = ""  # Path to user config DB, defaults to {snapshot_dir}/
    max_premodel_depth: int = 3  # Callee recursive pre-modeling max depth
    max_premodel_callees: int = 20  # Max callees to expand per level
    trivial_function_max_lines: int = 5  # Skip modeling if function <= this many valid lines


@dataclass
class ProjectConfig:
    """Configuration for the C project being analyzed."""

    project_root: Path
    source_root: Path
    entry_function: Optional[str] = None
    agents: List[AgentConfig] = field(default_factory=list)
    compile_commands_path: Optional[Path] = None
    entry_functions_list: Optional[Path] = None  # Path to JSON file for batch mode
    include_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)

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
        for p in (self.include_paths or []):
            path_obj = Path(p)
            if not path_obj.is_absolute():
                resolved_includes.append((self.source_root / path_obj).absolute())
            else:
                resolved_includes.append(path_obj.absolute())
        self.include_paths = resolved_includes

        resolved_excludes = []
        for p in (self.exclude_paths or []):
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
                self.compile_commands_path = (self.project_root / self.compile_commands_path).resolve()
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
                self.entry_functions_list = (self.project_root / self.entry_functions_list).resolve()
            else:
                self.entry_functions_list = Path(self.entry_functions_list).resolve()


@dataclass
class ZScopeConfig:
    """Main configuration container."""

    llm: LLMConfig
    llms: Dict[str, LLMConfig]
    indexing: IndexingConfig
    analysis: AnalysisConfig
    project: ProjectConfig


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
                    default_llm_config = LLMConfig(
                        provider=llm_data.get("provider", "openai"),
                        api_key=llm_data.get("api_key", ""),
                        base_url=llm_data.get("base_url", "https://api.openai.com/v1"),
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
                cfg = LLMConfig(
                    provider=data.get("provider", "openai"),
                    api_key=data.get("api_key", ""),
                    base_url=data.get("base_url", "https://api.openai.com/v1"),
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
                knowledge_db_path=indexing_data.get("knowledge_db_path", ".zscope_knowledge/code_knowledge.db"),
                batch_size=indexing_data.get("batch_size", 50),
                max_clangd_threads=indexing_data.get("max_clangd_threads", 8),
                svf_bin_dir=indexing_data.get("svf_bin_dir", ""),
                gclang_path=indexing_data.get("gclang_path", "gclang"),
                get_bc_path=indexing_data.get("get_bc_path", "get-bc"),
                llvm_link_path=indexing_data.get("llvm_link_path", "llvm-link"),
                svf_heap_limit_mb=indexing_data.get("svf_heap_limit_mb", 32768),
                svf_timeout=indexing_data.get("svf_timeout", 1800),
            )

            # Analysis config
            analysis_data = raw_config.get("analysis", {})
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
            )

            # Project config
            project_data = raw_config.get("project", {})
            if not project_data:
                raise ValueError("Missing 'project' section")

            project_root = project_data.get("root")
            if not project_root:
                raise ValueError("Missing 'project.root'")

            entry_function = project_data.get("entry_function")
            entry_functions_list = project_data.get("entry_functions_list")
            
            if not entry_function and not entry_functions_list:
                raise ValueError("Either 'project.entry_function' or 'project.entry_functions_list' must be provided.")

            # Parse Agents
            agents_data = project_data.get("agents", [])
            agents = []
            for a in agents_data:
                agents.append(AgentConfig(
                    name=a.get("name"),
                    task=a.get("task"),
                    enabled=a.get("enabled", True),
                    llm_ref=a.get("llm_ref")
                ))
            
            # Fallback for old 'task' field
            if not agents and project_data.get("task"):
                 agents.append(AgentConfig(name="vulnerability_analyzer", task=project_data.get("task")))

            compile_commands = project_data.get("compile_commands_path") or project_data.get("compile_commands")
            compile_commands_path = Path(compile_commands) if compile_commands else None
            
            # Parse entry_functions_list for batch mode
            entry_functions_list = project_data.get("entry_functions_list")
            entry_functions_list_path = Path(entry_functions_list) if entry_functions_list else None

            project_config = ProjectConfig(
                project_root=Path(project_root),
                source_root=Path(project_data.get("source_root", project_root)),
                entry_function=entry_function,
                agents=agents,
                compile_commands_path=compile_commands_path,
                entry_functions_list=Path(entry_functions_list) if entry_functions_list else None,
                include_paths=project_data.get("include_paths", []),
                exclude_paths=project_data.get("exclude_paths", []),
            )

            return ZScopeConfig(
                llm=default_llm_config,
                llms=parsed_llms,
                indexing=indexing_config,
                analysis=analysis_config,
                project=project_config,
            )

        except KeyError as e:
            raise ValueError(f"Missing required config key: {e}")
        except Exception as e:
            raise ValueError(f"Invalid config format: {e}")
