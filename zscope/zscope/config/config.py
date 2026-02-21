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

    provider: str = "openai"  # openai or ollama
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


@dataclass
class IndexingConfig:
    """Configuration for code indexing."""

    backend: str = "joern"
    joern_path: str = "joern"
    joern_server_host: str = "localhost"
    joern_server_port: int = 8080
    joern_heap_size: str = "8g"
    import_timeout: int = 1800


@dataclass
class AnalysisConfig:
    """Configuration for analysis behavior."""

    max_recursion_depth: int = 3
    max_function_lines: int = 500
    max_tool_iterations: int = 50
    snapshot_dir: str = ".zscope_snapshots"
    enable_snapshot_cache: bool = True
    parallel_workers: int = 3  # Number of concurrent workers for batch analysis
    user_config_db: str = ""  # Path to user config DB, defaults to {snapshot_dir}/


@dataclass
class ProjectConfig:
    """Configuration for the C project being analyzed."""

    project_root: Path
    source_root: Path
    entry_function: Optional[str] = None
    agents: List[AgentConfig] = field(default_factory=list)
    compile_commands_path: Optional[Path] = None
    entry_functions_list: Optional[Path] = None  # Path to JSON file for batch mode

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

        if self.compile_commands_path:
            self.compile_commands_path = Path(self.compile_commands_path).resolve()
        elif (self.project_root / "compile_commands.json").exists():
            self.compile_commands_path = self.project_root / "compile_commands.json"
        
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
            llm_data = raw_config.get("llm", {})
            models = llm_data.get("models", [])
            if not models and llm_data.get("model"):
                models = [llm_data.get("model")]
            if not models:
                raise ValueError("Missing 'llm.models' or 'llm.model' configuration.")

            llm_config = LLMConfig(
                provider=llm_data.get("provider", "openai"),
                api_key=llm_data.get("api_key", ""),
                base_url=llm_data.get("base_url", "https://api.openai.com/v1"),
                models=models,
                temperature=llm_data.get("temperature", 0.1),
                max_tokens=llm_data.get("max_tokens", 4096),
                timeout=llm_data.get("timeout", 120),
                max_retries=llm_data.get("max_retries", 2),
            )

            # Indexing config
            indexing_data = raw_config.get("indexing", {})
            indexing_config = IndexingConfig(
                backend=indexing_data.get("backend", "joern"),
                joern_path=indexing_data.get("joern_path", "joern"),
                joern_server_host=indexing_data.get("joern_server_host", "localhost"),
                joern_server_port=indexing_data.get("joern_server_port", 8080),
                joern_heap_size=indexing_data.get("joern_heap_size", "8g"),
                import_timeout=indexing_data.get("import_timeout", 1800),
            )

            # Analysis config
            analysis_data = raw_config.get("analysis", {})
            analysis_config = AnalysisConfig(
                max_recursion_depth=analysis_data.get("max_recursion_depth", 3),
                max_function_lines=analysis_data.get("max_function_lines", 500),
                max_tool_iterations=analysis_data.get("max_tool_iterations", 50),
                snapshot_dir=analysis_data.get("snapshot_dir", ".zscope_snapshots"),
                enable_snapshot_cache=analysis_data.get("enable_snapshot_cache", True),
                parallel_workers=analysis_data.get("parallel_workers", 3),
                user_config_db=analysis_data.get("user_config_db", ""),
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
                    enabled=a.get("enabled", True)
                ))
            
            # Fallback for old 'task' field
            if not agents and project_data.get("task"):
                 agents.append(AgentConfig(name="vulnerability_analyzer", task=project_data.get("task")))

            compile_commands = project_data.get("compile_commands")
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
            )

            return ZScopeConfig(
                llm=llm_config,
                indexing=indexing_config,
                analysis=analysis_config,
                project=project_config,
            )

        except KeyError as e:
            raise ValueError(f"Missing required config key: {e}")
        except Exception as e:
            raise ValueError(f"Invalid config format: {e}")
