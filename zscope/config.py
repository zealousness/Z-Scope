"""
Configuration management for Z-SCOPE.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class LLMConfig:
    """Configuration for LLM client."""

    api_key: str
    base_url: str
    model: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 120
    max_retries: int = 3


@dataclass
class AnalysisConfig:
    """Configuration for analysis behavior."""

    max_recursion_depth: int = 3
    max_function_lines: int = 500
    max_tool_iterations: int = 50
    snapshot_dir: str = ".zscope_snapshots"
    enable_snapshot_cache: bool = True


@dataclass
class ProjectConfig:
    """Configuration for the C project being analyzed."""

    project_root: Path
    entry_function: str
    task_description: str
    compile_commands_path: Optional[Path] = None

    def __post_init__(self):
        self.project_root = Path(self.project_root).resolve()
        if self.compile_commands_path:
            self.compile_commands_path = Path(self.compile_commands_path).resolve()
        elif (self.project_root / "compile_commands.json").exists():
            self.compile_commands_path = self.project_root / "compile_commands.json"


@dataclass
class ZScopeConfig:
    """Main configuration container."""

    llm: LLMConfig
    analysis: AnalysisConfig
    project: ProjectConfig
