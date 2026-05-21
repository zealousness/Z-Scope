from pathlib import Path

from zscope.config.config import (
    AgentConfig,
    AnalysisConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer


def _config_with_task(task: str) -> ZScopeConfig:
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(),
        analysis=AnalysisConfig(),
        project=ProjectConfig(
            project_root=Path("."),
            source_root=Path("."),
            agents=[AgentConfig(name="vulnerability_analyzer", task=task)],
        ),
    )


def test_custom_prompt_does_not_replace_empty_vulnerability_task() -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.base_config = _config_with_task("")

    config = analyzer._create_config_for_entry(
        FunctionEntry("entry", custom_prompt="Focus on caller-controlled input")
    )
    agent_cfg = config.project.agents[0]

    assert agent_cfg.task == ""
    assert agent_cfg.entry_custom_prompt == "Focus on caller-controlled input"


def test_custom_prompt_does_not_append_to_vulnerability_task() -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.base_config = _config_with_task("general security audit")

    config = analyzer._create_config_for_entry(
        FunctionEntry("entry", custom_prompt="Focus on async handoff")
    )
    agent_cfg = config.project.agents[0]

    assert agent_cfg.task == "general security audit"
    assert agent_cfg.entry_custom_prompt == "Focus on async handoff"
