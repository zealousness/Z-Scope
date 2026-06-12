from pathlib import Path

from zscope.config.config import (
    AgentConfig,
    AnalysisConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry, FunctionListLoader
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


def test_entry_config_copy_isolates_project_and_agent_state() -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.base_config = _config_with_task("general security audit")

    first = analyzer._create_config_for_entry(
        FunctionEntry("first", custom_prompt="Focus first", file_path="src/a.c")
    )
    second = analyzer._create_config_for_entry(
        FunctionEntry("second", custom_prompt="Focus second", file_path="src/b.c")
    )

    assert first is not analyzer.base_config
    assert first.project is not analyzer.base_config.project
    assert first.project.agents is not analyzer.base_config.project.agents
    assert first.project.agents[0] is not analyzer.base_config.project.agents[0]
    assert first.project.entry_function == "first"
    assert second.project.entry_function == "second"
    assert first.project.agents[0].entry_custom_prompt == "Focus first"
    assert second.project.agents[0].entry_custom_prompt == "Focus second"

    first.project.agents[0].entry_custom_prompt = "mutated"

    assert analyzer.base_config.project.agents[0].entry_custom_prompt is None
    assert second.project.agents[0].entry_custom_prompt == "Focus second"


def test_parallel_scheduler_prioritizes_heavy_input_entries() -> None:
    class FakeCodeIndex:
        def get_function_impl(self, func_name, **kwargs):
            if func_name == "entry_a":
                code = "\n".join(
                    f"{idx} | if (argc) {{ recv(fd, buf, sizeof(buf)); process_message(buf); }}"
                    for idx in range(1, 80)
                )
            else:
                code = "1 | return 0;"
            return {"code": code}

    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.base_config = _config_with_task("general security audit")
    analyzer.code_index = FakeCodeIndex()

    entries = [
        FunctionEntry("small_api", exposure="api", reasons=["declared_in_header"]),
        FunctionEntry("entry_a", exposure="other_user_input", reasons=["input:argv"]),
        FunctionEntry("entry_b", exposure="thread", reasons=["thread_entry:pthread_create"]),
    ]

    prioritized = analyzer._prioritize_entries_for_execution(entries)

    assert [entry.function_name for entry in prioritized][:2] == ["entry_a", "entry_b"]


def test_parallel_scheduler_does_not_score_function_names() -> None:
    class FakeCodeIndex:
        def get_function_impl(self, func_name, **kwargs):
            return {"code": "1 | int x = 0;\n2 | return x;"}

    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.base_config = _config_with_task("general security audit")
    analyzer.code_index = FakeCodeIndex()

    entries = [
        FunctionEntry("main"),
        FunctionEntry("runtime_worker_dispatch"),
        FunctionEntry("plain_entry"),
    ]

    prioritized = analyzer._prioritize_entries_for_execution(entries)

    assert [entry.function_name for entry in prioritized] == [
        "main",
        "runtime_worker_dispatch",
        "plain_entry",
    ]


def test_function_list_loader_preserves_entry_discovery_metadata(tmp_path) -> None:
    path = tmp_path / "entries.json"
    path.write_text(
        """
        {
          "functions": [
            {
              "function_name": "main",
              "exposure": "other_user_input",
              "reasons": ["input:argv"]
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    entries = FunctionListLoader.load(path)

    assert entries[0].exposure == "other_user_input"
    assert entries[0].reasons == ["input:argv"]


def test_function_list_loader_restores_diff_focus_from_file_metadata(tmp_path) -> None:
    path = tmp_path / "entry_functions_diff.json"
    path.write_text(
        """
        {
          "mode": "diff_impact",
          "diff_impact": {
            "mode": "diff_impact",
            "component": "repo_a",
            "base_ref": "base",
            "head_ref": "head",
            "changed_functions": [
              {
                "function_name": "Changed",
                "file_path": "src/changed.c",
                "changed_lines": [12]
              }
            ]
          },
          "functions": [
            {
              "function_name": "Api",
              "file_path": "src/api.c"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    entries = FunctionListLoader.load(path)
    focus = entries[0].diff_focus

    assert focus["mode"] == "diff_impact"
    assert focus["component"] == "repo_a"
    assert focus["base_ref"] == "base"
    assert focus["entry_function"] == "Api"
    assert focus["entry_file_path"] == "src/api.c"
    assert focus["changed_functions"][0]["function_name"] == "Changed"
