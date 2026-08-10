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


def test_function_entry_identity_is_cross_platform_and_signature_complete(
    tmp_path,
) -> None:
    source = tmp_path / "src" / "net" / "handler.c"
    windows_style = str(source).replace("/", "\\")
    absolute_entry = FunctionEntry(
        "handle",
        file_path=windows_style,
        signature="int   handle( const char * value )",
    )
    relative_entry = FunctionEntry(
        "handle",
        file_path="src/net/handler.c",
        signature="int handle( const char * value )",
    )

    assert absolute_entry.identity_key(tmp_path) == relative_entry.identity_key(tmp_path)
    assert relative_entry.identity_key(tmp_path) == (
        "src/net/handler.c::int handle( const char * value )"
    )


def test_function_list_loader_preserves_entry_signature(tmp_path) -> None:
    path = tmp_path / "entries.json"
    path.write_text(
        """
        {
          "functions": [
            {
              "function_name": "handle",
              "file_path": "src/handler.c",
              "signature": "int handle(const char *value)"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    entry = FunctionListLoader.load(path)[0]

    assert entry.lookup_query() == "int handle(const char *value)"
    assert entry.identity_key() == ("src/handler.c::int handle(const char *value)")


def test_function_entry_identity_keeps_java_qualified_method_name(tmp_path) -> None:
    file_path = "src/main/java/demo/Controller.java"
    first = FunctionEntry(
        "demo.Controller.first:java.lang.String(java.lang.String)",
        file_path=file_path,
        signature="java.lang.String(java.lang.String)",
    )
    second = FunctionEntry(
        "demo.Controller.second:java.lang.String(java.lang.String)",
        file_path=file_path,
        signature="java.lang.String(java.lang.String)",
    )

    assert first.identity_key(tmp_path) != second.identity_key(tmp_path)
    assert first.identity_key(tmp_path) == (
        "src/main/java/demo/Controller.java::"
        "demo.Controller.first:java.lang.String(java.lang.String)::"
        "java.lang.String(java.lang.String)"
    )


def test_parallel_entry_result_key_distinguishes_same_file_overloads() -> None:
    integer = FunctionEntry(
        "parse",
        file_path=r"src\parser.cc",
        signature="int parse(int value)",
    )
    text = FunctionEntry(
        "parse",
        file_path="src/parser.cc",
        signature="int parse(const char *value)",
    )

    integer_key = ParallelAnalyzer._entry_result_key(integer)
    text_key = ParallelAnalyzer._entry_result_key(text)

    assert integer_key != text_key
    assert "src/parser.cc" in integer_key
    assert "int parse(int value)" in integer_key


def test_parallel_materializes_ambiguous_legacy_entry_as_distinct_identities(
    tmp_path,
) -> None:
    class SameNameIndex:
        def find_function_identities(self, func_name, file_path=""):
            assert func_name == "handle"
            return [
                {
                    "function_name": "handle",
                    "file_path": r"src\alpha\handler.c",
                    "signature": "static int handle(int value)",
                },
                {
                    "function_name": "handle",
                    "file_path": "src/beta/handler.c",
                    "signature": "static int handle(const char *value)",
                },
            ]

    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.base_config = _config_with_task("general security audit")
    analyzer.base_config.project.project_root = tmp_path
    analyzer.code_index = SameNameIndex()

    entries = analyzer._materialize_entry_identities([FunctionEntry("handle")])

    assert [entry.identity_key(tmp_path) for entry in entries] == [
        "src/alpha/handler.c::static int handle(int value)",
        "src/beta/handler.c::static int handle(const char *value)",
    ]


def test_parallel_materializes_java_entries_with_same_descriptor(tmp_path) -> None:
    first = "demo.Controller.first:java.lang.String(java.lang.String)"
    second = "demo.Controller.second:java.lang.String(java.lang.String)"

    class JavaIndex:
        def find_function_identities(self, func_name, file_path=""):
            assert file_path == ""
            return [
                {
                    "function_name": func_name,
                    "file_path": "src/main/java/demo/Controller.java",
                    "signature": "java.lang.String(java.lang.String)",
                }
            ]

    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.base_config = _config_with_task("general security audit")
    analyzer.base_config.project.project_root = tmp_path
    analyzer.code_index = JavaIndex()

    entries = analyzer._materialize_entry_identities([FunctionEntry(first), FunctionEntry(second)])

    assert [entry.function_name for entry in entries] == [first, second]


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
