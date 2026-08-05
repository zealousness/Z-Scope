from pathlib import Path
from types import SimpleNamespace

from zscope.config.config import (
    AnalysisConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.config.user_config_store import UserConfigStore
from zscope.core.analysis import analyzer as analyzer_module
from zscope.framework.base import AgentResponse
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.global_modeler import GlobalModeler
from zscope.retrieval.code_index import CodeIndex
from zscope.snapshots.modeling_input import build_semantic_model_input
from zscope.snapshots.store import SnapshotStore


class FakeCodeIndex:
    def __init__(self):
        self.impls = {
            "entry": self._impl("entry", ["mid", "sibling"]),
            "mid": self._impl("mid", ["leaf"]),
            "leaf": self._impl("leaf", []),
            "sibling": self._impl("sibling", []),
        }

    @staticmethod
    def _impl(name, callees):
        return {
            "func_name": name,
            "file": f"src/{name}.c",
            "index_name": f"{name}@src/{name}.c:1-8",
            "start_line": 1,
            "end_line": 8,
            "signature": f"int {name}(void)",
            "is_static": False,
            "is_macro": False,
            "code": f"1 | int {name}(void) {{\n2 |     return external_{name}();\n3 | }}\n",
            "callees": list(callees),
        }

    def get_function_impl(self, func_name, **kwargs):
        for impl in self.impls.values():
            if func_name in {impl["func_name"], impl["index_name"]}:
                return impl
        return None

    def find_function_infos(self, func_name, file_path=""):
        matches = []
        for impl in self.impls.values():
            if func_name not in {impl["func_name"], impl["index_name"]}:
                continue
            if file_path and impl["file"] != file_path:
                continue
            matches.append(
                {
                    "function_name": impl["func_name"],
                    "file_path": impl["file"],
                    "index_name": impl["index_name"],
                    "start_line": impl["start_line"],
                    "end_line": impl["end_line"],
                    "signature": impl["signature"],
                    "is_static": impl["is_static"],
                    "is_macro": impl["is_macro"],
                    "project_callees": [
                        {
                            "callee_index_name": self.impls[callee]["index_name"],
                            "callsite_lines": [2],
                            "call_type": ["direct"],
                            "is_static": self.impls[callee]["is_static"],
                        }
                        for callee in impl.get("callees", [])
                    ],
                    "external_callees": [],
                    "referenced_globals": [],
                    "referenced_macros": [],
                    "referenced_types": [],
                }
            )
        return matches

    def get_callees(self, func_name, limit=30):
        impl = self.impls.get(func_name) or {}
        return [{"name": callee} for callee in impl.get("callees", [])][:limit]


class SameNameCodeIndex:
    def __init__(self):
        self.impls = {
            "src/a/handler.c": {
                "func_name": "handle",
                "file": "src/a/handler.c",
                "index_name": "handle@src/a/handler.c:1-8",
                "start_line": 1,
                "end_line": 8,
                "signature": "int handle(void)",
                "is_static": False,
                "is_macro": False,
                "code": "1 | int handle(void) {\n2 |     return external_a();\n3 | }\n",
                "callees": [],
            },
            "src/b/handler.c": {
                "func_name": "handle",
                "file": "src/b/handler.c",
                "index_name": "handle@src/b/handler.c:1-8",
                "start_line": 1,
                "end_line": 8,
                "signature": "int handle(void)",
                "is_static": False,
                "is_macro": False,
                "code": "1 | int handle(void) {\n2 |     return external_b();\n3 | }\n",
                "callees": [],
            },
        }

    def get_function_impl(self, func_name, **kwargs):
        for impl in self.impls.values():
            if func_name == impl["index_name"]:
                return impl
        assert func_name == "handle"
        return self.impls.get(kwargs.get("file_path"))

    def find_function_infos(self, func_name, file_path=""):
        matches = []
        for impl in self.impls.values():
            if func_name not in {impl["func_name"], impl["index_name"]}:
                continue
            if file_path and impl["file"] != file_path:
                continue
            matches.append(
                {
                    "function_name": impl["func_name"],
                    "file_path": impl["file"],
                    "index_name": impl["index_name"],
                    "start_line": impl["start_line"],
                    "end_line": impl["end_line"],
                    "signature": impl["signature"],
                    "is_static": impl["is_static"],
                    "is_macro": impl["is_macro"],
                    "project_callees": [],
                    "external_callees": [],
                    "referenced_globals": [],
                    "referenced_macros": [],
                    "referenced_types": [],
                }
            )
        return matches

    def get_callees(self, func_name, limit=30):
        return []


class RecordingAgent:
    def __init__(self, calls):
        self.calls = calls

    def run(self, context):
        name = context["func_name"]
        self.calls.append(name)
        return AgentResponse(
            success=True,
            data={
                "type": "function_snapshot",
                "func_name": name,
                "index_name": context["index_name"],
                "file_path": context["file_path"],
                "start_line": context["start_line"],
                "end_line": context["end_line"],
                "signature": context["signature"],
                "snapshot_kind": "LLM-modeled",
                "is_static": context["is_static"],
                "is_macro": context["is_macro"],
                "referenced_globals": context["referenced_globals"],
                "referenced_macros": context["referenced_macros"],
                "referenced_types": context["referenced_types"],
                "summary": f"modeled {name}",
                "parameters": [],
                "return_values": {"return_type": "int"},
                "effects": [],
                "error_handling": {"error_paths": []},
                "suspicious_points": [],
                "project_callees": context["project_callees"],
                "external_callees": context["external_callees"],
            },
            metadata={"context_tokens": 7},
        )


def _config(tmp_path: Path) -> ZScopeConfig:
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(),
        analysis=AnalysisConfig(
            snapshot_dir=str(tmp_path / "snapshots"),
            user_config_db=str(tmp_path / "user-config"),
            parallel_workers=2,
            max_premodel_depth=-1,
            max_premodel_callees=10,
            trivial_function_max_lines=0,
        ),
        project=ProjectConfig(project_root=tmp_path, source_root=tmp_path),
    )


def test_global_modeler_models_children_before_parents(tmp_path):
    calls = []
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    modeler = GlobalModeler(
        config,
        FakeCodeIndex(),
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
        max_workers=2,
    )

    stats = modeler.run([FunctionEntry("entry")])

    assert stats.reachable_functions == 4
    assert stats.llm_snapshot_count == 4
    assert stats.total_context_tokens == 28
    assert calls.index("leaf") < calls.index("mid") < calls.index("entry")
    assert store.load_snapshot("entry@src/entry.c:1-8")["summary"] == "modeled entry"
    entry_callees = store.load_snapshot("entry@src/entry.c:1-8")["project_callees"]
    assert {item["callee_summary"] for item in entry_callees} == {
        "modeled mid",
        "modeled sibling",
    }
    assert stats.reconciliation_failures == 0
    assert stats.stage_complete is True


def test_global_modeler_excludes_llvm_intrinsics_from_graph_and_model_input(tmp_path):
    entry_source = tmp_path / "src" / "entry.c"
    child_source = tmp_path / "src" / "child.c"
    entry_source.parent.mkdir(parents=True)
    entry_source.write_text(
        "int entry(void) { unsigned char buffer[32] = {0}; return child(); }\n",
        encoding="utf-8",
    )
    child_source.write_text("int child(void) { return 0; }\n", encoding="utf-8")

    class IntrinsicBackend:
        def build_function_index(self):
            return {
                "entry": {
                    "name": "entry",
                    "file": "src/entry.c",
                    "start_line": 1,
                    "end_line": 1,
                    "signature": "int entry(void)",
                },
                "child": {
                    "name": "child",
                    "file": "src/child.c",
                    "start_line": 1,
                    "end_line": 1,
                    "signature": "int child(void)",
                },
            }

        @staticmethod
        def _callees(func_name):
            if func_name == "entry":
                return [
                    {
                        "name": "llvm.memset.p0.i64",
                        "call_file": "src/entry.c",
                        "call_line": 0,
                        "source": "svf-ander",
                    },
                    {
                        "name": "child",
                        "filename": "src/child.c",
                        "lineNumber": 1,
                        "call_type": "direct",
                    },
                ]
            return []

        def get_callees(self, func_name, limit=30):
            return self._callees(func_name)[:limit]

        def get_function_info_callees(self, func_name, file_path=""):
            return self._callees(func_name)

        def get_function_symbol_context(self, func_name, file_path=""):
            return {"referenced_globals": [], "referenced_macros": []}

        def get_method(self, name):
            return None

        def get_method_callees(self, name, limit=30):
            return self.get_callees(name, limit=limit)

        def close(self):
            pass

    code_index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=IntrinsicBackend(),
        indexing_config=SimpleNamespace(backend="unified"),
    )
    calls = []
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))

    stats = GlobalModeler(
        config,
        code_index,
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
    ).run([FunctionEntry("entry")])

    assert stats.reachable_functions == 2
    assert stats.unresolved_external_callees == 0
    assert sorted(calls) == ["child", "entry"]
    entry_snapshot = store.load_snapshot("entry@src/entry.c:1-1")
    assert entry_snapshot is not None
    assert [item["callee_index_name"] for item in entry_snapshot["project_callees"]] == [
        "child@src/child.c:1-1"
    ]
    assert entry_snapshot["external_callees"] == []


def test_global_modeler_reconciles_mutual_recursion_without_extra_llm_calls(tmp_path):
    calls = []
    config = _config(tmp_path)
    index = FakeCodeIndex()
    index.impls = {
        "left": index._impl("left", ["right"]),
        "right": index._impl("right", ["left"]),
    }
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    modeler = GlobalModeler(
        config,
        index,
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
        max_workers=2,
    )

    stats = modeler.run([FunctionEntry("left"), FunctionEntry("right")])

    assert sorted(calls) == ["left", "right"]
    assert len(calls) == 2
    assert stats.stage_complete is True
    assert stats.reconciliation_failures == 0
    assert store.load_snapshot("left@src/left.c:1-8")["project_callees"][0][
        "callee_summary"
    ] == "modeled right"
    assert store.load_snapshot("right@src/right.c:1-8")["project_callees"][0][
        "callee_summary"
    ] == "modeled left"


def test_global_modeler_reconciles_self_recursion_without_second_llm_call(tmp_path):
    calls = []
    config = _config(tmp_path)
    index = FakeCodeIndex()
    index.impls = {"self_call": index._impl("self_call", ["self_call"])}
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    modeler = GlobalModeler(
        config,
        index,
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
    )

    stats = modeler.run([FunctionEntry("self_call")])

    assert calls == ["self_call"]
    assert stats.stage_complete is True
    assert store.load_snapshot("self_call@src/self_call.c:1-8")["project_callees"][0][
        "callee_summary"
    ] == "modeled self_call"


def test_global_modeler_failure_skips_reconciliation_within_stage_tolerance(tmp_path):
    config = _config(tmp_path)
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", [])}
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))

    class FailingAgent:
        def run(self, context):
            return AgentResponse(success=False, data={}, error="api unavailable")

    stats = GlobalModeler(
        config,
        index,
        store,
        user_config,
        semantic_agent_factory=FailingAgent,
    ).run([FunctionEntry("entry")])

    assert stats.failed_functions == 1
    assert stats.reconciled_functions == 0
    assert stats.reconciliation_unchanged_functions == 0
    assert stats.stage_complete is True


def test_global_modeler_unresolved_entry_fails_stage_gate(tmp_path):
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    stats = GlobalModeler(
        config,
        FakeCodeIndex(),
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent([]),
    ).run([FunctionEntry("missing_entry")])

    assert stats.unresolved_entry_functions == 1
    assert stats.stage_complete is False
    assert stats.reconciled_functions == 0


def test_global_modeler_retries_terminal_guard_in_fresh_agent(tmp_path):
    config = _config(tmp_path)
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", [])}
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    created_agents = []
    successful_calls = []

    class GuardedAgent:
        def run(self, context):
            return AgentResponse(
                success=False,
                data={},
                error="terminal guard",
                metadata={
                    "reason": "terminal_tool_loop_guard",
                    "terminal_loop_guard_triggered": True,
                    "terminal_loop_guard_reason": "identical_invalid_terminal_call_limit",
                    "context_tokens": 3,
                },
            )

    def factory():
        agent = GuardedAgent() if not created_agents else RecordingAgent(successful_calls)
        created_agents.append(agent)
        return agent

    stats = GlobalModeler(
        config,
        index,
        store,
        user_config,
        semantic_agent_factory=factory,
    ).run([FunctionEntry("entry")])

    assert len(created_agents) == 2
    assert successful_calls == ["entry"]
    assert stats.llm_snapshot_count == 1
    assert stats.failed_functions == 0
    assert stats.total_context_tokens == 10
    assert store.load_snapshot("entry@src/entry.c:1-8")["summary"] == "modeled entry"


def test_global_model_stats_allows_ten_but_rejects_more_than_ten_failed_functions(tmp_path):
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    modeler = GlobalModeler(
        config,
        FakeCodeIndex(),
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent([]),
    )

    stats = modeler.run([FunctionEntry("entry")])
    stats.failed_functions = 10
    assert stats.stage_complete is True
    stats.failed_functions = 11

    assert stats.stage_complete is False


def test_global_modeler_resolves_header_api_to_source_implementation(tmp_path):
    calls = []
    config = _config(tmp_path)
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", [])}
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    stats = GlobalModeler(
        config,
        index,
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
    ).run([FunctionEntry("entry", file_path="include/public_api.h")])

    assert calls == ["entry"]
    assert stats.unresolved_entry_functions == 0
    assert stats.stage_complete is True


def test_global_modeler_models_same_name_entries_in_different_files(tmp_path):
    calls = []
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    modeler = GlobalModeler(
        config,
        SameNameCodeIndex(),
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
        max_workers=2,
    )

    stats = modeler.run(
        [
            FunctionEntry("handle", file_path="src/a/handler.c"),
            FunctionEntry("handle", file_path="src/b/handler.c"),
        ]
    )

    assert stats.llm_snapshot_count == 2
    assert calls == ["handle", "handle"]
    assert store.load_snapshot("handle@src/a/handler.c:1-8")["summary"] == "modeled handle"
    assert store.load_snapshot("handle@src/b/handler.c:1-8")["summary"] == "modeled handle"


def test_global_modeler_reuses_existing_snapshots(tmp_path):
    calls = []
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    impl = FakeCodeIndex().impls["leaf"]
    store.save_snapshot(
        impl["index_name"],
        {
            "type": "function_snapshot",
            "func_name": "leaf",
            "index_name": impl["index_name"],
            "file_path": impl["file"],
            "start_line": impl["start_line"],
            "end_line": impl["end_line"],
            "signature": impl["signature"],
            "snapshot_kind": "LLM-modeled",
            "is_static": False,
            "is_macro": False,
            "referenced_globals": [],
            "referenced_macros": [],
            "referenced_types": [],
            "summary": "cached leaf",
            "inputs": [],
            "outputs": [],
            "resources": {},
            "error_handling": {},
            "concurrency": {},
            "key_semantics": ["cached"],
            "suspicious_points": [],
            "project_callees": [],
            "external_callees": [],
        },
        impl["code"],
    )
    modeler = GlobalModeler(
        config,
        FakeCodeIndex(),
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
        max_workers=2,
    )

    stats = modeler.run([FunctionEntry("entry")])

    assert stats.cache_hit_functions == 1
    assert "leaf" not in calls


def test_global_modeler_treats_negative_callee_cap_as_unlimited(tmp_path):
    calls = []
    config = _config(tmp_path)
    config.analysis.max_premodel_callees = -1
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    modeler = GlobalModeler(
        config,
        FakeCodeIndex(),
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
        max_workers=2,
    )

    stats = modeler.run([FunctionEntry("entry")])

    assert stats.reachable_functions == 4
    assert stats.breadth_capped_edges == 0


def test_global_modeler_uses_deterministic_snapshot_for_trivial_function(tmp_path):
    calls = []
    config = _config(tmp_path)
    config.analysis.trivial_function_max_lines = 5
    index = FakeCodeIndex()
    index.impls = {
            "entry": {
                "func_name": "entry",
                "file": "src/entry.c",
                "index_name": "entry@src/entry.c:1-4",
                "start_line": 1,
                "end_line": 4,
                "signature": "int entry(void)",
                "is_static": False,
                "is_macro": False,
            "code": "1 | int entry(void) {\n2 |     return tiny();\n3 | }\n",
            "callees": ["tiny"],
        },
            "tiny": {
                "func_name": "tiny",
                "file": "src/tiny.c",
                "index_name": "tiny@src/tiny.c:1-3",
                "start_line": 1,
                "end_line": 3,
                "signature": "int tiny(void)",
                "is_static": False,
                "is_macro": False,
            "code": "1 | int tiny(void) {\n2 |     return 0;\n3 | }\n",
            "project_callees": [],
            "external_callees": [],
        }
    }
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    modeler = GlobalModeler(
        config,
        index,
        store,
        user_config,
        semantic_agent_factory=lambda: RecordingAgent(calls),
    )

    stats = modeler.run([FunctionEntry("entry")])

    assert stats.deterministic_snapshot_count == 1
    assert calls == ["entry"]
    tiny_snapshot = store.load_snapshot("tiny@src/tiny.c:1-3")
    assert tiny_snapshot["snapshot_kind"] == "syntactic"
    assert tiny_snapshot["referenced_globals"] == []
    assert tiny_snapshot["referenced_macros"] == []


def test_entry_model_reuses_global_snapshot_without_llm(tmp_path):
    config = _config(tmp_path)
    config.analysis.enable_global_model = True
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    code = "1 | int entry(void) {\n2 |     return 0;\n3 | }\n"
    store.save_snapshot(
        "entry@src/entry.c:1-3",
        {
            "type": "function_snapshot",
            "func_name": "entry",
            "index_name": "entry@src/entry.c:1-3",
            "file_path": "src/entry.c",
            "start_line": 1,
            "end_line": 3,
            "signature": "int entry(void)",
            "snapshot_kind": "LLM-modeled",
            "is_static": False,
            "is_macro": False,
            "referenced_globals": [],
            "referenced_macros": [],
            "referenced_types": [],
            "summary": "global entry",
            "inputs": [],
            "outputs": [],
            "resources": {},
            "error_handling": {},
            "concurrency": {},
            "key_semantics": ["global"],
            "suspicious_points": [],
                "project_callees": [],
                "external_callees": [],
        },
        code,
    )
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = config
    analyzer.snapshot_store = store

    state = {
        "entry_func": "entry",
        "entry_index_name": "entry@src/entry.c:1-3",
        "impl_result": {"file": "src/entry.c", "code": code},
            "semantic_model_input": {
                "project_callees": [],
                "external_callees": [],
            "referenced_globals": [],
            "referenced_macros": [],
            "referenced_types": [],
        },
        "notes": [],
    }

    analyzer._step_model_entry(state)

    assert state["notes"] == ["Reused globally modeled snapshot for entry."]


def test_entry_model_retries_terminal_guard_in_fresh_agent(monkeypatch, tmp_path):
    config = _config(tmp_path)
    config.analysis.enable_global_model = False
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", [])}
    semantic_context = build_semantic_model_input(index, "entry", include_context=False)
    created_agents = []
    successful_calls = []

    class FakeSemanticModeler:
        def __init__(self, *args, **kwargs):
            created_agents.append(self)

        def run(self, context):
            if len(created_agents) == 1:
                return AgentResponse(
                    success=False,
                    data={},
                    error="terminal guard",
                    metadata={
                        "reason": "terminal_tool_loop_guard",
                        "terminal_loop_guard_triggered": True,
                        "terminal_loop_guard_reason": "identical_invalid_terminal_call_limit",
                        "context_tokens": 3,
                    },
                )
            return RecordingAgent(successful_calls).run(context)

    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = config
    analyzer.snapshot_store = store
    analyzer.llm_clients = {"default": object()}
    analyzer._get_tools = lambda *args, **kwargs: []
    analyzer._tool_policy_for_agent = lambda *args, **kwargs: None
    analyzer._attach_agent_contract = lambda *args, **kwargs: None
    monkeypatch.setattr(analyzer_module, "SemanticModeler", FakeSemanticModeler)
    state = {
        "entry_func": "entry",
        "entry_index_name": semantic_context["index_name"],
        "impl_result": index.impls["entry"],
        "agent_context": {},
        "semantic_model_input": semantic_context,
        "notes": [],
        "total_context_tokens": 0,
        "total_cumulative_prompt_tokens": 0,
        "total_cumulative_completion_tokens": 0,
        "total_cumulative_total_tokens": 0,
    }

    analyzer._step_model_entry(state)

    assert len(created_agents) == 2
    assert successful_calls == ["entry"]
    assert state["total_context_tokens"] == 10
    assert state["total_cumulative_total_tokens"] == 10
    assert store.load_snapshot(semantic_context["index_name"])["summary"] == "modeled entry"


def test_premodel_retries_terminal_guard_in_fresh_agent(monkeypatch, tmp_path):
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    index = FakeCodeIndex()
    attempts = {}
    created_agents = []
    successful_calls = []

    class FakeSemanticModeler:
        def __init__(self, *args, **kwargs):
            created_agents.append(self)

        def run(self, context):
            index_name = context["index_name"]
            attempts[index_name] = attempts.get(index_name, 0) + 1
            if attempts[index_name] == 1:
                return AgentResponse(
                    success=False,
                    data={},
                    error="terminal guard",
                    metadata={
                        "reason": "terminal_tool_loop_guard",
                        "terminal_loop_guard_triggered": True,
                        "terminal_loop_guard_reason": "identical_invalid_terminal_call_limit",
                        "context_tokens": 3,
                    },
                )
            return RecordingAgent(successful_calls).run(context)

    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = config
    analyzer.snapshot_store = store
    analyzer.code_index = index
    analyzer._get_tools = lambda *args, **kwargs: []
    analyzer._tool_policy_for_agent = lambda *args, **kwargs: None
    analyzer._attach_agent_contract = lambda *args, **kwargs: None
    monkeypatch.setattr(analyzer_module, "SemanticModeler", FakeSemanticModeler)

    modeled, skipped, total_tokens = analyzer._premodel_callees(
        "entry", object(), max_depth=3, max_callees=10
    )

    assert modeled == 3
    assert skipped == 0
    assert total_tokens == 30
    assert len(created_agents) == 6
    assert sorted(successful_calls) == ["leaf", "mid", "sibling"]
    assert all(count == 2 for count in attempts.values())


def test_on_demand_snapshot_build_uses_file_qualified_lock(monkeypatch, tmp_path):
    calls = []
    attempts = {}
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    index = SameNameCodeIndex()

    class FakeSemanticModeler:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, context):
            calls.append(context["index_name"])
            attempts[context["index_name"]] = attempts.get(context["index_name"], 0) + 1
            if attempts[context["index_name"]] == 1:
                return AgentResponse(
                    success=False,
                    data={},
                    error="terminal guard",
                    metadata={
                        "reason": "terminal_tool_loop_guard",
                        "terminal_loop_guard_triggered": True,
                        "terminal_loop_guard_reason": "identical_invalid_terminal_call_limit",
                        "context_tokens": 1,
                    },
                )
            return AgentResponse(
                success=True,
                data={
                    "type": "function_snapshot",
                    "func_name": context["func_name"],
                    "index_name": context["index_name"],
                    "file_path": context["file_path"],
                    "start_line": context["start_line"],
                    "end_line": context["end_line"],
                    "signature": context["signature"],
                    "snapshot_kind": "LLM-modeled",
                        "is_static": context["is_static"],
                        "is_macro": context["is_macro"],
                            "referenced_globals": context["referenced_globals"],
                            "referenced_macros": context["referenced_macros"],
                            "referenced_types": context["referenced_types"],
                        "summary": context["index_name"],
                    "inputs": [],
                    "outputs": [],
                    "resources": {},
                    "error_handling": {},
                    "concurrency": {},
                    "key_semantics": [context["index_name"]],
                    "suspicious_points": [],
                    "project_callees": [],
                    "external_callees": [],
                },
                metadata={"context_tokens": 1},
            )

    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = config
    analyzer.snapshot_store = store
    analyzer.code_index = index
    analyzer.llm_clients = {"default": object()}
    analyzer._get_tools = lambda *args, **kwargs: []
    analyzer._tool_policy_for_agent = lambda *args, **kwargs: None
    analyzer._attach_agent_contract = lambda *args, **kwargs: None
    monkeypatch.setattr(analyzer_module, "SemanticModeler", FakeSemanticModeler)

    first = analyzer._get_or_build_snapshot("handle", file_path="src/a/handler.c")
    second = analyzer._get_or_build_snapshot("handle", file_path="src/b/handler.c")

    assert first["success"] is True
    assert second["success"] is True
    assert calls == [
        "handle@src/a/handler.c:1-8",
        "handle@src/a/handler.c:1-8",
        "handle@src/b/handler.c:1-8",
        "handle@src/b/handler.c:1-8",
    ]
    assert store.load_snapshot("handle@src/a/handler.c:1-8")["summary"] == (
        "handle@src/a/handler.c:1-8"
    )
    assert store.load_snapshot("handle@src/b/handler.c:1-8")["summary"] == (
        "handle@src/b/handler.c:1-8"
    )
