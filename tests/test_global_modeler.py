from pathlib import Path

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
            "start_line": 1,
            "end_line": 8,
            "signature": f"int {name}(void)",
            "code": f"1 | int {name}(void) {{\n2 |     return external_{name}();\n3 | }}\n",
            "callees": list(callees),
        }

    def get_function_impl(self, func_name, **kwargs):
        return self.impls.get(func_name)

    def get_callees(self, func_name, limit=30):
        impl = self.impls.get(func_name) or {}
        return [{"name": callee} for callee in impl.get("callees", [])][:limit]


class SameNameCodeIndex:
    def __init__(self):
        self.impls = {
            "src/a/handler.c": {
                "func_name": "handle",
                "file": "src/a/handler.c",
                "start_line": 1,
                "end_line": 8,
                "signature": "int handle(void)",
                "code": "1 | int handle(void) {\n2 |     return external_a();\n3 | }\n",
                "callees": [],
            },
            "src/b/handler.c": {
                "func_name": "handle",
                "file": "src/b/handler.c",
                "start_line": 1,
                "end_line": 8,
                "signature": "int handle(void)",
                "code": "1 | int handle(void) {\n2 |     return external_b();\n3 | }\n",
                "callees": [],
            },
        }

    def get_function_impl(self, func_name, **kwargs):
        assert func_name == "handle"
        return self.impls.get(kwargs.get("file_path"))

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
                "location": context["location"],
                "summary": f"modeled {name}",
                "inputs": [],
                "outputs": [],
                "resources": {},
                "error_handling": {},
                "concurrency": {},
                "semantic_fingerprint": {"key_semantics": [name]},
                "suspicious_points": [],
                "callees": [],
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
    assert store.load_snapshot("entry", "src/entry.c")["summary"] == "modeled entry"


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
    assert store.load_snapshot("handle", "src/a/handler.c")["summary"] == "modeled handle"
    assert store.load_snapshot("handle", "src/b/handler.c")["summary"] == "modeled handle"


def test_global_modeler_reuses_existing_snapshots(tmp_path):
    calls = []
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    user_config = UserConfigStore(Path(config.analysis.user_config_db))
    impl = FakeCodeIndex().impls["leaf"]
    store.save_snapshot(
        "leaf",
        {
            "type": "function_snapshot",
            "func_name": "leaf",
            "location": "src/leaf.c:1",
            "summary": "cached leaf",
            "inputs": [],
            "outputs": [],
            "resources": {},
            "error_handling": {},
            "concurrency": {},
            "semantic_fingerprint": {"key_semantics": ["cached"]},
            "suspicious_points": [],
            "callees": [],
        },
        impl["code"],
        "src/leaf.c:1",
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
            "start_line": 1,
            "end_line": 4,
            "signature": "int entry(void)",
            "code": "1 | int entry(void) {\n2 |     return tiny();\n3 | }\n",
            "callees": ["tiny"],
        },
        "tiny": {
            "func_name": "tiny",
            "file": "src/tiny.c",
            "start_line": 1,
            "end_line": 3,
            "signature": "int tiny(void)",
            "code": "1 | int tiny(void) {\n2 |     return 0;\n3 | }\n",
            "callees": [],
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
    assert store.load_snapshot("tiny", "src/tiny.c")["snapshot_kind"] == "syntactic"


def test_entry_model_reuses_global_snapshot_without_llm(tmp_path):
    config = _config(tmp_path)
    config.analysis.enable_global_model = True
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    code = "1 | int entry(void) {\n2 |     return 0;\n3 | }\n"
    store.save_snapshot(
        "entry",
        {
            "type": "function_snapshot",
            "func_name": "entry",
            "location": "src/entry.c:1",
            "summary": "global entry",
            "inputs": [],
            "outputs": [],
            "resources": {},
            "error_handling": {},
            "concurrency": {},
            "semantic_fingerprint": {"key_semantics": ["global"]},
            "suspicious_points": [],
            "callees": [],
        },
        code,
        "src/entry.c:1",
    )
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = config
    analyzer.snapshot_store = store

    state = {
        "entry_func": "entry",
        "impl_result": {"file": "src/entry.c", "code": code},
        "notes": [],
    }

    analyzer._step_model_entry(state)

    assert state["notes"] == ["Reused globally modeled snapshot for entry."]


def test_on_demand_snapshot_build_uses_file_qualified_lock(monkeypatch, tmp_path):
    calls = []
    config = _config(tmp_path)
    store = SnapshotStore(Path(config.analysis.snapshot_dir))
    index = SameNameCodeIndex()

    class FakeSemanticModeler:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, context):
            calls.append(context["location"])
            return AgentResponse(
                success=True,
                data={
                    "type": "function_snapshot",
                    "func_name": context["func_name"],
                    "location": context["location"],
                    "summary": context["location"],
                    "inputs": [],
                    "outputs": [],
                    "resources": {},
                    "error_handling": {},
                    "concurrency": {},
                    "semantic_fingerprint": {"key_semantics": [context["location"]]},
                    "suspicious_points": [],
                    "callees": [],
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
    assert calls == ["src/a/handler.c:1", "src/b/handler.c:1"]
    assert store.load_snapshot("handle", "src/a/handler.c")["summary"] == "src/a/handler.c:1"
    assert store.load_snapshot("handle", "src/b/handler.c")["summary"] == "src/b/handler.c:1"
