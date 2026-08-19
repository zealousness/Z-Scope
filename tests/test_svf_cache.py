import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from zscope.config.function_entry import FunctionEntry
from zscope.retrieval import svf_analyzer as svf_module
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.retrieval.svf_analyzer import SvfAnalyzer
from zscope.retrieval.svf_parser import CallGraphParser, SvfOutputMapper
from zscope.retrieval.svf_runner import SvfResult


def _write_compile_commands(tmp_path: Path) -> tuple[Path, Path]:
    source_root = tmp_path / "project"
    source_root.mkdir()
    source_file = source_root / "main.c"
    source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text(
        json.dumps(
            [
                {
                    "directory": str(source_root),
                    "command": "cc -c main.c",
                    "file": "main.c",
                }
            ]
        ),
        encoding="utf-8",
    )
    return source_root, compile_commands


def _write_callgraph(dot_path: Path, edges: list[tuple[str, str]]) -> Path:
    names = sorted({name for edge in edges for name in edge})
    node_ids = {name: f"0x{index + 1:x}" for index, name in enumerate(names)}
    lines = ["digraph {"]
    lines.extend(f'  Node{node_ids[name]} [label="{{ {name} }}"];' for name in names)
    lines.extend(
        f"  Node{node_ids[caller]} -> Node{node_ids[callee]} [color=red];"
        for caller, callee in edges
    )
    lines.append("}")
    dot_path.parent.mkdir(parents=True, exist_ok=True)
    dot_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dot_path


def test_svf_mapper_imports_only_explicit_red_indirect_edges(tmp_path: Path) -> None:
    dot = tmp_path / "callgraph_final.dot"
    dot.write_text(
        "digraph {\n"
        '  Node0x1 [label="{ caller }"];\n'
        '  Node0x2 [label="{ direct_target }"];\n'
        '  Node0x3 [label="{ indirect_target }"];\n'
        "  Node0x1:s0 -> Node0x2 [color=black];\n"
        "  Node0x1:s1 -> Node0x3 [color=red];\n"
        "}\n",
        encoding="utf-8",
    )
    parser_edges = CallGraphParser().parse_edges(dot)
    assert parser_edges == [
        {
            "caller": "caller",
            "callee": "direct_target",
            "edge_color": "black",
            "caller_port": "s0",
        },
        {
            "caller": "caller",
            "callee": "indirect_target",
            "edge_color": "red",
            "caller_port": "s1",
        },
    ]

    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("caller", "src/caller.c", 1, 10)
        SvfOutputMapper(db).import_callgraph(dot)
        db.commit()
        assert db.get_indirect_callees("caller") == [
            {
                "name": "indirect_target",
                "source": "svf-ander",
                "confidence": 1.0,
                "svf_group": "default",
                "svf_groups": ["default"],
                "call_file": "src/caller.c",
                "call_line": 0,
            }
        ]
        assert db.get_indirect_call_records("caller") == [
            {
                "name": "indirect_target",
                "call_file": "src/caller.c",
                "call_line": 0,
                "callsite_id": "svf:s1",
                "pointer_symbol": "",
                "pointer_kind": "unknown",
                "pointer_type": "",
                "pointer_signature": "",
                "callsite_expression": "",
                "guard": "",
                "source": "svf-ander",
                "confidence": 1.0,
                "svf_group": "default",
                "call_type": "indirect",
            }
        ]
    finally:
        db.close()


def test_svf_mapper_resolves_unique_field_pointer_callsite_from_source(tmp_path: Path) -> None:
    source = tmp_path / "src" / "main.c"
    source.parent.mkdir()
    source.write_text(
        "typedef void (*Callback)(void* value);\n"
        "typedef struct { Callback callback; } Ops;\n"
        "void Target(void* value) {}\n"
        "void caller(Ops ops, void* value) {\n"
        "    ops.callback(value);\n"
        "}\n",
        encoding="utf-8",
    )
    dot = tmp_path / "callgraph_final.dot"
    dot.write_text(
        "digraph {\n"
        '  Node0x1 [label="{ caller }"];\n'
        '  Node0x2 [label="{ Target }"];\n'
        "  Node0x1:s0 -> Node0x2 [color=red];\n"
        "}\n",
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function(
            "caller", "src/main.c", 4, 6, signature="void caller(Ops ops, void* value)"
        )
        db.insert_function("Target", "src/main.c", 3, 3, signature="void Target(void* value)")
        db.insert_type(
            "Ops",
            "struct",
            "src/main.c",
            2,
            2,
            "typedef struct { Callback callback; } Ops;",
        )
        db.insert_type(
            "Callback",
            "typedef",
            "src/main.c",
            1,
            1,
            "typedef void (*Callback)(void* value);",
        )
        db.insert_call_edge(
            "caller",
            "src/main.c",
            "callback",
            "src/main.c",
            5,
            "indirect",
            "function_pointer_field",
        )
        db.commit()

        SvfOutputMapper(db, project_root=tmp_path).import_callgraph(dot)
        db.commit()

        assert db.get_indirect_call_records("caller") == [
            {
                "name": "Target",
                "call_file": "src/main.c",
                "call_line": 5,
                "callsite_id": "source:5:Ops.callback",
                "pointer_symbol": "Ops.callback",
                "pointer_kind": "field",
                "pointer_type": "Callback",
                "pointer_signature": "void (*)(void* value)",
                "callsite_expression": "ops.callback",
                "guard": "",
                "source": "svf-ander",
                "confidence": 1.0,
                "svf_group": "default",
                "call_type": "indirect",
            }
        ]
    finally:
        db.close()


def test_svf_mapper_resolves_parameter_function_pointer_callsite_from_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "main.c"
    source.parent.mkdir()
    source.write_text(
        "typedef void (*Callback)(void* value);\n"
        "void Target(void* value) {}\n"
        "void caller(Callback callback, void* value) {\n"
        "    (*callback)(value);\n"
        "}\n",
        encoding="utf-8",
    )
    dot = tmp_path / "callgraph_final.dot"
    dot.write_text(
        "digraph {\n"
        '  Node0x1 [label="{ caller }"];\n'
        '  Node0x2 [label="{ Target }"];\n'
        "  Node0x1:s0 -> Node0x2 [color=red];\n"
        "}\n",
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function(
            "caller",
            "src/main.c",
            3,
            5,
            signature="void caller(Callback callback, void* value)",
        )
        db.insert_function("Target", "src/main.c", 2, 2, signature="void Target(void* value)")
        db.insert_type(
            "Callback",
            "typedef",
            "src/main.c",
            1,
            1,
            "typedef void (*Callback)(void* value);",
        )
        db.insert_call_edge(
            "caller", "src/main.c", "callback", "", 4, "indirect", "function_pointer_variable"
        )
        db.commit()

        SvfOutputMapper(db, project_root=tmp_path).import_callgraph(dot)
        db.commit()

        record = db.get_indirect_call_records("caller")[0]
        assert record["call_line"] == 4
        assert record["pointer_symbol"] == "caller.callback"
        assert record["pointer_kind"] == "parameter"
        assert record["pointer_type"] == "Callback"
        assert record["callsite_expression"] == "(*callback)"
    finally:
        db.close()


def test_svf_cache_fingerprint_includes_timeout_config(tmp_path: Path) -> None:
    _, compile_commands = _write_compile_commands(tmp_path)
    groups = {"default": []}

    legacy_source_hash = SvfAnalyzer._compute_aggregate_hash(compile_commands, groups)
    timeout_30_hash = SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        {"timeout": 30},
    )
    timeout_60_hash = SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        {"timeout": 60},
    )

    assert legacy_source_hash != timeout_30_hash
    assert timeout_30_hash != timeout_60_hash


def test_svf_cache_fingerprint_includes_entry_scope(tmp_path: Path) -> None:
    _, compile_commands = _write_compile_commands(tmp_path)
    groups = {"default": []}

    entry_main_hash = SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        {"scope": "auto"},
        ["main"],
    )
    entry_api_hash = SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        {"scope": "auto"},
        ["public_api"],
    )

    assert entry_main_hash != entry_api_hash


def test_svf_cache_fingerprint_treats_entry_order_as_stable(tmp_path: Path) -> None:
    _, compile_commands = _write_compile_commands(tmp_path)
    groups = {"default": []}

    first = SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        {"scope": "auto"},
        ["api_b", "api_a"],
    )
    second = SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        {"scope": "auto"},
        ["api_a", "api_b"],
    )
    legacy = SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        {"scope": "auto"},
        ["api_b", "api_a"],
        sort_entry_functions=False,
    )

    assert first == second
    assert legacy != first


def test_svf_legacy_hash_does_not_skip_configured_run(tmp_path: Path, monkeypatch) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    groups = {"default": []}
    db.set_svf_hash(SvfAnalyzer._compute_aggregate_hash(compile_commands, groups))

    calls = []

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            pass

        def build(self, groups):
            return {"default": tmp_path / "all.bc"}

    class FakeSvfRunner:
        def __init__(self, *args, timeout=1800, **kwargs):
            self.timeout = timeout

        def run_ander(self, bc_path, output_dir):
            calls.append(self.timeout)
            output_dir.mkdir(parents=True, exist_ok=True)
            dot = output_dir / "callgraph_final.dot"
            dot.write_text("digraph { }\n", encoding="utf-8")
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, bc_path, output_dir):
            return SvfResult(tool="saber", success=True)

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42)

    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert calls == [42]
    assert db.get_svf_hash() == SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        analyzer._cache_config(),
    )
    db.close()


def test_svf_artifact_hash_without_materialization_marker_reruns_tool(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    groups = {"default": []}
    merged_bc = tmp_path / "all.bc"
    merged_bc.write_text("merged bitcode\n", encoding="utf-8")
    calls = []

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            pass

        def build(self, groups):
            calls.append("build")
            return {"default": merged_bc}

    class FakeSvfRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, bc_path, output_dir):
            calls.append("runner")
            output_dir.mkdir(parents=True, exist_ok=True)
            dot = output_dir / "callgraph_final.dot"
            dot.write_text("digraph { }\n", encoding="utf-8")
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, bc_path, output_dir):
            return SvfResult(tool="saber", success=True)

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42)
    db.set_svf_hash("stale-source-hash")
    db.set_metadata(
        "svf_artifact_hash",
        SvfAnalyzer._compute_artifact_hash(
            {"default": merged_bc},
            groups,
            analyzer._cache_config(),
            [],
        ),
    )

    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert calls == ["build", "runner"]
    assert db.get_svf_hash() == SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        analyzer._cache_config(),
    )
    db.close()


def test_reused_merged_group_without_materialization_marker_reruns_tool(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    merged_bc = tmp_path / "all.bc"
    merged_bc.write_text("merged bitcode\n", encoding="utf-8")
    calls = []

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            self.reused_linked_groups = {"default"}

        def build(self, groups):
            calls.append("build")
            return {"default": merged_bc}

    class FakeSvfRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, bc_path, output_dir):
            calls.append("runner")
            output_dir.mkdir(parents=True, exist_ok=True)
            dot = output_dir / "callgraph_final.dot"
            dot.write_text("digraph { }\n", encoding="utf-8")
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, bc_path, output_dir):
            return SvfResult(tool="saber", success=True)

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42)
    db.set_svf_hash("older-successful-svf-hash")

    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert calls == ["build", "runner"]
    assert db.get_metadata("svf_artifact_hash")
    db.close()


def test_partial_bitcode_build_retries_failed_tus_next_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    merged_bc = tmp_path / "partial.bc"
    merged_bc.write_text("partial merged bitcode\n", encoding="utf-8")
    calls = []

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            self.failed_tus = [{"file": "failed.c", "reason": "compile_failed"}]
            self.reused_linked_groups = set()

        def build(self, groups):
            calls.append("build")
            return {"default": merged_bc}

    class FakeSvfRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, bc_path, output_dir):
            calls.append("runner")
            output_dir.mkdir(parents=True, exist_ok=True)
            dot = output_dir / "callgraph_final.dot"
            dot.write_text("digraph { }\n", encoding="utf-8")
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, bc_path, output_dir):
            return SvfResult(tool="saber", success=True)

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42)

    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert db.get_svf_hash() == ""
    assert db.get_metadata("svf_artifact_hash")

    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert calls == ["build", "runner", "build"]
    assert db.get_svf_hash() == ""
    db.close()


def test_svf_timeout_result_is_not_cached(tmp_path: Path, monkeypatch) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    calls = []

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            pass

        def build(self, groups):
            return {"default": tmp_path / "all.bc"}

    class FakeSvfRunner:
        def __init__(self, *args, timeout=1800, **kwargs):
            self.timeout = timeout

        def run_ander(self, bc_path, output_dir):
            calls.append(self.timeout)
            return SvfResult(tool="wpa-ander", timed_out=True)

        def run_saber(self, bc_path, output_dir):
            return SvfResult(tool="saber", success=True)

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=7)

    assert analyzer.run(source_root, tmp_path, compile_commands) is False
    assert analyzer.run(source_root, tmp_path, compile_commands) is False
    assert calls == [7, 7]
    assert db.get_svf_hash() == ""
    db.close()


def test_split_svf_runs_wpa_groups_in_parallel_and_saber_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    paths = {
        "entry_cluster_1": tmp_path / "cluster1.bc",
        "entry_cluster_2": tmp_path / "cluster2.bc",
        "saber:default": tmp_path / "saber_default.bc",
    }
    for path in paths.values():
        path.write_text("bitcode\n", encoding="utf-8")
    calls = {
        "ander": [],
        "saber": [],
        "active": 0,
        "max_active": 0,
    }
    lock = threading.Lock()

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            self.failed_tus = []
            self.reused_linked_groups = set()

        def build(self, **kwargs):
            assert kwargs["auto_entry_clusters"] is True
            assert kwargs["saber_groups"] is True
            return dict(paths)

    class FakeSvfRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, bc_path, output_dir):
            with lock:
                calls["active"] += 1
                calls["max_active"] = max(calls["max_active"], calls["active"])
            try:
                time.sleep(0.05)
                output_dir.mkdir(parents=True, exist_ok=True)
                dot = output_dir / "callgraph_final.dot"
                dot.write_text("digraph { }\n", encoding="utf-8")
                calls["ander"].append(Path(bc_path).name)
                return SvfResult(tool="wpa-ander", success=True, output_file=dot)
            finally:
                with lock:
                    calls["active"] -= 1

        def run_saber(self, bc_path, output_dir):
            calls["saber"].append(Path(bc_path).name)
            return SvfResult(tool="saber", success=True, bugs=[])

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42, parallel_workers=2)

    assert (
        analyzer.run(
            source_root,
            tmp_path,
            compile_commands,
            entry_functions=["api_a", "api_b"],
        )
        is True
    )
    assert sorted(calls["ander"]) == ["cluster1.bc", "cluster2.bc"]
    assert calls["saber"] == ["saber_default.bc"]
    assert calls["max_active"] == 2
    db.close()


def test_explicit_svf_groups_still_enable_entry_clustering(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    groups_config = tmp_path / "svf_groups.json"
    groups_config.write_text(json.dumps({"alpha": []}), encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    paths = {
        "alpha__entry_cluster_1": tmp_path / "alpha_cluster.bc",
        "saber:alpha": tmp_path / "saber_alpha.bc",
    }
    for path in paths.values():
        path.write_text("bitcode\n", encoding="utf-8")
    seen: dict[str, object] = {}

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            self.failed_tus = []
            self.reused_linked_groups = set()

        def build(self, **kwargs):
            seen["groups"] = kwargs["groups"]
            seen["auto_entry_clusters"] = kwargs["auto_entry_clusters"]
            seen["saber_groups"] = kwargs["saber_groups"]
            return dict(paths)

    class FakeSvfRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, bc_path, output_dir):
            output_dir.mkdir(parents=True, exist_ok=True)
            dot = output_dir / "callgraph_final.dot"
            dot.write_text("digraph { }\n", encoding="utf-8")
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, bc_path, output_dir):
            return SvfResult(tool="saber", success=True, bugs=[])

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42, parallel_workers=2)

    assert (
        analyzer.run(
            source_root,
            tmp_path,
            compile_commands,
            entry_functions=["api_alpha"],
            svf_groups_config=str(groups_config),
        )
        is True
    )
    assert seen == {
        "groups": {"alpha": []},
        "auto_entry_clusters": True,
        "saber_groups": True,
    }
    db.close()


def test_wpa_group_timeout_does_not_block_successful_groups_or_full_saber(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    paths = {
        "entry_cluster_ok": tmp_path / "ok.bc",
        "entry_cluster_timeout": tmp_path / "timeout.bc",
        "saber:default": tmp_path / "saber_default.bc",
    }
    for path in paths.values():
        path.write_text("bitcode\n", encoding="utf-8")
    calls = {"saber": 0}

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            self.failed_tus = []
            self.reused_linked_groups = set()

        def build(self, **kwargs):
            return dict(paths)

    class FakeSvfRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, bc_path, output_dir):
            if Path(bc_path).name == "timeout.bc":
                return SvfResult(tool="wpa-ander", timed_out=True)
            output_dir.mkdir(parents=True, exist_ok=True)
            dot = output_dir / "callgraph_final.dot"
            dot.write_text("digraph { }\n", encoding="utf-8")
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, bc_path, output_dir):
            calls["saber"] += 1
            return SvfResult(
                tool="saber",
                success=True,
                bugs=[{"type": "Double Free", "file": "src/a.c", "line": 7}],
            )

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42, parallel_workers=2)

    assert (
        analyzer.run(
            source_root,
            tmp_path,
            compile_commands,
            entry_functions=["api_a", "api_b"],
        )
        is False
    )
    assert calls["saber"] == 1
    assert db.get_taint_bugs("Double Free")[0]["svf_group"] == "saber:default"
    assert db.get_svf_hash() == ""
    db.close()


def test_svf_resume_reruns_only_failed_groups(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    paths = {
        "entry_cluster_ok": tmp_path / "ok.bc",
        "entry_cluster_retry": tmp_path / "retry.bc",
        "saber:default": tmp_path / "saber_default.bc",
    }
    for path in paths.values():
        path.write_text(f"bitcode {path.name}\n", encoding="utf-8")
    calls = {"ander": [], "saber": []}
    run_number = {"value": 0}

    class FakeBitcodeBuilder:
        def __init__(self, *args, **kwargs):
            self.failed_tus = []
            self.reused_linked_groups = set()

        def build(self, **kwargs):
            return dict(paths)

    class FakeSvfRunner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, bc_path, output_dir):
            name = Path(bc_path).name
            calls["ander"].append(name)
            if name == "retry.bc" and run_number["value"] == 1:
                return SvfResult(tool="wpa-ander", timed_out=True)
            output_dir.mkdir(parents=True, exist_ok=True)
            dot = output_dir / "callgraph_final.dot"
            dot.write_text("digraph { }\n", encoding="utf-8")
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, bc_path, output_dir):
            calls["saber"].append(Path(bc_path).name)
            return SvfResult(tool="saber", success=True, bugs=[])

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42, parallel_workers=2)
    run_number["value"] = 1
    assert (
        analyzer.run(
            source_root,
            tmp_path,
            compile_commands,
            entry_functions=["api_a", "api_b"],
        )
        is False
    )

    run_number["value"] = 2
    assert (
        analyzer.run(
            source_root,
            tmp_path,
            compile_commands,
            entry_functions=["api_a", "api_b"],
        )
        is True
    )

    assert calls["ander"].count("ok.bc") == 1
    assert calls["ander"].count("retry.bc") == 2
    assert calls["saber"] == ["saber_default.bc"]
    assert db.get_svf_hash()
    db.close()


def test_wpa_valid_marker_skips_and_missing_marker_reimports_without_runner(
    tmp_path: Path,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("td_init", "src/td.c", 1, 10)
    db.commit()
    bc_path = tmp_path / "default.bc"
    bc_path.write_text("bitcode\n", encoding="utf-8")
    calls = []

    class Runner:
        def run_ander(self, _bc_path, output_dir):
            calls.append("ander")
            dot = _write_callgraph(
                output_dir / "callgraph_final.dot",
                [("td_init", "_packet_receiver_thread")],
            )
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

    analyzer = SvfAnalyzer(db=db)
    paths = {"default": bc_path}

    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    assert calls == ["ander"]

    db.purge_svf_data("default")
    assert db.get_indirect_callees("td_init") == []
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    assert calls == ["ander"]
    assert db.get_indirect_callees("td_init")[0]["name"] == "_packet_receiver_thread"
    marker = json.loads(db.get_metadata("svf_db_import:ander:default"))
    assert marker["imported_row_count"] == 1
    db.close()


def test_zero_edge_marker_is_a_valid_cache_hit(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    bc_path = tmp_path / "empty.bc"
    bc_path.write_text("bitcode\n", encoding="utf-8")
    calls = []

    class Runner:
        def run_ander(self, _bc_path, output_dir):
            calls.append("ander")
            dot = _write_callgraph(output_dir / "callgraph_final.dot", [])
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

    analyzer = SvfAnalyzer(db=db)
    paths = {"default": bc_path}
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    assert calls == ["ander"]
    marker = json.loads(db.get_metadata("svf_db_import:ander:default"))
    assert marker["imported_row_count"] == 0
    db.close()


def test_wpa_artifact_hash_mismatch_reruns_tool(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    bc_path = tmp_path / "default.bc"
    bc_path.write_text("bitcode\n", encoding="utf-8")
    calls = []

    class Runner:
        def run_ander(self, _bc_path, output_dir):
            calls.append("ander")
            dot = _write_callgraph(
                output_dir / "callgraph_final.dot",
                [("caller", f"callee_{len(calls)}")],
            )
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

    analyzer = SvfAnalyzer(db=db)
    paths = {"default": bc_path}
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    artifact = tmp_path / ".zscope_svf" / "callgraph_final.dot"
    artifact.write_text("corrupted\n", encoding="utf-8")
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    assert calls == ["ander", "ander"]
    assert db.get_indirect_callees("caller")[0]["name"] == "callee_2"
    db.close()


def test_source_cache_hit_does_not_skip_missing_replay_artifact(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, compile_commands = _write_compile_commands(tmp_path)
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    bc_path = tmp_path / "default.bc"
    bc_path.write_text("bitcode\n", encoding="utf-8")
    calls = {"build": 0, "ander": 0}

    class Builder:
        def __init__(self, *args, **kwargs):
            self.failed_tus = []
            self.reused_linked_groups = set()

        def build(self, **kwargs):
            calls["build"] += 1
            return {"default": bc_path}

    class Runner:
        def __init__(self, *args, **kwargs):
            pass

        def run_ander(self, _bc_path, output_dir):
            calls["ander"] += 1
            dot = _write_callgraph(output_dir / "callgraph_final.dot", [])
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

        def run_saber(self, _bc_path, _output_dir):
            raise AssertionError("unexpected Saber run")

    monkeypatch.setattr(svf_module, "BitcodeBuilder", Builder)
    monkeypatch.setattr(svf_module, "SvfRunner", Runner)
    analyzer = SvfAnalyzer(db=db)
    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert calls == {"build": 1, "ander": 1}

    (tmp_path / ".zscope_svf" / "callgraph_final.dot").unlink()
    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert calls == {"build": 2, "ander": 2}
    db.close()


def test_saber_persists_and_replays_stable_json(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    bc_path = tmp_path / "saber.bc"
    bc_path.write_text("bitcode\n", encoding="utf-8")
    calls = []

    class Runner:
        def run_saber(self, _bc_path, _output_dir):
            calls.append("saber")
            return SvfResult(
                tool="saber",
                success=True,
                bugs=[{"line": 7, "file": "src/a.c", "type": "Double Free"}],
            )

    analyzer = SvfAnalyzer(db=db)
    paths = {"saber:default": bc_path}
    assert analyzer._run_saber_groups(Runner(), paths, tmp_path) is False
    artifact = tmp_path / ".zscope_svf_saber_default" / "saber_results.json"
    first_bytes = artifact.read_bytes()
    db.purge_svf_data("saber:default")
    assert analyzer._run_saber_groups(Runner(), paths, tmp_path) is False
    assert calls == ["saber"]
    assert artifact.read_bytes() == first_bytes
    assert db.get_taint_bugs("Double Free")[0]["svf_group"] == "saber:default"
    db.close()


def test_materialization_failure_rolls_back_existing_group(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_indirect_call("old_caller", "old_callee", svf_group="default")
    db.commit()
    dot = _write_callgraph(
        tmp_path / ".zscope_svf" / "callgraph_final.dot",
        [("new_caller", "new_callee")],
    )

    def fail_import(mapper, dot_path, *, commit=True, existing_edges=None):
        mapper.db.insert_indirect_call("new_caller", "new_callee", svf_group="default")
        raise RuntimeError("injected import failure")

    monkeypatch.setattr(svf_module.SvfOutputMapper, "import_callgraph", fail_import)
    analyzer = SvfAnalyzer(db=db)
    assert (
        analyzer._materialize_group(
            "ander",
            "default",
            "fingerprint",
            dot,
            analyzer._file_hash(dot),
            ".zscope_svf/callgraph_final.dot",
        )
        is False
    )
    assert db.get_indirect_callees("old_caller")[0]["name"] == "old_callee"
    assert db.get_indirect_callees("new_caller") == []
    assert db.get_metadata("svf_db_import:ander:default") == ""
    db.close()


def test_multi_group_recovery_only_reimports_stale_group(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    paths = {
        "alpha": tmp_path / "alpha.bc",
        "beta": tmp_path / "beta.bc",
    }
    for path in paths.values():
        path.write_text("bitcode\n", encoding="utf-8")
    calls = []

    class Runner:
        def run_ander(self, bc_path, output_dir):
            group = Path(bc_path).stem
            calls.append(group)
            dot = _write_callgraph(
                output_dir / "callgraph_final.dot",
                [(f"caller_{group}", f"callee_{group}")],
            )
            return SvfResult(tool="wpa-ander", success=True, output_file=dot)

    analyzer = SvfAnalyzer(db=db, parallel_workers=2)
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    db.purge_svf_data("alpha")
    assert analyzer._run_wpa_groups(Runner(), paths, tmp_path) is False
    assert sorted(calls) == ["alpha", "beta"]
    assert db.get_indirect_callees("caller_alpha")[0]["name"] == "callee_alpha"
    assert db.get_indirect_callees("caller_beta")[0]["name"] == "callee_beta"
    db.close()


def test_purge_svf_data_except_removes_only_stale_group_markers(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    for group in ("keep", "drop", "saber:drop"):
        tool = "saber" if group.startswith("saber:") else "ander"
        db.set_metadata(f"svf_db_import:{tool}:{group}", "{}")
    db.purge_svf_data_except({"keep"})
    assert db.get_metadata("svf_db_import:ander:keep") == "{}"
    assert db.get_metadata("svf_db_import:ander:drop") == ""
    assert db.get_metadata("svf_db_import:saber:saber:drop") == ""
    db.close()
