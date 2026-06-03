import json
import threading
import time
from pathlib import Path

from zscope.retrieval import svf_analyzer as svf_module
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.retrieval.svf_analyzer import SvfAnalyzer
from zscope.retrieval.svf_runner import SvfResult


def _write_compile_commands(tmp_path: Path) -> tuple[Path, Path]:
    source_root = tmp_path / "project"
    source_root.mkdir()
    source_file = source_root / "main.c"
    source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text(
        json.dumps([
            {
                "directory": str(source_root),
                "command": "cc -c main.c",
                "file": "main.c",
            }
        ]),
        encoding="utf-8",
    )
    return source_root, compile_commands


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

        def run_all(self, bc_path, output_dir):
            calls.append(self.timeout)
            return {
                "ander": SvfResult(tool="wpa-ander", success=True),
                "saber": SvfResult(tool="saber", success=True),
            }

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


def test_svf_artifact_hash_skips_runner_when_source_hash_misses(
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

        def run_all(self, bc_path, output_dir):
            calls.append("runner")
            return {
                "ander": SvfResult(tool="wpa-ander", success=True),
                "saber": SvfResult(tool="saber", success=True),
            }

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
    assert calls == ["build"]
    assert db.get_svf_hash() == SvfAnalyzer._compute_aggregate_hash(
        compile_commands,
        groups,
        analyzer._cache_config(),
    )
    db.close()


def test_svf_skips_runner_when_builder_reuses_all_merged_groups(
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

        def run_all(self, bc_path, output_dir):
            calls.append("runner")
            return {}

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42)
    db.set_svf_hash("older-successful-svf-hash")

    assert analyzer.run(source_root, tmp_path, compile_commands) is True
    assert calls == ["build"]
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

        def run_all(self, bc_path, output_dir):
            calls.append("runner")
            return {
                "ander": SvfResult(tool="wpa-ander", success=True),
                "saber": SvfResult(tool="saber", success=True),
            }

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

        def run_all(self, bc_path, output_dir):
            calls.append(self.timeout)
            return {
                "ander": SvfResult(tool="wpa-ander", timed_out=True),
                "saber": SvfResult(tool="saber", success=True),
            }

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

    assert analyzer.run(
        source_root,
        tmp_path,
        compile_commands,
        entry_functions=["api_a", "api_b"],
    ) is True
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

    assert analyzer.run(
        source_root,
        tmp_path,
        compile_commands,
        entry_functions=["api_alpha"],
        svf_groups_config=str(groups_config),
    ) is True
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
            return SvfResult(tool="saber", success=True, bugs=[
                {"type": "Double Free", "file": "src/a.c", "line": 7}
            ])

    monkeypatch.setattr(svf_module, "BitcodeBuilder", FakeBitcodeBuilder)
    monkeypatch.setattr(svf_module, "SvfRunner", FakeSvfRunner)

    analyzer = SvfAnalyzer(db=db, timeout=42, parallel_workers=2)

    assert analyzer.run(
        source_root,
        tmp_path,
        compile_commands,
        entry_functions=["api_a", "api_b"],
    ) is False
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
    assert analyzer.run(
        source_root,
        tmp_path,
        compile_commands,
        entry_functions=["api_a", "api_b"],
    ) is False

    run_number["value"] = 2
    assert analyzer.run(
        source_root,
        tmp_path,
        compile_commands,
        entry_functions=["api_a", "api_b"],
    ) is True

    assert calls["ander"].count("ok.bc") == 1
    assert calls["ander"].count("retry.bc") == 2
    assert calls["saber"] == ["saber_default.bc"]
    assert db.get_svf_hash()
    db.close()
