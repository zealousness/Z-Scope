import json
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
