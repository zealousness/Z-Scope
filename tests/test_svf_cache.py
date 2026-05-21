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
