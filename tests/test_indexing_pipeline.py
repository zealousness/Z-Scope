import json
import os
import sys
from pathlib import Path

import pytest

from zscope.retrieval.indexing_identity import (
    dependencies_current,
    dependency_snapshot,
    file_digest,
    parse_depfile,
)
from zscope.retrieval.indexing_inventory import inventory
from zscope.retrieval.indexing_runtime import admitted_workers, run_process
from zscope.retrieval.build_llvm import BitcodeBuilder
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.retrieval.svf_analyzer import SvfAnalyzer
from zscope.retrieval.svf_runner import SvfResult, SvfRunner


def test_memory_admission_reserves_each_full_process():
    state = {"cpu_count": 16, "task_memory_budget_bytes": 48 * 1024**3}
    assert admitted_workers(8, 10, 32768, state) == 1
    assert admitted_workers(4, 10, 12288, state) == 4
    assert admitted_workers(1, 1, 65536, state) == 0
    assert admitted_workers(8, 10, 4096, {"cpu_count": 2, "task_memory_budget_bytes": None}) == 1


def test_measured_process_timeout_and_disk_output(tmp_path):
    result = run_process(
        [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(5)"],
        cwd=tmp_path,
        output_prefix=tmp_path / "test",
        timeout=0.2,
        heartbeat_seconds=0.05,
    )
    assert result.returncode != 0
    assert result.metrics["timed_out"]
    assert "ready" in result.stdout
    assert result.metrics["wall_seconds"] < 4
    assert Path(result.metrics["stdout_path"]).is_file()


def test_dependency_hash_detects_same_timestamp_change_and_deletion(tmp_path):
    source = tmp_path / "with space.h"
    source.write_text("one")
    original = source.stat()
    snapshot = dependency_snapshot([source])
    source.write_text("two")
    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert not dependencies_current(snapshot)
    source.unlink()
    assert not dependencies_current(snapshot)
    assert not dependencies_current({str(source): "missing"})


def test_compiler_search_paths_and_nested_response_files(tmp_path):
    from zscope.retrieval.indexing_identity import compiler_search_directories, include_search_roots

    assert compiler_search_directories("warning only", tmp_path) is None
    assert compiler_search_directories(
        "#include <...> search starts here:\n /sdk/includes\nEnd of search list.", tmp_path
    ) == [Path("/sdk/includes").resolve()]
    (tmp_path / "one.rsp").write_text("@two.rsp")
    (tmp_path / "two.rsp").write_text("-I ../early")
    assert (tmp_path.parent / "early").resolve() in include_search_roots(
        ["cc", "@one.rsp"], tmp_path
    )


def test_owned_cache_creation_is_not_an_include_change(tmp_path):
    from zscope.retrieval.indexing_identity import InputValidator
    cache = tmp_path / ".cache" / "clangd"
    database = tmp_path / "facts.db"
    exclusions = [cache, database, Path(str(database) + "-wal")]
    before = InputValidator(exclusions).directories([tmp_path])
    cache.mkdir(parents=True)
    (cache / "background.idx").write_text("index")
    database.write_text("db")
    Path(str(database) + "-wal").write_text("wal")
    assert InputValidator(exclusions).searches(before)
    (cache.parent / "real_header.h").write_text("#define VALUE 1\n")
    assert not InputValidator(exclusions).searches(before)


def test_legacy_artifacts_do_not_prove_compilation_coverage(tmp_path):
    source = tmp_path / "main.c"
    source.write_text("int f(void) {return 0;}")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "file": str(source),
                    "directory": str(tmp_path),
                    "arguments": ["cc", "-c", str(source)],
                }
            ]
        )
    )
    (tmp_path / "merged_a.bc").write_bytes(b"same")
    (tmp_path / "merged_b.bc").write_bytes(b"same")
    audit = inventory(cdb, tmp_path)
    assert not audit["coverage_verified"]
    assert audit["tasks_by_tool"] == {"unverified": 2}
    assert len(audit["equal_content_groups"]) == 1
    key = audit["contexts"][0]["context"]
    unproven = inventory(cdb, tmp_path, {"attempts": {key: {"status": "compiled"}}})
    assert not unproven["coverage_verified"]
    assert unproven["contexts"][0]["reason"] == "artifact_not_recorded"


def test_svf_identical_inputs_share_solver_but_keep_group_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "zscope.retrieval.indexing_runtime.resource_limits",
        lambda: {"cpu_count": 16, "task_memory_budget_bytes": 48 * 1024**3},
    )
    db = KnowledgeDB(str(tmp_path / "code.db"))
    analyzer = SvfAnalyzer(db, heap_limit_mb=32768, parallel_workers=8)
    main_thread = __import__("threading").get_ident()
    writer = analyzer._materialize_group

    def checked_writer(*args):
        assert __import__("threading").get_ident() == main_thread
        return writer(*args)

    monkeypatch.setattr(analyzer, "_materialize_group", checked_writer)
    calls = []

    class Runner:
        def run_saber(self, path, output):
            calls.append(path)
            return SvfResult(tool="saber", success=True)

    paths = {}
    for name in ("a", "b"):
        path = tmp_path / (name + ".bc")
        path.write_bytes(b"identical-bitcode")
        paths["saber:" + name] = path
    assert not analyzer._run_saber_groups(Runner(), paths, tmp_path)
    assert len(calls) == 1
    stats = json.loads(db.get_metadata("svf_run_stats:saber"))
    assert stats["executed"] == 1 and stats["deduplicated"] == 1
    assert stats["import_seconds"] >= 0 and stats["completed"] == 2
    assert all(analyzer._load_tool_status("saber", name)["status"] == "success" for name in paths)
    # Restart and change worker budget: the successful artifact remains reusable.
    second = SvfAnalyzer(db, heap_limit_mb=4096, parallel_workers=1)
    assert not second._run_saber_groups(Runner(), {"saber:renamed": paths["saber:a"]}, tmp_path)
    assert len(calls) == 1
    db.close()


@pytest.mark.parametrize(
    "hierarchy", ["0::/parent/job", "4:memory:/parent/job\n3:cpu,cpuacct:/parent/job"]
)
def test_resource_admission_respects_nested_container_limits(monkeypatch, hierarchy):
    from zscope.retrieval import indexing_runtime as runtime

    if os.name == "nt":
        pytest.skip("Linux cgroup input")
    contents = {
        "/proc/meminfo": "MemAvailable: 67108864 kB\n",
        "/proc/self/cgroup": hierarchy,
        "/sys/fs/cgroup/parent/memory.max": str(12 * 1024**3),
        "/sys/fs/cgroup/parent/memory.current": str(4 * 1024**3),
        "/sys/fs/cgroup/parent/cpu.max": "200000 100000",
        "/sys/fs/cgroup/memory/parent/memory.limit_in_bytes": str(12 * 1024**3),
        "/sys/fs/cgroup/memory/parent/memory.usage_in_bytes": str(4 * 1024**3),
        "/sys/fs/cgroup/cpu,cpuacct/parent/cpu.cfs_quota_us": "200000",
        "/sys/fs/cgroup/cpu,cpuacct/parent/cpu.cfs_period_us": "100000",
    }

    def read(path, *args, **kwargs):
        if str(path) not in contents:
            raise FileNotFoundError(str(path))
        return contents[str(path)]

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(os, "sched_getaffinity", lambda pid: set(range(16)))
    state = runtime.resource_limits()
    assert state["cpu_count"] == 2
    assert state["task_memory_budget_bytes"] == 6 * 1024**3


@pytest.mark.skipif(
    not os.environ.get("Z_SCOPE_TEST_LLVM"), reason="requires Linux LLVM/SVF toolchain"
)
def test_real_direct_bitcode_dependency_cache_and_svf(tmp_path, monkeypatch):
    monkeypatch.setenv("Z_SCOPE_BITCODE_MEMORY_MB", "512")
    source = tmp_path / "main.c"
    header = tmp_path / "value.h"
    header.write_text("#define VALUE 1\n")
    source.write_text('#include "value.h"\nint main(void) { return VALUE; }\n')
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "file": str(source),
                    "directory": str(tmp_path),
                    "arguments": ["cc", "-c", str(source)],
                }
            ]
        )
    )

    def build():
        builder = BitcodeBuilder(tmp_path, cdb, output_dir=tmp_path / "bc")
        output = builder.build()
        assert not builder.failed_tus
        assert output
        return builder, output["default"]

    builder, bc = build()
    assert list(builder._manifest["attempts"].values())[0]["status"] == "compiled"
    assert inventory(cdb, builder.output_dir)["coverage_verified"]
    original_hash = file_digest(bc)
    builder, _ = build()
    assert list(builder._manifest["attempts"].values())[0]["status"] == "reused"
    # A crash before aggregate-manifest publication still has full TU checkpoints.
    builder._manifest_path.unlink()
    builder, _ = build()
    assert list(builder._manifest["attempts"].values())[0]["status"] == "reused"
    header.write_text("#define VALUE 2\n")
    assert not inventory(cdb, builder.output_dir)["coverage_verified"]
    builder, bc = build()
    assert list(builder._manifest["attempts"].values())[0]["status"] == "compiled"
    assert file_digest(bc) != original_hash
    runner = SvfRunner(heap_limit_mb=512, timeout=60)
    runner.validate_llvm("llvm-link")
    for result in (
        runner.run_ander(bc, tmp_path / "wpa"),
        runner.run_saber(bc, tmp_path / "saber"),
    ):
        assert result.success, result.stderr
        assert result.metrics["cpu_seconds"] is not None
        assert result.metrics["peak_rss_bytes"] > 0
