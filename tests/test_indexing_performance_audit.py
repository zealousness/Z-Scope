"""Scale and concurrency regressions found in the indexing pipeline audit."""

import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from zscope.retrieval import indexing_identity as identity
from zscope.retrieval.clang_batch import BatchIndexer


@pytest.mark.parametrize("namespace", ["path", "cache"])
def test_broker_owner_can_join_worker_singleflight(namespace):
    # Keep a deadlock regression from hanging the whole pytest process.
    code = """
from pathlib import Path
from types import SimpleNamespace
import threading
from zscope.retrieval.clang_derived_cache import DerivedCache
from zscope.retrieval.clang_source_snapshot import DerivedSourceSnapshots
cache = DerivedCache()
views = DerivedSourceSnapshots(SimpleNamespace(project_root=Path.cwd()), cache, threading.local())
read = (lambda: views.path('probe.c')) if NAMESPACE == 'path' else (lambda: cache.compute('probe', 'key', lambda: {'ok': True}))
worker = threading.Thread(target=read, daemon=True)
worker.start()
assert cache.wakeup.wait(2)
assert read()
worker.join(2)
assert not worker.is_alive()
cache.close()
""".replace(
        "NAMESPACE", repr(namespace)
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr


def test_slow_directory_validation_does_not_block_other_file_hashes(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = identity.search_directories_snapshot

    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    source = tmp_path / "fast.h"
    source.write_text("int a;\n")
    digest = identity.file_digest(source)
    validator = identity.InputValidator()
    monkeypatch.setattr(identity, "search_directories_snapshot", slow)
    with ThreadPoolExecutor(2) as workers:
        first = workers.submit(validator.directories, [tmp_path])
        try:
            assert entered.wait(2)
            second = workers.submit(validator.dependencies, {str(source): digest})
            assert second.result(timeout=2)
        finally:
            release.set()
        assert first.result(timeout=2)


def test_shared_validation_only_reads_each_input_once(tmp_path, monkeypatch):
    source = tmp_path / "shared.h"
    source.write_text("int a;\n")
    expected = identity.file_digest(source)
    calls = []

    def digest(path):
        calls.append(path)
        return expected

    monkeypatch.setattr(identity, "file_digest", digest)
    validator = identity.InputValidator()
    with ThreadPoolExecutor(8) as workers:
        assert all(
            workers.map(lambda _: validator.dependencies({str(source): expected}), range(1000))
        )
    assert calls == [source]
    roots = validator.directories([tmp_path])
    with monkeypatch.context() as patch:
        patch.setattr(Path, "resolve", lambda *args: pytest.fail("warm root resolved again"))
        for _ in range(1000):
            assert validator.directories([tmp_path]) == roots
    (tmp_path / "new.h").write_text("int b;\n")
    assert not identity.InputValidator().searches(roots)


def make_importer(tmp_path):
    importer = BatchIndexer.__new__(BatchIndexer)
    importer.root, importer.stats = tmp_path, {}
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE native_identities(usr TEXT,kind TEXT,data TEXT)")
    conn.execute("CREATE INDEX identities ON native_identities(usr,kind)")
    declaration = {"definition_kind": "definition", "location": {"file": str(tmp_path / "a.c")}}
    conn.execute(
        "INSERT INTO native_identities VALUES (?,?,?)", ("g", "global", json.dumps(declaration))
    )
    return importer, SimpleNamespace(_conn=conn)


@pytest.mark.parametrize("budget", [0, 1 << 20])
def test_import_bindings_and_paths_survive_hot_cache_eviction(tmp_path, monkeypatch, budget):
    importer, stage = make_importer(tmp_path)
    try:
        with importer._import_session():
            importer._native_cache.max_bytes = budget
            importer._native_sources.budget = budget
            expected = importer._native_binding(stage, "global", {"usr": "g", "name": "g"}, {})
            assert expected["target_file"] == "a.c"
            for i in range(20):
                importer._native_binding(stage, "global", {"usr": str(i), "name": str(i)}, {})
            with monkeypatch.context() as patch:
                patch.setattr(
                    Path, "resolve", lambda *args: pytest.fail("import resolved a warm path")
                )
                for _ in range(1000):
                    assert importer._relative(str(tmp_path / "a.c")) == "a.c"
                    assert (
                        importer._native_binding(stage, "global", {"usr": "g", "name": "g"}, {})
                        == expected
                    )
            assert importer.stats["identity_queries"] == 21
    finally:
        stage._conn.close()


def test_import_type_layout_and_ambiguity_are_not_cached_by_name(tmp_path):
    importer, stage = make_importer(tmp_path)
    types = {}
    for number, fingerprint in enumerate(("A", "B"), 1):
        file = f"{number}.h"
        types["Item", "struct", file, 1] = {
            "id": number,
            "name": "Item",
            "kind": "struct",
            "file_path": file,
            "start_line": 1,
            "end_line": 2,
        }
        declaration = {
            "target": {"definition_hash": fingerprint},
            "type_kind": "struct",
            "begin": {"file": str(tmp_path / file), "line": 1},
        }
        stage._conn.execute(
            "INSERT INTO native_identities VALUES (?,?,?)",
            ("item", "type", json.dumps(declaration)),
        )
    try:
        with importer._import_session():
            for fingerprint, expected in (("A", 1), ("B", 2), ("", None)):
                result = importer._native_binding(
                    stage,
                    "type",
                    {"usr": "item", "name": "Item", "definition_hash": fingerprint},
                    types,
                )
                assert result["id"] == expected
                assert bool(result["reason"]) == (expected is None)
    finally:
        stage._conn.close()


@pytest.mark.skipif(os.name == "nt", reason="native C++ unit test runs in Linux")
def test_native_function_owner_lookup(tmp_path):
    compiler = shutil.which("g++") or shutil.which("clang++")
    if not compiler:
        pytest.skip("C++ compiler required")
    root = Path(__file__).resolve().parents[1]
    executable = tmp_path / "ownership"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-O2",
            "-I",
            str(root / "native/clang-indexer"),
            str(root / "tests/fixtures/clang_function_ownership.cpp"),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
