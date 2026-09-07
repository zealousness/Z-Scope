"""Regressions for the customer run's cache thrashing and broker contention."""

from concurrent.futures import ThreadPoolExecutor
import threading
from types import SimpleNamespace

import pytest

from zscope.retrieval.clang_derived_cache import DerivedCache
from zscope.retrieval.clang_extractor import ClangExtractor, _DerivedFileResult
from zscope.retrieval.clang_resolution import DerivedResolver
from zscope.retrieval.clang_source_snapshot import SourceInputsChanged


def test_new_keys_do_not_queue_sqlite_reads(tmp_path):
    cache = DerivedCache(tmp_path / "cache.db", max_bytes=1 << 20)
    try:
        with ThreadPoolExecutor(8) as pool:
            futures = [pool.submit(cache.get, "new", str(i)) for i in range(2000)]
            # No broker pump is required for keys proven absent.
            assert all(f.result(timeout=3) is None for f in futures)
        assert cache.stats["sqlite_selects"] == 0
        assert cache.stats["presence_misses"] == 2000
        assert cache.snapshot()["presence_bytes"] + cache.max_bytes == 1 << 20
    finally:
        cache.close()


def test_presence_filter_never_hides_persisted_or_evicted_entries(tmp_path):
    path = tmp_path / "cache.db"
    cache = DerivedCache(path, epoch="one", max_bytes=4096)
    try:
        for i in range(100):
            cache.put("sample", str(i), {"data": "x" * 500, "i": i})
        cache.put("sample", "1", {"data": "override", "_volatile": True})
        assert cache.get_many("sample", [str(i) for i in range(100)])["1"]["data"] == "override"
        cache.checkpoint()
    finally:
        cache.close()

    cache = DerivedCache(path, epoch="one", max_bytes=4096)
    try:
        assert all(cache.get("sample", str(i))["i"] == i for i in range(100))
        cache.put("sample", "transient", {"_volatile": True})
        cache.discard_volatile()
        assert cache.get("sample", "transient") is None
    finally:
        cache.close()
    cache = DerivedCache(path, epoch="changed", max_bytes=4096)
    try:
        assert cache.get("sample", "1") is None
        assert cache.stats["sqlite_selects"] == 0
    finally:
        cache.close()


def test_batched_receipts_survive_filter_saturation(tmp_path):
    cache = DerivedCache(max_bytes=64)
    try:
        for i in range(1000):
            cache.put("receipt", str(i), {"index": i})
        values = cache.get_many("receipt", [str(i) for i in range(1001)])
        assert values == {str(i): {"index": i} for i in range(1000)}
        assert cache.stats["sqlite_selects"] == 3
    finally:
        cache.close()


def test_coordinate_stream_does_not_evict_source_working_set(tmp_path):
    source = tmp_path / "one.cpp"
    source.write_text("a" * 10000 + "\n", encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    cache = DerivedCache(max_bytes=128 << 10)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        info = resolver.sources.path(source)
        view = resolver.sources.source_for_path(info)
        before = cache.stats["sqlite_selects"]
        for char in range(10000):
            assert resolver.sources.coordinate(resolver.sources.path(source), 0, char) == (
                "one.cpp",
                1,
                char,
            )
        assert resolver.sources.source_for_path(info) is view
        assert resolver.sources.stats["evictions"] == 0
        assert cache.stats["sqlite_selects"] == before
    finally:
        cache.close()


@pytest.mark.parametrize("budget", [0, 8192])
def test_validation_reads_receipts_instead_of_source_bodies(tmp_path, budget):
    source = tmp_path / "large.cpp"
    source.write_text("int value;\n" * 100000, encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    cache = DerivedCache(max_bytes=budget)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source) as state:
            resolver.sources.lines(source)
        before = cache.stats["sqlite_read_bytes"]
        for _ in range(20):
            resolver.sources.validate_used(state)
            receipts = resolver.sources.receipts(state)
            assert all("lines" not in row["value"] for row in receipts)
        assert cache.stats["sqlite_read_bytes"] - before < 100000
        assert resolver.sources.stats["source_reads"] == 1
        source.write_text("changed\n", encoding="utf-8")
        with pytest.raises(SourceInputsChanged):
            resolver.sources.validate_used(state)
    finally:
        cache.close()


def test_file_checkpoint_follows_single_completion_validation(tmp_path, monkeypatch):
    source = tmp_path / "one.c"
    source.write_text("int value;\n", encoding="utf-8")
    ex = ClangExtractor(tmp_path, max_threads=1)
    cache = DerivedCache()
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    resolver.scope = "rebuild_function_symbol_refs"
    original = resolver.sources.validate_used
    validations = []

    def validate(state):
        validations.append(True)
        return original(state)

    monkeypatch.setattr(resolver.sources, "validate_used", validate)

    def worker(_item):
        resolver.sources.lines(source)
        return _DerivedFileResult(stats_by_index={"function_symbol_context": {}})

    try:
        ex._run_derived_file_jobs([("one.c", [])], worker, lambda result: None, {})
        assert len(validations) == 1
        assert (
            cache.db.execute(
                "SELECT COUNT(*) FROM entries WHERE namespace LIKE '%:file'"
            ).fetchone()[0]
            == 1
        )
    finally:
        cache.close()


def test_json_decoding_does_not_hold_broker_registry_lock(tmp_path, monkeypatch):
    from zscope.retrieval import clang_derived_cache as module

    cache = DerivedCache()
    cache.put("item", "value", {"a": 1})
    entered, release = threading.Event(), threading.Event()
    original = module.json.loads

    def decode(value):
        entered.set()
        assert release.wait(3)
        return original(value)

    monkeypatch.setattr(module.json, "loads", decode)
    try:
        with ThreadPoolExecutor(2) as pool:
            reading = pool.submit(cache.get, "item", "value")
            try:
                assert entered.wait(2)
                assert pool.submit(cache.snapshot).result(timeout=2)["memory_hits"] == 1
            finally:
                release.set()
            assert reading.result() == {"a": 1}
    finally:
        cache.close()


def test_cached_source_version_is_tracked_for_each_task(tmp_path):
    source = tmp_path / "one.cpp"
    source.write_text("int value;\n", encoding="utf-8")
    cache = DerivedCache()
    resolver = DerivedResolver(ClangExtractor(tmp_path), cache)
    try:
        resolver.sources.version_key(source)
        with pytest.raises(SourceInputsChanged):
            with resolver.file(source) as state:
                resolver.sources.version_key(source)
                assert ("source", str(source)) in state["source_views"]
                source.write_text("changed\n", encoding="utf-8")
    finally:
        cache.close()


def test_heartbeat_covers_validation_and_cache_close(tmp_path, monkeypatch):
    from zscope.retrieval import clang_resolution as module
    from zscope.retrieval.clang_source_snapshot import DerivedSourceSnapshots

    ex = ClangExtractor(tmp_path)
    monkeypatch.setattr(module, "build_identity", lambda *a: ("epoch", True, "verified"))
    phases = []
    close = DerivedCache.close

    def validate(sources, progress):
        snapshot = ex._derived_resolver.progress_snapshot()
        assert snapshot["files_completed"] == snapshot["files_total"] == 1
        assert snapshot["active"] == []
        phases.append(snapshot["phase"])
        progress(validation_file="header.h", validation_kind="source")
        assert ex._derived_resolver.progress_snapshot()["phase_progress"]["checked"] == 1

    def closing(cache):
        phases.append(ex._derived_resolver.progress_snapshot()["phase"])
        assert any(t.name == "ClangDerivedHeartbeat" for t in threading.enumerate())
        close(cache)

    monkeypatch.setattr(DerivedSourceSnapshots, "validate_all", validate)
    monkeypatch.setattr(DerivedCache, "close", closing)

    @module.derived_session
    def collect(extractor, db):
        extractor._derived_resolver.workload(1)
        extractor._derived_resolver.file_completed()
        return "done"

    assert collect(ex, SimpleNamespace(_db_path=tmp_path / "db.sqlite3")) == "done"
    assert phases == ["source-validation", "cache-close"]
    assert ex._derived_resolver is None
