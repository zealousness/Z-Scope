"""Metadata IO is bounded by source views, not reference occurrences."""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from zscope.retrieval.clang_derived_cache import DerivedCache
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.clang_resolution import DerivedResolver
from zscope.retrieval.clang_source_snapshot import SourceInputsChanged


def setup(tmp_path, budget=1 << 20):
    source = tmp_path / "a.cpp"
    source.write_text("/*😀*/ value\n", encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    cache = DerivedCache(max_bytes=budget)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    raw = {"uri": source.as_uri(), "range": {"start": {"line": 0, "character": 7}}}
    return source, ex, cache, resolver, raw


@pytest.mark.parametrize("encoding,column", [("utf-16", 7), ("utf-8", 9), ("utf-32", 6)])
def test_warm_location_needs_no_filesystem_calls(tmp_path, monkeypatch, encoding, column):
    source, ex, cache, resolver, raw = setup(tmp_path)
    ex._position_encoding = encoding
    raw["range"]["start"]["character"] = column
    try:
        expected = resolver.location(raw)
        assert expected == ("a.cpp", 1, 6)

        def forbidden(*args, **kwargs):
            pytest.fail("filesystem operation in warm coordinate path")

        with monkeypatch.context() as patch:
            patch.setattr(Path, "resolve", forbidden)
            patch.setattr(Path, "stat", forbidden)
            for _ in range(1000):
                assert resolver.location(raw) == expected
                assert ex._read_source_lines(source)[0].startswith("/*😀*/")
        resolver.sources.validate_all()
    finally:
        cache.close()


@pytest.mark.parametrize("workers,budget", [(1, 0), (8, 0), (8, 1 << 20)])
def test_concurrent_and_evicted_views_do_not_reread_sources(tmp_path, workers, budget):
    source, ex, cache, resolver, raw = setup(tmp_path, budget)

    def run():
        with resolver.file(source):
            return [resolver.location(raw) for _ in range(32)]

    try:
        with ThreadPoolExecutor(workers) as pool:
            futures = [pool.submit(run) for _ in range(workers)]
            while not all(f.done() for f in futures):
                cache.wakeup.clear()
                cache.pump()
                cache.wakeup.wait(0.001)
            results = [f.result() for f in futures]
        assert all(value == results[0] for value in results)
        assert resolver.sources.stats["source_reads"] == 1
        assert resolver.sources.used + cache._bytes <= budget
        cache.discard_volatile()
        assert resolver.location(raw) == results[0][0]
        assert resolver.sources.stats["source_reads"] == 1
    finally:
        cache.close()


@pytest.mark.parametrize("change", ["modify", "delete", "symlink"])
def test_validation_rejects_changed_source_or_alias(tmp_path, change):
    source, ex, cache, resolver, raw = setup(tmp_path)
    try:
        if change == "symlink":
            if os.name == "nt":
                pytest.skip("symlink privileges vary on Windows; exercised on Linux")
            alias = tmp_path / "alias.cpp"
            alias.symlink_to(source)
            raw["uri"] = alias.as_uri()
        resolver.location(raw)
        if change == "delete":
            source.unlink()
        elif change == "symlink":
            other = tmp_path / "other.cpp"
            other.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            alias.unlink()
            alias.symlink_to(other)
        else:
            original = source.stat()
            source.write_text("/*😀*/ other\n", encoding="utf-8")
            os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        with pytest.raises(SourceInputsChanged):
            resolver.sources.validate_all()
    finally:
        cache.close()


def test_irrelevant_reference_files_do_not_load_source(tmp_path):
    source, ex, cache, resolver, raw = setup(tmp_path)
    candidate = {"name": "value", "file_path": "a.cpp", "start_line": 1, "end_line": 1}
    unrelated = tmp_path / "unrelated.cpp"
    unrelated.write_text("unrelated\n", encoding="utf-8")
    raw["uri"] = unrelated.as_uri()
    try:
        assert resolver.matching_declarations([candidate], [raw] * 1000, {}) == []
        assert resolver.sources.stats["source_reads"] == 0
        assert len(list(resolver.unique_locations([raw] * 1000))) == 1
    finally:
        cache.close()


def test_ordinary_source_reads_still_refresh(tmp_path):
    source = tmp_path / "a.c"
    source.write_text("one")
    ex = ClangExtractor(tmp_path)
    assert ex._read_source_lines(source) == ["one"]
    source.write_text("changed")
    assert ex._read_source_lines(source) == ["changed"]


def test_restored_receipts_are_checked_again_before_publication(tmp_path):
    source, ex, cache, resolver, raw = setup(tmp_path, budget=0)
    try:
        with resolver.file(source) as state:
            resolver.location(raw)
        receipts = resolver.sources.receipts(state)
    finally:
        cache.close()
    cache = DerivedCache(max_bytes=0)
    resolver = DerivedResolver(ex, cache)
    try:
        resolver.sources.validate_receipts(receipts)
        source.write_text("changed after checkpoint restore\n")
        with pytest.raises(SourceInputsChanged):
            resolver.sources.validate_all()
    finally:
        cache.close()


def test_warm_rpc_leases_and_source_helpers_do_not_restat(tmp_path, monkeypatch):
    source, ex, cache, resolver, raw = setup(tmp_path)
    ex.get_symbol_details = lambda *args: [{"usr": "global"}]
    ex.send_notification = lambda *args: True
    try:
        with resolver.file(source):
            expected = resolver._rpc("symbolInfo", source, 1, 6, {})
            masked = ex._read_masked_source(source)
            context = ex._get_file_semantic_context(
                source, ex._read_source_lines(source), enabled=False
            )
            with monkeypatch.context() as patch:

                def forbidden(*args, **kwargs):
                    pytest.fail("filesystem operation in a warm RPC/source helper")

                patch.setattr(Path, "resolve", forbidden)
                patch.setattr(Path, "stat", forbidden)
                for _ in range(100):
                    assert resolver._rpc("symbolInfo", source, 1, 6, {}) == expected
                    with resolver.lease(source) as opened:
                        assert opened
                    assert ex._read_masked_source(source) == masked
                    assert ex._get_file_semantic_context(source, [], enabled=False) == context
    finally:
        cache.close()


@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_snapshots_keep_original_newline_normalization(tmp_path, newline):
    source, ex, cache, resolver, raw = setup(tmp_path)
    source.write_bytes(newline.join([b"int a;", b"int b;", b""]))
    try:
        snapshot = ex._read_source_text(source)
        ex._derived_resolver = None
        assert snapshot == ex._read_source_text(source)
    finally:
        cache.close()


def test_active_reference_batch_reuses_oversized_view(tmp_path, monkeypatch):
    source, ex, cache, resolver, raw = setup(tmp_path, budget=0)
    calls = []
    original = resolver.sources.source_for_path

    def read(info):
        calls.append(info["absolute"])
        return original(info)

    monkeypatch.setattr(resolver.sources, "source_for_path", read)
    rows = [
        {"uri": source.as_uri(), "range": {"start": {"line": 0, "character": column}}}
        for column in range(1000)
    ]
    try:
        converted = list(resolver.locations(rows + rows))
        assert len(converted) == 1000
        assert converted[7] == ("a.cpp", 1, 6)
        assert calls == [str(source)]
        assert resolver.sources.used + cache._bytes == 0
    finally:
        cache.close()
