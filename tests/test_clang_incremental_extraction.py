from pathlib import Path

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_extractor import ClangExtractor


class _FakeDB:
    def __init__(self):
        self.register_calls = 0
        self.purged = []
        self.commits = 0

    def register_tu_hash(self, file_path: str, file_hash: str):
        self.register_calls += 1
        raise AssertionError("register_tu_hash should not be called with prescanned_tus")

    def purge_tu_data(self, tu_id: int):
        self.purged.append(tu_id)

    def commit(self):
        self.commits += 1


def test_run_batch_extraction_uses_prescanned_tus_without_rehashing(
    tmp_path, monkeypatch
) -> None:
    changed_file = tmp_path / "changed.c"
    unchanged_file = tmp_path / "unchanged.c"
    changed_file.write_text("int changed(void) { return 1; }\n", encoding="utf-8")
    unchanged_file.write_text("int unchanged(void) { return 0; }\n", encoding="utf-8")

    def fail_hash(_path: Path) -> str:
        raise AssertionError("_compute_file_hash should not be called with prescanned_tus")

    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(fail_hash))

    extracted = []

    def fake_extract_tu(self, file_path, db, tu_id, progress_cb=None):
        extracted.append((Path(file_path), tu_id))
        return True

    monkeypatch.setattr(ClangExtractor, "extract_tu", fake_extract_tu)

    extractor = ClangExtractor(project_root=tmp_path)
    db = _FakeDB()
    stats = extractor.run_batch_extraction(
        [changed_file, unchanged_file],
        db,
        batch_size=10,
        prescanned_tus={
            str(changed_file.resolve()): (11, True),
            str(unchanged_file.resolve()): (12, False),
        },
    )

    assert stats == {"total": 2, "success": 1, "failed": 0, "skipped": 1}
    assert extracted == [(changed_file.resolve(), 11)]
    assert db.purged == [11]
    assert db.commits == 1
    assert db.register_calls == 0


def test_run_batch_extraction_keeps_legacy_hash_register_path(tmp_path, monkeypatch) -> None:
    source = tmp_path / "legacy.c"
    source.write_text("int legacy(void) { return 0; }\n", encoding="utf-8")

    class LegacyDB(_FakeDB):
        def register_tu_hash(self, file_path: str, file_hash: str):
            self.register_calls += 1
            assert file_path == str(source.resolve())
            assert file_hash == "hash"
            return (21, False)

    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(lambda _path: "hash"))
    extractor = ClangExtractor(project_root=tmp_path)
    db = LegacyDB()

    stats = extractor.run_batch_extraction([source], db, batch_size=10)

    assert stats == {"total": 1, "success": 0, "failed": 0, "skipped": 1}
    assert db.register_calls == 1
    assert db.commits == 1


def test_clang_backend_passes_prescanned_tus_to_batch_extraction(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "demo.c"
    source.write_text("int demo(void) { return 0; }\n", encoding="utf-8")

    class BackendDB(_FakeDB):
        def register_tu_hash(self, file_path: str, file_hash: str):
            self.register_calls += 1
            assert file_path == str(source.resolve())
            assert file_hash == "hash"
            return (31, True)

    class FakeExtractor:
        def __init__(self):
            self.received_prescanned_tus = None

        def wait_for_indexing(self, timeout: int, idle_threshold: float) -> bool:
            return True

        def run_batch_extraction(
            self,
            file_list,
            db,
            batch_size=50,
            progress_cb=None,
            prescanned_tus=None,
        ):
            self.received_prescanned_tus = prescanned_tus
            return {"total": len(file_list), "success": 1, "failed": 0, "skipped": 0}

    backend = ClangBackend(batch_size=7)
    backend._source_path = tmp_path
    backend._db = BackendDB()
    backend._extractor = FakeExtractor()

    monkeypatch.setattr(backend, "_collect_source_files", lambda: [source])
    monkeypatch.setattr(backend, "_ensure_extractor", lambda: True)
    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(lambda _path: "hash"))

    assert backend._run_full_extraction() is True

    assert backend._extractor.received_prescanned_tus == {str(source.resolve()): (31, True)}
    assert backend._status == "ready"
