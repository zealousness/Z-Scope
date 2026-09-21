from concurrent.futures import ThreadPoolExecutor
import threading

from zscope.config.user_config_workbook import UserConfigWorkbook


def row(name, source="inferred:semantic_modeling"):
    return {"symbol_name": name, "kind": "allocator", "symbol_type": "function", "source": source}


def test_independent_analyzers_merge_under_one_path_transaction(tmp_path):
    path = tmp_path / "user_config.xlsx"
    first, second = UserConfigWorkbook(path), UserConfigWorkbook(path)
    first.write_rows({"resource": [row("manual", "user")]})
    second.read_rows()  # Populate a cache which the other instance will invalidate.
    entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
    read = first.read_rows

    def paused_read():
        rows = read()
        entered.set()
        assert release.wait(5)
        return rows

    first.read_rows = paused_read

    def merge_second():
        second_started.set()
        return second.merge_generated(
            {"resource": [row("beta")]}, covered_symbols={("beta", "", "")}
        )

    with ThreadPoolExecutor(2) as pool:
        one = pool.submit(
            first.merge_generated, {"resource": [row("alpha")]}, covered_symbols={("alpha", "", "")}
        )
        assert entered.wait(5)
        two = pool.submit(merge_second)
        assert second_started.wait(5)
        acquired = second._cache_lock.acquire(blocking=False)
        if acquired:
            second._cache_lock.release()
        release.set()
        one.result()
        two.result()
    assert not acquired, "The read/merge/write interval must hold the path's shared lock"
    assert {r["symbol_name"] for r in UserConfigWorkbook(path).read_rows()["resource"]} == {
        "manual",
        "alpha",
        "beta",
    }


def test_different_workbooks_still_publish_concurrently(tmp_path):
    books = [UserConfigWorkbook(tmp_path / (name + ".xlsx")) for name in ("one", "two")]
    barrier = threading.Barrier(2)
    for book in books:
        original = book.read_rows

        def read(original=original):
            barrier.wait(5)
            return original()

        book.read_rows = read
    with ThreadPoolExecutor(2) as pool:
        futures = [
            pool.submit(book.merge_generated, {"resource": [row("alpha")]}) for book in books
        ]
        assert all(future.result()["added"] == 1 for future in futures)


def test_canonical_path_and_no_change_write_are_shared(tmp_path):
    path = tmp_path / "user_config.xlsx"
    first = UserConfigWorkbook(path)
    second = UserConfigWorkbook(tmp_path / "unused" / ".." / path.name)
    assert first._cache_lock is second._cache_lock
    first.write_rows({"resource": [row("manual", "user")]})
    before = path.stat().st_mtime_ns
    # Use the existing path to avoid platform differences resolving absent parents.
    same = UserConfigWorkbook(path)
    same.write_rows(first.read_rows())
    assert path.stat().st_mtime_ns == before


def test_pending_review_rows_expire_only_in_the_current_scope(tmp_path):
    book = UserConfigWorkbook(tmp_path / "user_config.xlsx")

    def proposal(uid, name, status="pending"):
        return {
            "review_id": uid,
            "symbol_name": name,
            "file_path": "a.c",
            "signature": "sig",
            "source": "inferred:contract_review",
            "status": status,
        }

    book.write_rows(
        {
            "contract_review": [
                proposal("old", "alpha"),
                proposal("other", "beta"),
                proposal("manual", "alpha", "confirmed"),
            ]
        }
    )
    scope = {("alpha", "a.c", "sig")}
    book.merge_generated({"contract_review": [proposal("new", "alpha")]}, covered_symbols=scope)
    assert {r["review_id"] for r in book.read_rows()["contract_review"]} == {
        "new",
        "other",
        "manual",
    }
    book.merge_generated({"contract_review": []}, covered_symbols=scope)
    assert {r["review_id"] for r in book.read_rows()["contract_review"]} == {"other", "manual"}
