from zscope.snapshots.store import SnapshotStore


def test_snapshot_load_cache_returns_independent_copies(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(
        "handle_request",
        {"summary": "first", "items": [{"name": "a"}]},
        "int handle_request(void) { return 0; }",
        "src/server.c:10",
    )

    loaded = store.load_snapshot("handle_request")
    assert loaded is not None
    loaded["summary"] = "mutated"
    loaded["items"][0]["name"] = "mutated"

    loaded_again = store.load_snapshot("handle_request")

    assert loaded_again == {"summary": "first", "items": [{"name": "a"}]}


def test_snapshot_save_refreshes_cached_value(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(
        "handle_request",
        {"summary": "first"},
        "int handle_request(void) { return 0; }",
        "src/server.c:10",
    )
    assert store.load_snapshot("handle_request") == {"summary": "first"}

    store.save_snapshot(
        "handle_request",
        {"summary": "second"},
        "int handle_request(void) { return 1; }",
        "src/server.c:10",
    )

    assert store.load_snapshot("handle_request") == {"summary": "second"}
