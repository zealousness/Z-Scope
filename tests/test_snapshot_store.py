from zscope.snapshots.store import SnapshotStore
from zscope.common.utils import compute_code_hash, compute_semantic_fingerprint


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


def test_snapshot_load_prefers_source_file_over_header_snapshot(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    header_code = "int handle_request(void);\n"
    source_code = "int handle_request(void) { return 1; }\n"

    store.save_snapshot(
        "handle_request",
        {"summary": "header declaration"},
        header_code,
        "internal/server.ph:10",
    )
    store.save_snapshot(
        "handle_request",
        {"summary": "source implementation"},
        source_code,
        "src/server.c:10",
    )

    assert store.load_snapshot("handle_request") == {"summary": "source implementation"}
    assert store.load_snapshot("handle_request", file_path="internal/server.ph") == {
        "summary": "header declaration"
    }
    assert store.get_fingerprints("handle_request") == {
        "code_hash": compute_code_hash(source_code),
        "semantic_hash": compute_semantic_fingerprint(source_code),
    }


def test_final_report_load_prefers_source_file_over_header_snapshot(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")

    store.save_snapshot(
        "handle_request",
        {"summary": "header declaration"},
        "int handle_request(void);\n",
        "include/server.h:10",
    )
    store.save_snapshot(
        "handle_request",
        {"summary": "source implementation"},
        "int handle_request(void) { return 1; }\n",
        "src/server.c:10",
    )
    store.save_final_report(
        "handle_request",
        {"issues": [{"source": "header"}]},
        "include/server.h:10",
    )
    store.save_final_report(
        "handle_request",
        {"issues": [{"source": "source"}]},
        "src/server.c:10",
    )

    assert store.load_final_report("handle_request") == {
        "issues": [{"source": "source"}]
    }
