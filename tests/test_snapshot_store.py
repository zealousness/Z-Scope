import json

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


def test_final_report_load_matches_normalized_path_hint(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(
        "handle_request",
        {"summary": "source implementation"},
        "int handle_request(void) { return 1; }\n",
        "src/server.c:10",
    )
    store.save_final_report(
        "handle_request",
        {"issues": [{"source": "source"}]},
        "src/server.c:10",
    )

    assert store.load_final_report("handle_request", file_path=".\\src\\server.c") == {
        "issues": [{"source": "source"}]
    }


def test_save_final_report_updates_snapshot_row_for_normalized_path_hint(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(
        "handle_request",
        {"summary": "source implementation"},
        "int handle_request(void) { return 1; }\n",
        ".\\src\\server.c:10",
    )
    store.save_final_report(
        "handle_request",
        {"issues": [{"source": "source"}]},
        "src/server.c:10",
    )

    assert store.load_final_report("handle_request", file_path="src/server.c") == {
        "issues": [{"source": "source"}]
    }


def test_location_parser_preserves_windows_drive_colon(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(
        "handle_request",
        {"summary": "windows path"},
        "int handle_request(void) { return 1; }\n",
        "C:\\repo\\src\\server.c:10",
    )
    store.save_final_report(
        "handle_request",
        {"issues": [{"source": "source"}]},
        "C:\\repo\\src\\server.c:10",
    )

    assert store.load_final_report(
        "handle_request",
        file_path="C:\\repo\\src\\server.c",
    ) == {"issues": [{"source": "source"}]}


def test_final_report_path_hint_does_not_guess_ambiguous_suffix(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    for file_path, source in (
        ("src/a/server.c", "a"),
        ("src/b/server.c", "b"),
    ):
        store.save_snapshot(
            "handle_request",
            {"summary": source},
            "int handle_request(void) { return 1; }\n",
            f"{file_path}:10",
        )
        store.save_final_report(
            "handle_request",
            {"issues": [{"source": source}]},
            f"{file_path}:10",
        )

    assert store.load_final_report("handle_request", file_path="server.c") is None


def test_final_report_cache_returns_independent_copies_and_refreshes_on_save(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    store = SnapshotStore(snapshot_dir)
    store.save_snapshot(
        "handle_request",
        {"summary": "snapshot"},
        "int handle_request(void) { return 0; }\n",
        "src/server.c:10",
    )
    store.save_final_report(
        "handle_request",
        {"issues": [{"id": "first"}]},
        "src/server.c:10",
    )

    reloaded_store = SnapshotStore(snapshot_dir)
    first = reloaded_store.load_final_report("handle_request", file_path="src/server.c")
    assert first is not None
    first["issues"][0]["id"] = "mutated"

    second = reloaded_store.load_final_report("handle_request", file_path="src/server.c")
    assert second == {"issues": [{"id": "first"}]}

    reloaded_store.save_final_report(
        "handle_request",
        {"issues": [{"id": "second"}]},
        "src/server.c:10",
    )

    assert reloaded_store.load_final_report("handle_request", file_path="src/server.c") == {
        "issues": [{"id": "second"}]
    }


def test_final_report_missing_file_is_not_cached_as_permanent_miss(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    store = SnapshotStore(snapshot_dir)
    store.save_snapshot(
        "handle_request",
        {"summary": "snapshot"},
        "int handle_request(void) { return 0; }\n",
        "src/server.c:10",
    )
    store.save_final_report(
        "handle_request",
        {"issues": [{"id": "first"}]},
        "src/server.c:10",
    )
    final_path = next(snapshot_dir.glob("*_final.json"))
    final_path.unlink()

    reloaded_store = SnapshotStore(snapshot_dir)
    assert reloaded_store.load_final_report("handle_request", file_path="src/server.c") is None

    final_path.write_text(json.dumps({"issues": [{"id": "restored"}]}), encoding="utf-8")

    assert reloaded_store.load_final_report("handle_request", file_path="src/server.c") == {
        "issues": [{"id": "restored"}]
    }
