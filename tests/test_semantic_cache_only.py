import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.common.readonly import ReadonlyStateError, readonly_database
from zscope.snapshots.store import SnapshotStore
from zscope.tools.registry import build_tool_registry
from zscope.tools.runtime import ToolsRuntime


def fixture(root):
    file = root / "demo.c"
    file.write_text("int run(void) { return 1; }\n", encoding="utf-8")
    store = SnapshotStore(root / ".zscope_snapshots")
    snapshot = {
        "index_name": "run",
        "func_name": "run",
        "file_path": "demo.c",
        "start_line": 1,
        "end_line": 1,
        "referenced_globals": [],
        "referenced_macros": [],
        "referenced_types": [],
        "interface_contracts": [],
        "suspicious_points": [{"verdict": "NEVER_EXPOSE"}],
    }
    filename = store.save_snapshot("run", snapshot, file.read_text())
    index = SimpleNamespace(
        project_root=root,
        _index_epoch=1,
        _function_index={
            "run": {
                "name": "run",
                "file": "demo.c",
                "signature": "int run(void)",
                "start_line": 1,
                "end_line": 1,
            }
        },
    )
    return store, index, filename


def state(root):
    return {
        p.relative_to(root).as_posix(): (
            p.stat().st_mtime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest(),
        )
        for p in root.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize(
    "case,expected",
    [
        ("unchanged", "unverifiable"),
        ("missing", "missing"),
        ("stale", "stale"),
        ("corrupt", "corrupt"),
        ("header", "unverifiable"),
        ("build", "unverifiable"),
        ("contract", "unverifiable"),
        ("document", "unverifiable"),
        ("spec", "unverifiable"),
    ],
)
def test_cache_only_never_refreshes_or_writes(tmp_path, monkeypatch, case, expected):
    store, index, filename = fixture(tmp_path)
    rt = ToolsRuntime(index, store, snapshot_resolver=lambda *a: pytest.fail("resolver invoked"))
    found = rt.execute_tool("search_code", {"query": "run"})
    symbol = found["data"]["symbols"][0]["symbol_id"]
    if case == "missing":
        store.delete_snapshot("run")
    elif case == "stale":
        (tmp_path / "demo.c").write_text("int run(void) { return 2; }\n")
    elif case == "corrupt":
        (store.snapshot_dir / filename).write_text("{broken")
    elif case in {"header", "build", "contract", "document", "spec"}:
        (
            tmp_path
            / {
                "header": "api.h",
                "build": "compile_commands.json",
                "contract": "manual-contract.yaml",
                "document": "design.md",
                "spec": "runtime-spec.yaml",
            }[case]
        ).write_text("changed")
    before = state(tmp_path)

    def prohibited(*a, **kw):
        pytest.fail("side effect or lazy builder invoked")

    monkeypatch.setattr("zscope.tools.semantic_context.build_semantic_model_input", prohibited)
    monkeypatch.setattr(store, "load_snapshot", prohibited)
    monkeypatch.setattr(store, "needs_refresh", prohibited)
    monkeypatch.setattr(store, "save_snapshot", prohibited)
    monkeypatch.setattr("zscope.framework.llm_client.LLMClient.chat_completion", prohibited)
    monkeypatch.setattr("zscope.retrieval.code_index.CodeIndex.__init__", prohibited)
    monkeypatch.setattr("zscope.retrieval.knowledge_db.KnowledgeDB.__init__", prohibited)
    monkeypatch.setattr("zscope.config.user_config_store.UserConfigStore.__init__", prohibited)
    monkeypatch.setattr("zscope.snapshots.store.SnapshotStore.__init__", prohibited)
    monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor.submit", prohibited)
    result = rt.execute_tool(
        "get_semantic_context",
        {"kind": "function", "symbol_id": symbol, "refresh_policy": "cache_only"},
    )
    assert result["data"]["snapshot"]["status"] == expected
    assert result["data"]["snapshot"]["rebuilt"] is False
    assert result["data"]["snapshot"]["persisted"] is False
    assert result["data"]["contract"] == {}
    assert state(tmp_path) == before


def test_cache_only_does_not_build_catalog(tmp_path, monkeypatch):
    store, index, _ = fixture(tmp_path)
    tools = build_tool_registry(index, store)
    symbol = tools["search_code"].execute({"query": "run"})["data"]["symbols"][0]["symbol_id"]
    semantic = tools["get_semantic_context"]
    semantic.catalog._snapshot = None
    monkeypatch.setattr(semantic.catalog, "snapshot", lambda: pytest.fail("lazy catalog"))
    assert (
        semantic.execute({"kind": "function", "symbol_id": symbol, "refresh_policy": "cache_only"})[
            "status"
        ]
        == "partial"
    )


def test_profile_annotations_and_explicit_refresh_rejection(tmp_path):
    store, index, _ = fixture(tmp_path)
    normal = build_tool_registry(index, store)
    blind = build_tool_registry(index, store, access_profile="candidate_blind")
    assert normal["get_semantic_context"].get_contract().annotations["readOnlyHint"] is False
    assert blind["get_semantic_context"].get_contract().annotations["readOnlyHint"] is True
    assert (
        blind["get_semantic_context"].execute(
            {"kind": "summary", "refresh_policy": "ensure_current"}
        )["status"]
        == "forbidden"
    )
    symbol = blind["search_code"].execute({"query": "run"})["data"]["symbols"][0]["symbol_id"]
    result = blind["get_semantic_context"].execute({"kind": "function", "symbol_id": symbol})
    assert "NEVER_EXPOSE" not in str(result)
    assert result["data"]["snapshot"]["data"] is None
    assert (
        normal["get_semantic_context"].validate_arguments(
            {"kind": "summary", "refresh_policy": "ensure_current"}
        )["status"]
        == "invalid_request"
    )


def test_blind_map_uses_typed_fields_and_never_echoes_nested_conclusions(tmp_path):
    store, index, _ = fixture(tmp_path)
    with sqlite3.connect(store.snapshot_dir / "security_map.db") as conn:
        conn.execute("CREATE TABLE security_maps (payload_json TEXT, updated_at TEXT)")
        conn.execute(
            "INSERT INTO security_maps VALUES (?, ?)",
            (
                json.dumps(
                    {
                        "claims": [
                            {
                                "claim_id": "ok",
                                "origin": "program",
                                "evidence_refs": [{"findings": "NEVER_EXPOSE"}],
                                "value": {"verdict": "NEVER_EXPOSE"},
                            },
                            {"claim_id": "NEVER_EXPOSE", "origin": "llm"},
                        ],
                        "audit_units": [
                            {
                                "unit_id": "u",
                                "member_functions": ["run"],
                                "metadata": {"findings": "NEVER_EXPOSE"},
                            }
                        ],
                        "functions": [],
                        "revision": {"verdict": "NEVER_EXPOSE"},
                    }
                ),
                "now",
            ),
        )
    tools = build_tool_registry(index, store, access_profile="candidate_blind")
    before = state(tmp_path)
    for kind in ("claim", "audit_unit", "summary"):
        result = tools["get_semantic_context"].execute({"kind": kind})
        assert result["status"] == "partial"
        assert "NEVER_EXPOSE" not in str(result)
    assert state(tmp_path) == before


def test_readonly_sqlite_rejects_active_wal_and_missing_without_creation(tmp_path):
    with pytest.raises(FileNotFoundError):
        with readonly_database(tmp_path, "absent.db"):
            pass
    assert list(tmp_path.iterdir()) == []
    db = sqlite3.connect(tmp_path / "active.db")
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE t (value TEXT)")
        db.commit()
        before = state(tmp_path)
        with pytest.raises(ReadonlyStateError, match="active_wal"):
            with readonly_database(tmp_path, "active.db"):
                pass
        assert state(tmp_path) == before
    finally:
        db.close()
    before = state(tmp_path)
    with readonly_database(tmp_path, "active.db") as conn:
        assert conn.execute("SELECT * FROM t").fetchall() == []
        with pytest.raises(sqlite3.OperationalError):
            conn.execute('INSERT INTO t VALUES ("no")')
    assert state(tmp_path) == before


def test_nested_state_symlink_is_not_a_read_boundary(tmp_path):
    store, index, _ = fixture(tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    store.snapshot_dir.rename(real / "snapshots")
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    store.snapshot_dir = tmp_path / "link" / "snapshots"
    rt = ToolsRuntime(index, store, access_profile="candidate_blind")
    symbol = rt.execute_tool("search_code", {"query": "run"})["data"]["symbols"][0]["symbol_id"]
    result = rt.execute_tool("get_semantic_context", {"kind": "function", "symbol_id": symbol})
    assert result["data"]["snapshot"]["status"] == "unavailable"
    assert "NEVER_EXPOSE" not in str(result)
