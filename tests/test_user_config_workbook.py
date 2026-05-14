from pathlib import Path

from zscope.config.user_config_store import UserConfigStore
from zscope.config.user_config_workbook import SHEET_HEADERS, UserConfigWorkbook
from zscope.core.analyzer import Analyzer
from zscope.orchestration.user_config_inference import infer_user_config_rows


def test_workbook_store_round_trips_many_to_many_pairs(tmp_path: Path) -> None:
    workbook_path = tmp_path / "user_config.xlsx"
    store = UserConfigStore(workbook_path)

    store.upsert_external_function(
        "VOS_MemAlloc",
        "Project allocator",
        memory_behavior={"allocates": True},
    )
    store.upsert_paired_function("memory", "VOS_MemAlloc", "VOS_MemFree")
    store.upsert_paired_function("memory", "VOS_MemAlloc", "VOS_MemFree_F")
    store.upsert_pointer_target("ops->alloc", "*", ["VOS_MemAlloc"], "zip hooks")
    store.upsert_function_intent(
        "entry",
        caller_constraints={"must_hold_lock": False},
        concurrent_with=["worker"],
        notes="unit test",
    )
    store.add_false_positive_suppression("entry", "src/demo.c:1", "memory_leak")

    reloaded = UserConfigStore(workbook_path)
    assert reloaded.get_external_function("VOS_MemAlloc")["description"] == "Project allocator"
    pairs = reloaded.list_paired_functions("memory")
    assert {(item["acquire_func"], item["release_func"]) for item in pairs} == {
        ("VOS_MemAlloc", "VOS_MemFree"),
        ("VOS_MemAlloc", "VOS_MemFree_F"),
    }
    assert reloaded.get_pointer_targets("ops->alloc")[0]["target_functions"] == '["VOS_MemAlloc"]'
    assert "unit test" in reloaded.get_function_intent("entry")["intents"]
    assert reloaded.is_false_positive("entry", "src/demo.c:1", "memory_leak")
    assert workbook_path.with_suffix(".state.db").exists()


def test_store_uses_user_config_xlsx_inside_legacy_directory(tmp_path: Path) -> None:
    workbook = UserConfigWorkbook(tmp_path / "user_config.xlsx")
    workbook.write_rows(
        {
            "resource": [
                {
                    "symbol_name": "ZIP_ALLOC",
                    "kind": "allocator",
                    "symbol_type": "macro",
                    "description": "Macro allocator",
                }
            ]
        }
    )

    store = UserConfigStore(tmp_path)
    assert store.get_external_function("ZIP_ALLOC")["kind"] == "allocator"


class FakeCodeIndex:
    def __init__(self, root: Path):
        self.project_root = root
        self.source_root = root
        self.include_paths = []
        self.exclude_paths = []
        self.functions = {
            "VOS_MemAlloc": "void *VOS_MemAlloc(size_t n) { return malloc(n); }",
            "VOS_MemFree": "void VOS_MemFree(void *p) { free(p); }",
            "VOS_MemFree_F": "void VOS_MemFree_F(void *p) { free(p); }",
            "VOS_Lock": "void VOS_Lock(Mutex *m) { pthread_mutex_lock(m); }",
            "VOS_Unlock": "void VOS_Unlock(Mutex *m) { pthread_mutex_unlock(m); }",
            "MsgDispatch": (
                "int MsgDispatch(int msg) { switch (msg) { "
                "case ZIP_MSG_APPLY: return HandleApply(); "
                "case ZIP_MSG_RELEASE: return HandleRelease(); "
                "default: return -1; } }"
            ),
            "HandleApply": "int HandleApply(void) { g_nodes = VOS_MemAlloc(32); return g_nodes ? 0 : -1; }",
            "HandleRelease": "void HandleRelease(void) { VOS_MemFree(g_nodes); g_nodes = 0; }",
            "ZipInit": "int ZipInit(void) { g_nodes = VOS_MemAlloc(32); return g_nodes ? 0 : -1; }",
            "ZipFinit": "void ZipFinit(void) { VOS_MemFree(g_nodes); }",
        }

    def list_functions(self, pattern=None, limit=50):
        return list(self.functions)[:limit]

    def get_function_impl(self, name, max_lines=240, warn_missing=False):
        code = self.functions.get(name)
        if not code:
            return None
        return {"func_name": name, "code": code, "file": "demo.c", "start_line": 1, "end_line": 1}

    def _is_path_allowed(self, path: Path) -> bool:
        return True


def test_inference_detects_private_apis_macros_and_many_to_many_pairs(tmp_path: Path) -> None:
    (tmp_path / "api.h").write_text(
        "\n".join(
            [
                "#define ZIP_ALLOC(sz) VOS_MemAlloc(sz)",
                "#define ZIP_FREE(p) VOS_MemFree_F(p)",
            ]
        ),
        encoding="utf-8",
    )

    rows = infer_user_config_rows(FakeCodeIndex(tmp_path))
    resource = {item["symbol_name"]: item for item in rows["resource"]}
    assert resource["VOS_MemAlloc"]["kind"] == "allocator"
    assert resource["VOS_MemFree_F"]["kind"] == "deallocator"
    assert resource["ZIP_ALLOC"]["symbol_type"] == "macro"
    assert resource["VOS_MemAlloc"]["pair"] == "VOS_MemFree, VOS_MemFree_F"
    assert resource["ZIP_ALLOC"]["pair"] == "ZIP_FREE"
    assert "size/count params: n" in resource["VOS_MemAlloc"]["description"]

    locks = {item["symbol_name"]: item for item in rows["lock"]}
    assert locks["VOS_Lock"]["pair"] == "VOS_Unlock"


def test_inference_moves_dispatcher_and_handler_context_into_user_config(tmp_path: Path) -> None:
    rows = infer_user_config_rows(FakeCodeIndex(tmp_path))
    assert "HandleApply" not in {item["symbol_name"] for item in rows["resource"]}
    dispatch_rows = {
        (item["message_type"], item["handler_name"]): item
        for item in rows["dispatcher"]
    }
    assert dispatch_rows[("ZIP_MSG_APPLY", "HandleApply")]["handler_kind"] == "resource_acquire"
    assert dispatch_rows[("ZIP_MSG_APPLY", "HandleApply")]["pair"] == "HandleRelease"
    assert dispatch_rows[("ZIP_MSG_RELEASE", "HandleRelease")]["handler_kind"] == "resource_release"
    assert rows["function_intents"] == []


def test_inference_moves_init_finit_into_module_lifecycle_sheet(tmp_path: Path) -> None:
    rows = infer_user_config_rows(FakeCodeIndex(tmp_path))
    lifecycle = {item["symbol_name"]: item for item in rows["module_lifecycle"]}
    assert lifecycle["ZipInit"]["kind"] == "init"
    assert lifecycle["ZipInit"]["pair"] == "ZipFinit"
    assert lifecycle["ZipInit"]["needs_finit"] == "review"
    assert lifecycle["ZipInit"]["error_path_cleanup_required"] == "review"


def test_workbook_merge_marks_missing_inferred_rows_stale(tmp_path: Path) -> None:
    workbook = UserConfigWorkbook(tmp_path / "user_config.xlsx")
    generated = {name: [] for name in SHEET_HEADERS}
    generated["resource"] = [
        {
            "symbol_name": "OldAlloc",
            "kind": "allocator",
            "symbol_type": "function",
            "source": "inferred:name",
        }
    ]
    workbook.merge_generated(generated)

    empty_generated = {name: [] for name in SHEET_HEADERS}
    stats = workbook.merge_generated(empty_generated)
    rows = workbook.read_rows()["resource"]
    assert stats["removed"] == 1
    assert rows == []


def test_workbook_merge_removes_stale_inferred_function_intents(tmp_path: Path) -> None:
    workbook = UserConfigWorkbook(tmp_path / "user_config.xlsx")
    generated = {name: [] for name in SHEET_HEADERS}
    generated["function_intents"] = [
        {
            "symbol_name": "MsgDispatch",
            "file_path": "demo.c",
            "intents": "[inferred:dispatcher] dispatches messages.",
        }
    ]
    workbook.merge_generated(generated)

    empty_generated = {name: [] for name in SHEET_HEADERS}
    stats = workbook.merge_generated(empty_generated)
    assert stats["removed"] == 1
    assert workbook.read_rows()["function_intents"] == []


def test_workbook_merge_preserves_user_intents(tmp_path: Path) -> None:
    workbook = UserConfigWorkbook(tmp_path / "user_config.xlsx")
    workbook.write_rows(
        {
            "function_intents": [
                {
                    "symbol_name": "MsgDispatch",
                    "file_path": "demo.c",
                    "intents": "user-confirmed dispatcher notes",
                }
            ]
        }
    )
    generated = {name: [] for name in SHEET_HEADERS}
    generated["function_intents"] = [
        {
            "symbol_name": "MsgDispatch",
            "file_path": "demo.c",
            "intents": "[inferred:dispatcher] refreshed generated notes.",
        }
    ]

    workbook.merge_generated(generated)
    rows = workbook.read_rows()["function_intents"]
    assert rows[0]["intents"] == "user-confirmed dispatcher notes"


def test_relevant_context_filters_user_config_before_llm_context(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    store.upsert_paired_function("memory", "VOS_MemAlloc", "VOS_MemFree")
    store.upsert_paired_function("memory", "OtherAlloc", "OtherFree")
    store.upsert_external_function(
        "VOS_MemAlloc",
        "Project allocator",
        memory_behavior={"allocates": True},
    )
    store.upsert_external_function("OtherAlloc", "Unrelated allocator")

    dummy = type("DummyAnalyzer", (), {"user_config": store})()
    store.upsert_pointer_target("ops->alloc", "*/zip/*", ["VOS_MemAlloc"])
    workbook = store.workbook
    assert workbook is not None
    rows = workbook.read_rows()
    rows["dispatcher"] = [
        {
            "dispatcher_name": "ZipDispatch",
            "file_path": "src/zip/compress.c",
            "message_type": "ZIP_MSG_APPLY",
            "handler_name": "entry",
            "handler_kind": "resource_acquire",
            "resource": "zip node",
            "pair": "ZipRelease",
            "description": "zip dispatcher branch",
            "source": "user",
        },
        {
            "dispatcher_name": "OtherDispatch",
            "file_path": "src/other.c",
            "message_type": "OTHER_MSG",
            "handler_name": "OtherHandler",
            "handler_kind": "query",
            "resource": "",
            "source": "user",
        },
    ]
    rows["module_lifecycle"] = [
        {
            "symbol_name": "ZipInit",
            "file_path": "src/zip/compress.c",
            "kind": "init",
            "pair": "entry",
            "needs_finit": "yes",
            "error_path_cleanup_required": "no",
            "description": "zip init lifecycle",
            "source": "user",
        }
    ]
    workbook.write_rows(rows)

    context = Analyzer._relevant_user_config_context(
        dummy,
        "entry",
        "void entry(void) { void *p = VOS_MemAlloc(16); }",
        "src/zip/compress.c",
    )

    assert "VOS_MemAlloc" in context
    assert "VOS_MemFree" in context
    assert "ops->alloc" in context
    assert "ZipDispatch" in context
    assert "ZipInit" in context
    assert "OtherAlloc" not in context
    assert "OtherFree" not in context
    assert "OtherDispatch" not in context
