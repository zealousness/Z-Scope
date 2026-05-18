import re
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import zscope.cli.cli as cli_module
import zscope.orchestration.user_config_inference as inference_module
from zscope.cli.cli import _resolve_user_config_workbook_path
from zscope.config.user_config_store import UserConfigStore
from zscope.config.user_config_workbook import SHEET_HEADERS, UserConfigWorkbook
from zscope.core.analyzer import Analyzer
from zscope.orchestration.user_config_inference import (
    filter_user_config_rows_with_llm,
    infer_user_config_rows,
)


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


def test_store_uses_user_config_xlsx_inside_config_directory(tmp_path: Path) -> None:
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


def test_store_rejects_database_config_paths(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        UserConfigStore(tmp_path / "user_config.db")


def test_infer_user_config_rejects_database_config_paths(tmp_path: Path) -> None:
    config = SimpleNamespace(
        analysis=SimpleNamespace(
            user_config_db=str(tmp_path / "user_config.db"),
            snapshot_dir=str(tmp_path),
        )
    )
    with pytest.raises(ValueError):
        _resolve_user_config_workbook_path(config)


def test_infer_user_config_defers_svf(monkeypatch, tmp_path: Path) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("project: {}\n", encoding="utf-8")
    captured = {}
    captured_filter = {}

    class FakeCodeIndex:
        def __init__(self, *args, **kwargs):
            captured["kwargs"] = kwargs

        def close(self):
            captured["closed"] = True

    def fake_load(_path: str):
        return SimpleNamespace(
            project=SimpleNamespace(
                project_root=tmp_path,
                compile_commands_path=None,
                source_root=tmp_path,
                include_paths=[],
                exclude_paths=[],
            ),
            indexing=SimpleNamespace(backend="unified"),
            analysis=SimpleNamespace(
                snapshot_dir=str(tmp_path / "snapshots"),
                user_config_db=str(tmp_path / "user_config.xlsx"),
                parallel_workers=3,
            ),
            llms={
                "default": SimpleNamespace(
                    api_key="test",
                    base_url="http://127.0.0.1:1/v1",
                    models=["fake-model"],
                    timeout=1,
                    max_retries=0,
                    max_tokens=512,
                )
            },
        )

    monkeypatch.setattr(cli_module, "CodeIndex", FakeCodeIndex)
    monkeypatch.setattr(cli_module.ConfigLoader, "load", fake_load)
    monkeypatch.setattr(
        inference_module,
        "infer_user_config_rows",
        lambda *args, **kwargs: {name: [] for name in SHEET_HEADERS},
    )
    def fake_filter_user_config_rows_with_llm(rows, *args, **kwargs):
        captured_filter["kwargs"] = kwargs
        return (rows, {
            "reviewed": 0,
            "kept": 0,
            "dropped": 0,
            "revised": 0,
            "unreviewed": 0,
            "errors": 0,
        })

    monkeypatch.setattr(
        inference_module,
        "filter_user_config_rows_with_llm",
        fake_filter_user_config_rows_with_llm,
    )

    result = CliRunner().invoke(
        cli_module.main,
        ["--config", str(config_path), "--infer-user-config"],
    )

    assert result.exit_code == 0, result.output
    assert captured["kwargs"]["wait_for_cpg"] is True
    assert captured["kwargs"]["defer_svf"] is True
    assert captured_filter["kwargs"]["max_workers"] == 3
    assert "3 worker(s)" in result.output
    assert captured["closed"] is True


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
    assert "resource_output=return" in resource["VOS_MemAlloc"]["description"]
    assert "size_arg=arg1" in resource["VOS_MemAlloc"]["description"]
    assert "resource_input=arg1" in resource["VOS_MemFree"]["description"]

    locks = {item["symbol_name"]: item for item in rows["lock"]}
    assert locks["VOS_Lock"]["pair"] == "VOS_Unlock"
    assert "lock_arg=arg1" in locks["VOS_Lock"]["description"]


def test_inference_filters_constant_like_names_and_does_not_promote_api_callers(tmp_path: Path) -> None:
    (tmp_path / "api.h").write_text(
        "\n".join(
            [
                "#define ANYXML_MALLOC(sz) malloc(sz)",
                "#define ANYXML_FREE(p) free(p)",
                "#define ANYXML_LOCK(m) pthread_mutex_lock(m)",
                "#define ANYXML_UNLOCK(m) pthread_mutex_unlock(m)",
                "#define ALLOCATOR_ERR(err) ((err) != 0)",
                "#define ALLOC_SIZE_MAX_1(sz) ((sz) > 1)",
            ]
        ),
        encoding="utf-8",
    )
    code_index = FakeCodeIndex(tmp_path)
    code_index.functions.update(
        {
            "ParseAnyxml": "void *ParseAnyxml(size_t n) { return ANYXML_MALLOC(n); }",
            "CleanupAnyxml": "void CleanupAnyxml(void *p) { ANYXML_FREE(p); }",
            "UseAnyxmlLock": "void UseAnyxmlLock(Mutex *m) { ANYXML_LOCK(m); ANYXML_UNLOCK(m); }",
        }
    )

    rows = infer_user_config_rows(code_index)

    resource = {item["symbol_name"]: item for item in rows["resource"]}
    assert resource["ANYXML_MALLOC"]["kind"] == "allocator"
    assert resource["ANYXML_MALLOC"]["pair"] == "ANYXML_FREE"
    assert resource["ANYXML_FREE"]["kind"] == "deallocator"
    assert "ParseAnyxml" not in resource
    assert "CleanupAnyxml" not in resource
    assert "ALLOCATOR_ERR" not in resource
    assert "ALLOC_SIZE_MAX_1" not in resource

    locks = {item["symbol_name"]: item for item in rows["lock"]}
    assert locks["ANYXML_LOCK"]["pair"] == "ANYXML_UNLOCK"
    assert "UseAnyxmlLock" not in locks


def test_inference_keeps_project_default_wrappers_with_specific_roles(tmp_path: Path) -> None:
    code_index = FakeCodeIndex(tmp_path)
    code_index.functions.update(
        {
            "_safe_malloc": "void *_safe_malloc(size_t size) { return malloc(size); }",
            "_safe_calloc": "void *_safe_calloc(size_t nmemb, size_t size) { return calloc(nmemb, size); }",
            "_safe_realloc": "void *_safe_realloc(void *ptr, size_t size) { return realloc(ptr, size); }",
        }
    )

    rows = infer_user_config_rows(code_index)
    resource = {item["symbol_name"]: item for item in rows["resource"]}

    assert resource["_safe_malloc"]["kind"] == "allocator"
    assert resource["_safe_calloc"]["kind"] == "calloc"
    assert resource["_safe_realloc"]["kind"] == "reallocator"
    assert "old_resource=arg1" in resource["_safe_realloc"]["description"]


def test_llm_filter_drops_noisy_candidates_and_records_generalized_pattern(tmp_path: Path) -> None:
    rows = {name: [] for name in SHEET_HEADERS}
    rows["resource"] = [
        {
            "symbol_name": "DDM_ALLOC",
            "kind": "allocator",
            "symbol_type": "macro",
            "pair": "DDM_FREE, ParseAnyxml",
            "description": "Project allocator macro.",
            "source": "inferred:macro",
            "confidence": "0.78",
            "notes": "",
        },
        {
            "symbol_name": "DDM_FREE",
            "kind": "deallocator",
            "symbol_type": "macro",
            "pair": "",
            "description": "Project free macro.",
            "source": "inferred:macro",
            "confidence": "0.78",
            "notes": "",
        },
        {
            "symbol_name": "ParseAnyxml",
            "kind": "allocator",
            "symbol_type": "function",
            "pair": "",
            "description": "Caller of DDM_ALLOC.",
            "source": "inferred:body",
            "confidence": "0.80",
            "notes": "",
        },
        {
            "symbol_name": "ALLOCATOR_ERR",
            "kind": "allocator",
            "symbol_type": "macro",
            "pair": "",
            "description": "Error helper.",
            "source": "inferred:name",
            "confidence": "0.72",
            "notes": "",
        },
    ]
    rows["lock"] = [
        {
            "symbol_name": "DDM_LOCK",
            "kind": "lock",
            "symbol_type": "macro",
            "pair": "DDM_UNLOCK, UseAnyxmlLock",
            "description": "Project lock macro.",
            "source": "inferred:macro",
            "confidence": "0.78",
            "notes": "",
        },
        {
            "symbol_name": "DDM_UNLOCK",
            "kind": "unlock",
            "symbol_type": "macro",
            "pair": "",
            "description": "Project unlock macro.",
            "source": "inferred:macro",
            "confidence": "0.78",
            "notes": "",
        },
        {
            "symbol_name": "UseAnyxmlLock",
            "kind": "lock",
            "symbol_type": "function",
            "pair": "",
            "description": "Caller of DDM_LOCK/DDM_UNLOCK.",
            "source": "inferred:body",
            "confidence": "0.80",
            "notes": "",
        },
    ]

    class FakeLLM:
        def chat_completion(self, messages, **kwargs):
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"items": ['
                                '{"id":"resource:0","action":"keep","confidence":0.93,'
                                '"description":"macro `DDM_ALLOC` allocates memory; resource_output=return; size_arg=arg1; failure_values=NULL.",'
                                '"generalized_pattern":"XXX_ALLOC","notes":"thin allocation macro"},'
                                '{"id":"resource:1","action":"keep","confidence":0.92,'
                                '"description":"macro `DDM_FREE` releases memory; resource_input=arg1.",'
                                '"generalized_pattern":"XXX_FREE","notes":"paired free macro"},'
                                '{"id":"resource:2","action":"drop","notes":"ordinary caller"},'
                                '{"id":"resource:3","action":"drop","notes":"constant/error helper"},'
                                '{"id":"lock:0","action":"keep","confidence":0.91,'
                                '"generalized_pattern":"XXX_LOCK","notes":"thin lock macro"},'
                                '{"id":"lock:1","action":"keep","confidence":0.91,'
                                '"generalized_pattern":"XXX_UNLOCK","notes":"thin unlock macro"},'
                                '{"id":"lock:2","action":"drop","notes":"ordinary lock caller"}'
                                "]}"
                            )
                        }
                    }
                ]
            }

    filtered, stats = filter_user_config_rows_with_llm(
        rows,
        FakeCodeIndex(tmp_path),
        FakeLLM(),
    )

    resource = {item["symbol_name"]: item for item in filtered["resource"]}
    assert set(resource) == {"DDM_ALLOC", "DDM_FREE"}
    assert resource["DDM_ALLOC"]["pair"] == "DDM_FREE"
    assert "resource_output=return" in resource["DDM_ALLOC"]["description"]
    assert "resource_input=arg1" in resource["DDM_FREE"]["description"]
    assert "pattern=XXX_ALLOC" in resource["DDM_ALLOC"]["notes"]
    assert resource["DDM_ALLOC"]["source"] == "inferred:macro, llm:screened"

    locks = {item["symbol_name"]: item for item in filtered["lock"]}
    assert set(locks) == {"DDM_LOCK", "DDM_UNLOCK"}
    assert locks["DDM_LOCK"]["pair"] == "DDM_UNLOCK"
    assert "lock_arg=review" in locks["DDM_LOCK"]["description"]
    assert "pattern=XXX_LOCK" in locks["DDM_LOCK"]["notes"]
    assert stats["dropped"] == 3
    assert stats["kept"] == 4


def test_llm_filter_uses_parallel_workers_for_batches(tmp_path: Path) -> None:
    rows = {name: [] for name in SHEET_HEADERS}
    for idx in range(4):
        rows["resource"].append(
            {
                "symbol_name": f"DDM_ALLOC_{idx}",
                "kind": "allocator",
                "symbol_type": "macro",
                "pair": "",
                "description": "Project allocator macro.",
                "source": "inferred:macro",
                "confidence": "0.78",
                "notes": "",
            }
        )

    class ParallelFakeLLM:
        def __init__(self):
            self.active = 0
            self.max_active = 0
            self.lock = threading.Lock()

        def chat_completion(self, messages, **kwargs):
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            try:
                time.sleep(0.05)
                content = messages[1]["content"]
                ids = list(dict.fromkeys(re.findall(r'"id":\s*"([^"]+)"', content)))
                return {
                    "choices": [
                        {
                            "message": {
                                "content": '{"items": ['
                                + ", ".join(
                                    f'{{"id":"{candidate_id}","action":"keep","notes":"ok"}}'
                                    for candidate_id in ids
                                )
                                + "]}"
                            }
                        }
                    ]
                }
            finally:
                with self.lock:
                    self.active -= 1

    llm = ParallelFakeLLM()
    filtered, stats = filter_user_config_rows_with_llm(
        rows,
        FakeCodeIndex(tmp_path),
        llm,
        batch_size=1,
        max_workers=3,
    )

    assert len(filtered["resource"]) == 4
    assert stats["kept"] == 4
    assert llm.max_active > 1


def test_llm_keep_decision_cannot_change_kind(tmp_path: Path) -> None:
    rows = {name: [] for name in SHEET_HEADERS}
    rows["resource"] = [
        {
            "symbol_name": "_safe_realloc",
            "kind": "reallocator",
            "symbol_type": "function",
            "pair": "SAFE_FREE",
            "description": "function `_safe_realloc` resizes memory. old_resource=arg1; resource_output=return; size_arg=arg2.",
            "source": "inferred:name",
            "confidence": "0.72",
            "notes": "",
        }
    ]

    class FakeLLM:
        def chat_completion(self, messages, **kwargs):
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"items": ['
                                '{"id":"resource:0","action":"keep","kind":"allocator",'
                                '"description":"Safe realloc wrapper. resource_output=return; old_resource=arg1; size_arg=arg2; failure_values=NULL."}'
                                "]}"
                            )
                        }
                    }
                ]
            }

    filtered, stats = filter_user_config_rows_with_llm(
        rows,
        FakeCodeIndex(tmp_path),
        FakeLLM(),
        batch_size=1,
        max_workers=1,
    )

    assert filtered["resource"][0]["kind"] == "reallocator"
    assert "old_resource=arg1" in filtered["resource"][0]["description"]
    assert stats["kept"] == 1


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
