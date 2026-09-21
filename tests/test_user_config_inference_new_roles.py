"""Tests for user_config inference of the extended risk-interface roles."""

from __future__ import annotations

import json
from pathlib import Path

from zscope.orchestration.user_config_inference import (
    classify_single_interface_with_llm,
    collect_ambiguous_interface_candidates,
    infer_user_config_rows,
)


IMPLS = {
    "_safe_malloc": {
        "code": "void* _safe_malloc(size_t s){ void* p = malloc(s); if(!p && s>0) return NULL; return p; }",
        "callees": ["malloc"],
        "signature": "",
    },
    "_safe_free": {"code": "void _safe_free(void* p){ free(p); }", "callees": ["free"], "signature": ""},
    "get_buffer": {"code": "void* get_buffer(size_t n){ return malloc(n); }", "callees": ["malloc"], "signature": ""},
    "put_buffer": {"code": "void put_buffer(void* p){ free(p); }", "callees": ["free"], "signature": ""},
    "mutex_enter": {
        "code": "void mutex_enter(unsigned* l){ pthread_mutex_lock((pthread_mutex_t*)l); }",
        "callees": ["pthread_mutex_lock"],
        "signature": "",
    },
    "mutex_exit": {
        "code": "void mutex_exit(unsigned* l){ pthread_mutex_unlock((pthread_mutex_t*)l); }",
        "callees": ["pthread_mutex_unlock"],
        "signature": "",
    },
    "file_open_wrap": {
        "code": "int file_open_wrap(const char* p, int f){ return open(p, f); }",
        "callees": ["open"],
        "signature": "",
    },
    "file_close_wrap": {
        "code": "void file_close_wrap(int fd){ close(fd); }",
        "callees": ["close"],
        "signature": "",
    },
    "net_send_wrap": {
        "code": "int net_send_wrap(int fd, const void* b, size_t n){ return (int)send(fd, b, n, 0); }",
        "callees": ["send"],
        "signature": "",
    },
    "net_recv_wrap": {
        "code": "int net_recv_wrap(int fd, void* b, size_t n){ return (int)recv(fd, b, n, 0); }",
        "callees": ["recv"],
        "signature": "",
    },
    "audit_log": {
        "code": (
            "void audit_log(const char* fmt, ...){ va_list a; va_start(a, fmt); "
            "vfprintf(stderr, fmt, a); va_end(a); }"
        ),
        "callees": ["vfprintf"],
        "signature": "",
    },
    "cb_register": {
        "code": "void cb_register(int (*fn)(void*), void* a){ worker_subscribe(fn); }",
        "callees": ["worker_subscribe"],
        "signature": "",
    },
    "helper_unused": {"code": "int helper_unused(int x){ return x + 1; }", "callees": [], "signature": ""},
    # Ambiguous: calls a standard risk API but has no name hint at all.
    "obtain_ctx": {
        "code": "void* obtain_ctx(size_t n){ return malloc(n); }",
        "callees": ["malloc"],
        "signature": "",
    },
    "plain_business": {
        "code": "int plain_business(int x){ return x * 2; }",
        "callees": [],
        "signature": "",
    },
}


class FakeCodeIndex:
    def __init__(self, root: Path):
        self.source_root = root
        self.project_root = root

    def list_functions(self, limit=0):
        return sorted(IMPLS)

    def get_function_impl(self, name, max_lines=240, warn_missing=False):
        impl = IMPLS.get(name)
        if not impl:
            return None
        return {"func_name": name, **impl, "file": "src/demo.c", "start_line": 1, "end_line": 1}


class FakeLLM:
    def __init__(self, decisions):
        self._decisions = decisions
        self.calls = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append(messages)
        content = json.dumps({"items": self._decisions}, ensure_ascii=False)
        return {"choices": [{"message": {"content": content}}]}


def test_infer_user_config_rows_covers_extended_roles(tmp_path) -> None:
    rows = infer_user_config_rows(FakeCodeIndex(tmp_path))
    resource = {row["symbol_name"]: row for row in rows["resource"]}
    lock = {row["symbol_name"]: row for row in rows["lock"]}

    assert resource["get_buffer"]["kind"] == "allocator"
    assert resource["get_buffer"]["pair"] == "put_buffer"
    assert resource["put_buffer"]["kind"] == "deallocator"
    assert resource["file_open_wrap"]["kind"] == "io_acquire"
    assert resource["file_open_wrap"]["pair"] == "file_close_wrap"
    assert resource["file_close_wrap"]["kind"] == "io_release"
    assert resource["net_send_wrap"]["kind"] == "send_sink"
    assert resource["net_recv_wrap"]["kind"] == "recv_source"
    assert resource["audit_log"]["kind"] == "format_sink"
    assert resource["cb_register"]["kind"] == "callback_register"
    assert lock["mutex_enter"]["kind"] == "lock"
    assert lock["mutex_enter"]["pair"] == "mutex_exit"
    assert lock["mutex_exit"]["kind"] == "unlock"
    assert "plain_business" not in resource
    assert "obtain_ctx" not in resource  # unhinted bodies stay out of the cheap pass


def test_collect_ambiguous_interface_candidates_prefers_unhinted_risk_bodies(tmp_path) -> None:
    rows = infer_user_config_rows(FakeCodeIndex(tmp_path))
    known = {
        str(row.get("symbol_name") or "")
        for sheet in ("resource", "lock")
        for row in rows[sheet]
    }
    ambiguous = collect_ambiguous_interface_candidates(
        FakeCodeIndex(tmp_path), exclude=known, max_candidates=50
    )
    names = [item["symbol"] for item in ambiguous]
    assert "obtain_ctx" in names  # calls malloc but has no name hint
    assert "plain_business" not in names
    assert not known & set(names)


def test_classify_single_interface_with_llm_parses_kind() -> None:
    llm = FakeLLM(
        [
            {
                "id": "single:0",
                "action": "keep",
                "kind": "allocator",
                "confidence": 0.9,
                "description": "resource_output=return",
            }
        ]
    )
    decision = classify_single_interface_with_llm(
        llm,
        "obtain_ctx",
        {"code_excerpt": "void* obtain_ctx(size_t n){ return malloc(n); }"},
    )
    assert decision == {
        "kind": "allocator",
        "confidence": 0.9,
        "description": "resource_output=return",
    }
    assert llm.calls and "obtain_ctx" in llm.calls[0][1]["content"]


def test_classify_single_interface_with_llm_rejects_invalid_kinds() -> None:
    llm = FakeLLM([{"id": "single:0", "action": "keep", "kind": "wizard"}])
    assert classify_single_interface_with_llm(llm, "obtain_ctx", {"code_excerpt": "x"}) is None

    llm_drop = FakeLLM([{"id": "single:0", "action": "drop", "kind": "allocator"}])
    assert classify_single_interface_with_llm(llm_drop, "obtain_ctx", {"code_excerpt": "x"}) is None


def test_risk_api_wrappers_fixture_baseline_is_intact() -> None:
    """Guard the fixture that documents the 12-interface inference baseline."""

    fixture = Path(__file__).parent / "fixtures" / "risk_api_wrappers"
    header = (fixture / "include" / "wrap_api.h").read_text(encoding="utf-8")
    readme = (fixture / "README.md").read_text(encoding="utf-8")

    for symbol in (
        "_safe_malloc",
        "get_buffer",
        "put_buffer",
        "mutex_enter",
        "mutex_exit",
        "file_open_wrap",
        "file_close_wrap",
        "net_send_wrap",
        "net_recv_wrap",
        "audit_log",
        "cb_register",
    ):
        assert symbol in header, f"{symbol} missing from wrap_api.h"
        assert symbol in readme, f"{symbol} missing from fixture README baseline"
    for defect in (
        "memory_leak",
        "missing_unlock",
        "held_lock_callback",
        "fd_leak",
        "signed_unsigned",
        "format_string",
    ):
        assert defect in readme, f"expected defect {defect} missing from README baseline"
