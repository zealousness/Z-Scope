"""Tests for UserConfigStore CRUD operations."""

import json
import tempfile
from pathlib import Path

import pytest

from zscope.config.user_config_store import UserConfigStore


@pytest.fixture
def store(tmp_path):
    return UserConfigStore(tmp_path)


# ── External Functions ──

class TestExternalFunctions:
    def test_upsert_and_get(self, store):
        store.upsert_external_function(
            "ext_alloc", "描述: 分配内存并返回指针",
            library="libext",
            memory_behavior={"allocates": True},
            return_semantics="NULL=失败"
        )
        result = store.get_external_function("ext_alloc")
        assert result is not None
        assert result["func_name"] == "ext_alloc"
        assert result["library"] == "libext"
        assert json.loads(result["memory_behavior"])["allocates"] is True

    def test_get_nonexistent(self, store):
        assert store.get_external_function("no_such") is None

    def test_list(self, store):
        store.upsert_external_function("func_a", "desc a")
        store.upsert_external_function("func_b", "desc b")
        items = store.list_external_functions()
        assert len(items) == 2

    def test_delete(self, store):
        store.upsert_external_function("to_del", "desc")
        store.delete_external_function("to_del")
        assert store.get_external_function("to_del") is None

    def test_upsert_overwrites(self, store):
        store.upsert_external_function("f", "old")
        store.upsert_external_function("f", "new")
        assert store.get_external_function("f")["description"] == "new"


# ── Paired Functions ──

class TestPairedFunctions:
    def test_upsert_and_list(self, store):
        store.upsert_paired_function("memory", "my_malloc", "my_free", "自定义内存分配")
        items = store.list_paired_functions()
        assert len(items) == 1
        assert items[0]["acquire_func"] == "my_malloc"

    def test_list_by_category(self, store):
        store.upsert_paired_function("memory", "alloc", "dealloc")
        store.upsert_paired_function("lock", "lock", "unlock")
        assert len(store.list_paired_functions("memory")) == 1
        assert len(store.list_paired_functions("lock")) == 1

    def test_delete(self, store):
        store.upsert_paired_function("memory", "a", "b")
        items = store.list_paired_functions()
        store.delete_paired_function(items[0]["id"])
        assert len(store.list_paired_functions()) == 0


# ── False Positives ──

class TestFalsePositives:
    def test_add_and_check(self, store):
        store.add_false_positive("func_a", "file.c:10", "memory_leak", "非问题")
        assert store.is_false_positive("func_a", "file.c:10", "memory_leak")
        assert not store.is_false_positive("func_a", "file.c:10", "other")

    def test_list_and_delete(self, store):
        store.add_false_positive("f", "loc", "cat")
        items = store.list_false_positives()
        assert len(items) == 1
        store.delete_false_positive(items[0]["id"])
        assert len(store.list_false_positives()) == 0


# ── Config Warnings ──

class TestConfigWarnings:
    def test_add_and_list(self, store):
        store.add_config_warning("missing_external_func", "foo", "未找到foo")
        warnings = store.list_config_warnings()
        assert len(warnings) == 1
        assert warnings[0]["warning_type"] == "missing_external_func"

    def test_clear(self, store):
        store.add_config_warning("t", "c", "m")
        store.clear_config_warnings()
        assert len(store.list_config_warnings()) == 0


# ── Context Injection Helpers ──

class TestContextHelpers:
    def test_paired_functions_context(self, store):
        store.upsert_paired_function("memory", "my_alloc", "my_free", "自定义")
        ctx = store.get_paired_functions_context()
        assert "my_alloc" in ctx
        assert "my_free" in ctx
        assert "memory" in ctx

    def test_paired_functions_context_empty(self, store):
        assert store.get_paired_functions_context() == ""

    def test_function_intent_context(self, store):
        store.upsert_function_intent(
            "safe_func", "",
            caller_constraints={"pointer_valid": True},
            concurrency_group="task_a",
            concurrent_with=["task_b"],
            notes="不会并发调用"
        )
        ctx = store.get_function_intent_context("safe_func")
        assert "safe_func" in ctx
        assert "task_a" in ctx
        assert "task_b" in ctx

    def test_function_intent_context_empty(self, store):
        assert store.get_function_intent_context("no_such") == ""
