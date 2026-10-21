"""LLM review tests for the extended roles, self-consistency, and ambiguity."""

from __future__ import annotations

import json
from pathlib import Path

from zscope.orchestration.user_config_inference import (
    classify_ambiguous_interfaces_with_llm,
    filter_user_config_rows_with_llm,
)


class FakeLLMClient:
    """Scripted chat_completion returning per-call decision payloads."""

    def __init__(self, *payloads):
        self._payloads = list(payloads)
        self.calls: list[list[dict]] = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append(messages)
        payload = self._payloads.pop(0) if self._payloads else {"items": []}
        return {"choices": [{"message": {"content": json.dumps(payload)}}]}

    def close_thread_session(self):
        pass


class FakeCodeIndex:
    source_root = Path(".")
    project_root = Path(".")

    def __init__(self, functions):
        self.functions = functions

    def list_functions(self, limit=0):
        return sorted(self.functions)

    def get_function_impl(self, name, max_lines=240, warn_missing=False):
        code = self.functions.get(name)
        if code is None:
            return None
        return {"func_name": name, "code": code, "file": "src/x.c", "signature": ""}


def _rows():
    return {
        "resource": [
            {
                "symbol_name": "file_open_wrap",
                "kind": "io_acquire",
                "symbol_type": "function",
                "pair": "file_close_wrap",
                "description": "opens a file handle",
                "source": "inferred:body",
                "confidence": "0.80",
                "notes": "",
            },
            {
                "symbol_name": "noisy_helper",
                "kind": "allocator",
                "symbol_type": "function",
                "pair": "",
                "description": "",
                "source": "inferred:caller_context",
                "confidence": "0.68",
                "notes": "",
            },
        ],
        "lock": [],
        "dispatcher": [],
        "module_lifecycle": [],
        "pointer_targets": [],
        "function_intents": [],
    }


def test_llm_review_keeps_io_acquire_and_rewrites_markers() -> None:
    llm = FakeLLMClient(
        {
            "items": [
                {
                    "id": "resource:0",
                    "action": "revise",
                    "kind": "io_acquire",
                    "pair": "file_close_wrap",
                    "description": "resource_output=return; failure_values=-1",
                    "confidence": 0.9,
                    "notes": "handle wrapper",
                },
                {"id": "resource:1", "action": "drop", "confidence": 0.9},
            ]
        }
    )
    code_index = FakeCodeIndex(
        {
            "file_open_wrap": "int file_open_wrap(const char* p){ return open(p, 0); }",
            "noisy_helper": "void* noisy_helper(size_t n){ return proj_alloc(n); }",
        }
    )
    filtered, stats = filter_user_config_rows_with_llm(_rows(), code_index, llm)

    assert stats["revised"] == 1
    assert stats["dropped"] == 1
    assert [row["symbol_name"] for row in filtered["resource"]] == ["file_open_wrap"]
    row = filtered["resource"][0]
    assert "resource_output=return" in row["description"]
    assert "failure_values=-1" in row["description"]
    assert row["pair"] == "file_close_wrap"


def test_llm_review_recheck_downgrades_conflicting_low_confidence_rows() -> None:
    llm = FakeLLMClient(
        # First round: keep the noisy helper with low confidence.
        {"items": [{"id": "resource:1", "action": "keep", "confidence": 0.55}]},
        # Second (independent) opinion: drop it.
        {"items": [{"id": "resource:1", "action": "drop", "confidence": 0.8}]},
    )
    code_index = FakeCodeIndex({"noisy_helper": "void* noisy_helper(size_t n){ return malloc(n); }"})
    filtered, stats = filter_user_config_rows_with_llm(_rows(), code_index, llm)

    assert stats["recheck"] == 1
    row = next(item for item in filtered["resource"] if item["symbol_name"] == "noisy_helper")
    assert row["confidence"] == "0.40"
    assert "llm:conflict" in row["notes"]
    assert "llm:needs_review" in row["source"]


def test_llm_review_recheck_keeps_consistent_rows_untouched() -> None:
    llm = FakeLLMClient(
        {"items": [{"id": "resource:1", "action": "keep", "confidence": 0.55}]},
        {"items": [{"id": "resource:1", "action": "keep", "confidence": 0.7}]},
    )
    code_index = FakeCodeIndex({"noisy_helper": "void* noisy_helper(size_t n){ return malloc(n); }"})
    filtered, stats = filter_user_config_rows_with_llm(_rows(), code_index, llm)

    assert stats["recheck"] == 1
    row = next(item for item in filtered["resource"] if item["symbol_name"] == "noisy_helper")
    assert row["confidence"] != "0.40"
    assert "llm:conflict" not in row["notes"]


def test_classify_ambiguous_interfaces_with_llm_builds_rows() -> None:
    llm = FakeLLMClient(
        {
            "items": [
                {
                    "id": "ambiguous:0",
                    "action": "keep",
                    "kind": "allocator",
                    "confidence": 0.85,
                    "description": "resource_output=return; size_arg=arg1",
                },
                {
                    "id": "ambiguous:1",
                    "action": "drop",
                },
            ]
        }
    )
    code_index = FakeCodeIndex(
        {
            "obtain_ctx": "void* obtain_ctx(size_t n){ return malloc(n); }",
            # free_pool is name-classifiable (deallocator) so the collector
            # must skip it and never ask the LLM about it.
            "free_pool": "void free_pool(void* p){ free(p); }",
            "unrelated": "int unrelated(int x){ return x; }",
        }
    )
    rows, stats = classify_ambiguous_interfaces_with_llm(code_index, llm)

    assert stats["collected"] == 1
    assert stats["classified"] == 1
    assert stats["dropped"] == 0
    assert [row["symbol_name"] for row in rows["resource"]] == ["obtain_ctx"]
    row = rows["resource"][0]
    assert row["kind"] == "allocator"
    assert row["source"] == "llm:classified"
    assert "resource_output=return" in row["description"]


def test_classify_ambiguous_interfaces_skips_invalid_kinds() -> None:
    llm = FakeLLMClient(
        {
            "items": [
                {"id": "ambiguous:0", "action": "keep", "kind": "wizard", "confidence": 0.99}
            ]
        }
    )
    code_index = FakeCodeIndex({"obtain_ctx": "void* obtain_ctx(size_t n){ return malloc(n); }"})
    rows, stats = classify_ambiguous_interfaces_with_llm(code_index, llm)

    assert stats["classified"] == 0
    assert stats["dropped"] == 1
    assert rows["resource"] == []
