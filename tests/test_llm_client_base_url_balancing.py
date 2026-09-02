import json
import errno
import ssl
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from zscope.config.config import ConfigLoader
from zscope.framework import llm_client as llm_client_module
from zscope.framework.llm_client import LLMClient, ProviderFailureError
from zscope.framework.llm_usage import (
    P6_BALANCED_ADMISSION_MAX_TOKENS,
    ScanTokenUsageLedger,
)


class _FakeResponse:
    def __init__(
        self,
        status_code=200,
        text="ok",
        headers=None,
        model="unit-model",
        finish_reason="stop",
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.model = model
        self.finish_reason = finish_reason
        self.closed = False

    def iter_lines(self):
        yield (
            "data: "
            + json.dumps(
                {
                    "model": self.model,
                    "choices": [
                        {
                            "delta": {"content": "ok"},
                            "finish_reason": self.finish_reason,
                        }
                    ],
                }
            )
        ).encode("utf-8")
        yield b"data: [DONE]"

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _isolate_process_capacity_state(monkeypatch) -> None:
    monkeypatch.setattr(llm_client_module, "_ENDPOINT_CAPACITY_STATES", {})
    monkeypatch.setattr(
        llm_client_module,
        "_GLOBAL_CAPACITY_STATE",
        llm_client_module._GlobalCapacityState(),
    )


def test_llm_client_balances_base_urls_by_recent_load(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url=["http://one.example/v1", "http://two.example/v1"],
        models=["unit-model"],
    )
    called_urls = []

    def fake_post(url, **kwargs):
        called_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr(client.session, "post", fake_post)

    for _ in range(3):
        response = client.chat_completion([{"role": "user", "content": "hello"}])
        assert response["choices"][0]["message"]["content"] == "ok"

    assert called_urls == [
        "http://one.example/v1/chat/completions",
        "http://two.example/v1/chat/completions",
        "http://one.example/v1/chat/completions",
    ]


def test_streaming_requests_explicitly_request_terminal_provider_usage(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://usage.example/v1",
        models=["unit-model"],
    )
    payloads = []
    redirect_flags = []

    def fake_post(_url, **kwargs):
        payloads.append(kwargs["json"])
        redirect_flags.append(kwargs["allow_redirects"])
        return _FakeResponse()

    monkeypatch.setattr(client.session, "post", fake_post)

    client.chat_completion([{"role": "user", "content": "hello"}])

    assert payloads[0]["stream"] is True
    assert payloads[0]["stream_options"] == {"include_usage": True}
    assert redirect_flags == [False]


class _StrictUsageResponse(_FakeResponse):
    def __init__(self, *, model="unit-model", usage=None):
        super().__init__(model=model)
        self.usage = usage

    def iter_lines(self):
        yield (
            "data: "
            + json.dumps(
                {
                    "model": self.model,
                    "usage": self.usage,
                    "choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}],
                }
            )
        ).encode("utf-8")
        yield b"data: [DONE]"


class _LegacyFunctionCallResponse(_FakeResponse):
    def iter_lines(self):
        chunks = [
            {
                "model": self.model,
                "choices": [
                    {
                        "delta": {
                            "role": "assistant",
                            "function_call": {"name": "emit_"},
                        },
                        "finish_reason": None,
                    }
                ],
            },
            {
                "model": self.model,
                "choices": [
                    {
                        "delta": {"function_call": {"name": "result"}},
                        "finish_reason": None,
                    }
                ],
            },
            {
                "model": self.model,
                "choices": [
                    {
                        "delta": {"function_call": {"arguments": '{"value":'}},
                        "finish_reason": None,
                    }
                ],
            },
            {
                "model": self.model,
                "choices": [
                    {
                        "delta": {"function_call": {"arguments": "7}"}},
                        "finish_reason": "function_call",
                    }
                ],
            },
            {
                "model": self.model,
                "usage": {
                    "prompt_tokens": 17,
                    "completion_tokens": 5,
                    "total_tokens": 22,
                },
                "choices": [],
            },
        ]
        for chunk in chunks:
            yield ("data: " + json.dumps(chunk)).encode("utf-8")
        yield b"data: [DONE]"


class _ScriptedToolCallResponse(_FakeResponse):
    def __init__(self, chunks):
        super().__init__()
        self.chunks = chunks

    def iter_lines(self):
        for chunk in self.chunks:
            value = dict(chunk)
            value.setdefault("model", self.model)
            yield ("data: " + json.dumps(value)).encode("utf-8")
        yield b"data: [DONE]"


def test_strict_sse_normalizes_fragmented_legacy_function_call_and_accounts_once(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    client = LLMClient(
        api_key="test",
        base_url="https://strict-legacy.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    payloads = []

    def fake_post(_url, **kwargs):
        payloads.append(kwargs["json"])
        return _LegacyFunctionCallResponse()

    monkeypatch.setattr(client.session, "post", fake_post)
    response = client.chat_completion(
        [{"role": "user", "content": "return the result"}],
        tools=[{"type": "function", "function": {"name": "emit_result"}}],
        tool_choice={"type": "function", "function": {"name": "emit_result"}},
    )

    message = response["choices"][0]["message"]
    assert "function_call" not in message
    assert len(message["tool_calls"]) == 1
    assert message["tool_calls"][0]["function"] == {
        "name": "emit_result",
        "arguments": '{"value":7}',
    }
    assert payloads[0]["parallel_tool_calls"] is False
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["tool_call_count"] == 1


def test_strict_sse_assembles_one_complete_modern_tool_call(monkeypatch) -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    client = LLMClient(
        api_key="test",
        base_url="https://strict-modern.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    response = _ScriptedToolCallResponse(
        [
            {
                "choices": [
                    {
                        "delta": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_lookup",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": '{"name":',
                                    },
                                }
                            ],
                        },
                        "finish_reason": None,
                    }
                ]
            },
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {"arguments": '"demo"}'},
                                }
                            ]
                        },
                        "finish_reason": "tool_calls",
                    }
                ]
            },
            {
                "usage": {
                    "prompt_tokens": 11,
                    "completion_tokens": 4,
                    "total_tokens": 15,
                },
                "choices": [],
            },
        ]
    )
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    result = client.chat_completion(
        [{"role": "user", "content": "lookup"}],
        tools=[{"type": "function", "function": {"name": "lookup"}}],
    )

    assert result["choices"][0]["message"]["tool_calls"] == [
        {
            "index": 0,
            "id": "call_lookup",
            "type": "function",
            "function": {"name": "lookup", "arguments": '{"name":"demo"}'},
        }
    ]
    assert ledger.snapshot(include_events=True)["events"][0]["tool_call_count"] == 1


def _invalid_modern_tool_chunks(case: str):
    first_call = {
        "index": 0,
        "id": "call_stable",
        "type": "function",
        "function": {"name": "lookup", "arguments": ""},
    }
    if case == "missing-function":
        return _tool_delta_chunks([{"index": 0, "id": "call_missing"}])
    if case == "empty-tool-batch":
        return _tool_delta_chunks([])
    if case == "duplicate-argument-key":
        first_call["function"][
            "arguments"
        ] = '{"PRIVATE_DUPLICATE_KEY":1,"PRIVATE_DUPLICATE_KEY":2}'
        return _tool_delta_chunks([first_call])
    if case == "nonfinite-argument":
        first_call["function"]["arguments"] = '{"PRIVATE_NONFINITE":NaN}'
        return _tool_delta_chunks([first_call])
    if case == "multiple":
        first_call["function"]["arguments"] = "{}"
        second = {
            "index": 1,
            "id": "PRIVATE_SECOND_CALL",
            "type": "function",
            "function": {"name": "lookup", "arguments": "{}"},
        }
        return _tool_delta_chunks([first_call, second])

    second_call = {"index": 0, "function": {"arguments": "{}"}}
    if case == "id-drift":
        second_call["id"] = "PRIVATE_DRIFTING_CALL_ID"
    elif case == "function-name-drift":
        second_call["function"]["name"] = "PRIVATE_DRIFTING_FUNCTION_NAME"
    elif case == "index-drift":
        second_call.update({"index": 1, "id": "call_stable", "type": "function"})
        second_call["function"]["name"] = "lookup"
    else:
        raise AssertionError(f"unknown case: {case}")
    return [
        *_tool_delta_chunks([first_call], finish_reason=None),
        *_tool_delta_chunks([second_call]),
    ]


def _tool_delta_chunks(tool_calls, *, finish_reason="tool_calls"):
    return [
        {
            "choices": [
                {
                    "delta": {"tool_calls": tool_calls},
                    "finish_reason": finish_reason,
                }
            ]
        }
    ]


@pytest.mark.parametrize(
    "case",
    [
        "missing-function",
        "id-drift",
        "function-name-drift",
        "index-drift",
        "duplicate-argument-key",
        "nonfinite-argument",
        "empty-tool-batch",
        "multiple",
    ],
)
def test_strict_sse_rejects_incomplete_or_drifting_modern_tool_calls(
    monkeypatch,
    caplog,
    case,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://strict-invalid-modern.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
    )
    response = _ScriptedToolCallResponse(_invalid_modern_tool_chunks(case))
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "lookup"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert str(raised.value) == ProviderFailureError.MESSAGE
    assert "PRIVATE_" not in caplog.text


def test_strict_curl_normalizes_legacy_function_call_and_disables_parallel_tools(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    client = LLMClient(
        api_key="test",
        base_url="https://strict-curl-legacy.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    client._transport = "curl"
    captured = {}
    body = {
        "model": "unit-model",
        "choices": [
            {
                "finish_reason": "function_call",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "function_call": {
                        "name": "emit_result",
                        "arguments": '{"value":7}',
                    },
                },
            }
        ],
        "usage": {"prompt_tokens": 17, "completion_tokens": 5, "total_tokens": 22},
    }

    class Completed:
        returncode = 0
        stderr = b""
        stdout = (json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode("utf-8")

    def fake_run(_command, **kwargs):
        captured.update(json.loads(kwargs["input"].decode("utf-8")))
        return Completed()

    monkeypatch.setattr(client, "_curl_executable", lambda: "curl")
    monkeypatch.setattr(llm_client_module.subprocess, "run", fake_run)
    response = client.chat_completion(
        [{"role": "user", "content": "return the result"}],
        tools=[{"type": "function", "function": {"name": "emit_result"}}],
        tool_choice={"type": "function", "function": {"name": "emit_result"}},
    )

    message = response["choices"][0]["message"]
    assert "function_call" not in message
    assert len(message["tool_calls"]) == 1
    assert captured["parallel_tool_calls"] is False
    assert captured["stream"] is False
    assert ledger.snapshot(include_events=True)["events"][0]["tool_call_count"] == 1


def test_strict_curl_accepts_one_complete_modern_tool_call(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://strict-curl-modern.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
    )
    client._transport = "curl"
    body = {
        "model": "unit-model",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "function_call": None,
                    "tool_calls": [
                        {
                            "id": "call_lookup",
                            "type": "function",
                            "function": {
                                "name": "lookup",
                                "arguments": '{"name":"demo"}',
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
    }

    class Completed:
        returncode = 0
        stderr = b""
        stdout = (json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode("utf-8")

    monkeypatch.setattr(client, "_curl_executable", lambda: "curl")
    monkeypatch.setattr(
        llm_client_module.subprocess,
        "run",
        lambda *_args, **_kwargs: Completed(),
    )

    response = client.chat_completion([{"role": "user", "content": "lookup"}])

    assert (
        response["choices"][0]["message"]["tool_calls"]
        == body["choices"][0]["message"]["tool_calls"]
    )


@pytest.mark.parametrize(
    "tool_calls",
    [
        [
            {
                "type": "function",
                "function": {"name": "lookup", "arguments": "{}"},
            }
        ],
        [
            {
                "id": "call_wrong_type",
                "type": "PRIVATE_WRONG_TYPE",
                "function": {"name": "lookup", "arguments": "{}"},
            }
        ],
        [
            {
                "id": "call_missing_name",
                "type": "function",
                "function": {"arguments": "{}"},
            }
        ],
        [
            {
                "id": "call_missing_arguments",
                "type": "function",
                "function": {"name": "lookup"},
            }
        ],
        [
            {
                "id": "call_one",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{}"},
            },
            {
                "id": "PRIVATE_SECOND_CALL",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{}"},
            },
        ],
    ],
    ids=["missing-id", "wrong-type", "missing-name", "missing-arguments", "multiple"],
)
def test_strict_curl_rejects_incomplete_or_multiple_modern_tool_calls(
    monkeypatch,
    caplog,
    tool_calls,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://strict-curl-invalid-modern.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
    )
    client._transport = "curl"
    body = {
        "model": "unit-model",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": tool_calls,
                },
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }

    class Completed:
        returncode = 0
        stderr = b""
        stdout = (json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode("utf-8")

    monkeypatch.setattr(client, "_curl_executable", lambda: "curl")
    monkeypatch.setattr(
        llm_client_module.subprocess,
        "run",
        lambda *_args, **_kwargs: Completed(),
    )

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "lookup"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert str(raised.value) == ProviderFailureError.MESSAGE
    assert "PRIVATE_" not in caplog.text


@pytest.mark.parametrize(
    "message",
    [
        {
            "role": "assistant",
            "content": "",
            "function_call": {"name": "emit_result", "arguments": "{}"},
            "tool_calls": [],
        },
        {
            "role": "assistant",
            "content": "",
            "function_call": {"name": "emit_result", "arguments": {}},
        },
    ],
    ids=["mixed-modern-and-legacy", "non-string-arguments"],
)
def test_strict_curl_rejects_ambiguous_legacy_function_call(
    monkeypatch,
    message,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://strict-curl-invalid.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
    )
    client._transport = "curl"
    body = {
        "model": "unit-model",
        "choices": [{"finish_reason": "function_call", "message": message}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }

    class Completed:
        returncode = 0
        stderr = b""
        stdout = (json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode("utf-8")

    monkeypatch.setattr(client, "_curl_executable", lambda: "curl")
    monkeypatch.setattr(
        llm_client_module.subprocess,
        "run",
        lambda *_args, **_kwargs: Completed(),
    )

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert str(raised.value) == ProviderFailureError.MESSAGE


def test_strict_provider_rejects_mixed_legacy_and_modern_tool_protocols(
    monkeypatch,
    caplog,
) -> None:
    canary = "PRIVATE_MIXED_TOOL_ARGUMENT_MUST_NOT_LEAK"
    client = LLMClient(
        api_key="test",
        base_url="https://strict-mixed.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
    )

    class MixedResponse(_FakeResponse):
        def iter_lines(self):
            yield (
                "data: "
                + json.dumps(
                    {
                        "model": self.model,
                        "choices": [
                            {
                                "delta": {
                                    "function_call": {
                                        "name": "emit_result",
                                        "arguments": json.dumps({"private": canary}),
                                    },
                                    "tool_calls": [],
                                },
                                "finish_reason": "function_call",
                            }
                        ],
                    }
                )
            ).encode("utf-8")

    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: MixedResponse())

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert str(raised.value) == ProviderFailureError.MESSAGE
    assert canary not in caplog.text


def test_strict_provider_accepts_only_exact_model_and_conserved_integer_usage(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    monkeypatch.setattr(
        client.session,
        "post",
        lambda *_args, **_kwargs: _StrictUsageResponse(
            usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
        ),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])

    assert response["model"] == "unit-model"
    assert response["usage"]["estimated"] is False
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["provider_reported"] is True
    assert event["provider_response_model"] == "unit-model"


def test_strict_provider_accepts_zero_optional_usage_details_with_positive_total(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict-zero-details.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    monkeypatch.setattr(
        client.session,
        "post",
        lambda *_args, **_kwargs: _StrictUsageResponse(
            usage={
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "total_tokens": 3,
                "cached_prompt_tokens": 0,
                "reasoning_tokens": 0,
            }
        ),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])

    assert response["usage"]["estimated"] is False
    assert response["usage"]["cached_prompt_tokens"] == 0
    assert response["usage"]["reasoning_tokens"] == 0
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["provider_reported"] is True
    assert event["cached_prompt_tokens"] == 0
    assert event["reasoning_tokens"] == 0


def test_strict_sse_treats_null_tool_protocol_fields_as_absent(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://strict-null-tools.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
    )
    response = _ScriptedToolCallResponse(
        [
            {
                "choices": [
                    {
                        "delta": {
                            "role": "assistant",
                            "content": "ok",
                            "function_call": None,
                            "tool_calls": None,
                        },
                        "finish_reason": "stop",
                    }
                ]
            },
            {
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 1,
                    "total_tokens": 3,
                },
                "choices": [],
            },
        ]
    )
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["choices"][0]["message"] == {
        "role": "assistant",
        "content": "ok",
    }


def test_strict_provider_accepts_only_the_frozen_canonical_response_model(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["request-alias"],
        response_model_map={"request-alias": "canonical-response"},
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    monkeypatch.setattr(
        client.session,
        "post",
        lambda *_args, **_kwargs: _StrictUsageResponse(
            model="canonical-response",
            usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        ),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])

    assert response["model"] == "canonical-response"
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["requested_model"] == "request-alias"
    assert event["provider_response_model"] == "canonical-response"


def test_strict_provider_accepts_the_exact_requested_alias_from_a_mapped_gateway(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["request-alias"],
        response_model_map={"request-alias": "canonical-response"},
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    monkeypatch.setattr(
        client.session,
        "post",
        lambda *_args, **_kwargs: _StrictUsageResponse(
            model="request-alias",
            usage={"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        ),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])

    assert response["model"] == "request-alias"
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["provider_response_model"] == "request-alias"


def test_strict_provider_accepts_only_identical_duplicate_usage_chunks(monkeypatch) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    usage = {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
    first_usage = {**usage, "completion_tokens_details": {"reasoning_tokens": 1}}
    second_usage = {**usage, "completion_tokens_details": {"reasoning_tokens": 2}}
    response = _StrictUsageResponse(model="unit-model", usage=usage)
    response.iter_lines = lambda: iter(
        [
            (
                "data: "
                + json.dumps(
                    {
                        "model": "unit-model",
                        "usage": first_usage,
                        "choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}],
                    }
                )
            ).encode("utf-8"),
            (
                "data: " + json.dumps({"model": "unit-model", "usage": second_usage, "choices": []})
            ).encode("utf-8"),
            b"data: [DONE]",
        ]
    )
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["usage"]["estimated"] is False
    assert ledger.snapshot(include_events=True)["events"][0]["provider_reported"] is True


def test_strict_provider_accepts_null_usage_placeholders_before_terminal_usage(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    response = _StrictUsageResponse()
    response.iter_lines = lambda: iter(
        [
            b'data: {"model":"unit-model","usage":null,"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}',
            b'data: {"model":"unit-model","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"choices":[]}',
            b"data: [DONE]",
        ]
    )
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["usage"]["estimated"] is False
    assert ledger.snapshot(include_events=True)["events"][0]["provider_reported"] is True


@pytest.mark.parametrize(
    ("model", "usage", "failure_class"),
    [
        (
            " unit-model ",
            {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            "provider_identity_mismatch",
        ),
        ("unit-model", {"prompt_tokens": 2}, "provider_usage_unverifiable"),
        (
            "unit-model",
            {"prompt_tokens": 2.0, "completion_tokens": 3, "total_tokens": 5},
            "provider_usage_unverifiable",
        ),
        (
            "unit-model",
            {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 6},
            "provider_usage_unverifiable",
        ),
        (
            "unit-model",
            {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "provider_usage_unverifiable",
        ),
    ],
)
def test_strict_provider_rejects_identity_or_usage_before_returning_model_output(
    monkeypatch, model, usage, failure_class
) -> None:
    canary = "P6_STRICT_OUTPUT_CANARY"
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    response = _StrictUsageResponse(model=model, usage=usage)
    response.iter_lines = lambda: iter(
        [
            (
                "data: "
                + json.dumps(
                    {
                        "model": model,
                        "usage": usage,
                        "choices": [
                            {
                                "delta": {"content": canary},
                                "finish_reason": "stop",
                            }
                        ],
                    }
                )
            ).encode("utf-8"),
            b"data: [DONE]",
        ]
    )
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == failure_class
    assert str(raised.value) == ProviderFailureError.MESSAGE
    assert canary not in str(raised.value)
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["outcome"] != "success"


def test_strict_curl_rejects_nonempty_output_with_all_zero_usage_without_leak(
    monkeypatch,
    caplog,
) -> None:
    canary = "P6_ZERO_USAGE_CURL_OUTPUT_CANARY"
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict-zero-curl.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    client._transport = "curl"
    body = {
        "model": "unit-model",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": canary},
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }

    class Completed:
        returncode = 0
        stderr = b""
        stdout = (json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode("utf-8")

    monkeypatch.setattr(client, "_curl_executable", lambda: "curl")
    monkeypatch.setattr(
        llm_client_module.subprocess,
        "run",
        lambda *_args, **_kwargs: Completed(),
    )

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_usage_unverifiable"
    assert str(raised.value) == ProviderFailureError.MESSAGE
    assert canary not in str(raised.value)
    assert canary not in caplog.text
    assert client.usage_snapshot()["successful_calls"] == 0
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["outcome"] == "failed_unknown_usage"
    assert event["provider_reported"] is False


def test_strict_provider_rejects_duplicate_streaming_json_keys(monkeypatch) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    response = _StrictUsageResponse()
    response.iter_lines = lambda: iter(
        [
            b'data: {"model":"unit-model","model":"alias-model","choices":[]}',
            b"data: [DONE]",
        ]
    )
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["outcome"] != "success"


@pytest.mark.parametrize(
    "lines",
    [
        [b'data: {"model":"unit-model",'],
        [b"event: message"],
        [
            b'data: {"model":7,"choices":[]}',
            b'data: {"model":"unit-model","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}',
        ],
        [
            b'data: {"model":"unit-model","usage":"unknown","choices":[]}',
            b'data: {"model":"unit-model","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}',
        ],
        [
            b'data: {"model":"unit-model","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"choices":[{"delta":"invalid","finish_reason":"stop"}]}',
        ],
        [
            b'data: {"model":"unit-model","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"choices":[{"delta":{"content":"one"},"finish_reason":"stop"}]}',
            b'data: {"model":"unit-model","choices":[{"delta":{"content":"two"},"finish_reason":"stop"}]}',
        ],
    ],
)
def test_strict_provider_rejects_ambiguous_stream_protocol(monkeypatch, lines) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    response = _StrictUsageResponse()
    response.iter_lines = lambda: iter([*lines, b"data: [DONE]"])
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class in {
        "provider_protocol_incompatible",
        "provider_usage_unverifiable",
    }
    assert ledger.snapshot(include_events=True)["events"][0]["outcome"] != "success"


def test_strict_provider_allows_sse_comment_keepalive(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ScanTokenUsageLedger(depth="fast"),
    )
    response = _StrictUsageResponse(
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    )
    original_lines = list(response.iter_lines())
    response.iter_lines = lambda: iter([b": keepalive", *original_lines])
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["model"] == "unit-model"


@pytest.mark.parametrize(
    "lines",
    [
        [
            {
                "model": "unit-model",
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                "choices": [],
            },
            {
                "model": "unit-model",
                "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
                "choices": [],
            },
        ],
        [
            {
                "model": "unit-model",
                "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
                "choices": [{"delta": {"content": "ignored"}, "finish_reason": "length"}],
            }
        ],
    ],
)
def test_strict_provider_rejects_usage_drift_or_nonterminal_finish_reason(
    monkeypatch, lines
) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://strict.example/v1",
        models=["unit-model"],
        max_retries=0,
        require_exact_response_model=True,
        token_usage_ledger=ledger,
    )
    response = _StrictUsageResponse()
    response.iter_lines = lambda: iter(
        [
            *(f"data: {json.dumps(line)}".encode("utf-8") for line in lines),
            b"data: [DONE]",
        ]
    )
    monkeypatch.setattr(client.session, "post", lambda *_args, **_kwargs: response)

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class in {
        "provider_protocol_incompatible",
        "provider_usage_unverifiable",
    }
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["outcome"] != "success"


@pytest.mark.parametrize(
    ("response_model", "expected_response_model"),
    [("unit-model", "unit-model"), ("alias-model", "alias-model"), ("", "")],
)
def test_streaming_usage_event_binds_provider_response_model_without_fallback(
    monkeypatch,
    response_model,
    expected_response_model,
) -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="http://identity.example/v1",
        models=["unit-model"],
        max_retries=0,
        token_usage_ledger=ledger,
    )
    monkeypatch.setattr(
        client.session,
        "post",
        lambda *_args, **_kwargs: _FakeResponse(model=response_model),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])
    event = ledger.snapshot(include_events=True)["events"][0]

    assert response["requested_model"] == "unit-model"
    assert response["model"] == expected_response_model
    assert event["model"] == "unit-model"
    assert event["requested_model"] == "unit-model"
    assert event["provider_response_model"] == expected_response_model


def test_streaming_usage_event_reduces_provider_finish_reason_to_fixed_enum(monkeypatch) -> None:
    canary = "P6_PROVIDER_FINISH_REASON_CANARY"
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="http://identity.example/v1",
        models=["unit-model"],
        max_retries=0,
        token_usage_ledger=ledger,
    )
    monkeypatch.setattr(
        client.session,
        "post",
        lambda *_args, **_kwargs: _FakeResponse(finish_reason=canary),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])
    event = ledger.snapshot(include_events=True)["events"][0]

    assert response["choices"][0]["finish_reason"] == canary
    assert event["finish_reason"] == "other"
    assert canary not in json.dumps(event)


def test_http_failure_never_logs_or_accounts_provider_body(monkeypatch, caplog) -> None:
    secret_canary = "P6_SECRET_MODEL_OUTPUT_CANARY"
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="http://safe-errors.example/v1",
        models=["unit-model"],
        max_retries=0,
        token_usage_ledger=ledger,
    )
    monkeypatch.setattr(
        client.session,
        "post",
        lambda *_args, **_kwargs: _FakeResponse(status_code=400, text=secret_canary),
    )

    with pytest.raises(ProviderFailureError) as error:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert error.value.failure_class == "provider_protocol_incompatible"
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["reason"] == "provider_http_client_error"
    assert secret_canary not in str(error.value)
    assert secret_canary not in caplog.text
    assert secret_canary not in json.dumps(event)


@pytest.mark.parametrize(
    ("failure", "expected_class"),
    [
        (401, "provider_credentials_unavailable"),
        (403, "provider_credentials_unavailable"),
        (429, "provider_transport_exhausted"),
        (500, "provider_transport_exhausted"),
        (503, "provider_transport_exhausted"),
        (requests.exceptions.Timeout("private timeout detail"), "provider_transport_exhausted"),
    ],
)
def test_provider_failures_expose_only_the_fixed_typed_class(
    monkeypatch,
    failure,
    expected_class,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://typed-errors.example/v1",
        models=["unit-model"],
        max_retries=0,
    )

    def fail(*_args, **_kwargs):
        if isinstance(failure, BaseException):
            raise failure
        return _FakeResponse(status_code=failure, text="private provider response")

    monkeypatch.setattr(client.session, "post", fail)

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == expected_class
    assert str(raised.value) == ProviderFailureError.MESSAGE
    assert "private" not in str(raised.value)


def test_llm_client_falls_back_to_another_base_url_after_rate_limit(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url=["http://limited.example/v1", "http://ready.example/v1"],
        models=["unit-model"],
        max_retries=0,
    )
    called_urls = []

    def fake_post(url, **kwargs):
        called_urls.append(url)
        if len(called_urls) == 1:
            return _FakeResponse(
                status_code=429,
                text="rate limited",
                headers={"Retry-After": "30"},
            )
        return _FakeResponse()

    monkeypatch.setattr(client.session, "post", fake_post)

    response = client.chat_completion([{"role": "user", "content": "hello"}])

    assert response["choices"][0]["message"]["content"] == "ok"
    assert called_urls == [
        "http://limited.example/v1/chat/completions",
        "http://ready.example/v1/chat/completions",
    ]


def test_llm_client_retry_until_available_remains_bounded(
    monkeypatch,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://recovering.example/v1",
        models=["unit-model"],
        max_retries=1,
        retry_until_available=True,
    )
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        if len(calls) <= 2:
            raise requests.exceptions.SSLError("temporary TLS EOF")
        return _FakeResponse()

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(ProviderFailureError):
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert len(calls) == 2


def test_llm_client_closes_streaming_response_on_success(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://one.example/v1",
        models=["unit-model"],
    )
    responses = []

    def fake_post(url, **kwargs):
        response = _FakeResponse()
        responses.append(response)
        return response

    monkeypatch.setattr(client.session, "post", fake_post)

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["choices"][0]["message"]["content"] == "ok"
    assert responses and responses[0].closed is True


def test_llm_client_closes_error_response_before_retry(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url=["http://limited.example/v1", "http://ready.example/v1"],
        models=["unit-model"],
        max_retries=0,
    )
    responses = []

    def fake_post(url, **kwargs):
        response = (
            _FakeResponse(status_code=429, text="rate limited", headers={"Retry-After": "0.01"})
            if not responses
            else _FakeResponse()
        )
        responses.append(response)
        return response

    monkeypatch.setattr(client.session, "post", fake_post)

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["choices"][0]["message"]["content"] == "ok"
    assert [response.closed for response in responses] == [True, True]


def test_llm_client_retries_one_isolated_401_after_prior_success(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://auth.example/v1",
        models=["unit-model"],
        max_retries=1,
    )
    responses = [
        _FakeResponse(),
        _FakeResponse(status_code=401, text="transient auth failure"),
        _FakeResponse(),
    ]
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return responses[len(calls) - 1]

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)

    first = client.chat_completion([{"role": "user", "content": "first"}])
    recovered = client.chat_completion([{"role": "user", "content": "second"}])

    assert first["choices"][0]["message"]["content"] == "ok"
    assert recovered["choices"][0]["message"]["content"] == "ok"
    assert len(calls) == 3
    assert all(response.closed for response in responses)


def test_llm_client_does_not_retry_first_401_without_prior_success(monkeypatch) -> None:
    client = LLMClient(
        api_key="bad",
        base_url="http://auth.example/v1",
        models=["unit-model"],
        max_retries=0,
    )
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return _FakeResponse(status_code=401, text="invalid credential")

    monkeypatch.setattr(client.session, "post", fake_post)

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_credentials_unavailable"
    assert len(calls) == 1


def test_llm_client_retries_repeated_401_only_once(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://auth.example/v1",
        models=["unit-model"],
        max_retries=1,
    )
    statuses = [200, 401, 401, 200]
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return _FakeResponse(
            status_code=statuses[len(calls) - 1],
            text="auth failure",
        )

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)

    client.chat_completion([{"role": "user", "content": "seed success"}])
    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_credentials_unavailable"
    assert len(calls) == 3


def test_llm_client_retries_isolated_400_once_after_prior_success(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://client-response.example/v1",
        models=["unit-model"],
        max_retries=1,
    )
    statuses = [200, 400, 200]
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs["json"]))
        return _FakeResponse(status_code=statuses[len(calls) - 1], text="private")

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)

    client.chat_completion([{"role": "user", "content": "seed success"}])
    recovered = client.chat_completion([{"role": "user", "content": "same request"}])

    assert recovered["choices"][0]["message"]["content"] == "ok"
    assert len(calls) == 3
    assert calls[1][1] == calls[2][1]


def test_llm_client_retries_repeated_400_only_once(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://client-response.example/v1",
        models=["unit-model"],
        max_retries=1,
    )
    statuses = [200, 400, 400, 200]
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return _FakeResponse(status_code=statuses[len(calls) - 1], text="private")

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)

    client.chat_completion([{"role": "user", "content": "seed success"}])
    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "same request"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert len(calls) == 3


def test_llm_client_retries_first_400_once_without_prior_success(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://client-response.example/v1",
        models=["unit-model"],
        max_retries=1,
    )
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return _FakeResponse(status_code=400, text="private")

    monkeypatch.setattr(client.session, "post", fake_post)

    with pytest.raises(ProviderFailureError):
        client.chat_completion([{"role": "user", "content": "invalid first request"}])

    assert len(calls) == 2


def test_first_400_then_success_preserves_exact_payload_and_usage_conservation(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    client = LLMClient(
        api_key="test",
        base_url="http://client-response.example/v1",
        models=["unit-model"],
        max_retries=1,
        token_usage_ledger=ledger,
    )
    statuses = [400, 200]
    payloads = []

    def fake_post(_url, **kwargs):
        payloads.append(kwargs["json"])
        return _FakeResponse(status_code=statuses[len(payloads) - 1], text="private")

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)

    result = client.chat_completion([{"role": "user", "content": "same request"}])

    assert result["choices"][0]["message"]["content"] == "ok"
    assert payloads[0] == payloads[1]
    snapshot = ledger.snapshot(include_events=True)
    assert snapshot["event_count"] == 1
    assert snapshot["events"][0]["outcome"] == "success"
    assert snapshot["rejected_before_model_count"] == 1
    assert snapshot["rejected_before_model_reasons"] == {"provider_http_client_error": 1}


@pytest.mark.parametrize("failure", [429, "timeout"], ids=["http-429", "timeout"])
def test_p6_single_endpoint_transport_is_bounded_to_exactly_two_attempts(
    monkeypatch, failure
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://bounded.example/v1",
        models=["unit-model"],
        max_retries=1,
    )
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs["json"]))
        if failure == "timeout":
            raise requests.exceptions.Timeout("private timeout detail")
        return _FakeResponse(status_code=429, text="private rate limit detail")

    monkeypatch.setattr(client.session, "post", fake_post)
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(llm_client_module.random, "uniform", lambda _a, _b: 0.0)

    with pytest.raises(ProviderFailureError):
        client.chat_completion([{"role": "user", "content": "same request"}])

    assert len(calls) == 2
    assert calls[0][1] == calls[1][1]


def test_llm_client_closes_current_thread_session(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://one.example/v1",
        models=["unit-model"],
    )
    initial_session = client._session_for_thread()
    closed = []

    def close_initial():
        closed.append(initial_session)

    monkeypatch.setattr(initial_session, "close", close_initial)

    client.close_thread_session()
    new_session = client._session_for_thread()

    assert closed == [initial_session]
    assert new_session is not initial_session


def test_llm_client_recovers_from_too_many_open_files(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://one.example/v1",
        models=["unit-model"],
        max_retries=1,
    )
    client.close()
    client.LOCAL_FD_EXHAUSTION_COOLDOWN_SECONDS = 0.0
    monkeypatch.setattr("zscope.framework.llm_client.random.uniform", lambda _a, _b: -1.0)
    sessions = []

    class FakeSession:
        def __init__(self, index):
            self.index = index
            self.closed = False

        def post(self, url, **kwargs):
            if self.index == 0:
                raise requests.exceptions.ConnectionError(
                    OSError(errno.EMFILE, "Too many open files")
                )
            return _FakeResponse()

        def close(self):
            self.closed = True

    def fake_new_session():
        session = FakeSession(len(sessions))
        sessions.append(session)
        with client._sessions_lock:
            client._sessions.add(session)
        return session

    monkeypatch.setattr(client, "_new_session", fake_new_session)

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["choices"][0]["message"]["content"] == "ok"
    assert len(sessions) == 2
    assert sessions[0].closed is True
    assert sessions[1].closed is False


@pytest.mark.parametrize(
    ("transport_error", "expected_reason"),
    [
        (
            requests.exceptions.SSLError(
                ssl.SSLEOFError(8, "EOF occurred in violation of protocol")
            ),
            "ssl_error",
        ),
        (
            requests.exceptions.ConnectionError(
                ConnectionResetError(104, "Connection reset by peer")
            ),
            "connection_error",
        ),
        (
            requests.exceptions.ChunkedEncodingError("Response ended prematurely"),
            "connection_error",
        ),
    ],
    ids=["ssl-eof", "connection-reset", "truncated-stream"],
)
def test_llm_client_transport_disconnect_triggers_aimd_and_cooldown(
    monkeypatch,
    caplog,
    transport_error,
    expected_reason,
) -> None:
    shared_url = f"http://transport-overload-{uuid.uuid4().hex}.example/v1"
    client = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        max_retries=0,
        global_max_concurrent_requests=4,
    )
    capacity = client._endpoint_capacity_states[shared_url]
    endpoint = client._base_url_states[0]
    capacity.success_streak = 11
    calls = 0

    class FakeSession:
        def post(self, url, **kwargs):
            nonlocal calls
            calls += 1
            raise transport_error

    monkeypatch.setattr(client, "_session_for_thread", lambda: FakeSession())
    monkeypatch.setattr(
        "zscope.framework.llm_client.random.uniform",
        lambda _a, _b: 0.0,
    )
    started_at = time.monotonic()

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_transport_exhausted"
    snapshot = client.endpoint_capacity_snapshot()[shared_url]
    assert calls == 1
    assert snapshot["max_concurrent_requests"] == 2
    assert snapshot["overload_events"] == 1
    assert snapshot["in_flight"] == 0
    assert capacity.success_streak == 0
    assert endpoint.cooldown_until >= started_at + 0.9
    assert any(expected_reason in record.getMessage() for record in caplog.records)


def test_llm_client_usage_snapshot_is_thread_safe_at_response_boundary(
    monkeypatch,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url=f"http://usage-{uuid.uuid4().hex}.example/v1",
        models=["unit-model"],
    )

    class FakeSession:
        def post(self, url, **kwargs):
            return _FakeResponse()

    monkeypatch.setattr(client, "_session_for_thread", lambda: FakeSession())
    messages = [{"role": "user", "content": "hello"}]

    with ThreadPoolExecutor(max_workers=16) as executor:
        responses = list(executor.map(lambda _index: client.chat_completion(messages), range(32)))

    expected_prompt = sum(int(response["usage"]["prompt_tokens"]) for response in responses)
    expected_completion = sum(int(response["usage"]["completion_tokens"]) for response in responses)
    snapshot = client.usage_snapshot()
    assert {
        key: snapshot[key]
        for key in (
            "successful_calls",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "estimated_calls",
            "provider_reported_calls",
            "provider_usage_coverage",
        )
    } == {
        "successful_calls": 32,
        "prompt_tokens": expected_prompt,
        "completion_tokens": expected_completion,
        "total_tokens": expected_prompt + expected_completion,
        "estimated_calls": 32,
        "provider_reported_calls": 0,
        "provider_usage_coverage": 0.0,
    }
    assert snapshot["successful_call_wall_seconds_total"] >= 0.0
    assert snapshot["successful_call_wall_seconds_p95"] >= 0.0


def test_llm_client_usage_snapshot_tracks_provider_coverage_and_survives_failure(
    monkeypatch,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url=f"http://provider-usage-{uuid.uuid4().hex}.example/v1",
        models=["unit-model"],
        max_retries=0,
    )
    client._transport = "curl"
    monkeypatch.setattr(
        client,
        "_curl_chat_completion",
        lambda _url, _payload: (
            {"role": "assistant", "content": "ok"},
            "stop",
            {
                "prompt_tokens": 17,
                "completion_tokens": 5,
                "total_tokens": 22,
            },
            "unit-model",
        ),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])
    snapshot_after_success = client.usage_snapshot()

    assert response["usage"]["estimated"] is False
    assert {
        key: snapshot_after_success[key]
        for key in (
            "successful_calls",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "estimated_calls",
            "provider_reported_calls",
            "provider_usage_coverage",
        )
    } == {
        "successful_calls": 1,
        "prompt_tokens": 17,
        "completion_tokens": 5,
        "total_tokens": 22,
        "estimated_calls": 0,
        "provider_reported_calls": 1,
        "provider_usage_coverage": 1.0,
    }

    client._transport = "requests"

    class FailingSession:
        def post(self, url, **kwargs):
            raise requests.exceptions.ConnectionError("provider disconnected")

    monkeypatch.setattr(client, "_session_for_thread", lambda: FailingSession())
    monkeypatch.setattr(
        "zscope.framework.llm_client.random.uniform",
        lambda _a, _b: 0.0,
    )
    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "fail now"}])

    assert raised.value.failure_class == "provider_transport_exhausted"
    client.close()
    assert client.usage_snapshot() == snapshot_after_success


def test_llm_client_usage_snapshot_records_successful_call_wall_distribution() -> None:
    client = LLMClient(
        api_key="test",
        base_url="https://example.test/v1",
        models=["model"],
    )
    usage = {
        "prompt_tokens": 1,
        "completion_tokens": 1,
        "total_tokens": 2,
        "estimated": True,
    }

    client._record_successful_usage(usage, duration_seconds=10.0)
    client._record_successful_usage(usage, duration_seconds=30.0)

    snapshot = client.usage_snapshot()
    assert snapshot["successful_call_wall_seconds_total"] == 40.0
    assert snapshot["successful_call_wall_seconds_mean"] == 20.0
    assert snapshot["successful_call_wall_seconds_p50"] == 20.0
    assert snapshot["successful_call_wall_seconds_p95"] == 30.0
    assert snapshot["successful_call_wall_seconds_max"] == 30.0


def test_active_stream_has_no_total_elapsed_budget(monkeypatch) -> None:
    client = LLMClient(
        api_key="unit-key",
        base_url=f"https://active-stream-{uuid.uuid4().hex}.example/v1",
        models=["unit-model"],
        timeout=120,
    )
    observed = {}

    def fake_chunks(_response, **kwargs):
        observed.update(kwargs)
        yield {
            "choices": [
                {
                    "delta": {"content": "complete"},
                    "finish_reason": "stop",
                }
            ]
        }

    monkeypatch.setattr(client, "_iter_chat_chunks", fake_chunks)

    message, finish_reason = client._assemble_chat_response(object())

    assert message["content"] == "complete"
    assert finish_reason == "stop"
    assert observed["max_stream_seconds"] is None
    assert observed["max_idle_valid_chunk_seconds"] == 120


def test_llm_client_limits_concurrent_requests_per_base_url(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://limited.example/v1",
        models=["unit-model"],
        base_url_max_concurrent_requests=1,
    )
    active = 0
    max_active = 0
    lock = threading.Lock()

    class FakeSession:
        def post(self, url, **kwargs):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return _FakeResponse()

    fake_session = FakeSession()
    monkeypatch.setattr(client, "_session_for_thread", lambda: fake_session)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(client.chat_completion, [{"role": "user", "content": "hello"}])
            for _ in range(2)
        ]
        for future in futures:
            assert future.result()["choices"][0]["message"]["content"] == "ok"

    assert max_active == 1


def test_llm_client_shares_concurrency_capacity_across_clients(monkeypatch) -> None:
    shared_url = f"http://shared-{uuid.uuid4().hex}.example/v1"
    client_a = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        base_url_max_concurrent_requests=1,
    )
    client_b = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        base_url_max_concurrent_requests=1,
    )
    active = 0
    max_active = 0
    lock = threading.Lock()

    class FakeSession:
        def post(self, url, **kwargs):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return _FakeResponse()

    fake_session = FakeSession()
    monkeypatch.setattr(client_a, "_session_for_thread", lambda: fake_session)
    monkeypatch.setattr(client_b, "_session_for_thread", lambda: fake_session)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(client_a.chat_completion, [{"role": "user", "content": "hello"}]),
            executor.submit(client_b.chat_completion, [{"role": "user", "content": "hello"}]),
        ]
        for future in futures:
            assert future.result()["choices"][0]["message"]["content"] == "ok"

    assert max_active == 1


def test_llm_client_caps_total_inflight_across_distinct_endpoints(monkeypatch) -> None:
    client_a = LLMClient(
        api_key="test",
        base_url=f"http://global-a-{uuid.uuid4().hex}.example/v1",
        models=["unit-model"],
    )
    client_b = LLMClient(
        api_key="test",
        base_url=f"http://global-b-{uuid.uuid4().hex}.example/v1",
        models=["unit-model"],
    )
    active = 0
    max_active = 0
    lock = threading.Lock()
    reached_global_limit = threading.Event()
    release_requests = threading.Event()

    class FakeSession:
        def post(self, url, **kwargs):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
                if active >= LLMClient.DEFAULT_GLOBAL_MAX_INFLIGHT:
                    reached_global_limit.set()
            release_requests.wait(timeout=5.0)
            with lock:
                active -= 1
            return _FakeResponse()

    fake_session = FakeSession()
    monkeypatch.setattr(client_a, "_session_for_thread", lambda: fake_session)
    monkeypatch.setattr(client_b, "_session_for_thread", lambda: fake_session)

    clients = [client_a, client_b] * 6
    with ThreadPoolExecutor(max_workers=len(clients)) as executor:
        futures = [
            executor.submit(
                client.chat_completion,
                [{"role": "user", "content": "hello"}],
            )
            for client in clients
        ]
        try:
            assert reached_global_limit.wait(timeout=3.0)
            time.sleep(0.05)
            with lock:
                active_while_blocked = active
            assert active_while_blocked == LLMClient.DEFAULT_GLOBAL_MAX_INFLIGHT
            assert client_a.global_capacity_snapshot()["in_flight"] == 8
        finally:
            release_requests.set()

        for future in futures:
            assert future.result()["choices"][0]["message"]["content"] == "ok"

    assert max_active == LLMClient.DEFAULT_GLOBAL_MAX_INFLIGHT
    assert client_b.global_capacity_snapshot()["in_flight"] == 0


def test_p6_near_cap_eight_clients_conserve_out_of_order_retry_attempts(
    monkeypatch,
) -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    per_attempt_reservation = 11
    initial_consumed = P6_BALANCED_ADMISSION_MAX_TOKENS - (
        LLMClient.DEFAULT_GLOBAL_MAX_INFLIGHT * per_attempt_reservation
    )
    initial = ledger.reserve(
        initial_consumed - 1,
        1,
        model="unit-model",
        call_chain_id=ledger.new_call_chain_id(),
    )
    ledger.settle(
        initial,
        prompt_tokens=initial_consumed - 1,
        completion_tokens=1,
        provider_reported=True,
        provider_response_model="unit-model",
    )

    monkeypatch.setattr(
        LLMClient,
        "_estimate_request_prompt_tokens",
        classmethod(
            lambda _cls, _messages, *, tools, response_format, request_payload=None: 1
        ),
    )
    monkeypatch.setattr(llm_client_module.time, "sleep", lambda _seconds: None)

    clients = [
        LLMClient(
            api_key="test",
            base_url=f"http://p6-near-cap-{index}-{uuid.uuid4().hex}.example/v1",
            models=["unit-model"],
            max_retries=1,
            max_tokens=10,
            require_exact_response_model=True,
            token_usage_ledger=ledger,
            llm_ref=f"client-{index}",
            global_max_concurrent_requests=8,
        )
        for index in range(8)
    ]
    lock = threading.Lock()
    first_wave_full = threading.Event()
    retry_started = threading.Event()
    release = [threading.Event() for _ in clients]
    calls = [0 for _ in clients]
    active = 0
    max_active = 0
    admission_boundaries = []

    class FakeSession:
        def __init__(self, index: int) -> None:
            self.index = index

        def post(self, _url, **_kwargs):
            nonlocal active, max_active
            with lock:
                calls[self.index] += 1
                attempt = calls[self.index]
                active += 1
                max_active = max(max_active, active)
                if active == 8:
                    first_wave_full.set()
            admission_boundaries.append(ledger.snapshot())
            try:
                assert first_wave_full.wait(timeout=3.0)
                if self.index == 0 and attempt == 1:
                    return _FakeResponse(status_code=400, text="private")
                if self.index == 0 and attempt == 2:
                    retry_started.set()
                assert release[self.index].wait(timeout=3.0)
                return _StrictUsageResponse(
                    model="unit-model",
                    usage={
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                )
            finally:
                with lock:
                    active -= 1

    for index, client in enumerate(clients):
        session = FakeSession(index)
        monkeypatch.setattr(client, "_session_for_thread", lambda session=session: session)

    messages = [{"role": "user", "content": "same request"}]
    settlement_order = [7, 2, 5, 1, 6, 3, 4, 0]
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(client.chat_completion, messages) for client in clients]
        assert retry_started.wait(timeout=3.0)
        at_retry = ledger.snapshot(include_events=True)
        assert at_retry["consumed_tokens"] + at_retry["reserved_tokens"] == (
            P6_BALANCED_ADMISSION_MAX_TOKENS
        )
        assert at_retry["active_reservation_count"] == 8
        assert at_retry["rejected_before_model_count"] == 1
        assert clients[0].global_capacity_snapshot()["in_flight"] == 8

        for index in settlement_order:
            release[index].set()
            result = futures[index].result(timeout=3.0)
            assert result["choices"][0]["message"]["content"] == "ok"

    snapshot = ledger.snapshot(include_events=True)
    assert max_active == 8
    assert calls == [2, 1, 1, 1, 1, 1, 1, 1]
    assert clients[-1].global_capacity_snapshot()["in_flight"] == 0
    assert all(
        item["consumed_tokens"] + item["reserved_tokens"]
        <= P6_BALANCED_ADMISSION_MAX_TOKENS
        for item in admission_boundaries
    )
    assert snapshot["consumed_tokens"] == initial_consumed + 16
    assert snapshot["reserved_tokens"] == 0
    assert snapshot["active_reservation_count"] == 0
    assert snapshot["event_count"] == 9
    assert snapshot["rejected_before_model_count"] == 1
    assert snapshot["rejected_before_model_reasons"] == {"provider_http_client_error": 1}
    assert [row["llm_ref"] for row in snapshot["events"][-8:]] == [
        f"client-{index}" for index in settlement_order
    ]
    retried = next(row for row in snapshot["events"] if row["llm_ref"] == "client-0")
    rejected = snapshot["rejected_before_model_attempts"][0]
    assert retried["attempt_index"] == 2
    assert retried["retry"] is True
    assert rejected["attempt_index"] == 1
    assert rejected["call_chain_id"] == retried["call_chain_id"]
    attempts_by_chain = {}
    for row in [*snapshot["events"], *snapshot["rejected_before_model_attempts"]]:
        attempts_by_chain.setdefault(row["call_chain_id"], []).append(row["attempt_index"])
    assert len(attempts_by_chain) == 9
    assert all(
        sorted(attempts) == list(range(1, len(attempts) + 1))
        for attempts in attempts_by_chain.values()
    )
    totals = snapshot["usage_attribution"]["totals"]
    assert totals["request_count"] == 9
    assert totals["provider_reported_calls"] == 9
    assert totals["estimated_or_conservative_calls"] == 0
    assert totals["retry_count"] == 1
    assert totals["provider_reported_calls"] / totals["request_count"] == 1.0
    admission = snapshot["p6_balanced_admission"]
    assert admission["request_count"] == 10
    assert admission["admitted_request_count"] == 10
    assert admission["denied_request_count"] == 0
    assert admission["request_conservation_passed"] is True
    assert admission["admitted_request_count"] == (
        snapshot["event_count"] + snapshot["rejected_before_model_count"]
    )
    assert admission["request_count"] == (
        snapshot["event_count"]
        + snapshot["rejected_before_model_count"]
        + admission["denied_request_count"]
    )


def test_llm_client_defaults_to_global_endpoint_cap_of_eight() -> None:
    shared_url = f"http://default-cap-{uuid.uuid4().hex}.example/v1"
    client = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
    )

    state = client.endpoint_capacity_snapshot()[shared_url]

    assert state["hard_max_concurrent_requests"] == 8
    assert state["max_concurrent_requests"] == 8
    assert client.global_capacity_snapshot() == {
        "hard_max_concurrent_requests": 8,
        "in_flight": 0,
    }


def test_llm_client_legacy_nonpositive_global_cap_maps_to_eight() -> None:
    shared_url = f"http://legacy-cap-{uuid.uuid4().hex}.example/v1"
    client = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        global_max_concurrent_requests=0,
    )

    state = client.endpoint_capacity_snapshot()[shared_url]
    assert state["hard_max_concurrent_requests"] == 8
    assert state["max_concurrent_requests"] == 8


def test_llm_client_uses_strictest_positive_cap_for_shared_endpoint() -> None:
    shared_url = f"http://strict-cap-{uuid.uuid4().hex}.example/v1"
    client_a = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        base_url_max_concurrent_requests=6,
        global_max_concurrent_requests=8,
    )
    client_b = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        base_url_max_concurrent_requests=3,
        global_max_concurrent_requests=8,
    )

    assert client_a.endpoint_capacity_snapshot()[shared_url]["hard_max_concurrent_requests"] == 3
    assert client_b.endpoint_capacity_snapshot()[shared_url]["max_concurrent_requests"] == 3


def test_llm_client_uses_strictest_positive_process_cap_across_endpoints() -> None:
    client_a = LLMClient(
        api_key="test",
        base_url=f"http://process-cap-a-{uuid.uuid4().hex}.example/v1",
        models=["unit-model"],
        global_max_concurrent_requests=6,
    )
    client_b = LLMClient(
        api_key="test",
        base_url=f"http://process-cap-b-{uuid.uuid4().hex}.example/v1",
        models=["unit-model"],
        global_max_concurrent_requests=3,
    )

    assert client_a.global_capacity_snapshot()["hard_max_concurrent_requests"] == 3
    assert client_b.global_capacity_snapshot()["hard_max_concurrent_requests"] == 3


def test_llm_client_shared_aimd_reduces_and_recovers_endpoint_cap() -> None:
    shared_url = f"http://aimd-{uuid.uuid4().hex}.example/v1"
    client_a = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        global_max_concurrent_requests=8,
    )
    client_b = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        global_max_concurrent_requests=8,
    )
    client_a.AIMD_SUCCESS_THRESHOLD = 2
    endpoint = client_a._base_url_states[0]

    client_a._record_endpoint_overload(endpoint, reason="unit_test")

    assert client_b.endpoint_capacity_snapshot()[shared_url]["max_concurrent_requests"] == 4

    client_a._record_endpoint_success(endpoint)
    client_a._record_endpoint_success(endpoint)

    assert client_b.endpoint_capacity_snapshot()[shared_url]["max_concurrent_requests"] == 5


def test_llm_client_aimd_never_reduces_below_two(caplog) -> None:
    shared_url = f"http://aimd-floor-{uuid.uuid4().hex}.example/v1"
    client = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        global_max_concurrent_requests=3,
    )
    endpoint = client._base_url_states[0]

    client._record_endpoint_overload(endpoint, reason="unit_test")
    client._record_endpoint_overload(endpoint, reason="unit_test")

    assert client.endpoint_capacity_snapshot()[shared_url]["max_concurrent_requests"] == 2
    assert not any(
        "reduced concurrency from 2 to 2" in record.getMessage() for record in caplog.records
    )


def test_llm_client_shares_rate_budget_across_clients() -> None:
    shared_url = f"http://shared-rate-{uuid.uuid4().hex}.example/v1"
    client_a = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        base_url_rate_limit_per_minute=2,
    )
    client_b = LLMClient(
        api_key="test",
        base_url=shared_url,
        models=["unit-model"],
        base_url_rate_limit_per_minute=2,
    )

    selected_a = client_a._select_base_url()
    client_a._release_base_url(selected_a)
    selected_b = client_b._select_base_url()
    client_b._release_base_url(selected_b)

    endpoint = client_b._endpoint_capacity_states[shared_url]
    assert client_b.endpoint_capacity_snapshot()[shared_url]["recent_requests"] == 2
    assert client_b._has_minute_capacity(endpoint) is False


def test_config_loader_parses_multiple_llm_base_urls(tmp_path) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text(
        json.dumps(
            {
                "config_version": 2,
                "llms": {
                    "default": {
                        "api_key": "test",
                        "base_urls": [
                            "http://one.example/v1/",
                            "http://two.example/v1",
                        ],
                        "base_url_rate_limit_per_minute": 12,
                        "base_url_max_concurrent_requests": 5,
                        "retry_until_available": True,
                        "models": ["unit-model"],
                    }
                },
                "project": {
                    "root": str(tmp_path),
                    "source_root": ".",
                    "language": "c_cpp",
                },
                "scan": {"task": ""},
                "indexing": {"backend": "regex"},
                "concurrency": {
                    "entry_workers": 2,
                    "validator_workers": 2,
                    "investigator_workers": 1,
                    "evidence_completion_workers": 2,
                    "index_workers": 2,
                    "svf_workers": 1,
                    "llm_max_inflight": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    config = ConfigLoader.load(str(config_path))

    assert config.llms["default"].base_url == "http://one.example/v1"
    assert config.llms["default"].base_urls == [
        "http://one.example/v1",
        "http://two.example/v1",
    ]
    assert config.llms["default"].base_url_rate_limit_per_minute == 12
    assert config.llms["default"].base_url_max_concurrent_requests == 5
    assert config.llms["default"].retry_until_available is True
