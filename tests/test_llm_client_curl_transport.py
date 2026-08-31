import json
import subprocess

import pytest

from zscope.framework.llm_client import LLMClient, ProviderFailureError
from zscope.framework.llm_usage import ScanTokenUsageLedger


def test_curl_transport_parses_non_streaming_chat_response(monkeypatch) -> None:
    monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "curl")
    monkeypatch.setenv("Z_SCOPE_CURL_BIN", "curl-test")
    captured = {}

    def fake_run(command, *, input, stdout, stderr, check):
        captured["command"] = command
        config_path = command[command.index("--config") + 1]
        with open(config_path, encoding="utf-8") as handle:
            captured["config"] = handle.read()
        captured["payload"] = json.loads(input.decode("utf-8"))
        body = json.dumps(
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": '{"ok": true}'},
                        "finish_reason": "stop",
                    }
                ],
                "model": "test-model",
                "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            }
        )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(body + "\n__Z_SCOPE_HTTP_STATUS__:200").encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test-key",
        base_url="https://example.test/v1",
        models=["test-model"],
        max_retries=0,
        token_usage_ledger=ledger,
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])

    assert response["choices"][0]["message"]["content"] == '{"ok": true}'
    assert response["choices"][0]["finish_reason"] == "stop"
    assert response["model"] == "test-model"
    assert response["requested_model"] == "test-model"
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["requested_model"] == "test-model"
    assert event["provider_response_model"] == "test-model"
    assert response["usage"]["total_tokens"] == 5
    assert captured["payload"]["stream"] is False
    assert captured["command"] == ["curl-test", "--config", captured["command"][2]]
    assert "Authorization: Bearer test-key" not in " ".join(captured["command"])
    assert "http1.1" in captured["config"]
    assert "Authorization: Bearer test-key" in captured["config"]


@pytest.mark.parametrize("response_model", ["alias-model", None])
def test_curl_usage_event_records_mismatched_or_missing_response_model(
    monkeypatch, response_model
) -> None:
    monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "curl")
    monkeypatch.setenv("Z_SCOPE_CURL_BIN", "curl-test")

    def fake_run(command, **_kwargs):
        body = {
            "choices": [
                {
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
        }
        if response_model is not None:
            body["model"] = response_model
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode(),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://example.test/v1",
        models=["requested-model"],
        max_retries=0,
        token_usage_ledger=ledger,
    )

    client.chat_completion([{"role": "user", "content": "hello"}])
    event = ledger.snapshot(include_events=True)["events"][0]

    assert event["requested_model"] == "requested-model"
    assert event["provider_response_model"] == (response_model or "")


def test_curl_failure_does_not_retain_stdout_stderr_or_response_body(monkeypatch, caplog) -> None:
    monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "curl")
    monkeypatch.setenv("Z_SCOPE_CURL_BIN", "curl-test")
    canary = "P6_CURL_SECRET_MODEL_OUTPUT_CANARY"

    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            22,
            stdout=(canary + "\n__Z_SCOPE_HTTP_STATUS__:500").encode(),
            stderr=canary.encode(),
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    ledger = ScanTokenUsageLedger(depth="fast")
    client = LLMClient(
        api_key="test",
        base_url="https://example.test/v1",
        models=["requested-model"],
        max_retries=0,
        token_usage_ledger=ledger,
    )

    with pytest.raises(ProviderFailureError) as error:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert error.value.failure_class == "provider_transport_exhausted"
    assert str(error.value) == ProviderFailureError.MESSAGE
    event = ledger.snapshot(include_events=True)["events"][0]
    assert event["reason"] == "provider_transport_error"
    assert canary not in str(error.value)
    assert canary not in caplog.text
    assert canary not in json.dumps(event)


@pytest.mark.parametrize(
    "body",
    [
        {
            "choices": [
                {
                    "message": {"role": "assistant", "content": "ignored"},
                    "finish_reason": "length",
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
        },
        {
            "choices": [
                {"message": {"content": "one"}, "finish_reason": "stop"},
                {"message": {"content": "two"}, "finish_reason": "stop"},
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
        },
    ],
)
def test_strict_curl_rejects_invalid_finish_or_multiple_choices_without_retry(
    monkeypatch, body
) -> None:
    monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "curl")
    monkeypatch.setenv("Z_SCOPE_CURL_BIN", "curl-test")
    calls = 0

    def fake_run(command, **_kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode(),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    client = LLMClient(
        api_key="test",
        base_url="https://example.test/v1",
        models=["unit-model"],
        max_retries=2,
        require_exact_response_model=True,
        token_usage_ledger=ScanTokenUsageLedger(depth="fast"),
    )

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert calls == 1


@pytest.mark.parametrize(
    "message",
    [
        None,
        "not-an-object",
        {"role": "user", "content": "ignored"},
        {"role": "assistant", "content": 7},
        {"role": "assistant", "content": "", "tool_calls": {}},
    ],
)
def test_strict_curl_rejects_invalid_message_shape_without_retry(monkeypatch, message) -> None:
    monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "curl")
    monkeypatch.setenv("Z_SCOPE_CURL_BIN", "curl-test")
    calls = 0
    body = {
        "choices": [{"message": message, "finish_reason": "stop"}],
        "model": "unit-model",
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
    }

    def fake_run(command, **_kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(json.dumps(body) + "\n__Z_SCOPE_HTTP_STATUS__:200").encode(),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    client = LLMClient(
        api_key="test",
        base_url="https://example.test/v1",
        models=["unit-model"],
        max_retries=2,
        require_exact_response_model=True,
        token_usage_ledger=ScanTokenUsageLedger(depth="fast"),
    )

    with pytest.raises(ProviderFailureError) as raised:
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert calls == 1
