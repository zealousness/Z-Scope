import json
import subprocess
from pathlib import Path

import pytest

from zscope.common.cancellation import CancellationError, CancellationToken
from zscope.framework.llm_client import LLMClient


def test_curl_transport_parses_non_streaming_chat_response(monkeypatch) -> None:
    monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "curl")
    monkeypatch.setenv("Z_SCOPE_CURL_BIN", "curl-test")
    captured = {}

    class FakeProcess:
        returncode = 0

        def __init__(self, command, **kwargs):
            captured["command"] = command
            config_path = command[command.index("--config") + 1]
            with open(config_path, encoding="utf-8") as handle:
                captured["config"] = handle.read()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def communicate(self, *, input, timeout):
            captured["payload"] = json.loads(input.decode("utf-8"))
            body = json.dumps({
                "choices": [{
                    "message": {"role": "assistant", "content": '{"ok": true}'},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            })
            return (body + "\n__Z_SCOPE_HTTP_STATUS__:200").encode("utf-8"), b""

    monkeypatch.setattr(subprocess, "Popen", FakeProcess)
    client = LLMClient(
        api_key="test-key",
        base_url="https://example.test/v1",
        models=["test-model"],
        max_retries=0,
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])

    assert response["choices"][0]["message"]["content"] == '{"ok": true}'
    assert response["choices"][0]["finish_reason"] == "stop"
    assert response["usage"]["total_tokens"] == 5
    assert captured["payload"]["stream"] is False
    assert captured["command"] == ["curl-test", "--config", captured["command"][2]]
    assert "Authorization: Bearer test-key" not in " ".join(captured["command"])
    assert "http1.1" in captured["config"]
    assert "Authorization: Bearer test-key" in captured["config"]


def test_curl_cancellation_kills_and_reaps_process(monkeypatch):
    token = CancellationToken()
    captured = {}

    class PendingProcess:
        returncode = None

        def __init__(self, command, **kwargs):
            captured["config"] = Path(command[command.index("--config") + 1])
            captured["process"] = self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            captured["closed"] = True

        def communicate(self, input=None, timeout=None):
            if timeout is not None:
                assert timeout <= 0.2
                token.cancel("user_stop")
                raise subprocess.TimeoutExpired("curl", timeout)
            captured["reaped"] = True
            return b"", b""

        def poll(self):
            return self.returncode

        def kill(self):
            captured["killed"] = True
            self.returncode = -9

    monkeypatch.setattr(subprocess, "Popen", PendingProcess)
    monkeypatch.setattr("zscope.framework.llm_client.current_cancellation_token", lambda: token)
    client = LLMClient(api_key="test", base_url="https://example.test/v1", models=["unit"])
    client._transport = "curl"
    monkeypatch.setattr(client, "_curl_executable", lambda: "curl-test")
    try:
        with pytest.raises(CancellationError, match="user_stop"):
            client.chat_completion([{"role": "user", "content": "hello"}])
        assert captured["killed"] and captured["reaped"] and captured["closed"]
        assert not captured["config"].exists()
    finally:
        client.close()
