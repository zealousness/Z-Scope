import json
import subprocess

from zscope.framework.llm_client import LLMClient


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
