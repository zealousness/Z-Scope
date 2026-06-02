import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from zscope.config.config import ConfigLoader
from zscope.framework.llm_client import LLMClient


class _FakeResponse:
    def __init__(self, status_code=200, text="ok", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def iter_lines(self):
        yield (
            b'data: {"choices":[{"delta":{"content":"ok"},'
            b'"finish_reason":"stop"}]}'
        )
        yield b"data: [DONE]"


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


def test_config_loader_parses_multiple_llm_base_urls(tmp_path) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text(
        json.dumps(
            {
                "llms": {
                    "default": {
                        "provider": "openai",
                        "api_key": "test",
                        "base_urls": [
                            "http://one.example/v1/",
                            "http://two.example/v1",
                        ],
                        "base_url_rate_limit_per_minute": 12,
                        "base_url_max_concurrent_requests": 5,
                        "models": ["unit-model"],
                    }
                },
                "project": {"root": ".", "source_root": "."},
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
