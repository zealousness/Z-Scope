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
from zscope.framework.llm_client import LLMClient


class _FakeResponse:
    def __init__(self, status_code=200, text="ok", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.closed = False

    def iter_lines(self):
        yield (
            b'data: {"choices":[{"delta":{"content":"ok"},'
            b'"finish_reason":"stop"}]}'
        )
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


def test_llm_client_retries_transient_errors_until_service_recovers(
    monkeypatch,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://recovering.example/v1",
        models=["unit-model"],
        max_retries=0,
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

    result = client.chat_completion([{"role": "user", "content": "hello"}])

    assert result["choices"][0]["message"]["content"] == "ok"
    assert len(calls) == 3


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
        max_retries=0,
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

    with pytest.raises(Exception, match="HTTP 401"):
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert len(calls) == 1


def test_llm_client_retries_repeated_401_only_once(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://auth.example/v1",
        models=["unit-model"],
        max_retries=0,
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
    with pytest.raises(Exception, match="HTTP 401"):
        client.chat_completion([{"role": "user", "content": "hello"}])

    assert len(calls) == 3


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

    with pytest.raises(Exception, match="All models failed"):
        client.chat_completion([{"role": "user", "content": "hello"}])

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
        responses = list(
            executor.map(lambda _index: client.chat_completion(messages), range(32))
        )

    expected_prompt = sum(
        int(response["usage"]["prompt_tokens"]) for response in responses
    )
    expected_completion = sum(
        int(response["usage"]["completion_tokens"]) for response in responses
    )
    snapshot = client.usage_snapshot()
    assert snapshot == {
        "successful_calls": 32,
        "prompt_tokens": expected_prompt,
        "completion_tokens": expected_completion,
        "total_tokens": expected_prompt + expected_completion,
        "estimated_calls": 32,
        "provider_reported_calls": 0,
        "provider_usage_coverage": 0.0,
    }


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
        ),
    )

    response = client.chat_completion([{"role": "user", "content": "hello"}])
    snapshot_after_success = client.usage_snapshot()

    assert response["usage"]["estimated"] is False
    assert snapshot_after_success == {
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
    with pytest.raises(Exception, match="All models failed"):
        client.chat_completion([{"role": "user", "content": "fail now"}])

    client.close()
    assert client.usage_snapshot() == snapshot_after_success


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

    assert client_a.endpoint_capacity_snapshot()[shared_url][
        "hard_max_concurrent_requests"
    ] == 3
    assert client_b.endpoint_capacity_snapshot()[shared_url][
        "max_concurrent_requests"
    ] == 3


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

    assert client_b.endpoint_capacity_snapshot()[shared_url][
        "max_concurrent_requests"
    ] == 4

    client_a._record_endpoint_success(endpoint)
    client_a._record_endpoint_success(endpoint)

    assert client_b.endpoint_capacity_snapshot()[shared_url][
        "max_concurrent_requests"
    ] == 5


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

    assert client.endpoint_capacity_snapshot()[shared_url][
        "max_concurrent_requests"
    ] == 2
    assert not any(
        "reduced concurrency from 2 to 2" in record.getMessage()
        for record in caplog.records
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
                        "retry_until_available": True,
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
    assert config.llms["default"].retry_until_available is True
