"""Requests-compatible arguments and buffered response lifecycle, without network I/O."""

import os
from contextlib import closing
from types import MappingProxyType

import httpx
import pytest
import requests

from zscope.common.cancellation import CancellationToken, bind_cancellation_token
from zscope.framework.cancellable_http import CancellableHTTPAdapter


@pytest.fixture
def owned_transport(monkeypatch):
    options = []
    clients = []
    original = httpx.AsyncClient

    def client(**kwargs):
        options.append(kwargs)
        # Keep real HTTPX stream/response cleanup; do not load synthetic TLS
        # credentials or send the synthetic proxy address to the network.
        value = original(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"message": "你好"})),
            trust_env=False,
        )
        clients.append(value)
        return value

    monkeypatch.setattr(httpx, "AsyncClient", client)
    return options, clients


@pytest.mark.parametrize("stream", [False, True])
def test_owned_response_can_close_then_replay_buffered_body(owned_transport, stream):
    options, clients = owned_transport
    request = requests.Request("POST", "https://transport.invalid/chat", json={}).prepare()
    with closing(CancellableHTTPAdapter()) as adapter, bind_cancellation_token(CancellationToken()):
        response = adapter.send(request, stream=stream)
    assert clients[0].is_closed
    # This must succeed before .content/.json or a requests.Session has an
    # opportunity to mark the response consumed on the adapter's behalf.
    response.close()
    chunks = list(response.iter_content(chunk_size=2))
    assert b"".join(chunks) == response.content
    assert response.json() == {"message": "你好"}
    assert response.request is request
    assert response.status_code == 200
    assert options[0]["trust_env"] is False


@pytest.mark.parametrize(
    "cert, expected",
    [
        (None, None),
        ("client.pem", "client.pem"),
        (b"client.pem", "client.pem"),
        ((b"client.pem", "key.pem"), ("client.pem", "key.pem")),
        (("client.pem", b"key.pem"), ("client.pem", "key.pem")),
        (b"client-\xff.pem", os.fsdecode(b"client-\xff.pem")),
    ],
)
def test_owned_transport_accepts_certificate_paths_and_read_only_proxy_mapping(
    owned_transport, cert, expected
):
    options, _ = owned_transport
    proxies = MappingProxyType({"https": "http://proxy.invalid:8080"})
    request = requests.Request("POST", "https://transport.invalid/chat", json={}).prepare()
    with closing(CancellableHTTPAdapter()) as adapter, bind_cancellation_token(CancellationToken()):
        response = adapter.send(request, cert=cert, proxies=proxies)
    assert response.json() == {"message": "你好"}
    assert options[0]["cert"] == expected
    assert options[0]["proxy"] == proxies["https"]


def test_unbound_attempt_preserves_requests_adapter_arguments(monkeypatch):
    captured = []
    expected = requests.Response()

    def send(self, request, **kwargs):
        captured.append(kwargs)
        return expected

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    request = requests.Request("POST", "https://transport.invalid/chat", json={}).prepare()
    proxies = MappingProxyType({"https": "http://proxy.invalid:8080"})
    cert = (b"client.pem", b"key.pem")
    with closing(CancellableHTTPAdapter()) as adapter:
        assert adapter.send(request, cert=cert, proxies=proxies) is expected
    assert captured[0]["cert"] is cert
    assert captured[0]["proxies"] is proxies
