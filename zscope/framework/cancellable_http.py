"""Requests adapter with owned, cancellable async I/O for bounded agent work.

The async client and its request task live for exactly one HTTP attempt. On
cancellation we await their cleanup before releasing the caller's capacity slot;
no detached worker continues reading or writing after cancellation returns.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
import os
import ssl
import time
from typing import Any

import httpx
import requests

from ..common.cancellation import CancellationToken, current_cancellation_token
from .chat_protocol import ChatChunkDecoder


class CancellableHTTPAdapter(requests.adapters.HTTPAdapter):
    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: float | tuple[float | None, float | None] | None = None,
        verify: bool | str = True,
        cert: bytes | str | tuple[bytes | str, bytes | str] | None = None,
        proxies: Mapping[str, str] | None = None,
    ) -> requests.Response:
        kwargs: dict[str, Any] = dict(
            stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies
        )
        token = current_cancellation_token()
        if token is None:
            return super().send(request, **kwargs)
        token.raise_if_cancelled()
        # This is a synchronous API, called by the scan's synchronous workers.
        # Do not start an unowned background thread if an async caller misuses it.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Call synchronous LLM operations from a worker, not an event loop")
        return asyncio.run(self._send_owned(request, token, kwargs))

    async def _send_owned(
        self, request: requests.PreparedRequest, token: CancellationToken, options: dict[str, Any]
    ) -> requests.Response:
        task = asyncio.create_task(self._fetch(request, options))
        try:
            while not task.done():
                token.raise_if_cancelled()
                await asyncio.wait({task}, timeout=0.05)
            token.raise_if_cancelled()
            return await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _fetch(
        self, request: requests.PreparedRequest, options: dict[str, Any]
    ) -> requests.Response:
        timeout = options.get("timeout")
        read_timeout = timeout[1] if isinstance(timeout, tuple) else timeout
        connect_timeout = timeout[0] if isinstance(timeout, tuple) else timeout
        verify = options.get("verify", True)
        if isinstance(verify, str):
            verify = ssl.create_default_context(cafile=verify)
        cert = options.get("cert")
        # Requests permits byte paths. HTTPX treats a non-string certificate
        # as a tuple, so a single bytes path must first become a filesystem string.
        if isinstance(cert, bytes):
            cert = os.fsdecode(cert)
        elif isinstance(cert, tuple):
            cert = tuple(os.fsdecode(path) for path in cert)
        proxy = requests.utils.select_proxy(request.url or "", options.get("proxies") or {})
        body = request.body
        if body is not None and not isinstance(body, (str, bytes)):
            raise ValueError("LLM HTTP requests require a fully materialized body")
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(read_timeout, connect=connect_timeout),
                verify=verify,
                cert=cert,
                proxy=proxy,
                trust_env=False,  # Requests has already resolved proxy/CA environment settings.
                follow_redirects=False,
            ) as client:
                async with client.stream(
                    request.method or "POST",
                    request.url or "",
                    headers={
                        key: value.decode("latin-1") if isinstance(value, bytes) else value
                        for key, value in request.headers.items()
                    },
                    content=body,
                ) as response:
                    lines: list[str] = []
                    decoder = ChatChunkDecoder()
                    is_sse = (
                        response.status_code == 200
                        and "text/event-stream" in response.headers.get("content-type", "")
                    )
                    last_valid = time.monotonic()
                    # Read timeout bounds silence; this additional guard bounds
                    # endless comments/malformed SSE even when bytes keep arriving.
                    async with asyncio.timeout(read_timeout) as idle:
                        async for line in response.aiter_lines():
                            lines.append(line)
                            valid = decoder.feed(line) is not None if is_sse else False
                            if decoder.done:
                                break
                            if valid:
                                last_valid = time.monotonic()
                                if read_timeout is not None:
                                    idle.reschedule(
                                        asyncio.get_running_loop().time() + read_timeout
                                    )
                            elif (
                                read_timeout is not None
                                and time.monotonic() - last_valid > read_timeout
                            ):
                                raise TimeoutError("Chat stream idle timeout")
                    result = requests.Response()
                    result.status_code = response.status_code
                    result.headers = requests.structures.CaseInsensitiveDict(response.headers)
                    result.url = str(response.url)
                    result.reason = response.reason_phrase
                    result.request = request
                    result.encoding = "utf-8"
                    result._content = "\n".join(lines).encode("utf-8")
                    # Let Requests mark the buffered response consumed. This
                    # also makes iter_content/close safe without a live raw stream.
                    _ = result.content
                    return result
        except (httpx.TimeoutException, TimeoutError) as exc:
            raise requests.exceptions.Timeout("Cancellable HTTP request timed out") from exc
        except httpx.HTTPError as exc:
            raise requests.exceptions.ConnectionError("Cancellable HTTP transport failed") from exc
