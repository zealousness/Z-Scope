#!/usr/bin/env python3
"""Credential-free bounded raw TCP relay for the sealed P6 model endpoint.

The relay never parses TLS or HTTP and never logs payload bytes.  Its only
configuration is a listen port plus a frozen list of public upstream IP/port
pairs passed in argv by the local runtime provisioner.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
from typing import Sequence


BUFFER_BYTES = 64 * 1024
CONNECT_TIMEOUT_SECONDS = 15
IDLE_TIMEOUT_SECONDS = 180
MAX_CONNECTIONS = 16


def _upstream(value: str) -> tuple[str, int]:
    if value.startswith("[") and "]:" in value:
        host, raw_port = value[1:].split("]:", 1)
    else:
        host, separator, raw_port = value.rpartition(":")
        if not separator:
            raise argparse.ArgumentTypeError("upstream must be IP:port")
    try:
        canonical = str(ipaddress.ip_address(host))
        port = int(raw_port)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("upstream must be IP:port") from exc
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("upstream port is invalid")
    return canonical, port


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            payload = await asyncio.wait_for(reader.read(BUFFER_BYTES), IDLE_TIMEOUT_SECONDS)
            if not payload:
                break
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), IDLE_TIMEOUT_SECONDS)
    except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
        pass
    finally:
        try:
            writer.write_eof()
        except (AttributeError, OSError, RuntimeError):
            pass


async def serve(*, listen_port: int, upstreams: Sequence[tuple[str, int]]) -> None:
    semaphore = asyncio.Semaphore(MAX_CONNECTIONS)

    async def handle(
        client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        async with semaphore:
            upstream_reader: asyncio.StreamReader | None = None
            upstream_writer: asyncio.StreamWriter | None = None
            for host, port in upstreams:
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), CONNECT_TIMEOUT_SECONDS
                    )
                    break
                except (OSError, TimeoutError):
                    continue
            if upstream_reader is None or upstream_writer is None:
                client_writer.close()
                await client_writer.wait_closed()
                return
            await asyncio.gather(
                _pipe(client_reader, upstream_writer),
                _pipe(upstream_reader, client_writer),
            )
            upstream_writer.close()
            client_writer.close()
            await asyncio.gather(
                upstream_writer.wait_closed(),
                client_writer.wait_closed(),
                return_exceptions=True,
            )

    server = await asyncio.start_server(handle, host="0.0.0.0", port=listen_port)
    async with server:
        await server.serve_forever()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream", type=_upstream, action="append", required=True)
    args = parser.parse_args(argv)
    if args.listen_port < 1 or args.listen_port > 65535:
        parser.error("listen port is invalid")
    upstreams = tuple(dict.fromkeys(args.upstream))
    if not upstreams:
        parser.error("at least one upstream is required")
    asyncio.run(serve(listen_port=args.listen_port, upstreams=upstreams))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
