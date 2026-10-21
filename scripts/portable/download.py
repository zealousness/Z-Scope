"""Immutable downloads with bounded retries and verified range assembly."""

from __future__ import annotations

import concurrent.futures
import os
import shutil
import time
import urllib.request
from pathlib import Path

from .abi import sha256


def fetch_file(entry, directory):
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / entry["filename"]
    if destination.is_file():
        if sha256(destination) != entry["sha256"]:
            raise ValueError(f"Cached download hash mismatch: {destination}")
        return
    direct = os.environ.get("ZSCOPE_DOWNLOAD_DIRECT") == "1"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}) if direct else urllib.request.ProxyHandler()
    )
    temporary = destination.with_name(destination.name + ".partial")
    size = entry.get("size", 0)
    if size > 128 * 1024 * 1024 and direct:
        parts = directory / (entry["sha256"][:24] + ".parts")
        parts.mkdir(exist_ok=True)
        block_size = 32 * 1024 * 1024
        blocks = [
            (start, min(size - 1, start + block_size - 1)) for start in range(0, size, block_size)
        ]

        def fetch_block(bounds):
            start, end = bounds
            path = parts / str(start)
            if path.is_file() and path.stat().st_size == end - start + 1:
                return path
            for attempt in range(5):
                try:
                    request = urllib.request.Request(
                        entry["url"],
                        headers={
                            "User-Agent": "zscope-portable-release",
                            "Range": f"bytes={start}-{end}",
                        },
                    )
                    with opener.open(request, timeout=120) as response, path.open("wb") as output:
                        if (
                            response.status != 206
                            or response.headers.get("Content-Range")
                            != f"bytes {start}-{end}/{size}"
                        ):
                            raise ValueError("Unexpected range response: " + entry["filename"])
                        shutil.copyfileobj(response, output, 1024 * 1024)
                    if path.stat().st_size != end - start + 1:
                        raise OSError("Truncated download segment")
                    return path
                except OSError:
                    if attempt == 4:
                        raise
                    time.sleep(min(2**attempt, 10))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            paths = list(pool.map(fetch_block, blocks))
        with temporary.open("wb") as output:
            for path in paths:
                with path.open("rb") as stream:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
    else:
        for attempt in range(5):
            try:
                request = urllib.request.Request(
                    entry["url"], headers={"User-Agent": "zscope-portable-release"}
                )
                with opener.open(request, timeout=120) as response, temporary.open("wb") as output:
                    expected = int(response.headers.get("Content-Length", size or 0))
                    shutil.copyfileobj(response, output, 1024 * 1024)
                if expected and temporary.stat().st_size != expected:
                    raise OSError("Truncated download: " + destination.name)
                break
            except OSError:
                if attempt == 4:
                    raise
                time.sleep(min(2**attempt, 10))
    if sha256(temporary) != entry["sha256"]:
        raise ValueError(f"Downloaded hash mismatch: {destination.name}")
    temporary.replace(destination)
