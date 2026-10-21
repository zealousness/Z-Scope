"""Stream report JSON without materializing a second report-sized string."""

from __future__ import annotations

import json
import importlib
import os
import sys
from collections import OrderedDict
from decimal import Decimal
from pathlib import Path
import tempfile
import time
from typing import Any


def require_streaming_json() -> Any:
    """Benchmark reports can exceed RAM when decoded through read_text/json.loads."""
    try:
        return importlib.import_module("ijson")
    except ImportError as exc:
        raise RuntimeError(
            "Large benchmark reports require: pip install 'zscope[benchmark]'"
        ) from exc


def read_json_streaming(path: Path) -> Any:
    """Decode one complete JSON value without a report-sized text/bytes buffer.

    Retain the complete object (no projection or evidence pruning). Decimal events
    become floats to preserve stdlib json number types; arbitrary integers stay ints.
    Exhausting the parser also rejects truncation and trailing JSON values.
    """
    parser = require_streaming_json()
    builder = importlib.import_module("ijson.common").ObjectBuilder()
    keys: dict[str, str] = {}
    strings: OrderedDict[str, str] = OrderedDict()
    string_bytes = 0
    with Path(path).open("rb") as stream:
        for event, value in parser.basic_parse(stream):
            # Evidence repeats source text and paths across entries. Sharing only
            # immutable strings is lossless; containers remain independently mutable.
            if event == "map_key" and len(keys) < 4096:
                value = keys.setdefault(value, value)
            elif event == "string" and len(value) >= 32:
                previous = strings.get(value)
                if previous is not None:
                    value = previous
                    strings.move_to_end(value)
                else:
                    size = sys.getsizeof(value)
                    if size <= 1024 * 1024:
                        strings[value] = value
                        string_bytes += size
                        while string_bytes > 32 * 1024 * 1024 or len(strings) > 16384:
                            _, removed = strings.popitem(last=False)
                            string_bytes -= sys.getsizeof(removed)
            builder.event(event, float(value) if isinstance(value, Decimal) else value)
    from .shared_objects import decode_storage

    return decode_storage(builder.value)


def read_report(path: Path, *, strict: bool = False, immutable: bool = False) -> Any:
    """Read complete legacy/shared data; optionally share immutable containers."""
    value = _read_report(path, strict=strict)
    if immutable:
        from .frozen_objects import frozen_view

        return frozen_view(value)
    return value


def _read_report(path: Path, *, strict: bool = False) -> Any:
    """Read legacy or shared storage without altering the logical report.

    Replay artifacts require strict duplicate-key and finite-number validation.
    Their historical strict reader is retained before shared graph decoding.
    """
    from .shared_objects import decode_storage

    path = Path(path)
    if strict:
        def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON key: {key}")
                result[key] = item
            return result

        def finite_constant(value: str) -> None:
            raise ValueError(f"non-finite JSON value: {value}")

        payload = json.loads(path.read_text(encoding="utf-8"),
                             object_pairs_hook=unique_pairs, parse_constant=finite_constant)
        return decode_storage(payload)
    if path.stat().st_size >= 16 * 1024 * 1024:
        return read_json_streaming(path)
    return decode_storage(json.loads(path.read_text(encoding="utf-8")))


def write_report_atomic(path: Path, payload: Any) -> dict[str, float]:
    from .shared_objects import ObjectEncoder

    started = time.monotonic()
    envelope = ObjectEncoder().envelope(payload)
    assembled = time.monotonic()
    timings = write_json_atomic(path, envelope, compact=True)
    timings["object_table_seconds"] = assembled - started
    timings["total_seconds"] = time.monotonic() - started
    # Timing is recorded after fsync without rewriting the report.
    write_json_atomic(Path(path).with_suffix(".timings.json"), timings)
    return timings


def write_json_atomic(
    path: Path, payload: Any, *, shared: bool = False, compact: bool = False
) -> dict[str, float]:
    if shared:
        from .shared_objects import ObjectEncoder

        payload = ObjectEncoder().envelope(payload)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".report-", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        serialization = 0.0
        writing = 0.0
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            encoder = json.JSONEncoder(
                ensure_ascii=False,
                indent=None if shared or compact else 2,
                separators=(",", ":") if shared or compact else None,
                allow_nan=False,
            )
            chunks = []
            buffered_chars = 0
            started = time.monotonic()
            for chunk in encoder.iterencode(payload):
                chunks.append(chunk)
                buffered_chars += len(chunk)
                if len(chunks) < 1024 and buffered_chars < 64 * 1024:
                    continue
                text = "".join(chunks)
                serialization += time.monotonic() - started
                started = time.monotonic()
                stream.write(text)
                writing += time.monotonic() - started
                chunks.clear()
                buffered_chars = 0
                started = time.monotonic()
            text = "".join(chunks)
            serialization += time.monotonic() - started
            started = time.monotonic()
            stream.write(text + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            writing += time.monotonic() - started
        started = time.monotonic()
        temporary.replace(path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        writing += time.monotonic() - started
        return {"serialization_seconds": serialization, "write_seconds": writing}
    finally:
        temporary.unlink(missing_ok=True)
