"""Lossless large-report reader for post-scan experiments.

Only immutable strings share storage; every JSON container stays independent.
The matcher, values, evidence, and scan source are unchanged.
"""
from __future__ import annotations
import importlib
import sys
from collections import OrderedDict
from decimal import Decimal
from pathlib import Path
from typing import Any
from zscope.reporting.json_io import require_streaming_json

def read_large_report(path: Path) -> Any:
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
            elif event == "string" and len(value) >= 1:
                previous = strings.get(value)
                if previous is not None:
                    value = previous
                    strings.move_to_end(value)
                else:
                    size = sys.getsizeof(value)
                    if size <= 1024 * 1024:
                        strings[value] = value
                        string_bytes += size
                        while string_bytes > 512 * 1024 * 1024 or len(strings) > 262144:
                            _, removed = strings.popitem(last=False)
                            string_bytes -= sys.getsizeof(removed)
            builder.event(event, float(value) if isinstance(value, Decimal) else value)
    return builder.value
