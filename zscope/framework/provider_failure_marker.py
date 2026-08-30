"""Minimal live-runtime writer for the P6 typed provider failure marker.

The product CLI cannot import the answer-isolated ``zscope.benchmarking``
package.  This module therefore owns only the fixed, body-free side-channel
writer needed by the scanner process; benchmark-side validation remains in
``zscope.benchmarking.provider_runtime``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .llm_client import PROVIDER_FAILURE_CLASSES


P6_PROVIDER_FAILURE_SCHEMA_VERSION = "zscope.p6-provider-failure.v1"
P6_PROVIDER_FAILURE_CONTAINER_PATH = "/zscope-output/p6-scan-failure.json"
P6_PROVIDER_FAILURE_FILENAME = "p6-scan-failure.json"


def write_p6_provider_failure_marker(path: Path, *, failure_class: str) -> None:
    """Exclusively write the fixed three-field marker without free text."""

    target = Path(path)
    if target.as_posix() != P6_PROVIDER_FAILURE_CONTAINER_PATH:
        raise ValueError("P6 provider failure marker path is invalid")
    if failure_class not in PROVIDER_FAILURE_CLASSES:
        raise ValueError("P6 provider failure class is invalid")
    payload = (
        json.dumps(
            {
                "schema_version": P6_PROVIDER_FAILURE_SCHEMA_VERSION,
                "failure_class": failure_class,
                "failure_count": 1,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short provider failure marker write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "P6_PROVIDER_FAILURE_CONTAINER_PATH",
    "P6_PROVIDER_FAILURE_FILENAME",
    "P6_PROVIDER_FAILURE_SCHEMA_VERSION",
    "write_p6_provider_failure_marker",
]
