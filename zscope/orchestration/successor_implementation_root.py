"""Lightweight content root for the current successor implementation.

This module deliberately depends only on the standard library and packaged
resources.  Both the offline qualification builder and the live review latch
use the same reducer, so a reviewed status cannot survive a source or packaged
resource change while the live import path remains independent of benchmark
and LLM runtime modules.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from typing import Any, Iterator, Mapping, Tuple


P6_IMPLEMENTATION_ROOT_VERSION = "zscope.successor-implementation-root.v1"

IMPLEMENTATION_ROOT_EXCLUDED_PATHS = frozenset(
    {
        # Historical governance remains immutable but cannot authorize a new
        # implementation candidate.
        "zscope/orchestration/p5-release-status.json",
        # Historical P4 corpus summaries are verified in the control plane and
        # represented in the successor by their frozen dependency identity.
        # They are not live scanner implementation material and are physically
        # absent from the P6 producer/OCI tree.
        "zscope/orchestration/hypothesis_hunter/qualification/qualification-artifact.json",
        "zscope/orchestration/hypothesis_hunter/qualification/qualification-artifact.v2.json",
        # Truth-contract helpers belong to the scoring/control plane and are
        # never mounted into the answer-free scanner runtime.
        "zscope/benchmarking/truth_contract.py",
        # Generated evidence is bound by content hash outside the source root.
        # Excluding it prevents a self-referential digest cycle.
        "zscope/orchestration/p6-proof-promotion-qualification.v1.json",
        "zscope/orchestration/successor-runtime-review-status.v1.json",
        "zscope/orchestration/successor-runtime-review-integration-receipt.v1.json",
    }
)
IMPLEMENTATION_ROOT_EXCLUDED_PREFIXES = (
    # A later evidence-only integration stores the byte-exact reviewed bundle
    # here.  It is validated independently and must not create a digest cycle
    # in the implementation root it attests.
    "zscope/orchestration/successor-runtime-review-evidence/",
)
_NON_SOURCE_CACHE_SUFFIXES = (".pyc", ".pyo")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _content_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _implementation_path_excluded(relative: str, *, name: str) -> bool:
    return (
        name == "__pycache__"
        or relative in IMPLEMENTATION_ROOT_EXCLUDED_PATHS
        or relative.startswith(IMPLEMENTATION_ROOT_EXCLUDED_PREFIXES)
        or name.endswith(_NON_SOURCE_CACHE_SUFFIXES)
    )


def _iter_implementation_paths() -> Iterator[str]:
    root = resources.files("zscope")

    def walk(node: Any, prefix: str) -> Iterator[str]:
        for child in sorted(node.iterdir(), key=lambda value: value.name):
            relative = f"{prefix}/{child.name}"
            if _implementation_path_excluded(relative, name=child.name):
                continue
            if child.is_dir():
                yield from walk(child, relative)
            elif child.is_file():
                yield relative

    yield from walk(root, "zscope")


# A newly packaged scanner, prompt, rule, adapter, or authority file therefore
# changes the root without requiring a hand-maintained allowlist.
SOURCE_BOUND_PATHS: Tuple[str, ...] = tuple(_iter_implementation_paths())


def _resource_bytes(relative: str) -> bytes:
    parts = relative.split("/")
    if not parts or parts[0] != "zscope" or any(not value for value in parts):
        raise ValueError("successor_qualification_source_path_invalid")
    current = resources.files("zscope")
    for part in parts[1:]:
        current = current.joinpath(part)
    return current.read_bytes()


def current_source_hashes() -> dict[str, str]:
    return {path: hashlib.sha256(_resource_bytes(path)).hexdigest() for path in SOURCE_BOUND_PATHS}


def implementation_root_sha256(source_hashes: Mapping[str, str]) -> str:
    if set(source_hashes) != set(SOURCE_BOUND_PATHS):
        raise ValueError("successor_implementation_source_set_mismatch")
    return implementation_inventory_root_sha256(source_hashes)


def implementation_inventory_root_sha256(source_hashes: Mapping[str, str]) -> str:
    """Hash an already sealed, explicit implementation inventory.

    The control plane first proves that the inventory equals its complete
    candidate package.  A physically reduced producer tree can then revalidate
    its present files against that same inventory without reintroducing the
    excluded control-plane evidence into OCI.
    """

    if not source_hashes:
        raise ValueError("successor_implementation_source_set_mismatch")
    paths = tuple(sorted(source_hashes))
    if any(
        not path.startswith("zscope/")
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        for path in paths
    ):
        raise ValueError("successor_implementation_source_path_invalid")
    rows = [{"path": path, "sha256": str(source_hashes[path])} for path in paths]
    if any(_SHA256_RE.fullmatch(row["sha256"]) is None for row in rows):
        raise ValueError("successor_implementation_source_hash_invalid")
    return _content_sha256(
        {
            "schema_version": P6_IMPLEMENTATION_ROOT_VERSION,
            "files": rows,
        }
    )


def current_implementation_root_sha256() -> str:
    return implementation_root_sha256(current_source_hashes())


__all__ = [
    "IMPLEMENTATION_ROOT_EXCLUDED_PATHS",
    "IMPLEMENTATION_ROOT_EXCLUDED_PREFIXES",
    "P6_IMPLEMENTATION_ROOT_VERSION",
    "SOURCE_BOUND_PATHS",
    "current_implementation_root_sha256",
    "current_source_hashes",
    "implementation_inventory_root_sha256",
    "implementation_root_sha256",
]
