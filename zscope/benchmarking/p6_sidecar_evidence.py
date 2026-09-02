"""Immutable answer-free P6 usage and decision-trace evidence helpers.

The cold producer's JSONL usage ledger and complete decision-trace object graph
must survive the freeze boundary.  This module stores the trace graph in one
closed JSON envelope so GitHub artifacts remain flat while every original
relative path, byte length, SHA-256, and manifest count stays independently
reconstructable.  It never reads Truth, expected answers, prompts, responses,
or provider credentials.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


TRACE_SIDECAR_EVIDENCE_VERSION = "zscope.p6-trace-sidecar-evidence.v1"
TRACE_SIDECAR_EVIDENCE_FILENAME = "trace-sidecars.json"
USAGE_EVENTS_EVIDENCE_FILENAME = "llm_usage_events.jsonl"

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_TRACE_DIRECTORIES = frozenset(
    {"decision_traces", "coverage_traces", "evidence_objects", "model_events"}
)
_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_BYTES = 1024 * 1024 * 1024


class P6SidecarEvidenceError(ValueError):
    """A trace evidence envelope is malformed, unsafe, or incomplete."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_value(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _json_object(payload: bytes, *, field: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise P6SidecarEvidenceError(f"{field} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise P6SidecarEvidenceError(f"{field} must contain one object")
    return value


def _manifest_name(value: Any) -> str:
    raw = str(value or "")
    if not raw or "\\" in raw or PurePosixPath(raw).name != raw or raw in {".", ".."}:
        raise P6SidecarEvidenceError("decision-trace manifest path is invalid")
    return raw


def _trace_relative_path(value: Any) -> str:
    raw = str(value or "")
    path = PurePosixPath(raw)
    if (
        not raw
        or "\\" in raw
        or path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0] not in _TRACE_DIRECTORIES
    ):
        raise P6SidecarEvidenceError("decision-trace sidecar path is invalid")
    return raw


def _expected_trace_members(manifest: Mapping[str, Any]) -> set[str]:
    selected: set[str] = set()
    for collection_name in ("traces", "coverage_traces"):
        collection = manifest.get(collection_name)
        if not isinstance(collection, Mapping):
            raise P6SidecarEvidenceError("decision-trace manifest is incomplete")
        for key, row in collection.items():
            if not isinstance(key, str) or not key or not isinstance(row, Mapping):
                raise P6SidecarEvidenceError("decision-trace manifest row is invalid")
            relative = _trace_relative_path(row.get("path"))
            if relative in selected:
                raise P6SidecarEvidenceError("decision-trace sidecar path is duplicated")
            selected.add(relative)
    for field, directory in (
        ("evidence_object_sha256", "evidence_objects"),
        ("model_event_sha256", "model_events"),
    ):
        digests = manifest.get(field)
        if (
            not isinstance(digests, list)
            or any(not isinstance(item, str) or _SHA256_RE.fullmatch(item) is None for item in digests)
            or len(digests) != len(set(digests))
        ):
            raise P6SidecarEvidenceError("decision-trace object manifest is invalid")
        for digest in digests:
            relative = f"{directory}/{digest}.json"
            if relative in selected:
                raise P6SidecarEvidenceError("decision-trace sidecar path is duplicated")
            selected.add(relative)
    expected_counts = {
        "trace_count": len(manifest.get("traces") or {}),
        "coverage_trace_count": len(manifest.get("coverage_traces") or {}),
        "evidence_object_count": len(manifest.get("evidence_object_sha256") or []),
        "model_event_count": len(manifest.get("model_event_sha256") or []),
    }
    for field, expected in expected_counts.items():
        value = manifest.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            raise P6SidecarEvidenceError("decision-trace manifest counts do not conserve")
    if manifest.get("complete") is not True:
        raise P6SidecarEvidenceError("decision-trace manifest is incomplete")
    return selected


def build_trace_sidecar_evidence(
    *,
    manifest_path: str,
    manifest_payload: bytes,
    sidecar_payloads: Mapping[str, bytes],
) -> dict[str, Any]:
    """Build one deterministic, path-safe envelope from exact producer bytes."""

    manifest_name = _manifest_name(manifest_path)
    manifest = _json_object(manifest_payload, field="decision-trace manifest")
    expected = _expected_trace_members(manifest)
    if set(sidecar_payloads) != expected:
        raise P6SidecarEvidenceError("decision-trace sidecar set is incomplete")
    payloads: dict[str, bytes] = {manifest_name: bytes(manifest_payload)}
    for raw_path, payload in sidecar_payloads.items():
        path = _trace_relative_path(raw_path)
        if path in payloads:
            raise P6SidecarEvidenceError("decision-trace member path is duplicated")
        payloads[path] = bytes(payload)
    total = sum(len(payload) for payload in payloads.values())
    if total > _MAX_TOTAL_BYTES or any(len(payload) > _MAX_MEMBER_BYTES for payload in payloads.values()):
        raise P6SidecarEvidenceError("decision-trace evidence exceeds the size limit")
    members = [
        {
            "path": path,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
        }
        for path, payload in sorted(payloads.items())
    ]
    member_bindings = [
        {"path": row["path"], "sha256": row["sha256"], "size": row["size"]}
        for row in members
    ]
    value: dict[str, Any] = {
        "schema_version": TRACE_SIDECAR_EVIDENCE_VERSION,
        "decision_trace_manifest_path": manifest_name,
        "decision_trace_manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "member_count": len(members),
        "members_sha256": _sha256_value(member_bindings),
        "trace_count": int(manifest["trace_count"]),
        "coverage_trace_count": int(manifest["coverage_trace_count"]),
        "evidence_object_count": int(manifest["evidence_object_count"]),
        "model_event_count": int(manifest["model_event_count"]),
        "members": members,
        "answer_material_present": False,
    }
    value["content_sha256"] = _sha256_value(value)
    validate_trace_sidecar_evidence(value)
    return value


def validate_trace_sidecar_evidence(value: Mapping[str, Any]) -> dict[str, bytes]:
    """Validate an envelope and return its exact path-to-byte mapping."""

    expected_fields = {
        "schema_version",
        "decision_trace_manifest_path",
        "decision_trace_manifest_sha256",
        "member_count",
        "members_sha256",
        "trace_count",
        "coverage_trace_count",
        "evidence_object_count",
        "model_event_count",
        "members",
        "answer_material_present",
        "content_sha256",
    }
    if set(value) != expected_fields or value.get("schema_version") != TRACE_SIDECAR_EVIDENCE_VERSION:
        raise P6SidecarEvidenceError("trace sidecar evidence fields are invalid")
    unsigned = dict(value)
    supplied = unsigned.pop("content_sha256", None)
    if not isinstance(supplied, str) or supplied != _sha256_value(unsigned):
        raise P6SidecarEvidenceError("trace sidecar evidence content digest is invalid")
    if value.get("answer_material_present") is not False:
        raise P6SidecarEvidenceError("trace sidecar evidence is not answer-free")
    manifest_name = _manifest_name(value.get("decision_trace_manifest_path"))
    rows = value.get("members")
    if not isinstance(rows, list) or isinstance(value.get("member_count"), bool) or value.get("member_count") != len(rows):
        raise P6SidecarEvidenceError("trace sidecar evidence member count is invalid")
    payloads: dict[str, bytes] = {}
    bindings: list[dict[str, Any]] = []
    total = 0
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256", "size", "payload_base64"}:
            raise P6SidecarEvidenceError("trace sidecar evidence member is invalid")
        raw_path = row.get("path")
        path = manifest_name if raw_path == manifest_name else _trace_relative_path(raw_path)
        if path in payloads:
            raise P6SidecarEvidenceError("trace sidecar evidence member is duplicated")
        size = row.get("size")
        digest = row.get("sha256")
        encoded = row.get("payload_base64")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > _MAX_MEMBER_BYTES
            or not isinstance(digest, str)
            or _SHA256_RE.fullmatch(digest) is None
            or not isinstance(encoded, str)
        ):
            raise P6SidecarEvidenceError("trace sidecar evidence member binding is invalid")
        try:
            payload = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise P6SidecarEvidenceError("trace sidecar evidence payload is invalid") from exc
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
            raise P6SidecarEvidenceError("trace sidecar evidence member digest is invalid")
        total += len(payload)
        if total > _MAX_TOTAL_BYTES:
            raise P6SidecarEvidenceError("trace sidecar evidence exceeds the size limit")
        payloads[path] = payload
        bindings.append({"path": path, "sha256": digest, "size": size})
    if value.get("members_sha256") != _sha256_value(bindings):
        raise P6SidecarEvidenceError("trace sidecar evidence member manifest is invalid")
    manifest_payload = payloads.get(manifest_name)
    if manifest_payload is None or hashlib.sha256(manifest_payload).hexdigest() != value.get(
        "decision_trace_manifest_sha256"
    ):
        raise P6SidecarEvidenceError("trace sidecar evidence manifest binding is invalid")
    manifest = _json_object(manifest_payload, field="decision-trace manifest")
    expected_sidecars = _expected_trace_members(manifest)
    if set(payloads) != {manifest_name, *expected_sidecars}:
        raise P6SidecarEvidenceError("trace sidecar evidence graph is incomplete")
    for field in (
        "trace_count",
        "coverage_trace_count",
        "evidence_object_count",
        "model_event_count",
    ):
        if isinstance(value.get(field), bool) or value.get(field) != manifest.get(field):
            raise P6SidecarEvidenceError("trace sidecar evidence counts do not conserve")
    return payloads


def materialize_trace_sidecar_evidence(
    value: Mapping[str, Any], *, destination: Path
) -> dict[str, Path]:
    """Materialize validated bytes under a fresh private directory."""

    payloads = validate_trace_sidecar_evidence(value)
    root = Path(destination)
    if root.exists() or root.is_symlink():
        raise P6SidecarEvidenceError("trace evidence destination already exists")
    root.mkdir(mode=0o700, parents=True)
    written: dict[str, Path] = {}
    try:
        for relative, payload in sorted(payloads.items()):
            pure = PurePosixPath(relative)
            target = root.joinpath(*pure.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written_count = os.write(descriptor, view)
                    if written_count <= 0:
                        raise OSError("short trace sidecar write")
                    view = view[written_count:]
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise OSError("trace sidecar is not a regular file")
            finally:
                os.close(descriptor)
            written[relative] = target
        return written
    except BaseException:
        import shutil

        shutil.rmtree(root, ignore_errors=True)
        raise


__all__ = [
    "P6SidecarEvidenceError",
    "TRACE_SIDECAR_EVIDENCE_FILENAME",
    "TRACE_SIDECAR_EVIDENCE_VERSION",
    "USAGE_EVENTS_EVIDENCE_FILENAME",
    "build_trace_sidecar_evidence",
    "materialize_trace_sidecar_evidence",
    "validate_trace_sidecar_evidence",
]
