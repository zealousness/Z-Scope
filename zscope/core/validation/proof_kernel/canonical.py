"""Canonical JSON and content-addressing helpers for proof artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, Mapping, Tuple


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def seal_mapping(payload: Mapping[str, Any], *, uid_field: str, prefix: str) -> Dict[str, Any]:
    """Add a deterministic UID and hash without a self-reference."""

    if uid_field in payload or "content_sha256" in payload:
        raise ValueError("proof payload already contains a seal field")
    normalized = dict(payload)
    uid = prefix + content_sha256(normalized)[:32]
    body = {**normalized, uid_field: uid}
    return {**body, "content_sha256": content_sha256(body)}


def verify_sealed_mapping(
    raw: Mapping[str, Any],
    *,
    uid_field: str,
    prefix: str,
    expected_keys: Iterable[str],
) -> Tuple[bool, str]:
    keys = set(raw)
    expected = set(expected_keys)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        return False, f"schema_keys_mismatch:missing={missing}:extra={extra}"
    supplied_hash = str(raw.get("content_sha256") or "")
    supplied_uid = str(raw.get(uid_field) or "")
    if not SHA256_RE.fullmatch(supplied_hash):
        return False, "invalid_content_sha256"
    body = dict(raw)
    body.pop("content_sha256", None)
    if content_sha256(body) != supplied_hash:
        return False, "content_sha256_mismatch"
    uid_payload = dict(body)
    uid_payload.pop(uid_field, None)
    expected_uid = prefix + content_sha256(uid_payload)[:32]
    if supplied_uid != expected_uid:
        return False, "content_uid_mismatch"
    return True, "ok"
