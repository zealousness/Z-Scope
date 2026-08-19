"""Canonical JSON helpers shared by SecuritySpec artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


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


def seal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in payload:
        raise ValueError("security_spec_payload_already_sealed")
    body = dict(payload)
    return {**body, "content_sha256": content_sha256(body)}


def verify_seal(raw: Mapping[str, Any]) -> tuple[bool, str]:
    supplied = str(raw.get("content_sha256") or "")
    if SHA256_RE.fullmatch(supplied) is None:
        return False, "invalid_content_sha256"
    body = dict(raw)
    body.pop("content_sha256", None)
    if content_sha256(body) != supplied:
        return False, "content_sha256_mismatch"
    return True, "ok"
