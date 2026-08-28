"""Stable identities for Wiki objects and project-relative page slugs."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable


def stable_id(prefix: str, *parts: object, length: int = 32) -> str:
    payload = "\0".join(str(part) for part in parts)
    return f"{prefix}_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:length]}"


def slugify(value: str) -> str:
    value = str(value).strip().lower().replace("\\", "/")
    value = re.sub(r"[^a-z0-9./-]+", "-", value)
    value = re.sub(r"/{2,}", "/", value).strip("/.")
    return value or "untitled"


def digest_json(value: object) -> str:
    import json

    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


__all__ = ["stable_id", "slugify", "digest_json"]
