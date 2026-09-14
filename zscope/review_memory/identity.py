from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, value: Dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()[:24]}"


def project_id(project: Any) -> str:
    return str(getattr(project, "project_id", "") or getattr(project, "project_root", "project"))
