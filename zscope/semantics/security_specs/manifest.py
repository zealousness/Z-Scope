"""Strict read-only loading of a frozen authoritative Security Spec manifest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_sha256
from .lifecycle import SECURITY_SPEC_MODE
from .store import SecuritySpecObjectStore


def load_manifest_identity(root: Path, *, consumer: str) -> dict[str, Any]:
    root = Path(root)
    fallback = {
        "security_spec_mode": SECURITY_SPEC_MODE,
        "security_spec_root_manifest_sha256": "",
        "security_spec_artifact_refs": [],
        "security_spec_decision": {
            "active_product_effect": "semantic_input",
            "compiled_spec_count": 0,
            "reason_code": f"{consumer}_security_spec_manifest_unavailable",
        },
    }
    try:
        raw = json.loads((root / "security_spec_manifest.json").read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "mode",
            "artifact_refs",
            "content_sha256",
        }:
            raise ValueError("security_spec_manifest_schema_mismatch")
        body = {key: value for key, value in raw.items() if key != "content_sha256"}
        if raw.get("schema_version") != "zscope.security-spec-root-manifest.v1":
            raise ValueError("security_spec_manifest_version_mismatch")
        if raw.get("mode") != SECURITY_SPEC_MODE or content_sha256(body) != raw.get(
            "content_sha256"
        ):
            raise ValueError("security_spec_manifest_hash_or_mode_mismatch")
        refs = raw.get("artifact_refs")
        object_store = SecuritySpecObjectStore(root)
        if not isinstance(refs, list) or any(
            not object_store.verify_ref(str(value)) for value in refs
        ):
            raise ValueError("security_spec_manifest_artifact_ref_invalid")
        compiled_count = max(
            [
                len(value["payload"].get("compiled_specs") or [])
                for value in (object_store.load(str(reference)) for reference in refs)
                if value.get("kind") == "compilation" and isinstance(value.get("payload"), dict)
            ]
            or [0]
        )
        return {
            "security_spec_mode": SECURITY_SPEC_MODE,
            "security_spec_root_manifest_sha256": str(raw["content_sha256"]),
            "security_spec_artifact_refs": list(refs),
            "security_spec_decision": {
                "active_product_effect": "semantic_input",
                "compiled_spec_count": compiled_count,
                "reason_code": f"{consumer}_security_spec_manifest_loaded",
            },
        }
    except (OSError, ValueError, json.JSONDecodeError):
        return fallback
