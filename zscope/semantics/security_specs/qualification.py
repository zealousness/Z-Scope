"""Load the independently generated P3 qualification authority artifact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import content_sha256
from .compiler import SecuritySpecCompiler
from .models import validate_qualification
from .registry import registry_manifest


BUILTIN_QUALIFICATION_PATH = (
    Path(__file__).with_name("qualification") / "p3-security-spec-qualification.json"
)


def load_builtin_qualification() -> dict[str, Any]:
    raw = json.loads(BUILTIN_QUALIFICATION_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("builtin_security_spec_qualification_not_object")
    valid, reason = validate_qualification(raw)
    if not valid:
        raise ValueError("builtin_security_spec_qualification_invalid:" + reason)
    if raw["registry_sha256"] != content_sha256(registry_manifest()):
        raise ValueError("builtin_security_spec_registry_qualification_stale")
    if raw["compiler_sha256"] != content_sha256(
        {"compiler_version": SecuritySpecCompiler.compiler_version}
    ):
        raise ValueError("builtin_security_spec_compiler_qualification_stale")
    return raw
