"""Read and verify the current Hypothesis Hunter qualification artifact."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from ...core.validation.proof_kernel.canonical import content_sha256


P4_HYPOTHESIS_QUALIFICATION_SHA256 = (
    "059377eff0b4abd2ffbc0e0c890b80959885406d9ada5c0c295c6d90daeea010"
)


def load_builtin_qualification() -> dict[str, Any]:
    resource = files(__package__).joinpath("qualification/qualification-artifact.v2.json")
    raw = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("P4 qualification artifact must be an object")
    supplied = str(raw.get("content_sha256") or "")
    body = {key: value for key, value in raw.items() if key != "content_sha256"}
    if (
        raw.get("schema_version") != "zscope.p4-hypothesis-qualification.v2"
        or content_sha256(body) != supplied
        or int(raw.get("case_count", 0) or 0) < 120
        or int(raw.get("safe_case_count", 0) or 0) < 48
        or int(raw.get("safe_false_acceptance_count", -1)) != 0
        or int(raw.get("near_miss_false_acceptance_count", -1)) != 0
        or float(raw.get("contract_resolution_percent", 0.0) or 0.0) != 100.0
        or raw.get("metamorphic_consistent") is not True
        or len(raw.get("projects_with_replayable_proof") or []) < 3
        or supplied != P4_HYPOTHESIS_QUALIFICATION_SHA256
    ):
        raise ValueError("P4 qualification artifact failed acceptance validation")
    return raw


def qualification_identity_sha256() -> str:
    """Return the frozen dependency identity without requiring runtime evidence.

    Source/control-plane packages still revalidate the historical artifact when
    it is present.  The sealed P6 producer intentionally omits that historical
    corpus summary and consumes only this compiled dependency identity, which
    is itself bound by the current successor qualification.
    """

    try:
        raw = load_builtin_qualification()
    except FileNotFoundError:
        return P4_HYPOTHESIS_QUALIFICATION_SHA256
    supplied = str(raw.get("content_sha256") or "")
    if supplied != P4_HYPOTHESIS_QUALIFICATION_SHA256:
        raise ValueError("P4 qualification identity mismatch")
    return supplied
