"""Public P5 scan-depth contract for Hypothesis Hunter scheduling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class HuntingProfile:
    name: str
    risk_threshold: int
    max_units: Optional[int]


_PROFILES = {
    "fast": HuntingProfile("fast", 101, 0),
    "balanced": HuntingProfile("balanced", 60, None),
    "deep": HuntingProfile("deep", 35, None),
}


def resolve_hunting_profile(config: Any) -> HuntingProfile:
    """Resolve only the public ``scan.depth`` field; no legacy rollout switch."""

    depth = str(getattr(getattr(config, "scan", None), "depth", "fast") or "fast")
    return _PROFILES.get(depth.strip().lower(), _PROFILES["fast"])
