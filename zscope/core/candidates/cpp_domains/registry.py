"""Deterministic C/C++ detector plan assembly and execution."""

from __future__ import annotations

from functools import lru_cache
from typing import Tuple

from . import (
    concurrency_shared_state,
    memory_bounds_integer,
    protocol_ownership_logic,
    resource_lifecycle,
)
from .models import DetectorEngine, DetectorPhase, DetectorStage

_DOMAIN_MODULES = (
    resource_lifecycle,
    memory_bounds_integer,
    concurrency_shared_state,
    protocol_ownership_logic,
)


@lru_cache(maxsize=None)
def detector_plan(engine: DetectorEngine, phase: DetectorPhase) -> Tuple[DetectorStage, ...]:
    """Return the immutable, globally ordered plan for one facade phase."""

    stages = tuple(
        stage
        for module in _DOMAIN_MODULES
        for stage in module.STAGES
        if stage.engine == engine and stage.phase == phase
    )
    orders = [stage.order for stage in stages]
    if len(orders) != len(set(orders)):
        raise RuntimeError(f"duplicate detector order for {engine}/{phase}: {orders}")
    names = [stage.name for stage in stages]
    if len(names) != len(set(names)):
        raise RuntimeError(f"duplicate detector name for {engine}/{phase}: {names}")
    return tuple(sorted(stages, key=lambda stage: stage.order))


def run_detector_plan(engine: DetectorEngine, phase: DetectorPhase, context: object) -> None:
    """Execute registered stages in the exact legacy rule-call order."""

    for stage in detector_plan(engine, phase):
        stage.run(context)
