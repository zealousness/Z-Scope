from __future__ import annotations

import threading

from zscope.orchestration.scheduler import (
    ENTRY_ROLE,
    INVESTIGATOR_ROLE,
    VALIDATOR_ROLE,
    ScanScheduler,
)


def test_scan_scheduler_uses_one_bounded_pool_per_role() -> None:
    scheduler = ScanScheduler(
        entry_workers=2,
        validator_workers=1,
        investigator_workers=1,
    )
    try:
        futures = [
            scheduler.submit(ENTRY_ROLE, lambda: threading.current_thread().name),
            scheduler.submit(VALIDATOR_ROLE, lambda: threading.current_thread().name),
            scheduler.submit(INVESTIGATOR_ROLE, lambda: threading.current_thread().name),
        ]
        names = [future.result(timeout=2) for future in futures]
    finally:
        scheduler.shutdown()

    assert names[0].startswith("zscope-entry-")
    assert names[1].startswith("zscope-validator-")
    assert names[2].startswith("zscope-investigator-")


def test_scan_scheduler_honors_priority_for_queued_work() -> None:
    scheduler = ScanScheduler(
        entry_workers=1,
        validator_workers=1,
        investigator_workers=1,
    )
    gate = threading.Event()
    order: list[str] = []
    try:
        blocker = scheduler.submit(
            ENTRY_ROLE,
            lambda: gate.wait(timeout=2),
            priority=100,
        )
        low = scheduler.submit(ENTRY_ROLE, lambda: order.append("low"), priority=1)
        high = scheduler.submit(ENTRY_ROLE, lambda: order.append("high"), priority=10)
        gate.set()
        blocker.result(timeout=2)
        high.result(timeout=2)
        low.result(timeout=2)
    finally:
        scheduler.shutdown()

    assert order == ["high", "low"]
