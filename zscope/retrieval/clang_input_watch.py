"""Parallel live-stat gate over scoped input stamps for the type collector.

Every verification live-stats its scope (OSError -> ``None``, matching
``input_stamp``), so a change is observed exactly when the gate runs — the
same guarantee as the original per-check full sweep, just scoped to the
function's dependency footprint instead of the whole project inventory.

A short TTL lets identical *pre-flight* scopes skip an immediate
re-verification (the scheduler registers a job, then the collector re-checks
it at collection entry). Correctness boundaries — after collection and
before publication — must pass ``verify=True``, which never skips and never
trusts a previous pass.

The exact invalidation backstop remains unchanged: receipt validation at
every task boundary live-stats the files a collection actually read, and
``DerivedSourceSnapshots.validate_used`` revalidates them when the file scope
closes.
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, Optional

from .clang_resolution import input_stamp

logger = logging.getLogger(__name__)

Stamp = Optional[tuple[int, int, int, int]]


def _env_int(name: str, default: int) -> int:
    try:
        value = int(str(os.environ.get(name, "") or default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


class InputStampWatch:
    """Baseline input stamps with parallel live verification helpers."""

    def __init__(
        self,
        baseline: Dict[Path, Stamp],
        *,
        stat_workers: Optional[int] = None,
    ):
        if stat_workers is None:
            stat_workers = _env_int("ZSCOPE_TYPE_INPUT_STAT_WORKERS", 16)
        self.stat_workers = max(1, int(stat_workers))
        self._baseline: Dict[Path, Stamp] = dict(baseline)
        self._extra_baseline: Dict[Path, Stamp] = {}
        self._lock = threading.Lock()
        self.generation = 0
        self.stats: Dict[str, int] = {
            "baseline_paths": len(self._baseline),
            "verifications": 0,
            "parallel_verifications": 0,
            "live_stats": 0,
            "changes_detected": 0,
        }

    def changed(self, paths: Iterable[Path]) -> bool:
        """Live-verify a scope; True when any path differs from its baseline.

        Paths discovered after the session baseline record their first
        sighting as the baseline. Changes before that first sighting are
        covered by receipt validation, which live-stats what was read.
        """
        with self._lock:
            self.stats["verifications"] = int(self.stats["verifications"]) + 1
            changed = 0
            for path in paths:
                if path in self._baseline:
                    baseline = self._baseline[path]
                else:
                    baseline = self._extra_baseline.get(path)
                    if baseline is None and path not in self._extra_baseline:
                        self._extra_baseline[path] = input_stamp(path)
                        self.stats["live_stats"] = int(self.stats["live_stats"]) + 1
                        continue
                self.stats["live_stats"] = int(self.stats["live_stats"]) + 1
                if input_stamp(path) != baseline:
                    changed += 1
            if changed:
                self.stats["changes_detected"] = int(self.stats["changes_detected"]) + changed
                self.generation += 1
            return bool(changed)

    def changed_parallel(self, paths: Iterable[Path]) -> bool:
        """Live-verify a large scope (whole inventory fallback) in parallel."""
        path_list = list(paths)
        stamps = self._parallel_stamps(path_list)
        with self._lock:
            self.stats["parallel_verifications"] = (
                int(self.stats["parallel_verifications"]) + 1
            )
            self.stats["live_stats"] = int(self.stats["live_stats"]) + len(path_list)
            changed = 0
            for path in path_list:
                if path in self._baseline:
                    baseline = self._baseline[path]
                else:
                    # First sighting: the current stamp becomes the baseline.
                    baseline = self._extra_baseline.setdefault(path, stamps[path])
                if stamps[path] != baseline:
                    changed += 1
            if changed:
                self.stats["changes_detected"] = int(self.stats["changes_detected"]) + changed
                self.generation += 1
            return bool(changed)

    def _parallel_stamps(self, paths: list[Path]) -> Dict[Path, Stamp]:
        if len(paths) <= 1 or self.stat_workers <= 1:
            return {path: input_stamp(path) for path in paths}
        workers = min(self.stat_workers, len(paths))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="InputStamp") as pool:
            return {path: stamp for path, stamp in zip(paths, pool.map(input_stamp, paths))}
