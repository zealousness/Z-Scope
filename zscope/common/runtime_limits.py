"""Runtime resource-limit helpers."""

from __future__ import annotations

import logging
import sys
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_LINUX_NOFILE_LIMIT = 65535


def ensure_linux_nofile_limit(target: int = DEFAULT_LINUX_NOFILE_LIMIT) -> bool:
    """Raise Linux RLIMIT_NOFILE soft limit before scan-heavy work starts.

    Returns True when the soft limit was changed. The hard limit is preserved,
    so non-root users get the highest limit their current session permits.
    """
    if not sys.platform.startswith("linux"):
        return False

    try:
        import resource
    except ImportError:
        logger.debug("Python resource module is unavailable; cannot set RLIMIT_NOFILE.")
        return False

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            logger.debug("Linux open-file soft limit is already unlimited.")
            return False
        desired = _desired_soft_limit(target, hard, resource.RLIM_INFINITY)
        if soft >= desired:
            if soft < target:
                logger.warning(
                    "Linux open-file soft limit is %s, below target %s; hard limit is %s.",
                    soft,
                    target,
                    _limit_for_log(hard, resource.RLIM_INFINITY),
                )
            return False

        resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
        if desired < target:
            logger.warning(
                "Raised Linux open-file soft limit from %s to hard-limit cap %s "
                "(target %s).",
                soft,
                desired,
                target,
            )
        else:
            logger.info("Raised Linux open-file soft limit from %s to %s.", soft, desired)
        return True
    except (OSError, ValueError) as exc:
        logger.warning("Unable to raise Linux open-file limit to %s: %s", target, exc)
        return False


def _desired_soft_limit(target: int, hard: int, rlim_infinity: Any) -> int:
    target = max(1, int(target or DEFAULT_LINUX_NOFILE_LIMIT))
    if hard == rlim_infinity:
        return target
    return min(target, int(hard))


def _limit_for_log(limit: int, rlim_infinity: Any) -> str:
    if limit == rlim_infinity:
        return "unlimited"
    return str(limit)
