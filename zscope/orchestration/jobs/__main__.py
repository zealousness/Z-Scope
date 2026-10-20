"""Entry point for the detached job owner process.

The service spawns ``python -m zscope.orchestration.jobs --job-id ...`` with
``ZSCOPE_JOB_OWNER_TOKEN`` in the environment; the owner then owns the
scanner process group independently of the UI/service that started it.
"""

from __future__ import annotations

import sys

from .owner import main

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
