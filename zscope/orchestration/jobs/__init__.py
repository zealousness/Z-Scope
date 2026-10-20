"""Persistent scan jobs (S08): store, control-plane service and detached owner.

The job store (``store.py``) is the single source of truth; the service
(``service.py``) exposes the contract-aligned control plane and spawns one
detached owner process per attempt (``owner.py``, run via
``python -m zscope.orchestration.jobs``).  ``scheduler_hook.py`` is the
contract the coordinator wires into the scan session runner; until then
window enforcement is owner/process-granular only.
"""

from __future__ import annotations

from .models import SCHEMA_VERSION, JobError
from .service import ScanJobService, ServiceResponse
from .store import JobStore

__all__ = [
    "SCHEMA_VERSION",
    "JobError",
    "JobStore",
    "ScanJobService",
    "ServiceResponse",
]
