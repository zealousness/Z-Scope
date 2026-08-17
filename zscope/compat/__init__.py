"""Read-only compatibility helpers for persisted Z-Scope 1.x artifacts."""

from .config import migrate_legacy_document
from .reports import read_legacy_report_view
from .usage import map_legacy_usage_stage

__all__ = [
    "map_legacy_usage_stage",
    "migrate_legacy_document",
    "read_legacy_report_view",
]
