"""Stable read-only mapping for historical usage dimensions."""

from __future__ import annotations

import re


_LEGACY_USAGE_STAGE_MAP = {
    "vulnerability": "hypothesis_hunter",
    "vulnerability_analyzer": "hypothesis_hunter",
    "deep_worker": "hypothesis_hunter",
    "deepworker": "hypothesis_hunter",
    "discovery": "hypothesis_hunter",
    "active_discovery": "hypothesis_hunter",
    "semantic": "security_spec_miner",
    "semantic_modeler": "security_spec_miner",
    "global": "security_spec_miner",
    "global_modeler": "security_spec_miner",
    "enricher": "security_spec_miner",
    "semantic_enricher": "security_spec_miner",
    "validator": "proof_engine",
    "validator_agent": "proof_engine",
    "issue_reconciler": "history_maintenance_agent",
    "issue_reconciler_agent": "history_maintenance_agent",
}


def map_legacy_usage_stage(value: str) -> str:
    """Map a historical usage label to the Z-Scope 2.0 accounting stage."""

    normalized = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    return _LEGACY_USAGE_STAGE_MAP.get(normalized, normalized)
