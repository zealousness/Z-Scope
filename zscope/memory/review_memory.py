"""Lightweight facade for review feedback memory."""

from __future__ import annotations

from typing import Any, Dict, Optional


class ReviewMemory:
    """Proxy review-memory operations through the configured persistence store.

    The facade intentionally stays thin: it centralizes review-memory access
    without changing the storage semantics owned by ``UserConfigStore``.
    """

    def __init__(self, store: Any):
        self.store = store

    def is_false_positive(self, func_name: str, location: str, category: str) -> bool:
        return bool(self.store.is_false_positive(func_name, location, category))

    def get_finding_baseline(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        return self.store.get_finding_baseline(dedup_key)

    def get_finding_baseline_for_issue(
        self,
        issue: Dict[str, Any],
        dedup_key: str = "",
    ) -> Optional[Dict[str, Any]]:
        lookup = getattr(self.store, "get_finding_baseline_for_issue", None)
        if callable(lookup):
            return lookup(issue, dedup_key)
        key = dedup_key or str((issue or {}).get("dedup_key") or "")
        if not key:
            return None
        return self.get_finding_baseline(key)

    def upsert_finding_baseline(
        self,
        dedup_key: str,
        status: str,
        issue: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.store.upsert_finding_baseline(dedup_key, status, issue)

    def record_validator_memory(
        self,
        dedup_key: str,
        status: Optional[str],
        issue: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist validator memory when the caller produced a memory status."""
        if status:
            self.upsert_finding_baseline(dedup_key, status, issue)
