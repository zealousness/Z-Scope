"""Isolated mutable views over one immutable JSON evidence graph per ledger."""

from copy import deepcopy
import threading
from typing import Any

from .shared_objects import ObjectDecoder, ObjectEncoder, STORAGE_SCHEMA


class _JsonEncoder(ObjectEncoder):
    def encode(self, value: Any) -> list[Any]:
        # Internal callers may carry non-JSON values. Preserve their existing
        # deepcopy behavior instead of silently converting tuples or key types.
        if (
            isinstance(value, tuple)
            or (type(value) is dict and any(not isinstance(key, str) for key in value))
            or not isinstance(value, (dict, list, str, int, float, bool, type(None)))
        ):
            raise TypeError("non-JSON internal evidence")
        return super().encode(value)


class ImmutableEvidencePool:
    """Freeze terminal evidence once; every projection owns its modifications.

    Content objects only grow, never change. The encoder retains no references
    to mutable input trees after a clone, and public report serialization still
    exports every reachable object. This is not a persistent proof authority.
    """

    def __init__(self) -> None:
        self._encoder = _JsonEncoder()
        self._decoder = ObjectDecoder(
            {
                "storage_schema": STORAGE_SCHEMA,
                "objects": self._encoder.objects,
                "root": ["value", None],
            }
        )
        self._lock = threading.RLock()
        self.shared_clones = 0
        self.fallback_clones = 0

    def clone(self, value: Any) -> Any:
        with self._lock:
            try:
                node = self._encoder.encode(value)
                # Validate only the new root: earlier committed immutable nodes
                # remain checked, avoiding a full-table walk for every outcome.
                self._decoder._validate(node)
                self.shared_clones += 1
                return self._decoder.decode(node)
            except (TypeError, ValueError):
                self.fallback_clones += 1
                return deepcopy(value)
            finally:
                self._encoder._identities.clear()
