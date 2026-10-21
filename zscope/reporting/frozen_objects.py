"""Immutable views for consumers that only inspect shared evidence.

One decoded container per content object keeps repeated read-only traversals
from materializing the expanded logical report. Explicit deepcopy returns the
ordinary independently mutable view; the default public reader is unchanged.
"""

from __future__ import annotations

from typing import Any, cast

from .shared_objects import ObjectDecoder, ObjectEncoder, SharedDict, SharedList


def _immutable(*args: Any, **kwargs: Any) -> Any:
    raise TypeError("immutable report view; deepcopy before modifying")


class FrozenDict(SharedDict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> SharedDict:
        result = SharedDict(cast(FrozenDecoder, self._decoder).mutable_decoder(), self._body)
        memo[id(self)] = result
        return result


class FrozenList(SharedList):
    __setitem__ = __delitem__ = append = extend = insert = pop = clear = remove = _immutable
    reverse = sort = __iadd__ = __imul__ = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> SharedList:
        result = SharedList(cast(FrozenDecoder, self._decoder).mutable_decoder(), self._body)
        memo[id(self)] = result
        return result


class FrozenDecoder(ObjectDecoder):
    def __init__(self, envelope: dict[str, Any]) -> None:
        self._decoded: dict[str, Any] = {}
        self._mutable: ObjectDecoder | None = None
        self._envelope = envelope
        super().__init__(envelope)

    def decode(self, encoded: list[Any]) -> Any:
        kind, body = encoded
        if kind == "ref":
            if body not in self._decoded:
                self._decoded[body] = self.decode(self.objects[body])
            return self._decoded[body]
        if kind == "map":
            return FrozenDict(self, body)
        if kind == "list":
            return FrozenList(self, body)
        return body

    def mutable_decoder(self) -> ObjectDecoder:
        if self._mutable is None:
            self._mutable = ObjectDecoder(self._envelope)
        return self._mutable


def frozen_view(value: Any) -> Any:
    """Snapshot a JSON value without removing fields or changing their order."""
    if isinstance(value, (FrozenDict, FrozenList)):
        return value
    return FrozenDecoder(ObjectEncoder().envelope(value)).root
