"""Lossless, self-contained JSON object graphs with copy-on-write readers.

References exist only inside the storage envelope. User dictionaries, including
ones containing similarly named keys, are encoded as ordinary map nodes.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, is_dataclass
import hashlib
import json
import weakref
from typing import Any, Iterator, cast

STORAGE_SCHEMA = "zscope.shared-json.v1"


def node_digest(node: Any) -> str:
    return hashlib.sha256(
        json.dumps(node, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class ObjectEncoder:
    def __init__(self) -> None:
        self.objects: dict[str, Any] = {}
        self._active: set[int] = set()
        self._identities: dict[int, tuple[Any, Any]] = {}

    def intern(self, node: Any) -> list[Any]:
        uid = node_digest(node)
        self.objects.setdefault(uid, node)
        return ["ref", uid]

    def encode(self, value: Any) -> list[Any]:
        if isinstance(value, (SharedDict, SharedList)) and not value._dirty:
            node = ["map" if isinstance(value, SharedDict) else "list", value._body]
            self._import_refs(node, value._decoder)
            return self.intern(node)
        if isinstance(value, (dict, list, tuple)):
            identity = id(value)
            if identity in self._active:
                raise ValueError("cyclic JSON value")
            cached = self._identities.get(identity)
            if cached is not None and cached[0] is value:
                return cast(list[Any], cached[1])
            self._active.add(identity)
            try:
                if isinstance(value, dict):
                    node = ["map", [[str(k), self.encode(v)] for k, v in value.items()]]
                else:
                    node = ["list", [self.encode(v) for v in value]]
                ref = self.intern(node)
                self._identities[identity] = (value, ref)
                return ref
            finally:
                self._active.remove(identity)
        node = ["value", value]
        return self.intern(node) if isinstance(value, str) and len(value) >= 96 else node

    def _import_refs(self, node: Any, decoder: Any) -> None:
        kind, body = node
        if kind == "ref":
            if body not in self.objects:
                original = decoder.objects[body]
                self.objects[body] = original
                self._import_refs(original, decoder)
        elif kind == "map":
            for _, child in body:
                self._import_refs(child, decoder)
        elif kind == "list":
            for child in body:
                self._import_refs(child, decoder)

    def envelope(self, value: Any) -> dict[str, Any]:
        root = self.encode(value)
        return {"storage_schema": STORAGE_SCHEMA, "root": root, "objects": self.objects}


class ObjectDecoder:
    def __init__(self, envelope: dict[str, Any]) -> None:
        if envelope.get("storage_schema") != STORAGE_SCHEMA:
            raise ValueError("unsupported shared JSON schema")
        objects = envelope.get("objects")
        if not isinstance(objects, dict):
            raise ValueError("missing shared objects")
        self.objects: dict[str, Any] = objects
        self._checked: set[str] = set()
        self._answer_free_nodes: set[str] = set()
        self._checking: set[str] = set()
        self._validate(envelope.get("root"))
        # Orphan objects are validated too; corrupt evidence is never ignored.
        for uid in self.objects:
            self._validate(["ref", uid])
        self.root_node = envelope["root"]
        self.root = self.decode(self.root_node)

    def _validate(self, value: Any) -> None:
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError("invalid shared JSON node")
        kind, body = value
        if kind == "ref":
            if not isinstance(body, str) or body not in self.objects:
                raise ValueError("missing shared JSON reference")
            if body in self._checking:
                raise ValueError("cyclic shared JSON reference")
            if body not in self._checked:
                node = self.objects[body]
                if node_digest(node) != body:
                    raise ValueError("shared JSON integrity failure")
                self._checking.add(body)
                self._validate(node)
                self._checking.remove(body)
                self._checked.add(body)
        elif kind == "map":
            if not isinstance(body, list) or any(
                not isinstance(x, list) or len(x) != 2 or not isinstance(x[0], str) for x in body
            ):
                raise ValueError("invalid shared JSON map")
            if len({x[0] for x in body}) != len(body):
                raise ValueError("duplicate shared JSON map key")
            for _, child in body:
                self._validate(child)
        elif kind == "list":
            if not isinstance(body, list):
                raise ValueError("invalid shared JSON list")
            for child in body:
                self._validate(child)
        elif kind != "value" or isinstance(body, (dict, list)):
            raise ValueError("invalid shared JSON scalar")

    def decode(self, encoded: list[Any]) -> Any:
        kind, body = encoded
        if kind == "ref":
            return self.decode(self.objects[body])
        if kind == "map":
            return SharedDict(self, body)
        if kind == "list":
            return SharedList(self, body)
        return body


def dataclass_dict(value: Any) -> dict[str, Any]:
    """Convert dataclass fields without rebuilding or expanding shared views."""
    if not is_dataclass(value) or isinstance(value, type):
        raise TypeError("dataclass_dict requires a dataclass instance")
    return {
        item.name: _dataclass_value(getattr(value, item.name))
        for item in fields(value)
    }


def _dataclass_value(value: Any) -> Any:
    if type(value) in (str, int, float, bool, type(None)):
        return value
    if isinstance(value, (SharedDict, SharedList)):
        return deepcopy(value)
    if is_dataclass(value) and not isinstance(value, type):
        return dataclass_dict(value)
    if isinstance(value, dict):
        if hasattr(type(value), "default_factory"):
            result = type(value)(getattr(value, "default_factory"))
            result.update(
                (_dataclass_value(key), _dataclass_value(item))
                for key, item in value.items()
            )
            return result
        return type(value)(
            (_dataclass_value(key), _dataclass_value(item))
            for key, item in value.items()
        )
    if isinstance(value, tuple) and hasattr(value, "_fields"):
        return type(value)(*[_dataclass_value(item) for item in value])
    if isinstance(value, (list, tuple)):
        return type(value)(_dataclass_value(item) for item in value)
    return deepcopy(value)


class _SharedChanges:
    """Read caches do not change content; nested writes invalidate ancestors."""

    _decoder: Any

    def _initialize_tracking(self) -> None:
        self._dirty = False
        self._parents: dict[int, Any] = {}

    def _decoded_child(self, encoded: list[Any]) -> Any:
        child = self._decoder.decode(encoded)
        if isinstance(child, _SharedChanges):
            child._parents[id(self)] = weakref.ref(self)
        return child

    def _mark_changed(self) -> None:
        if self._dirty:
            return
        self._dirty = True
        for reference in tuple(self._parents.values()):
            parent = reference()
            if parent is not None:
                parent._mark_changed()


class SharedDict(_SharedChanges, dict):
    """Each logical occurrence owns its mutations; encoded evidence is shared."""

    def __init__(self, decoder: ObjectDecoder, body: list[Any]) -> None:
        self._decoder, self._body = decoder, body
        self._initialize_tracking()
        self._cache: dict[str, Any] | None = None
        # Real keys preserve interoperability with C-level dict consumers.
        super().__init__((k, None) for k, _ in body)

    def _data(self) -> dict[str, Any]:
        if self._cache is None:
            self._cache = {k: self._decoded_child(v) for k, v in self._body}
        return self._cache

    def __getitem__(self, key: str) -> Any:
        return self._data()[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._mark_changed()
        self._data()[key] = value
        super().__setitem__(key, None)

    def __delitem__(self, key: str) -> None:
        self._mark_changed()
        del self._data()[key]
        super().__delitem__(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._data())

    def get(self, key: str, default: Any = None) -> Any:
        return self._data().get(key, default)

    def items(self):
        return self._data().items()

    def values(self):
        return self._data().values()

    def keys(self):
        return self._data().keys()

    def copy(self):
        return self._data().copy()

    def pop(self, key, *default):
        self._mark_changed()
        value = self._data().pop(key, *default)
        super().pop(key, None)
        return value

    def popitem(self):
        self._mark_changed()
        key, value = self._data().popitem()
        super().pop(key, None)
        return key, value

    def clear(self):
        self._mark_changed()
        self._data().clear()
        super().clear()

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

    def update(self, *args, **kwargs):
        for key, value in dict(*args, **kwargs).items():
            self[key] = value

    def __ior__(self, other):
        self.update(other)
        return self

    def __or__(self, other):
        return self._data() | other

    def __ror__(self, other):
        return other | self._data()

    def __eq__(self, other):
        return self._data() == other

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return repr(self._data())

    def __deepcopy__(self, memo):
        result = SharedDict(self._decoder, self._body)
        memo[id(self)] = result
        if self._dirty:
            result.clear()
            result.update(deepcopy(self._cache, memo))
        return result


class SharedList(_SharedChanges, list):
    def __init__(self, decoder: ObjectDecoder, body: list[Any]) -> None:
        self._decoder, self._body = decoder, body
        self._initialize_tracking()
        self._cache: list[Any] | None = None
        super().__init__([None] * len(body))

    def _data(self) -> list[Any]:
        if self._cache is None:
            self._cache = [self._decoded_child(v) for v in self._body]
        return self._cache

    def __getitem__(self, key):
        return self._data()[key]

    def __setitem__(self, key, value):
        self._mark_changed()
        self._data()[key] = value
        super().__setitem__(slice(None), [None] * len(self._data()))

    def __delitem__(self, key):
        self._mark_changed()
        del self._data()[key]
        super().__setitem__(slice(None), [None] * len(self._data()))

    def __iter__(self):
        return iter(self._data())

    def __contains__(self, value):
        return value in self._data()

    def append(self, value):
        self._mark_changed()
        self._data().append(value)
        super().append(None)

    def extend(self, values):
        for value in values:
            self.append(value)

    def insert(self, index, value):
        self._mark_changed()
        self._data().insert(index, value)
        super().insert(index, None)

    def pop(self, index=-1):
        self._mark_changed()
        value = self._data().pop(index)
        super().pop(index)
        return value

    def clear(self):
        self._mark_changed()
        self._data().clear()
        super().clear()

    def remove(self, value):
        self.pop(self._data().index(value))

    def reverse(self):
        self._mark_changed()
        self._data().reverse()

    def sort(self, *args, **kwargs):
        self._mark_changed()
        self._data().sort(*args, **kwargs)

    def copy(self):
        return self._data().copy()

    def count(self, value):
        return self._data().count(value)

    def index(self, *args):
        return self._data().index(*args)

    def __add__(self, other):
        return self._data() + list(other)

    def __iadd__(self, other):
        self.extend(other)
        return self

    def __mul__(self, count):
        return self._data() * count

    __rmul__ = __mul__

    def __imul__(self, count):
        self._mark_changed()
        self._data().__imul__(count)
        super().__setitem__(slice(None), [None] * len(self._data()))
        return self

    def __reversed__(self):
        return reversed(self._data())

    def __lt__(self, other):
        return self._data() < other

    def __le__(self, other):
        return self._data() <= other

    def __gt__(self, other):
        return self._data() > other

    def __ge__(self, other):
        return self._data() >= other

    def __eq__(self, other):
        return self._data() == other

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return repr(self._data())

    def __deepcopy__(self, memo):
        result = SharedList(self._decoder, self._body)
        memo[id(self)] = result
        if self._dirty:
            result.clear()
            result.extend(deepcopy(self._cache, memo))
        return result


def decode_storage(value: Any) -> Any:
    if isinstance(value, dict) and value.get("storage_schema") == STORAGE_SCHEMA:
        return ObjectDecoder(value).root
    return value


def encode_legacy_stream(path: Any) -> dict[str, Any]:
    """Bottom-up event encoding: never materialize the expanded legacy tree."""
    from decimal import Decimal
    from pathlib import Path
    from .json_io import require_streaming_json

    encoder = ObjectEncoder()
    stack: list[tuple[str, list[Any], list[str]]] = []
    root: Any = None

    def accept(value: Any) -> None:
        nonlocal root
        if not stack:
            if root is not None:
                raise ValueError("multiple JSON values")
            root = value
        elif stack[-1][0] == "map":
            _, children, keys = stack[-1]
            if not keys:
                raise ValueError("map value without key")
            children.append([keys.pop(), value])
        else:
            stack[-1][1].append(value)

    with Path(path).open("rb") as stream:
        for event, value in require_streaming_json().basic_parse(stream):
            if event in {"start_map", "start_array"}:
                stack.append(("map" if event == "start_map" else "list", [], []))
            elif event == "map_key":
                stack[-1][2].append(value)
            elif event in {"end_map", "end_array"}:
                kind, children, _ = stack.pop()
                accept(encoder.intern([kind, children]))
            else:
                accept(encoder.encode(float(value) if isinstance(value, Decimal) else value))
    if stack or root is None:
        raise ValueError("incomplete JSON")
    return {"storage_schema": STORAGE_SCHEMA, "root": root, "objects": encoder.objects}
