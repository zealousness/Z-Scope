"""Reuse an AST projection over immutable evidence, without proof authority."""

from __future__ import annotations

import threading
from typing import Any
import weakref

from ...reporting.shared_objects import SharedDict
from ...retrieval.validation_facts import walk_ast


_INDEXES: Any = weakref.WeakKeyDictionary()
_GUARD = threading.RLock()


def _collect(ast: Any) -> dict[str, Any]:
    grouped: dict[str, list[Any]] = {}
    for node in walk_ast(ast):
        if node.get("kind") == "FunctionDecl" and any(
            child.get("kind") == "CompoundStmt" for child in node.get("inner", [])
        ):
            grouped.setdefault(str(node.get("name")), []).append(node)
    return {name: nodes[0] for name, nodes in grouped.items() if len(nodes) == 1}


def function_definitions(data: dict[str, Any]) -> dict[str, Any]:
    """Fresh views preserve mutation isolation and ambiguous-name exclusion.

    A shared AST can reuse a projection after read-only access. A modified
    view is traversed as provided, so local edits are never ignored.
    The source digest/dependency check remains the fact store's responsibility.
    """
    ast = data["ast"]
    if not isinstance(ast, SharedDict) or ast._dirty:
        return _collect(ast)
    decoder, body = ast._decoder, ast._body
    key = id(body)
    with _GUARD:
        indexes = _INDEXES.setdefault(decoder, {})
        cached = indexes.get(key)
        if cached is None:
            # Traverse a separate read view. Cache encoded bodies only; keeping
            # decoded nodes would retain their decoder and prevent collection.
            functions = _collect(SharedDict(decoder, body))
            cached = (body, {name: node._body for name, node in functions.items()})
            indexes[key] = cached
    return {name: SharedDict(decoder, encoded) for name, encoded in cached[1].items()}
