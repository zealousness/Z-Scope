"""Build-scoped resource regions and bounded native-to-runtime witnesses."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

from .contracts import digest


# Heap-allocating calls a sanitizer allocation frame may name. The frame carries
# only file/line, so any second one of these on the allocation's own line makes
# the allocation identity ambiguous.
_HEAP_ALLOCATOR_NAMES = frozenset(
    {
        "malloc",
        "calloc",
        "realloc",
        "aligned_alloc",
        "memalign",
        "posix_memalign",
        "strdup",
        "operator new",
        "operator new[]",
    }
)


@dataclass(frozen=True)
class ObjectRef:
    build_context_id: str
    symbol_usr: str
    region: str
    allocation_site: str
    generation: str
    member_path: str = ""

    @property
    def key(self) -> str:
        return digest(asdict(self))


@dataclass(frozen=True)
class HandleValue:
    """C integer value with saved descriptor provenance, separate from backing identity."""

    value: int
    namespace: tuple[str, ...]
    resource_id: str

    def __bool__(self) -> bool:
        return bool(self.value)


@dataclass(frozen=True)
class SourceObjectWitness:
    object_ref: ObjectRef
    expression: str
    access_site: str
    access_kind: str
    function: str
    event_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def native_heap_witness(
    facts: Mapping[str, Any], *, name: str, site_file: str, site_line: int
) -> SourceObjectWitness | None:
    """Bind a single local heap allocation to a simple, unique native access.

    Loops, aliases, opaque pointer calls, reassignments, macros and compound
    access expressions require a stronger strategy; no name-only fallback. An
    escaped slot address (``&p``) is refused as well: any later indirect write
    can rebind the object, and proving otherwise needs real alias analysis. A
    second heap-allocating call on the allocation's own line is refused too,
    because a sanitizer allocation frame names only file/line and cannot tell
    the two allocations apart.
    """
    bodies = facts.get("functions", [])
    scope = str(facts.get("build_context_id") or "")
    if (
        not scope
        or not facts.get("complete")
        or len(bodies) != 1
        or not re.fullmatch(r"[A-Za-z_]\w*", name)
    ):
        return None
    body = bodies[0]
    if body.get("fact_version") != "zscope.program-events.v7":
        return None
    adjacency: dict[int, set[int]] = {}
    for edge in body.get("cfg_edges", []):
        adjacency.setdefault(edge["from"], set()).add(edge["to"])
    active: set[int] = set()
    done: set[int] = set()

    def cyclic(node: int) -> bool:
        if node in active:
            return True
        if node in done:
            return False
        active.add(node)
        if any(cyclic(child) for child in adjacency.get(node, ())):
            return True
        active.remove(node)
        done.add(node)
        return False

    if any(cyclic(node) for node in adjacency):
        return None
    events = body.get("events", [])
    allocations = [
        e
        for e in events
        if e.get("event_kind") == "call"
        and (e.get("object") or {}).get("name") == name
        and (e.get("callee") or {}).get("name") in {"malloc", "calloc"}
        and (e.get("callee") or {}).get("is_system_header")
    ]
    if len(allocations) != 1:
        return None
    allocation = allocations[0]
    usr = str(allocation["object"].get("usr") or "")
    if not usr or allocation.get("macro_expansion"):
        return None
    for event in events:
        if event is allocation or (
            event.get("event_kind") == "call"
            and event.get("location") == allocation.get("location")
            and event.get("callee") == allocation.get("callee")
            and event.get("expression") == allocation.get("expression")
        ):
            continue
        if any(
            item.get("name") == name and item.get("usr") != usr
            for item in [*event.get("defs", []), *event.get("uses", [])]
        ):
            return None
        if event.get("assignment_target") == name or any(
            item.get("usr") == usr for item in event.get("defs", [])
        ):
            return None
        expression = str(event.get("expression") or "")
        if re.search(
            r"(?:\+\+|--)\s*"
            + re.escape(name)
            + r"\b|\b"
            + re.escape(name)
            + r"\s*(?:\+\+|--|[+\-*/]=)",
            expression,
        ):
            return None
        if re.search(r"(?<!&)&\s*\(*\s*" + re.escape(name) + r"\b(?!\s*\[)", expression):
            # The object's slot address escapes into another pointer; any
            # later indirect write can rebind it. Bitwise-and on the pointer
            # is refused too - conservative beats unprovable here.
            return None
        if event.get("event_kind") == "call":
            callee = event.get("callee") or {}
            location = event.get("location") or {}
            if (
                callee.get("name") in _HEAP_ALLOCATOR_NAMES
                and location.get("file") == allocation["location"].get("file")
                and location.get("line") == allocation["location"].get("line")
            ):
                return None
        if (
            event.get("event_kind") == "call"
            and any(item.get("usr") == usr for item in event.get("uses", []))
            and not (
                (event.get("callee") or {}).get("name") == "free"
                and (event.get("callee") or {}).get("is_system_header")
            )
        ):
            return None
    accesses = [
        e
        for e in events
        if (e.get("location") or {}).get("file") == site_file
        and (e.get("location") or {}).get("line") == site_line
        and e.get("event_kind") in {"assignment", "return"}
    ]
    if len(accesses) != 1 or accesses[0].get("macro_expansion"):
        return None
    access = accesses[0]
    expr = str(access.get("expression") or "")
    if re.fullmatch(re.escape(name) + r"\s*\[\s*\d+\s*\]\s*=\s*\d+", expr):
        kind = "write"
    elif re.fullmatch(r"return\s+" + re.escape(name) + r"\s*\[\s*\d+\s*\]", expr):
        kind = "read"
    else:
        return None
    location = allocation["location"]
    allocation_site = f"{location['file']}:{location['line']}"
    return SourceObjectWitness(
        ObjectRef(scope, usr, "heap", allocation_site, "single_acyclic_allocation"),
        name,
        f"{site_file}:{site_line}",
        kind,
        str(body.get("owner", {}).get("name") or ""),
        str(access.get("event_id") or ""),
    )
