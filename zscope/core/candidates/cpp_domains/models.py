"""Shared, read-only execution contexts for C/C++ deterministic detectors.

Detector algorithms live in the four domain mixin modules.  The stable engine
facades retain source/fact parsing, caches, candidate emission, and ordered
dispatch, while these models form the narrow boundary between both layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class CodeLine:
    """A normalized C/C++ source line used by the regex detector mixins."""

    number: int
    raw: str
    text: str
    index: int
    column: int = 1
    offset: int = 0
    ordinal: int = 0
    ordered: bool = True
    offset_basis: str = "function_utf8"


@dataclass(frozen=True)
class ClangCfgLine:
    number: int
    raw: str
    text: str
    index: int
    block_id: int
    column: int = 1
    offset: int = 0
    ordinal: int = 0
    ordered: bool = True
    offset_basis: str = "function_utf8"


@dataclass(frozen=True)
class ResourceState:
    var: str
    api: str
    line: ClangCfgLine
    carrier: str
    status_var: str = ""
    null_guarded: bool = False
    status_guarded: bool = False
    transferred: bool = False
    object_identity: str = ""
    resource_domain: str = ""
    resource_family: str = ""


@dataclass(frozen=True)
class LockState:
    lock_id: str
    api: str
    line: ClangCfgLine
    definite: bool = True


@dataclass(frozen=True)
class GraphLine:
    number: int
    text: str
    raw: str
    index: int
    column: int = 1
    offset: int = 0
    ordinal: int = 0
    ordered: bool = True
    offset_basis: str = "function_utf8"


@dataclass(frozen=True)
class FunctionView:
    name: str
    file_path: str
    signature: str
    lines: Tuple[GraphLine, ...]
    callees: Tuple[str, ...]


@dataclass(frozen=True)
class LockOrderEdge:
    function: str
    file_path: str
    first_lock: str
    second_lock: str
    first_line: int
    second_line: int


DetectorDomain = Literal[
    "resource_lifecycle",
    "memory_bounds_integer",
    "concurrency_shared_state",
    "protocol_ownership_logic",
]

DetectorEngine = Literal["regex", "clang_ast_cfg", "graph"]
DetectorPhase = Literal["function", "view", "batch"]


@dataclass(frozen=True)
class DetectorStage:
    """A deterministic facade method registered in its semantic domain."""

    engine: DetectorEngine
    phase: DetectorPhase
    order: int
    domain: DetectorDomain
    name: str
    method_name: str
    argument_names: Tuple[str, ...]
    covers: Tuple[DetectorDomain, ...] = ()

    def run(self, context: Any) -> None:
        generator = context.generator
        method = getattr(generator, self.method_name)
        method(*(getattr(context, name) for name in self.argument_names))


@dataclass(frozen=True)
class RegexRuleContext:
    generator: Any
    lines: Sequence[Any]
    emit: Any


@dataclass(frozen=True)
class ClangRuleContext:
    generator: Any
    issues: list[dict[str, Any]]
    func_name: str
    file_path: str
    lines: Sequence[Any]
    allowed_skills: Optional[Set[str]]


@dataclass(frozen=True)
class GraphViewRuleContext:
    generator: Any
    view: Any
    by_name: Mapping[str, Any]
    issues: list[dict[str, Any]]


@dataclass(frozen=True)
class GraphBatchRuleContext:
    generator: Any
    views: Sequence[Any]
    issues: list[dict[str, Any]]
