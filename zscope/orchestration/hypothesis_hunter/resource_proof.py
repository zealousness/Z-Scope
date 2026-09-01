"""Answer-free resource identity and ownership qualification for Hunter offers.

FunctionIR v2 has exact local-symbol cleanup coverage, but deliberately lacks
closed-world ownership-transfer and field-sensitive alias proofs.  This module
keeps that limitation explicit: only one source-bound, reachable acquisition
with an unambiguous local identity can become a terminal resource offer.  Any
alias, escape, transfer or unknown callee makes the unit non-terminal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...core.validation.function_ir import FunctionIREvent, FunctionIRGraph
from ...semantics.security_map import SecurityEvent


@dataclass(frozen=True)
class ResourceProofBinding:
    resource_uid: str
    acquisition_event_uid: str
    acquisition_statement_uid: str
    cleanup_complete: bool


def resolve_resource_proof_binding(
    graph: FunctionIRGraph,
    event: SecurityEvent,
) -> ResourceProofBinding | None:
    """Resolve one acquisition and reject any unmodelled ownership edge."""

    if not graph.coverage_complete or graph.unresolved_dynamic_edges or not graph.exit_block_uids:
        return None
    acquisitions = [value for value in graph.events if value.kind == "resource_acquire"]
    if not acquisitions:
        return None

    matches = acquisitions
    if int(event.line or 0) > 0:
        # A source-bound event may never fall back to an acquisition on a
        # different line.  Expression binding further selects same-line calls.
        matches = [value for value in matches if value.source_line == int(event.line)]
    matches = [value for value in matches if _matches_resource_event(value, event)]
    if len(matches) != 1:
        return None
    acquisition = matches[0]
    if not graph.reachable(graph.entry_block_uid, acquisition.block_uid):
        return None

    resources = tuple(dict.fromkeys(value for value in acquisition.subject_symbols if value))
    # ``owner->left`` is represented by two symbols.  Selecting either one
    # would conflate sibling resources, so field-sensitive identities remain
    # non-terminal until the proof IR can represent them exactly.
    if len(resources) != 1:
        return None
    resource_uid = resources[0]
    if sum(
        resource_uid in value.subject_symbols for value in acquisitions
    ) != 1 or _has_unmodelled_ownership_edge(graph, acquisition, resource_uid):
        return None

    outstanding = graph.resource_outstanding_at_exits(resource_uid)
    if set(outstanding) != set(graph.exit_block_uids):
        return None
    return ResourceProofBinding(
        resource_uid=resource_uid,
        acquisition_event_uid=acquisition.event_uid,
        acquisition_statement_uid=acquisition.statement_uid,
        cleanup_complete=not any(outstanding.values()),
    )


def _matches_resource_event(acquisition: FunctionIREvent, event: SecurityEvent) -> bool:
    expression = str(event.expression or "")
    callees = re.findall(r"\b([A-Za-z_]\w*)\s*\(", expression)
    if callees and acquisition.callee not in callees:
        return False
    assignment = re.search(r"(?<![=!<>])=(?!=)", expression)
    if assignment is None:
        return bool(callees or int(event.line or 0) > 0)
    left_identifiers = re.findall(r"\b[A-Za-z_]\w*\b", expression[: assignment.start()])
    return bool(left_identifiers and left_identifiers[-1] in acquisition.subject_symbols)


def _has_unmodelled_ownership_edge(
    graph: FunctionIRGraph,
    acquisition: FunctionIREvent,
    resource_uid: str,
) -> bool:
    """Fail closed for aliases, escapes, transfers and unknown callees."""

    event_by_statement = {value.statement_uid: value for value in graph.events}
    resource_token = re.compile(rf"\b{re.escape(resource_uid)}\b")
    assignment = re.compile(r"(?<![=!<>])=(?!=)")
    for block in graph.blocks:
        for statement in sorted(block.statements, key=lambda value: value.ordinal):
            if (
                statement.statement_uid == acquisition.statement_uid
                or not graph.statement_reachable(
                    acquisition.statement_uid,
                    statement.statement_uid,
                )
            ):
                continue
            text = str(statement.text or "")
            if resource_token.search(text) is None:
                continue
            statement_event = event_by_statement.get(statement.statement_uid)
            if statement_event is not None:
                subjects = tuple(
                    dict.fromkeys(value for value in statement_event.subject_symbols if value)
                )
                if statement_event.kind == "resource_release":
                    # ``free(owner->field)`` must not discharge ``owner`` or a
                    # sibling field acquisition.
                    if subjects != (resource_uid,):
                        return True
                    continue
                if statement_event.kind == "resource_acquire":
                    return True
                if statement_event.kind == "call" and resource_uid in subjects:
                    return True
                if statement_event.kind == "return" and _returns_resource(text, resource_uid):
                    return True

            match = assignment.search(text)
            if match is None:
                continue
            left = text[: match.start()]
            right = text[match.end() :]
            # Assignment to any other local/global/field/out-param/container
            # or callback creates an alias/transfer outside this proof domain.
            # Assignment *to* the resource (for example a null reset) is not a
            # safety transfer and therefore does not suppress a leak proof.
            if resource_token.search(right) and not _lhs_is_resource(left, resource_uid):
                return True
    return False


def _returns_resource(text: str, resource_uid: str) -> bool:
    match = re.search(r"\breturn\b(?P<value>[^;]*)", text or "")
    return bool(match and re.search(rf"\b{re.escape(resource_uid)}\b", match.group("value") or ""))


def _lhs_is_resource(left: str, resource_uid: str) -> bool:
    identifiers = re.findall(r"\b[A-Za-z_]\w*\b", left or "")
    return bool(identifiers and identifiers[-1] == resource_uid)
