"""Finite P2 predicate registry and deterministic evaluators."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True)
class PredicateSpec:
    predicate_id: str
    provider_family: str
    fact_kind: str
    quantifier: str
    parameter_keys: Tuple[str, ...]
    coverage_domain: str
    provider_id: str
    verifier_id: str


@dataclass(frozen=True)
class PredicateEvaluation:
    status: str
    reason_code: str
    predicate_value: Any
    witness: Dict[str, Any]
    coverage: Dict[str, Any]
    assumption_ids: Tuple[str, ...] = ()


def _spec(
    predicate_id: str,
    family: str,
    fact_kind: str,
    quantifier: str,
    parameters: Sequence[str],
    domain: str,
) -> PredicateSpec:
    return PredicateSpec(
        predicate_id=predicate_id,
        provider_family=family,
        fact_kind=fact_kind,
        quantifier=quantifier,
        parameter_keys=tuple(parameters),
        coverage_domain=domain,
        provider_id=f"zscope.{family}-proof-provider.v2",
        verifier_id=f"zscope.{family}-proof-verifier.v2",
    )


PREDICATE_REGISTRY: Dict[str, PredicateSpec] = {
    value.predicate_id: value
    for value in (
        _spec(
            "lock_must_hold_at_access",
            "concurrency",
            "lockset",
            "must_at_point",
            ("access_statement_uid", "lock_uid"),
            "all_cfg_paths_reaching_statement",
        ),
        _spec(
            "cleanup_covers_all_exits",
            "resource",
            "cleanup_coverage",
            "for_all_exits",
            ("resource_uid",),
            "all_reachable_function_exits",
        ),
        _spec(
            "source_sink_path_exists",
            "path_guard",
            "source_sink_reachability",
            "exists_path",
            ("source_node_uid", "sink_node_uid"),
            "concrete_adjacent_cfg_path",
        ),
        _spec(
            "guard_dominates_sink",
            "path_guard",
            "guard_dominance",
            "for_all_paths",
            ("guard_statement_uid", "sink_statement_uid"),
            "all_cfg_paths_reaching_sink",
        ),
        _spec(
            "external_entry_parameter_binding",
            "contract_type",
            "source_controllability",
            "exact_binding",
            ("parameter_uid", "parameter_slot"),
            "frozen_entry_signature",
        ),
        _spec(
            "record_layout_matches",
            "contract_type",
            "type_layout",
            "exact_layout",
            ("type_uid",),
            "clang_record_layout",
        ),
    )
}

ALLOWED_ASSUMPTION_IDS: frozenset[str] = frozenset()

# These facts remain visible to planners, but no P2 action may execute them.
# A later phase must add a new frozen contract before moving one into the
# executable registry.
NON_EXECUTABLE_PREDICATES = {
    "happens_before": "complete_cross_thread_graph_unavailable",
    "ownership_transfer": "closed_world_ownership_contract_unavailable",
    "caller_contract": "closed_world_caller_contract_unavailable",
    "object_identity": "field_sensitive_alias_proof_unavailable",
    "value_range": "value_domain_proof_unavailable",
}

POLARITY_ROLE_TERMINAL_MATRIX = {
    ("confirmation", "supports"): "confirmation",
    ("counterproof", "refutes"): "counterproof",
    ("open", "supports"): "none",
    ("open", "refutes"): "none",
}


def _empty_witness() -> Dict[str, Any]:
    return {
        "cfg_nodes": [],
        "cfg_edges": [],
        "path_node_uids": [],
        "exit_node_uids": [],
        "values": {},
    }


def _coverage(
    spec: PredicateSpec,
    *,
    enumerated: Sequence[str] = (),
    required: Sequence[str] = (),
    complete: bool,
    unresolved: Sequence[str] = (),
) -> Dict[str, Any]:
    return {
        "domain": spec.coverage_domain,
        "enumerated_uids": sorted({str(value) for value in enumerated if str(value)}),
        "required_uids": sorted({str(value) for value in required if str(value)}),
        "complete": bool(complete),
        "unresolved_reasons": sorted({str(value) for value in unresolved if str(value)}),
    }


def _unknown(spec: PredicateSpec, reason: str) -> PredicateEvaluation:
    return PredicateEvaluation(
        status="unknown",
        reason_code=reason,
        predicate_value=None,
        witness=_empty_witness(),
        coverage=_coverage(spec, complete=False, unresolved=(reason,)),
    )


def _function(proof_ir: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    functions = proof_ir.get("functions")
    if not isinstance(functions, list) or len(functions) != 1:
        return None
    value = functions[0]
    return value if isinstance(value, Mapping) else None


def _node_ids(summary: Mapping[str, Any]) -> set[str]:
    return {
        str(value.get("node_uid") or "")
        for value in summary.get("cfg_nodes") or []
        if isinstance(value, Mapping) and str(value.get("node_uid") or "")
    }


def _edges(summary: Mapping[str, Any]) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for value in summary.get("cfg_edges") or []:
        if isinstance(value, list) and len(value) == 2:
            result.add((str(value[0]), str(value[1])))
    return result


def _predecessors(summary: Mapping[str, Any]) -> Dict[str, set[str]]:
    result: Dict[str, set[str]] = {value: set() for value in _node_ids(summary)}
    for source, target in _edges(summary):
        result.setdefault(target, set()).add(source)
    return result


def _successors(summary: Mapping[str, Any]) -> Dict[str, set[str]]:
    result: Dict[str, set[str]] = {value: set() for value in _node_ids(summary)}
    for source, target in _edges(summary):
        result.setdefault(source, set()).add(target)
    return result


def _statement_location(summary: Mapping[str, Any], statement_uid: str) -> tuple[str, int]:
    for node in summary.get("cfg_nodes") or []:
        if not isinstance(node, Mapping):
            continue
        statements = [str(value) for value in node.get("statement_uids") or []]
        if statement_uid in statements:
            return str(node.get("node_uid") or ""), statements.index(statement_uid)
    return "", -1


def _events(summary: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [value for value in summary.get("events") or [] if isinstance(value, Mapping)]


def _event_ordinal(event: Mapping[str, Any]) -> int:
    attributes = event.get("attributes")
    attributes = attributes if isinstance(attributes, Mapping) else {}
    try:
        return int(attributes.get("statement_ordinal") or 0)
    except (TypeError, ValueError):
        return 0


def _reachable_path(summary: Mapping[str, Any], source: str, sink: str) -> list[str]:
    nodes = _node_ids(summary)
    if source not in nodes or sink not in nodes:
        return []
    queue: list[tuple[str, list[str]]] = [(source, [source])]
    seen = {source}
    successors = _successors(summary)
    while queue:
        current, path = queue.pop(0)
        if current == sink:
            return path
        for value in sorted(successors.get(current, set())):
            if value not in seen:
                seen.add(value)
                queue.append((value, [*path, value]))
    return []


def _reachable_nodes(summary: Mapping[str, Any]) -> set[str]:
    entry = str(summary.get("entry_node_uid") or "")
    if not entry:
        return set()
    seen = {entry}
    queue = [entry]
    successors = _successors(summary)
    while queue:
        current = queue.pop(0)
        for value in successors.get(current, set()):
            if value not in seen:
                seen.add(value)
                queue.append(value)
    return seen


def _dominators(summary: Mapping[str, Any]) -> Dict[str, set[str]]:
    nodes = _node_ids(summary)
    entry = str(summary.get("entry_node_uid") or "")
    if entry not in nodes:
        return {}
    predecessors = _predecessors(summary)
    result = {node: ({node} if node == entry else set(nodes)) for node in nodes}
    changed = True
    while changed:
        changed = False
        for node in nodes - {entry}:
            incoming = predecessors.get(node, set())
            common = set(nodes)
            if incoming:
                for predecessor in incoming:
                    common.intersection_update(result[predecessor])
            else:
                common = set()
            updated = {node, *common}
            if updated != result[node]:
                result[node] = updated
                changed = True
    return result


def _must_locksets(summary: Mapping[str, Any]) -> Dict[str, set[str]]:
    nodes = _node_ids(summary)
    entry = str(summary.get("entry_node_uid") or "")
    if entry not in nodes:
        return {}
    predecessors = _predecessors(summary)
    events_by_node: Dict[str, list[Mapping[str, Any]]] = {value: [] for value in nodes}
    for event in _events(summary):
        events_by_node.setdefault(str(event.get("node_uid") or ""), []).append(event)
    incoming: Dict[str, Optional[set[str]]] = {value: None for value in nodes}
    incoming[entry] = set()
    outgoing: Dict[str, set[str]] = {value: set() for value in nodes}
    changed = True
    rounds = 0
    while changed and rounds <= max(8, len(nodes) * 4):
        changed = False
        rounds += 1
        for node in sorted(nodes):
            if node != entry:
                parents = predecessors.get(node, set())
                state = (
                    set.intersection(*(set(outgoing[parent]) for parent in parents))
                    if parents
                    else set()
                )
                if incoming[node] != state:
                    incoming[node] = state
                    changed = True
            state = set(incoming[node] or set())
            for event in sorted(events_by_node.get(node, []), key=_event_ordinal):
                subjects = [str(value) for value in event.get("subject_uids") or [] if str(value)]
                if not subjects:
                    continue
                if event.get("kind") == "lock_acquire":
                    state.add(subjects[0])
                elif event.get("kind") == "lock_release":
                    state.discard(subjects[0])
            if outgoing[node] != state:
                outgoing[node] = state
                changed = True
    return {key: set(value or set()) for key, value in incoming.items()}


def _summary_complete(summary: Mapping[str, Any]) -> tuple[bool, tuple[str, ...]]:
    coverage = summary.get("coverage")
    coverage = coverage if isinstance(coverage, Mapping) else {}
    reasons = tuple(str(value) for value in coverage.get("unresolved_reasons") or [] if str(value))
    return coverage.get("complete") is True and not reasons, reasons


def _matches_expected(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping) and expected.get("$derived") is True:
        return True
    if isinstance(expected, Mapping) and isinstance(actual, Mapping):
        return all(
            key in actual and _matches_expected(actual[key], value)
            for key, value in expected.items()
        )
    return bool(actual == expected)


def _complete_result(
    spec: PredicateSpec,
    *,
    actual: Any,
    expected: Any,
    witness: Mapping[str, Any],
    enumerated: Sequence[str],
    required: Sequence[str],
    reason: str,
) -> PredicateEvaluation:
    return PredicateEvaluation(
        status="verified_true" if _matches_expected(actual, expected) else "verified_false",
        reason_code=reason,
        predicate_value=actual,
        witness=dict(witness),
        coverage=_coverage(
            spec,
            enumerated=enumerated,
            required=required,
            complete=True,
        ),
    )


def evaluate_predicate(
    *,
    proof_ir: Mapping[str, Any],
    clause: Mapping[str, Any],
    action: Mapping[str, Any],
) -> PredicateEvaluation:
    predicate_id = str(action.get("predicate_id") or "")
    spec = PREDICATE_REGISTRY.get(predicate_id)
    if spec is None:
        raise ValueError("unregistered proof predicate")
    if proof_ir.get("language") == "java":
        return _unknown(spec, "java_provider_preview_non_executable")
    parameters = action.get("fixed_parameters")
    if not isinstance(parameters, Mapping) or set(parameters) != set(spec.parameter_keys):
        return _unknown(spec, "invalid_fixed_parameter_schema")
    summary = _function(proof_ir)
    if summary is None:
        return _unknown(spec, "program_ir_function_scope_not_unique")
    complete, unresolved = _summary_complete(summary)
    expected = clause.get("expected_value")

    if predicate_id == "lock_must_hold_at_access":
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        statement = str(parameters.get("access_statement_uid") or "")
        lock_uid = str(parameters.get("lock_uid") or "")
        node, ordinal = _statement_location(summary, statement)
        if not node or not lock_uid:
            return _unknown(spec, "lock_or_access_identity_unresolved")
        if node not in _reachable_nodes(summary):
            return _unknown(spec, "access_statement_unreachable")
        lock_state = _must_locksets(summary).get(node, set())
        for event in sorted(
            [value for value in _events(summary) if value.get("node_uid") == node],
            key=_event_ordinal,
        ):
            if _event_ordinal(event) >= ordinal:
                break
            subjects = [str(value) for value in event.get("subject_uids") or [] if str(value)]
            if not subjects:
                continue
            if event.get("kind") == "lock_acquire":
                lock_state.add(subjects[0])
            elif event.get("kind") == "lock_release":
                lock_state.discard(subjects[0])
        actual = {
            "must_hold": lock_uid in lock_state,
            "must_hold_locks": sorted(lock_state),
        }
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": [node],
                "cfg_edges": [],
                "path_node_uids": [],
                "exit_node_uids": [],
                "values": {"access_statement_uid": statement, **actual},
            },
            enumerated=sorted(_node_ids(summary)),
            required=sorted(_node_ids(summary)),
            reason="cfg_must_lockset_recomputed",
        )

    if predicate_id == "cleanup_covers_all_exits":
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        resource_uid = str(parameters.get("resource_uid") or "")
        if not resource_uid:
            return _unknown(spec, "resource_identity_unresolved")
        events = _events(summary)
        acquisitions = [
            value
            for value in events
            if value.get("kind") == "resource_acquire"
            and resource_uid in [str(item) for item in value.get("subject_uids") or []]
        ]
        if not acquisitions:
            return _unknown(spec, "resource_acquisition_unresolved")
        unresolved_calls = [
            str(value.get("event_uid") or "")
            for value in events
            if value.get("kind") == "call"
            and resource_uid in [str(item) for item in value.get("subject_uids") or []]
        ]
        if unresolved_calls:
            return _unknown(spec, "resource_transfer_or_alias_unresolved")
        nodes = _node_ids(summary)
        entry = str(summary.get("entry_node_uid") or "")
        exits = [str(value) for value in summary.get("exit_node_uids") or []]
        predecessors = _predecessors(summary)
        by_node: Dict[str, list[Mapping[str, Any]]] = {value: [] for value in nodes}
        for event in events:
            by_node.setdefault(str(event.get("node_uid") or ""), []).append(event)
        incoming = {value: False for value in nodes}
        outgoing = {value: False for value in nodes}
        changed = True
        rounds = 0
        while changed and rounds <= max(8, len(nodes) * 4):
            changed = False
            rounds += 1
            for node in sorted(nodes):
                resource_live = (
                    False
                    if node == entry
                    else any(outgoing.get(value, False) for value in predecessors.get(node, set()))
                )
                if incoming[node] != resource_live:
                    incoming[node] = resource_live
                    changed = True
                for event in sorted(by_node.get(node, []), key=_event_ordinal):
                    subjects = [str(value) for value in event.get("subject_uids") or []]
                    if resource_uid not in subjects:
                        continue
                    if event.get("kind") == "resource_acquire":
                        resource_live = True
                    elif event.get("kind") == "resource_release":
                        resource_live = False
                if outgoing[node] != resource_live:
                    outgoing[node] = resource_live
                    changed = True
        uncovered = sorted(value for value in exits if outgoing.get(value, False))
        covered = sorted(value for value in exits if not outgoing.get(value, False))
        actual = {
            "cleanup_complete": not uncovered,
            "covered_exits": covered,
            "uncovered_exits": uncovered,
        }
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": sorted(nodes),
                "cfg_edges": [list(value) for value in sorted(_edges(summary))],
                "path_node_uids": [],
                "exit_node_uids": exits,
                "values": actual,
            },
            enumerated=exits,
            required=exits,
            reason="all_reachable_exits_recomputed",
        )

    if predicate_id == "source_sink_path_exists":
        source = str(parameters.get("source_node_uid") or "")
        sink = str(parameters.get("sink_node_uid") or "")
        if source not in _node_ids(summary) or sink not in _node_ids(summary):
            return _unknown(spec, "source_or_sink_node_unresolved")
        path = _reachable_path(summary, source, sink)
        expected_exists = bool(
            expected.get("path_exists") if isinstance(expected, Mapping) else expected
        )
        if not path and expected_exists and not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        if not path and not expected_exists and not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        actual = {"path_exists": bool(path)}
        path_edges = [list(value) for value in zip(path, path[1:])]
        required = path if path else sorted(_node_ids(summary))
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": path,
                "cfg_edges": path_edges,
                "path_node_uids": path,
                "exit_node_uids": [],
                "values": actual,
            },
            enumerated=required,
            required=required,
            reason=(
                "cfg_path_witness_recomputed" if path else "complete_cfg_nonreachability_recomputed"
            ),
        )

    if predicate_id == "guard_dominates_sink":
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        guard = str(parameters.get("guard_statement_uid") or "")
        sink = str(parameters.get("sink_statement_uid") or "")
        guard_node, guard_ordinal = _statement_location(summary, guard)
        sink_node, sink_ordinal = _statement_location(summary, sink)
        if not guard_node or not sink_node:
            return _unknown(spec, "guard_or_sink_statement_unresolved")
        dominates = (
            guard_ordinal < sink_ordinal
            if guard_node == sink_node
            else guard_node in _dominators(summary).get(sink_node, set())
        )
        actual = {"guard_dominates_sink": dominates}
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": [guard_node, sink_node],
                "cfg_edges": [],
                "path_node_uids": [],
                "exit_node_uids": [],
                "values": {"guard_statement_uid": guard, "sink_statement_uid": sink, **actual},
            },
            enumerated=sorted(_node_ids(summary)),
            required=sorted(_node_ids(summary)),
            reason="cfg_dominance_recomputed",
        )

    if predicate_id == "external_entry_parameter_binding":
        parameter_uid = str(parameters.get("parameter_uid") or "")
        parameter_slot = str(parameters.get("parameter_slot") or "")
        entry_events = [
            event for event in _events(summary) if event.get("kind") == "entry_parameter"
        ]
        signature_frozen = bool(entry_events) and all(
            isinstance(event.get("attributes"), Mapping)
            and event["attributes"].get("entry_signature_complete") is True
            for event in entry_events
        )
        if not signature_frozen:
            return _unknown(spec, "entry_signature_not_frozen")
        matches = []
        for event in entry_events:
            attributes = event.get("attributes")
            attributes = attributes if isinstance(attributes, Mapping) else {}
            subjects = [str(value) for value in event.get("subject_uids") or []]
            if (
                event.get("kind") == "entry_parameter"
                and parameter_uid in subjects
                and str(attributes.get("parameter_slot") or "") == parameter_slot
            ):
                matches.append(str(event.get("event_uid") or ""))
        if len(matches) > 1:
            return _unknown(spec, "entry_parameter_binding_ambiguous")
        actual = {"external_entry_parameter_bound": bool(matches)}
        signature_event_uids = [str(value.get("event_uid") or "") for value in entry_events]
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": [str(summary.get("entry_node_uid") or "")] if matches else [],
                "cfg_edges": [],
                "path_node_uids": [],
                "exit_node_uids": [],
                "values": {
                    "matching_event_uids": matches,
                    "signature_event_uids": signature_event_uids,
                    **actual,
                },
            },
            enumerated=signature_event_uids,
            required=signature_event_uids,
            reason="entry_parameter_binding_recomputed",
        )

    if predicate_id == "record_layout_matches":
        type_uid = str(parameters.get("type_uid") or "")
        layouts = [
            dict(value)
            for value in summary.get("type_layouts") or []
            if isinstance(value, Mapping) and str(value.get("type_uid") or "") == type_uid
        ]
        if len(layouts) != 1:
            return _unknown(spec, "record_layout_missing_or_ambiguous")
        layout = layouts[0]
        required_layout_keys = {
            "type_uid",
            "size_bytes",
            "alignment_bytes",
            "fields",
            "backend_sha256",
            "layout_sha256",
        }
        if set(layout) != required_layout_keys:
            return _unknown(spec, "record_layout_schema_incomplete")
        if str(layout.get("backend_sha256") or "") != str(summary.get("backend_sha256") or ""):
            return _unknown(spec, "record_layout_backend_hash_mismatch")
        if (
            not isinstance(layout.get("size_bytes"), int)
            or int(layout["size_bytes"]) < 0
            or not isinstance(layout.get("alignment_bytes"), int)
            or int(layout["alignment_bytes"]) <= 0
            or not isinstance(layout.get("fields"), list)
        ):
            return _unknown(spec, "record_layout_values_invalid")
        supplied_layout_hash = str(layout.get("layout_sha256") or "")
        layout_body = dict(layout)
        layout_body.pop("layout_sha256", None)
        from .canonical import content_sha256

        if supplied_layout_hash != content_sha256(layout_body):
            return _unknown(spec, "record_layout_hash_mismatch")
        actual = {"layout": layouts[0]}
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": [],
                "cfg_edges": [],
                "path_node_uids": [],
                "exit_node_uids": [],
                "values": actual,
            },
            enumerated=(type_uid,),
            required=(type_uid,),
            reason="clang_record_layout_recomputed",
        )

    raise AssertionError(f"missing evaluator for {predicate_id}")
