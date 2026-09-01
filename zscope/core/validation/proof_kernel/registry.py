"""Finite P2 predicate registry and deterministic evaluators."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional, Sequence, Tuple

from .canonical import content_sha256

if TYPE_CHECKING:
    from ..function_ir import FunctionIRGraph


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
        _spec(
            "signed_value_reaches_unsigned_sink",
            "path_guard",
            "value_range",
            "exists_path",
            (
                "value_uid",
                "source_assignment_fact_uid",
                "sink_argument_fact_uid",
                "source_event_uid",
                "sink_event_uid",
            ),
            "complete_typed_ast_and_cfg_path",
        ),
        _spec(
            "qualified_race_shared_object_identity",
            "contract_type",
            "object_identity",
            "exact_binding",
            (
                "object_uid",
                "creator_function_uid",
                "left_function_uid",
                "left_statement_uid",
                "left_create_event_uid",
                "right_function_uid",
                "right_statement_uid",
                "right_create_event_uid",
            ),
            "qualified_complete_cross_thread_function_ir",
        ),
        _spec(
            "qualified_race_conflicting_accesses",
            "concurrency",
            "conflicting_accesses",
            "must_at_point",
            (
                "object_uid",
                "creator_function_uid",
                "left_function_uid",
                "left_statement_uid",
                "left_create_event_uid",
                "right_function_uid",
                "right_statement_uid",
                "right_create_event_uid",
            ),
            "qualified_complete_cross_thread_function_ir",
        ),
        _spec(
            "qualified_race_cross_thread_reachability",
            "concurrency",
            "cross_thread_reachability",
            "exists_path",
            (
                "object_uid",
                "creator_function_uid",
                "left_function_uid",
                "left_statement_uid",
                "left_create_event_uid",
                "right_function_uid",
                "right_statement_uid",
                "right_create_event_uid",
            ),
            "qualified_complete_cross_thread_function_ir",
        ),
        _spec(
            "qualified_race_empty_locksets",
            "concurrency",
            "lockset",
            "must_at_point",
            (
                "object_uid",
                "creator_function_uid",
                "left_function_uid",
                "left_statement_uid",
                "left_create_event_uid",
                "right_function_uid",
                "right_statement_uid",
                "right_create_event_uid",
            ),
            "qualified_complete_cross_thread_function_ir",
        ),
        _spec(
            "qualified_race_no_happens_before",
            "concurrency",
            "happens_before",
            "for_all_paths",
            (
                "object_uid",
                "creator_function_uid",
                "left_function_uid",
                "left_statement_uid",
                "left_create_event_uid",
                "right_function_uid",
                "right_statement_uid",
                "right_create_event_uid",
            ),
            "qualified_complete_cross_thread_function_ir",
        ),
        _spec(
            "qualified_bounds_source_controllable",
            "contract_type",
            "source_controllability",
            "exact_binding",
            (
                "value_uid",
                "source_assignment_fact_uid",
                "sink_argument_fact_uid",
                "source_event_uid",
                "sink_event_uid",
            ),
            "qualified_complete_typed_ast_and_cfg_path",
        ),
        _spec(
            "qualified_bounds_path_complete",
            "path_guard",
            "source_sink_reachability",
            "exists_path",
            (
                "value_uid",
                "source_assignment_fact_uid",
                "sink_argument_fact_uid",
                "source_event_uid",
                "sink_event_uid",
            ),
            "qualified_complete_typed_ast_and_cfg_path",
        ),
        _spec(
            "qualified_bounds_sink_contract",
            "contract_type",
            "caller_contract",
            "exact_binding",
            (
                "value_uid",
                "source_assignment_fact_uid",
                "sink_argument_fact_uid",
                "source_event_uid",
                "sink_event_uid",
            ),
            "qualified_complete_typed_ast_and_cfg_path",
        ),
        _spec(
            "qualified_bounds_range_violation",
            "path_guard",
            "value_range",
            "exists_path",
            (
                "value_uid",
                "source_assignment_fact_uid",
                "sink_argument_fact_uid",
                "source_event_uid",
                "sink_event_uid",
            ),
            "qualified_complete_typed_ast_and_cfg_path",
        ),
        _spec(
            "qualified_command_source_controllable",
            "contract_type",
            "source_controllability",
            "exact_binding",
            (
                "parameter_uid",
                "parameter_fact_uid",
                "sink_argument_fact_uid",
                "sink_event_uid",
            ),
            "qualified_entry_parameter_to_command_sink",
        ),
        _spec(
            "qualified_command_path_complete",
            "path_guard",
            "source_sink_reachability",
            "exists_path",
            (
                "parameter_uid",
                "parameter_fact_uid",
                "sink_argument_fact_uid",
                "sink_event_uid",
            ),
            "qualified_entry_parameter_to_command_sink",
        ),
        _spec(
            "qualified_command_sink_contract",
            "contract_type",
            "caller_contract",
            "exact_binding",
            (
                "parameter_uid",
                "parameter_fact_uid",
                "sink_argument_fact_uid",
                "sink_event_uid",
            ),
            "qualified_entry_parameter_to_command_sink",
        ),
        _spec(
            "qualified_command_counterproof_absent",
            "path_guard",
            "guard_dominance",
            "for_all_paths",
            (
                "parameter_uid",
                "parameter_fact_uid",
                "sink_argument_fact_uid",
                "sink_event_uid",
            ),
            "qualified_entry_parameter_to_command_sink",
        ),
        _spec(
            "qualified_leak_acquisition_identity",
            "contract_type",
            "object_identity",
            "exact_binding",
            ("resource_uid", "acquisition_event_uid"),
            "qualified_resource_ownership_closure",
        ),
        _spec(
            "qualified_leak_exit_outstanding",
            "resource",
            "cleanup_coverage",
            "for_all_exits",
            ("resource_uid", "acquisition_event_uid"),
            "qualified_resource_ownership_closure",
        ),
        _spec(
            "qualified_leak_transfer_excluded",
            "resource",
            "ownership_transfer",
            "for_all_paths",
            ("resource_uid", "acquisition_event_uid"),
            "qualified_resource_ownership_closure",
        ),
        _spec(
            "qualified_leak_cleanup_complete",
            "resource",
            "cleanup_coverage",
            "for_all_exits",
            ("resource_uid", "acquisition_event_uid"),
            "qualified_resource_ownership_closure",
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


def _typed_ast_facts(summary: Mapping[str, Any], fact_kind: str) -> list[Mapping[str, Any]]:
    return [
        value
        for value in summary.get("wrapper_summaries") or []
        if isinstance(value, Mapping)
        and value.get("summary_kind") == "typed_ast_value_fact"
        and value.get("fact_kind") == fact_kind
    ]


def _typed_ast_complete(summary: Mapping[str, Any]) -> bool:
    markers = [
        value
        for value in summary.get("wrapper_summaries") or []
        if isinstance(value, Mapping) and value.get("summary_kind") == "typed_ast_value_coverage"
    ]
    return len(markers) == 1 and markers[0].get("complete") is True


_COMPOUND_CONTRACT_BINDING_VERSION = "zscope.compound-contract-binding.v1"
_FUNCTION_IR_STATEMENT_SUMMARY_VERSION = "zscope.function-ir-statement-summary.v1"
_CROSS_THREAD_FUNCTION_IR_VERSION = "zscope.cross-thread-function-ir.v1"
_CROSS_THREAD_FUNCTION_IR_PRODUCER = "zscope.clang-cross-thread-function-ir.v1"
_COMPOUND_CONTRACT_BINDING_KEYS = frozenset(
    {
        "summary_kind",
        "schema_version",
        "qualification_uid",
        "qualification_ref",
        "qualified_predicates",
        "content_sha256",
    }
)
_FUNCTION_IR_STATEMENT_SUMMARY_KEYS = frozenset(
    {
        "summary_kind",
        "schema_version",
        "statement_uid",
        "node_uid",
        "ordinal",
        "text",
        "text_sha256",
        "content_sha256",
    }
)
_CROSS_THREAD_FUNCTION_IR_KEYS = frozenset(
    {
        "summary_kind",
        "schema_version",
        "producer_id",
        "candidate_function_uid",
        "candidate_ir_sha256",
        "project_revision_sha256",
        "object_binding",
        "creator_graph",
        "worker_graphs",
        "content_sha256",
    }
)
_CROSS_THREAD_OBJECT_BINDING_KEYS = frozenset(
    {
        "object_uid",
        "declaration_uid",
        "declaration_file",
        "declaration_line",
        "storage_duration",
        "atomic",
        "field_sensitive_identity_complete",
        "content_sha256",
    }
)


def compound_contract_binding() -> Dict[str, Any]:
    """Return the exact independent qualification bound to compound facts.

    The binding is product-owned and reconstructed by the checker.  A model or
    Validator cannot substitute a different qualification hash or predicate
    set merely by placing an object in an evidence pack.
    """

    from ....semantics.security_specs.qualification import load_builtin_qualification

    qualification = load_builtin_qualification()
    body = {
        "summary_kind": "compound_contract_binding",
        "schema_version": _COMPOUND_CONTRACT_BINDING_VERSION,
        "qualification_uid": str(qualification["qualification_uid"]),
        "qualification_ref": str(qualification["content_sha256"]),
        "qualified_predicates": sorted(map(str, qualification["qualified_predicates"])),
    }
    return {**body, "content_sha256": content_sha256(body)}


def build_cross_thread_function_ir(
    *,
    candidate_graph: "FunctionIRGraph",
    creator_graph: "FunctionIRGraph",
    worker_graphs: Sequence["FunctionIRGraph"],
    object_uid: str,
    declaration_uid: str,
    declaration_file: str,
    declaration_line: int,
    project_revision_sha256: str,
) -> Dict[str, Any]:
    """Build the product-owned cross-thread IR accepted by race predicates.

    This object is proof input, not a certificate.  The provider reconstructs
    every FunctionIRGraph, thread-entry edge, access mode, must-lockset and
    synchronization domain from it.  In particular, no Validator verdict or
    precomputed ``conflicting``/``no_happens_before`` boolean is accepted.
    """

    workers = tuple(worker_graphs)
    if (
        len(workers) != 2
        or len({value.function for value in workers}) != 2
        or candidate_graph.function not in {value.function for value in workers}
        or creator_graph.function in {value.function for value in workers}
        or not re.fullmatch(r"[A-Za-z_]\w*", str(object_uid or ""))
        or not str(declaration_uid or "")
        or not str(declaration_file or "")
        or int(declaration_line) <= 0
        or not re.fullmatch(r"[0-9a-f]{64}", str(project_revision_sha256 or ""))
    ):
        raise ValueError("invalid_cross_thread_function_ir_identity")
    all_graphs = (creator_graph, *workers)
    if any(
        not value.coverage_complete
        or value.unresolved_dynamic_edges
        or not re.fullmatch(r"[0-9a-f]{64}", value.ir_sha256)
        or not re.fullmatch(r"[0-9a-f]{64}", value.code_snapshot_sha256)
        or not re.fullmatch(r"[0-9a-f]{64}", value.backend_sha256)
        for value in all_graphs
    ):
        raise ValueError("incomplete_cross_thread_function_ir_graph")
    object_body = {
        "object_uid": str(object_uid),
        "declaration_uid": str(declaration_uid),
        "declaration_file": str(declaration_file),
        "declaration_line": int(declaration_line),
        "storage_duration": "static",
        "atomic": False,
        "field_sensitive_identity_complete": True,
    }
    object_binding = {
        **object_body,
        "content_sha256": content_sha256(object_body),
    }
    body = {
        "summary_kind": "cross_thread_function_ir",
        "schema_version": _CROSS_THREAD_FUNCTION_IR_VERSION,
        "producer_id": _CROSS_THREAD_FUNCTION_IR_PRODUCER,
        "candidate_function_uid": candidate_graph.function,
        "candidate_ir_sha256": candidate_graph.ir_sha256,
        "project_revision_sha256": str(project_revision_sha256),
        "object_binding": object_binding,
        "creator_graph": creator_graph.to_dict(),
        "worker_graphs": [
            value.to_dict() for value in sorted(workers, key=lambda item: item.function)
        ],
    }
    return {**body, "content_sha256": content_sha256(body)}


def _validated_cross_thread_function_ir(
    summary: Mapping[str, Any],
) -> Optional[Dict[str, Any]]:
    from ..function_ir import graph_from_mapping

    candidates = [
        dict(value)
        for value in summary.get("wrapper_summaries") or []
        if isinstance(value, Mapping) and value.get("summary_kind") == "cross_thread_function_ir"
    ]
    if len(candidates) != 1:
        return None
    raw = candidates[0]
    if (
        set(raw) != _CROSS_THREAD_FUNCTION_IR_KEYS
        or raw.get("schema_version") != _CROSS_THREAD_FUNCTION_IR_VERSION
        or raw.get("producer_id") != _CROSS_THREAD_FUNCTION_IR_PRODUCER
        or not re.fullmatch(r"[0-9a-f]{64}", str(raw.get("project_revision_sha256") or ""))
    ):
        return None
    body = dict(raw)
    supplied = str(body.pop("content_sha256", ""))
    if supplied != content_sha256(body):
        return None
    object_binding = raw.get("object_binding")
    if (
        not isinstance(object_binding, Mapping)
        or set(object_binding) != _CROSS_THREAD_OBJECT_BINDING_KEYS
    ):
        return None
    object_body = dict(object_binding)
    object_digest = str(object_body.pop("content_sha256", ""))
    if (
        object_digest != content_sha256(object_body)
        or not re.fullmatch(r"[A-Za-z_]\w*", str(object_binding.get("object_uid") or ""))
        or not str(object_binding.get("declaration_uid") or "")
        or not str(object_binding.get("declaration_file") or "")
        or int(object_binding.get("declaration_line") or 0) <= 0
        or object_binding.get("storage_duration") != "static"
        or object_binding.get("atomic") is not False
        or object_binding.get("field_sensitive_identity_complete") is not True
    ):
        return None
    try:
        creator = graph_from_mapping(raw.get("creator_graph") or {})
        workers = [graph_from_mapping(value) for value in raw.get("worker_graphs") or []]
    except (TypeError, ValueError):
        return None
    if (
        len(workers) != 2
        or len({value.function for value in workers}) != 2
        or creator.function in {value.function for value in workers}
        or any(
            not value.coverage_complete or value.unresolved_dynamic_edges
            for value in (creator, *workers)
        )
        or str(raw.get("candidate_function_uid") or "") != str(summary.get("function_uid") or "")
        or str(raw.get("candidate_function_uid") or "") not in {value.function for value in workers}
        or str(raw.get("candidate_ir_sha256") or "")
        != next(
            (
                value.ir_sha256
                for value in workers
                if value.function == str(raw.get("candidate_function_uid") or "")
            ),
            "",
        )
        or str(summary.get("code_sha256") or "")
        != next(
            (
                value.code_snapshot_sha256
                for value in workers
                if value.function == str(raw.get("candidate_function_uid") or "")
            ),
            "",
        )
        or str(summary.get("backend_sha256") or "")
        != next(
            (
                value.backend_sha256
                for value in workers
                if value.function == str(raw.get("candidate_function_uid") or "")
            ),
            "",
        )
    ):
        return None
    return {
        "raw": raw,
        "creator": creator,
        "workers": workers,
        "object_binding": dict(object_binding),
    }


def function_ir_compound_wrappers(
    graph: "FunctionIRGraph",
    *,
    cross_thread_function_ir: Optional[Mapping[str, Any]] = None,
) -> list[Dict[str, Any]]:
    """Freeze statement text needed for ownership counterproof recomputation.

    FunctionSecuritySummary already freezes CFG statement identities but not
    their text.  These individually sealed wrappers preserve the missing
    deterministic input without accepting any statement supplied by a model.
    """

    wrappers = [compound_contract_binding()]
    for block in graph.blocks:
        for statement in block.statements:
            body = {
                "summary_kind": "function_ir_statement",
                "schema_version": _FUNCTION_IR_STATEMENT_SUMMARY_VERSION,
                "statement_uid": statement.statement_uid,
                "node_uid": statement.block_uid,
                "ordinal": statement.ordinal,
                "text": statement.text,
                "text_sha256": content_sha256(statement.text),
            }
            wrappers.append({**body, "content_sha256": content_sha256(body)})
    if cross_thread_function_ir is not None:
        # The full verifier runs after the wrapper is bound into the function
        # summary.  Here we accept only the exact sealed producer envelope;
        # malformed input is omitted so the race obligation stays open.
        raw = dict(cross_thread_function_ir)
        body = dict(raw)
        supplied = str(body.pop("content_sha256", ""))
        if (
            set(raw) == _CROSS_THREAD_FUNCTION_IR_KEYS
            and raw.get("schema_version") == _CROSS_THREAD_FUNCTION_IR_VERSION
            and raw.get("producer_id") == _CROSS_THREAD_FUNCTION_IR_PRODUCER
            and supplied == content_sha256(body)
            and raw.get("candidate_function_uid") == graph.function
            and raw.get("candidate_ir_sha256") == graph.ir_sha256
        ):
            wrappers.append(raw)
    return wrappers


def _compound_contract_qualified(
    summary: Mapping[str, Any],
    *,
    required_predicates: Sequence[str],
) -> bool:
    bindings = [
        value
        for value in summary.get("wrapper_summaries") or []
        if isinstance(value, Mapping) and value.get("summary_kind") == "compound_contract_binding"
    ]
    if len(bindings) != 1:
        return False
    binding = dict(bindings[0])
    if set(binding) != _COMPOUND_CONTRACT_BINDING_KEYS:
        return False
    try:
        expected = compound_contract_binding()
    except (KeyError, TypeError, ValueError):
        return False
    return bool(
        binding == expected
        and set(map(str, required_predicates))
        <= set(map(str, binding.get("qualified_predicates") or []))
    )


def _statement_records(summary: Mapping[str, Any]) -> Optional[Dict[str, Mapping[str, Any]]]:
    expected_locations = {
        str(statement_uid): (str(node.get("node_uid") or ""), ordinal)
        for node in summary.get("cfg_nodes") or []
        if isinstance(node, Mapping)
        for ordinal, statement_uid in enumerate(node.get("statement_uids") or [])
        if str(statement_uid)
    }
    records: Dict[str, Mapping[str, Any]] = {}
    for raw in summary.get("wrapper_summaries") or []:
        if not isinstance(raw, Mapping) or raw.get("summary_kind") != "function_ir_statement":
            continue
        value = dict(raw)
        if set(value) != _FUNCTION_IR_STATEMENT_SUMMARY_KEYS:
            return None
        statement_uid = str(value.get("statement_uid") or "")
        location = expected_locations.get(statement_uid)
        if (
            not statement_uid
            or statement_uid in records
            or location != (str(value.get("node_uid") or ""), int(value.get("ordinal") or 0))
            or str(value.get("schema_version") or "") != _FUNCTION_IR_STATEMENT_SUMMARY_VERSION
            or str(value.get("text_sha256") or "") != content_sha256(str(value.get("text") or ""))
        ):
            return None
        body = dict(value)
        supplied = str(body.pop("content_sha256", ""))
        if supplied != content_sha256(body):
            return None
        records[statement_uid] = value
    return records if set(records) == set(expected_locations) else None


def _integer_type_is_unsigned(value: Any) -> bool:
    text = str(value or "").lower().replace("_t", "")
    if "ssize" in text:
        return False
    return bool("unsigned" in text or "size" in text or text in {"ulong", "uint"})


def _integer_type_is_signed(value: Any) -> bool:
    text = str(value or "").lower().replace("_t", "")
    if not text or _integer_type_is_unsigned(text):
        return False
    return bool(
        "signed" in text or "ssize" in text or text in {"int", "long", "short", "char", "long long"}
    )


def _thread_entry_target(statement: str, callee: str) -> str:
    if callee == "pthread_create":
        match = re.fullmatch(
            r"\s*pthread_create\s*\(\s*[^,()]+\s*,\s*[^,()]+\s*,\s*&?\s*"
            r"([A-Za-z_]\w*)\s*,\s*[^,()]+\s*\)\s*;?\s*",
            statement,
        )
    elif callee == "thrd_create":
        match = re.fullmatch(
            r"\s*thrd_create\s*\(\s*[^,()]+\s*,\s*&?\s*([A-Za-z_]\w*)\s*,\s*"
            r"[^,()]+\s*\)\s*;?\s*",
            statement,
        )
    else:
        return ""
    return str(match.group(1)) if match else ""


def _graph_statement(graph: Any, statement_uid: str) -> Optional[Any]:
    return graph.statement_map.get(statement_uid)


def _race_access_mode(statement: str, object_uid: str) -> str:
    if not re.search(rf"\b{re.escape(object_uid)}\b", statement):
        return ""
    # The qualified identity is an exact scalar object.  Pointer/member/index
    # syntax would require alias and bounds domains not carried by this IR.
    if re.search(
        rf"(?:->|\.|\[)\s*{re.escape(object_uid)}\b|"
        rf"\b{re.escape(object_uid)}\b\s*(?:->|\.|\[)|"
        rf"(?:\*|&)\s*{re.escape(object_uid)}\b",
        statement,
    ):
        return ""
    if re.search(r"\b(?:_Atomic|atomic_|__atomic|__sync)\w*", statement):
        return ""
    target = re.escape(object_uid)
    if re.search(rf"(?:\+\+|--)\s*\b{target}\b|\b{target}\b\s*(?:\+\+|--)", statement):
        return "write"
    if re.search(rf"\b{target}\b\s*(?:<<|>>|[+\-*/%&|^])?=(?!=)", statement):
        return "write"
    return "read"


def qualified_race_options(summary: Mapping[str, Any]) -> list[Dict[str, Any]]:
    """Recompute one strict two-thread data-race obligation.

    The accepted shape is intentionally narrow: two independently created
    workers, one exact static non-atomic scalar object, one reachable access in
    each worker, no locks at either access, and no call/synchronization event in
    either worker or the creator beyond the two create operations.  Anything
    richer stays open for a future complete cross-thread backend.
    """

    if not _compound_contract_qualified(
        summary,
        required_predicates=("lock", "unlock", "caller_contract"),
    ):
        return []
    bundle = _validated_cross_thread_function_ir(summary)
    if bundle is None:
        return []
    creator = bundle["creator"]
    workers = sorted(bundle["workers"], key=lambda value: value.function)
    object_uid = str(bundle["object_binding"].get("object_uid") or "")

    creator_events = list(creator.events)
    create_events = [value for value in creator_events if value.kind == "thread_create"]
    if len(create_events) != 2 or any(
        value.kind not in {"thread_create", "return"} for value in creator_events
    ):
        return []
    creator_allowed_statements = {
        value.statement_uid for value in creator_events if value.kind in {"thread_create", "return"}
    }
    if any(
        statement.statement_uid not in creator_allowed_statements
        for block in creator.blocks
        for statement in block.statements
        if statement.text.strip()
    ):
        # A local flag/condition operation around creation could itself
        # establish ordering that this deliberately narrow IR does not model.
        return []
    create_by_worker: Dict[str, Any] = {}
    for event in create_events:
        statement = _graph_statement(creator, event.statement_uid)
        if statement is None:
            return []
        target = _thread_entry_target(statement.text, event.callee)
        if not target or target in create_by_worker:
            return []
        create_by_worker[target] = event
    if set(create_by_worker) != {value.function for value in workers}:
        return []

    accesses: list[Dict[str, Any]] = []
    for worker in workers:
        # Unknown calls, joins, atomics or hidden synchronization make the
        # happens-before domain incomplete.  A return event is harmless.
        if any(value.kind != "return" for value in worker.events):
            return []
        matches = []
        unsupported_statement = False
        for block in worker.blocks:
            for statement in block.statements:
                mode = _race_access_mode(statement.text, object_uid)
                if mode:
                    matches.append((statement, mode))
                elif statement.text.strip() and not re.fullmatch(
                    r"\s*return(?:\s+[^;]+)?\s*;?\s*",
                    statement.text,
                ):
                    # An unmodeled read/write, atomic flag, condition, fence or
                    # local transformation may carry synchronization.  Absence
                    # of a call event is not proof of absence of happens-before.
                    unsupported_statement = True
        if unsupported_statement:
            return []
        if len(matches) != 1:
            return []
        statement, mode = matches[0]
        path = worker.reachable(worker.entry_block_uid, statement.block_uid)
        if not path:
            return []
        locksets = worker.must_hold_locksets_at_statements()
        if statement.statement_uid not in locksets or locksets[statement.statement_uid]:
            return []
        accesses.append(
            {
                "function_uid": worker.function,
                "statement_uid": statement.statement_uid,
                "create_event_uid": create_by_worker[worker.function].event_uid,
                "mode": mode,
                "path_node_uids": list(path),
                "must_hold_locks": [],
            }
        )
    if not any(value["mode"] == "write" for value in accesses):
        return []
    left, right = accesses
    fixed_parameters = {
        "object_uid": object_uid,
        "creator_function_uid": creator.function,
        "left_function_uid": str(left["function_uid"]),
        "left_statement_uid": str(left["statement_uid"]),
        "left_create_event_uid": str(left["create_event_uid"]),
        "right_function_uid": str(right["function_uid"]),
        "right_statement_uid": str(right["statement_uid"]),
        "right_create_event_uid": str(right["create_event_uid"]),
    }
    return [
        {
            "fixed_parameters": fixed_parameters,
            "actual": {
                "shared_object_identity": True,
                "conflicting_accesses": True,
                "cross_thread_reachable": True,
                "must_hold_locks": [],
                "happens_before": False,
                "object_uid": object_uid,
                "access_modes": [str(left["mode"]), str(right["mode"])],
            },
            "witness": {
                "creator_function_uid": creator.function,
                "accesses": accesses,
                "object_binding_sha256": str(bundle["object_binding"].get("content_sha256") or ""),
                "cross_thread_ir_sha256": str(bundle["raw"].get("content_sha256") or ""),
            },
        }
    ]


_SIGNED_RESULT_APIS = frozenset({"read", "readv", "pread", "recv", "recvfrom", "recvmsg"})
_UNSIGNED_LENGTH_SINK_ARGUMENTS: Dict[str, frozenset[int]] = {
    "malloc": frozenset({0}),
    "realloc": frozenset({1}),
    "memcpy": frozenset({2}),
    "memmove": frozenset({2}),
    "strncpy": frozenset({2}),
    "strncat": frozenset({2}),
    "write": frozenset({2}),
    "send": frozenset({2}),
    "sendto": frozenset({2}),
}


def _event_for_call(
    summary: Mapping[str, Any],
    *,
    callee: str,
    line: int,
) -> Optional[Mapping[str, Any]]:
    matches = []
    for event in _events(summary):
        attributes = event.get("attributes")
        attributes = attributes if isinstance(attributes, Mapping) else {}
        if str(attributes.get("callee") or "") != callee:
            continue
        if line and int(attributes.get("source_line") or 0) != line:
            continue
        matches.append(event)
    return matches[0] if len(matches) == 1 else None


def _negative_guard_exists(
    summary: Mapping[str, Any],
    *,
    value_uid: str,
    after_line: int,
    before_line: int,
) -> bool:
    for guard in _typed_ast_facts(summary, "terminating_guard"):
        line = int(guard.get("line") or 0)
        if line and not (after_line <= line <= before_line):
            continue
        for comparison in guard.get("comparisons") or []:
            if not isinstance(comparison, Mapping):
                continue
            opcode = str(comparison.get("opcode") or "")
            lhs_refs = {str(value) for value in comparison.get("lhs_refs") or []}
            rhs_refs = {str(value) for value in comparison.get("rhs_refs") or []}
            lhs_literals = {str(value) for value in comparison.get("lhs_integer_literals") or []}
            rhs_literals = {str(value) for value in comparison.get("rhs_integer_literals") or []}
            if value_uid in lhs_refs and "0" in rhs_literals and opcode in {"<", "<="}:
                return True
            if value_uid in rhs_refs and "0" in lhs_literals and opcode in {">", ">="}:
                return True
    return False


def signed_unsigned_flow_options(summary: Mapping[str, Any]) -> list[Dict[str, str]]:
    """Return exact typed-AST/CFG identities for unguarded signed-length flows."""

    complete, _ = _summary_complete(summary)
    statement_records = _statement_records(summary)
    if not complete or not _typed_ast_complete(summary) or statement_records is None:
        return []
    assignments = _typed_ast_facts(summary, "call_assignment")
    arguments = _typed_ast_facts(summary, "call_argument")
    options: list[Dict[str, str]] = []
    for source in assignments:
        value_uid = str(source.get("target") or "")
        source_callee = str(source.get("callee") or "").lower()
        source_line = int(source.get("line") or 0)
        if (
            not value_uid
            or source_callee not in _SIGNED_RESULT_APIS
            or not _integer_type_is_signed(source.get("result_type"))
        ):
            continue
        source_event = _event_for_call(summary, callee=source_callee, line=source_line)
        if source_event is None:
            continue
        for sink in arguments:
            sink_callee = str(sink.get("callee") or "").lower()
            argument_index = int(sink.get("argument_index") or 0)
            sink_line = int(sink.get("line") or 0)
            if argument_index not in _UNSIGNED_LENGTH_SINK_ARGUMENTS.get(sink_callee, frozenset()):
                continue
            refs = {str(value) for value in sink.get("refs") or []}
            ref_types = sink.get("ref_types")
            ref_types = ref_types if isinstance(ref_types, Mapping) else {}
            if (
                value_uid not in refs
                or not _integer_type_is_unsigned(sink.get("argument_type"))
                or (
                    value_uid in ref_types and not _integer_type_is_signed(ref_types.get(value_uid))
                )
                or (source_line and sink_line and sink_line < source_line)
                or _negative_guard_exists(
                    summary,
                    value_uid=value_uid,
                    after_line=source_line,
                    before_line=sink_line,
                )
            ):
                continue
            sink_event = _event_for_call(summary, callee=sink_callee, line=sink_line)
            if sink_event is None:
                continue
            source_node = str(source_event.get("node_uid") or "")
            sink_node = str(sink_event.get("node_uid") or "")
            path = _reachable_path(summary, source_node, sink_node)
            if not path:
                continue
            if source_node == sink_node and _event_ordinal(source_event) > _event_ordinal(
                sink_event
            ):
                continue
            source_statement_uid = str(source_event.get("statement_uid") or "")
            sink_statement_uid = str(sink_event.get("statement_uid") or "")
            if any(
                statement_uid not in {source_statement_uid, sink_statement_uid}
                and str(record.get("node_uid") or "") in path
                and re.search(
                    rf"\b{re.escape(value_uid)}\b",
                    str(record.get("text") or ""),
                )
                for statement_uid, record in statement_records.items()
            ):
                # Function-local path existence does not preserve taint/range
                # through an intervening clamp, reassignment, alias or call.
                # Until a value-versioned def-use chain is frozen, keep it open.
                continue
            options.append(
                {
                    "value_uid": value_uid,
                    "source_assignment_fact_uid": str(source.get("fact_uid") or ""),
                    "sink_argument_fact_uid": str(sink.get("fact_uid") or ""),
                    "source_event_uid": str(source_event.get("event_uid") or ""),
                    "sink_event_uid": str(sink_event.get("event_uid") or ""),
                }
            )
    unique = {tuple(sorted(value.items())): value for value in options}
    return [unique[key] for key in sorted(unique)]


def qualified_bounds_options(summary: Mapping[str, Any]) -> list[Dict[str, str]]:
    """Return only qualification-backed, complete signed-length violations."""

    if not _compound_contract_qualified(
        summary,
        required_predicates=("source", "sink", "caller_contract"),
    ):
        return []
    return signed_unsigned_flow_options(summary)


_COMMAND_SINK_ARGUMENTS: Dict[str, frozenset[int]] = {
    "system": frozenset({0}),
    "popen": frozenset({0}),
    "execl": frozenset({0}),
    "execlp": frozenset({0}),
    "execle": frozenset({0}),
    "execv": frozenset({0}),
    "execvp": frozenset({0}),
    "execve": frozenset({0}),
}


def qualified_command_flow_options(summary: Mapping[str, Any]) -> list[Dict[str, str]]:
    """Keep command flows open until an exact caller contract is available.

    A function-local parameter declaration and a direct call to ``system`` do
    not establish that the parameter is externally controllable.  The generic
    SecuritySpec qualification binds the predicate implementation, not the
    closed-world contract of this particular entry/function.  No product
    producer currently freezes that exact caller contract into Proof IR, so a
    command candidate must remain ``needs_review`` even when its local path is
    syntactically direct.  Retaining the narrow recomputation below would make
    a model/candidate label an accidental substitute for the missing contract.
    """

    return []


def _unqualified_command_flow_options(summary: Mapping[str, Any]) -> list[Dict[str, str]]:
    """Local-only diagnostic retained for future exact-contract integration."""

    complete, _ = _summary_complete(summary)
    records = _statement_records(summary)
    if (
        not complete
        or not _typed_ast_complete(summary)
        or records is None
        or not _compound_contract_qualified(
            summary,
            required_predicates=("source", "sink", "caller_contract", "sanitize"),
        )
    ):
        return []
    parameters = _typed_ast_facts(summary, "parameter")
    arguments = _typed_ast_facts(summary, "call_argument")
    options: list[Dict[str, str]] = []
    entry_node = str(summary.get("entry_node_uid") or "")
    event_by_uid = {str(value.get("event_uid") or ""): value for value in _events(summary)}
    for parameter in parameters:
        parameter_uid = str(parameter.get("name") or "")
        parameter_fact_uid = str(parameter.get("fact_uid") or "")
        if not parameter_uid or not parameter_fact_uid:
            continue
        for sink in arguments:
            callee = str(sink.get("callee") or "").lower()
            argument_index = int(sink.get("argument_index") or 0)
            refs = [str(value) for value in sink.get("refs") or [] if str(value)]
            if argument_index not in _COMMAND_SINK_ARGUMENTS.get(callee, frozenset()) or refs != [
                parameter_uid
            ]:
                continue
            sink_event = _event_for_call(summary, callee=callee, line=int(sink.get("line") or 0))
            if sink_event is None:
                continue
            sink_node = str(sink_event.get("node_uid") or "")
            path = _reachable_path(summary, entry_node, sink_node)
            if not path:
                continue
            sink_statement_uid = str(sink_event.get("statement_uid") or "")
            # A direct command call is the only statement on the selected
            # entry-to-sink slice allowed to mention the source parameter.
            # Unknown calls, assignments, guards and ownership transfers all
            # fail closed instead of being guessed safe or unsafe.
            unresolved_reference = False
            for statement_uid, record in records.items():
                if statement_uid == sink_statement_uid:
                    continue
                if str(record.get("node_uid") or "") not in path:
                    continue
                text = str(record.get("text") or "")
                if re.search(rf"\b{re.escape(parameter_uid)}\b", text):
                    unresolved_reference = True
                    break
            if unresolved_reference:
                continue
            fixed = {
                "parameter_uid": parameter_uid,
                "parameter_fact_uid": parameter_fact_uid,
                "sink_argument_fact_uid": str(sink.get("fact_uid") or ""),
                "sink_event_uid": str(sink_event.get("event_uid") or ""),
            }
            if all(fixed.values()) and fixed["sink_event_uid"] in event_by_uid:
                options.append(fixed)
    unique = {tuple(sorted(value.items())): value for value in options}
    return [unique[key] for key in sorted(unique)]


_RESOURCE_ACQUIRE_APIS = frozenset(
    {"malloc", "calloc", "realloc", "strdup", "open", "fopen", "socket"}
)
_RESOURCE_RELEASE_APIS = frozenset({"free", "close", "fclose", "munmap"})


def _qualified_local_resource_declaration(
    summary: Mapping[str, Any],
    *,
    resource_uid: str,
    acquisition_callee: str,
) -> Optional[Mapping[str, Any]]:
    """Return the unique complete local declaration for an acquired object.

    The ownership proof is function-local.  It may therefore close only when
    Clang proves that the acquisition target is an automatic local variable;
    a same-named global, static local, field, or out parameter must stay open.
    """

    if not _typed_ast_complete(summary):
        return None
    matches = [
        value
        for value in _typed_ast_facts(summary, "variable_declaration")
        if str(value.get("name") or "") == resource_uid
    ]
    if len(matches) != 1:
        return None
    declaration = matches[0]
    storage = str(declaration.get("storage_class") or "").strip().lower()
    type_name = str(declaration.get("type") or "").strip()
    if storage not in {"", "auto", "register"} or not type_name:
        return None
    normalized_type = re.sub(r"\s+", " ", type_name).strip().lower()
    if re.search(r"\b(?:_atomic|atomic_)\w*", normalized_type):
        return None
    if acquisition_callee in {"malloc", "calloc", "realloc", "strdup", "fopen"}:
        if "*" not in normalized_type:
            return None
    elif acquisition_callee in {"open", "socket"}:
        if not (
            _integer_type_is_signed(normalized_type) or _integer_type_is_unsigned(normalized_type)
        ):
            return None
    else:
        return None
    return declaration


def _resource_cleanup_state(
    summary: Mapping[str, Any],
    *,
    resource_uid: str,
) -> Optional[Dict[str, Any]]:
    nodes = _node_ids(summary)
    entry = str(summary.get("entry_node_uid") or "")
    exits = [str(value) for value in summary.get("exit_node_uids") or []]
    if not nodes or entry not in nodes or not exits or not set(exits) <= nodes:
        return None
    predecessors = _predecessors(summary)
    by_node: Dict[str, list[Mapping[str, Any]]] = {value: [] for value in nodes}
    for event in _events(summary):
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
    if rounds > max(8, len(nodes) * 4):
        return None
    uncovered = sorted(value for value in exits if outgoing.get(value, False))
    covered = sorted(value for value in exits if not outgoing.get(value, False))
    return {
        "cleanup_complete": not uncovered,
        "covered_exits": covered,
        "uncovered_exits": uncovered,
    }


def qualified_resource_leak_options(summary: Mapping[str, Any]) -> list[Dict[str, Any]]:
    """Return exact resource identity/cleanup/transfer closure options.

    Passing an owned object to an unknown callee, returning it, storing it in a
    different lvalue, reassigning the identity, or taking its address makes the
    closed-world ownership predicate unavailable.  No heuristic aliases are
    accepted.
    """

    complete, _ = _summary_complete(summary)
    records = _statement_records(summary)
    if (
        not complete
        or records is None
        or not _compound_contract_qualified(
            summary,
            required_predicates=("acquire", "release", "transfer", "callback_retains"),
        )
    ):
        return []
    reachable = _reachable_nodes(summary)
    events = [value for value in _events(summary) if str(value.get("node_uid") or "") in reachable]
    options: list[Dict[str, Any]] = []
    resource_uids = sorted(
        {
            str(subject)
            for event in events
            if event.get("kind") == "resource_acquire"
            for subject in event.get("subject_uids") or []
            if str(subject)
        }
    )
    for resource_uid in resource_uids:
        acquisitions = [
            event
            for event in events
            if event.get("kind") == "resource_acquire"
            and resource_uid in [str(value) for value in event.get("subject_uids") or []]
        ]
        if len(acquisitions) != 1:
            continue
        acquisition = acquisitions[0]
        acquisition_callee = str(
            (acquisition.get("attributes") or {}).get("callee")
            if isinstance(acquisition.get("attributes"), Mapping)
            else ""
        ).lower()
        if acquisition_callee not in _RESOURCE_ACQUIRE_APIS:
            continue
        local_declaration = _qualified_local_resource_declaration(
            summary,
            resource_uid=resource_uid,
            acquisition_callee=acquisition_callee,
        )
        if local_declaration is None:
            continue
        acquisition_statement_uid = str(acquisition.get("statement_uid") or "")
        acquisition_record = records.get(acquisition_statement_uid)
        if acquisition_record is None:
            continue
        acquisition_text = str(acquisition_record.get("text") or "")
        if "=" not in acquisition_text:
            continue
        lhs = acquisition_text.split("=", 1)[0]
        lhs_identities = re.findall(r"\b[A-Za-z_]\w*\b", lhs)
        if not lhs_identities or lhs_identities[-1] != resource_uid:
            continue

        ownership_closed = True
        for statement_uid, record in records.items():
            if statement_uid == acquisition_statement_uid:
                continue
            if str(record.get("node_uid") or "") not in reachable:
                continue
            text = str(record.get("text") or "")
            if not re.search(rf"\b{re.escape(resource_uid)}\b", text):
                continue
            matching_events = [
                event for event in events if str(event.get("statement_uid") or "") == statement_uid
            ]
            if len(matching_events) > 1:
                ownership_closed = False
                break
            event = matching_events[0] if matching_events else None
            kind = str(event.get("kind") or "") if event else ""
            attributes = event.get("attributes") if event else {}
            attributes = attributes if isinstance(attributes, Mapping) else {}
            callee = str(attributes.get("callee") or "").lower()
            if kind == "resource_release" and callee in _RESOURCE_RELEASE_APIS:
                if re.search(
                    rf"\b{re.escape(callee)}\s*\(\s*{re.escape(resource_uid)}\s*\)",
                    text,
                ):
                    continue
                ownership_closed = False
                break
            if kind in {"call", "resource_acquire"}:
                ownership_closed = False
                break
            if re.search(rf"\breturn\b[^;]*\b{re.escape(resource_uid)}\b", text):
                ownership_closed = False
                break
            if "=" in text:
                assign_lhs, assign_rhs = text.split("=", 1)
                if re.search(rf"\b{re.escape(resource_uid)}\b", assign_rhs):
                    lhs_symbols = re.findall(r"\b[A-Za-z_]\w*\b", assign_lhs)
                    if not lhs_symbols or lhs_symbols[-1] != resource_uid:
                        ownership_closed = False
                        break
                if re.search(rf"\b{re.escape(resource_uid)}\b", assign_lhs):
                    ownership_closed = False
                    break
            if re.search(rf"&\s*{re.escape(resource_uid)}\b", text):
                ownership_closed = False
                break
        if not ownership_closed:
            continue
        cleanup = _resource_cleanup_state(summary, resource_uid=resource_uid)
        if cleanup is None:
            continue
        options.append(
            {
                "fixed_parameters": {
                    "resource_uid": resource_uid,
                    "acquisition_event_uid": str(acquisition.get("event_uid") or ""),
                },
                "actual": {
                    "exact_acquisition_identity": True,
                    "outstanding_on_reachable_exit": bool(cleanup["uncovered_exits"]),
                    "ownership_transfer_excluded": True,
                    "local_declaration_fact_uid": str(local_declaration.get("fact_uid") or ""),
                    **cleanup,
                },
            }
        )
    return sorted(
        options,
        key=lambda value: tuple(sorted(map(str, value["fixed_parameters"].items()))),
    )


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

    race_predicates = {
        "qualified_race_shared_object_identity",
        "qualified_race_conflicting_accesses",
        "qualified_race_cross_thread_reachability",
        "qualified_race_empty_locksets",
        "qualified_race_no_happens_before",
    }
    if predicate_id in race_predicates:
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        fixed = {str(key): str(value) for key, value in parameters.items()}
        selected = next(
            (
                value
                for value in qualified_race_options(summary)
                if {str(key): str(item) for key, item in value["fixed_parameters"].items()} == fixed
            ),
            None,
        )
        if selected is None:
            return _unknown(spec, "qualified_cross_thread_race_unresolved")
        actual = dict(selected["actual"])
        race_witness = selected["witness"]
        accesses = list(race_witness["accesses"])
        path_nodes = [
            f"{access['function_uid']}:{node_uid}"
            for access in accesses
            for node_uid in access["path_node_uids"]
        ]
        path_edges = [
            [
                f"{access['function_uid']}:{left}",
                f"{access['function_uid']}:{right}",
            ]
            for access in accesses
            for left, right in zip(
                access["path_node_uids"],
                access["path_node_uids"][1:],
            )
        ]
        required = [
            *fixed.values(),
            str(race_witness["object_binding_sha256"]),
            str(race_witness["cross_thread_ir_sha256"]),
        ]
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": list(dict.fromkeys(path_nodes)),
                "cfg_edges": path_edges,
                "path_node_uids": list(dict.fromkeys(path_nodes)),
                "exit_node_uids": [],
                "values": {
                    **actual,
                    "creator_function_uid": race_witness["creator_function_uid"],
                    "accesses": accesses,
                    "object_binding_sha256": race_witness["object_binding_sha256"],
                    "cross_thread_ir_sha256": race_witness["cross_thread_ir_sha256"],
                },
            },
            enumerated=required,
            required=required,
            reason="qualified_cross_thread_race_recomputed",
        )

    bounds_predicates = {
        "qualified_bounds_source_controllable",
        "qualified_bounds_path_complete",
        "qualified_bounds_sink_contract",
        "qualified_bounds_range_violation",
    }
    if predicate_id in bounds_predicates:
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        fixed = {str(key): str(value) for key, value in parameters.items()}
        if fixed not in qualified_bounds_options(summary):
            return _unknown(spec, "qualified_bounds_obligation_unresolved")
        event_map = {str(value.get("event_uid") or ""): value for value in _events(summary)}
        source_event = event_map.get(fixed["source_event_uid"], {})
        sink_event = event_map.get(fixed["sink_event_uid"], {})
        source_node = str(source_event.get("node_uid") or "")
        sink_node = str(sink_event.get("node_uid") or "")
        path = _reachable_path(summary, source_node, sink_node)
        actual = {
            "source_controllable": True,
            "path_exists": True,
            "dangerous_sink_contract": True,
            "range_violation": True,
            "value_uid": fixed["value_uid"],
        }
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": path,
                "cfg_edges": [list(value) for value in zip(path, path[1:])],
                "path_node_uids": path,
                "exit_node_uids": [],
                "values": actual,
            },
            enumerated=[
                str(value.get("fact_uid") or "")
                for value in summary.get("wrapper_summaries") or []
                if isinstance(value, Mapping) and value.get("fact_uid")
            ]
            + [str(value.get("event_uid") or "") for value in _events(summary)],
            required=(
                fixed["source_assignment_fact_uid"],
                fixed["sink_argument_fact_uid"],
                fixed["source_event_uid"],
                fixed["sink_event_uid"],
            ),
            reason="qualified_signed_length_obligation_recomputed",
        )

    command_predicates = {
        "qualified_command_source_controllable",
        "qualified_command_path_complete",
        "qualified_command_sink_contract",
        "qualified_command_counterproof_absent",
    }
    if predicate_id in command_predicates:
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        fixed = {str(key): str(value) for key, value in parameters.items()}
        if fixed not in qualified_command_flow_options(summary):
            return _unknown(spec, "qualified_command_flow_unresolved")
        event_map = {str(value.get("event_uid") or ""): value for value in _events(summary)}
        sink_event = event_map.get(fixed["sink_event_uid"], {})
        sink_node = str(sink_event.get("node_uid") or "")
        path = _reachable_path(summary, str(summary.get("entry_node_uid") or ""), sink_node)
        actual = {
            "source_controllable": True,
            "path_exists": True,
            "dangerous_sink_contract": True,
            "guard_or_sanitizer_counterproof_absent": True,
            "parameter_uid": fixed["parameter_uid"],
        }
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": path,
                "cfg_edges": [list(value) for value in zip(path, path[1:])],
                "path_node_uids": path,
                "exit_node_uids": [],
                "values": actual,
            },
            enumerated=[
                str(value.get("fact_uid") or "")
                for value in summary.get("wrapper_summaries") or []
                if isinstance(value, Mapping) and value.get("fact_uid")
            ]
            + [str(value.get("event_uid") or "") for value in _events(summary)],
            required=(
                fixed["parameter_fact_uid"],
                fixed["sink_argument_fact_uid"],
                fixed["sink_event_uid"],
            ),
            reason="qualified_entry_parameter_command_flow_recomputed",
        )

    leak_predicates = {
        "qualified_leak_acquisition_identity",
        "qualified_leak_exit_outstanding",
        "qualified_leak_transfer_excluded",
        "qualified_leak_cleanup_complete",
    }
    if predicate_id in leak_predicates:
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        fixed = {str(key): str(value) for key, value in parameters.items()}
        options = qualified_resource_leak_options(summary)
        selected = next(
            (
                value
                for value in options
                if {str(key): str(item) for key, item in value["fixed_parameters"].items()} == fixed
            ),
            None,
        )
        if selected is None:
            return _unknown(spec, "qualified_resource_ownership_unresolved")
        actual = dict(selected["actual"])
        statement_records = _statement_records(summary) or {}
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": sorted(_node_ids(summary)),
                "cfg_edges": [list(value) for value in sorted(_edges(summary))],
                "path_node_uids": [],
                "exit_node_uids": list(summary.get("exit_node_uids") or []),
                "values": actual,
            },
            enumerated=[
                *sorted(statement_records),
                *sorted(_node_ids(summary)),
                *sorted(
                    str(value.get("event_uid") or "")
                    for value in _events(summary)
                    if value.get("event_uid")
                ),
            ],
            required=(
                fixed["acquisition_event_uid"],
                *map(str, summary.get("exit_node_uids") or []),
            ),
            reason="qualified_resource_ownership_closure_recomputed",
        )

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

    if predicate_id == "signed_value_reaches_unsigned_sink":
        if not complete:
            return _unknown(spec, unresolved[0] if unresolved else "function_cfg_incomplete")
        if not _typed_ast_complete(summary):
            return _unknown(spec, "typed_ast_value_facts_incomplete")
        fixed = {str(key): str(value) for key, value in parameters.items()}
        options = signed_unsigned_flow_options(summary)
        if fixed not in options:
            return _unknown(spec, "signed_unsigned_flow_identity_unresolved")
        event_map = {str(value.get("event_uid") or ""): value for value in _events(summary)}
        source_event = event_map.get(fixed["source_event_uid"], {})
        sink_event = event_map.get(fixed["sink_event_uid"], {})
        source_node = str(source_event.get("node_uid") or "")
        sink_node = str(sink_event.get("node_uid") or "")
        path = _reachable_path(summary, source_node, sink_node)
        actual = {"range_violation": True, "value_uid": fixed["value_uid"]}
        return _complete_result(
            spec,
            actual=actual,
            expected=expected,
            witness={
                "cfg_nodes": path,
                "cfg_edges": [list(value) for value in zip(path, path[1:])],
                "path_node_uids": path,
                "exit_node_uids": [],
                "values": actual,
            },
            enumerated=[
                str(value.get("fact_uid") or "")
                for value in summary.get("wrapper_summaries") or []
                if isinstance(value, Mapping) and value.get("fact_uid")
            ]
            + [
                str(value.get("event_uid") or "")
                for value in _events(summary)
                if value.get("event_uid")
            ],
            required=(
                fixed["source_assignment_fact_uid"],
                fixed["sink_argument_fact_uid"],
                fixed["source_event_uid"],
                fixed["sink_event_uid"],
            ),
            reason="signed_unsigned_sink_flow_recomputed",
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
        signature = str(summary.get("signature") or "")
        signature_frozen = bool(entry_events)
        declared_counts: set[int] = set()
        slots: list[int] = []
        identities: list[str] = []
        for event in entry_events:
            attributes = event.get("attributes")
            attributes = attributes if isinstance(attributes, Mapping) else {}
            subjects = [str(value) for value in event.get("subject_uids") or [] if str(value)]
            raw_slot = attributes.get("parameter_slot")
            raw_count = attributes.get("parameter_count")
            if raw_slot is None or raw_count is None:
                signature_frozen = False
                continue
            try:
                slot = int(raw_slot)
                count = int(raw_count)
            except (TypeError, ValueError):
                signature_frozen = False
                continue
            if (
                attributes.get("entry_signature_complete") is not True
                or str(attributes.get("entry_signature") or "") != signature
                or len(subjects) != 1
                or slot < 0
                or count <= 0
                or slot >= count
            ):
                signature_frozen = False
            declared_counts.add(count)
            slots.append(slot)
            identities.extend(subjects)
        declared_count = next(iter(declared_counts)) if len(declared_counts) == 1 else -1
        signature_frozen = bool(
            signature_frozen
            and declared_count == len(entry_events)
            and sorted(slots) == list(range(declared_count))
            and len(set(identities)) == len(identities) == declared_count
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
                and str(attributes.get("parameter_slot")) == parameter_slot
                and len(subjects) == 1
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
