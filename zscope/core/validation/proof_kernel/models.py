"""Strict builders and validators for the P2 proof protocol."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

from ..function_ir import FunctionIRGraph
from .canonical import SHA256_RE, content_sha256, seal_mapping, verify_sealed_mapping


PROTOCOL_REVISION = 2
FUNCTION_SECURITY_SUMMARY_VERSION = "zscope.function-security-summary.v2"
PROGRAM_PROOF_IR_VERSION = "zscope.program-proof-ir.v2"
PROOF_OBLIGATION_VERSION = "zscope.proof-obligation.v2"
EVIDENCE_ACTION_VERSION = "zscope.evidence-action.v2"
EVIDENCE_CERTIFICATE_VERSION = "zscope.evidence-certificate.v2"
PROOF_CHECK_RESULT_VERSION = "zscope.proof-check-result.v2"

PROVIDER_FAMILIES = frozenset({"concurrency", "resource", "path_guard", "contract_type"})
QUANTIFIERS = frozenset(
    {
        "must_at_point",
        "for_all_exits",
        "exists_path",
        "for_all_paths",
        "exact_binding",
        "exact_layout",
    }
)

FUNCTION_SUMMARY_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "summary_uid",
        "function_uid",
        "signature",
        "file",
        "entry_node_uid",
        "exit_node_uids",
        "cfg_nodes",
        "cfg_edges",
        "events",
        "type_layouts",
        "wrapper_summaries",
        "coverage",
        "code_sha256",
        "backend_sha256",
        "content_sha256",
    }
)
PROGRAM_IR_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "proof_ir_uid",
        "language",
        "project_uid",
        "revision_uid",
        "functions",
        "dependency_hashes",
        "coverage",
        "content_sha256",
    }
)
CLAUSE_KEYS = frozenset(
    {
        "clause_uid",
        "role",
        "provider_family",
        "predicate_id",
        "fact_kind",
        "quantifier",
        "expected_value",
        "parameters",
        "required",
    }
)
OBLIGATION_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "obligation_uid",
        "validation_cluster_uid",
        "defect_family",
        "subject_uid",
        "decision_region_uid",
        "confirmation_clauses",
        "counterproof_clauses",
        "open_clauses",
        "dependency_hashes",
        "content_sha256",
    }
)
ACTION_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "action_uid",
        "obligation_uid",
        "clause_uid",
        "proof_ir_uid",
        "provider_family",
        "provider_id",
        "verifier_id",
        "predicate_id",
        "fact_kind",
        "quantifier",
        "subject_uid",
        "decision_region_uid",
        "fixed_parameters",
        "dependency_hashes",
        "content_sha256",
    }
)
CERTIFICATE_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "certificate_uid",
        "action_uid",
        "obligation_uid",
        "clause_uid",
        "proof_ir_uid",
        "provider_family",
        "provider_id",
        "provider_version",
        "verifier_id",
        "predicate_id",
        "fact_kind",
        "status",
        "predicate_polarity",
        "quantifier",
        "subject_uid",
        "decision_region_uid",
        "predicate_value",
        "witness",
        "coverage",
        "assumption_ids",
        "code_sha256",
        "ir_sha256",
        "backend_sha256",
        "dependency_hashes",
        "content_sha256",
    }
)
CHECK_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "check_uid",
        "checker_id",
        "checker_version",
        "certificate_uid",
        "action_uid",
        "obligation_uid",
        "clause_uid",
        "proof_ir_uid",
        "status",
        "certificate_status",
        "reason_codes",
        "terminal_contribution",
        "recomputed_coverage",
        "accepted_fact",
        "content_sha256",
    }
)


def _unique_strings(values: Iterable[Any]) -> list[str]:
    return sorted({str(value) for value in values if str(value)})


def _valid_hashes(values: Any, *, nonempty: bool = True) -> bool:
    return bool(
        isinstance(values, list)
        and (values or not nonempty)
        and len(set(map(str, values))) == len(values)
        and all(SHA256_RE.fullmatch(str(value)) for value in values)
    )


def function_summary_from_graph(
    graph: FunctionIRGraph,
    *,
    function_uid: str = "",
    type_layouts: Sequence[Mapping[str, Any]] = (),
    wrapper_summaries: Sequence[Mapping[str, Any]] = (),
) -> Dict[str, Any]:
    unresolved = []
    if not graph.coverage_complete:
        unresolved.append("function_cfg_incomplete")
    if graph.unresolved_dynamic_edges:
        unresolved.append("unresolved_dynamic_edges")
    nodes = [
        {
            "node_uid": block.block_uid,
            "statement_uids": [statement.statement_uid for statement in block.statements],
        }
        for block in graph.blocks
    ]
    edges = sorted(
        [block.block_uid, successor] for block in graph.blocks for successor in block.successors
    )
    statement_ordinals = {
        statement.statement_uid: statement.ordinal
        for block in graph.blocks
        for statement in block.statements
    }
    events = [
        {
            "event_uid": event.event_uid,
            "node_uid": event.block_uid,
            "statement_uid": event.statement_uid,
            "kind": event.kind,
            "subject_uids": list(event.subject_symbols),
            "attributes": {
                "callee": event.callee,
                "source_line": event.source_line,
                "statement_ordinal": statement_ordinals.get(event.statement_uid, -1),
            },
        }
        for event in graph.events
    ]
    payload = {
        "schema_version": FUNCTION_SECURITY_SUMMARY_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "function_uid": str(function_uid or graph.function),
        "signature": graph.function,
        "file": graph.file,
        "entry_node_uid": graph.entry_block_uid,
        "exit_node_uids": list(graph.exit_block_uids),
        "cfg_nodes": nodes,
        "cfg_edges": edges,
        "events": events,
        "type_layouts": [dict(value) for value in type_layouts],
        "wrapper_summaries": [dict(value) for value in wrapper_summaries],
        "coverage": {"complete": not unresolved, "unresolved_reasons": unresolved},
        "code_sha256": graph.code_snapshot_sha256,
        "backend_sha256": graph.backend_sha256,
    }
    return seal_mapping(payload, uid_field="summary_uid", prefix="FUNSUM_")


def program_proof_ir_from_graph(
    graph: FunctionIRGraph,
    *,
    project_uid: str,
    revision_uid: str,
    language: str = "c_cpp",
    type_layouts: Sequence[Mapping[str, Any]] = (),
    wrapper_summaries: Sequence[Mapping[str, Any]] = (),
) -> Dict[str, Any]:
    summary = function_summary_from_graph(
        graph,
        type_layouts=type_layouts,
        wrapper_summaries=wrapper_summaries,
    )
    dependency_hashes = _unique_strings(
        (graph.code_snapshot_sha256, graph.backend_sha256, graph.ir_sha256)
    )
    payload = {
        "schema_version": PROGRAM_PROOF_IR_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "language": language,
        "project_uid": project_uid,
        "revision_uid": revision_uid,
        "functions": [summary],
        "dependency_hashes": dependency_hashes,
        "coverage": dict(summary["coverage"]),
    }
    return seal_mapping(payload, uid_field="proof_ir_uid", prefix="PROOFIR_")


def build_proof_clause(
    *,
    role: str,
    provider_family: str,
    predicate_id: str,
    fact_kind: str,
    quantifier: str,
    expected_value: Any,
    parameters: Mapping[str, Any],
    required: bool = True,
) -> Dict[str, Any]:
    if role not in {"confirmation", "counterproof", "open"}:
        raise ValueError("invalid proof clause role")
    if provider_family not in PROVIDER_FAMILIES:
        raise ValueError("invalid proof provider family")
    if quantifier not in QUANTIFIERS:
        raise ValueError("invalid proof quantifier")
    payload = {
        "role": role,
        "provider_family": provider_family,
        "predicate_id": predicate_id,
        "fact_kind": fact_kind,
        "quantifier": quantifier,
        "expected_value": expected_value,
        "parameters": dict(parameters),
        "required": bool(required),
    }
    digest = content_sha256(payload)
    return {"clause_uid": "PCLAUSE_" + digest[:32], **payload}


def build_proof_obligation(
    *,
    validation_cluster_uid: str,
    defect_family: str,
    subject_uid: str,
    decision_region_uid: str,
    confirmation_clauses: Sequence[Mapping[str, Any]],
    counterproof_clauses: Sequence[Mapping[str, Any]],
    open_clauses: Sequence[Mapping[str, Any]] = (),
    dependency_hashes: Sequence[str],
) -> Dict[str, Any]:
    payload = {
        "schema_version": PROOF_OBLIGATION_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "validation_cluster_uid": validation_cluster_uid,
        "defect_family": defect_family,
        "subject_uid": subject_uid,
        "decision_region_uid": decision_region_uid,
        "confirmation_clauses": [dict(value) for value in confirmation_clauses],
        "counterproof_clauses": [dict(value) for value in counterproof_clauses],
        "open_clauses": [dict(value) for value in open_clauses],
        "dependency_hashes": _unique_strings(dependency_hashes),
    }
    return seal_mapping(payload, uid_field="obligation_uid", prefix="POBL_")


def build_evidence_action(
    *,
    obligation: Mapping[str, Any],
    clause: Mapping[str, Any],
    proof_ir: Mapping[str, Any],
    provider_id: str,
    verifier_id: str,
) -> Dict[str, Any]:
    payload = {
        "schema_version": EVIDENCE_ACTION_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "obligation_uid": str(obligation.get("obligation_uid") or ""),
        "clause_uid": str(clause.get("clause_uid") or ""),
        "proof_ir_uid": str(proof_ir.get("proof_ir_uid") or ""),
        "provider_family": str(clause.get("provider_family") or ""),
        "provider_id": provider_id,
        "verifier_id": verifier_id,
        "predicate_id": str(clause.get("predicate_id") or ""),
        "fact_kind": str(clause.get("fact_kind") or ""),
        "quantifier": str(clause.get("quantifier") or ""),
        "subject_uid": str(obligation.get("subject_uid") or ""),
        "decision_region_uid": str(obligation.get("decision_region_uid") or ""),
        "fixed_parameters": dict(clause.get("parameters") or {}),
        "dependency_hashes": _unique_strings(proof_ir.get("dependency_hashes") or []),
    }
    return seal_mapping(payload, uid_field="action_uid", prefix="EVACTION_")


def validate_function_summary(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="summary_uid",
        prefix="FUNSUM_",
        expected_keys=FUNCTION_SUMMARY_KEYS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != FUNCTION_SECURITY_SUMMARY_VERSION:
        return False, "unsupported_function_summary_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    for key in ("function_uid", "signature", "file"):
        if not str(raw.get(key) or ""):
            return False, f"{key}_required"
    nodes = raw.get("cfg_nodes")
    if not isinstance(nodes, list) or not nodes:
        return False, "function_summary_requires_cfg_nodes"
    node_ids = [str(value.get("node_uid") or "") for value in nodes if isinstance(value, Mapping)]
    if len(node_ids) != len(nodes) or not all(node_ids) or len(set(node_ids)) != len(node_ids):
        return False, "cfg_node_identity_invalid"
    statements: set[str] = set()
    for value in nodes:
        if not isinstance(value, Mapping) or set(value) != {
            "node_uid",
            "statement_uids",
        }:
            return False, "cfg_node_schema_invalid"
        raw_statements = value.get("statement_uids")
        if not isinstance(raw_statements, list):
            return False, "cfg_statement_uids_not_array"
        statement_ids = [str(item) for item in raw_statements if str(item)]
        if (
            len(statement_ids) != len(raw_statements)
            or len(set(statement_ids)) != len(statement_ids)
            or statements.intersection(statement_ids)
        ):
            return False, "cfg_statement_identity_invalid"
        statements.update(statement_ids)
    node_set = set(node_ids)
    if str(raw.get("entry_node_uid") or "") not in node_set:
        return False, "cfg_entry_node_invalid"
    exits = raw.get("exit_node_uids")
    if not isinstance(exits, list) or not exits or not set(map(str, exits)) <= node_set:
        return False, "cfg_exit_nodes_invalid"
    edges = raw.get("cfg_edges")
    if not isinstance(edges, list):
        return False, "cfg_edges_not_array"
    normalized_edges = []
    for edge in edges:
        if not isinstance(edge, list) or len(edge) != 2:
            return False, "cfg_edge_shape_invalid"
        pair = (str(edge[0]), str(edge[1]))
        if not all(pair) or not set(pair) <= node_set:
            return False, "cfg_edge_identity_invalid"
        normalized_edges.append(pair)
    if len(set(normalized_edges)) != len(normalized_edges):
        return False, "cfg_edges_not_unique"
    events = raw.get("events")
    if not isinstance(events, list):
        return False, "function_events_not_array"
    event_uids: set[str] = set()
    entry_parameters: list[tuple[int, str, int, str]] = []
    statement_positions = {
        str(statement): index
        for node in nodes
        for index, statement in enumerate(node.get("statement_uids") or [])
    }
    for event in events:
        if not isinstance(event, Mapping) or set(event) != {
            "event_uid",
            "node_uid",
            "statement_uid",
            "kind",
            "subject_uids",
            "attributes",
        }:
            return False, "function_event_schema_invalid"
        event_uid = str(event.get("event_uid") or "")
        if not event_uid or event_uid in event_uids:
            return False, "event_identity_invalid"
        event_uids.add(event_uid)
        if str(event.get("node_uid") or "") not in node_set:
            return False, "event_cfg_node_invalid"
        statement_uid = str(event.get("statement_uid") or "")
        if not statement_uid or statement_uid not in statements:
            return False, "event_statement_invalid"
        if not str(event.get("kind") or ""):
            return False, "event_kind_required"
        subject_uids = event.get("subject_uids")
        if not isinstance(subject_uids, list) or len({str(value) for value in subject_uids}) != len(
            subject_uids
        ):
            return False, "event_subject_uids_invalid"
        attributes = event.get("attributes")
        if not isinstance(attributes, Mapping):
            return False, "event_attributes_not_object"
        ordinal_value = attributes.get("statement_ordinal")
        if ordinal_value is None:
            return False, "event_statement_ordinal_invalid"
        try:
            ordinal = int(ordinal_value)
        except (TypeError, ValueError):
            return False, "event_statement_ordinal_invalid"
        if statement_uid and ordinal != statement_positions.get(statement_uid):
            return False, "event_statement_order_mismatch"
        if event.get("kind") == "entry_parameter":
            subjects = [str(value) for value in subject_uids if str(value)]
            if len(subjects) != 1:
                return False, "entry_parameter_identity_invalid"
            raw_parameter_slot = attributes.get("parameter_slot")
            raw_parameter_count = attributes.get("parameter_count")
            if raw_parameter_slot is None or raw_parameter_count is None:
                return False, "entry_parameter_slot_or_count_invalid"
            try:
                parameter_slot = int(raw_parameter_slot)
                parameter_count = int(raw_parameter_count)
            except (TypeError, ValueError):
                return False, "entry_parameter_slot_or_count_invalid"
            if (
                attributes.get("entry_signature_complete") is not True
                or parameter_slot < 0
                or parameter_count <= 0
                or parameter_slot >= parameter_count
                or str(attributes.get("entry_signature") or "") != str(raw.get("signature") or "")
            ):
                return False, "entry_parameter_signature_binding_invalid"
            entry_parameters.append((parameter_slot, subjects[0], parameter_count, event_uid))
    if entry_parameters:
        declared_counts = {value[2] for value in entry_parameters}
        slots = [value[0] for value in entry_parameters]
        identities = [value[1] for value in entry_parameters]
        declared_count = next(iter(declared_counts)) if len(declared_counts) == 1 else -1
        if (
            len(declared_counts) != 1
            or declared_count != len(entry_parameters)
            or sorted(slots) != list(range(declared_count))
            or len(set(identities)) != len(identities)
        ):
            return False, "entry_parameter_signature_domain_incomplete"
    for key in ("code_sha256", "backend_sha256"):
        if not SHA256_RE.fullmatch(str(raw.get(key) or "")):
            return False, f"{key}_invalid"
    for key in ("type_layouts", "wrapper_summaries"):
        values = raw.get(key)
        if not isinstance(values, list) or any(not isinstance(value, Mapping) for value in values):
            return False, f"{key}_invalid"
    coverage = raw.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != {"complete", "unresolved_reasons"}:
        return False, "function_coverage_schema_invalid"
    unresolved = coverage.get("unresolved_reasons")
    if (
        not isinstance(coverage.get("complete"), bool)
        or not isinstance(unresolved, list)
        or len({str(value) for value in unresolved}) != len(unresolved)
    ):
        return False, "function_coverage_reasons_not_array"
    if coverage.get("complete") is True and unresolved:
        return False, "complete_function_has_coverage_gaps"
    if coverage.get("complete") is False and not unresolved:
        return False, "incomplete_function_requires_coverage_gap"
    if coverage.get("complete") is True:
        successors: Dict[str, set[str]] = {value: set() for value in node_set}
        for source, target in normalized_edges:
            successors[source].add(target)
        reachable = {str(raw.get("entry_node_uid") or "")}
        pending = list(reachable)
        while pending:
            current = pending.pop()
            for target in successors.get(current, set()):
                if target not in reachable:
                    reachable.add(target)
                    pending.append(target)
        reachable_terminals = {value for value in reachable if not successors.get(value)}
        if set(map(str, exits)) != reachable_terminals:
            return False, "complete_cfg_exit_set_mismatch"
    return True, "ok"


def validate_program_ir(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="proof_ir_uid",
        prefix="PROOFIR_",
        expected_keys=PROGRAM_IR_KEYS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != PROGRAM_PROOF_IR_VERSION:
        return False, "unsupported_program_ir_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    if raw.get("language") not in {"c_cpp", "java"}:
        return False, "unsupported_program_ir_language"
    functions = raw.get("functions")
    if not isinstance(functions, list) or not functions:
        return False, "program_ir_requires_function"
    for value in functions:
        if not isinstance(value, Mapping):
            return False, "function_summary_not_object"
        valid, detail = validate_function_summary(value)
        if not valid:
            return False, detail
    dependencies = raw.get("dependency_hashes")
    if not _valid_hashes(dependencies):
        return False, "program_ir_dependency_hashes_invalid"
    assert isinstance(dependencies, list)
    required_dependencies = {
        str(value.get(key) or "")
        for value in functions
        for key in ("code_sha256", "backend_sha256")
    }
    if not required_dependencies <= {str(value) for value in dependencies}:
        return False, "program_ir_dependency_binding_incomplete"
    coverage = raw.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != {"complete", "unresolved_reasons"}:
        return False, "program_ir_coverage_schema_invalid"
    unresolved = coverage.get("unresolved_reasons")
    if (
        not isinstance(coverage.get("complete"), bool)
        or not isinstance(unresolved, list)
        or len({str(value) for value in unresolved}) != len(unresolved)
    ):
        return False, "program_ir_coverage_values_invalid"
    function_complete = all(
        isinstance(value.get("coverage"), Mapping)
        and value["coverage"].get("complete") is True
        and not value["coverage"].get("unresolved_reasons")
        for value in functions
    )
    if coverage.get("complete") is not function_complete:
        return False, "program_ir_coverage_binding_mismatch"
    if coverage.get("complete") is True and unresolved:
        return False, "complete_program_ir_has_coverage_gaps"
    if coverage.get("complete") is False and not unresolved:
        return False, "incomplete_program_ir_requires_coverage_gap"
    return True, "ok"


def _validate_clause(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    if set(raw) != CLAUSE_KEYS:
        return False, "proof_clause_schema_keys_mismatch"
    body = dict(raw)
    supplied_uid = str(body.pop("clause_uid", ""))
    if supplied_uid != "PCLAUSE_" + content_sha256(body)[:32]:
        return False, "proof_clause_uid_mismatch"
    if raw.get("role") not in {"confirmation", "counterproof", "open"}:
        return False, "invalid_proof_clause_role"
    if raw.get("provider_family") not in PROVIDER_FAMILIES:
        return False, "invalid_provider_family"
    if raw.get("quantifier") not in QUANTIFIERS:
        return False, "invalid_quantifier"
    return True, "ok"


def validate_obligation(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="obligation_uid",
        prefix="POBL_",
        expected_keys=OBLIGATION_KEYS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != PROOF_OBLIGATION_VERSION:
        return False, "unsupported_obligation_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    for key in ("validation_cluster_uid", "defect_family", "subject_uid", "decision_region_uid"):
        if not str(raw.get(key) or ""):
            return False, f"{key}_required"
    if not _valid_hashes(raw.get("dependency_hashes")):
        return False, "obligation_dependency_hashes_invalid"
    clause_uids = []
    for key, role in (
        ("confirmation_clauses", "confirmation"),
        ("counterproof_clauses", "counterproof"),
        ("open_clauses", "open"),
    ):
        values = raw.get(key)
        if not isinstance(values, list):
            return False, "proof_clauses_not_array"
        for value in values:
            if not isinstance(value, Mapping):
                return False, "proof_clause_not_object"
            valid, detail = _validate_clause(value)
            if not valid:
                return False, detail
            if value.get("role") != role:
                return False, "proof_clause_role_bucket_mismatch"
            clause_uids.append(str(value.get("clause_uid") or ""))
    if len(set(clause_uids)) != len(clause_uids):
        return False, "proof_clause_uid_not_unique"
    return True, "ok"


def validate_action(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="action_uid",
        prefix="EVACTION_",
        expected_keys=ACTION_KEYS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != EVIDENCE_ACTION_VERSION:
        return False, "unsupported_evidence_action_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    for key in (
        "obligation_uid",
        "clause_uid",
        "proof_ir_uid",
        "provider_family",
        "provider_id",
        "verifier_id",
        "predicate_id",
        "fact_kind",
        "quantifier",
        "subject_uid",
        "decision_region_uid",
    ):
        if not str(raw.get(key) or ""):
            return False, f"{key}_required"
    if not isinstance(raw.get("fixed_parameters"), Mapping):
        return False, "fixed_parameters_not_object"
    if raw.get("provider_family") not in PROVIDER_FAMILIES:
        return False, "invalid_provider_family"
    if raw.get("quantifier") not in QUANTIFIERS:
        return False, "invalid_quantifier"
    if not _valid_hashes(raw.get("dependency_hashes")):
        return False, "action_dependency_hashes_invalid"
    return True, "ok"


def validate_certificate_envelope(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    if (
        raw.get("schema_version") == EVIDENCE_CERTIFICATE_VERSION
        and raw.get("protocol_revision") != 2
    ):
        return False, "legacy_preview"
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="certificate_uid",
        prefix="CERT_",
        expected_keys=CERTIFICATE_KEYS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != EVIDENCE_CERTIFICATE_VERSION:
        return False, "unsupported_certificate_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    if raw.get("status") not in {"verified_true", "verified_false", "unknown", "conflicting"}:
        return False, "invalid_certificate_status"
    if raw.get("predicate_polarity") not in {"supports", "refutes"}:
        return False, "invalid_certificate_polarity"
    witness = raw.get("witness")
    if not isinstance(witness, Mapping) or set(witness) != {
        "cfg_nodes",
        "cfg_edges",
        "path_node_uids",
        "exit_node_uids",
        "values",
    }:
        return False, "certificate_witness_schema_invalid"
    for key in ("cfg_nodes", "path_node_uids", "exit_node_uids"):
        values = witness.get(key)
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value for value in values)
            or len(set(values)) != len(values)
        ):
            return False, f"certificate_witness_{key}_invalid"
    edges = witness.get("cfg_edges")
    if not isinstance(edges, list) or any(
        not isinstance(value, list)
        or len(value) != 2
        or any(not isinstance(item, str) or not item for item in value)
        for value in edges
    ):
        return False, "certificate_witness_cfg_edges_invalid"
    if not isinstance(witness.get("values"), Mapping):
        return False, "certificate_witness_values_invalid"
    coverage = raw.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != {
        "domain",
        "enumerated_uids",
        "required_uids",
        "complete",
        "unresolved_reasons",
    }:
        return False, "certificate_coverage_schema_invalid"
    enumerated = coverage.get("enumerated_uids")
    required = coverage.get("required_uids")
    unresolved = coverage.get("unresolved_reasons")
    if not all(
        isinstance(values, list)
        and all(isinstance(value, str) and value for value in values)
        and len(set(values)) == len(values)
        for values in (enumerated, required, unresolved)
    ) or not isinstance(coverage.get("complete"), bool):
        return False, "certificate_coverage_values_invalid"
    assert isinstance(enumerated, list)
    assert isinstance(required, list)
    assert isinstance(unresolved, list)
    if coverage.get("complete") is True and (unresolved or not set(required) <= set(enumerated)):
        return False, "certificate_complete_coverage_invalid"
    if coverage.get("complete") is False and not unresolved:
        return False, "certificate_incomplete_coverage_requires_reason"
    for key in ("code_sha256", "ir_sha256", "backend_sha256"):
        if not SHA256_RE.fullmatch(str(raw.get(key) or "")):
            return False, f"certificate_{key}_invalid"
    if not _valid_hashes(raw.get("dependency_hashes")):
        return False, "certificate_dependency_hashes_invalid"
    return True, "ok"


def validate_check_result(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="check_uid",
        prefix="PCHECK_",
        expected_keys=CHECK_RESULT_KEYS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != PROOF_CHECK_RESULT_VERSION:
        return False, "unsupported_check_result_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    if raw.get("status") not in {"accepted", "rejected", "unknown", "conflicting"}:
        return False, "invalid_check_status"
    if raw.get("terminal_contribution") not in {"none", "confirmation", "counterproof"}:
        return False, "invalid_terminal_contribution"
    reasons = raw.get("reason_codes")
    if not isinstance(reasons, list) or not reasons or len(set(map(str, reasons))) != len(reasons):
        return False, "check_reason_codes_invalid"
    if not isinstance(raw.get("recomputed_coverage"), Mapping):
        return False, "check_recomputed_coverage_invalid"
    if raw.get("status") == "accepted" and not isinstance(raw.get("accepted_fact"), Mapping):
        return False, "accepted_check_requires_fact"
    if raw.get("status") != "accepted" and raw.get("accepted_fact") is not None:
        return False, "nonaccepted_check_has_fact"
    return True, "ok"
