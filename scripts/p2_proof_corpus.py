"""Deterministically materialize the answer-free P2 proof qualification corpus."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Mapping

from zscope.core.validation.proof_kernel.canonical import content_sha256, seal_mapping
from zscope.core.validation.proof_kernel.checker import ProofChecker
from zscope.core.validation.proof_kernel.models import (
    FUNCTION_SECURITY_SUMMARY_VERSION,
    PROGRAM_PROOF_IR_VERSION,
    PROTOCOL_REVISION,
    build_evidence_action,
    build_proof_clause,
    build_proof_obligation,
)
from zscope.core.validation.proof_kernel.provider import ProofProvider
from zscope.core.validation.proof_kernel.registry import PREDICATE_REGISTRY


TRANSFORMATIONS = (
    "identifier_rename",
    "wrapper_extraction",
    "wrapper_inlining",
    "macro_equivalent",
    "branch_reorder",
    "fixed_pair",
)
STRUCTURE_FAMILIES = ("linear", "branching", "wrapped")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _summary(
    *,
    label: str,
    nodes: list[Dict[str, Any]],
    edges: list[list[str]],
    events: list[Dict[str, Any]],
    exits: list[str],
    complete: bool,
    type_layouts: list[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    payload = {
        "schema_version": FUNCTION_SECURITY_SUMMARY_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "function_uid": f"FUN_{label}",
        "signature": f"int neutral_{label}(void)",
        "file": f"src/p2_{label.split('_', 1)[0]}.c",
        "entry_node_uid": nodes[0]["node_uid"],
        "exit_node_uids": exits,
        "cfg_nodes": nodes,
        "cfg_edges": edges,
        "events": events,
        "type_layouts": type_layouts or [],
        "wrapper_summaries": [],
        "coverage": {
            "complete": complete,
            "unresolved_reasons": [] if complete else ["qualification_partial_coverage"],
        },
        "code_sha256": _digest(f"code:{label}"),
        "backend_sha256": _digest(f"clang-21.1.8:{label}"),
    }
    return seal_mapping(payload, uid_field="summary_uid", prefix="FUNSUM_")


def _program_ir(label: str, summary: Mapping[str, Any]) -> Dict[str, Any]:
    payload = {
        "schema_version": PROGRAM_PROOF_IR_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "language": "c_cpp",
        "project_uid": "PROJECT_P2_QUALIFICATION",
        "revision_uid": "REV_" + _digest("p2-neutral-corpus")[:32],
        "functions": [dict(summary)],
        "dependency_hashes": sorted(
            {
                str(summary["code_sha256"]),
                str(summary["backend_sha256"]),
                _digest(f"dependency:{label}"),
            }
        ),
        "coverage": dict(summary["coverage"]),
    }
    return seal_mapping(payload, uid_field="proof_ir_uid", prefix="PROOFIR_")


def _event(
    label: str,
    ordinal: int,
    node: str,
    statement: str,
    kind: str,
    subjects: list[str],
) -> Dict[str, Any]:
    return {
        "event_uid": "EVENT_" + _digest(f"{label}:{ordinal}:{kind}")[:32],
        "node_uid": node,
        "statement_uid": statement,
        "kind": kind,
        "subject_uids": subjects,
        "attributes": {"callee": "", "source_line": ordinal + 1, "statement_ordinal": ordinal},
    }


def _family_case(family: str, index: int) -> tuple[Dict[str, Any], str, Dict[str, Any], Any]:
    label = f"{family}_{index:02d}"
    positive = index < 10
    partial = index >= 20
    entry, middle, exit_node = f"N_{label}_E", f"N_{label}_M", f"N_{label}_X"

    if family == "concurrency":
        access = f"S_{label}_ACCESS"
        acquire = f"S_{label}_ACQUIRE"
        if 10 <= index < 20:
            nodes = [
                {"node_uid": entry, "statement_uids": []},
                {"node_uid": middle, "statement_uids": [access, acquire]},
                {"node_uid": exit_node, "statement_uids": []},
            ]
            events = [_event(label, 1, middle, acquire, "lock_acquire", ["gate"])]
        else:
            nodes = [
                {"node_uid": entry, "statement_uids": [acquire]},
                {"node_uid": middle, "statement_uids": [access]},
                {"node_uid": exit_node, "statement_uids": []},
            ]
            events = [_event(label, 0, entry, acquire, "lock_acquire", ["gate"])]
        summary = _summary(
            label=label,
            nodes=nodes,
            edges=[[entry, middle], [middle, exit_node]],
            events=events,
            exits=[exit_node],
            complete=not partial,
        )
        return (
            summary,
            "lock_must_hold_at_access",
            {
                "access_statement_uid": access,
                "lock_uid": "gate",
            },
            {"must_hold": True},
        )

    if family == "resource":
        acquire, release = f"S_{label}_ACQUIRE", f"S_{label}_RELEASE"
        nodes = [
            {"node_uid": entry, "statement_uids": [acquire]},
            {"node_uid": middle, "statement_uids": [release] if positive else []},
            {"node_uid": exit_node, "statement_uids": []},
        ]
        events = [_event(label, 0, entry, acquire, "resource_acquire", ["handle"])]
        if positive:
            events.append(_event(label, 0, middle, release, "resource_release", ["handle"]))
        summary = _summary(
            label=label,
            nodes=nodes,
            edges=[[entry, middle], [middle, exit_node]],
            events=events,
            exits=[exit_node],
            complete=not partial,
        )
        return (
            summary,
            "cleanup_covers_all_exits",
            {"resource_uid": "handle"},
            {"cleanup_complete": True},
        )

    if family == "path_guard":
        sink = exit_node
        edges = [[entry, middle], [middle, exit_node]] if positive else [[entry, middle]]
        exits = [exit_node] if positive else [middle]
        nodes = [
            {"node_uid": entry, "statement_uids": [f"S_{label}_SOURCE"]},
            {"node_uid": middle, "statement_uids": []},
            {"node_uid": exit_node, "statement_uids": [f"S_{label}_SINK"]},
        ]
        summary = _summary(
            label=label,
            nodes=nodes,
            edges=edges,
            events=[],
            exits=exits,
            complete=not partial,
        )
        return (
            summary,
            "source_sink_path_exists",
            {
                "source_node_uid": entry,
                "sink_node_uid": sink,
            },
            {"path_exists": True},
        )

    if family == "contract_type":
        nodes = [
            {"node_uid": entry, "statement_uids": []},
            {"node_uid": exit_node, "statement_uids": []},
        ]
        layout_body = {
            "type_uid": "TYPE_PACKET",
            "size_bytes": 16,
            "alignment_bytes": 8,
            "fields": [
                {"name": "length", "offset_bits": 0, "size_bits": 32},
                {"name": "data", "offset_bits": 64, "size_bits": 64},
            ],
            "backend_sha256": _digest(f"clang-21.1.8:{label}"),
        }
        layout = {**layout_body, "layout_sha256": content_sha256(layout_body)}
        if partial:
            layout = {"type_uid": "TYPE_PACKET", "size_bytes": 16}
        summary = _summary(
            label=label,
            nodes=nodes,
            edges=[[entry, exit_node]],
            events=[],
            exits=[exit_node],
            complete=True,
            type_layouts=[layout],
        )
        expected_layout = dict(layout)
        if 10 <= index < 20:
            expected_layout["size_bytes"] = 24
        return (
            summary,
            "record_layout_matches",
            {"type_uid": "TYPE_PACKET"},
            {"layout": expected_layout},
        )

    raise ValueError(f"unknown family: {family}")


def build_case(family: str, index: int) -> Dict[str, Any]:
    label = f"{family}_{index:02d}"
    summary, predicate_id, parameters, expected = _family_case(family, index)
    proof_ir = _program_ir(label, summary)
    spec = PREDICATE_REGISTRY[predicate_id]
    clause = build_proof_clause(
        role="confirmation",
        provider_family=spec.provider_family,
        predicate_id=predicate_id,
        fact_kind=spec.fact_kind,
        quantifier=spec.quantifier,
        expected_value=expected,
        parameters=parameters,
    )
    obligation = build_proof_obligation(
        validation_cluster_uid=f"VAL_{label}",
        defect_family=f"neutral_{family}",
        subject_uid=f"SUBJECT_{label}",
        decision_region_uid=f"REGION_{label}",
        confirmation_clauses=(clause,),
        counterproof_clauses=(),
        open_clauses=(),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    action = build_evidence_action(
        obligation=obligation,
        clause=clause,
        proof_ir=proof_ir,
        provider_id=spec.provider_id,
        verifier_id=spec.verifier_id,
    )
    certificate = ProofProvider().produce(proof_ir=proof_ir, obligation=obligation, action=action)
    check_result = ProofChecker().check(
        proof_ir=proof_ir,
        obligation=obligation,
        action=action,
        certificate=certificate,
    )
    accepted = check_result["status"] == "accepted"
    return {
        "case_uid": "P2CASE_" + _digest(label)[:32],
        "family": family,
        "variant": "positive" if index < 10 else "near_miss_safe",
        "structure_family": STRUCTURE_FAMILIES[index % len(STRUCTURE_FAMILIES)],
        "transformation": TRANSFORMATIONS[index % len(TRANSFORMATIONS)],
        "source_file": f"sources/{family}.c",
        "program_proof_ir": proof_ir,
        "proof_obligation": obligation,
        "evidence_action": action,
        "evidence_certificate": certificate,
        "proof_check_result": check_result,
        "expected": {
            "checker_status": "accepted" if index < 10 else check_result["status"],
            "terminal": "confirmed" if index < 10 else "needs_review",
            "safe_case": index >= 10,
        },
    }


def build_corpus() -> Dict[str, Any]:
    cases = [
        build_case(family, index)
        for family in ("concurrency", "resource", "path_guard", "contract_type")
        for index in range(30)
    ]
    body = {
        "schema_version": "zscope.p2-proof-qualification-corpus.v1",
        "language": "c_cpp",
        "answer_free": True,
        "model_calls": 0,
        "network": False,
        "case_count": len(cases),
        "safe_case_count": sum(bool(value["expected"]["safe_case"]) for value in cases),
        "transformations": list(TRANSFORMATIONS),
        "structure_families": list(STRUCTURE_FAMILIES),
        "cases": cases,
    }
    return {**body, "content_sha256": content_sha256(body)}
