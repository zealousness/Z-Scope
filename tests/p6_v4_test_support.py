"""Shared construction of a genuinely producer-bound terminal v4 issue."""

from __future__ import annotations

from typing import Any

from zscope.core.validation.audit_eligibility import (
    revalidate_v4_producer_occurrence_binding,
)
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.fact_capabilities import FunctionIRFactService
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import ProofKernelEngine
from zscope.orchestration.candidate_envelope import annotate_issue_identity


def confirmed_product_v4_issue(
    *,
    project_id: str = "p6-v4-test",
    revision: str = "rev-p6-v4-test",
) -> dict[str, Any]:
    """Build one complete product obligation with physical occurrence binding."""

    call = {
        "callee": "malloc",
        "line": 4,
        "callee_decl_identity": (
            '{"kind":"FunctionDecl","name":"malloc",' '"type":"void *(size_t)"}'
        ),
        "callee_binding_complete": True,
        "callee_decl_origin": "external_declaration",
        "callee_project_definition": False,
        "result_type": "void *",
        "arg_count": 1,
        "argument_kinds": ["IntegerLiteral"],
        "argument_types": ["int"],
        "argument_refs": [[]],
        "argument_ref_types": [{}],
        "first_argument_refs": [],
    }
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "clang_path": "clang",
            "code_snapshot_sha256": "d" * 64,
            "cfg_dump": {
                "summary": {
                    "parse_ok": True,
                    "function": "resource_target",
                    "function_section_unique": True,
                    "entry_blocks": ["B1"],
                    "exit_blocks": ["B0"],
                    "blocks": [
                        {
                            "id": "B1",
                            "label": "(ENTRY)",
                            "successors": ["B0"],
                            "predecessors": [],
                            "statements": ["p = malloc(8)"],
                        },
                        {
                            "id": "B0",
                            "label": "(EXIT)",
                            "successors": [],
                            "predecessors": ["B1"],
                            "statements": [],
                        },
                    ],
                }
            },
            "ast_dump": {
                "summary": {
                    "parse_ok": True,
                    "target_function": {
                        "call_exprs": [call],
                        "call_assignments": [{**call, "target": "p"}],
                        "var_decls": [
                            {
                                "name": "p",
                                "type": "void *",
                                "line": 4,
                                "storage_class": "",
                            }
                        ],
                        "value_fact_coverage_complete": True,
                    },
                }
            },
        },
        function="resource_target",
        file="src/resource.c",
    )
    assert graph is not None and graph.coverage_complete is True
    issue: dict[str, Any] = {
        "candidate_source": "llm",
        "candidate_disposition": "confirmed",
        "status": "confirmed",
        "file": "src/resource.c",
        "line": 4,
        "location": "src/resource.c:4",
        "function": "resource_target",
        "category": "memory_leak",
        "defect_class": "memory_leak",
        "source": {
            "kind": "resource_acquire",
            "function": "resource_target",
            "file": "src/resource.c",
            "line": 4,
            "operation": "malloc",
            "resource": "p",
        },
        "sink": {
            "kind": "exit",
            "function": "resource_target",
            "file": "src/resource.c",
            "line": 4,
            "resource": "p",
        },
        "resource": "p",
        "function_ir_graph": graph.to_dict(),
        "decision_fact_graph_v1": True,
        "decision_context_v31": True,
        "decision_context_v32": True,
        "decision_context_v33": True,
        "security_obligation_v1": True,
        "missing_fact_kinds": [],
        "validator_evidence_actions": [],
    }
    annotate_issue_identity(issue, project_id=project_id, revision=revision)
    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(
        issue,
        {},
    )
    assert frozen is not None
    selected_action_uids = tuple(map(str, frozen["selected_action_uids"]))
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
        selected_action_uids=selected_action_uids,
    )
    assert evaluation.closure_evaluation.complete is True
    issue["proof_kernel_input"] = frozen
    issue["proof_kernel_input_origin"] = "product_composite_obligation_v4"
    issue["proof_kernel_checker_results"] = [dict(value) for value in evaluation.check_results]
    issue["proof_kernel_live_selected_action_uids"] = list(selected_action_uids)
    evaluation.apply_to_issue(issue)
    issue["proof_kernel_artifact_refs"] = list(evaluation.artifact_refs)
    issue["proof_kernel_checker_result_refs"] = list(evaluation.checker_result_refs)
    issue["proof_kernel_root_manifest_sha256"] = evaluation.root_manifest_sha256
    producer_binding, occurrence_binding = revalidate_v4_producer_occurrence_binding(issue)
    assert producer_binding and occurrence_binding
    issue["proof_kernel_producer_binding_sha256"] = producer_binding
    issue["proof_kernel_occurrence_binding_sha256"] = occurrence_binding
    authority = TerminalAuthorityEvaluator().evaluate(issue, operation="live").to_dict()
    assert authority["terminal"] is True and authority["disposition"] == "confirmed"
    issue["proof_kernel_terminal_authority_decision"] = authority
    issue["terminal_authority_decision"] = authority
    return issue


__all__ = ["confirmed_product_v4_issue"]
