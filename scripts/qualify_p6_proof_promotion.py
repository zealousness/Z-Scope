#!/usr/bin/env python3
"""Build the deterministic, answer-free P6 proof/promotion successor artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from scripts.p2_proof_corpus import build_corpus
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from p2_proof_corpus import build_corpus
from zscope.core.validation.authority import (
    LEGACY_TERMINAL_AUTHORITY_DECISION_V3,
    TerminalAuthorityEvaluator,
    terminal_decision_from_promotion,
)
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import (
    ProofKernelEngine,
    build_evidence_action,
    build_proof_clause,
    build_proof_obligation,
    issue_promotion_certificate,
)
from zscope.core.validation.proof_kernel.canonical import content_sha256
from zscope.core.validation.proof_kernel.checker import ProofChecker
from zscope.core.validation.proof_kernel.provider import ProofProvider
from zscope.orchestration.hypothesis_hunter.resource_proof import (
    resolve_resource_proof_binding,
)
from zscope.orchestration.proof_promotion_qualification import (
    P2_CORPUS_FILE_SHA256,
    P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE,
    P6_PROOF_PROMOTION_QUALIFICATION_VERSION,
    current_dependency_qualifications,
    implementation_root_sha256,
    current_source_hashes,
    protocol_identity,
    validate_successor_freshness,
    validate_successor_qualification,
)
from zscope.orchestration.successor_runtime_review_status import (
    build_in_progress_successor_runtime_review_status,
)
from zscope.semantics.security_map import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "zscope/orchestration" / P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    """Replace one generated JSON resource without exposing a partial file."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _freeze_reduce(
    *,
    proof_ir: Mapping[str, Any],
    obligation: Mapping[str, Any],
    actions: Sequence[Mapping[str, Any]],
    check_results: Sequence[Mapping[str, Any]],
) -> tuple[Any, Any, Mapping[str, Any]]:
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=proof_ir,
        obligation=obligation,
        selected_action_uids=[str(value["action_uid"]) for value in actions],
    )
    expected_checks = sorted(content_sha256(value) for value in check_results)
    actual_checks = sorted(content_sha256(value) for value in evaluation.check_results)
    if actual_checks != expected_checks:
        raise ValueError("successor_checker_recomputation_mismatch")
    authority_input = evaluation.authority_inputs()["proof_kernel_input"]
    return evaluation.frozen_state, evaluation.closure_evaluation, authority_input


def _p2_closure_counts() -> tuple[
    dict[str, int],
    list[tuple[Any, Any, Any, Mapping[str, Any]]],
    tuple[Any, Any, Mapping[str, Any]] | None,
]:
    corpus = build_corpus()
    confirmed = 0
    incomplete = 0
    safe_false_confirmation = 0
    terminal_examples: list[tuple[Any, Any, Any, Mapping[str, Any]]] = []
    incomplete_example: tuple[Any, Any, Mapping[str, Any]] | None = None
    for case in corpus["cases"]:
        state, closure, authority_input = _freeze_reduce(
            proof_ir=case["program_proof_ir"],
            obligation=case["proof_obligation"],
            actions=[case["evidence_action"]],
            check_results=[case["proof_check_result"]],
        )
        if closure.complete:
            promotion = issue_promotion_certificate(
                frozen_state=state,
                closure_evaluation=closure,
            )
            decision = terminal_decision_from_promotion(
                proof_kernel_input=authority_input,
                frozen_state=state,
                closure_evaluation=closure,
                promotion_certificate=promotion,
            )
            if decision.disposition != "confirmed":
                raise ValueError("positive_p2_case_did_not_confirm")
            confirmed += 1
            terminal_examples.append((state, closure, promotion, authority_input))
            if case["expected"]["safe_case"]:
                safe_false_confirmation += 1
        else:
            decision = TerminalAuthorityEvaluator().evaluate(
                {
                    "proof_kernel_frozen_state": state.to_dict(),
                    "proof_kernel_closure_evaluation": closure.to_dict(),
                    "proof_kernel_input": authority_input,
                },
                has_executable_action=False,
            )
            if decision.disposition != "needs_review":
                raise ValueError("incomplete_p2_case_became_terminal_proof")
            incomplete += 1
            if incomplete_example is None:
                incomplete_example = (state, closure, authority_input)
    return (
        {
            "p2_case_count": int(corpus["case_count"]),
            "complete_confirmation_count": confirmed,
            "incomplete_needs_review_count": incomplete,
            "safe_false_confirmation_count": safe_false_confirmation,
        },
        terminal_examples,
        incomplete_example,
    )


def _counterproof_rejection() -> tuple[Any, Any, Any, Mapping[str, Any]]:
    base = next(
        value
        for value in build_corpus()["cases"]
        if value["proof_check_result"]["status"] == "accepted"
    )
    original = base["proof_obligation"]["confirmation_clauses"][0]
    clause = build_proof_clause(
        role="counterproof",
        provider_family=str(original["provider_family"]),
        predicate_id=str(original["predicate_id"]),
        fact_kind=str(original["fact_kind"]),
        quantifier=str(original["quantifier"]),
        expected_value=original["expected_value"],
        parameters=original["parameters"],
    )
    obligation = build_proof_obligation(
        validation_cluster_uid="P6_SUCCESSOR_COUNTERPROOF",
        defect_family=str(base["proof_obligation"]["defect_family"]),
        subject_uid=str(base["proof_obligation"]["subject_uid"]),
        decision_region_uid=str(base["proof_obligation"]["decision_region_uid"]),
        confirmation_clauses=(),
        counterproof_clauses=(clause,),
        open_clauses=(),
        dependency_hashes=base["program_proof_ir"]["dependency_hashes"],
    )
    action = build_evidence_action(
        obligation=obligation,
        clause=clause,
        proof_ir=base["program_proof_ir"],
        provider_id=str(base["evidence_action"]["provider_id"]),
        verifier_id=str(base["evidence_action"]["verifier_id"]),
    )
    certificate = ProofProvider().produce(
        proof_ir=base["program_proof_ir"],
        obligation=obligation,
        action=action,
    )
    checked = ProofChecker().check(
        proof_ir=base["program_proof_ir"],
        obligation=obligation,
        action=action,
        certificate=certificate,
    )
    state, closure, authority_input = _freeze_reduce(
        proof_ir=base["program_proof_ir"],
        obligation=obligation,
        actions=[action],
        check_results=[checked],
    )
    promotion = issue_promotion_certificate(
        frozen_state=state,
        closure_evaluation=closure,
    )
    decision = terminal_decision_from_promotion(
        proof_kernel_input=authority_input,
        frozen_state=state,
        closure_evaluation=closure,
        promotion_certificate=promotion,
    )
    if decision.disposition != "rejected_with_proof":
        raise ValueError("counterproof_did_not_reject")
    return state, closure, promotion, authority_input


def _authority_fail_closed_counts(
    terminal_examples: Sequence[tuple[Any, Any, Any, Mapping[str, Any]]],
    incomplete_example: tuple[Any, Any, Mapping[str, Any]] | None,
) -> dict[str, int]:
    if len(terminal_examples) < 2 or incomplete_example is None:
        raise ValueError("terminal_and_incomplete_examples_required")
    state, closure, promotion, authority_input = terminal_examples[0]
    other_state, other_closure, other_promotion, other_authority_input = terminal_examples[1]
    tampered = promotion.to_dict()
    tampered["proof_root_sha256"] = "0" * 64
    tampered_decision = TerminalAuthorityEvaluator().evaluate(
        {
            "proof_kernel_frozen_state": state.to_dict(),
            "proof_kernel_closure_evaluation": closure.to_dict(),
            "proof_kernel_promotion_certificate": tampered,
            "proof_kernel_input": authority_input,
        }
    )
    cross_decision = TerminalAuthorityEvaluator().evaluate(
        {
            "proof_kernel_frozen_state": state.to_dict(),
            "proof_kernel_closure_evaluation": closure.to_dict(),
            "proof_kernel_promotion_certificate": other_promotion.to_dict(),
            "proof_kernel_input": authority_input,
        }
    )
    legacy_decision = TerminalAuthorityEvaluator().evaluate(
        {
            "proof_kernel_terminal_authority_decision": {
                "schema_version": LEGACY_TERMINAL_AUTHORITY_DECISION_V3,
                "terminal": True,
                "disposition": "confirmed",
                "reason_code": "CONFIRMED_DETERMINISTIC_PROOF",
                "authority": "zscope.proof-checker",
                "checker_result_refs": ["sha256:" + "a" * 64],
                "proof_root_sha256": "b" * 64,
                "integrity_status": "verified",
            }
        }
    )
    fact_complete_decision = TerminalAuthorityEvaluator().evaluate(
        {
            "fact_plan_complete": True,
            "proof_kernel_frozen_state": incomplete_example[0].to_dict(),
            "proof_kernel_closure_evaluation": incomplete_example[1].to_dict(),
            "proof_kernel_input": incomplete_example[2],
        }
    )
    # A valid but incomplete proof stays non-terminal even when the separate
    # fact-plan projection claims completion.
    results = (
        tampered_decision,
        cross_decision,
        legacy_decision,
        fact_complete_decision,
    )
    if any(value.disposition != "needs_review" for value in results):
        raise ValueError("authority_fail_closed_qualification_failed")
    # Silence unused bindings while keeping the cross-obligation construction
    # explicit and independently auditable.
    if other_state.content_sha256 == state.content_sha256 or (
        other_closure.content_sha256 == closure.content_sha256
    ):
        raise ValueError("cross_obligation_examples_not_distinct")
    if other_authority_input == authority_input:
        raise ValueError("cross_obligation_authority_inputs_not_distinct")
    return {
        "complete_counterproof_rejection_count": 1,
        "fact_complete_without_proof_not_promoted_count": 1,
        "tampered_promotion_fail_closed_count": 1,
        "cross_obligation_fail_closed_count": 1,
        "legacy_v3_fail_closed_count": 1,
    }


def _resource_graph(extra_statements: Sequence[str]) -> FunctionIRGraph:
    statements = ["p = malloc(8)", *extra_statements]
    calls = [{"callee": "malloc", "line": 3}]
    for index, statement in enumerate(extra_statements, start=4):
        if "free(" in statement:
            calls.append({"callee": "free", "line": index})
        elif "consume(" in statement:
            calls.append({"callee": "consume", "line": index})
    evidence = {
        "clang_path": "clang-21.1.8",
        "code_snapshot_sha256": content_sha256(statements),
        "unresolved_dynamic_edges": False,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "p6_resource_successor",
                "function_section_unique": True,
                "entry_blocks": ["B1"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B1",
                        "label": "ENTRY",
                        "successors": ["B0"],
                        "predecessors": [],
                        "statements": statements,
                    },
                    {
                        "id": "B0",
                        "label": "EXIT",
                        "successors": [],
                        "predecessors": ["B1"],
                        "statements": [],
                    },
                ],
            }
        },
        "ast_dump": {"summary": {"target_function": {"call_exprs": calls}}},
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="p6_resource_successor",
        file="synthetic/p6_resource_successor.c",
    )
    if graph is None or not graph.coverage_complete:
        raise ValueError("resource_successor_graph_incomplete")
    return graph


def _resource_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="P6_RESOURCE_EVENT",
        family="resource_lifecycle",
        kind="resource_acquire",
        function_uid="p6_resource_successor",
        file="synthetic/p6_resource_successor.c",
        line=3,
        expression="p = malloc(8)",
        evidence_ref="synthetic:p6-resource",
    )


def _resource_counts() -> dict[str, int]:
    event = _resource_event()
    leak = resolve_resource_proof_binding(_resource_graph(()), event)
    cleanup = resolve_resource_proof_binding(_resource_graph(("free(p)",)), event)
    if leak is None or leak.cleanup_complete is not False:
        raise ValueError("resource_exact_leak_binding_failed")
    if cleanup is None or cleanup.cleanup_complete is not True:
        raise ValueError("resource_cleanup_binding_failed")
    escapes = (
        "return p",
        "alias = p",
        "global_owner = p",
        "owner_field = p",
        "out_parameter = p",
        "container_slot = p",
        "callback_slot = p",
        "consume(p)",
    )
    rejected = sum(
        resolve_resource_proof_binding(_resource_graph((statement,)), event) is None
        for statement in escapes
    )
    if rejected != len(escapes):
        raise ValueError("resource_ownership_escape_not_fail_closed")
    return {
        "resource_exact_leak_binding_count": 1,
        "resource_cleanup_binding_count": 1,
        "resource_ownership_escape_rejected_count": rejected,
    }


def qualify() -> dict[str, Any]:
    corpus_path = ROOT / "tests/fixtures/p2_proof_kernel/corpus.json"
    if _sha256_bytes(corpus_path.read_bytes()) != P2_CORPUS_FILE_SHA256:
        raise ValueError("p2_successor_corpus_hash_mismatch")
    p2_counts, terminals, incomplete = _p2_closure_counts()
    _counterproof_rejection()
    counts = {
        **p2_counts,
        **_authority_fail_closed_counts(terminals, incomplete),
        **_resource_counts(),
    }
    source_hashes = current_source_hashes()
    body = {
        "schema_version": P6_PROOF_PROMOTION_QUALIFICATION_VERSION,
        "status": "local_candidate_qualified",
        "requires_independent_review": True,
        "authorizes_phase_completion": False,
        "answer_free": True,
        "network": False,
        "llm_calls": 0,
        "protocol_identity": protocol_identity(),
        "qualification_dependencies": current_dependency_qualifications(),
        "source_sha256": source_hashes,
        "implementation_root_sha256": implementation_root_sha256(source_hashes),
        "case_counts": counts,
        "acceptance": {
            "passed": True,
            "reason_code": "local_candidate_successor_requires_independent_review",
        },
    }
    result = {**body, "content_sha256": content_sha256(body)}
    valid, reason = validate_successor_qualification(result)
    if not valid:
        raise ValueError(reason)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--status-output",
        type=Path,
        help="Atomically reseal the non-authoritative in-progress review projection",
    )
    args = parser.parse_args()
    if args.status_output is not None and (args.output is None or args.check):
        parser.error("--status-output requires --output and cannot be combined with --check")
    result = qualify()
    if args.check:
        try:
            frozen = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            print("P6 proof/promotion successor artifact is missing or invalid")
            return 1
        valid, reason = validate_successor_freshness(frozen)
        if not valid or frozen != result:
            print(f"P6 proof/promotion successor replay mismatch: {reason}")
            return 1
        print(
            "P6 proof/promotion successor qualification passed: "
            f"cases={result['case_counts']['p2_case_count']} "
            f"confirmed={result['case_counts']['complete_confirmation_count']} "
            "review=required"
        )
        return 0
    if args.output is not None:
        _write_json_atomic(args.output, result)
        if args.status_output is not None:
            _write_json_atomic(
                args.status_output,
                build_in_progress_successor_runtime_review_status(result),
            )
        print(result["content_sha256"])
        return 0
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
