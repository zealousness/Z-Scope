import threading

from zscope.alerts.adapter import ExternalAlert
from zscope.alerts.verifier import AlertVerifier
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import (
    PREDICATE_REGISTRY,
    ProofKernelEngine,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
)


def _alert(idx: int, *, raw=None) -> ExternalAlert:
    return ExternalAlert(
        tool="codeql",
        rule_id=f"rule-{idx}",
        message=f"alert {idx}",
        file_path=f"src/demo_{idx}.c",
        line=idx,
        raw=raw or {},
    )


def _proof_input_with_unknown_required_counterproof() -> dict:
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "clang_path": "clang-21.1.8",
            "code_snapshot_sha256": "a" * 64,
            "unresolved_dynamic_edges": True,
            "cfg_dump": {
                "summary": {
                    "parse_ok": True,
                    "function": "neutral_worker",
                    "function_section_unique": True,
                    "entry_blocks": ["B2"],
                    "exit_blocks": ["B0"],
                    "blocks": [
                        {
                            "id": "B2",
                            "label": "ENTRY",
                            "successors": ["B1"],
                            "predecessors": [],
                            "statements": ["consume(input)"],
                        },
                        {
                            "id": "B1",
                            "label": "",
                            "successors": ["B0"],
                            "predecessors": ["B2"],
                            "statements": ["return 0"],
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
            "ast_dump": {
                "summary": {"target_function": {"call_exprs": [{"callee": "consume", "line": 3}]}}
            },
        },
        function="neutral_worker",
        file="src/neutral_worker.c",
    )
    assert graph is not None
    proof_ir = program_proof_ir_from_graph(
        graph, project_uid="PROJECT_ALERT", revision_uid="REV_ALERT"
    )
    spec = PREDICATE_REGISTRY["source_sink_path_exists"]
    confirmation = build_proof_clause(
        role="confirmation",
        provider_family=spec.provider_family,
        predicate_id=spec.predicate_id,
        fact_kind=spec.fact_kind,
        quantifier=spec.quantifier,
        expected_value={"path_exists": True},
        parameters={"source_node_uid": "B2", "sink_node_uid": "B1"},
    )
    counterproof = build_proof_clause(
        role="counterproof",
        provider_family=spec.provider_family,
        predicate_id=spec.predicate_id,
        fact_kind=spec.fact_kind,
        quantifier=spec.quantifier,
        expected_value={"path_exists": False},
        parameters={"source_node_uid": "B1", "sink_node_uid": "B2"},
    )
    obligation = build_proof_obligation(
        validation_cluster_uid="VAL_ALERT_REQUIRED_COUNTERPROOF",
        defect_family="neutral_family",
        subject_uid="SUBJECT_ALERT",
        decision_region_uid="REGION_ALERT",
        confirmation_clauses=(confirmation,),
        counterproof_clauses=(counterproof,),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    actions = ProofKernelEngine().action_catalog(
        proof_ir=proof_ir,
        obligation=obligation,
    )
    return {
        "proof_ir": proof_ir,
        "proof_obligation": obligation,
        "selected_action_uids": [value["action_uid"] for value in actions],
    }


def _terminal_path_proof_input(*, role: str) -> dict:
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "clang_path": "clang-21.1.8",
            "code_snapshot_sha256": "b" * 64,
            "unresolved_dynamic_edges": False,
            "cfg_dump": {
                "summary": {
                    "parse_ok": True,
                    "function": "sealed_worker",
                    "function_section_unique": True,
                    "entry_blocks": ["B2"],
                    "exit_blocks": ["B0"],
                    "blocks": [
                        {
                            "id": "B2",
                            "label": "ENTRY",
                            "successors": ["B1"],
                            "predecessors": [],
                            "statements": ["consume(input)"],
                        },
                        {
                            "id": "B1",
                            "label": "",
                            "successors": ["B0"],
                            "predecessors": ["B2"],
                            "statements": ["return 0"],
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
            "ast_dump": {
                "summary": {"target_function": {"call_exprs": [{"callee": "consume", "line": 3}]}}
            },
        },
        function="sealed_worker",
        file="src/sealed_worker.c",
    )
    assert graph is not None
    proof_ir = program_proof_ir_from_graph(
        graph, project_uid="PROJECT_ALERT", revision_uid="REV_ALERT_V4"
    )
    spec = PREDICATE_REGISTRY["source_sink_path_exists"]
    if role == "confirmation":
        parameters = {"source_node_uid": "B2", "sink_node_uid": "B1"}
        expected = {"path_exists": True}
    else:
        assert role == "counterproof"
        parameters = {"source_node_uid": "B1", "sink_node_uid": "B2"}
        expected = {"path_exists": False}
    clause = build_proof_clause(
        role=role,
        provider_family=spec.provider_family,
        predicate_id=spec.predicate_id,
        fact_kind=spec.fact_kind,
        quantifier=spec.quantifier,
        expected_value=expected,
        parameters=parameters,
    )
    obligation = build_proof_obligation(
        validation_cluster_uid=f"VAL_ALERT_{role.upper()}",
        defect_family="neutral_family",
        subject_uid="SUBJECT_ALERT",
        decision_region_uid="REGION_ALERT",
        confirmation_clauses=((clause,) if role == "confirmation" else ()),
        counterproof_clauses=((clause,) if role == "counterproof" else ()),
        dependency_hashes=proof_ir["dependency_hashes"],
    )
    actions = ProofKernelEngine().action_catalog(
        proof_ir=proof_ir,
        obligation=obligation,
    )
    return {
        "proof_ir": proof_ir,
        "proof_obligation": obligation,
        "selected_action_uids": [value["action_uid"] for value in actions],
    }


def test_alert_verifier_uses_workers_and_preserves_order() -> None:
    class ParallelVerifier(AlertVerifier):
        def __init__(self) -> None:
            self.barrier = threading.Barrier(2, timeout=2)
            self.thread_names: list[str] = []
            self.lock = threading.Lock()

        def _verify_single(self, alert: ExternalAlert, idx: int) -> dict:
            with self.lock:
                self.thread_names.append(threading.current_thread().name)
            if idx <= 2:
                self.barrier.wait()
            return {
                "alert_id": f"ALERT_{idx}",
                "idx": idx,
                "verdict": "uncertain",
                "candidate_disposition": "needs_review",
            }

    verifier = ParallelVerifier()
    results = verifier.verify_alerts([_alert(1), _alert(2), _alert(3)], max_workers=2)

    assert [result["idx"] for result in results] == [1, 2, 3]
    assert any(name.startswith("zscope-alert-verifier") for name in verifier.thread_names)


def test_alert_verifier_worker_error_becomes_operational_failure() -> None:
    class FailingVerifier(AlertVerifier):
        def __init__(self) -> None:
            pass

        def _verify_single(self, alert: ExternalAlert, idx: int) -> dict:
            if idx == 2:
                raise RuntimeError("checker failed")
            return {
                "alert_id": f"ALERT_{idx}",
                "verdict": "uncertain",
                "candidate_disposition": "needs_review",
            }

    results = FailingVerifier().verify_alerts([_alert(1), _alert(2), _alert(3)], max_workers=3)

    assert [result["alert_id"] for result in results] == ["ALERT_1", "ALERT_2", "ALERT_3"]
    assert results[1]["candidate_disposition"] == "engine_failed"
    assert results[1]["engine_status"] == "failed"
    assert "checker failed" in results[1]["reasoning"]


def test_alert_without_frozen_proof_is_needs_review_without_model() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)
    verifier.terminal_authority = TerminalAuthorityEvaluator()

    result = verifier._verify_single(_alert(1), 1)

    assert result["verdict"] == "uncertain"
    assert result["candidate_disposition"] == "needs_review"
    assert result["attribution"]["decided_by"] == "proof_engine"
    assert result["proof_kernel_mode"] == "authoritative"
    assert result["proof_kernel_decision"]["reason_code"] == (
        "alert_verify_frozen_proof_unavailable"
    )
    assert "model_verdict" not in result


def test_alert_tampered_proof_input_fails_closed_without_execution() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)
    verifier.terminal_authority = TerminalAuthorityEvaluator()
    alert = _alert(1, raw={"properties": {"zscopeProofKernelInput": {"proof_ir": {}}}})

    result = verifier._verify_single(alert, 1)

    assert result["candidate_disposition"] == "needs_review"
    assert result["proof_kernel_decision"]["reason_code"] == (
        "alert_verify_proof_input_schema_invalid"
    )


def test_alert_required_unknown_counterproof_cannot_confirm() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)
    verifier.terminal_authority = TerminalAuthorityEvaluator()
    alert = _alert(
        1,
        raw={
            "properties": {
                "zscopeProofKernelInput": (_proof_input_with_unknown_required_counterproof())
            }
        },
    )

    result = verifier._verify_single(alert, 1)

    assert result["candidate_disposition"] == "needs_review"
    assert result["proof_kernel_decision"]["reason_code"] == ("open_or_unknown_proof_clause")


def test_alert_confirmed_proof_uses_v4_promotion_chain() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)
    verifier.terminal_authority = TerminalAuthorityEvaluator()
    alert = _alert(
        1,
        raw={
            "properties": {
                "zscopeProofKernelInput": _terminal_path_proof_input(role="confirmation"),
                "proof_kernel_terminal_authority_decision": {
                    "schema_version": "zscope.terminal-authority-decision.v3",
                    "disposition": "rejected_with_proof",
                },
            }
        },
    )

    result = verifier._verify_single(alert, 1)

    assert result["candidate_disposition"] == "confirmed"
    assert result["terminal_authority_decision"]["schema_version"] == (
        "zscope.terminal-authority-decision.v4"
    )
    assert (
        result["proof_kernel_terminal_authority_decision"] == result["terminal_authority_decision"]
    )
    assert result["proof_kernel_frozen_state"]["obligation_uid"]
    assert result["proof_kernel_closure_evaluation"]["complete"] is True
    assert result["proof_kernel_promotion_certificate"]["disposition"] == "confirmed"


def test_alert_counterproof_uses_v4_promotion_chain() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)
    verifier.terminal_authority = TerminalAuthorityEvaluator()
    alert = _alert(
        1,
        raw={
            "properties": {
                "zscopeProofKernelInput": _terminal_path_proof_input(role="counterproof")
            }
        },
    )

    result = verifier._verify_single(alert, 1)

    assert result["candidate_disposition"] == "rejected_with_proof"
    assert result["terminal_authority_decision"]["schema_version"] == (
        "zscope.terminal-authority-decision.v4"
    )
    assert result["proof_kernel_promotion_certificate"]["disposition"] == ("rejected_with_proof")
