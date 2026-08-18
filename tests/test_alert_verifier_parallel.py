import threading

from zscope.alerts.adapter import ExternalAlert
from zscope.alerts.verifier import AlertVerifier


def _alert(idx: int) -> ExternalAlert:
    return ExternalAlert(
        tool="codeql",
        rule_id=f"rule-{idx}",
        message=f"alert {idx}",
        file_path=f"src/demo_{idx}.c",
        line=idx,
    )


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
                "verdict": "confirmed",
            }

    verifier = ParallelVerifier()

    results = verifier.verify_alerts([_alert(1), _alert(2), _alert(3)], max_workers=2)

    assert [result["idx"] for result in results] == [1, 2, 3]
    assert any(name.startswith("zscope-alert-verifier") for name in verifier.thread_names)


def test_alert_verifier_worker_error_becomes_uncertain_result() -> None:
    class FailingVerifier(AlertVerifier):
        def __init__(self) -> None:
            pass

        def _verify_single(self, alert: ExternalAlert, idx: int) -> dict:
            if idx == 2:
                raise RuntimeError("validator failed")
            return {"alert_id": f"ALERT_{idx}", "verdict": "confirmed"}

    verifier = FailingVerifier()

    results = verifier.verify_alerts([_alert(1), _alert(2), _alert(3)], max_workers=3)

    assert [result["alert_id"] for result in results] == ["ALERT_1", "ALERT_2", "ALERT_3"]
    assert results[1]["verdict"] == "uncertain"
    assert results[1]["candidate_disposition"] == "engine_failed"
    assert results[1]["engine_status"] == "failed"
    assert "validator failed" in results[1]["reasoning"]


def test_alert_verifier_closes_worker_thread_llm_sessions() -> None:
    class CloseTrackingClient:
        def __init__(self) -> None:
            self.closed_threads: list[str] = []
            self.lock = threading.Lock()

        def close_thread_session(self) -> None:
            with self.lock:
                self.closed_threads.append(threading.current_thread().name)

    class ClosingVerifier(AlertVerifier):
        def __init__(self) -> None:
            self.llm_client = CloseTrackingClient()

        def _verify_single(self, alert: ExternalAlert, idx: int) -> dict:
            if idx == 2:
                raise RuntimeError("validator failed")
            return {"alert_id": f"ALERT_{idx}", "idx": idx, "verdict": "confirmed"}

    verifier = ClosingVerifier()

    results = verifier.verify_alerts([_alert(1), _alert(2), _alert(3)], max_workers=3)

    assert [result["alert_id"] for result in results] == ["ALERT_1", "ALERT_2", "ALERT_3"]
    assert len(verifier.llm_client.closed_threads) == 3
    assert all(
        name.startswith("zscope-alert-verifier") for name in verifier.llm_client.closed_threads
    )


def test_alert_llm_rejection_remains_actionable_without_deterministic_proof() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)

    result = verifier._parse_verification(
        '{"type":"alert_verification","verdict":"rejected","confidence":0.99}',
        _alert(1),
        "ALERT_1",
    )

    assert result["verdict"] == "rejected"
    assert result["candidate_disposition"] == "needs_review"
    assert result["validation_status"] == "needs_review"
    assert result["engine_status"] == "complete"


def test_unparseable_alert_validator_response_is_engine_failure() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)

    result = verifier._parse_verification(
        "not json",
        _alert(1),
        "ALERT_1",
    )

    assert result["candidate_disposition"] == "engine_failed"
    assert result["validation_status"] == "pending"
    assert result["engine_status"] == "failed"


def test_alert_validator_v3_rejection_is_policy_uncertain() -> None:
    verifier = AlertVerifier.__new__(AlertVerifier)

    result = verifier._validator_v3_result(
        {
            "pass": "initial",
            "verdict": "rejected",
            "reasoning": "No exploitable path is established.",
            "positive_evidence": [],
            "negative_evidence": [],
            "evidence_refs": [],
            "blocking_negative_evidence": False,
            "stop_reason": "decision_complete",
        },
        alert=_alert(1),
        alert_id="ALERT_1",
        candidate_uid="CAND_1",
        cluster_uid="VCL_1",
    )

    assert result["model_verdict"] == "rejected"
    assert result["verdict"] == "uncertain"
    assert result["candidate_disposition"] == "needs_review"
    assert result["attribution"]["decided_by"] == "unresolved"
    assert result["proof_kernel_mode"] == "shadow"
    assert (
        result["proof_kernel_shadow_terminal_authority_decision"]["disposition"] == "needs_review"
    )
    assert result["proof_kernel_shadow_decision"] == {
        "disposition": "needs_review",
        "reason_code": "open_or_unknown_proof_clause",
        "source": "alert_verify_proof_ir_unavailable",
        "accepted_fact_kinds": [],
        "missing_fact_kinds": ["external_alert_program_evidence"],
    }
    assert result["hypothesis_hunter_mode"] == "shadow"
    assert result["hypothesis_hunter_artifact_refs"] == []
    assert result["hypothesis_hunter_shadow_decision"]["active_product_effect"] == "none"
