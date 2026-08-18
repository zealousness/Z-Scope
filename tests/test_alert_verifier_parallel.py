import threading

from zscope.alerts.adapter import ExternalAlert
from zscope.alerts.verifier import AlertVerifier
from zscope.core.validation.authority import TerminalAuthorityEvaluator


def _alert(idx: int, *, raw=None) -> ExternalAlert:
    return ExternalAlert(
        tool="codeql",
        rule_id=f"rule-{idx}",
        message=f"alert {idx}",
        file_path=f"src/demo_{idx}.c",
        line=idx,
        raw=raw or {},
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
