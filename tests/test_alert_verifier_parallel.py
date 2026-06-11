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
    assert all(name.startswith("zscope-alert-verifier") for name in verifier.llm_client.closed_threads)
