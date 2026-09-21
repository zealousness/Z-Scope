from concurrent.futures import ThreadPoolExecutor
import threading
import pytest

from zscope.agents.semantic_modeler.retry import run_semantic_model_with_retries
from zscope.framework.base import AgentResponse
from zscope.framework.llm_usage import (
    ScanTokenUsageLedger,
    collect_task_usage_events,
    task_usage_counters,
)
from zscope.orchestration.modeling_coordinator import scan_coordinator
from zscope.snapshots.store import SnapshotStore


@pytest.mark.parametrize("raise_after_failure", [False, True])
def test_task_counters_include_failed_provider_attempts(tmp_path, raise_after_failure):
    ledger = ScanTokenUsageLedger()
    store = SnapshotStore(tmp_path / "snapshots")

    class Agent:
        def run(self, context):
            reservation = ledger.reserve(10, 5)
            ledger.forfeit(reservation, reason="injected_network_failure")
            if raise_after_failure:
                raise RuntimeError("injected_owner_failure")
            reservation = ledger.reserve(10, 5)
            ledger.settle(
                reservation, prompt_tokens=10, completion_tokens=2, provider_reported=True
            )
            return AgentResponse(
                success=True,
                data={"interface_contracts": []},
                metadata={"api_call_count": 1, "cumulative_total_tokens": 12},
            )

    def request():
        return run_semantic_model_with_retries(
            Agent,
            {"func_name": "alpha", "file_path": "a.c", "code": "void alpha(void) {}"},
            snapshot_store=store,
        )

    if raise_after_failure:
        with pytest.raises(RuntimeError, match="injected_owner_failure"):
            request()
    else:
        result = request()
        assert result.metadata["provider_attempt_count"] == 2
        reused = request()
        assert reused.metadata["provider_attempt_count"] == 0
    counters = scan_coordinator(str(store.snapshot_dir), store).metrics()
    assert counters["physical_llm_calls"] == (1 if raise_after_failure else 2)
    assert counters["successful_llm_responses"] == (0 if raise_after_failure else 1)
    assert counters["tokens"] == (15 if raise_after_failure else 27)
    assert counters["conservative_tokens"] == 15
    assert counters["provider_reported_tokens"] == (0 if raise_after_failure else 12)


def test_parallel_and_nested_usage_scopes_do_not_double_count():
    ledger = ScanTokenUsageLedger()
    barrier = threading.Barrier(2)

    def worker(amount):
        with collect_task_usage_events() as events:
            barrier.wait(timeout=3)
            reservation = ledger.reserve(amount, 1)
            ledger.settle(reservation, prompt_tokens=amount, completion_tokens=1)
            with collect_task_usage_events() as nested:
                reservation = ledger.reserve(100, 1)
                ledger.settle(reservation, prompt_tokens=100, completion_tokens=1)
            assert task_usage_counters(nested)["provider_accounted_tokens"] == 101
        return task_usage_counters(events)

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(worker, [10, 20]))
    assert [result["provider_accounted_tokens"] for result in results] == [11, 21]
    assert ledger.snapshot()["event_count"] == 4
