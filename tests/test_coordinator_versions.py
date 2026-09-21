from concurrent.futures import ThreadPoolExecutor
import threading
import pytest

from zscope.agents.semantic_modeler.retry import run_semantic_model_with_retries
from zscope.common.cancellation import CancellationToken, bind_cancellation_token
from zscope.framework.base import AgentResponse
from zscope.snapshots.store import SnapshotStore


@pytest.mark.parametrize("difference", ["namespace", "symbol", "code", "compilation"])
def test_distinct_inputs_run_in_parallel_instead_of_incorrectly_joining(tmp_path, difference):
    barrier = threading.Barrier(2)
    calls = []

    class Agent:
        def run(self, context):
            calls.append(context)
            barrier.wait(timeout=5)
            return AgentResponse(success=True, data={"interface_contracts": []}, metadata={})

    def request(index):
        context = {
            "func_name": "alpha",
            "file_path": "a.c",
            "signature": "void alpha(void)",
            "code": "void alpha(void) { opaque(); }",
        }
        inputs = {"compilation": "one"}
        directory = tmp_path / ("second" if difference == "namespace" and index else "first")
        if index and difference == "symbol":
            context["file_path"] = "b.c"
        if index and difference == "code":
            context["code"] = "void alpha(void) { changed(); }"
        if index and difference == "compilation":
            inputs["compilation"] = "two"
        with bind_cancellation_token(CancellationToken()):
            return run_semantic_model_with_retries(
                Agent, context, snapshot_store=SnapshotStore(directory), input_version=inputs
            )

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(request, [0, 1]))
    assert len(calls) == 2
    assert all(result.success for result in results)
    assert results[0].metadata["semantic_task_key"] != results[1].metadata["semantic_task_key"]
