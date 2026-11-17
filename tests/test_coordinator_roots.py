from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
import time

import pytest

from zscope.agents.semantic_modeler.retry import run_semantic_model_with_retries
from zscope.common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from zscope.framework.base import AgentResponse
from zscope.orchestration.modeling_coordinator import scan_coordinator
from zscope.snapshots.store import SnapshotStore

CONTEXT = {
    "func_name": "f",
    "file_path": "a.c",
    "signature": "void f(void)",
    "code": "void f(void) { opaque(); }",
}


def joined(store, root):
    with bind_cancellation_token(root):
        coordinator = scan_coordinator(str(store.snapshot_dir), store)
    until = time.monotonic() + 3
    while coordinator.metrics()["requests"] < 1 and time.monotonic() < until:
        threading.Event().wait(0.001)
    assert coordinator.metrics()["joined_requests"] == 1


@pytest.mark.parametrize("second_unbound", [False, True])
def test_independent_roots_share_committed_result_and_owner_cancel(tmp_path, second_unbound):
    stores = [SnapshotStore(tmp_path / "snapshots") for _ in range(2)]
    roots = [CancellationToken(), None if second_unbound else CancellationToken()]
    entered, release = threading.Event(), threading.Event()
    calls = []

    class Agent:
        def run(self, context):
            calls.append(1)
            entered.set()
            assert release.wait(3)
            current_cancellation_token().raise_if_cancelled()
            return AgentResponse(success=True, data={"interface_contracts": []}, metadata={})

    def request(i):
        with bind_cancellation_token(roots[i]):
            result = run_semantic_model_with_retries(Agent, CONTEXT, snapshot_store=stores[i])
            assert list((Path(stores[i].snapshot_dir) / ".modeling-tasks").glob("*.json"))
            return result

    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(request, 0)
        assert entered.wait(3)
        second = pool.submit(request, 1)
        try:
            joined(stores[1], roots[1])
            roots[0].cancel("owner_cancelled")
        finally:
            release.set()
        with pytest.raises(CancellationError):
            first.result()
        result = second.result()
    assert result.success and result.metadata["semantic_task_reused"]
    assert calls == [1]


def test_failure_is_shared_then_a_new_scan_retries(tmp_path):
    store = SnapshotStore(tmp_path / "snapshots")
    roots = [CancellationToken() for _ in range(3)]
    entered, release = threading.Event(), threading.Event()
    calls = []

    class Agent:
        def run(self, context):
            calls.append(1)
            entered.set()
            assert release.wait(3)
            return AgentResponse(success=False, data={}, error="fixture_failure", metadata={})

    def request(root):
        with bind_cancellation_token(root):
            return run_semantic_model_with_retries(Agent, CONTEXT, snapshot_store=store)

    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(request, roots[0])
        assert entered.wait(3)
        second = pool.submit(request, roots[1])
        try:
            joined(store, roots[1])
        finally:
            release.set()
        assert first.result().error == second.result().error == "fixture_failure"
    assert len(calls) == 1
    assert request(roots[0]).error == request(roots[1]).error == "fixture_failure"
    assert len(calls) == 1
    assert request(roots[2]).error == "fixture_failure"
    assert len(calls) == 2


def test_all_participating_scans_cancel_the_shared_operation(tmp_path):
    store = SnapshotStore(tmp_path / "snapshots")
    roots = [CancellationToken(), CancellationToken()]
    entered = threading.Event()
    calls = []

    class Agent:
        def run(self, context):
            calls.append(1)
            entered.set()
            assert current_cancellation_token().wait(3)
            current_cancellation_token().raise_if_cancelled()

    def request(root):
        with bind_cancellation_token(root):
            return run_semantic_model_with_retries(Agent, CONTEXT, snapshot_store=store)

    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(request, roots[0])
        assert entered.wait(3)
        second = pool.submit(request, roots[1])
        try:
            joined(store, roots[1])
        finally:
            for root in roots:
                root.cancel("all_scans_cancelled")
        for future in (first, second):
            with pytest.raises(CancellationError):
                future.result()
    assert calls == [1]
