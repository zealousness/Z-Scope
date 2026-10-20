"""First effective causes survive observation and concurrent later mutations."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
import time

import pytest

from zscope.common.cancellation import CancellationError, CancellationToken
from zscope.orchestration.modeling_coordinator import _SharedTaskCancellation


@pytest.mark.parametrize("observe", ["is_cancelled", "reason", "state", "remaining", "wait"])
@pytest.mark.parametrize("later", ["self", "parent", "tighten"])
def test_observed_local_deadline_is_immutable(observe: str, later: str) -> None:
    parent = CancellationToken()
    token = parent.child()
    token.tighten_deadline(time.monotonic() - 1, reason="own deadline")
    if observe == "is_cancelled":
        assert token.is_cancelled()
    elif observe == "reason":
        assert token.reason == "own deadline"
    elif observe == "state":
        assert token.state().cancelled
    elif observe == "remaining":
        assert token.remaining_seconds() == 0
    else:
        assert token.wait(0)

    if later == "self":
        token.cancel("later explicit")
    elif later == "parent":
        parent.cancel("later parent")
    else:
        token.tighten_deadline(time.monotonic() - 100, reason="later backdated deadline")
    assert token.reason == "own deadline"
    with pytest.raises(CancellationError, match="own deadline"):
        token.raise_if_cancelled()


@pytest.mark.parametrize("later", ["self", "parent", "tighten"])
def test_expired_unobserved_local_deadline_precedes_later_mutation(later: str) -> None:
    parent = CancellationToken()
    token = parent.child()
    token.tighten_deadline(time.monotonic() - 1, reason="local expired")
    if later == "self":
        token.cancel("later explicit")
    elif later == "parent":
        parent.cancel("later parent")
    else:
        token.tighten_deadline(time.monotonic() - 100, reason="later backdated")
    assert token.reason == "local expired"


@pytest.mark.parametrize("first", ["parent", "child"])
def test_first_explicit_cancel_survives_other_explicit_cancel(first: str) -> None:
    parent = CancellationToken()
    child = parent.child()
    if first == "parent":
        parent.cancel("parent first")
        child.cancel("child second")
    else:
        child.cancel("child first")
        parent.cancel("parent second")
    assert child.reason == f"{first} first"


@pytest.mark.parametrize("first", ["parent", "child"])
def test_explicit_cancel_precedes_later_registered_past_deadline(first: str) -> None:
    parent = CancellationToken()
    child = parent.child()
    if first == "parent":
        parent.cancel("first explicit")
        child.tighten_deadline(time.monotonic() - 100, reason="backdated child")
    else:
        child.cancel("first explicit")
        parent.tighten_deadline(time.monotonic() - 100, reason="backdated parent")
    assert child.reason == "first explicit"


@pytest.mark.parametrize("first", ["parent", "child"])
def test_later_registered_past_parent_or_child_deadline_cannot_go_back_in_time(first: str) -> None:
    parent = CancellationToken()
    child = parent.child()
    earlier, later = (parent, child) if first == "parent" else (child, parent)
    earlier.tighten_deadline(time.monotonic() - 1, reason="first effective deadline")
    later.tighten_deadline(time.monotonic() - 100, reason="later registered deadline")
    assert child.reason == "first effective deadline"


@pytest.mark.parametrize("earlier", ["parent", "child"])
def test_both_elapsed_deadlines_choose_earlier_expiry_without_child_observation(
    earlier: str,
) -> None:
    now = time.monotonic()
    parent = CancellationToken()
    child = parent.child()
    parent_deadline = now + (0.04 if earlier == "parent" else 0.08)
    child_deadline = now + (0.04 if earlier == "child" else 0.08)
    parent.tighten_deadline(parent_deadline, reason="parent deadline")
    child.tighten_deadline(child_deadline, reason="child deadline")
    # Wait directly for the later real monotonic boundary. No watcher, patched
    # clock, or child observation can select a winner on behalf of the token.
    threading.Event().wait(max(parent_deadline, child_deadline) - time.monotonic() + 0.01)
    assert child.reason == f"{earlier} deadline"


def test_equal_deadlines_keep_parent_reason_in_existing_and_future_children() -> None:
    parent = CancellationToken()
    existing = parent.child()
    deadline = time.monotonic() + 0.04
    parent.tighten_deadline(deadline, reason="parent boundary")
    existing.tighten_deadline(deadline, reason="local same boundary")
    future = parent.child()
    assert parent.wait(0.2)
    assert existing.reason == future.reason == "parent boundary"


def test_multilevel_chain_keeps_each_tokens_first_cause() -> None:
    root = CancellationToken()
    middle = root.child()
    leaf = middle.child()
    sibling = root.child()
    leaf.tighten_deadline(time.monotonic() - 1, reason="leaf first")
    middle.tighten_deadline(time.monotonic() - 1, reason="middle second")
    root.cancel("root third")
    assert leaf.reason == "leaf first"
    assert middle.reason == "middle second"
    assert root.reason == sibling.reason == "root third"
    assert leaf.child().reason == "leaf first"


def test_unknown_and_tightened_budgets_preserve_minimum_and_default_reason() -> None:
    root = CancellationToken()
    child = root.child()
    leaf = child.child()
    assert leaf.remaining_seconds() is None
    assert leaf.state().reason == ""
    assert not leaf.wait(0)
    root.tighten_deadline(time.monotonic() + 100, reason="root")
    child.tighten_deadline(time.monotonic() + 10, reason="child")
    root.tighten_deadline(time.monotonic() + 200, reason="ignored extension")
    assert 0 < leaf.remaining_seconds() <= 10
    assert 50 < root.remaining_seconds() <= 100
    leaf.tighten_deadline(time.monotonic() - 1)
    assert leaf.reason == "deadline_exceeded"
    assert not root.is_cancelled()
    assert not child.is_cancelled()


def test_cancel_if_deadline_cannot_relabel_observed_or_different_deadline() -> None:
    token = CancellationToken()
    deadline = time.monotonic() - 1
    token.tighten_deadline(deadline, reason="bound reason")
    assert token.is_cancelled()
    assert not token.cancel_if_deadline(deadline, "late watcher reason")
    assert token.reason == "bound reason"
    other = CancellationToken()
    other.tighten_deadline(deadline, reason="other bound reason")
    assert not other.cancel_if_deadline(deadline + 1, "wrong deadline")
    assert other.reason == "other bound reason"


def test_cancel_if_deadline_records_only_unobserved_matching_first_cause() -> None:
    parent = CancellationToken()
    child = parent.child()
    deadline = time.monotonic() - 1
    child.tighten_deadline(deadline)
    parent.cancel("later parent")
    assert child.cancel_if_deadline(deadline, "own watcher")
    assert child.reason == "own watcher"
    assert not child.cancel_if_deadline(deadline, "second watcher")
    assert child.reason == "own watcher"


def test_parent_cause_denies_matching_child_watcher() -> None:
    parent = CancellationToken()
    child = parent.child()
    parent.cancel("parent first")
    deadline = time.monotonic() - 1
    child.tighten_deadline(deadline, reason="child second")
    assert not child.cancel_if_deadline(deadline, "child watcher")
    assert child.reason == "parent first"


def test_concurrent_late_cancel_tighten_and_read_keep_recorded_deadline() -> None:
    root = CancellationToken()
    child = root.child()
    leaf = child.child()
    leaf.tighten_deadline(time.monotonic() - 1, reason="recorded leaf")
    assert leaf.reason == "recorded leaf"
    barrier = threading.Barrier(4)

    def mutate(index: int) -> set[str]:
        barrier.wait(timeout=5)
        observed = set()
        for repeat in range(50):
            if index == 0:
                root.cancel(f"root {repeat}")
            elif index == 1:
                child.cancel(f"child {repeat}")
            elif index == 2:
                leaf.tighten_deadline(time.monotonic() - repeat - 2, reason=f"late {repeat}")
            else:
                leaf.cancel(f"local {repeat}")
            snapshot = leaf.state()
            assert snapshot.cancelled and snapshot.remaining_seconds == 0
            observed.add(snapshot.reason)
        return observed

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(mutate, index) for index in range(4)]
        assert [future.result(timeout=10) for future in futures] == [{"recorded leaf"}] * 4


def test_concurrent_first_cancel_and_deadline_publish_one_consistent_reason() -> None:
    for _ in range(20):
        parent = CancellationToken()
        token = parent.child()
        barrier = threading.Barrier(3)

        def mutate(kind: str) -> str:
            barrier.wait(timeout=5)
            if kind == "deadline":
                token.tighten_deadline(time.monotonic() - 1, reason=kind)
            elif kind == "parent":
                parent.cancel(kind)
            else:
                token.cancel(kind)
            return token.reason

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(mutate, kind) for kind in ("deadline", "parent", "explicit")]
            reasons = {future.result(timeout=10) for future in futures}
        assert len(reasons) == 1
        assert token.reason in reasons
        assert token.is_cancelled()


def test_concurrent_tightening_keeps_earliest_budget_and_its_paired_reason() -> None:
    token = CancellationToken()
    deadline = time.monotonic() + 0.15
    barrier = threading.Barrier(5)

    def tighten(index: int) -> None:
        barrier.wait(timeout=5)
        token.tighten_deadline(deadline + index, reason=f"deadline {index}")
        token.state()

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(tighten, index) for index in range(5)]
        for future in futures:
            future.result(timeout=10)
    assert token.wait(1)
    assert token.reason == "deadline 0"


def test_shared_modeling_parent_public_semantics_remain_effective() -> None:
    first = CancellationToken()
    second = CancellationToken()
    shared = _SharedTaskCancellation(first)
    shared.add(second)
    child = shared.child()
    first.cancel("first scan cancelled")
    assert not child.is_cancelled()
    assert child.reason == ""
    assert child.remaining_seconds() is None
    second.cancel("second scan cancelled")
    assert child.is_cancelled()
    assert child.reason in {"first scan cancelled", "second scan cancelled"}
    recorded = child.reason
    child.cancel("later child")
    assert child.reason == recorded


def test_opaque_shared_parent_cancel_precedes_later_child_expiry_before_first_observation() -> None:
    root = CancellationToken()
    shared = _SharedTaskCancellation(root)
    child = shared.child()
    deadline = time.monotonic() + 0.04
    child.tighten_deadline(deadline, reason="child expiry")
    root.cancel("scan root first")
    threading.Event().wait(max(0.0, deadline - time.monotonic()) + 0.01)
    # The shared token exposes cancellation publicly, but has no native
    # occurrence receipt. Preserve its original priority over an unobserved
    # local expiry instead of treating observation time as cancellation time.
    assert child.reason == "scan root first"
    assert child.state().reason == "scan root first"


def test_observed_child_expiry_survives_later_opaque_shared_parent_cancel() -> None:
    root = CancellationToken()
    shared = _SharedTaskCancellation(root)
    child = shared.child()
    child.tighten_deadline(time.monotonic() - 1, reason="child first")
    assert child.is_cancelled()
    assert child.reason == "child first"
    root.cancel("scan root later")
    assert child.reason == "child first"
    assert child.state().reason == "child first"


def test_specialized_parent_public_callback_runs_without_family_lock() -> None:
    class PublicParent(CancellationToken):
        def is_cancelled(self) -> bool:
            worker = threading.Thread(target=super().cancel, args=("private reason",), daemon=True)
            worker.start()
            worker.join(timeout=2)
            assert not worker.is_alive(), "public parent callback ran under the family lock"
            return True

        @property
        def reason(self) -> str:
            return "public reason"

    parent = PublicParent()
    child = parent.child()
    assert child.is_cancelled()
    assert child.reason == "public reason"


def test_deep_parent_chain_uses_iteration_and_preserves_root_reason() -> None:
    root = CancellationToken()
    leaf = root
    for _ in range(1100):
        leaf = leaf.child()
    root.cancel("root reason")
    assert leaf.reason == "root reason"
