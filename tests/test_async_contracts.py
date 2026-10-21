from dataclasses import replace

import pytest

from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.resource_coverage import consumer_support
from test_wrapper_contract_compiler import context, compile_all, publish


@pytest.mark.parametrize(
    "name,kind",
    [
        ("pthread_create", "start_callback"),
        ("pthread_join", "wait_callback_completion"),
        ("pthread_detach", "release_join_handle"),
        ("pthread_cancel", "request_cancellation"),
    ],
)
def test_effects_preserve_status_and_distinct_objects(name, kind):
    registry = default_local_pattern_semantics().contracts
    args = ["&worker", "0", "callback", "payload"] if name == "pthread_create" else ["worker", "0"]
    for returned, status in [("0", "applies"), ("11", "does_not_apply"), ("rc", "unknown")]:
        (transition,) = registry.resolved_transitions(name, args, returned)
        assert transition["applicability"] == status
        (action,) = transition["actions"]
        assert action["kind"] == kind
        if name == "pthread_create":
            assert action["callback"] == "callback" and action["context"] == "payload"
            assert action["object"] != action["context"]
    (contract,) = registry.find_for_call(name)
    assert "not_all_schedules" in consumer_support(contract)["async_callback"]
    registry.add(replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    assert registry.resolved_transitions(name, args, "0")[0]["applicability"] == "unknown"


def test_wrapper_publication_does_not_turn_detach_or_cancel_into_drain(tmp_path):
    snapshots = compile_all(
        [
            context("waiter", "int waiter(unsigned long t) { return pthread_join(t, 0); }"),
            context("detach", "int detach(unsigned long t) { return pthread_detach(t); }"),
            context("cancel", "int cancel(unsigned long t) { return pthread_cancel(t); }"),
        ]
    )
    _, semantics, _ = publish(tmp_path, snapshots)
    for name, expected in [
        ("waiter", "wait_callback_completion"),
        ("detach", "release_join_handle"),
        ("cancel", "request_cancellation"),
    ]:
        (transition,) = semantics.contracts.resolved_transitions(name, ["thread"], "0")
        assert transition["applicability"] == "applies"
        assert transition["actions"] == [{"kind": expected, "object": "thread"}]
        assert (
            semantics.contracts.resolved_transitions(name, ["thread"], "5")[0]["applicability"]
            == "does_not_apply"
        )


def test_launch_bindings_survive_wrapper_publication(tmp_path):
    snapshots = compile_all(
        [
            context(
                "launch",
                "int launch(unsigned long *out, void *attr, Callback fn, void *data) { return pthread_create(out, attr, fn, data); }",
            ),
        ]
    )
    _, semantics, _ = publish(tmp_path, snapshots)
    (transition,) = semantics.contracts.resolved_transitions(
        "launch", ["&t", "attrs", "run", "item"], "0"
    )
    assert transition["applicability"] == "applies"
    (action,) = transition["actions"]
    assert action["kind"] == "start_callback"
    assert action["callback"] == "run" and action["context"] == "item"


def test_testcancel_is_a_point_not_a_deallocator_or_completion():
    registry = default_local_pattern_semantics().contracts
    (contract,) = registry.find_for_call("pthread_testcancel")
    assert contract.role == "standard_operation"
    assert registry.resolved_transitions("pthread_testcancel", [], "0") == []
    assert "bounded_c_glibc_deferred_cleanup" in consumer_support(contract)["async_callback"]
