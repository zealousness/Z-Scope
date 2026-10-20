"""Native call identity with controlled payload checks snapshot storage only.

The nested payload is deliberate test data, not a native guard/effect receipt;
it must never be used to authorize a contract or claim a real scan effect.
"""
from copy import deepcopy
import os
from pathlib import Path
import sys

workspace = Path(os.environ["PYTHONPATH"])
sys.path.insert(0, str(workspace / "tests"))
sys.path.insert(0, str(workspace.parents[3] / "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12"))
from test_validation_callee_rebind_boundary import native_overloads, setup_native
from zscope.core.validation.execution_context import current_execution_context, rebound_execution_context
from zscope.semantics.call_context import bind_call_context, current_call_facts, current_call_values


def controlled_values(registry):
    live = current_call_facts()
    calls = [c for c in live[1] if c[0] == "log_event" and c[1] == ["mode"]]
    assert len(calls) == 1, "actual unambiguous native caller must expose one parsed call"
    calls[0][3]["capture_probe"] = {"samples": [1, {"value": 2}]}
    values = current_call_values(registry, "log_event", ["mode"], "")
    assert values["capture_probe"] == {"samples": [1, {"value": 2}]}
    return values


def test_captured_call_values_keep_the_valid_argument_match(native_overloads):
    index, _ = native_overloads
    registry, _, _, only_int, _, _ = setup_native(index)
    with bind_call_context(only_int, registry):
        before = controlled_values(registry)
        captured = current_execution_context()
        with rebound_execution_context(captured):
            assert current_call_values(registry, "log_event", ["mode"], "") == before, (
                "freezing argument storage cannot silently erase a valid call-value match"
            )


def test_captured_nested_call_payload_is_independent_of_the_parent(native_overloads):
    index, _ = native_overloads
    registry, _, _, only_int, _, _ = setup_native(index)
    with bind_call_context(only_int, registry):
        parent_values = controlled_values(registry)
        expected = deepcopy(parent_values)
        captured = current_execution_context()
        # This nested dict is returned from the parent's live bound values.
        # It must not be the same object consumed by a captured worker.
        parent_values["capture_probe"]["samples"][1]["value"] = 99
        with rebound_execution_context(captured):
            assert current_call_values(registry, "log_event", ["mode"], "") == expected, (
                "a read-only outer mapping is insufficient when its nested guard value is shared"
            )
