"""Malformed scope receipts cannot restore a pinned source effect.

These are synthetic boundary cases, not native extraction evidence. The
existing native mixed-overload probe remains a separate acceptance gate.
"""
from copy import deepcopy

import pytest

from test_contract_usr_boundary import compiled
from zscope.semantics.build_scope import bind_build_scope
from zscope.semantics.call_context import bind_call_context, callee_usr_map


@pytest.mark.parametrize("damage", ["incomplete_body", "missing_body_complete", "stale_reason", "context_build_conflict", "identity_usr_conflict", "identity_build_conflict", "duplicate_owner"])
def test_invalid_entry_receipt_cannot_resolve_an_omitted_usr(damage):
    context, registry, contract = compiled()
    current = deepcopy(context)
    facts = current["program_facts"]
    body = facts["functions"][0]
    if damage == "incomplete_body":
        body["complete"] = False
    elif damage == "missing_body_complete":
        body.pop("complete")
    elif damage == "stale_reason":
        facts["reason"] = "stale_build_dependencies"
    elif damage == "context_build_conflict":
        current["build_context_id"] = "other-build"
    elif damage == "identity_usr_conflict":
        facts["function_identity"] = {"build_context_id": "build-a", "usr": "other-usr"}
    elif damage == "identity_build_conflict":
        facts["function_identity"] = {"build_context_id": "other-build", "usr": contract.symbol.usr}
    elif damage == "duplicate_owner":
        facts["functions"].append(deepcopy(body))
    with bind_build_scope(context):
        assert registry.find_for_call("dispose", "deallocator") == [contract]
        with bind_build_scope(current):
            assert registry.find_for_call("dispose", "deallocator") == []
            assert registry.match_call("dispose", "deallocator", ["p"], facts={"p": {"non_null_identity": "p"}}) == []
        assert registry.find_for_call("dispose", "deallocator") == [contract]


def test_mixed_recursive_callees_cannot_fall_back_to_the_entry_usr():
    context, registry, contract = compiled()
    body = context["program_facts"]["functions"][0]
    first = deepcopy(body["events"][0])
    first.update(event_id="2:0", expression="dispose(p)", callee={"name": "dispose", "usr": contract.symbol.usr})
    second = deepcopy(first)
    second.update(event_id="3:0", callee={"name": "dispose", "usr": "c:@F@dispose#other-overload"})
    body["events"].extend([first, second])
    assert "dispose" not in callee_usr_map(context)
    with bind_call_context(context, registry):
        assert registry.find_for_call("dispose", "deallocator") == []
        assert registry.match_call("dispose", "deallocator", ["p"], facts={"p": {"non_null_identity": "p"}}) == []
