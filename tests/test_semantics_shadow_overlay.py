"""Shared overlay consumers must retain the same deny boundary as merge."""

import pytest

from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.models import (
    CATEGORY_BY_ATTR,
    DEFAULT_SEMANTICS_SOURCE,
    MERGE_ATTRS,
    LocalPatternSemantics,
)


@pytest.mark.parametrize("attr", MERGE_ATTRS)
def test_overlay_removes_shadowed_builtin_roles_and_prevents_resurrection(attr):
    registry = LocalPatternSemantics()
    category = CATEGORY_BY_ATTR[attr]
    registry.add_api(category, "denied_api", DEFAULT_SEMANTICS_SOURCE)
    registry.add_api(category, "allowed_api", DEFAULT_SEMANTICS_SOURCE)
    registry.add_api(category, "project_api", "project_verified")
    denied_contract = next(
        contract.to_dict()
        for contract in registry.contracts.contracts
        if contract.symbol.name == "denied_api"
    )
    overlay = {
        "shadowed_symbols": ["denied_api", "project_api"],
        "api_contracts": [denied_contract],
    }
    registry.merge_overlay(overlay)
    registry.merge_overlay(overlay)
    assert "denied_api" not in getattr(registry, attr)
    assert registry.contracts.find("denied_api") == []
    assert getattr(registry, attr)["allowed_api"] == [DEFAULT_SEMANTICS_SOURCE]
    assert getattr(registry, attr)["project_api"] == ["project_verified"]


def test_default_preseeded_allocator_overlay_keeps_denial_and_unrelated_defaults():
    registry = default_local_pattern_semantics()
    assert "malloc" in registry.allocators
    registry.merge_overlay({"shadowed_symbols": ["malloc"]})
    assert "malloc" not in registry.allocators
    assert registry.contracts.find("malloc") == []
    assert not registry.contracts.allows("malloc", "free")
    assert "free" in registry.deallocators
    assert registry.contracts.find("free")


def test_existing_merge_and_overlay_have_identical_builtin_role_denial():
    merged = default_local_pattern_semantics()
    overlaid = default_local_pattern_semantics()
    denied = LocalPatternSemantics()
    denied.contracts.shadowed_symbols.update({"malloc", "free", "memcpy"})
    merged.merge(denied)
    overlaid.merge_overlay({"shadowed_symbols": sorted(denied.contracts.shadowed_symbols)})
    for attr in MERGE_ATTRS:
        assert getattr(merged, attr) == getattr(overlaid, attr)
