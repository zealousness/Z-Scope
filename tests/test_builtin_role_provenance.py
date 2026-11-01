"""Lexical categories must not fabricate typed effects for catalogued APIs."""

import pytest

from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.models import LocalPatternSemantics


@pytest.mark.parametrize("name", ["read", "recv", "fread", "send", "write"])
def test_legacy_copy_names_remain_lexical_only(name):
    semantics = default_local_pattern_semantics()
    assert name in semantics.copy_sinks
    assert not [
        c for c in semantics.contracts.contracts if c.symbol.name == name and c.role == "copy"
    ]
    merged = LocalPatternSemantics()
    merged.merge(semantics)
    assert name in merged.copy_sinks
    assert not [c for c in merged.contracts.contracts if c.symbol.name == name and c.role == "copy"]


@pytest.mark.parametrize(
    "name,role,index",
    [
        ("read", "recv_source", 1),
        ("recv", "recv_source", 1),
        ("fread", "recv_source", 0),
        ("send", "send_sink", 1),
        ("write", "send_sink", 1),
        ("memcpy", "copy", 0),
    ],
)
def test_precise_catalog_carrier_survives_legacy_name_categories(name, role, index):
    rows = [
        c
        for c in default_local_pattern_semantics().contracts.contracts
        if c.symbol.name == name and c.role == role
    ]
    assert rows
    assert all(c.to_dict()["carrier"]["argument_index"] == index for c in rows)
