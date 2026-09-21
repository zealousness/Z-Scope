"""Transparent C pointer casts preserve resource identity, not arbitrary casts."""

import pytest

from test_wrapper_contract_compiler import context
from zscope.semantics.contract_compiler import derive_contracts, deterministic_contract_snapshot
from zscope.semantics.contracts import ApiContract, ObjectBinding
from zscope.semantics.defaults import default_local_pattern_semantics


@pytest.mark.parametrize("value", ["(char*)malloc(n)", "((char *)(void *)malloc(n))"])
def test_pointer_cast_allocation_assignment_and_error_cleanup(value):
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        f"char *obtain(size_t n, int ok) {{ char *p={value}; if (!p) return NULL; if (!ok) {{ free(p); return NULL; }} return p; }}",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    assert any(c["role"] == "allocator" for c in snapshot["interface_contracts"])


@pytest.mark.parametrize("expression", ["(int)malloc(n)", "(char*)(int)malloc(n)", "malloc(n)+1"])
def test_truncation_or_arithmetic_is_not_transparent(expression):
    registry = default_local_pattern_semantics().contracts
    for body in (f"char *p={expression}; return p;", f"return {expression};"):
        rows = derive_contracts(
            context("obtain", "char *obtain(size_t n) {" + body + "}"), registry
        )
        assert not any(c["role"] == "allocator" for c in rows)


def test_pointer_cast_alias_and_release_share_the_same_object():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain", "char *obtain(size_t n) { void *p=malloc(n); char *q=(char*)p; return (char*)q; }"
    )
    assert deterministic_contract_snapshot(ctx, registry) is not None
    rows = derive_contracts(context("drop", "void drop(char *p) { free((void*)p); }"), registry)
    assert len(rows) == 1
    item = ApiContract.from_row({"contract": rows[0]})
    assert item.carrier.argument_index == 0
    assert item.carrier.resolve(["(char*)object"]) == "object"
    assert ObjectBinding("return").resolve([], "(int)object") != "object"


def test_additional_acquisitions_do_not_inherit_a_single_free_pair():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "make",
        "Node *make(void) { Node *p=(Node*)calloc(1,sizeof(Node)); p->data=malloc(8); return p; }",
    )
    rows = derive_contracts(ctx, registry)
    outer = next(c for c in rows if c["role"] == "calloc")
    assert outer["pairs"] == []
    assert not any(d.get("transparent") for d in outer["delegates"])
