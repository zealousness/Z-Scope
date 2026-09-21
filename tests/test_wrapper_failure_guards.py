"""Unknown calls are excluded by immutable result guards, never by spelling."""

from copy import deepcopy

import pytest

from test_wrapper_contract_compiler import context, publish
from zscope.semantics.contract_compiler import (
    complete_transparent_pairs,
    derive_contracts,
    deterministic_contract_snapshot,
)
from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics


@pytest.mark.parametrize(
    "primitive,role,args",
    [
        ("malloc", "allocator", "n"),
        ("calloc", "calloc", "1,n"),
        ("realloc", "reallocator", "NULL,n"),
    ],
)
def test_failed_allocation_branch_composes_and_roundtrips(tmp_path, primitive, role, args):
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        f"void *obtain(size_t n) {{ void *p = {primitive}({args}); if (!p && n > 0) {{ unknown_action(n); return NULL; }} return p; }}",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    item = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
    assert item.role == role and item.effects_trusted
    assert item.verification["excluded_failure_calls"][0]["callee"] == "unknown_action"
    registry.add(item)
    outer = deterministic_contract_snapshot(
        context("FETCH", "#define FETCH(n) obtain(n)", True), registry
    )
    assert outer is not None
    snapshots = [snapshot, outer]
    complete_transparent_pairs(snapshots, registry)
    _, custom_semantics, overlay = publish(tmp_path, snapshots)
    semantics = default_local_pattern_semantics()
    semantics.merge(custom_semantics)
    assert overlay["contract_version"] == semantics.contracts.version
    assert semantics.contracts.find("FETCH")[0].effects_trusted
    assert semantics.contracts.allows("FETCH", "free")
    match = semantics.contracts.match_call("FETCH", role, ["8"], "p", facts={"p": 1})[0]
    assert match.applicability == "applies"
    assert (
        semantics.contracts.match_call("FETCH", role, ["8"], "NULL")[0].applicability
        == "does_not_apply"
    )


@pytest.mark.parametrize(
    "middle,ending",
    [
        ("unknown_action(p);", "return p;"),
        ("if (p) unknown_action(p);", "return p;"),
        ("if (!p) unknown_action(&p);", "return p;"),
        ("p = NULL; if (!p) unknown_action(n);", "return p;"),
        ("p++; if (!p) unknown_action(n);", "return p;"),
        ("p += 1; if (!p) unknown_action(n);", "return p;"),
        ("if (!p) object.recover(n);", "return p;"),
        ("if (!p) unknown_action(n);", "if (n) return borrowed; return p;"),
    ],
)
def test_opaque_interference_cannot_be_certified(middle, ending):
    registry = default_local_pattern_semantics().contracts
    ctx = context("obtain", f"void *obtain(size_t n) {{ void *p = malloc(n); {middle} {ending} }}")
    assert deterministic_contract_snapshot(ctx, registry) is None
    assert all(
        not ApiContract.from_row({"contract": c}).effects_trusted
        for c in derive_contracts(ctx, registry)
    )


def test_hidden_lock_status_stays_unknown_and_recovery_is_not_no_effect():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "enter",
        "void enter(pthread_mutex_t *m) { if (!m) return; int r = pthread_mutex_lock(m); if (r != 0) recover(m); }",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    item = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
    assert item.effects_trusted
    assert any(c["effect"] == "unknown" for c in item.effect_cases)
    assert not any(c["effect"] == "no_effect" for c in item.effect_cases)
    registry.add(item)
    assert registry.match_call("enter", "lock", ["&mu"])[0].applicability == "unknown"
    assert registry.match_call("enter", "lock", ["NULL"])[0].applicability == "does_not_apply"
    changed = deepcopy(ctx)
    changed["code"] = changed["code"].replace("recover(m)", "recover(&r)")
    assert deterministic_contract_snapshot(changed, registry) is None


def test_unverified_callee_role_does_not_mean_its_other_effects_are_known():
    registry = default_local_pattern_semantics().contracts
    registry.add(
        ApiContract.from_row(
            {
                "contract": {
                    "symbol": {"name": "emit"},
                    "role": "format_sink",
                    "carrier": {"kind": "argument", "argument_index": 0},
                    "source": "inferred:semantic_modeling",
                    "verification": {"method": "schema_only"},
                }
            }
        )
    )
    ctx = context("obtain", "void *obtain(size_t n) { void *p = malloc(n); emit(p); return p; }")
    assert deterministic_contract_snapshot(ctx, registry) is None
    assert all(
        not ApiContract.from_row({"contract": c}).effects_trusted
        for c in derive_contracts(ctx, registry)
    )


@pytest.mark.parametrize("declaration", ["", "static void *", "volatile void *"])
def test_opaque_call_cannot_rely_on_a_nonlocal_result_guard(declaration):
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        f"void *obtain(size_t n) {{ {declaration}p=malloc(n); if (!p) recover(); return p; }}",
    )
    assert deterministic_contract_snapshot(ctx, registry) is None


def test_unknown_precondition_branch_is_preserved_in_lock_contract():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "enter",
        "void enter(pthread_mutex_t *m) { if (!m) { observe(); return; } int r = pthread_mutex_lock(m); if (r != 0) recover(m); }",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    item = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
    registry.add(item)
    assert registry.match_call("enter", "lock", ["NULL"])[0].applicability == "unknown"
    # Reference parameters may be changed indirectly via their caller storage.
    ctx["code"] = ctx["code"].replace("*m", "*&m")
    assert deterministic_contract_snapshot(ctx, registry) is None


@pytest.mark.parametrize(
    "code,macro",
    [
        ("void idle(void) {}", False),
        ("#define idle() do {} while (0)", True),
        ("#define idle() {}", True),
    ],
)
def test_empty_implementations_do_not_need_a_model(code, macro):
    snapshot = deterministic_contract_snapshot(
        context("idle", code, macro), default_local_pattern_semantics().contracts
    )
    assert snapshot is not None and snapshot["interface_contracts"] == []


def test_empty_nonvoid_or_unknown_action_is_not_a_trivial_implementation():
    registry = default_local_pattern_semantics().contracts
    assert deterministic_contract_snapshot(context("idle", "int idle(void) {}"), registry) is None
    assert (
        deterministic_contract_snapshot(context("idle", "void idle(void) { invoke(); }"), registry)
        is None
    )
