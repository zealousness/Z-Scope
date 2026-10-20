"""Independent synthetic selection counterexamples; native extraction is separate."""
from dataclasses import replace
from copy import deepcopy
from pathlib import Path
import sys

from zscope.semantics import contracts as contract_module
from zscope.semantics.build_scope import bind_build_scope
from zscope.semantics.contract_compiler import derive_contracts, compile_snapshot
from zscope.semantics.contracts import ApiContract, contract_rows
from zscope.semantics.defaults import default_local_pattern_semantics

sys.path.insert(0, str(Path(contract_module.__file__).resolve().parents[2] / "tests"))
from test_contract_build_scope import context  # noqa: E402


def compiled():
    registry = default_local_pattern_semantics().contracts
    ctx = context("build-a")
    # Use the actual compiler publication envelope, including its inferred
    # provenance; a generic user-row loader intentionally strips native USR.
    snapshot = {key:ctx[key] for key in ("func_name","file_path","signature")}
    snapshot["interface_contracts"] = derive_contracts(ctx, registry)
    assert compile_snapshot(snapshot, ctx, registry) == []
    rows = contract_rows([snapshot])
    contract = ApiContract.from_row((rows["resource"] + rows["lock"])[0])
    assert contract is not None and contract.effects_trusted
    assert getattr(contract.symbol, "usr", "") == "c:@F@dispose"
    registry.add(contract)
    return ctx, registry, contract


def test_explicit_callee_usr_selects_only_that_verified_identity():
    ctx, registry, contract = compiled()
    with bind_build_scope(ctx):
        good = registry.match_call("dispose", "deallocator", ["p"], usr="c:@F@dispose", facts={"p":{"non_null_identity":"p"}})
        assert len(good) == 1 and good[0].applicability == "applies"
        assert registry.match_call("dispose", "deallocator", ["p"], usr="c:@F@other") == []


def test_unknown_query_usr_cannot_authorize_precise_source_contract():
    ctx, registry, contract = compiled()
    with bind_build_scope(ctx):
        assert registry.match_call("dispose", "deallocator", ["p"], usr="", facts={"p":{"non_null_identity":"p"}}) == []


def test_unknown_contract_usr_cannot_wildcard_exact_query():
    ctx, registry, contract = compiled()
    registry.contracts = [replace(contract, symbol=replace(contract.symbol, usr=""))]
    with bind_build_scope(ctx):
        assert registry.match_call("dispose", "deallocator", ["p"], usr="c:@F@dispose", facts={"p":{"non_null_identity":"p"}}) == []


def test_snapshot_cannot_override_native_owner_with_declared_usr():
    from zscope.semantics.contracts import contract_rows

    ctx, registry, contract = compiled()
    raw = derive_contracts(ctx, default_local_pattern_semantics().contracts)[0]
    raw["symbol"]["usr"] = "c:@F@foreign"
    snapshot = {"func_name":"dispose", "file_path":"unit.c", "signature":ctx["signature"], "build_context_id":"build-a", "usr":"c:@F@dispose", "interface_contracts":[raw]}
    rows = contract_rows([snapshot])
    values = rows["resource"] + rows["lock"]
    assert all(row["contract"]["symbol"].get("usr") == "c:@F@dispose" for row in values), values


def test_ambiguous_native_owner_does_not_select_first_usr():
    from zscope.semantics.build_scope import context_symbol_usr

    ctx = context("build-a")
    second = deepcopy(ctx["program_facts"]["functions"][0])
    second["owner"]["usr"] = "c:@F@dispose#other-overload"
    ctx["program_facts"]["functions"].append(second)
    assert context_symbol_usr(ctx) == ""


def test_foreign_native_identity_receipt_cannot_supply_context_usr():
    from zscope.semantics.build_scope import context_symbol_usr

    ctx = context("build-a")
    ctx["program_facts"]["function_identity"] = {"usr":"c:@F@foreign", "build_context_id":"build-b"}
    assert context_symbol_usr(ctx) == ""
