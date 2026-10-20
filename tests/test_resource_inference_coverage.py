"""RAPI01: missing discovery or consumption never becomes a clean finding count."""

from dataclasses import replace

from test_wrapper_contract_compiler import context
from zscope.semantics.contract_compiler import derive_contracts
from zscope.semantics.contracts import ApiContract, ObjectBinding, SymbolIdentity
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.resource_coverage import inference_coverage, consumer_support


def test_interface_and_call_coverage_separate_authority_and_unknowns():
    registry = default_local_pattern_semantics().contracts
    known = context("obtain", "void *obtain(int n) { return malloc(n); }")
    (raw,) = derive_contracts(known, registry)
    registry.add(ApiContract.from_row({"contract": raw}))
    unknown = context("entry", "void entry(void) { mystery(); obtain(8); mystery(); }")
    result = inference_coverage(
        {"obtain": known, "entry": unknown},
        {"obtain": {"interface_contracts": [raw]}},
        registry,
        scheduled=["obtain", "entry", "cleanup"],
    )
    assert {r["symbol"]: r["status"] for r in result["interfaces"]} == {
        "obtain": "source_verified",
        "entry": "unsupported",
        "cleanup": "not_seen",
    }
    assert any(
        c.get("callee") == "mystery" and c["applicability"] == "unknown" for c in result["calls"]
    )
    sites = [c for c in result["calls"] if c.get("callee") == "mystery"]
    assert len(sites) == len({c["token_offset"] for c in sites}) == 2
    assert any(c["coverage_reason"] == "native_receipt_unavailable" for c in result["calls"])
    assert result["outside_entry_cleanup_coverage"] == "not_measured"
    assert not result["finding_verdict_authority"]
    assert not any("code" in r for r in result["interfaces"])


def test_shadow_schema_manual_and_stale_remain_distinct():
    registry = default_local_pattern_semantics().contracts
    registry.shadowed_symbols.add("malloc")
    ctx = context("malloc", "void *malloc(int n) { return 0; }")
    caller = context("entry", "void entry(void) { malloc(8); }")
    result = inference_coverage({"project_malloc": ctx, "caller": caller}, {}, registry)
    assert any(r["coverage_reason"] == "project_shadows_standard" for r in result["calls"])
    raw = {
        "symbol": {"name": "custom", "file_path": "interfaces.c"},
        "role": "allocator",
        "carrier": {"kind": "return"},
        "source": "inferred:model",
        "confidence": 1.0,
        "verification": {"method": "schema_only"},
    }
    registry.add(ApiContract.from_row({"contract": raw}))
    custom = context("custom", "void *custom(void) { return 0; }")
    result = inference_coverage({"custom": custom}, {}, registry)
    assert result["interfaces"][0]["status"] == "schema_only"
    manual = replace(registry.find_for_call("custom")[0], source="user")
    registry.add(manual)
    assert (
        inference_coverage({"custom": custom}, {}, registry)["interfaces"][0]["status"]
        == "manual_assumption"
    )
    custom["program_facts"] = {"reason": "stale_compilation"}
    assert (
        inference_coverage({"custom": custom}, {}, registry)["interfaces"][0]["status"]
        == "stale/conflict"
    )


def test_unsupported_consumption_is_explicit_even_for_known_contract():
    contract = ApiContract(SymbolIdentity("make"), "allocator", ObjectBinding("output_argument", 0))
    support = consumer_support(contract)
    assert support["contract_registry"] == "guarded_resolution"
    assert support["regex"] == support["clang"] == support["graph"] == "semantic_event_only"
    assert "carrier_not_a_return_pattern" in support["limitations"]
    assert "proof" in support["knowledge_db"] and "proof" in support["security_map"]
