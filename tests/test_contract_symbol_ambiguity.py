"""Roles cannot disambiguate overloaded or file-local interface identities."""

from dataclasses import replace

from zscope.semantics.contract_compiler import derive_contracts
from zscope.semantics.contracts import ApiContract, ContractRegistry, ObjectBinding, SymbolIdentity


def overloaded():
    release = ApiContract(
        SymbolIdentity("operate", "api.cpp", "void operate(char *)"),
        "deallocator",
        ObjectBinding("argument", 0),
        source="user",
    )
    borrow = ApiContract(
        SymbolIdentity("operate", "api.cpp", "void operate(const char *)"),
        "ownership_transfer",
        ObjectBinding("argument", 0),
        source="user",
    )
    return ContractRegistry([release, borrow])


def test_role_is_not_evidence_of_the_selected_overload():
    registry = overloaded()
    assert len(registry.find("operate")) == 2
    assert not registry.match_call("operate", "deallocator", ["buffer"])
    assert registry.effect_status("operate", "deallocator", "operate(buffer)") == "unknown"
    assert registry.resolve_object("operate", "deallocator", ["buffer"]) == ""
    exact = registry.match_call(
        "operate", "deallocator", ["buffer"], signature=registry.contracts[0].symbol.signature
    )
    assert len(exact) == 1 and exact[0].applicability == "applies"
    assert not registry.match_call(
        "operate", "deallocator", ["buffer"], signature=registry.contracts[1].symbol.signature
    )


def test_same_symbol_can_still_have_multiple_effects():
    registry = overloaded()
    registry.contracts[1] = replace(registry.contracts[1], symbol=registry.contracts[0].symbol)
    assert len(registry.match_call("operate", "deallocator", ["buffer"])) == 1
    assert len(registry.match_call("operate", "ownership_transfer", ["buffer"])) == 1


def test_file_local_homonyms_require_a_file_selector():
    registry = overloaded()
    registry.contracts[1] = replace(
        registry.contracts[1], symbol=SymbolIdentity("operate", "other.cpp")
    )
    assert not registry.match_call("operate", "deallocator", ["buffer"])
    assert len(registry.match_call("operate", "deallocator", ["buffer"], file_path="api.cpp")) == 1


def test_wrapper_cannot_derive_effects_from_one_role_of_an_ambiguous_symbol():
    registry = overloaded()
    context = {
        "func_name": "wrapper",
        "file_path": "wrapper.cpp",
        "signature": "void wrapper(char *buffer)",
        "code": "void wrapper(char *buffer) { operate(buffer); }",
    }
    assert derive_contracts(context, registry) == []


def test_ambiguous_allocation_cannot_supply_size_domain_or_transitions():
    registry = overloaded()
    registry.contracts[0] = replace(
        registry.contracts[0],
        role="allocator",
        carrier=ObjectBinding("return"),
        resource_domain=ObjectBinding("argument", 0),
        resource_family="pool",
        protocol={
            "kind": "standard_api_effects",
            "allocation_extent": [{"kind": "literal", "value": 8}],
            "transitions": [
                {
                    "when": {"op": "true"},
                    "actions": [
                        {"kind": "preserve", "object": {"kind": "argument", "argument_index": 0}}
                    ],
                }
            ],
        },
    )
    assert registry.allocation_extent("operate", ["pool"]) == ""
    assert registry.acquisition_domain("operate", "operate(pool)") == ("", "")
    assert registry.resolved_transitions("operate", ["pool"]) == []
