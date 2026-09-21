"""Publication interfaces need contracts; suggestive names provide no evidence."""

from dataclasses import replace

import pytest

from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.semantics.contracts import ApiContract, ObjectBinding, SymbolIdentity
from zscope.semantics.defaults import default_local_pattern_semantics


def issues(name, contract=None, initialize_first=False):
    semantics = default_local_pattern_semantics()
    if contract:
        semantics.contracts.add(contract)
        semantics.add_api(contract.role, contract.symbol.name, contract.source)
    init = "node->value=1;"
    code = (
        "int entry(void) {\nNode *node=calloc(1,sizeof(Node));\nif (!node) return -1;\n"
        + (init if initialize_first else "")
        + f"\n{name}(arena,node);\n"
        + ("" if initialize_first else init)
        + "\nreturn 0;\n}"
    )
    return [
        i
        for i in RegexCandidateGenerator(semantics).generate_issues("entry", code, "unit.c")
        if i["rule"] == "object_published_by_helper_before_initialization"
    ]


def test_renamed_contract_maps_actual_object_in_second_parameter():
    contract = ApiContract(SymbolIdentity("q"), "ownership_transfer", ObjectBinding("argument", 1))
    assert issues("q", contract)
    assert not issues("q", contract, initialize_first=True)


@pytest.mark.parametrize(
    "name", ["insert_node", "add_item", "publish_entry", "register_record", "attach_link"]
)
def test_suggestive_names_do_not_supply_publication_contracts(name):
    assert not issues(name)


def test_unverified_or_unknown_effect_is_not_publication_proof():
    contract = ApiContract(SymbolIdentity("q"), "ownership_transfer", ObjectBinding("argument", 1))
    assert not issues("q", replace(contract, source="inferred:semantic_modeling"))
    assert not issues("q", replace(contract, conditions=[{"description": "sometimes"}]))


def test_validator_category_correction_uses_behavior_not_interface_spelling():
    from test_validation_pipeline import FakeUserConfig
    from zscope.core.validation.pipeline import ValidationPipeline

    pipeline = ValidationPipeline(FakeUserConfig())
    issue = {"category": "alloc_free_mismatch", "defect_class": "alloc_free_mismatch"}
    assert (
        pipeline._corrected_category_from_validator(
            issue, {"reasoning": "The actual path calls _runtime_noop_free(node)."}
        )
        == ""
    )
    assert (
        pipeline._corrected_category_from_validator(
            issue,
            {
                "reasoning": "The actual issue is a memory leak: q(node) leaves the object allocated."
            },
        )
        == "memory_leak"
    )
