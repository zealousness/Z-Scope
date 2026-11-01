"""Conditional handoff uses existing contracts and never relies on case order."""

from copy import deepcopy
from dataclasses import replace

import pytest

from test_wrapper_contract_compiler import context, publish
from zscope.config.user_config_store import UserConfigStore
from zscope.semantics.contract_compiler import compile_snapshot, derive_contracts, validate_contract
from zscope.semantics.contract_conditions import compare, evaluate, predicates_overlap
from zscope.semantics.contracts import (
    ApiContract,
    CONTRACT_COMPILER_VERSION,
    ContractRegistry,
    ObjectBinding,
    SymbolIdentity,
    contract_rows,
)
from zscope.semantics.inference import LocalPatternSemanticBuilder


def test_address_operand_never_uses_the_stored_pointer_value():
    condition = compare({"kind": "argument", "index": 0}, "==", None)
    assert evaluate(condition, ["&p"], facts={"p": None}) == "unknown"
    assert evaluate(condition, ["&p"], facts={"p": object()}) == "unknown"


def test_address_comparison_requires_exact_caller_identity():
    condition = {
        "op": "compare",
        "left": {"kind": "argument", "index": 0},
        "operator": "==",
        "right": {"kind": "argument", "index": 1},
    }
    assert evaluate(condition, ["&p", "&p"]) == "unknown"
    address = object()
    assert evaluate(condition, ["&p", "&p"], facts={"&p": address}) == "applies"
    assert evaluate(condition, ["&p", "&q"], facts={"&p": address}) == "unknown"


def handoff(**changes):
    return replace(
        ApiContract(
            symbol=SymbolIdentity("queue_push", "queue.c"),
            role="ownership_transfer",
            carrier=ObjectBinding("argument", 1),
            resource_domain=ObjectBinding("argument", 0),
            resource_family="owned-node",
            source="user",
            effect_cases=[
                {"when": compare({"kind": "return"}, "==", 0), "effect": "applies"},
                {"when": compare({"kind": "return"}, "!=", 0), "effect": "no_effect"},
            ],
            evidence=[{"lines": "1"}],
        ),
        **changes,
    )


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    "returned,expected", [("0", "applies"), ("-1", "does_not_apply"), ("status", "unknown")]
)
def test_success_transfers_failure_retains_unchecked_return_stays_unknown(
    reverse, returned, expected
):
    contract = handoff()
    if reverse:
        contract = replace(contract, effect_cases=list(reversed(contract.effect_cases)))
    registry = ContractRegistry([contract])
    result = registry.match_call(
        "queue_push", "ownership_transfer", ["pool_one", "node"], returned
    )[0]
    assert result.applicability == expected
    assert result.object == "node" and result.resource_domain == "pool_one"
    other = registry.match_call(
        "queue_push", "ownership_transfer", ["pool_two", "other"], returned
    )[0]
    assert other.object != result.object and other.resource_domain != result.resource_domain


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("op,value", [(">=", 0), ("<=", 0), ("!=", -1), ("==", 0)])
def test_conflicting_guards_never_discharge_by_order(reverse, op, value):
    cases = [
        {"when": compare({"kind": "return"}, op, value), "effect": "applies"},
        {"when": compare({"kind": "return"}, "==", 0), "effect": "no_effect"},
    ]
    contract = handoff(effect_cases=cases[::-1] if reverse else cases)
    assert contract.applicability(["pool", "node"], "0") == "unknown"
    ctx = context("queue_push", "int queue_push(Queue *q, Node *p) { return put(q, p); }")
    assert "conflicting_effect_cases" in validate_contract(contract.to_dict(), ctx)


@pytest.mark.parametrize("effect", ["no_effect", "unknown"])
@pytest.mark.parametrize("reverse", [False, True])
def test_true_effect_does_not_override_unresolved_competing_effect(effect, reverse):
    cases = [
        {"when": {"op": "true"}, "effect": "applies"},
        {"when": {"op": "unknown"}, "effect": effect},
    ]
    contract = handoff(effect_cases=cases[::-1] if reverse else cases)
    assert contract.applicability(["pool", "node"], "0") == "unknown"


def test_unknown_same_effect_and_false_case_do_not_remove_known_effect():
    contract = handoff(
        effect_cases=[
            {"when": {"op": "true"}, "effect": "applies"},
            {"when": {"op": "unknown"}, "effect": "applies"},
            {"when": {"op": "false"}, "effect": "no_effect"},
        ]
    )
    assert contract.applicability(["pool", "node"], "0") == "applies"
    assert (
        replace(contract, preconditions={"op": "unknown"}).applicability(["pool", "node"], "0")
        == "unknown"
    )
    assert (
        replace(contract, preconditions={"op": "false"}).applicability(["pool", "node"], "0")
        == "does_not_apply"
    )


def test_overlap_check_is_bounded_and_respects_preconditions_and_reference_identity():
    result = {"kind": "return"}
    assert predicates_overlap(compare(result, ">=", 0), compare(result, "==", 0))
    assert not predicates_overlap(compare(result, ">", 0), compare(result, "==", 0))
    assert not predicates_overlap(compare(result, "<", 1), compare(result, ">", 0))
    assert predicates_overlap(compare(result, "<", 2), compare(result, ">", 0))
    assert predicates_overlap(
        compare({"kind": "argument", "index": 0}, "==", 1),
        compare({"kind": "argument", "index": 1}, "==", 2),
    )
    assert not predicates_overlap({"op": "unknown"}, compare(result, "==", 0))
    assert not predicates_overlap({"op": "all", "items": [{"op": "true"}] * 65})
    contract = handoff(
        preconditions=compare(result, "<", 0),
        effect_cases=[
            {"when": compare(result, "!=", 0), "effect": "applies"},
            {"when": compare(result, ">", 0), "effect": "no_effect"},
        ],
    )
    ctx = context("queue_push", "int queue_push(Queue *q, Node *p) { return put(q, p); }")
    assert "conflicting_effect_cases" not in validate_contract(contract.to_dict(), ctx)


def test_swapped_wrapper_roundtrip_preserves_conditions_object_pool_and_assumptions(tmp_path):
    base = handoff()
    ctx = context("forward", "int forward(Node *p, Queue *q) { return queue_push(q, p); }")
    derived = derive_contracts(ctx, ContractRegistry([base]))
    assert len(derived) == 1
    wrapped = ApiContract.from_row({"contract": derived[0]})
    assert wrapped and wrapped.effects_trusted
    assert wrapped.carrier.argument_index == 0
    assert wrapped.resource_domain.argument_index == 1
    assert wrapped.verification["assumptions"][0]["source"] == "user"
    _, semantics, _ = publish(tmp_path, [{**ctx, "interface_contracts": derived}])
    registry = semantics.contracts
    for returned, expected in (("0", "applies"), ("-1", "does_not_apply"), ("status", "unknown")):
        match = registry.match_call("forward", "ownership_transfer", ["node", "pool"], returned)[0]
        assert (match.object, match.resource_domain, match.applicability) == (
            "node",
            "pool",
            expected,
        )


def test_unverified_proposal_or_stale_compiler_cannot_discharge_or_certify_wrapper():
    ctx = context("forward", "int forward(Node *p, Queue *q) { return queue_push(q, p); }")
    for verification in (
        {"method": "schema_only"},
        {
            "method": "source_composition",
            "source_hash": "old-source",
            "effect_strength": "must_under_guard",
            "compiler_version": "zscope.contract-compiler.v15",
        },
    ):
        base = handoff(
            source="inferred:semantic_modeling", confidence=1.0, verification=verification
        )
        assert not base.effects_trusted
        assert base.applicability(["pool", "node"], "0") == "unknown"
        derived = derive_contracts(ctx, ContractRegistry([base]))
        assert all(not ApiContract.from_row({"contract": raw}).effects_trusted for raw in derived)


def test_current_compiler_replaces_conflicting_document_proposal_and_changes_source_receipt():
    base = handoff()
    ctx = context("forward", "int forward(Node *p, Queue *q) { return queue_push(q, p); }")
    proposal = handoff(
        symbol=SymbolIdentity("forward"),
        effect_cases=[{"when": {"op": "true"}, "effect": "applies"}],
    ).to_dict()
    snapshot = {"interface_contracts": [proposal]}
    assert compile_snapshot(snapshot, ctx, ContractRegistry([base])) == []
    compiled = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
    assert compiled and compiled.applicability(["node", "pool"], "-1") == "does_not_apply"
    assert compiled.verification["compiler_version"] == CONTRACT_COMPILER_VERSION
    changed = dict(ctx, code="int forward(Node *p, Queue *q) { return queue_push(q, other); }")
    revised = derive_contracts(changed, ContractRegistry([base]))
    assert not any(ApiContract.from_row({"contract": raw}).effects_trusted for raw in revised)
    unverified = replace(
        base, source="inferred:semantic_modeling", verification={"method": "schema_only"}
    )
    assert ContractRegistry([base]).version != ContractRegistry([unverified]).version


def test_manual_contract_remains_authoritative_after_generated_conflict(tmp_path):
    manual = handoff()
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    store.workbook.write_rows(
        {
            "resource": [
                {
                    "symbol_name": "queue_push",
                    "file_path": "queue.c",
                    "kind": "ownership_transfer",
                    "source": "user",
                    "contract": manual.to_dict(),
                }
            ]
        }
    )
    proposed = deepcopy(manual.to_dict())
    proposed["effect_cases"] = [{"when": {"op": "true"}, "effect": "applies"}]
    proposed["verification"] = {"method": "schema_only"}
    store.workbook.merge_generated(
        contract_rows(
            [
                {
                    "func_name": "queue_push",
                    "file_path": "queue.c",
                    "interface_contracts": [proposed],
                }
            ]
        ),
        covered_symbols={"queue_push"},
    )
    reader = UserConfigStore(store.workbook.path)
    actual = (
        LocalPatternSemanticBuilder(None, reader, None, [])
        .semantics_from_user_config()
        .contracts.find("queue_push")
    )
    assert len(actual) == 1 and actual[0].source == "user"
    assert actual[0].applicability(["pool", "node"], "-1") == "does_not_apply"


def test_homonymous_interfaces_with_distinct_files_cannot_supply_unscoped_handoff():
    registry = ContractRegistry(
        [handoff(), handoff(symbol=SymbolIdentity("queue_push", "other.c"))]
    )
    assert registry.match_call("queue_push", "ownership_transfer", ["pool", "node"], "0") == []
    assert (
        registry.match_call(
            "queue_push", "ownership_transfer", ["pool", "node"], "0", file_path="queue.c"
        )[0].applicability
        == "applies"
    )


def test_callee_condition_change_invalidates_wrapper_contract_and_proof_dependencies():
    original = handoff()
    changed = replace(
        original,
        effect_cases=[
            {"when": compare({"kind": "return"}, "==", 1), "effect": "applies"},
            {"when": compare({"kind": "return"}, "!=", 1), "effect": "no_effect"},
        ],
    )
    ctx = context("forward", "int forward(Node *p, Queue *q) { return queue_push(q, p); }")
    before = ApiContract.from_row(
        {"contract": derive_contracts(ctx, ContractRegistry([original]))[0]}
    )
    after = ApiContract.from_row(
        {"contract": derive_contracts(ctx, ContractRegistry([changed]))[0]}
    )
    assert before and after and before.effects_trusted and after.effects_trusted
    assert before.verification["source_hash"] == after.verification["source_hash"]
    assert before.verification["proof_dependencies"] != after.verification["proof_dependencies"]
    assert ContractRegistry([before]).version != ContractRegistry([after]).version
    assert before.applicability(["node", "pool"], "0") == "applies"
    assert after.applicability(["node", "pool"], "0") == "does_not_apply"
