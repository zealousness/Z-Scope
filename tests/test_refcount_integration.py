"""RAPI07 publication, observed-link paths, feedback and current-input checks."""

from copy import deepcopy

from test_refcount_protocols import (
    HEADER,
    APIS,
    entry_source,
    proposals,
    registered,
    ref_project,
    native_context,
    native_index,
)
from test_lifecycle_paths import candidates, RULE
from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths
from zscope.core.candidates.decision_facts import attach_decision_facts
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.semantics.contracts import ApiContract, ContractRegistry


def test_workbook_reload_keeps_count_effects_out_of_deallocator_pairs(ref_project, tmp_path):
    from test_wrapper_contract_compiler import publish
    from zscope.semantics.build_scope import bind_build_scope
    from zscope.semantics.resource_coverage import consumer_support

    index, source = ref_project
    registry, snapshots = ContractRegistry(), []
    for name, raw in proposals().items():
        context = native_context(index, source, name)
        raw["evidence"][0]["lines"] = str(context["start_line"])
        snapshot = {**context, "interface_contracts": [raw]}
        compile_snapshot(snapshot, context, registry)
        for row in snapshot["interface_contracts"]:
            registry.add(ApiContract.from_row({"contract": row}))
        snapshots.append(snapshot)
    _, semantics, _ = publish(tmp_path, snapshots)
    with bind_build_scope(native_context(index, source, "ref_drop")):
        (drop,) = semantics.contracts.find_for_call("ref_drop", file_path=str(source))
        assert drop.effects_trusted and drop.role == "standard_operation"
        assert "ref_drop" not in semantics.deallocators
        assert not semantics.contracts.allows("pool_take", "ref_drop")
        assert "drop_is_not_terminal_release" in consumer_support(drop)["limitations"]
    result = LifecyclePaths(
        index.get_function_program_facts("scenario_last_drop", str(source)),
        semantics.contracts,
        index.get_function_program_facts,
    ).run()
    assert result["complete"] and not result["observations"], result["gaps"]
    assert result["trace"][-1]["terminal_effect"] == "logical_pool_return"


def test_serial_and_release_premises_both_required_and_revocable(ref_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.validation.proofs import deterministic_decision_proof

    index, source = ref_project
    registry = registered(ref_project)
    project = index, source, registry
    store = UserConfigStore(tmp_path / "answers")
    (issue,) = candidates(project, "scenario_missing_destroy")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(issue, index, registry, store)
    assumptions = {a["fact_kind"]: a for a in issue["protocol_assessment"]["assumptions"]}
    answer(store, assumptions["event:business_release_requirement"])
    assert not validate(project, store, issue)["issues"]
    assert issue["missing_fact_kinds"] == ["event:nonconcurrent_reference_count"]
    answer(store, assumptions["event:nonconcurrent_reference_count"])
    assert validate(project, store, issue)["issues"]
    old = deepcopy(issue)
    answer(
        store,
        assumptions["event:nonconcurrent_reference_count"],
        "unknown",
        "Recheck execution context",
        revision=1,
    )
    assert deterministic_decision_proof(old, outcome="confirm") is None
    assert not validate(project, store, issue)["issues"]
    assert "event:nonconcurrent_reference_count" in issue["missing_fact_kinds"]


def test_refcount_paths_remain_experimental_and_default_disabled(ref_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    index, source = ref_project
    for enabled, disabled, expected in [
        ([], [], False),
        ([RULE], [], True),
        ([RULE], [RULE], False),
    ]:
        policy = EffectiveRuleSet.build(
            RuleCatalog.builtin(),
            language="c_cpp",
            backend="clang",
            enabled_ids=enabled,
            disabled_ids=disabled,
        ).policy
        assert (
            bool(
                candidates(
                    (index, source, registered(ref_project)), "scenario_missing_destroy", policy
                )
            )
            == expected
        )


def test_actual_linked_refcounts_keep_both_tu_identities_and_invalidate(tmp_path):
    from test_link_targets import build_project

    declarations = """
Node *pool_take(Pool *pool); int pool_give(Pool *pool, Node *node);
void ref_init(Node *node); int ref_retain(Node *node);
int ref_drop(Pool *pool, Node *node); int count_only_drop(Node *node);
int table_drop(Pool *pool, Node *node);
"""
    header = tmp_path / "api.h"
    header.write_text(HEADER + declarations)
    database, _, _ = build_project(
        tmp_path,
        {
            "a.c": '#include "api.h"\n'
            + entry_source()
            + "int main(void) {scenario_last_drop(); return 0;}\n",
            "b.c": '#include "api.h"\n' + APIS,
        },
    )
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        registry = registered((index, tmp_path / "b.c"))
        for name in ("last_drop", "table_cleanup", "two_to_one"):
            facts = index.get_function_program_facts("scenario_" + name, str(tmp_path / "a.c"))
            result = LifecyclePaths(facts, registry, index.get_function_program_facts).run()
            assert result["complete"] and not result["observations"], result["gaps"]
            assert result["scope"] == "concrete_linked_c_entry_path"
            assert len({b["build_context_id"] for b in result["function_bindings"].values()}) == 2
        (issue,) = candidates((index, tmp_path / "a.c", registry), "scenario_missing_destroy")
        attach_decision_facts(issue)
        assessment = assess_protocol_candidate(issue, index, registry)
        assert assessment["state"] == "conditional" and assessment["link_target"]
        header.write_text(header.read_text() + "\n/* changed source dependency */\n")
        stale = assess_protocol_candidate(issue, index, registry)
        assert stale["state"] == "pending" and not stale["technical_witness_current"]
    finally:
        backend.close()
