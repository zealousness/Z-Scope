"""Bounded handle publication, current link replay and scoped acceptance."""

from copy import deepcopy

import pytest

from test_handle_protocols import (
    HEADER,
    APIS,
    entry_source,
    proposals,
    registered,
    handle_project,
    native_context,
    native_index,
)
from test_lifecycle_paths import candidates, RULE
from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths
from zscope.core.candidates.decision_facts import attach_decision_facts
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.semantics.contracts import ApiContract, ContractRegistry


def test_workbook_reload_keeps_descriptor_and_backing_separate(handle_project, tmp_path):
    from test_wrapper_contract_compiler import publish
    from test_semantic_contract_schema import errors
    from zscope.semantics.build_scope import bind_build_scope
    from zscope.semantics.resource_coverage import consumer_support

    index, source = handle_project
    registry, snapshots = ContractRegistry(), []
    for name, raw in proposals().items():
        raw.update(preconditions={"op": "true"}, pairs=[], confidence=0.9)
        assert errors(raw) == []
        context = native_context(index, source, name)
        raw["evidence"][0]["lines"] = str(context["start_line"])
        snapshot = {**context, "interface_contracts": [raw]}
        compile_snapshot(snapshot, context, registry)
        for row in snapshot["interface_contracts"]:
            registry.add(ApiContract.from_row({"contract": row}))
        snapshots.append(snapshot)
    _, semantics, _ = publish(tmp_path, snapshots)
    with bind_build_scope(native_context(index, source, "h_close")):
        (close,) = semantics.contracts.find_for_call("h_close", file_path=str(source))
        assert close.effects_trusted and close.role == "standard_operation"
        assert "h_close" not in semantics.deallocators
        assert not semantics.contracts.allows("h_open", "h_close")
        assert "close_status_not_release_state" in consumer_support(close)["limitations"]
    result = LifecyclePaths(
        index.get_function_program_facts("scenario_dup_survives", str(source)),
        semantics.contracts,
        index.get_function_program_facts,
    ).run()
    assert result["complete"], result["gaps"]
    first, second = result["resources"]
    assert first["id"] != second["id"] and first["backing_object_id"] == second["backing_object_id"]


@pytest.mark.parametrize(
    "withdraw",
    [
        "event:serial_handle_namespace",
        "event:responsibility_endpoint",
        "event:business_release_requirement",
    ],
)
def test_failure_requires_all_premises_and_withdrawal_reopens_gap(
    handle_project, tmp_path, withdraw
):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.validation.proofs import deterministic_decision_proof

    index, source = handle_project
    project = index, source, registered(handle_project)
    store = UserConfigStore(tmp_path / "answers")
    (issue,) = candidates(project, "scenario_failed_close")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(issue, index, project[2], store)
    assessment = issue["protocol_assessment"]
    assert assessment["state"] == "conditional"
    assumptions = {a["fact_kind"]: a for a in assessment["assumptions"]}
    assert set(assumptions) == {
        "event:serial_handle_namespace",
        "event:responsibility_endpoint",
        "event:business_release_requirement",
    }
    for kind, assumption in assumptions.items():
        if kind != withdraw:
            answer(store, assumption)
    assert not validate(project, store, issue)["issues"]
    assert issue["missing_fact_kinds"] == [withdraw]
    answer(store, assumptions[withdraw])
    assert validate(project, store, issue)["issues"]
    old = deepcopy(issue)
    answer(store, assumptions[withdraw], "unknown", "Recheck contract", revision=1)
    assert deterministic_decision_proof(old, outcome="confirm") is None
    assert not validate(project, store, issue)["issues"]
    assert withdraw in issue["missing_fact_kinds"]


def test_rules_stay_default_disabled_and_disabled_takes_precedence(handle_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    index, source = handle_project
    project = index, source, registered(handle_project)
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
        assert bool(candidates(project, "scenario_stale_close", policy)) == expected


def test_actual_cross_tu_handles_and_const_ops_keep_identities(tmp_path):
    from test_link_targets import build_project

    declarations = """
int h_open(Table *); int h_close(Table *,int,int); int h_close_late(Table *,int,int);
int h_dup(Table *,int); int wrapped_close(Table *,int); void table_close(Table *,int);
Table *expired_table(void); int escaped_handle(void);
"""
    header = tmp_path / "handles.h"
    header.write_text(HEADER + declarations)
    database, _, _ = build_project(
        tmp_path,
        {
            "a.c": '#include "handles.h"\n'
            + entry_source()
            + "\nint main(void){scenario_zero(); return 0;}",
            "b.c": '#include "handles.h"\n' + APIS,
        },
    )
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        registry = registered((index, tmp_path / "b.c"))
        for name in ("dup_cleanup", "retry_preserved", "reopen", "ops"):
            result = LifecyclePaths(
                index.get_function_program_facts("scenario_" + name, str(tmp_path / "a.c")),
                registry,
                index.get_function_program_facts,
            ).run()
            assert result["complete"] and not result["observations"], result["gaps"]
            assert result["scope"] == "concrete_linked_c_entry_path"
            assert len({b["build_context_id"] for b in result["function_bindings"].values()}) == 2
        (issue,) = candidates((index, tmp_path / "a.c", registry), "scenario_stale_close")
        attach_decision_facts(issue)
        assessment = assess_protocol_candidate(issue, index, registry)
        assert assessment["state"] == "conditional" and assessment["link_target"]
        header.write_text(header.read_text() + "\n/* current dependency changed */\n")
        stale = assess_protocol_candidate(issue, index, registry)
        assert stale["state"] == "pending" and not stale["technical_witness_current"]
    finally:
        backend.close()


def test_platform_dependent_close_error_never_claims_no_effect():
    from zscope.semantics.standard_api import standard_contracts

    close = next(c for c in standard_contracts() if c["symbol"]["name"] == "close")
    assert close["verification"]["behavior"] == "error_release_state_platform_dependent"
    assert close["effect_cases"][0]["effect"] == "applies"
    assert close["effect_cases"][1]["effect"] == "unknown"
    contract = ApiContract.from_row({"contract": close})
    assert contract.applicability(["fd"], "-1") == "unknown"
    assert contract.applicability(["fd"], "0") == "applies"
