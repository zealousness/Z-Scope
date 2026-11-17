"""Native slot teardown candidates must keep cross-stage obligations open."""

from copy import deepcopy
from dataclasses import replace

import pytest

from test_resource_protocol_baseline import protocol_project
from test_single_slot_pool import native_context, native_index, proposal
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.cpp_domains.retained_slots import retained_slot_teardown
from zscope.core.candidates.decision_facts import attach_decision_facts
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.single_slot_pool import verify_single_slot_pool

RULE = "zscope.c_cpp.cpp_clang_cfg.retained_slot_release"
CASES = {
    "copy_stale": "Node *n = queue->pending; if (n) pool_give(pool, n);",
    "clear_after": "if (queue->pending) pool_give(pool, queue->pending); queue->pending = NULL;",
    "clear_inside": "if (queue->pending) { pool_give(pool, queue->pending); queue->pending = 0; }",
    "copy_clear_after": "Node *n = queue->pending; if (n) pool_give(pool, n); queue->pending = 0;",
    "conditional_clear": "Node *n = queue->pending; if (pool->live) queue->pending = NULL; if (n) pool_give(pool, n);",
    "wrong_slot": "Node *n = queue->pending; queue->other = NULL; if (n) pool_give(pool, n);",
    "overwrite_alias": "Node *n = queue->pending; n = queue->other; if (n) pool_give(pool, n);",
    "extra_call": "if (queue->pending) pool_give(pool, queue->pending); queue_complete(queue, pool);",
    "wrong_guard": "if (pool->live) pool_give(pool, queue->pending);",
    "unconditional": "pool_give(pool, queue->pending);",
    "reset_non_null": "Node *n = queue->pending; queue->pending = (Node*)8; if (n) pool_give(pool, n);",
}


@pytest.fixture(scope="module")
def native_teardowns(tmp_path_factory):
    root, source, _, database = protocol_project.__wrapped__(tmp_path_factory.mktemp("slots"))
    code = source.read_text().replace("Node *pending;", "Node *pending; Node *other;")
    code += "\n" + "\n".join(
        f"void {name}(Queue *queue, Pool *pool) {{ {body} }}" for name, body in CASES.items()
    )
    source.write_text(code)
    backend, index = native_index(root, source, database)
    try:
        ctx = native_context(index, source, "pool_give")
        raw = verify_single_slot_pool(proposal("deallocator"), ctx)
        assert raw
        contract = ApiContract.from_row({"contract": raw})
        assert contract and contract.effects_trusted
        contexts = {
            name: native_context(index, source, name)
            for name in (*CASES, "cancel_a", "cancel_b", "queue_complete")
        }
        yield contexts, contract
    finally:
        backend.close()


@pytest.mark.parametrize(
    "name,state,order",
    [
        ("cancel_a", "entry_value", "absent"),
        ("copy_stale", "entry_value", "absent"),
        ("cancel_b", "null", "before_release"),
        ("queue_complete", "null", "before_release"),
        ("clear_after", "null", "after_release"),
        ("clear_inside", "null", "after_release"),
        ("copy_clear_after", "null", "after_release"),
    ],
)
def test_native_slot_summary_keeps_object_and_effect_unknown(native_teardowns, name, state, order):
    contexts, contract = native_teardowns
    summary = retained_slot_teardown(contexts[name], ContractRegistry([contract]))
    assert summary
    assert summary["slot_at_exit"] == state
    assert summary["detach_order"] == order
    assert summary["build_context_id"] == contract.symbol.build_context_id
    assert summary["generation"] == summary["allocation_site"] == "unknown"
    assert summary["release_applicability"] == "unknown"
    assert summary["slot_field_usr"] and summary["receiver_usr"] != summary["resource_domain_usr"]
    assert summary["proof_authority"] is False
    assert summary["scope"] == "local_slot_only"


@pytest.mark.parametrize("name", list(CASES)[4:])
def test_unsupported_native_bodies_are_unknown_not_cleared(native_teardowns, name):
    contexts, contract = native_teardowns
    assert retained_slot_teardown(contexts[name], ContractRegistry([contract])) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "stale",
        "incomplete",
        "ambiguous",
        "old",
        "missing_usr",
        "macro",
        "guard",
        "source",
        "other_build",
        "union",
    ],
)
def test_fact_receipt_or_source_mismatch_cannot_create_observation(native_teardowns, mutation):
    contexts, contract = native_teardowns
    ctx = deepcopy(contexts["cancel_a"])
    facts = ctx["program_facts"]
    body = facts["functions"][0]
    if mutation == "stale":
        facts["reason"] = "stale_build_context"
    elif mutation == "incomplete":
        facts["complete"] = False
    elif mutation == "ambiguous":
        facts["build_context_id"] = ""
        facts["build_contexts"] = ["a", "b"]
    elif mutation == "old":
        body.pop("resource_protocol_facts_version")
    elif mutation == "missing_usr":
        body["parameters"][0]["usr"] = ""
    elif mutation == "macro":
        for event in body["events"]:
            event["contains_macro"] = True
    elif mutation == "guard":
        for edge in body["cfg_edges"]:
            if edge["branch"] == "true":
                edge["branch"] = "false"
    elif mutation == "source":
        ctx["code"] = ctx["code"].replace("queue->pending)", "pool->live)", 1)
    elif mutation == "other_build":
        facts["build_context_id"] = "other-build"
    elif mutation == "union":
        body["parameters"][0]["pointee_record_kind"] = "union"
    assert retained_slot_teardown(ctx, ContractRegistry([contract])) is None


@pytest.mark.parametrize(
    "mutation",
    ["proposal", "wrong_build", "unscoped", "wrong_file", "wrong_type", "ambiguous", "missing"],
)
def test_proposed_or_wrong_release_contract_cannot_generate_candidate(native_teardowns, mutation):
    contexts, original = native_teardowns
    contract = deepcopy(original)
    if mutation == "proposal":
        contract = replace(contract, verification={"method": "schema_only"})
    elif mutation == "wrong_build":
        contract = replace(contract, symbol=replace(contract.symbol, build_context_id="elsewhere"))
    elif mutation == "unscoped":
        contract = replace(contract, symbol=replace(contract.symbol, build_context_id=""))
    elif mutation == "wrong_file":
        contract = replace(contract, symbol=replace(contract.symbol, file_path="other.c"))
    elif mutation == "wrong_type":
        contract.protocol["pool_identity"]["pool_type_usr"] = "different-record"
    contracts = [contract]
    if mutation == "ambiguous":
        contracts.append(replace(contract, role="reference_retention"))
    if mutation == "missing":
        contracts = []
    assert retained_slot_teardown(contexts["cancel_a"], ContractRegistry(contracts)) is None


def candidates(context, contract, policy=None, skills=None):
    semantics = default_local_pattern_semantics()
    semantics.contracts.add(contract)
    generator = ClangAstCfgCandidateGenerator(
        semantics,
        rule_policy=policy,
        program_facts_provider=lambda *_: context["program_facts"],
    )
    return [
        issue
        for issue in generator.generate_issues(
            context["func_name"], context["code"], context["file_path"], allowed_skills=skills
        )
        if issue["rule_id"] == RULE
    ]


def test_native_candidates_snapshot_and_open_decision_obligations(native_teardowns):
    contexts, contract = native_teardowns
    observed = {}
    for name in (
        "cancel_a",
        "copy_stale",
        "cancel_b",
        "queue_complete",
        "clear_after",
        "clear_inside",
    ):
        issues = candidates(contexts[name], contract)
        observed[name] = [(i["rule_id"], i["defect_class"], i["skill"]) for i in issues]
        for issue in issues:
            assert issue["build_context_id"] == contract.symbol.build_context_id
            assert issue["proofs"] == {}
            assert issue["validation_required"]
            assert deterministic_decision_proof(issue, outcome="confirm") is None
            assert deterministic_decision_proof(issue, outcome="reject") is None
            obligation = attach_decision_facts(issue)
            assert obligation.decision_fact_slice.coverage == "partial"
            assert {
                "event:release_effect_applies",
                "event:same_allocation_generation",
                "event:receiver_survives_release",
                "event:later_slot_access",
                "event:feasible_lifecycle_path",
            } <= set(obligation.decision_fact_slice.missing_fact_kinds)
    assert observed == {
        "cancel_a": [(RULE, "state_inconsistency", "ownership_contract")],
        "copy_stale": [(RULE, "state_inconsistency", "ownership_contract")],
        "cancel_b": [],
        "queue_complete": [],
        "clear_after": [],
        "clear_inside": [],
    }


def test_runtime_policy_default_disabled_explicit_enable_and_disable_wins(native_teardowns):
    contexts, contract = native_teardowns
    catalog = RuleCatalog.builtin()
    for enabled, disabled, expected in [
        ([], [], False),
        ([RULE], [], True),
        ([RULE], [RULE], False),
    ]:
        policy = EffectiveRuleSet.build(
            catalog, language="c_cpp", backend="clang", enabled_ids=enabled, disabled_ids=disabled
        ).policy
        assert bool(candidates(contexts["cancel_a"], contract, policy)) is expected
    assert not candidates(contexts["cancel_a"], contract, skills=["resource_lifecycle"])


def test_generic_completion_cannot_discharge_protocol_obligations(native_teardowns):
    contexts, contract = native_teardowns
    issue = candidates(contexts["cancel_a"], contract)[0]
    attach_decision_facts(issue)
    missing = set(issue["missing_fact_kinds"])
    requested = EvidenceCompletionQueue.required_resolution_fact_kinds(issue, {})
    assert set(requested) == {"caller_contract", "cleanup_coverage", "source_sink_reachability"}
    assert len(requested) == 3
    EvidenceCompletionQueue._apply_fact_delta_to_decision_context(
        issue,
        [
            {"fact_uid": "FACT_" + kind, "fact_kind": kind, "dependency_code_hash": "current"}
            for kind in requested
        ],
    )
    assert set(issue["missing_fact_kinds"]) == missing
    assert issue["decision_fact_coverage"] == "partial"
    assert issue.get("candidate_promotion_eligible") is not True
    assert deterministic_decision_proof(issue, outcome="confirm") is None


@pytest.mark.parametrize("verdict", ["verified", "rejected", "uncertain"])
def test_model_opinion_does_not_close_teardown_obligation(native_teardowns, verdict):
    from test_validation_pipeline import FakeUserConfig, _score
    from zscope.core.validation.pipeline import ValidationPipeline

    contexts, contract = native_teardowns
    issue = candidates(contexts["cancel_a"], contract)[0]
    attach_decision_facts(issue)
    outcome = ValidationPipeline(FakeUserConfig()).apply_validator_result(
        issue,
        {"reasoning": "model opinion without a new native fact", "confidence_score": 1.0},
        verdict=verdict,
        score_data=_score(1.0),
    )
    assert issue["candidate_disposition"] == "needs_review"
    assert outcome.report_bucket == "observations"
    assert issue["missing_fact_kinds"]


def test_navigation_index_name_keeps_native_binding(native_teardowns):
    contexts, contract = native_teardowns
    ctx = {**contexts["cancel_a"], "func_name": contexts["cancel_a"]["index_name"]}
    issues = candidates(ctx, contract)
    assert len(issues) == 1
    assert issues[0]["function"] == ctx["index_name"]
    assert issues[0]["evidence_pack"]["sink"]["column"] > 1


@pytest.mark.parametrize("verdict", ["verified", "uncertain"])
def test_slice_only_gap_survives_empty_top_level_and_high_score(native_teardowns, verdict):
    from test_validation_pipeline import FakeUserConfig, _score
    from zscope.core.validation.pipeline import ValidationPipeline

    contexts, contract = native_teardowns
    issue = candidates(contexts["cancel_a"], contract)[0]
    attach_decision_facts(issue)
    issue["missing_fact_kinds"] = []
    issue["negative_evidence"] = []
    pipeline = ValidationPipeline(FakeUserConfig(), uncertain_confirm_threshold=0.8)
    pipeline.apply_validator_result(
        issue, {"confidence_score": 1.0}, verdict=verdict, score_data=_score(1.0)
    )
    assert issue["candidate_disposition"] == "needs_review"
    assert "义务" in issue["promotion_review_reason"]
    if verdict == "uncertain":
        assert issue["needs_review_sub_state"] == "model_uncertain"


def test_missing_kind_normalization_keeps_unimplemented_obligations():
    from zscope.core.validation.evidence import normalize_missing_fact_kinds

    assert normalize_missing_fact_kinds(
        ("event:same_allocation_generation", "event:acquire", "event:same_allocation_generation")
    ) == ["event:same_allocation_generation", "ownership_transfer"]


@pytest.mark.parametrize("mutation", ["fake_null", "field_macro"])
def test_real_compiler_macro_counterexamples(protocol_project, mutation):
    root, source, _, database = protocol_project
    code = source.read_text().replace("Node *pending;", "Node *pending; Node *other;")
    if mutation == "fake_null":
        code += "\n#undef NULL\n#define NULL ((void*)8)\n"
    else:
        code += "\n#define pending other\n"
    code += "void teardown(Queue *queue, Pool *pool) { Node *n = queue->pending; queue->pending = NULL; if (n) pool_give(pool, n); }\n"
    source.write_text(code)
    backend, index = native_index(root, source, database)
    try:
        ctx = native_context(index, source, "pool_give")
        raw = verify_single_slot_pool(proposal("deallocator"), ctx)
        assert raw
        contract = ApiContract.from_row({"contract": raw})
        ctx = native_context(index, source, "teardown")
        assert retained_slot_teardown(ctx, ContractRegistry([contract])) is None
    finally:
        backend.close()
