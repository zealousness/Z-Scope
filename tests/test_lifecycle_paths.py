"""Native same-TU path observations; fixture answers never enter analysis."""

from copy import deepcopy

import pytest

from test_resource_protocol_baseline import protocol_project
from test_retention_protocols import proposal as retention_proposal
from test_single_slot_pool import native_context, native_index, proposal
from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.retention_protocols import verify_retention_contract
from zscope.semantics.single_slot_pool import verify_single_slot_pool


DRIVERS = {
    "aggregate_copy": "submit_b(&p, &q, 0); Queue copy = q; queue_complete(&q, &p); queue_complete(&copy, &p);",
    "union_values": "union { int a; int b; } x = {0}; x.a = 1; if (x.b) submit_a(&p, &q, 0); queue_complete(&q, &p);",
    "narrow_values": "int wide = 256; unsigned char x = wide; if (x) submit_a(&p, &q, 0); queue_complete(&q, &p);",
    "volatile_values": "volatile int x = 0; if (x) submit_a(&p, &q, 0); queue_complete(&q, &p);",
    "unsigned_conversion": "unsigned x = -1; if (x == 1) submit_a(&p, &q, 0); queue_complete(&q, &p);",
    "retained_then_returned": "submit_a(&p, &q, 0); queue_complete(&q, &p);",
    "success_clean": "submit_b(&p, &q, 0); queue_complete(&q, &p);",
    "failure_unreleased": "submit_c(&p, &q, 1); queue_complete(&q, &p);",
    "failure_clean": "submit_b(&p, &q, 1); queue_complete(&q, &p);",
    "retry_retained": "Node *n = pool_take(&p); if (!n) return; queue_send(&q, n, 1); queue_send(&q, n, 0);",
    "success_retained": "submit_b(&p, &q, 0);",
    "stale_retained": "submit_a(&p, &q, 0);",
    "cancel_stale": "submit_b(&p, &q, 0); cancel_a(&q, &p); queue_complete(&q, &p);",
    "cancel_clean": "submit_b(&p, &q, 0); cancel_b(&q, &p); queue_complete(&q, &p);",
    "other_pool": "Pool other = {0}; submit_b(&p, &q, 0); queue_complete(&q, &other);",
    "new_generation": "submit_b(&p, &q, 0); cancel_a(&q, &p); Node *next = pool_take(&p); queue_complete(&q, &p); (void)next;",
    "fresh_generation": "submit_b(&p, &q, 0); cancel_b(&q, &p); submit_b(&p, &q, 0); queue_complete(&q, &p);",
    "exclusive": "submit_b(&p, &q, 0); if (0) cancel_a(&q, &p); queue_complete(&q, &p);",
    "opaque": "submit_b(&p, &q, 0); cancel_a(&q, &p); opaque_hook(&q); queue_complete(&q, &p);",
    "loop": "while (p.live == 0) { submit_b(&p, &q, 0); cancel_b(&q, &p); }",
}


@pytest.fixture(scope="module")
def paths_project(tmp_path_factory):
    root, source, _, database = protocol_project.__wrapped__(tmp_path_factory.mktemp("paths"))
    source.write_text(
        source.read_text()
        + "\nvoid opaque_hook(Queue *q);\n"
        + "\n".join(
            f"void {name}(void) {{ Pool p = {{0}}; Queue q = {{0}}; {body} }}"
            for name, body in DRIVERS.items()
        )
    )
    backend, index = native_index(root, source, database)
    try:
        registry = ContractRegistry()
        for name, raw, verify in [
            ("pool_take", proposal("allocator"), verify_single_slot_pool),
            ("pool_give", proposal("deallocator"), verify_single_slot_pool),
            ("queue_send", retention_proposal(), verify_retention_contract),
        ]:
            row = verify(raw, native_context(index, source, name))
            assert row
            contract = ApiContract.from_row({"contract": row})
            assert contract and contract.effects_trusted
            registry.add(contract)
        yield index, source, registry
    finally:
        backend.close()


def analyze(project, name, **kwargs):
    index, source, registry = project
    return LifecyclePaths(
        index.get_function_program_facts(name, str(source)),
        registry,
        index.get_function_program_facts,
        **kwargs,
    ).run()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("retained_then_returned", "repeat_return"),
        ("failure_unreleased", "failed_retention_unreleased"),
        ("cancel_stale", "repeat_return"),
        ("other_pool", "wrong_pool_return"),
        ("new_generation", "stale_generation_return"),
    ],
)
def test_path_observations(paths_project, name, expected):
    result = analyze(paths_project, name)
    assert result["complete"], result["gaps"]
    assert [o["kind"] for o in result["observations"]] == [expected]
    assert result["proof_authority"] is False
    assert result["cfg_path"] and result["inputs"]
    for resource in result["resources"]:
        assert resource["generation_kind"] == "acquisition_epoch"
        assert resource["release_responsibility"] == "unresolved"
        assert resource["allocation_site"]["call_path"]


@pytest.mark.parametrize(
    "name", ["success_clean", "failure_clean", "cancel_clean", "fresh_generation", "exclusive"]
)
def test_real_cleanup_counterexamples(paths_project, name):
    result = analyze(paths_project, name)
    assert result["complete"], result["gaps"]
    assert result["observations"] == []
    assert all(r["state"] == "released" for r in result["resources"])


@pytest.mark.parametrize(
    "name,gap",
    [
        ("opaque", "link_target_missing_or_ambiguous"),
        ("loop", "loop_path_unclosed"),
        ("submit_a", "entry_inputs_unresolved"),
    ],
)
def test_unknown_is_not_safe_or_defective(paths_project, name, gap):
    result = analyze(paths_project, name)
    assert not result["complete"]
    assert gap in result["gaps"]
    assert not result["observations"]


def test_retention_is_not_automatic_transfer_or_endpoint(paths_project):
    for name in ("success_retained", "retry_retained"):
        result = analyze(paths_project, name)
        assert result["complete"], result["gaps"]
        assert result["observations"] == []
        resource = result["resources"][0]
        assert resource["state"] == "live" and resource["holders_at_exit"]
        assert resource["release_responsibility"] == "unresolved"
    stale = analyze(paths_project, "stale_retained")
    assert [o["kind"] for o in stale["observations"]] == ["released_reference_retained"]
    copied = analyze(paths_project, "aggregate_copy")
    assert copied["gaps"] == ["aggregate_value_copy_unclosed"]
    assert not copied["observations"]


def test_generations_domains_and_real_call_order(paths_project):
    repeat = analyze(paths_project, "cancel_stale")
    (resource,) = repeat["resources"]
    assert [e["kind"] for e in resource["events"]] == [
        "acquire",
        "retain_reference",
        "release_attempt",
        "release_attempt",
    ]
    releases = resource["events"][-2:]
    assert [e["effect_applies"] for e in releases] == [True, False]
    assert all(e["saved_generation"] == e["current_generation"] == 1 for e in releases)
    # The two caller frames are concrete and different, not paired by naming.
    assert releases[0]["call_path"][0]["callee_usr"].endswith("@cancel_a")
    assert releases[1]["call_path"][0]["callee_usr"].endswith("@queue_complete")
    renewed = analyze(paths_project, "new_generation")
    assert [r["generation"] for r in renewed["resources"]] == [1, 2]
    assert renewed["resources"][0]["region"] == renewed["resources"][1]["region"]
    assert len({r["id"] for r in renewed["resources"]}) == 2
    event = renewed["observations"][0]["event"]
    assert (event["saved_generation"], event["current_generation"], event["effect_applies"]) == (
        1,
        2,
        True,
    )


@pytest.mark.parametrize(
    "change,gap",
    [
        ("build", "incomplete_or_mismatched_build"),
        ("usr", "unresolved_native_function_identity"),
        ("cfg", "unsupported_cfg_shape"),
    ],
)
def test_callee_receipts_cannot_cross_scope(paths_project, change, gap):
    index, source, registry = paths_project

    def provider(*args, **kwargs):
        facts = deepcopy(index.get_function_program_facts(*args, **kwargs))
        if change == "build":
            facts["build_context_id"] = "other-build"
        if change == "usr":
            facts["functions"][0]["owner"]["usr"] = "c:@F@other"
        if change == "cfg":
            facts["functions"][0].pop("cfg_entry")
        return facts

    result = LifecyclePaths(
        index.get_function_program_facts("cancel_stale", str(source)), registry, provider
    ).run()
    assert not result["complete"] and result["gaps"] == [gap]
    assert not result["observations"]


def test_budget_and_callee_fact_reuse(paths_project):
    assert analyze(paths_project, "cancel_stale", max_steps=2)["gaps"] == ["path_step_bound"]
    assert analyze(paths_project, "cancel_stale", max_depth=1)["gaps"] == [
        "call_depth_or_recursion_bound"
    ]
    index, source, registry = paths_project
    calls = []

    def provider(*args, **kwargs):
        calls.append((args, kwargs))
        return index.get_function_program_facts(*args, **kwargs)

    result = LifecyclePaths(
        index.get_function_program_facts("fresh_generation", str(source)), registry, provider
    ).run()
    assert result["complete"]
    assert len(calls) == len({args[0] for args, kwargs in calls})
    assert all(kwargs["build_context_id"] == result["build_context_id"] for args, kwargs in calls)


RULE = "zscope.c_cpp.cpp_clang_cfg.object_protocol_path"


def candidates(project, name, policy=None, skills=None):
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.semantics.defaults import default_local_pattern_semantics

    index, source, registry = project
    semantics = default_local_pattern_semantics()
    for contract in registry.contracts:
        semantics.contracts.add(contract)
    ctx = native_context(index, source, name)
    generator = ClangAstCfgCandidateGenerator(
        semantics, rule_policy=policy, program_facts_provider=index.get_function_program_facts
    )
    return [
        issue
        for issue in generator.generate_issues(
            name, ctx["code"], str(source), allowed_skills=skills
        )
        if issue["rule_id"] == RULE
    ]


def test_candidates_and_s04_precise_remaining_obligations(paths_project):
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof

    expected = {
        "retained_then_returned": "repeat_return",
        "cancel_stale": "repeat_return",
        "failure_unreleased": "failed_retention_unreleased",
        "new_generation": "stale_generation_return",
        "other_pool": "wrong_pool_return",
        "stale_retained": "released_reference_retained",
    }
    snapshot = {}
    for name in (
        *expected,
        "success_clean",
        "failure_clean",
        "cancel_clean",
        "fresh_generation",
        "exclusive",
        "opaque",
    ):
        issues = candidates(paths_project, name)
        snapshot[name] = [
            i["evidence_pack"]["object_protocol_path"]["selected_observation"]["kind"]
            for i in issues
        ]
        for issue in issues:
            obligation = attach_decision_facts(issue)
            missing = set(obligation.decision_fact_slice.missing_fact_kinds)
            assert "event:business_release_requirement" in missing
            assert "event:feasible_lifecycle_path" not in missing
            assert "event:object_generation" not in missing
            assert ("event:responsibility_endpoint" in missing) == (name == "failure_unreleased")
            assert ("event:later_slot_access" in missing) == (name == "stale_retained")
            assert obligation.decision_fact_slice.coverage == "partial"
            assert issue["proofs"] == {} and issue["validation_required"]
            assert deterministic_decision_proof(issue, outcome="confirm") is None
            assert deterministic_decision_proof(issue, outcome="reject") is None
    assert snapshot == {name: [expected[name]] if name in expected else [] for name in snapshot}


def test_rule_policy_and_skill_routing(paths_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    for enabled, disabled, present in [
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
        assert bool(candidates(paths_project, "cancel_stale", policy)) == present
    assert not candidates(paths_project, "cancel_stale", skills=["resource_lifecycle"])


@pytest.mark.parametrize(
    "name,gap",
    [
        ("union_values", "union_aliasing"),
        ("narrow_values", "scalar_conversion_unclosed"),
        ("volatile_values", "concurrent_value_unclosed"),
        ("unsigned_conversion", "scalar_conversion_unclosed"),
    ],
)
def test_unsupported_c_value_semantics_stay_unknown(paths_project, name, gap):
    result = analyze(paths_project, name)
    assert result["gaps"] == [gap]
    assert not result["complete"] and not result["observations"]


@pytest.mark.parametrize("verdict", ["verified", "rejected", "uncertain"])
def test_s04_generic_completion_and_model_cannot_invent_responsibility(paths_project, verdict):
    from test_validation_pipeline import FakeUserConfig, _score
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
    from zscope.core.validation.pipeline import ValidationPipeline

    (issue,) = candidates(paths_project, "failure_unreleased")
    attach_decision_facts(issue)
    missing = set(issue["missing_fact_kinds"])
    requested = EvidenceCompletionQueue.required_resolution_fact_kinds(issue, {})
    assert set(requested) == {"caller_contract", "cleanup_coverage"}
    EvidenceCompletionQueue._apply_fact_delta_to_decision_context(
        issue, [{"fact_kind": kind, "fact_uid": "FACT_" + kind} for kind in requested]
    )
    assert set(issue["missing_fact_kinds"]) == missing
    outcome = ValidationPipeline(
        FakeUserConfig(), uncertain_confirm_threshold=0.8
    ).apply_validator_result(
        issue, {"confidence_score": 1.0}, verdict=verdict, score_data=_score(1.0)
    )
    assert issue["candidate_disposition"] == "needs_review"
    assert outcome.report_bucket == "observations"


def test_protocol_paths_do_not_depend_on_function_names(tmp_path):
    import re

    root, source, _, database = protocol_project.__wrapped__(tmp_path)
    code = (
        source.read_text()
        + "\nvoid driver(void) { Pool p = {0}; Queue q = {0}; submit_b(&p, &q, 0); cancel_a(&q, &p); queue_complete(&q, &p); }\n"
    )
    renamed = {
        name: f"operation_{i}"
        for i, name in enumerate(
            (
                "pool_take",
                "pool_give",
                "queue_send",
                "submit_a",
                "submit_b",
                "submit_c",
                "cancel_a",
                "cancel_b",
                "queue_complete",
            )
        )
    }
    source.write_text(
        re.sub(r"\b(" + "|".join(renamed) + r")\b", lambda match: renamed[match[0]], code)
    )
    backend, index = native_index(root, source, database)
    try:
        registry = ContractRegistry()
        for name, raw, verify in [
            ("pool_take", proposal("allocator"), verify_single_slot_pool),
            ("pool_give", proposal("deallocator"), verify_single_slot_pool),
            ("queue_send", retention_proposal(), verify_retention_contract),
        ]:
            row = verify(raw, native_context(index, source, renamed[name]))
            assert row
            contract = ApiContract.from_row({"contract": row})
            assert contract and contract.effects_trusted
            registry.add(contract)
        result = LifecyclePaths(
            index.get_function_program_facts("driver", str(source)),
            registry,
            index.get_function_program_facts,
        ).run()
        assert result["complete"], result["gaps"]
        assert [o["kind"] for o in result["observations"]] == ["repeat_return"]
    finally:
        backend.close()
