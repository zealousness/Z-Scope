"""Real native pthread identities and a bounded delayed-callback witness."""

from copy import deepcopy
from dataclasses import replace
import json
import shutil

import pytest

from test_single_slot_pool import native_index
from test_lifecycle_paths import candidates, RULE
from zscope.core.candidates.cpp_domains.async_paths import AsyncLifecyclePaths
from zscope.core.candidates.decision_facts import attach_decision_facts
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.defaults import default_local_pattern_semantics

DRIVERS = {
    "cancel_free_join": "pthread_cancel(t); free(p); pthread_join(t,0);",
    "free_join": "free(p); pthread_join(t,0);",
    "join_free": "pthread_join(t,0); free(p);",
    "cancel_join_free": "pthread_cancel(t); pthread_join(t,0); free(p);",
    "exclusive": "if(0) free(p); pthread_join(t,0); free(p);",
    "detach_free": "pthread_detach(t); free(p);",
    "detach_join": "pthread_detach(t); free(p); pthread_join(t,0);",
    "no_drain": "pthread_cancel(t); free(p);",
    "different_object": "struct Item *q=malloc(sizeof *q); if(!q)return; free(q); pthread_join(t,0); free(p);",
    "new_acquisition": "free(p); p=malloc(sizeof *p); if(!p)return; pthread_join(t,0); free(p);",
    "unknown_call": "opaque(p); free(p); pthread_join(t,0);",
    "wrong_handle": "pthread_t other=0; free(p); pthread_join(other,0);",
    "two_workers": "pthread_t other; pthread_create(&other,0,work,p); free(p); pthread_join(t,0);",
    "input_branch": "if(flag) free(p); pthread_join(t,0);",
    "cancel_point": "pthread_cancel(t); free(p); pthread_join(t,0);",
    "loop_callback": "free(p); pthread_join(t,0);",
    "unused_context": "free(p); pthread_join(t,0);",
}


@pytest.fixture(scope="module")
def async_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("pthread-paths")
    source = root / "work.c"
    source.write_text(
        """#include <pthread.h>
#include <stdlib.h>
struct Item {int value;};
extern int flag;
void opaque(void *p);
static void *work(void *raw) {struct Item *p=raw; p->value=1; return 0;}
static void *with_cancel_point(void *raw) {pthread_testcancel(); struct Item *p=raw; p->value=1; return 0;}
static void *with_loop(void *raw) {int k=1; while(k){} struct Item *p=raw; p->value=1; return 0;}
static void *unused(void *raw) {return 0;}
"""
        + "\n".join(f"""void {name}(void) {{
struct Item *p=malloc(sizeof *p);
if(!p)return;
pthread_t t;
if(pthread_create(&t,0,{ {'cancel_point':'with_cancel_point','loop_callback':'with_loop','unused_context':'unused'}.get(name,'work') },p)!=0){{free(p);return;}}
{body}
}}
""" for name, body in DRIVERS.items())
    )
    cdb = root / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(source),
                    "arguments": [shutil.which("clang"), "-c", str(source), "-pthread"],
                }
            ]
        )
    )
    backend, index = native_index(root, source, cdb)
    try:
        yield index, source, default_local_pattern_semantics().contracts
    finally:
        backend.close()


def analyze(project, name, **kwargs):
    index, source, registry = project
    return AsyncLifecyclePaths(
        index.get_function_program_facts(name, str(source)),
        registry,
        index.get_function_program_facts,
        **kwargs,
    ).run()


def test_default_deferred_cancellation_without_handlers_never_returns(async_project):
    result = analyze(async_project, "cancel_point")
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["cancelled"] and result["schedule"]["worker"]["joined"]
    assert not any(e["kind"] == "callback_access" for e in result["trace"])
    assert result["schedule"]["cancellation"]["cleanup_invocations"] == 0
    assert not result["schedule"]["absence_is_safety_proof"]


@pytest.mark.parametrize("name", ["cancel_free_join", "free_join", "new_acquisition"])
def test_actual_callback_access_to_released_generation(async_project, name):
    result = analyze(async_project, name)
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["kind"] == "callback_after_release"
    assert observation["resource_id"] == result["resources"][0]["id"]
    assert observation["event"]["function_usr"].endswith("@F@work")
    assert observation["event"]["call_path"][0]["edge_kind"] == "scheduled_callback_during_join"
    assert result["schedule"]["stopped_at_invalid_access"]
    assert not result["proof_authority"] and not result["schedule"]["all_interleavings_covered"]
    assert not any(
        c["kind"] == "pthread_join_returns_zero" for c in result["schedule"]["constraints"]
    )
    if name == "new_acquisition":
        assert len(result["resources"]) == 2
        assert result["resources"][0]["id"] != result["resources"][1]["id"]


@pytest.mark.parametrize(
    "name", ["join_free", "cancel_join_free", "exclusive", "different_object", "unused_context"]
)
def test_no_observation_is_only_this_schedule(async_project, name):
    result = analyze(async_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["complete"]
    assert not result["schedule"]["absence_is_safety_proof"]


@pytest.mark.parametrize(
    "name,gap",
    [
        ("detach_free", "async_worker_not_drained_in_entry"),
        ("no_drain", "async_worker_not_drained_in_entry"),
        ("detach_join", "async_join_not_available"),
        ("unknown_call", "async_unknown_call"),
        ("wrong_handle", "async_thread_identity_unresolved"),
        ("two_workers", "async_multiple_workers_or_attributes"),
        ("input_branch", "unsupported_object_expression"),
        ("loop_callback", "loop_path_unclosed"),
    ],
)
def test_unknown_does_not_become_safe_or_defect(async_project, name, gap):
    result = analyze(async_project, name)
    assert result["gaps"] == [gap]
    assert not result["complete"] and not result["observations"]


def test_candidate_native_replay_feedback_and_json_authority(async_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.validation.proofs import deterministic_decision_proof

    (issue,) = candidates(async_project, "cancel_free_join")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(
        issue, async_project[0], async_project[2]
    )
    assessment = issue["protocol_assessment"]
    assert assessment["state"] == "conditional", assessment
    store = UserConfigStore(tmp_path / "answers")
    assumption = assessment["assumptions"][0]
    answer(store, assumption)
    assert validate(async_project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "调度前提撤回", revision=1)
    assert not deterministic_decision_proof(issue, outcome="confirm")
    assert not validate(async_project, store, issue)["issues"]


def test_experimental_default_and_current_bindings(async_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(async_project, "free_join", policy)
    (issue,) = candidates(async_project, "free_join")
    altered = deepcopy(issue)
    altered["evidence_pack"]["object_protocol_path"]["schedule"]["worker"]["complete"] = True
    assert (
        assess_protocol_candidate(altered, async_project[0], async_project[2])["state"] == "pending"
    )
    registry = default_local_pattern_semantics().contracts
    (base,) = registry.find("pthread_join", "thread_release")
    registry.add(replace(base, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    assert assess_protocol_candidate(issue, async_project[0], registry)["state"] == "pending"


@pytest.mark.parametrize(
    "name", ["malloc", "free", "pthread_create", "pthread_cancel", "pthread_join"]
)
def test_changed_root_contract_cannot_use_hardcoded_effect(async_project, name):
    index, source, _ = async_project
    registry = default_local_pattern_semantics().contracts
    (contract,) = registry.find_for_call(name)
    registry.add(replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    result = AsyncLifecyclePaths(
        index.get_function_program_facts("cancel_free_join", str(source)),
        registry,
        index.get_function_program_facts,
    ).run()
    assert not result["complete"] and not result["observations"]
    assert result["gaps"] == ["async_standard_contract_unverified"]


def test_current_build_override_is_not_bypassed_by_builtin(async_project):
    index, source, _ = async_project
    facts = index.get_function_program_facts("free_join", str(source))
    for build in (facts["build_context_id"], "other-build"):
        registry = default_local_pattern_semantics().contracts
        (base,) = registry.find_for_call("free")
        registry.add(
            replace(base, source="manual", symbol=replace(base.symbol, build_context_id=build))
        )
        result = AsyncLifecyclePaths(facts, registry, index.get_function_program_facts).run()
        # The existing registry conservatively shadows a builtin even when
        # the overriding declaration belongs to another build. Do not bypass
        # that policy or borrow the other build's effect.
        assert result["gaps"] and not result["observations"]


@pytest.mark.parametrize(
    "definition",
    [
        "void free(void *p) {(void)p;}",
        "int pthread_create(pthread_t *t,const pthread_attr_t *a,void *(*f)(void *),void *p) {return 0;}",
    ],
)
def test_actual_project_definition_is_not_standard_root(tmp_path, definition):
    source = tmp_path / "shadow.c"
    source.write_text(
        """#include <pthread.h>
#include <stdlib.h>
struct Item {int value;};
static void *work(void *raw) {struct Item *p=raw; p->value=1; return 0;}
"""
        + definition
        + """
void entry(void) {
struct Item *p=malloc(sizeof *p); if(!p)return;
pthread_t t;
if(pthread_create(&t,0,work,p)!=0)return;
free(p); pthread_join(t,0);
}
"""
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [shutil.which("clang"), "-c", str(source), "-pthread"],
                }
            ]
        )
    )
    backend, index = native_index(tmp_path, source, cdb)
    try:
        result = analyze((index, source, default_local_pattern_semantics().contracts), "entry")
        assert result["gaps"] == ["async_standard_root_unverified"]
        assert not result["observations"]
    finally:
        backend.close()


@pytest.mark.parametrize("mutation", ["build", "signature", "callback", "budget"])
def test_incomplete_native_bindings_and_budget_stay_unknown(async_project, mutation):
    index, source, registry = async_project
    facts = deepcopy(index.get_function_program_facts("free_join", str(source)))
    if mutation == "build":
        facts["build_context_id"] = "unrelated-build"
    for event in facts["functions"][0]["events"]:
        if event.get("callee", {}).get("name") != "pthread_create":
            continue
        if mutation == "signature":
            event["callee"]["canonical_signature"] = "int (void *)"
        if mutation == "callback":
            event["argument_objects"][2]["has_definition"] = False
    result = AsyncLifecyclePaths(
        facts,
        registry,
        index.get_function_program_facts,
        max_steps=1 if mutation == "budget" else 512,
    ).run()
    assert not result["complete"] and result["gaps"] and not result["observations"]


def test_live_receipt_rechecks_source_and_registry(async_project):
    from zscope.core.validation.protocol_assessment import checked_assessment

    index, source, registry = async_project
    (issue,) = candidates(async_project, "free_join")
    attach_decision_facts(issue)
    current = default_local_pattern_semantics().contracts
    issue["protocol_assessment"] = assess_protocol_candidate(issue, index, current)
    assert checked_assessment(issue)
    current.shadowed_symbols.add("free")
    assert not checked_assessment(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(issue, index, registry)
    original = source.read_bytes()
    try:
        source.write_bytes(original.replace(b"p->value=1", b"p->value=2", 1))
        assert not checked_assessment(issue)
        assert analyze(async_project, "free_join")["gaps"] == ["async_native_inputs_stale"]
        assert assess_protocol_candidate(issue, index, registry)["state"] == "pending"
    finally:
        source.write_bytes(original)


@pytest.mark.parametrize("mutation", ["missing", "tool", "abi"])
def test_native_receipt_is_required_and_tool_digest_current(async_project, mutation):
    index, source, registry = async_project
    facts = deepcopy(index.get_function_program_facts("free_join", str(source)))
    if mutation == "missing":
        facts.pop("build_context")
    elif mutation == "abi":
        facts["build_context"]["target"]["target.triple"] = "unverified-platform"
    else:
        facts["build_context"]["tool"]["binary"]["sha256"] = "obsolete"
    result = AsyncLifecyclePaths(facts, registry, index.get_function_program_facts).run()
    assert not result["complete"] and not result["observations"]
