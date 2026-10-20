"""Native worker call stacks survive scheduler cuts and deferred cancellation."""

import json
import shutil
from copy import deepcopy
from dataclasses import replace

import pytest

from test_async_paths import analyze
from test_async_queue import queue_driver
from test_async_cleanup import CLEANUP_SOURCE
from test_single_slot_pool import native_index
from test_lifecycle_paths import candidates
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.defaults import default_local_pattern_semantics


HELPER_SOURCE = (
    CLEANUP_SOURCE
    + """
static struct Item *take_one(struct Queue *q) {
  pthread_mutex_lock(&q->mu);
  while(!q->slot && !q->stop) pthread_cond_wait(&q->cv,&q->mu);
  struct Item *p=q->slot; q->slot=0;
  pthread_mutex_unlock(&q->mu); return p;
}
static int leaf_process(struct Item *p, int write) {if(write) p->value=9; return write;}
static int process_item(struct Item *p) {return leaf_process(p,1);}
static void dispose_item(struct Item *p) {free(p);}
static void *helper_worker(void *raw) {
  struct Queue *q=raw; struct Item *p=take_one(q);
  if(p) process_item(p); return 0;
}
static void *discard_worker(void *raw) {
  struct Queue *q=raw; struct Item *p=take_one(q);
  if(p) dispose_item(p); return 0;
}
static void *repeated_worker(void *raw) {
  struct Queue *q=raw; struct Item *p=take_one(q); int i=0;
  while(i<2) {if(leaf_process(p,0)) p->value=2; i++;} return 0;
}
static void wait_nested(struct Queue *q) {
  pthread_mutex_lock(&q->mu);
  pthread_cleanup_push(unlock_queue,q);
  while(!q->stop) pthread_cond_wait(&q->cv,&q->mu);
  pthread_cleanup_pop(1);
}
static void wait_outer(struct Queue *q) {wait_nested(q);}
static void *cleanup_owner(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  pthread_cleanup_push(touch_item,p);
  pthread_mutex_unlock(&q->mu);
  wait_outer(q); pthread_cleanup_pop(0); return 0;
}
static void helper_point(struct Item *p) {pthread_testcancel(); p->value=3;}
static void *point_worker(void *raw) {
  struct Queue *q=raw; struct Item *p=take_one(q); helper_point(p); return 0;
}
static int recursive(struct Item *p) {return recursive(p);}
static void *recursive_worker(void *raw) {
  struct Queue *q=raw; struct Item *p=take_one(q); recursive(p); return 0;
}
static struct Item *local_address(void) {struct Item item={0}; return &item;}
static void *escape_worker(void *raw) {struct Item *p=local_address(); p->value=1; return 0;}
static void *local_argument_worker(void *raw) {struct Item item={0}; process_item(&item); return 0;}
extern void opaque_worker_call(struct Item *p);
static void *unknown_worker(void *raw) {struct Queue *q=raw; struct Item *p=take_one(q); opaque_worker_call(p); return 0;}
static void bad_unlock(void *raw) {struct Queue *q=raw; wait_outer(q);}
static void *handler_calls_helper(void *raw) {
  struct Queue *q=raw; pthread_cleanup_push(bad_unlock,q); pthread_testcancel(); pthread_cleanup_pop(0); return 0;
}
static void *alias_return_worker(void *raw) {
  struct Queue *q=raw; struct Item *p=take_one(q); struct Item *old=p; p=0; process_item(old); return 0;
}
"""
)
HELPER_DRIVERS = {
    "nested_uaf": ("helper_worker", "submit(q,p); free(p); pthread_join(t,0);"),
    "nested_drained": ("helper_worker", "submit(q,p); pthread_join(t,0); free(p);"),
    "returned_alias": ("alias_return_worker", "submit(q,p); free(p); pthread_join(t,0);"),
    "wait_then_uaf": (
        "helper_worker",
        "cancel_pending(q); submit(q,p); free(p); pthread_join(t,0);",
    ),
    "wait_then_stop": (
        "helper_worker",
        "cancel_pending(q); stop_accepting(q); pthread_join(t,0); free(p);",
    ),
    "helper_free": ("discard_worker", "submit(q,p); pthread_join(t,0);"),
    "repeated_call": ("repeated_worker", "submit(q,p); free(p); pthread_join(t,0);"),
    "cancel_point_helper": (
        "point_worker",
        "submit(q,p); pthread_cancel(t); free(p); pthread_join(t,0);",
    ),
    "no_cancel_helper_point": ("point_worker", "submit(q,p); free(p); pthread_join(t,0);"),
    "cancel_outer_cleanup": (
        "cleanup_owner",
        "submit(q,p); pthread_cancel(t); free(p); pthread_join(t,0);",
    ),
    "normal_outer_cleanup": (
        "cleanup_owner",
        "submit(q,p); stop_accepting(q); pthread_join(t,0); free(p);",
    ),
    "recursive_helper": ("recursive_worker", "submit(q,p); pthread_join(t,0);"),
    "local_escape": ("escape_worker", "pthread_join(t,0);"),
    "local_argument": ("local_argument_worker", "pthread_join(t,0);"),
    "unknown_helper": ("unknown_worker", "submit(q,p); free(p); pthread_join(t,0);"),
    "cleanup_helper": ("handler_calls_helper", "pthread_cancel(t); pthread_join(t,0);"),
}


@pytest.fixture(scope="module")
def helper_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("pthread-helpers")
    source = root / "helpers.c"
    source.write_text(
        HELPER_SOURCE
        + "\n".join(
            queue_driver(name, body, callback, "q->saved=p;")
            for name, (callback, body) in HELPER_DRIVERS.items()
        )
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


@pytest.mark.parametrize(
    "name", ["nested_uaf", "wait_then_uaf", "returned_alias", "no_cancel_helper_point"]
)
def test_suspended_helper_returns_captured_object_then_nested_access(helper_project, name):
    result = analyze(helper_project, name)
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["resource_id"] == result["resources"][1]["id"]
    assert observation["ordering"].endswith("scheduled_callback_during_join")
    edges = observation["event"]["call_path"]
    assert edges[0]["edge_kind"] == "scheduled_callback_during_join"
    assert edges[-1]["edge_kind"] == "worker_direct_helper"
    assert all(e["callee_build_context_id"] == result["build_context_id"] for e in edges)
    assert not any(e["callee_usr"].endswith("@F@take_one") for e in edges)
    events = result["trace"]
    join = next(i for i, e in enumerate(events) if e["kind"] == "join_wait_begin")
    taken = next(i for i, e in enumerate(events) if e["kind"] == "worker_helper_return")
    assert join < taken
    assert not result["schedule"]["worker"]["complete"]


@pytest.mark.parametrize(
    "name",
    ["nested_drained", "wait_then_stop", "helper_free", "normal_outer_cleanup", "repeated_call"],
)
def test_helper_results_and_branches_are_not_completions(helper_project, name):
    result = analyze(helper_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["joined"]
    assert not result["schedule"]["absence_is_safety_proof"]
    if name == "helper_free":
        release = result["resources"][1]["released_by"]
        assert release["function_usr"].endswith("@F@dispose_item")
    if name == "repeated_call":
        starts = [
            e["helper_invocation"] for e in result["trace"] if e["kind"] == "worker_helper_begin"
        ]
        assert len(starts) == len(set(starts)) == 3
        returns = [e["result"] for e in result["trace"] if e["kind"] == "worker_helper_return"]
        assert returns[-2:] == [0, 0]


def test_cancel_in_helper_unwinds_registration_owners_without_return(helper_project):
    result = analyze(helper_project, "cancel_outer_cleanup")
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["event"]["call_path"][-1]["caller_usr"].endswith("@F@cleanup_owner")
    assert observation["event"]["function_usr"].endswith("@F@touch_item")
    scopes = [e for e in result["trace"] if e["kind"] == "cleanup_unwind_scope"]
    assert len(scopes) == 2
    assert scopes[0]["cancel_origin"]["function_usr"].endswith("@F@wait_nested")
    assert len(scopes[0]["call_path"]) == 3 and len(scopes[1]["call_path"]) == 1
    assert not any(e["kind"] == "worker_helper_return" for e in result["trace"])
    assert not any(e["kind"] == "callback_complete_then_join_return" for e in result["trace"])


def test_testcancel_in_helper_does_not_resume_parent(helper_project):
    result = analyze(helper_project, "cancel_point_helper")
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["cancelled"] and result["schedule"]["worker"]["joined"]
    starts = [e for e in result["trace"] if e["kind"] == "worker_helper_begin"]
    returned = [e for e in result["trace"] if e["kind"] == "worker_helper_return"]
    assert len(starts) == 2 and len(returned) == 1


@pytest.mark.parametrize(
    "name,gap",
    [
        ("recursive_helper", "call_depth_or_recursion_bound"),
        ("local_escape", "async_helper_return_value_unclosed"),
        ("local_argument", "async_helper_argument_value_unclosed"),
        ("unknown_helper", "async_helper_target_unresolved"),
        ("cleanup_helper", "async_callback_call_or_cancellation_point"),
    ],
)
def test_helper_boundaries_are_unknown(helper_project, name, gap):
    result = analyze(helper_project, name)
    assert result["gaps"] == [gap]
    assert not result["observations"]


def test_helper_replay_default_rule_and_current_contract(helper_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    (issue,) = candidates(helper_project, "nested_uaf")
    assert (
        assess_protocol_candidate(issue, helper_project[0], helper_project[2])["state"]
        == "conditional"
    )
    altered = deepcopy(issue)
    altered["evidence_pack"]["object_protocol_path"]["schedule"]["helpers"]["calls"] = 0
    assert (
        assess_protocol_candidate(altered, helper_project[0], helper_project[2])["state"]
        == "pending"
    )
    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(helper_project, "nested_uaf", policy)
    registry = default_local_pattern_semantics().contracts
    (contract,) = registry.find_for_call("pthread_mutex_unlock")
    registry.add(replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    assert analyze((*helper_project[:2], registry), "nested_uaf")["gaps"] == [
        "async_standard_contract_unverified"
    ]


def test_helper_candidate_acceptance_retraction_and_json(helper_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof

    (issue,) = candidates(helper_project, "nested_uaf")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(
        issue, helper_project[0], helper_project[2]
    )
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    store = UserConfigStore(tmp_path / "answers")
    answer(store, assumption)
    assert validate(helper_project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "工作者 helper 路径前提撤回", revision=1)
    assert not deterministic_decision_proof(issue, outcome="confirm")
    assert not validate(helper_project, store, issue)["issues"]
