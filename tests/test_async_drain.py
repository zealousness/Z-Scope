"""A caller's condition-wait predicate is not callback completion by name."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_async_paths import analyze
from test_async_queue import QUEUE_SOURCE, queue_driver
from test_async_clock import clock_project_at
from test_lifecycle_paths import candidates
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.defaults import default_local_pattern_semantics

DRAIN_SOURCE = QUEUE_SOURCE + """
static void drain(struct Queue *q) {
  pthread_mutex_lock(&q->mu);
  while(q->active) pthread_cond_wait(&q->cv,&q->mu);
  pthread_mutex_unlock(&q->mu);
}
static void drain_if(struct Queue *q) {
  pthread_mutex_lock(&q->mu);
  if(q->active) pthread_cond_wait(&q->cv,&q->mu);
  pthread_mutex_unlock(&q->mu);
}
static void nested_drain(struct Queue *q) {drain(q);}
static void no_lock_drain(struct Queue *q) {pthread_cond_wait(&q->cv,&q->mu);}
static void timed_drain(struct Queue *q) {
  pthread_mutex_lock(&q->mu); struct timespec limit={0};
  pthread_cond_timedwait(&q->cv,&q->mu,&limit);
  pthread_mutex_unlock(&q->mu);
}
static void *finished(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu);
  struct Item *p=q->slot; q->slot=0; q->active=1;
  pthread_mutex_unlock(&q->mu);
  p->value=7;
  pthread_mutex_lock(&q->mu); q->active=0; pthread_cond_signal(&q->cv);
  pthread_mutex_unlock(&q->mu); return 0;
}
static void *premature(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu);
  struct Item *p=q->slot; q->slot=0; q->active=1;
  pthread_mutex_unlock(&q->mu);
  pthread_mutex_lock(&q->mu); q->active=0; pthread_cond_signal(&q->cv);
  pthread_mutex_unlock(&q->mu); p->value=8; return 0;
}
static void *notify_twice(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu);
  struct Item *p=q->slot; q->slot=0; q->active=1;
  pthread_mutex_unlock(&q->mu);
  pthread_mutex_lock(&q->mu); pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu);
  p->value=9;
  pthread_mutex_lock(&q->mu); q->active=0; pthread_cond_signal(&q->cv);
  pthread_mutex_unlock(&q->mu); return 0;
}
static void *no_notify(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu);
  struct Item *p=q->slot; q->slot=0; q->active=1;
  pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu);
  p->value=10;
  pthread_mutex_lock(&q->mu); q->active=0; pthread_mutex_unlock(&q->mu); return 0;
}
static void *other_unlock(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu);
  struct Item *p=q->slot; q->slot=0; q->active=1;
  pthread_mutex_unlock(&q->mu); p->value=11;
  pthread_mutex_lock(&q->mu); q->active=0; pthread_cond_signal(&q->cv);
  pthread_mutex_lock(&q->other); pthread_mutex_unlock(&q->other);
  pthread_mutex_unlock(&q->mu); return 0;
}
static void *never_finishes(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); q->active=1; pthread_mutex_unlock(&q->mu);
  int repeat=1;
  while(repeat) {pthread_mutex_lock(&q->mu); pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu);}
  return 0;
}
static void finish_cleanup(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); q->active=0;
  pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu);
}
static void touch_cleanup(void *raw) {struct Item *p=raw; p->value=12;}
static void *cancel_clean(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu);
  struct Item *p=q->slot; q->slot=0; q->active=1; pthread_mutex_unlock(&q->mu);
  pthread_cleanup_push(touch_cleanup,p);
  pthread_cleanup_push(finish_cleanup,q);
  pthread_testcancel();
  pthread_cleanup_pop(1); pthread_cleanup_pop(1); return 0;
}
"""
DRAIN_DRIVERS = {
    "drained": ("finished", "drain(q); free(p); pthread_join(t,0);"),
    "nested": ("finished", "nested_drain(q); free(p); pthread_join(t,0);"),
    "recheck": ("notify_twice", "drain(q); free(p); pthread_join(t,0);"),
    "early_flag": ("premature", "drain(q); free(p); pthread_join(t,0);"),
    "notify_is_not_done": ("notify_twice", "drain_if(q); free(p); pthread_join(t,0);"),
    "free_before_wait": ("finished", "free(p); drain(q); pthread_join(t,0);"),
    "join_fixed": ("premature", "drain(q); pthread_join(t,0); free(p);"),
    "unrelated_unlock": (
        "other_unlock",
        "drain(q); free(p); pthread_join(t,0); pthread_mutex_destroy(&q->other);",
    ),
    "lost_notification": ("no_notify", "drain(q); free(p); pthread_join(t,0);"),
    "without_mutex": ("finished", "no_lock_drain(q); pthread_join(t,0);"),
    "caller_timeout": ("finished", "timed_drain(q); pthread_join(t,0);"),
    "still_needs_join": ("finished", "drain(q); free(p);"),
    "bounded_rewait": ("never_finishes", "drain(q); pthread_join(t,0);"),
    "cancel_drain": ("cancel_clean", "pthread_cancel(t); drain(q); pthread_join(t,0); free(p);"),
    "cancel_cleanup_uaf": (
        "cancel_clean",
        "free(p); pthread_cancel(t); drain(q); pthread_join(t,0);",
    ),
}


@pytest.fixture(scope="module")
def drain_project(tmp_path_factory):
    code = DRAIN_SOURCE + "\n".join(
        queue_driver(
            name,
            "submit(q,p); stop_accepting(q); " + body,
            callback,
            "if(pthread_mutex_init(&q->other,0)!=0)return;" if name == "unrelated_unlock" else "",
        )
        for name, (callback, body) in DRAIN_DRIVERS.items()
    )
    backend, project = clock_project_at(tmp_path_factory.mktemp("pthread-drain"), code)
    try:
        yield project
    finally:
        backend.close()


@pytest.mark.parametrize(
    "name,count",
    [
        ("drained", 1),
        ("nested", 1),
        ("recheck", 2),
        ("join_fixed", 1),
        ("unrelated_unlock", 1),
        ("cancel_drain", 1),
    ],
)
def test_caller_wait_rechecks_current_predicate(drain_project, name, count):
    result = analyze(drain_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"] and result["schedule"]["worker"]["joined"]
    assert result["schedule"]["caller_condition_wait"]["count"] == count
    kinds = [e["kind"] for e in result["trace"]]
    assert kinds.index("caller_condition_wait_releases_mutex") < kinds.index(
        "caller_condition_wait_reacquires_mutex"
    )
    assert kinds.index("caller_condition_wait_reacquires_mutex") < kinds.index("join_wait_begin")
    assert not result["schedule"]["absence_is_safety_proof"]
    if name == "cancel_drain":
        scopes = [e for e in result["trace"] if e["kind"] == "cleanup_unwind_scope"]
        assert len(scopes) == 2 and all(len(s["call_path"]) == 2 for s in scopes)
        assert result["schedule"]["worker"]["cancelled"]


def test_two_waiters_cannot_bind_same_condition_to_different_mutexes(tmp_path):
    code = DRAIN_SOURCE + queue_driver(
        "entry",
        "cancel_pending(q); pthread_mutex_lock(&q->other); pthread_cond_wait(&q->cv,&q->other);",
        pre_create="if(pthread_mutex_init(&q->other,0)!=0)return;",
    )
    backend, project = clock_project_at(tmp_path, code)
    try:
        result = analyze(project, "entry")
        assert not result["complete"] and not result["observations"]
        assert result["gaps"] == ["async_condition_mutex_binding_conflict"]
    finally:
        backend.close()


def test_drain_support_is_not_rule_execution():
    from zscope.semantics.resource_coverage import consumer_support

    (root,) = default_local_pattern_semantics().contracts.find_for_call("pthread_cond_wait")
    support = consumer_support(root)["async_queue_sync"]
    assert "caller_matched_wait_predicate_recheck" in support
    assert "explicit_experimental_rule_only" in support
    for name in ("pthread_cond_timedwait", "pthread_cond_clockwait"):
        (root,) = default_local_pattern_semantics().contracts.find_for_call(name)
        support = consumer_support(root)["async_queue_sync"]
        assert "caller_wait_unsupported" in support
        assert "caller_matched_wait_predicate_recheck" not in support


@pytest.mark.parametrize(
    "name", ["early_flag", "notify_is_not_done", "free_before_wait", "cancel_cleanup_uaf"]
)
def test_notification_and_flag_do_not_authorize_release(drain_project, name):
    result = analyze(drain_project, name)
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["resource_id"] == result["resources"][1]["id"]
    if name in {"free_before_wait", "cancel_cleanup_uaf"}:
        assert observation["ordering"].endswith("scheduled_worker_during_caller_condition_wait")
        assert not any(
            e["kind"] in {"join_wait_begin", "caller_condition_wait_reacquires_mutex"}
            for e in result["trace"]
        )
    (issue,) = candidates(drain_project, name)
    assert (
        assess_protocol_candidate(issue, drain_project[0], drain_project[2])["state"]
        == "conditional"
    )


@pytest.mark.parametrize(
    "name,gap",
    [
        ("lost_notification", "async_caller_wait_no_matching_notification"),
        ("without_mutex", "async_wait_mutex_not_owned"),
        ("caller_timeout", "async_caller_condition_wait_unclosed"),
        ("still_needs_join", "async_sync_destroy_before_join"),
        ("bounded_rewait", "async_caller_wait_budget_exceeded"),
    ],
)
def test_unclosed_caller_wait_is_not_a_drain(drain_project, name, gap):
    result = analyze(drain_project, name)
    assert not result["complete"] and result["gaps"] == [gap], result
    assert not result["observations"]


def test_caller_wait_replay_current_contract_and_acceptance(drain_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    (issue,) = candidates(drain_project, "free_before_wait")
    altered = deepcopy(issue)
    altered["evidence_pack"]["object_protocol_path"]["schedule"]["caller_condition_wait"][
        "count"
    ] = 0
    assert (
        assess_protocol_candidate(altered, drain_project[0], drain_project[2])["state"] == "pending"
    )
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(
        issue, drain_project[0], drain_project[2]
    )
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    store = UserConfigStore(tmp_path / "answers")
    answer(store, assumption)
    assert validate(drain_project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "调用方等待路径前提撤回", revision=1)
    assert not deterministic_decision_proof(issue, outcome="confirm")
    assert not validate(drain_project, store, issue)["issues"]
    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(drain_project, "free_before_wait", policy)
    registry = default_local_pattern_semantics().contracts
    (root,) = registry.find_for_call("pthread_cond_wait")
    registry.add(replace(root, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    assert analyze((*drain_project[:2], registry), "free_before_wait")["gaps"] == [
        "async_standard_contract_unverified"
    ]
