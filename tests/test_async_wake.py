"""Bounded spurious and timed returns use real native facts, not a wall clock."""

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

WAKE_SOURCE = CLEANUP_SOURCE + """
#include <errno.h>
static void *spurious_access(void *raw) {
  struct Queue *q=raw;
  pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  if(!q->stop) pthread_cond_wait(&q->cv,&q->mu);
  pthread_mutex_unlock(&q->mu); p->value=42; return 0;
}
static void *spurious_guarded(void *raw) {
  struct Queue *q=raw;
  pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  while(!q->stop) pthread_cond_wait(&q->cv,&q->mu);
  pthread_mutex_unlock(&q->mu); p->value=42; return 0;
}
static void *timed_access(void *raw) {
  struct Queue *q=raw;
  pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  struct timespec limit={0}; limit.tv_sec=1; limit.tv_nsec=0;
  int rc=pthread_cond_timedwait(&q->cv,&q->mu,&limit);
  if(rc==ETIMEDOUT) {pthread_mutex_unlock(&q->mu); p->value=43; return 0;}
  pthread_mutex_unlock(&q->mu); return 0;
}
static void *timed_safe(void *raw) {
  struct Queue *q=raw;
  pthread_mutex_lock(&q->mu);
  struct timespec limit={0}; limit.tv_sec=1; limit.tv_nsec=0;
  int rc=pthread_cond_timedwait(&q->cv,&q->mu,&limit);
  pthread_mutex_unlock(&q->mu); return 0;
}
static void *timed_cleanup(void *raw) {
  struct Queue *q=raw;
  pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  struct timespec limit={0}; limit.tv_sec=1; limit.tv_nsec=0;
  pthread_cleanup_push(unlock_queue,q);
  int rc=pthread_cond_timedwait(&q->cv,&q->mu,&limit);
  if(rc==ETIMEDOUT) p->value=44;
  pthread_cleanup_pop(1); return 0;
}
static void timed_helper(struct Queue *q) {
  pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  struct timespec limit={0}; limit.tv_sec=1; limit.tv_nsec=0;
  int rc=pthread_cond_timedwait(&q->cv,&q->mu,&limit);
  if(rc==ETIMEDOUT) p->value=45;
  pthread_mutex_unlock(&q->mu);
}
static void *nested_timed(void *raw) {struct Queue *q=raw; timed_helper(q); return 0;}
"""
WAKE_DRIVERS = {
    "spurious_uaf": ("spurious_access", "cancel_pending(q); free(p); pthread_join(t,0);"),
    "spurious_recheck": ("spurious_guarded", "cancel_pending(q); free(p); pthread_join(t,0);"),
    "spurious_drained": ("spurious_access", "cancel_pending(q); pthread_join(t,0); free(p);"),
    "timeout_uaf": ("timed_access", "cancel_pending(q); free(p); pthread_join(t,0);"),
    "timeout_cleanup_uaf": ("timed_cleanup", "cancel_pending(q); free(p); pthread_join(t,0);"),
    "timeout_helper_uaf": ("nested_timed", "cancel_pending(q); free(p); pthread_join(t,0);"),
    "timeout_drained": ("timed_access", "cancel_pending(q); pthread_join(t,0); free(p);"),
    "timeout_no_access": ("timed_safe", "cancel_pending(q); free(p); pthread_join(t,0);"),
    "timed_notified": (
        "timed_access",
        "cancel_pending(q); stop_accepting(q); free(p); pthread_join(t,0);",
    ),
    "timed_cancelled": (
        "timed_cleanup",
        "cancel_pending(q); pthread_cancel(t); free(p); pthread_join(t,0);",
    ),
    "timed_blocked": (
        "timed_access",
        "cancel_pending(q); pthread_mutex_lock(&q->mu); free(p); pthread_join(t,0);",
    ),
    "timed_storage_dead": ("timed_access", "cancel_pending(q); free(q); pthread_join(t,0);"),
}


@pytest.fixture(scope="module")
def wake_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("pthread-wake")
    source = root / "wake.c"
    source.write_text(
        WAKE_SOURCE
        + "\n".join(
            queue_driver(name, body, callback, "q->saved=p;")
            for name, (callback, body) in WAKE_DRIVERS.items()
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
    "name,policy",
    [
        ("spurious_uaf", "spurious_once"),
        ("timeout_uaf", "timeout_once"),
        ("timeout_cleanup_uaf", "timeout_once"),
        ("timeout_helper_uaf", "timeout_once"),
    ],
)
def test_bounded_wake_reacquires_mutex_before_return_and_uaf(wake_project, name, policy):
    result = analyze(wake_project, name)
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["resource_id"] == result["resources"][1]["id"]
    assert result["schedule"]["wait_exploration"]["selected"] == policy
    assert result["schedule"]["condition_wait"]["bounded_unsignalled_returns"] == 1
    assert not result["schedule"]["all_interleavings_covered"]
    assert not result["schedule"]["worker"]["complete"]
    trace = result["trace"]
    reacquire = next(
        i for i, e in enumerate(trace) if e["kind"] == "condition_wait_reacquires_mutex"
    )
    assert trace[reacquire]["wake_reason"] == policy
    assert any(e["kind"] == "condition_unsignalled_wake_selected" for e in trace[:reacquire])
    outcome = next(c for c in result["schedule"]["constraints"] if c.get("wake_reason") == policy)
    assert bool(outcome["result"]) == (policy == "timeout_once")
    if policy == "timeout_once":
        assert outcome["clock_constraint"]["clock"] == "CLOCK_REALTIME"
        assert outcome["clock_constraint"]["at_or_after"]["tv_sec"] == 1
    (issue,) = candidates(wake_project, name)
    assert (
        assess_protocol_candidate(issue, wake_project[0], wake_project[2])["state"] == "conditional"
    )


@pytest.mark.parametrize(
    "name",
    [
        "spurious_drained",
        "timeout_drained",
        "timeout_no_access",
        "timed_notified",
        "timed_cancelled",
    ],
)
def test_wake_is_not_predicate_or_completion(wake_project, name):
    result = analyze(wake_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["joined"]
    assert not result["schedule"]["absence_is_safety_proof"]
    if name == "timed_cancelled":
        assert result["schedule"]["worker"]["cancelled"]
        assert result["schedule"]["condition_wait"]["bounded_unsignalled_returns"] == 0
        assert not any("timedwait_returns" in c["kind"] for c in result["schedule"]["constraints"])
    if name == "timed_notified":
        assert result["schedule"]["wait_exploration"]["selected"] == "notified"
        outcome = next(
            c
            for c in result["schedule"]["constraints"]
            if c["kind"] == "pthread_cond_timedwait_returns_zero"
        )
        assert outcome["clock_constraint"] is None


def test_spurious_return_rechecks_loop_and_keeps_bound(wake_project):
    result = analyze(wake_project, "spurious_recheck")
    assert result["gaps"] == ["async_wait_no_matching_notification"]
    assert not result["observations"]
    attempts = result["schedule"]["wait_exploration"]["attempts"]
    assert len(attempts) == 2 and all(not a["complete"] for a in attempts)


@pytest.mark.parametrize(
    "name,gap",
    [
        ("timed_blocked", "async_wait_mutex_reacquire_blocked"),
        ("timed_storage_dead", "async_wait_storage_lifetime_unclosed"),
    ],
)
def test_unknown_alternatives_are_preserved(wake_project, name, gap):
    result = analyze(wake_project, name)
    assert not result["complete"] and not result["observations"]
    assert any(gap in a["gaps"] for a in result["schedule"]["wait_exploration"]["attempts"])


def test_wake_replay_tampering_and_current_root(wake_project):
    (issue,) = candidates(wake_project, "timeout_uaf")
    altered = deepcopy(issue)
    altered["evidence_pack"]["object_protocol_path"]["schedule"]["wait_exploration"][
        "selected"
    ] = "notified"
    assert (
        assess_protocol_candidate(altered, wake_project[0], wake_project[2])["state"] == "pending"
    )
    registry = default_local_pattern_semantics().contracts
    (root,) = registry.find_for_call("pthread_cond_timedwait")
    registry.add(replace(root, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    assert analyze((*wake_project[:2], registry), "timeout_uaf")["gaps"] == [
        "async_standard_contract_unverified"
    ]


@pytest.mark.parametrize(
    "variant",
    [
        "invalid_nsec",
        "negative_seconds",
        "unknown_deadline",
        "cast_deadline",
        "project_errno",
        "wrapped_errno",
        "unsupported_clockwait",
        "packed_deadline",
    ],
)
def test_unsupported_deadline_or_macro_is_not_a_timeout_witness(tmp_path, variant):
    code = WAKE_SOURCE
    if variant == "invalid_nsec":
        code = code.replace("limit.tv_nsec=0;", "limit.tv_nsec=1000000000;")
    if variant == "negative_seconds":
        code = code.replace("limit.tv_sec=1;", "limit.tv_sec=-1;")
    if variant == "unknown_deadline":
        code = code.replace(
            "struct timespec limit={0}; limit.tv_sec=1; limit.tv_nsec=0;", "struct timespec limit;"
        )
    if variant == "cast_deadline":
        code = code.replace("&q->mu,&limit)", "&q->mu,(const struct timespec *)&limit)")
    if variant == "project_errno":
        code = code.replace(
            "#include <errno.h>", "#include <errno.h>\n#undef ETIMEDOUT\n#define ETIMEDOUT 110"
        )
    if variant == "wrapped_errno":
        code = code.replace(
            "#include <errno.h>", "#include <errno.h>\n#define WRAPPED_TIMEOUT ETIMEDOUT"
        )
        code = code.replace("rc==ETIMEDOUT", "rc==WRAPPED_TIMEOUT")
    if variant == "unsupported_clockwait":
        code = "#define _GNU_SOURCE\n" + code.replace(
            "pthread_cond_timedwait(&q->cv,&q->mu,&limit)",
            "pthread_cond_clockwait(&q->cv,&q->mu,CLOCK_BOOTTIME,&limit)",
        )
    source = tmp_path / "boundary.c"
    source.write_text(
        code
        + queue_driver(
            "entry", "cancel_pending(q); free(p); pthread_join(t,0);", "timed_access", "q->saved=p;"
        )
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [shutil.which("clang"), "-c", str(source), "-pthread"]
                    + (["-fpack-struct=1"] if variant == "packed_deadline" else []),
                }
            ]
        )
    )
    backend, index = native_index(tmp_path, source, cdb)
    try:
        result = analyze((index, source, default_local_pattern_semantics().contracts), "entry")
        assert not result["complete"] and result["gaps"] and not result["observations"], result
    finally:
        backend.close()


@pytest.mark.parametrize("mutation", ["missing", "old_version", "wrong_layout"])
def test_missing_native_timed_receipt_cannot_fallback(wake_project, mutation):
    from zscope.core.candidates.cpp_domains.async_paths import AsyncLifecyclePaths

    index, source, registry = wake_project

    def provider(*args, **kwargs):
        facts = deepcopy(index.get_function_program_facts(*args, **kwargs))
        for body in facts["functions"]:
            if mutation == "missing":
                body.pop("pthread_wait_facts_version", None)
            elif mutation == "old_version":
                body["pthread_wait_facts_version"] = "zscope.pthread-wait.v1"
            else:
                for event in body.get("events", []):
                    receipt = event.get("pthread_timed_wait")
                    if receipt:
                        receipt["layout"]["alignment_bytes"] = 1
        return facts

    result = AsyncLifecyclePaths(
        index.get_function_program_facts("timeout_uaf", str(source)), registry, provider
    ).run()
    assert result["gaps"] == ["async_timed_wait_receipt_missing"]
    assert not result["observations"]


def test_wake_acceptance_retraction_and_default_policy(wake_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    (issue,) = candidates(wake_project, "timeout_uaf")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(
        issue, wake_project[0], wake_project[2]
    )
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    store = UserConfigStore(tmp_path / "answers")
    answer(store, assumption)
    assert validate(wake_project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "截止时间及调度业务前提撤回", revision=1)
    assert not deterministic_decision_proof(issue, outcome="confirm")
    assert not validate(wake_project, store, issue)["issues"]
    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(wake_project, "timeout_uaf", policy)
