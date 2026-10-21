"""Actual native single-worker queue paths; no pthread program is executed."""

import json
import shutil
from copy import deepcopy
from dataclasses import replace

import pytest

from test_async_paths import analyze
from test_single_slot_pool import native_index
from test_lifecycle_paths import candidates
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.defaults import default_local_pattern_semantics


QUEUE_SOURCE = """#include <pthread.h>
#include <stdlib.h>
struct Item { int value; };
struct Queue { pthread_mutex_t mu; pthread_mutex_t other; pthread_cond_t cv; struct Item *slot; int stop; int active; };
static int submit(struct Queue *q, struct Item *p) {
  pthread_mutex_lock(&q->mu);
  if(q->stop || q->slot) {pthread_mutex_unlock(&q->mu); return 0;}
  q->slot=p; pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu); return 1;
}
static void cancel_pending(struct Queue *q) {
  pthread_mutex_lock(&q->mu); q->slot=0; pthread_mutex_unlock(&q->mu);
}
static void stop_accepting(struct Queue *q) {
  pthread_mutex_lock(&q->mu); q->stop=1; pthread_cond_broadcast(&q->cv); pthread_mutex_unlock(&q->mu);
}
static void *work(void *raw) {
  struct Queue *q=raw;
  while(1) {
    pthread_mutex_lock(&q->mu);
    while(!q->slot && !q->stop) pthread_cond_wait(&q->cv,&q->mu);
    if(!q->slot && q->stop) {pthread_mutex_unlock(&q->mu); return 0;}
    struct Item *p=q->slot; q->slot=0; q->active=1;
    pthread_mutex_unlock(&q->mu);
    if(p) p->value=1;
    pthread_mutex_lock(&q->mu); q->active=0; pthread_mutex_unlock(&q->mu);
  }
}
static void *same_lock(void *raw) {
  struct Queue *q=raw;
  pthread_mutex_lock(&q->mu);
  struct Item *p=q->slot; q->slot=0; q->active=1;
  pthread_mutex_unlock(&q->mu);
  pthread_mutex_lock(&q->mu);
  if(p) p->value=1;
  q->active=0; pthread_mutex_unlock(&q->mu); return 0;
}
static void *wrong_lock(void *raw) {
  struct Queue *q=raw;
  struct Item *p=q->slot; q->slot=0;
  if(p) p->value=1; return 0;
}
static void *spins(void *raw) {
  struct Queue *q=raw; int run=1; while(run) {pthread_mutex_lock(&q->mu); pthread_mutex_unlock(&q->mu);} return 0;
}
static void *different_mutex(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->other);
  struct Item *p=q->slot; q->slot=0; pthread_mutex_unlock(&q->other);
  if(p) p->value=1; return 0;
}
"""
DRIVERS = {
    "cancel_active": "submit(q,p); cancel_pending(q); stop_accepting(q); free(p); pthread_join(t,0);",
    "drain_active": "submit(q,p); cancel_pending(q); stop_accepting(q); pthread_join(t,0); free(p);",
    "stop_only": "submit(q,p); stop_accepting(q); free(p); pthread_join(t,0);",
    "same_mutex_uaf": "submit(q,p); pthread_mutex_lock(&q->mu); free(p); pthread_mutex_unlock(&q->mu); pthread_join(t,0);",
    "replacement": "submit(q,p); cancel_pending(q); stop_accepting(q); free(p); p=malloc(sizeof *p); pthread_join(t,0); free(p);",
    "other_object": "submit(q,p); stop_accepting(q); struct Item *other=malloc(sizeof *other); free(other); pthread_join(t,0); free(p);",
    "rejected_submit": "stop_accepting(q); if(submit(q,p)) free(p); pthread_join(t,0); free(p);",
    "empty_wait": "cancel_pending(q); stop_accepting(q); pthread_join(t,0); free(p);",
    "join_holding_lock": "submit(q,p); stop_accepting(q); pthread_mutex_lock(&q->mu); pthread_join(t,0);",
    "unsynchronized": "submit(q,p); stop_accepting(q); free(p); pthread_join(t,0);",
    "spin_bound": "submit(q,p); pthread_join(t,0);",
    "no_join": "submit(q,p); cancel_pending(q); stop_accepting(q); free(p);",
    "destroy_active": "submit(q,p); pthread_mutex_destroy(&q->mu); pthread_join(t,0);",
    "opaque_write": "submit(q,p); q->mu=q->mu; pthread_join(t,0);",
    "cancel_request": "submit(q,p); pthread_cancel(t); stop_accepting(q); pthread_join(t,0); free(p);",
    "cancel_before_start": "pthread_mutex_lock(&q->mu); q->slot=0; q->stop=1; pthread_mutex_unlock(&q->mu); free(p); pthread_join(t,0);",
    "drain_pending": "stop_accepting(q); pthread_join(t,0); free(p);",
    "different_mutex_instance": "submit(q,p); stop_accepting(q); free(p); pthread_join(t,0);",
    "unlocked_stop": "submit(q,p); q->stop=1; pthread_join(t,0); free(p);",
}


def queue_driver(name, body, callback="work", pre_create=""):
    return f"""void {name}(void) {{
        struct Queue *q=calloc(1,sizeof *q); if(!q)return;
        struct Item *p=malloc(sizeof *p); if(!p){{free(q);return;}}
        if(pthread_mutex_init(&q->mu,0)!=0)return;
        if(pthread_cond_init(&q->cv,0)!=0)return;
        {pre_create}
        pthread_t t;
        if(pthread_create(&t,0,{callback},q)!=0)return;
        {body}
        pthread_cond_destroy(&q->cv); pthread_mutex_destroy(&q->mu); free(q);
        }}"""


@pytest.fixture(scope="module")
def queue_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("pthread-queue")
    source = root / "queue.c"
    source.write_text(
        QUEUE_SOURCE
        + "\n".join(
            queue_driver(
                name,
                body,
                {
                    "same_mutex_uaf": "same_lock",
                    "unsynchronized": "wrong_lock",
                    "spin_bound": "spins",
                    "different_mutex_instance": "different_mutex",
                }.get(name, "work"),
                (
                    "submit(q,p);"
                    if name in {"cancel_before_start", "drain_pending"}
                    else (
                        "pthread_mutex_init(&q->other,0);"
                        if name == "different_mutex_instance"
                        else ""
                    )
                ),
            )
            for name, body in DRIVERS.items()
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


@pytest.mark.parametrize("name", ["cancel_active", "stop_only", "same_mutex_uaf", "replacement"])
def test_active_capture_survives_slot_cancel_and_stop(queue_project, name):
    result = analyze(queue_project, name)
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["kind"] == "callback_after_release"
    assert observation["resource_id"] == result["resources"][1]["id"]
    assert observation["resource_id"] != result["schedule"]["worker"]["resource_id"]
    assert any(
        e["kind"] == "worker_local_reference" and e["value"] == observation["resource_id"]
        for e in result["trace"]
    )
    assert any(e["kind"] == "worker_paused_after_unlock" for e in result["trace"])
    assert not result["schedule"]["worker"]["complete"]
    assert not any(
        e["kind"] == "pthread_join_returns_zero" for e in result["schedule"]["constraints"]
    )


@pytest.mark.parametrize(
    "name",
    [
        "drain_active",
        "other_object",
        "rejected_submit",
        "cancel_request",
        "cancel_before_start",
        "drain_pending",
        "empty_wait",
    ],
)
def test_join_completion_and_real_submit_guard(queue_project, name):
    result = analyze(queue_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["joined"]
    assert not result["schedule"]["absence_is_safety_proof"]
    if name in {"rejected_submit", "cancel_before_start"}:
        assert not any(
            e["kind"] == "worker_local_reference" and e["value"] == result["resources"][1]["id"]
            for e in result["trace"]
        )


@pytest.mark.parametrize(
    "name,gap",
    [
        ("join_holding_lock", "async_mutex_would_block_or_recurse"),
        ("unsynchronized", "async_shared_access_without_common_mutex"),
        ("spin_bound", "loop_path_unclosed"),
        ("no_join", "async_sync_destroy_before_join"),
        ("destroy_active", "async_sync_destroy_before_join"),
        ("opaque_write", "async_opaque_storage_access"),
        ("different_mutex_instance", "async_shared_access_without_common_mutex"),
        ("unlocked_stop", "async_shared_access_without_common_mutex"),
    ],
)
def test_unsupported_queue_paths_remain_gaps(queue_project, name, gap):
    result = analyze(queue_project, name)
    assert result["gaps"] == [gap]
    assert not result["complete"] and not result["observations"]


def test_queue_candidate_current_replay_and_default_off(queue_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    (issue,) = candidates(queue_project, "cancel_active")
    assert (
        assess_protocol_candidate(issue, queue_project[0], queue_project[2])["state"]
        == "conditional"
    )
    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(queue_project, "cancel_active", policy)
    altered = deepcopy(issue)
    altered["evidence_pack"]["object_protocol_path"]["trace"].pop()
    assert (
        assess_protocol_candidate(altered, queue_project[0], queue_project[2])["state"] == "pending"
    )


def test_sync_contract_change_cannot_keep_effect(queue_project):
    registry = default_local_pattern_semantics().contracts
    (contract,) = registry.find_for_call("pthread_mutex_lock")
    registry.add(replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    result = analyze((*queue_project[:2], registry), "cancel_active")
    assert result["gaps"] == ["async_standard_contract_unverified"]


def test_queue_business_acceptance_withdrawal_and_current_receipt(queue_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof
    from zscope.core.validation.protocol_assessment import checked_assessment

    (issue,) = candidates(queue_project, "same_mutex_uaf")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(
        issue, queue_project[0], queue_project[2]
    )
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    store = UserConfigStore(tmp_path / "answers")
    answer(store, assumption)
    assert validate(queue_project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "队列调度前提撤回", revision=1)
    assert not checked_assessment(issue)
    assert not validate(queue_project, store, issue)["issues"]


@pytest.mark.parametrize("mutation", ["receipt", "storage", "extent", "budget"])
def test_queue_requires_current_native_storage_and_limits(queue_project, mutation):
    from zscope.core.candidates.cpp_domains.async_paths import AsyncLifecyclePaths

    index, source, registry = queue_project
    facts = deepcopy(index.get_function_program_facts("cancel_active", str(source)))
    body = facts["functions"][0]
    if mutation == "receipt":
        body.pop("pthread_storage_facts_version")
    for event in body["events"]:
        if mutation == "storage":
            for row in (
                event.get("defs", []) + event.get("uses", []) + event.get("argument_objects", [])
            ):
                row.pop("system_record_type", None)
        if mutation == "extent" and event.get("callee", {}).get("name") == "calloc":
            event["arguments"][-1] = "sizeof *p"
    result = AsyncLifecyclePaths(
        facts,
        registry,
        index.get_function_program_facts,
        max_steps=5 if mutation == "budget" else 512,
    ).run()
    assert result["gaps"] and not result["complete"] and not result["observations"]
