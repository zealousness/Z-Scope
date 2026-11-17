"""Native single-waiter notification/reacquisition paths, not dynamic executions."""

import json
import shutil
from copy import deepcopy
from dataclasses import replace

import pytest

from test_async_paths import analyze
from test_async_queue import QUEUE_SOURCE, queue_driver
from test_single_slot_pool import native_index
from test_lifecycle_paths import candidates
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.defaults import default_local_pattern_semantics

WAIT_SOURCE = (
    QUEUE_SOURCE.replace("pthread_cond_t cv;", "pthread_cond_t cv; pthread_cond_t other_cv;") + """
static void *unowned_wait(void *raw) {
    struct Queue *q=raw; pthread_cond_wait(&q->cv,&q->mu); return 0;
}
"""
)
WAIT_SOURCE += "static void *checked_wait" + QUEUE_SOURCE.split("static void *work", 1)[1].split(
    "static void *same_lock", 1
)[0].replace(
    "while(!q->slot && !q->stop) pthread_cond_wait(&q->cv,&q->mu);",
    "while(!q->slot && !q->stop) {int rc=pthread_cond_wait(&q->cv,&q->mu); if(rc!=0) {pthread_mutex_unlock(&q->mu); return 0;}}",
)
WAIT_SOURCE += "static void *locked_access" + QUEUE_SOURCE.split("static void *work", 1)[1].split(
    "static void *same_lock", 1
)[0].replace(
    "pthread_mutex_unlock(&q->mu);\n    if(p) p->value=1;",
    "if(p) p->value=1;\n    pthread_mutex_unlock(&q->mu);",
)
WAIT_DRIVERS = {
    "wake_then_uaf": "cancel_pending(q); submit(q,p); stop_accepting(q); free(p); pthread_join(t,0);",
    "wake_prefix_uaf": "cancel_pending(q); pthread_mutex_lock(&q->mu); q->slot=p; free(p); pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu); pthread_join(t,0);",
    "wake_then_drain": "cancel_pending(q); submit(q,p); stop_accepting(q); pthread_join(t,0); free(p);",
    "checked_wait_status": "cancel_pending(q); submit(q,p); stop_accepting(q); pthread_join(t,0); free(p);",
    "stop_empty": "cancel_pending(q); stop_accepting(q); pthread_join(t,0); free(p);",
    "recheck_empty": "cancel_pending(q); pthread_mutex_lock(&q->mu); pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu); stop_accepting(q); pthread_join(t,0); free(p);",
    "signal_outside_lock": "cancel_pending(q); pthread_mutex_lock(&q->mu); q->stop=1; pthread_mutex_unlock(&q->mu); pthread_cond_signal(&q->cv); pthread_join(t,0); free(p);",
    "before_wait": "pthread_cond_signal(&q->cv); cancel_pending(q); pthread_join(t,0);",
    "wrong_condition": "cancel_pending(q); pthread_cond_signal(&q->other_cv); pthread_join(t,0);",
    "no_notification": "cancel_pending(q); pthread_join(t,0);",
    "join_owns_mutex": "cancel_pending(q); pthread_mutex_lock(&q->mu); q->stop=1; pthread_cond_signal(&q->cv); pthread_join(t,0);",
    "freed_wait_storage": "cancel_pending(q); pthread_cond_signal(&q->cv); free(q); pthread_join(t,0);",
    "cancel_waiting": "cancel_pending(q); pthread_cancel(t); pthread_join(t,0);",
    "cancel_before_wait": "pthread_cancel(t); cancel_pending(q); pthread_join(t,0);",
    "wait_without_mutex": "cancel_pending(q); pthread_join(t,0);",
    "caller_wait": "pthread_mutex_lock(&q->mu); pthread_cond_wait(&q->cv,&q->mu);",
    "notify_still_empty": "cancel_pending(q); pthread_mutex_lock(&q->mu); pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->mu); pthread_join(t,0);",
    "unrelated_unlock": "cancel_pending(q); pthread_mutex_lock(&q->mu); pthread_mutex_lock(&q->other); q->stop=1; pthread_cond_signal(&q->cv); pthread_mutex_unlock(&q->other); pthread_mutex_unlock(&q->mu); pthread_join(t,0); free(p);",
}


@pytest.fixture(scope="module")
def wait_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("pthread-waits")
    source = root / "wait.c"
    source.write_text(
        WAIT_SOURCE
        + "\n".join(
            queue_driver(
                name,
                body,
                (
                    "unowned_wait"
                    if name == "wait_without_mutex"
                    else {
                        "checked_wait_status": "checked_wait",
                        "wake_prefix_uaf": "locked_access",
                    }.get(name, "work")
                ),
                "pthread_cond_init(&q->other_cv,0);"
                + ("pthread_mutex_init(&q->other,0);" if name == "unrelated_unlock" else ""),
            )
            for name, body in WAIT_DRIVERS.items()
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


def test_notification_resumes_captured_object_not_completion(wait_project):
    result = analyze(wait_project, "wake_then_uaf")
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["resource_id"] == result["resources"][1]["id"]
    kinds = [e["kind"] for e in result["trace"]]
    captured = next(
        i
        for i, e in enumerate(result["trace"])
        if e["kind"] == "worker_local_reference" and e["value"] == observation["resource_id"]
    )
    assert (
        kinds.index("condition_wait_releases_mutex")
        < kinds.index("condition_notification_matched")
        < kinds.index("condition_wait_reacquires_mutex")
        < captured
        < kinds.index("physical_release")
        < kinds.index("callback_access")
    )
    assert not result["schedule"]["worker"]["complete"]
    assert not any(
        e["kind"] == "pthread_join_returns_zero" for e in result["schedule"]["constraints"]
    )


@pytest.mark.parametrize(
    "name",
    [
        "wake_then_drain",
        "checked_wait_status",
        "stop_empty",
        "recheck_empty",
        "signal_outside_lock",
        "unrelated_unlock",
    ],
)
def test_successful_wait_reacquires_and_rechecks_real_predicate(wait_project, name):
    result = analyze(wait_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["joined"]
    assert result["schedule"]["condition_wait"]["count"] == (2 if name == "recheck_empty" else 1)
    waits = [e for e in result["trace"] if e["kind"] == "condition_wait_releases_mutex"]
    returns = [e for e in result["trace"] if e["kind"] == "condition_wait_reacquires_mutex"]
    assert len({e["wait_id"] for e in waits}) == len(waits) == len(returns)
    for start, finish in zip(waits, returns):
        assert start["wait_id"] == finish["wait_id"]
        assert start["mutex"] == finish["mutex"] and start["condition"] == finish["condition"]
    assert not result["schedule"]["condition_wait"]["spurious_wakeups_covered"]
    assert not result["schedule"]["absence_is_safety_proof"]


@pytest.mark.parametrize(
    "name,gap",
    [
        ("before_wait", "async_wait_no_matching_notification"),
        ("wrong_condition", "async_wait_no_matching_notification"),
        ("no_notification", "async_wait_no_matching_notification"),
        ("join_owns_mutex", "async_wait_mutex_reacquire_blocked"),
        ("freed_wait_storage", "async_wait_storage_lifetime_unclosed"),
        ("cancel_waiting", "async_cancelled_worker_leaves_mutex_owned"),
        ("cancel_before_wait", "async_cancelled_worker_leaves_mutex_owned"),
        ("wait_without_mutex", "async_wait_mutex_not_owned"),
        ("caller_wait", "async_wait_no_matching_notification"),
    ],
)
def test_missing_notification_or_unsupported_cleanup_keeps_gap(wait_project, name, gap):
    result = analyze(wait_project, name)
    assert result["gaps"] == [gap]
    assert not result["complete"] and not result["observations"]
    assert not any(
        e["kind"] == "pthread_cond_wait_returns_zero" for e in result["schedule"]["constraints"]
    )


def test_notification_is_not_credit_for_next_wait(wait_project):
    result = analyze(wait_project, "notify_still_empty")
    assert result["gaps"] == ["async_wait_no_matching_notification"]
    state = result["schedule"]["condition_wait"]
    assert state["count"] == 2 and state["pending"] and not state["notification_matched"]
    assert len([e for e in result["trace"] if e["kind"] == "condition_wait_reacquires_mutex"]) == 1
    assert not result["observations"]


def test_uaf_during_notification_resume_does_not_invent_join(wait_project):
    result = analyze(wait_project, "wake_prefix_uaf")
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["ordering"].endswith("scheduled_worker_prefix_at_unlock")
    assert observation["event"]["call_path"][0]["edge_kind"] == "scheduled_worker_prefix_at_unlock"
    assert not any(e["kind"] == "join_wait_begin" for e in result["trace"])
    (issue,) = candidates(wait_project, "wake_prefix_uaf")
    assert (
        assess_protocol_candidate(issue, wait_project[0], wait_project[2])["state"] == "conditional"
    )


@pytest.mark.parametrize("root", ["pthread_cond_wait", "pthread_cond_signal", "pthread_mutex_lock"])
def test_current_wait_and_notification_contracts_are_required(wait_project, root):
    registry = default_local_pattern_semantics().contracts
    (contract,) = registry.find_for_call(root)
    registry.add(replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    result = analyze((*wait_project[:2], registry), "wake_then_uaf")
    assert result["gaps"] == ["async_standard_contract_unverified"]


def test_wait_witness_uses_current_replay_and_default_policy(wait_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    (issue,) = candidates(wait_project, "wake_then_uaf")
    assert (
        assess_protocol_candidate(issue, wait_project[0], wait_project[2])["state"] == "conditional"
    )
    altered = deepcopy(issue)
    altered["evidence_pack"]["object_protocol_path"]["schedule"]["condition_wait"]["count"] = 0
    assert (
        assess_protocol_candidate(altered, wait_project[0], wait_project[2])["state"] == "pending"
    )
    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(wait_project, "wake_then_uaf", policy)


def test_wait_candidate_acceptance_retraction_and_json(wait_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof

    (issue,) = candidates(wait_project, "wake_then_uaf")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(
        issue, wait_project[0], wait_project[2]
    )
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    store = UserConfigStore(tmp_path / "answers")
    answer(store, assumption)
    assert validate(wait_project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "通知与队列路径前提撤回", revision=1)
    assert not deterministic_decision_proof(issue, outcome="confirm")
    assert not validate(wait_project, store, issue)["issues"]
