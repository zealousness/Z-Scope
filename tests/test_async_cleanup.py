"""Real native deferred cancellation and bounded C/glibc cleanup stacks."""

import json
import shutil
from copy import deepcopy
from dataclasses import replace

import pytest

from test_async_paths import analyze
from test_async_queue import QUEUE_SOURCE, queue_driver
from test_single_slot_pool import native_index
from test_lifecycle_paths import candidates
from zscope.core.candidates.cpp_domains.async_paths import AsyncLifecyclePaths
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.defaults import default_local_pattern_semantics

CLEANUP_SOURCE = QUEUE_SOURCE.replace("int active;", "int active; struct Item *saved;") + """
static void unlock_queue(void *raw) {struct Queue *q=raw; pthread_mutex_unlock(&q->mu);}
static void touch_item(void *raw) {struct Item *p=raw; p->value=7;}
static void release_item(void *raw) {free(raw);}
static void noop(void *raw) {}
static void *wait_cleanup(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu);
  pthread_cleanup_push(unlock_queue,q);
  while(!q->stop) pthread_cond_wait(&q->cv,&q->mu);
  pthread_cleanup_pop(1);
  return 0;
}
static void *nested_cleanup(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  pthread_cleanup_push(touch_item,p);
  pthread_cleanup_push(unlock_queue,q);
  while(!q->stop) pthread_cond_wait(&q->cv,&q->mu);
  pthread_cleanup_pop(1);
  pthread_cleanup_pop(0);
  return 0;
}
static void *release_cleanup(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  pthread_cleanup_push(release_item,p);
  pthread_cleanup_push(unlock_queue,q);
  while(!q->stop) pthread_cond_wait(&q->cv,&q->mu);
  pthread_cleanup_pop(1);
  pthread_cleanup_pop(0);
  return 0;
}
static void *test_point(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  pthread_mutex_unlock(&q->mu);
  pthread_cleanup_push(touch_item,p);
  pthread_testcancel();
  pthread_cleanup_pop(0);
  return 0;
}
static void *pop_execute(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  pthread_mutex_unlock(&q->mu);
  pthread_cleanup_push(touch_item,p); pthread_cleanup_pop(1); return 0;
}
static void *pop_discard(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  pthread_mutex_unlock(&q->mu);
  pthread_cleanup_push(touch_item,p); pthread_cleanup_pop(0); return 0;
}
static void *capture_value(void *raw) {
  struct Queue *q=raw; pthread_mutex_lock(&q->mu); struct Item *p=q->saved;
  pthread_mutex_unlock(&q->mu);
  pthread_cleanup_push(touch_item,p); p=0; pthread_testcancel(); pthread_cleanup_pop(0); return 0;
}
static void *early_exit(void *raw) {
  struct Queue *q=raw; pthread_cleanup_push(noop,q); return 0; pthread_cleanup_pop(0); return 0;
}
static void *changed_mode(void *raw) {pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,0); return 0;}
"""
CLEANUP_DRIVERS = {
    "cancel_wait": (
        "wait_cleanup",
        "cancel_pending(q); pthread_cancel(t); pthread_join(t,0); free(p);",
    ),
    "cancel_before_wait_entry": (
        "wait_cleanup",
        "pthread_cancel(t); cancel_pending(q); pthread_join(t,0); free(p);",
    ),
    "normal_stop": (
        "wait_cleanup",
        "cancel_pending(q); stop_accepting(q); pthread_join(t,0); free(p);",
    ),
    "nested_uaf": (
        "nested_cleanup",
        "cancel_pending(q); pthread_cancel(t); free(p); pthread_join(t,0);",
    ),
    "cancel_prefix_uaf": (
        "nested_cleanup",
        "cancel_pending(q); pthread_mutex_lock(&q->mu); pthread_cancel(t); free(p); pthread_mutex_unlock(&q->mu); pthread_join(t,0);",
    ),
    "notified_cancel": (
        "wait_cleanup",
        "cancel_pending(q); pthread_mutex_lock(&q->mu); q->stop=1; pthread_cond_signal(&q->cv); pthread_cancel(t); pthread_mutex_unlock(&q->mu); pthread_join(t,0); free(p);",
    ),
    "nested_live": (
        "nested_cleanup",
        "cancel_pending(q); pthread_cancel(t); pthread_join(t,0); free(p);",
    ),
    "cleanup_free": ("release_cleanup", "cancel_pending(q); pthread_cancel(t); pthread_join(t,0);"),
    "cancel_testpoint": (
        "test_point",
        "submit(q,p); pthread_cancel(t); free(p); pthread_join(t,0);",
    ),
    "not_cancelled": ("test_point", "submit(q,p); pthread_join(t,0); free(p);"),
    "normal_pop_uaf": ("pop_execute", "submit(q,p); free(p); pthread_join(t,0);"),
    "normal_discard": ("pop_discard", "submit(q,p); free(p); pthread_join(t,0);"),
    "captured_uaf": (
        "capture_value",
        "submit(q,p); pthread_cancel(t); free(p); pthread_join(t,0);",
    ),
    "locked_join": (
        "wait_cleanup",
        "cancel_pending(q); pthread_cancel(t); pthread_mutex_lock(&q->mu); pthread_join(t,0);",
    ),
    "free_wait_context": (
        "wait_cleanup",
        "cancel_pending(q); pthread_cancel(t); free(q); pthread_join(t,0);",
    ),
    "no_drain_cleanup": ("wait_cleanup", "cancel_pending(q); pthread_cancel(t); free(p);"),
    "return_without_pop": ("early_exit", "pthread_join(t,0);"),
    "unsupported_cancel_mode": ("changed_mode", "pthread_cancel(t); pthread_join(t,0);"),
}


@pytest.fixture(scope="module")
def cleanup_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("pthread-cleanups")
    source = root / "cleanup.c"
    source.write_text(
        CLEANUP_SOURCE
        + "\n".join(
            queue_driver(name, body, callback, "q->saved=p;")
            for name, (callback, body) in CLEANUP_DRIVERS.items()
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
    "name",
    ["cancel_wait", "cancel_before_wait_entry", "nested_live", "cleanup_free", "notified_cancel"],
)
def test_cancellation_reacquires_before_lifo_cleanup_and_join(cleanup_project, name):
    result = analyze(cleanup_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert result["schedule"]["worker"]["cancelled"] and result["schedule"]["worker"]["joined"]
    kinds = [e["kind"] for e in result["trace"]]
    assert (
        kinds.index("request_cancellation")
        < kinds.index("cancellation_reacquires_mutex")
        < kinds.index("cleanup_begin")
        < kinds.index("cancelled_callback_complete")
        < kinds.index("callback_complete_then_join_return")
    )
    assert not any(
        c["kind"] == "pthread_cond_wait_returns_zero" for c in result["schedule"]["constraints"]
    )
    callbacks = [
        e["callback_usr"].split("@F@")[-1] for e in result["trace"] if e["kind"] == "cleanup_begin"
    ]
    assert callbacks[0] == "unlock_queue"
    if name in {"nested_live", "cleanup_free"}:
        assert len(callbacks) == 2
    if name == "cleanup_free":
        assert result["resources"][1]["state"] == "released"


@pytest.mark.parametrize(
    "name",
    ["nested_uaf", "cancel_testpoint", "normal_pop_uaf", "captured_uaf", "cancel_prefix_uaf"],
)
def test_cleanup_uses_captured_generation_and_stops_at_uaf(cleanup_project, name):
    result = analyze(cleanup_project, name)
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["resource_id"] == result["resources"][1]["id"]
    assert observation["event"]["function_usr"].endswith("@F@touch_item")
    assert observation["event"]["call_path"][-1]["edge_kind"].startswith("pthread_cleanup_")
    assert not result["schedule"]["worker"]["complete"]
    assert not any(
        c["kind"] == "pthread_join_returns_zero" for c in result["schedule"]["constraints"]
    )
    if name == "cancel_prefix_uaf":
        assert not any(e["kind"] == "join_wait_begin" for e in result["trace"])


@pytest.mark.parametrize("name", ["normal_stop", "not_cancelled", "normal_discard"])
def test_no_cancel_or_pop_zero_does_not_run_discarded_handler(cleanup_project, name):
    result = analyze(cleanup_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"]
    assert not result["schedule"]["cancellation"]["delivered"]
    assert result["schedule"]["cancellation"]["cleanup_invocations"] == (
        1 if name == "normal_stop" else 0
    )
    assert not result["schedule"]["absence_is_safety_proof"]


@pytest.mark.parametrize(
    "name,gap",
    [
        ("locked_join", "async_wait_mutex_reacquire_blocked"),
        ("free_wait_context", "async_wait_storage_lifetime_unclosed"),
        ("no_drain_cleanup", "async_sync_destroy_before_join"),
        ("return_without_pop", "async_cleanup_control_exit_unsupported"),
        ("unsupported_cancel_mode", "async_cancel_mode_unsupported"),
    ],
)
def test_unsupported_or_unfinished_cancellation_keeps_gap(cleanup_project, name, gap):
    result = analyze(cleanup_project, name)
    assert result["gaps"] == [gap]
    assert not result["observations"]


def test_cleanup_receipt_is_required(cleanup_project):
    index, source, registry = cleanup_project

    def provider(*args, **kwargs):
        facts = deepcopy(index.get_function_program_facts(*args, **kwargs))
        for body in facts["functions"]:
            body.pop("pthread_cleanup_facts_version", None)
        return facts

    result = AsyncLifecyclePaths(
        index.get_function_program_facts("nested_uaf", str(source)), registry, provider
    ).run()
    assert result["gaps"] == ["async_cleanup_receipt_missing"]


def test_cleanup_candidate_replay_and_default_rule_policy(cleanup_project):
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    (issue,) = candidates(cleanup_project, "nested_uaf")
    assert (
        assess_protocol_candidate(issue, cleanup_project[0], cleanup_project[2])["state"]
        == "conditional"
    )
    altered = deepcopy(issue)
    altered["evidence_pack"]["object_protocol_path"]["schedule"]["cancellation"][
        "cleanup_invocations"
    ] = 0
    assert (
        assess_protocol_candidate(altered, cleanup_project[0], cleanup_project[2])["state"]
        == "pending"
    )
    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(cleanup_project, "nested_uaf", policy)


def test_testcancel_requires_current_root_contract(cleanup_project):
    registry = default_local_pattern_semantics().contracts
    (contract,) = registry.find_for_call("pthread_testcancel")
    registry.add(replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    result = analyze((*cleanup_project[:2], registry), "cancel_testpoint")
    assert result["gaps"] == ["async_standard_contract_unverified"]


@pytest.mark.parametrize(
    "variant",
    [
        "redefined",
        "unlikely",
        "expression",
        "exceptions",
        "helper",
        "break_scope",
        "buffer_macro",
        "register_definition",
        "pop_expression",
        "stack_bound",
    ],
)
def test_unverified_macro_or_unsupported_handler_never_proves_cleanup(tmp_path, variant):
    code = CLEANUP_SOURCE
    flags = []
    if variant == "redefined":
        code = code.replace(
            "static void *wait_cleanup",
            "#undef pthread_cleanup_push\n#define pthread_cleanup_push(routine,arg) do {\n#undef pthread_cleanup_pop\n#define pthread_cleanup_pop(execute) } while(0)\nstatic void *wait_cleanup",
        )
    if variant == "unlikely":
        code = code.replace(
            "static void *wait_cleanup",
            "#undef __glibc_unlikely\n#define __glibc_unlikely(x) 1\nstatic void *wait_cleanup",
        )
    if variant == "expression":
        code = code.replace(
            "pthread_cleanup_push(unlock_queue,q);", "pthread_cleanup_push(unlock_queue,(q));"
        )
    if variant == "exceptions":
        flags = ["-fexceptions"]
    if variant == "buffer_macro":
        code = code.replace(
            "static void *wait_cleanup",
            "typedef __pthread_unwind_buf_t replacement_buffer;\n#define __pthread_unwind_buf_t replacement_buffer\nstatic void *wait_cleanup",
            1,
        )
    if variant == "register_definition":
        code = code.replace(
            "static void *wait_cleanup",
            "void __pthread_register_cancel(__pthread_unwind_buf_t *p) {}\nstatic void *wait_cleanup",
            1,
        )
    if variant == "pop_expression":
        code = code.replace("pthread_cleanup_pop(1);", "pthread_cleanup_pop(1+0);", 1)
    if variant == "stack_bound":
        code = code.replace(
            "pthread_cleanup_push(unlock_queue,q);", "pthread_cleanup_push(noop,q);" * 5, 1
        ).replace("pthread_cleanup_pop(1);", "pthread_cleanup_pop(0);" * 5, 1)
    if variant == "helper":
        code = code.replace(
            "static void unlock_queue(void *raw) {struct Queue *q=raw; pthread_mutex_unlock(&q->mu);}",
            "void opaque_cleanup(void*);\nstatic void unlock_queue(void *raw) {struct Queue *q=raw; opaque_cleanup(q);}",
            1,
        )
    if variant == "break_scope":
        code = code.replace("while(!q->stop) pthread_cond_wait(&q->cv,&q->mu);", "break;", 1)
    source = tmp_path / "unsupported.c"
    source.write_text(
        code
        + queue_driver(
            "entry",
            "cancel_pending(q); pthread_cancel(t); pthread_join(t,0);",
            "wait_cleanup",
            "q->saved=p;",
        )
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [shutil.which("clang"), "-c", str(source), "-pthread", *flags],
                }
            ]
        )
    )
    backend, index = native_index(tmp_path, source, cdb)
    try:
        result = analyze((index, source, default_local_pattern_semantics().contracts), "entry")
        assert not result["complete"] and result["gaps"], result
        assert not result["observations"]
        assert not result["schedule"]["worker"].get("joined")
    finally:
        backend.close()


def test_cleanup_acceptance_retraction_and_json(cleanup_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof

    (issue,) = candidates(cleanup_project, "nested_uaf")
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(
        issue, cleanup_project[0], cleanup_project[2]
    )
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    store = UserConfigStore(tmp_path / "answers")
    answer(store, assumption)
    assert validate(cleanup_project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "取消与清理路径前提撤回", revision=1)
    assert not deterministic_decision_proof(issue, outcome="confirm")
    assert not validate(cleanup_project, store, issue)["issues"]
