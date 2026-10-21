"""Explicit wait clocks need current native system-definition receipts."""

import json
import shutil
from copy import deepcopy
from dataclasses import replace

import pytest

from test_async_paths import analyze
from test_async_queue import queue_driver
from test_async_wake import WAKE_SOURCE, WAKE_DRIVERS
from test_lifecycle_paths import candidates
from test_single_slot_pool import native_index
from zscope.core.candidates.cpp_domains.async_paths import AsyncLifecyclePaths
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.defaults import default_local_pattern_semantics


def clock_source(clock="CLOCK_MONOTONIC"):
    return "#define _GNU_SOURCE\n" + WAKE_SOURCE.replace(
        "pthread_cond_timedwait(&q->cv,&q->mu,&limit)",
        f"pthread_cond_clockwait(&q->cv,&q->mu,{clock},&limit)",
    )


def clock_project_at(root, code, extra=()):
    source = root / "clock.c"
    source.write_text(code)
    cdb = root / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(source),
                    "arguments": [shutil.which("clang"), "-c", str(source), "-pthread", *extra],
                }
            ]
        )
    )
    backend, index = native_index(root, source, cdb)
    return backend, (index, source, default_local_pattern_semantics().contracts)


def test_clock_consumer_coverage_is_distinct_from_rule_execution():
    from zscope.semantics.resource_coverage import consumer_support

    (contract,) = default_local_pattern_semantics().contracts.find_for_call(
        "pthread_cond_clockwait"
    )
    support = consumer_support(contract)["async_queue_sync"]
    assert "direct_system_clockwait_constants_only" in support
    assert "explicit_experimental_rule_only" in support


@pytest.fixture(scope="module", params=["CLOCK_REALTIME", "CLOCK_MONOTONIC"])
def clock_project(tmp_path_factory, request):
    code = clock_source(request.param) + "\n".join(
        queue_driver(name, body, callback, "q->saved=p;")
        for name, (callback, body) in WAKE_DRIVERS.items()
        if not name.startswith("spurious")
    )
    backend, project = clock_project_at(tmp_path_factory.mktemp("clockwait"), code)
    try:
        yield project, request.param
    finally:
        backend.close()


@pytest.mark.parametrize("name", ["timeout_uaf", "timeout_helper_uaf", "timeout_cleanup_uaf"])
def test_explicit_clock_timeout_preserves_object_and_reacquires(clock_project, name):
    project, clock = clock_project
    result = analyze(project, name)
    assert result["complete"], result["gaps"]
    (observation,) = result["observations"]
    assert observation["resource_id"] == result["resources"][1]["id"]
    assert result["schedule"]["wait_exploration"]["selected"] == "timeout_once"
    outcome = next(
        c for c in result["schedule"]["constraints"] if c.get("wake_reason") == "timeout_once"
    )
    assert outcome["kind"] == "pthread_cond_clockwait_returns_timeout"
    assert outcome["clock_constraint"]["clock"] == clock
    assert outcome["clock_constraint"]["at_or_after"]["tv_sec"] == 1
    assert any(e["kind"] == "condition_wait_reacquires_mutex" for e in result["trace"])
    (issue,) = candidates(project, name)
    assert assess_protocol_candidate(issue, project[0], project[2])["state"] == "conditional"


@pytest.mark.parametrize("name", ["timeout_drained", "timed_notified", "timed_cancelled"])
def test_clockwait_drain_notification_and_cancellation(clock_project, name):
    project, _ = clock_project
    result = analyze(project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"] and result["schedule"]["worker"]["joined"]
    outcomes = [
        c
        for c in result["schedule"]["constraints"]
        if c["kind"].startswith("pthread_cond_clockwait_returns")
    ]
    if name == "timed_cancelled":
        assert result["schedule"]["worker"]["cancelled"] and not outcomes
    if name == "timed_notified":
        assert outcomes and all(
            c["result"] == 0 and c["clock_constraint"] is None for c in outcomes
        )
    assert not result["schedule"]["all_interleavings_covered"]
    assert not result["schedule"]["absence_is_safety_proof"]


@pytest.mark.parametrize(
    "variant",
    [
        "unsupported",
        "literal",
        "variable",
        "cast",
        "wrapped",
        "redefined",
        "packed",
        "unknown_deadline",
    ],
)
def test_unverified_clock_or_deadline_cannot_authorize(tmp_path, variant):
    code = clock_source(
        {
            "unsupported": "CLOCK_BOOTTIME",
            "literal": "1",
            "variable": "clock_id",
            "cast": "(clockid_t)CLOCK_MONOTONIC",
            "wrapped": "WRAPPED_CLOCK",
        }.get(variant, "CLOCK_MONOTONIC")
    )
    if variant == "variable":
        code = code.replace(
            "int rc=pthread_cond_clockwait",
            "clockid_t clock_id=CLOCK_MONOTONIC; int rc=pthread_cond_clockwait",
        )
    if variant in {"wrapped", "redefined"}:
        definition = (
            "#define WRAPPED_CLOCK CLOCK_MONOTONIC"
            if variant == "wrapped"
            else "#undef CLOCK_MONOTONIC\n#define CLOCK_MONOTONIC 1"
        )
        code = code.replace("#include <errno.h>", "#include <errno.h>\n" + definition)
    if variant == "unknown_deadline":
        code = code.replace(
            "struct timespec limit={0}; limit.tv_sec=1; limit.tv_nsec=0;", "struct timespec limit;"
        )
    code += queue_driver(
        "entry", "cancel_pending(q); free(p); pthread_join(t,0);", "timed_access", "q->saved=p;"
    )
    backend, project = clock_project_at(
        tmp_path, code, ["-fpack-struct=1"] if variant == "packed" else []
    )
    try:
        result = analyze(project, "entry")
        assert not result["complete"] and result["gaps"] and not result["observations"], result
    finally:
        backend.close()


@pytest.mark.parametrize(
    "mutation", ["old_v2", "missing_clock", "clock_value", "clock_name", "system_flag"]
)
def test_native_clock_receipts_have_no_weak_fallback(clock_project, mutation):
    project, _ = clock_project
    index, source, registry = project

    def provider(*args, **kwargs):
        facts = deepcopy(index.get_function_program_facts(*args, **kwargs))
        for body in facts["functions"]:
            for event in body.get("events", []):
                receipt = event.get("pthread_timed_wait")
                if not receipt:
                    continue
                if mutation == "old_v2":
                    body["pthread_wait_facts_version"] = "zscope.pthread-wait.v2"
                    receipt["schema"] = "zscope.pthread-deadline.v2"
                elif mutation == "missing_clock":
                    receipt.pop("clock")
                elif mutation == "clock_value":
                    receipt["clock"]["value"] = 99
                elif mutation == "clock_name":
                    receipt["clock"]["name"] = "CLOCK_BOOTTIME"
                else:
                    body["target_values"]["system." + receipt["clock"]["name"]] = False
        return facts

    result = AsyncLifecyclePaths(
        index.get_function_program_facts("timeout_uaf", str(source)), registry, provider
    ).run()
    assert not result["complete"] and result["gaps"] and not result["observations"], result


def test_clock_acceptance_current_contract_and_retraction(clock_project, tmp_path):
    from test_protocol_feedback import answer, validate
    from zscope.config.user_config_store import UserConfigStore
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    project, _ = clock_project
    (issue,) = candidates(project, "timeout_uaf")
    altered = deepcopy(issue)
    constraints = altered["evidence_pack"]["object_protocol_path"]["schedule"]["constraints"]
    next(c for c in constraints if c.get("clock_constraint"))["clock_constraint"][
        "clock"
    ] = "CLOCK_BOOTTIME"
    assert assess_protocol_candidate(altered, project[0], project[2])["state"] == "pending"
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(issue, project[0], project[2])
    (assumption,) = issue["protocol_assessment"]["assumptions"]
    store = UserConfigStore(tmp_path / "answers")
    answer(store, assumption)
    assert validate(project, store, issue)["issues"]
    assert deterministic_decision_proof(issue, outcome="confirm")
    assert not deterministic_decision_proof(json.loads(json.dumps(issue)), outcome="confirm")
    answer(store, assumption, "unknown", "时钟及调度前提撤回", revision=1)
    assert not deterministic_decision_proof(issue, outcome="confirm")
    assert not validate(project, store, issue)["issues"]
    policy = EffectiveRuleSet.build(RuleCatalog.builtin(), language="c_cpp", backend="clang").policy
    assert not candidates(project, "timeout_uaf", policy)
    registry = default_local_pattern_semantics().contracts
    (root,) = registry.find_for_call("pthread_cond_clockwait")
    registry.add(replace(root, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}]))
    assert analyze((*project[:2], registry), "timeout_uaf")["gaps"] == [
        "async_standard_contract_unverified"
    ]
