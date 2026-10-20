"""Matched wait/notification dependencies share existing current-input checks."""

import json
from copy import deepcopy
from dataclasses import replace

from test_clang_batch import project, build
from test_async_incremental import evaluate
from test_async_queue import queue_driver
from test_async_wait import WAIT_SOURCE, WAIT_DRIVERS
from zscope.core.validation.protocol_assessment import assess_protocol_candidate, checked_assessment
from zscope.retrieval.clang_backend import ClangBackend
from zscope.semantics.defaults import default_local_pattern_semantics


def test_wait_notifications_and_contract_changes_match_full(project):
    backend, root, cdb = project
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) {return 0;}\n')
    (root / "notes.txt").write_text("existing note\n")
    previous = None
    for stage in (
        "initial",
        "unchanged",
        "notifications_removed",
        "wrong_condition",
        "restored",
        "root_changed",
        "drain_fixed",
    ):
        registry = default_local_pattern_semantics().contracts
        code = WAIT_SOURCE
        driver = WAIT_DRIVERS["wake_then_drain" if stage == "drain_fixed" else "wake_then_uaf"]
        if stage == "notifications_removed":
            code = code.replace("pthread_cond_signal(&q->cv);", "").replace(
                "pthread_cond_broadcast(&q->cv);", ""
            )
        if stage == "wrong_condition":
            code = code.replace(
                "pthread_cond_signal(&q->cv)", "pthread_cond_signal(&q->other_cv)"
            ).replace("pthread_cond_broadcast(&q->cv)", "pthread_cond_broadcast(&q->other_cv)")
        if stage == "unchanged":
            (root / "notes.txt").write_text("unrelated note change\n")
        if stage == "root_changed":
            (contract,) = registry.find_for_call("pthread_cond_wait")
            registry.add(
                replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}])
            )
        (root / "a.c").write_text(
            code + queue_driver("entry", driver, pre_create="pthread_cond_init(&q->other_cv,0);")
        )
        if previous and stage != "unchanged":
            old_index, old_issues = previous
            for issue in old_issues:
                # A root change revokes the old live registry's receipt only
                # when that registry itself changes; replay always uses current.
                if stage != "root_changed":
                    assert not checked_assessment(issue)
                assert assess_protocol_candidate(issue, old_index, registry)["state"] == "pending"
        assert build(project)
        if stage in {"unchanged", "root_changed"}:
            stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
            assert stats["compiled_tus"] == 0 and stats["reused_tus"] == 2
        hot_index, issues, hot = evaluate(backend, root, cdb, registry)
        cold = ClangBackend(
            frontend="batch",
            clang_indexer_path=backend._clang_indexer_path,
            db_path=f".zscope_knowledge/wait-full-{stage}/db.sqlite",
            max_threads=1,
        )
        try:
            assert cold.initialize(str(root), compile_commands_path=str(cdb))
            assert json.loads(cold.db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2
            _, _, full = evaluate(cold, root, cdb, registry)
            assert hot == full
        finally:
            cold.close()
        # submit still publishes the task under the mutex. Without a matching
        # notification, one permitted spurious return can now reach that task
        # after free; the predicate is rechecked, not assumed true by the wake.
        assert bool(issues) == (stage not in {"root_changed", "drain_fixed"})
        assert hot["path"]["complete"] == (stage != "root_changed")
        if stage in {"notifications_removed", "wrong_condition"}:
            exploration = hot["path"]["schedule"]["wait_exploration"]
            assert exploration["selected"] == "spurious_once"
            assert exploration["attempts"][0]["gaps"] == ["async_wait_no_matching_notification"]
        if issues:
            assert all(checked_assessment(issue) for issue in issues)
            assert hot["projection"][0]["sub_state"] == "business_conditional"
            assert hot["projection"][0]["missing"] == ["event:business_release_requirement"]
        previous = (hot_index, deepcopy(issues))
