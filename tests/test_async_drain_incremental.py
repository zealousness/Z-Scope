"""Current caller-wait predicates, notifications and callbacks invalidate receipts."""

from copy import deepcopy
from dataclasses import replace
import json

from test_clang_batch import project, build
from test_async_incremental import evaluate
from test_async_queue import queue_driver
from test_async_drain import DRAIN_SOURCE
from zscope.core.validation.protocol_assessment import assess_protocol_candidate, checked_assessment
from zscope.retrieval.clang_backend import ClangBackend
from zscope.semantics.defaults import default_local_pattern_semantics


def test_caller_drain_changes_match_cold_replay(project):
    backend, root, cdb = project
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) {return 0;}\n')
    previous = None
    for stage in (
        "initial",
        "unchanged",
        "helper_predicate",
        "notification_removed",
        "callback_finished",
        "restored",
        "early_release",
        "root_changed",
        "drain_fixed",
    ):
        registry = default_local_pattern_semantics().contracts
        code = DRAIN_SOURCE
        driver = "drain(q); free(p); pthread_join(t,0);"
        callback = "premature"
        if stage == "helper_predicate":
            code = code.replace("while(q->active)", "while(q->active && !q->stop)")
        if stage == "notification_removed":
            code = code.replace("q->active=0; pthread_cond_signal(&q->cv);", "q->active=0;")
        if stage in {"callback_finished", "early_release", "root_changed"}:
            callback = "finished"
        if stage in {"early_release", "root_changed"}:
            driver = "free(p); drain(q); pthread_join(t,0);"
        if stage == "root_changed":
            (contract,) = registry.find_for_call("pthread_cond_wait")
            registry.add(
                replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}])
            )
        if stage == "drain_fixed":
            driver = "drain(q); pthread_join(t,0); free(p);"
        (root / "a.c").write_text(
            code + queue_driver("entry", "submit(q,p); stop_accepting(q); " + driver, callback)
        )
        if previous and stage != "unchanged":
            old_index, old_issues = previous
            for issue in old_issues:
                if stage != "root_changed":
                    assert not checked_assessment(issue)
                assert assess_protocol_candidate(issue, old_index, registry)["state"] == "pending"
        assert build(project)
        if stage in {"unchanged", "root_changed"}:
            stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
            assert stats["compiled_tus"] == 0 and stats["reused_tus"] == 2
        index, issues, hot = evaluate(backend, root, cdb, registry)
        cold = ClangBackend(
            frontend="batch",
            clang_indexer_path=backend._clang_indexer_path,
            db_path=f".zscope_knowledge/drain-full-{stage}/db.sqlite",
            max_threads=1,
        )
        try:
            assert cold.initialize(str(root), compile_commands_path=str(cdb))
            assert json.loads(cold.db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2
            _, _, full = evaluate(cold, root, cdb, registry)
            assert hot == full
        finally:
            cold.close()
        assert bool(issues) == (
            stage in {"initial", "unchanged", "helper_predicate", "restored", "early_release"}
        )
        assert hot["path"]["complete"] == (stage not in {"notification_removed", "root_changed"})
        if issues:
            assert all(checked_assessment(issue) for issue in issues)
            assert hot["projection"][0]["sub_state"] == "business_conditional"
        if stage == "early_release":
            (observation,) = hot["path"]["observations"]
            assert observation["ordering"].endswith("scheduled_worker_during_caller_condition_wait")
            assert len(observation["event"]["call_path"]) == 2
        previous = index, deepcopy(issues)
