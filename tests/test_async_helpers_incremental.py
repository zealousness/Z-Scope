"""Worker helper body, result and cancellation changes revoke old witnesses."""

import json
from copy import deepcopy
from dataclasses import replace

from test_clang_batch import project, build
from test_async_incremental import evaluate
from test_async_queue import queue_driver
from test_async_helpers import HELPER_SOURCE
from zscope.core.validation.protocol_assessment import assess_protocol_candidate, checked_assessment
from zscope.retrieval.clang_backend import ClangBackend
from zscope.semantics.defaults import default_local_pattern_semantics


def test_worker_helper_dependencies_match_independent_cold_analysis(project):
    backend, root, cdb = project
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) {return 0;}\n')
    previous = None
    for stage in (
        "initial",
        "unchanged",
        "body_changed",
        "restored",
        "target_changed",
        "return_changed",
        "restored_again",
        "root_changed",
        "helper_cancel",
        "drain_fixed",
    ):
        registry = default_local_pattern_semantics().contracts
        code = HELPER_SOURCE
        driver = "submit(q,p); pthread_cancel(t); free(p); pthread_join(t,0);"
        if stage == "body_changed":
            code = code.replace("if(write) p->value=9;", "")
        if stage == "target_changed":
            code = code.replace("if(p) process_item(p);", "if(p) leaf_process(p,0);")
        if stage == "return_changed":
            code = code.replace(
                "pthread_mutex_unlock(&q->mu); return p;", "pthread_mutex_unlock(&q->mu); return 0;"
            )
        if stage == "helper_cancel":
            code = code.replace(
                "if(write) p->value=9;", "pthread_testcancel(); if(write) p->value=9;"
            )
        if stage == "root_changed":
            (contract,) = registry.find_for_call("pthread_mutex_unlock")
            registry.add(
                replace(contract, effect_cases=[{"when": {"op": "true"}, "effect": "unknown"}])
            )
        if stage == "drain_fixed":
            driver = "submit(q,p); pthread_join(t,0); free(p);"
        (root / "a.c").write_text(
            code + queue_driver("entry", driver, "helper_worker", "q->saved=p;")
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
        hot_index, issues, hot = evaluate(backend, root, cdb, registry)
        cold = ClangBackend(
            frontend="batch",
            clang_indexer_path=backend._clang_indexer_path,
            db_path=f".zscope_knowledge/helpers-full-{stage}/db.sqlite",
            max_threads=1,
        )
        try:
            assert cold.initialize(str(root), compile_commands_path=str(cdb))
            assert json.loads(cold.db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2
            _, _, full = evaluate(cold, root, cdb, registry)
            assert hot == full
        finally:
            cold.close()
        assert bool(issues) == (stage in {"initial", "unchanged", "restored", "restored_again"})
        assert hot["path"]["complete"] == (stage != "root_changed")
        if issues:
            assert all(checked_assessment(issue) for issue in issues)
            assert hot["projection"][0]["sub_state"] == "business_conditional"
        if stage == "helper_cancel":
            assert hot["path"]["schedule"]["worker"]["cancelled"]
            assert hot["path"]["schedule"]["worker"]["joined"]
            # take_one returned, process_item and leaf_process were unwound.
            assert (
                len([e for e in hot["path"]["trace"] if e["kind"] == "worker_helper_return"]) == 1
            )
        previous = hot_index, deepcopy(issues)
